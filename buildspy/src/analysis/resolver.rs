//! Path normalization and noise filtering.
//!
//! The tracing layer captures *every* `openat` call made by tracked processes,
//! including temporary files, proc entries, and pipes.  This module keeps
//! only the paths that are relevant for SCA.

use std::path::{Path, PathBuf};

/// Extensions relevant for SCA: libraries, headers, and local source files.
/// Object files (.o) and build-system outputs are excluded.
const RELEVANT_EXTENSIONS: &[&str] = &["so", "a", "h", "hpp", "hxx", "c"];

/// Path prefixes we consider "system" (package-manager-owned).
/// NOTE: /usr/local/ is intentionally excluded — files there are manually
/// installed and not tracked by dpkg/pacman/rpm.
pub const SYSTEM_PREFIXES: &[&str] = &["/usr/lib", "/usr/include", "/lib/", "/lib64/"];

/// Kernel virtual filesystems and fd pseudo-paths — never files a build
/// produces or consumes.
const VIRTUAL_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "pipe:",
    "socket:",
    "anon_inode:",
];

/// Returns `true` for kernel virtual-fs paths and fd pseudo-paths.
pub fn is_virtual(raw: &str) -> bool {
    VIRTUAL_PREFIXES.iter().any(|prefix| raw.starts_with(prefix))
}

/// Returns `true` if the path is worth recording.
pub fn is_relevant(raw: &str) -> bool {
    if raw.is_empty() {
        return false;
    }

    // Drop kernel virtual-fs paths and compiler temporaries.
    if is_virtual(raw) || raw.starts_with("/tmp/") {
        return false;
    }

    // Keep only files with relevant extensions.
    // Versioned shared libraries (e.g. libssl.so.3, libfoo.so.1.2.3) have
    // their last extension as a version number, so they are matched by name.
    let path = Path::new(raw);
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if is_shared_library_name(filename) {
        return true;
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => RELEVANT_EXTENSIONS.contains(&ext),
        None => false,
    }
}

/// Returns `true` for `*.so` and `*.so.<version>` (`libssl.so.3`), but not
/// for every name that merely contains `.so` — the loader's `ld.so.cache`,
/// `ld.so.conf` and `ld.so.conf.d` are not libraries.
pub fn is_shared_library_name(filename: &str) -> bool {
    filename.match_indices(".so").any(|(at, _)| {
        let rest = &filename[at + 3..];
        rest.is_empty()
            || rest
                .strip_prefix('.')
                .is_some_and(|v| v.starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// Normalise a raw path string into a canonical `PathBuf`.
///
/// * Resolves `..` and `.` components lexically (without hitting the
///   filesystem, because the file may be transient or already deleted).
/// * Does NOT call `fs::canonicalize` to avoid extra syscalls and to work
///   even after the build has finished.
pub fn normalize(raw: &str, working_dir: &Path) -> PathBuf {
    let p = Path::new(raw);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        working_dir.join(p)
    };

    // Resolve `.` and `..` without filesystem access.
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in full.components() {
        use std::path::Component::*;
        match component {
            Prefix(x) => parts.push(x.as_os_str()),
            RootDir => parts.push(std::ffi::OsStr::new("/")),
            CurDir => {}
            ParentDir => { parts.pop(); }
            Normal(s) => parts.push(s),
        }
    }

    parts.iter().collect()
}

/// If `path` is a symlink to a shared library, return the file it points to.
///
/// The linker resolves `-lfoo` through the unversioned `libfoo.so` symlink,
/// which the `-dev` package ships, but what it actually reads — and what the
/// loader maps at run time — is the target owned by the runtime package
/// (`libstdc++.so` → `libstdc++.so.6.0.33` from `libstdc++6`).  The `-dev`
/// package still shows up through the headers it contributes.
///
/// Linker scripts (`libc.so`, `libgcc_s.so`) are regular files and are left
/// alone: the linker opens the libraries they name by itself.
pub fn library_symlink_target(path: &Path) -> Option<PathBuf> {
    let filename = path.file_name()?.to_str()?;
    if !is_shared_library_name(filename) {
        return None;
    }
    if !std::fs::symlink_metadata(path).ok()?.file_type().is_symlink() {
        return None;
    }
    std::fs::canonicalize(path).ok()
}

/// Returns `true` if `opened` has the shape of a link input rather than of a
/// library the dynamic loader maps into a running tool.
///
/// `-lfoo` makes the linker open the unversioned `libfoo.so`: a symlink the
/// `-dev` package ships, or a linker script (`libc.so`, `libgcc_s.so`).  The
/// loader opens sonames instead — `libisl.so.23`, or a regular file whose
/// soname has no version, such as `libbfd-2.42-system.so`.
pub fn is_link_input(opened: &Path) -> bool {
    let unversioned = opened
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".so"));
    let symlink = std::fs::symlink_metadata(opened).is_ok_and(|m| m.file_type().is_symlink());
    unversioned && (symlink || super::deps::read_elf_header(opened).is_none())
}

/// Returns `true` if the path lives under a system prefix.
pub fn is_system_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    SYSTEM_PREFIXES.iter().any(|prefix| s.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_noise() {
        assert!(!is_relevant("/proc/self/maps"));
        assert!(!is_relevant("/sys/bus/usb"));
        assert!(!is_relevant("pipe:12345"));
        assert!(!is_relevant(""));
        assert!(!is_relevant("/usr/bin/gcc")); // no relevant ext
    }

    #[test]
    fn accepts_relevant() {
        assert!(is_relevant("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
        assert!(is_relevant("/usr/include/openssl/ssl.h"));
        assert!(is_relevant("./build/libfoo.a"));
        assert!(is_relevant("src/main.cpp"));
    }

    #[test]
    fn shared_library_names() {
        assert!(is_shared_library_name("libfoo.so"));
        assert!(is_shared_library_name("libssl.so.3"));
        assert!(is_shared_library_name("libbfd-2.42-system.so"));
        assert!(!is_shared_library_name("ld.so.cache"));
        assert!(!is_shared_library_name("ld.so.conf"));
        assert!(!is_shared_library_name("ld.so.conf.d"));
        assert!(!is_shared_library_name("libfoo.sock"));
        assert!(!is_relevant("/etc/ld.so.cache"));
    }

    #[test]
    fn normalizes_dotdot() {
        let cwd = Path::new("/home/user/project");
        let got = normalize("../other/lib.so", cwd);
        assert_eq!(got, PathBuf::from("/home/user/other/lib.so"));
    }
}

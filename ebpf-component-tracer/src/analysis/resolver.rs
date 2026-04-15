//! Path normalization and noise filtering.
//!
//! The tracing layer captures *every* `openat` call made by tracked processes,
//! including temporary files, proc entries, and pipes.  This module keeps
//! only the paths that are relevant for SCA.

use std::path::{Path, PathBuf};

/// Extensions relevant for SCA: libraries, headers, and local source files.
/// Object files (.o) and build-system outputs are excluded.
const RELEVANT_EXTENSIONS: &[&str] = &["so", "a", "h", "hpp", "hxx", "c", "cpp", "cxx", "cc"];

/// Path prefixes we consider "system" (package-manager-owned).
/// NOTE: /usr/local/ is intentionally excluded — files there are manually
/// installed and not tracked by dpkg/pacman/rpm.
pub const SYSTEM_PREFIXES: &[&str] = &["/usr/lib", "/usr/include", "/lib/", "/lib64/"];

/// Path prefixes we always ignore (kernel virtual fs, pipe artefacts, …).
const NOISE_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/",
    "pipe:",
    "socket:",
    "anon_inode:",
];

/// Returns `true` if the path is worth recording.
pub fn is_relevant(raw: &str) -> bool {
    if raw.is_empty() {
        return false;
    }

    // Drop kernel virtual-fs paths and other noise.
    for prefix in NOISE_PREFIXES {
        if raw.starts_with(prefix) {
            return false;
        }
    }

    // Keep only files with relevant extensions.
    // Versioned shared libraries (e.g. libssl.so.3, libfoo.so.1.2.3) have
    // their last extension as a version number, so we check the whole filename
    // for a ".so" component in addition to the last extension.
    let path = Path::new(raw);
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Match `*.so` or `*.so.<version>` (e.g. libssl.so.3).
    if filename.contains(".so") {
        return true;
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => RELEVANT_EXTENSIONS.contains(&ext),
        None => false,
    }
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
    fn normalizes_dotdot() {
        let cwd = Path::new("/home/user/project");
        let got = normalize("../other/lib.so", cwd);
        assert_eq!(got, PathBuf::from("/home/user/other/lib.so"));
    }
}

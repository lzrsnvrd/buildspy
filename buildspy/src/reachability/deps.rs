//! Shared-library dependency resolution — Phase 2, Level 2.
//!
//! Collects the transitive `DT_NEEDED` closure of an ELF binary so each `.so`
//! can be fed through [`ElfExtractor`](super::elf::ElfExtractor) and merged into
//! the shared call graph. This lets BFS from `main` cross the `.so` boundary via
//! the public API contour (e.g. `curl_easy_perform → SSL_connect`, both
//! exported).
//!
//! Resolution mirrors the dynamic linker's search order (best effort, no cache
//! parsing): `DT_RPATH` (only when `DT_RUNPATH` is absent) → `LD_LIBRARY_PATH`
//! → `DT_RUNPATH` → `/etc/ld.so.conf` dirs → standard multiarch dirs, with
//! `$ORIGIN` expanded relative to the object being processed.
//!
//! This is intentionally Level 2 only — no debuginfo/debuginfod fetching. The
//! precision ceiling inside a stripped `.so` is set by the absence of bitcode
//! (function-pointer dispatch stays `Unknown`), not by missing symbols, so
//! `.dynsym` alone is the right stopping point here.

use std::{
    collections::{HashSet, VecDeque},
    path::{Path, PathBuf},
};

use goblin::elf::Elf;

/// Collect the transitive `DT_NEEDED` closure of `binary`.
///
/// Returns canonicalized `.so` paths, deduplicated, **excluding** `binary`
/// itself. Unresolvable or unreadable entries are logged and skipped rather
/// than failing the whole walk.
pub fn collect_so_closure(binary: &Path) -> Vec<PathBuf> {
    let std_dirs = standard_lib_dirs();
    let ld_library_path = env_dirs("LD_LIBRARY_PATH");

    let root = canonical(binary);
    // `visited` holds canonical paths already queued/processed, seeded with the
    // root so it is walked for its needs but never emitted as a dependency.
    let mut visited: HashSet<PathBuf> = HashSet::from([root.clone()]);
    let mut queue: VecDeque<PathBuf> = VecDeque::from([root]);
    let mut result: Vec<PathBuf> = Vec::new();

    while let Some(obj) = queue.pop_front() {
        let data = match std::fs::read(&obj) {
            Ok(d) => d,
            Err(e) => {
                log::debug!("reachability: cannot read {}: {e}", obj.display());
                continue;
            }
        };
        let elf = match Elf::parse(&data) {
            Ok(e) => e,
            Err(e) => {
                // Non-ELF (e.g. an LLVM bitcode artifact) — nothing to follow.
                log::debug!("reachability: cannot parse {} as ELF: {e}", obj.display());
                continue;
            }
        };

        let obj_dir = obj.parent();
        let search = search_dirs(&elf, obj_dir, &ld_library_path, &std_dirs);

        for soname in &elf.libraries {
            match resolve(soname, &search) {
                Some(path) => {
                    let cp = canonical(&path);
                    if visited.insert(cp.clone()) {
                        result.push(cp.clone());
                        queue.push_back(cp);
                    }
                }
                None => {
                    log::debug!(
                        "reachability: could not resolve DT_NEEDED '{soname}' for {}",
                        obj.display()
                    );
                }
            }
        }
    }

    result
}

/// Build the ordered search-dir list for one object's `DT_NEEDED` entries.
fn search_dirs(
    elf: &Elf,
    obj_dir: Option<&Path>,
    ld_library_path: &[PathBuf],
    std_dirs: &[PathBuf],
) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    // DT_RPATH is consulted only when DT_RUNPATH is absent (linker semantics).
    if elf.runpaths.is_empty() {
        dirs.extend(expand_origin(&elf.rpaths, obj_dir));
    }
    dirs.extend_from_slice(ld_library_path);
    dirs.extend(expand_origin(&elf.runpaths, obj_dir));
    dirs.extend_from_slice(std_dirs);
    dirs
}

/// First `dir/soname` that exists. Sonames containing a slash are treated as
/// paths, matching the loader.
fn resolve(soname: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    if soname.contains('/') {
        let p = PathBuf::from(soname);
        return p.is_file().then_some(p);
    }
    dirs.iter()
        .map(|d| d.join(soname))
        .find(|c| c.is_file())
}

/// Expand `$ORIGIN` / `${ORIGIN}` (to the object's directory) and split each
/// colon-separated `rpath`/`runpath` entry into individual dirs.
fn expand_origin(paths: &[&str], obj_dir: Option<&Path>) -> Vec<PathBuf> {
    let origin = obj_dir
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    paths
        .iter()
        .flat_map(|p| p.split(':'))
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(p.replace("${ORIGIN}", &origin).replace("$ORIGIN", &origin)))
        .collect()
}

fn env_dirs(var: &str) -> Vec<PathBuf> {
    std::env::var_os(var)
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default()
}

/// Standard loader directories: `/etc/ld.so.conf` (+ its includes) plus the
/// usual multiarch fallbacks. Missing/parse-failed config still yields the
/// hard-coded defaults.
fn standard_lib_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    parse_ld_so_conf(Path::new("/etc/ld.so.conf"), &mut dirs, 0);
    for d in [
        "/lib",
        "/usr/lib",
        "/lib64",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ] {
        let p = PathBuf::from(d);
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    dirs
}

/// Parse an `ld.so.conf`-style file: bare lines are directories, `include
/// <glob>` pulls in more files. Bounded recursion guards against include loops.
fn parse_ld_so_conf(path: &Path, out: &mut Vec<PathBuf>, depth: u32) {
    if depth > 16 {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(glob) = line.strip_prefix("include ").map(str::trim) {
            for inc in expand_conf_glob(glob) {
                parse_ld_so_conf(&inc, out, depth + 1);
            }
        } else {
            let p = PathBuf::from(line);
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
}

/// Expand a single `include` glob. Handles an exact path or a `dir/<prefix>*<suffix>`
/// pattern (as used by `/etc/ld.so.conf.d/*.conf`); other patterns are ignored.
fn expand_conf_glob(pattern: &str) -> Vec<PathBuf> {
    let path = Path::new(pattern);
    let (Some(parent), Some(file)) = (path.parent(), path.file_name().and_then(|f| f.to_str()))
    else {
        return Vec::new();
    };
    let Some(star) = file.find('*') else {
        // No wildcard: exact include path.
        return if path.is_file() {
            vec![path.to_path_buf()]
        } else {
            Vec::new()
        };
    };
    let (prefix, suffix) = (&file[..star], &file[star + 1..]);
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .map(|f| f.starts_with(prefix) && f.ends_with(suffix) && f.len() >= prefix.len() + suffix.len())
                .unwrap_or(false)
        })
        .collect()
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

//! Shared-library dependency resolution: the transitive `DT_NEEDED` closure of
//! ELF binaries, i.e. what `ldd` would list — without running the loader.
//!
//! Used by the SBOM (runtime dependencies of the build's artifacts, which the
//! linker never opens when it produces a `.so`) and by reachability Level 2
//! (each `.so` of the closure is merged into the call graph).
//!
//! Resolution mirrors the dynamic linker's search order (best effort, no cache
//! parsing): `DT_RPATH` (only when `DT_RUNPATH` is absent) → `LD_LIBRARY_PATH`
//! → `DT_RUNPATH` → `/etc/ld.so.conf` dirs → standard multiarch dirs, with
//! `$ORIGIN` expanded relative to the object being processed.  Like the loader,
//! a candidate whose ELF class or machine differs from the object that needs it
//! is skipped: on a multiarch system `/etc/ld.so.conf.d/i386-linux-gnu.conf`
//! sorts before the x86_64 one, so the first existing file is often the i386
//! copy.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
};

use goblin::elf::Elf;

// ---------------------------------------------------------------------------
// ELF identity
// ---------------------------------------------------------------------------

/// `ET_EXEC` — a non-PIE executable.
pub const ET_EXEC: u16 = 2;
/// `ET_DYN` — a shared library or PIE executable.
pub const ET_DYN: u16 = 3;

/// Word size and target machine: two objects can only be loaded together
/// when these match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ElfKind {
    pub is_64: bool,
    pub machine: u16,
}

/// The few ELF header fields needed to classify a file.
#[derive(Clone, Copy, Debug)]
pub struct ElfHeader {
    pub kind: ElfKind,
    /// `e_type`: [`ET_EXEC`], [`ET_DYN`], `ET_REL` (object file), …
    pub e_type: u16,
}

/// Read just the ELF header of `path` — 20 bytes, so it is cheap to call on
/// every file a build touched.  `None` for anything that is not ELF.
pub fn read_elf_header(path: &Path) -> Option<ElfHeader> {
    use std::io::Read;
    let mut buf = [0u8; 20];
    std::fs::File::open(path).ok()?.read_exact(&mut buf).ok()?;
    if buf[..4] != *b"\x7fELF" {
        return None;
    }
    let is_64 = match buf[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let half = |at: usize| match buf[5] {
        2 => u16::from_be_bytes([buf[at], buf[at + 1]]),
        _ => u16::from_le_bytes([buf[at], buf[at + 1]]),
    };
    Some(ElfHeader { kind: ElfKind { is_64, machine: half(18) }, e_type: half(16) })
}

/// The kind of the running buildspy binary — the architecture the build's own
/// tools (compilers, linkers) run as.
pub fn host_kind() -> Option<ElfKind> {
    read_elf_header(Path::new("/proc/self/exe")).map(|h| h.kind)
}

// ---------------------------------------------------------------------------
// Closure
// ---------------------------------------------------------------------------

/// Collect the transitive `DT_NEEDED` closure of `binary`.
///
/// Returns canonicalized `.so` paths, deduplicated, **excluding** `binary`
/// itself. Unresolvable or unreadable entries are logged and skipped rather
/// than failing the whole walk.
pub fn collect_so_closure(binary: &Path) -> Vec<PathBuf> {
    collect_closure(&[binary.to_path_buf()])
}

/// [`collect_so_closure`] over several binaries at once, sharing one walk so a
/// library needed by many of them is parsed once.  The roots themselves are
/// never emitted, even when one needs another.
///
/// A soname provided by one of the roots resolves to that root before any
/// search dir: libtool and CMake run uninstalled binaries against the build
/// tree (a wrapper's `LD_LIBRARY_PATH`, a build-tree `RUNPATH`), not against,
/// say, a stale `/usr/local/lib` install of the same project.
pub fn collect_closure(binaries: &[PathBuf]) -> Vec<PathBuf> {
    let std_dirs = standard_lib_dirs();
    let ld_library_path = env_dirs("LD_LIBRARY_PATH");

    let roots: Vec<PathBuf> = binaries.iter().map(|b| canonical(b)).collect();
    let built = sonames_of(&roots);
    // `visited` holds canonical paths already queued/processed, seeded with the
    // roots so they are walked for their needs but never emitted as a dependency.
    let mut visited: HashSet<PathBuf> = roots.iter().cloned().collect();
    let mut queue: VecDeque<PathBuf> = roots.into_iter().collect();
    let mut result: Vec<PathBuf> = Vec::new();

    while let Some(obj) = queue.pop_front() {
        let data = match std::fs::read(&obj) {
            Ok(d) => d,
            Err(e) => {
                log::debug!("deps: cannot read {}: {e}", obj.display());
                continue;
            }
        };
        let elf = match Elf::parse(&data) {
            Ok(e) => e,
            Err(e) => {
                // Non-ELF (e.g. an LLVM bitcode artifact) — nothing to follow.
                log::debug!("deps: cannot parse {} as ELF: {e}", obj.display());
                continue;
            }
        };

        let obj_dir = obj.parent();
        let search = search_dirs(&elf, obj_dir, &ld_library_path, &std_dirs);
        let kind = ElfKind { is_64: elf.is_64, machine: elf.header.e_machine };

        for soname in &elf.libraries {
            let own = built.get(&(soname.to_string(), kind)).cloned();
            match own.or_else(|| resolve(soname, &search, kind)) {
                Some(path) => {
                    let cp = canonical(&path);
                    if visited.insert(cp.clone()) {
                        result.push(cp.clone());
                        queue.push_back(cp);
                    }
                }
                None => {
                    log::debug!(
                        "deps: could not resolve DT_NEEDED '{soname}' for {}",
                        obj.display()
                    );
                }
            }
        }
    }

    result
}

/// `DT_SONAME` → path for the shared libraries among `objects`.
fn sonames_of(objects: &[PathBuf]) -> HashMap<(String, ElfKind), PathBuf> {
    let mut map = HashMap::new();
    for obj in objects {
        let Ok(data) = std::fs::read(obj) else { continue };
        let Ok(elf) = Elf::parse(&data) else { continue };
        if let Some(soname) = elf.soname {
            let kind = ElfKind { is_64: elf.is_64, machine: elf.header.e_machine };
            map.entry((soname.to_string(), kind)).or_insert_with(|| obj.clone());
        }
    }
    map
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

/// First `dir/soname` that is an ELF file of the requesting object's `kind`.
/// Sonames containing a slash are treated as paths, matching the loader.
fn resolve(soname: &str, dirs: &[PathBuf], kind: ElfKind) -> Option<PathBuf> {
    let loadable = |p: &Path| read_elf_header(p).is_some_and(|h| h.kind == kind);
    if soname.contains('/') {
        let p = PathBuf::from(soname);
        return loadable(&p).then_some(p);
    }
    dirs.iter()
        .map(|d| d.join(soname))
        .find(|c| loadable(c))
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
    // Sorted like the shell glob ldconfig uses, so the search order — and with
    // it which of two same-kind copies wins — is stable across runs.
    let mut matches: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .map(|f| f.starts_with(prefix) && f.ends_with(suffix) && f.len() >= prefix.len() + suffix.len())
                .unwrap_or(false)
        })
        .collect();
    matches.sort();
    matches
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

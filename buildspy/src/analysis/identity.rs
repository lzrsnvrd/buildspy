//! Component identity resolution.
//!
//! Given a file path:
//!  * **System paths** (`/usr/`, `/lib/`, …) → query the local package manager
//!    and return package name + version.
//!  * **Local paths** → compute a SHA-256 hash as a stable identifier.
//!    For files inside a Meson `subprojects/` directory the engine also
//!    enriches the identity with name, version, and VCS URL extracted from
//!    the corresponding `.wrap` file.
//!
//! For dpkg systems the database is read directly from
//! `/var/lib/dpkg/info/*.list` and `/var/lib/dpkg/status` at startup,
//! building an in-memory index.  Subsequent lookups are O(1) with no
//! subprocess overhead.  pacman and rpm fall back to subprocess calls.
//!
//! All look-ups are cached so the same path is never resolved twice.

use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::Path,
    process::Command,
    sync::Mutex,
};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ComponentIdentity {
    /// Owned by the system package manager.
    SystemPackage {
        name: String,
        version: String,
        /// Architecture from the dpkg key (e.g. `"amd64"`, `"i386"`).
        /// `None` for arch-independent packages (Architecture: all).
        arch: Option<String>,
        /// Upstream source package name when it differs from the binary name.
        /// E.g. binary `"libc6"` → source `"glibc"`.
        /// `None` if source == binary name (most -dev packages).
        src_name: Option<String>,
    },
    /// Local / vendored file; identified by SHA-256.
    ///
    /// `name_hint`, `version_hint`, and `vcs_url` are populated when the
    /// file is recognized as part of a Meson subproject (via `.wrap` metadata
    /// or directory-name heuristics).
    LocalFile {
        hash: String,
        /// Library name from the `.wrap` file or directory-name heuristic.
        name_hint: Option<String>,
        /// Upstream version from `revision`/`directory` in the `.wrap` file.
        version_hint: Option<String>,
        /// VCS or download URL from the `.wrap` file, if present.
        vcs_url: Option<String>,
    },
    /// Path exists on a system prefix but the package manager couldn't
    /// identify it (e.g. manually installed file).
    UnknownSystem,
}

// ---------------------------------------------------------------------------
// Package-manager detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Dpkg,
    Pacman,
    Rpm,
    None,
}

fn detect_package_manager() -> PackageManager {
    for (cmd, pm) in &[
        ("dpkg",   PackageManager::Dpkg),
        ("pacman", PackageManager::Pacman),
        ("rpm",    PackageManager::Rpm),
    ] {
        if Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return *pm;
        }
    }
    PackageManager::None
}

// ---------------------------------------------------------------------------
// DpkgIndex – in-memory dpkg database
// ---------------------------------------------------------------------------

/// In-memory index built from `/var/lib/dpkg/info/*.list` and
/// `/var/lib/dpkg/status`.  Replaces subprocess calls to `dpkg -S` /
/// `dpkg-query -W` with O(1) HashMap lookups.
struct DpkgIndex {
    /// Absolute file path → "pkgname:arch" key.
    path_to_pkg: HashMap<String, String>,
    /// "pkgname:arch" → version string.
    pkg_to_version: HashMap<String, String>,
    /// "pkgname:arch" → upstream source package name.
    pkg_to_src: HashMap<String, String>,
}

impl DpkgIndex {
    fn load() -> Option<Self> {
        let (pkg_to_version, pkg_to_src) = Self::load_versions().ok()?;
        let path_to_pkg = Self::load_paths().ok()?;
        log::debug!(
            "DpkgIndex: {} paths, {} packages, {} with upstream source",
            path_to_pkg.len(),
            pkg_to_version.len(),
            pkg_to_src.len(),
        );
        Some(Self { path_to_pkg, pkg_to_version, pkg_to_src })
    }

    fn load_versions() -> std::io::Result<(HashMap<String, String>, HashMap<String, String>)> {
        let content = fs::read_to_string("/var/lib/dpkg/status")?;
        let mut versions: HashMap<String, String> = HashMap::new();
        let mut sources: HashMap<String, String> = HashMap::new();

        let mut pkg = String::new();
        let mut arch = String::new();
        let mut version = String::new();
        let mut source = String::new();

        for line in content.lines() {
            if line.is_empty() {
                if !pkg.is_empty() && !version.is_empty() {
                    let key = if arch.is_empty() || arch == "all" {
                        pkg.clone()
                    } else {
                        format!("{}:{}", pkg, arch)
                    };
                    versions.insert(key.clone(), version.clone());
                    if !source.is_empty() && source != pkg {
                        sources.insert(key, source.clone());
                    }
                }
                pkg.clear(); arch.clear(); version.clear(); source.clear();
            } else if let Some(v) = line.strip_prefix("Package: ") {
                pkg = v.to_string();
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = v.to_string();
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = v.to_string();
            } else if let Some(v) = line.strip_prefix("Source: ") {
                source = v.split_whitespace().next().unwrap_or(v).to_string();
            }
        }
        if !pkg.is_empty() && !version.is_empty() {
            let key = if arch.is_empty() || arch == "all" {
                pkg.clone()
            } else {
                format!("{}:{}", pkg, arch)
            };
            versions.insert(key.clone(), version);
            if !source.is_empty() && source != pkg {
                sources.insert(key, source);
            }
        }

        Ok((versions, sources))
    }

    fn load_paths() -> std::io::Result<HashMap<String, String>> {
        let info_dir = Path::new("/var/lib/dpkg/info");
        let mut map = HashMap::new();

        for entry in fs::read_dir(info_dir)?.flatten() {
            let fpath = entry.path();
            if fpath.extension().and_then(|e| e.to_str()) != Some("list") {
                continue;
            }
            let stem = match fpath.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let Ok(content) = fs::read_to_string(&fpath) else {
                continue;
            };
            for line in content.lines() {
                if line.is_empty() || line == "/." {
                    continue;
                }
                if line.starts_with('/') {
                    map.insert(line.to_string(), stem.clone());
                }
            }
        }

        Ok(map)
    }

    fn lookup(&self, path: &str) -> Option<(String, String, Option<String>, Option<String>)> {
        let pkg_key = self.path_to_pkg.get(path)?;
        let mut parts = pkg_key.splitn(2, ':');
        let pkg_name = parts.next().unwrap_or(pkg_key).to_string();
        let arch = parts.next().map(str::to_string);
        let version = self.pkg_to_version
            .get(pkg_key.as_str())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let src_name = self.pkg_to_src.get(pkg_key.as_str()).cloned();
        Some((pkg_name, version, arch, src_name))
    }
}

// ---------------------------------------------------------------------------
// MesonSubprojectIndex – identify vendored subprojects by their .wrap files
// ---------------------------------------------------------------------------

/// Metadata extracted from a single Meson wrap file.
struct SubprojectEntry {
    /// Canonical library name (wrap filename stem, e.g. `"zlib"`).
    name: String,
    /// Upstream version, if determinable.
    version: Option<String>,
    /// VCS or download URL from the wrap file.
    vcs_url: Option<String>,
}

/// Index built from `<project_dir>/subprojects/*.wrap` at startup.
///
/// Lookup: given any file path, find `subprojects/<dirname>/` as a component
/// and return the matching `SubprojectEntry`.
struct MesonSubprojectIndex {
    /// Maps the subproject directory name (e.g. `"zlib-1.3.1"`) to its entry.
    by_dirname: HashMap<String, SubprojectEntry>,
}

impl MesonSubprojectIndex {
    fn load(project_dir: &Path) -> Self {
        let wrap_dir = project_dir.join("subprojects");
        let mut by_dirname: HashMap<String, SubprojectEntry> = HashMap::new();

        let Ok(entries) = fs::read_dir(&wrap_dir) else {
            return Self { by_dirname };
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wrap") {
                continue;
            }
            let wrap_name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let Ok(content) = fs::read_to_string(&path) else { continue };

            let parsed = parse_wrap_file(&content);
            // The directory the subproject unpacks into; fall back to wrap name.
            let dirname = parsed.directory
                .as_deref()
                .unwrap_or(&wrap_name)
                .to_string();

            // Version priority:
            //   wrap-git with tag:  revision (e.g. "v3.4.0") → strip leading 'v'
            //   wrap-file:          source_filename stem (e.g. "zlib-1.2.13.tar.gz")
            //   directory heuristic: dirname suffix (e.g. "zlib-1.2.13")
            //   wrap-git with HEAD: read actual commit hash from cloned .git/HEAD
            let version = parsed.revision
                .as_deref()
                .and_then(version_from_revision)
                .or_else(|| {
                    parsed.source_filename
                        .as_deref()
                        .and_then(version_from_source_filename)
                })
                .or_else(|| version_from_dirname(&dirname))
                .or_else(|| read_git_head_commit(&wrap_dir.join(&dirname)));

            let vcs_url = parsed.url.or(parsed.source_url);

            log::debug!(
                "meson wrap: {} dir={} ver={:?} url={:?}",
                wrap_name, dirname, version, vcs_url
            );

            by_dirname.insert(dirname, SubprojectEntry {
                name: wrap_name,
                version,
                vcs_url,
            });
        }

        log::debug!("MesonSubprojectIndex: {} subprojects", by_dirname.len());
        Self { by_dirname }
    }

    /// Returns the `SubprojectEntry` if `path` lives inside a known
    /// `subprojects/<dirname>/` directory (at any nesting level).
    fn lookup(&self, path: &Path) -> Option<&SubprojectEntry> {
        let components: Vec<_> = path.components().collect();
        for i in 0..components.len().saturating_sub(1) {
            if components[i].as_os_str() == "subprojects" {
                let dirname = components[i + 1].as_os_str().to_str()?;
                if let Some(entry) = self.by_dirname.get(dirname) {
                    return Some(entry);
                }
                // Not in the wrap index — try directory-name heuristic.
                // We return a synthetic entry stored inline below.
            }
        }
        None
    }

    /// Like `lookup`, but also applies the directory-name heuristic for
    /// subprojects that have no `.wrap` file (e.g. git submodules).
    fn lookup_with_fallback(&self, path: &Path) -> Option<(String, Option<String>, Option<String>)> {
        if let Some(entry) = self.lookup(path) {
            return Some((entry.name.clone(), entry.version.clone(), entry.vcs_url.clone()));
        }
        // Heuristic: find subprojects/<dirname>/ in path and parse dirname.
        let components: Vec<_> = path.components().collect();
        for i in 0..components.len().saturating_sub(1) {
            if components[i].as_os_str() == "subprojects" {
                let dirname = components[i + 1].as_os_str().to_str()?;
                let version = version_from_dirname(dirname);
                let name = name_from_dirname(dirname).to_string();
                return Some((name, version, None));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// .wrap file parser (simple INI)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ParsedWrap {
    directory: Option<String>,
    /// git URL (wrap-git)
    url: Option<String>,
    /// git tag or commit (wrap-git)
    revision: Option<String>,
    /// download URL (wrap-file)
    source_url: Option<String>,
    /// archive filename (wrap-file), e.g. "zlib-1.2.13.tar.gz"
    source_filename: Option<String>,
}

fn parse_wrap_file(content: &str) -> ParsedWrap {
    let mut out = ParsedWrap::default();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') || line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            match key {
                "directory"       => out.directory        = Some(val.to_string()),
                "url"             => out.url              = Some(val.to_string()),
                "revision"        => out.revision         = Some(val.to_string()),
                "source_url"      => out.source_url       = Some(val.to_string()),
                "source_filename" => out.source_filename  = Some(val.to_string()),
                _ => {}
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Version / name helpers
// ---------------------------------------------------------------------------

/// Extract version from a revision field like `"v1.3.1"`, `"1.3.1"`.
/// Returns `None` for bare commit hashes.
fn version_from_revision(revision: &str) -> Option<String> {
    let v = revision.trim_start_matches('v');
    if looks_like_version(v) { Some(v.to_string()) } else { None }
}

/// Read the checked-out commit hash from a subproject's `.git/HEAD`.
///
/// Handles both detached HEAD (bare hash) and symbolic refs (`ref: refs/heads/main`).
/// Returns the first 12 hex characters, which is enough to identify a commit.
/// Returns `None` if the directory is not a git repo or the file is unreadable.
fn read_git_head_commit(subproject_dir: &Path) -> Option<String> {
    let content = fs::read_to_string(subproject_dir.join(".git/HEAD")).ok()?;
    let content = content.trim();
    // Detached HEAD: the file contains the hash directly.
    if is_hex_hash(content) {
        return Some(content[..12].to_string());
    }
    // Symbolic ref: "ref: refs/heads/main" → read the ref file.
    if let Some(refname) = content.strip_prefix("ref: ") {
        let hash = fs::read_to_string(
            subproject_dir.join(".git").join(refname.trim()),
        ).ok()?;
        let hash = hash.trim();
        if is_hex_hash(hash) {
            return Some(hash[..12].to_string());
        }
    }
    None
}

fn is_hex_hash(s: &str) -> bool {
    s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract version from an archive filename like `"zlib-1.2.13.tar.gz"`.
/// Strips known archive suffixes, then delegates to `version_from_dirname`.
fn version_from_source_filename(filename: &str) -> Option<String> {
    let stem = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".tar.xz"))
        .or_else(|| filename.strip_suffix(".tar.bz2"))
        .or_else(|| filename.strip_suffix(".tar.zst"))
        .or_else(|| filename.strip_suffix(".zip"))
        .unwrap_or(filename);
    version_from_dirname(stem)
}

/// Extract version from a directory name like `"zlib-1.3.1"` → `"1.3.1"`.
fn version_from_dirname(dirname: &str) -> Option<String> {
    // Find the rightmost '-' whose suffix looks like a version number.
    let mut last = None;
    for (i, c) in dirname.char_indices() {
        if c == '-' {
            last = Some(i);
        }
    }
    let idx = last?;
    let candidate = &dirname[idx + 1..];
    if looks_like_version(candidate) { Some(candidate.to_string()) } else { None }
}

/// Strip the version suffix to recover the library name.
/// `"zlib-1.3.1"` → `"zlib"`, `"openssl-3.0.7"` → `"openssl"`.
/// Falls back to the full dirname if no version suffix is found.
fn name_from_dirname(dirname: &str) -> &str {
    let mut last = None;
    for (i, c) in dirname.char_indices() {
        if c == '-' {
            last = Some(i);
        }
    }
    if let Some(idx) = last {
        let candidate = &dirname[idx + 1..];
        if looks_like_version(candidate) {
            return &dirname[..idx];
        }
    }
    dirname
}

/// Returns `true` if `s` looks like a semver/version string (starts with a
/// digit, contains only digits, dots, hyphens, and plus signs).
fn looks_like_version(s: &str) -> bool {
    !s.is_empty()
        && s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '+')
}

// ---------------------------------------------------------------------------
// IdentityEngine
// ---------------------------------------------------------------------------

/// Thread-safe engine that resolves file paths to component identities.
pub struct IdentityEngine {
    pkg_manager: PackageManager,
    dpkg_index: Option<DpkgIndex>,
    meson_index: MesonSubprojectIndex,
    cache: Mutex<HashMap<String, Option<(String, String, Option<String>, Option<String>)>>>,
}

impl IdentityEngine {
    pub fn new(project_dir: &Path) -> Self {
        let pkg_manager = detect_package_manager();
        let dpkg_index = if pkg_manager == PackageManager::Dpkg {
            DpkgIndex::load()
        } else {
            None
        };
        let meson_index = MesonSubprojectIndex::load(project_dir);
        Self { pkg_manager, dpkg_index, meson_index, cache: Mutex::new(HashMap::new()) }
    }

    /// Returns `true` if `path` lives inside a known Meson subproject directory.
    pub fn is_in_meson_subproject(&self, path: &Path) -> bool {
        self.meson_index.lookup_with_fallback(path).is_some()
    }

    pub fn identify(&self, path: &Path) -> ComponentIdentity {
        if super::resolver::is_system_path(path) {
            self.identify_system(path)
        } else {
            self.identify_local(path)
        }
    }

    fn identify_system(&self, path: &Path) -> ComponentIdentity {
        let key = path.to_string_lossy().to_string();

        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&key) {
                return match entry {
                    Some((name, ver, arch, src)) => ComponentIdentity::SystemPackage {
                        name: name.clone(),
                        version: ver.clone(),
                        arch: arch.clone(),
                        src_name: src.clone(),
                    },
                    None => ComponentIdentity::UnknownSystem,
                };
            }
        }

        let result = self.query_package_manager(&key);

        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(key, result.clone());
        }

        match result {
            Some((name, version, arch, src_name)) => {
                ComponentIdentity::SystemPackage { name, version, arch, src_name }
            }
            None => ComponentIdentity::UnknownSystem,
        }
    }

    fn query_package_manager(
        &self,
        path: &str,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
        match self.pkg_manager {
            PackageManager::Dpkg   => self.query_dpkg(path),
            PackageManager::Pacman => self.query_pacman(path),
            PackageManager::Rpm    => self.query_rpm(path),
            PackageManager::None   => None,
        }
    }

    fn query_dpkg(&self, path: &str) -> Option<(String, String, Option<String>, Option<String>)> {
        if let Some(index) = &self.dpkg_index {
            return self.query_dpkg_indexed(path, index);
        }
        self.query_dpkg_subprocess(path)
    }

    /// O(1) lookup in the in-memory dpkg index.
    ///
    /// On merged-usr systems `/lib` is a symlink to `usr/lib`, so the dynamic
    /// linker may open e.g. `/lib/x86_64-linux-gnu/libc.so.6` while dpkg
    /// records the file as `/usr/lib/x86_64-linux-gnu/libc.so.6`.  When the
    /// direct lookup fails we resolve symlinks once and retry.
    fn query_dpkg_indexed(
        &self,
        path: &str,
        index: &DpkgIndex,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
        if let Some(result) = index.lookup(path) {
            return Some(result);
        }
        let canonical = fs::canonicalize(path).ok()?;
        let canonical_str = canonical.to_str()?;
        if canonical_str == path {
            return None;
        }
        index.lookup(canonical_str)
    }

    fn query_dpkg_subprocess(
        &self,
        path: &str,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
        self.query_dpkg_single(path).or_else(|| {
            let canonical = fs::canonicalize(path).ok()?;
            let canonical_str = canonical.to_str()?;
            if canonical_str == path {
                return None;
            }
            self.query_dpkg_single(canonical_str)
        })
    }

    fn query_dpkg_single(
        &self,
        path: &str,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
        let out = Command::new("dpkg").args(["-S", path]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let ownership_line = stdout
            .lines()
            .find(|l| !l.trim_start().starts_with("diversion"))?;
        let pkg_with_arch = ownership_line.splitn(2, ": ").next()?.trim().to_string();
        let mut parts = pkg_with_arch.splitn(2, ':');
        let pkg_name = parts.next().unwrap_or(&pkg_with_arch).to_string();
        let arch = parts.next().map(str::to_string);
        let ver_out = Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", &pkg_with_arch])
            .output()
            .ok()?;
        if !ver_out.status.success() {
            return Some((pkg_name, "unknown".to_string(), arch, None));
        }
        let version = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();
        Some((pkg_name, version, arch, None))
    }

    fn query_pacman(
        &self,
        path: &str,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
        let out = Command::new("pacman").args(["-Qo", path]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let parts: Vec<&str> = stdout.split_whitespace().collect();
        let owned_idx = parts.iter().position(|&w| w == "owned")?;
        let name = parts.get(owned_idx + 2)?.to_string();
        let version = parts.get(owned_idx + 3)?.to_string();
        Some((name, version, None, None))
    }

    fn query_rpm(
        &self,
        path: &str,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
        let out = Command::new("rpm")
            .args(["-qf", path, "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut parts = stdout.trim().splitn(2, ' ');
        let name = parts.next()?.to_string();
        let version = parts.next().unwrap_or("unknown").to_string();
        Some((name, version, None, None))
    }

    fn identify_local(&self, path: &Path) -> ComponentIdentity {
        let hash = compute_sha256(path).unwrap_or_else(|| "sha256:error".to_string());
        let (name_hint, version_hint, vcs_url) = if let Some(result) = self.meson_index.lookup_with_fallback(path) {
            let (n, v, u) = result;
            (Some(n), v, u)
        } else {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filename.contains(".so") {
                let (name, version) = soname_name_version(path);
                (name, version, None)
            } else {
                (None, None, None)
            }
        };
        ComponentIdentity::LocalFile { hash, name_hint, version_hint, vcs_url }
    }
}

// ---------------------------------------------------------------------------
// .so filename parser
// ---------------------------------------------------------------------------

/// Extract library name and full version from a shared-library path.
///
/// Resolves symlinks before parsing so that `libmsquic.so.2` (a symlink to
/// `libmsquic.so.2.4.1`) yields version `"2.4.1"` rather than just `"2"`.
///
/// `libssl.so.3.0.0`  → (`Some("ssl")`,    `Some("3.0.0")`)
/// `libfoo-bar.so`    → (`Some("foo-bar")`, `None`)
fn soname_name_version(path: &Path) -> (Option<String>, Option<String>) {
    // Resolve symlink to get the real filename (best-effort).
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let filename = real
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let Some(so_pos) = filename.find(".so") else {
        return (None, None);
    };

    let base = &filename[..so_pos]; // e.g. "libssl", "libfoo-bar"
    let name = base.strip_prefix("lib").unwrap_or(base);
    if name.is_empty() {
        return (None, None);
    }

    // Version is the suffix after ".so." if it starts with a digit.
    let after_so = &filename[so_pos + 3..]; // everything after ".so"
    let version = after_so
        .strip_prefix('.')
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .map(str::to_string);

    (Some(name.to_string()), version)
}

// ---------------------------------------------------------------------------
// SHA-256 helper
// ---------------------------------------------------------------------------

pub fn compute_sha256(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Some(format!("sha256:{}", hex::encode(digest)))
}

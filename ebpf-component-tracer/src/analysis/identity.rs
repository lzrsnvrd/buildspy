//! Component identity resolution.
//!
//! Given a file path:
//!  * **System paths** (`/usr/`, `/lib/`, …) → query the local package manager
//!    and return package name + version.
//!  * **Local paths** → compute a SHA-256 hash as a stable identifier.
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
    LocalFile {
        hash: String,
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
// IdentityEngine
// ---------------------------------------------------------------------------

/// Thread-safe engine that resolves file paths to component identities.
pub struct IdentityEngine {
    pkg_manager: PackageManager,
    dpkg_index: Option<DpkgIndex>,
    cache: Mutex<HashMap<String, Option<(String, String, Option<String>, Option<String>)>>>,
}

impl IdentityEngine {
    pub fn new() -> Self {
        let pkg_manager = detect_package_manager();
        let dpkg_index = if pkg_manager == PackageManager::Dpkg {
            DpkgIndex::load()
        } else {
            None
        };
        Self { pkg_manager, dpkg_index, cache: Mutex::new(HashMap::new()) }
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
        ComponentIdentity::LocalFile { hash }
    }
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

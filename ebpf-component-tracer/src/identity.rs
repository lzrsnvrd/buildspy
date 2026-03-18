//! Component identity resolution.
//!
//! Given a file path:
//!  * **System paths** (`/usr/`, `/lib/`, …) → query the local package manager
//!    (`dpkg -S`, `pacman -Qo`, or `rpm -qf`) and return package name + version.
//!  * **Local paths** → compute a SHA-256 hash as a stable identifier.
//!
//! All package-manager look-ups are cached in memory so that the same shared
//! library does not trigger hundreds of subprocess invocations.

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
// IdentityEngine
// ---------------------------------------------------------------------------

/// Thread-safe engine that resolves file paths to component identities.
pub struct IdentityEngine {
    pkg_manager: PackageManager,
    /// Cache: absolute path → resolved package info (or None if not found).
    cache: Mutex<HashMap<String, Option<(String, String)>>>,
}

impl IdentityEngine {
    pub fn new() -> Self {
        Self {
            pkg_manager: detect_package_manager(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a normalised absolute path to its `ComponentIdentity`.
    pub fn identify(&self, path: &Path) -> ComponentIdentity {
        if crate::resolver::is_system_path(path) {
            self.identify_system(path)
        } else {
            self.identify_local(path)
        }
    }

    // ------------------------------------------------------------------
    // System identification via package manager
    // ------------------------------------------------------------------

    fn identify_system(&self, path: &Path) -> ComponentIdentity {
        let key = path.to_string_lossy().to_string();

        // Check cache first (read lock).
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&key) {
                return match entry {
                    Some((name, ver)) => ComponentIdentity::SystemPackage {
                        name: name.clone(),
                        version: ver.clone(),
                    },
                    None => ComponentIdentity::UnknownSystem,
                };
            }
        }

        // Miss – query the package manager.
        let result = self.query_package_manager(&key);

        // Store in cache (write lock).
        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(key, result.clone());
        }

        match result {
            Some((name, version)) => ComponentIdentity::SystemPackage { name, version },
            None => ComponentIdentity::UnknownSystem,
        }
    }

    /// Returns `Some((name, version))` or `None` if the path is not owned by
    /// any known package.
    fn query_package_manager(&self, path: &str) -> Option<(String, String)> {
        match self.pkg_manager {
            PackageManager::Dpkg => self.query_dpkg(path),
            PackageManager::Pacman => self.query_pacman(path),
            PackageManager::Rpm => self.query_rpm(path),
            PackageManager::None => None,
        }
    }

    // ---- dpkg ---------------------------------------------------------------

    fn query_dpkg(&self, path: &str) -> Option<(String, String)> {
        // On merged-usr systems (Ubuntu 22.04+), /lib is a symlink to usr/lib.
        // The dynamic linker reads paths from ld.so.cache which uses /lib/…,
        // but dpkg's database records files under /usr/lib/….  So
        // `dpkg -S /lib/x86_64-linux-gnu/libfoo.so.1` fails even though
        // `dpkg -S /usr/lib/x86_64-linux-gnu/libfoo.so.1` succeeds.
        //
        // Strategy: try the path as-is first; if dpkg doesn't recognise it,
        // resolve symlinks with canonicalize() and retry once.
        self.query_dpkg_single(path).or_else(|| {
            let canonical = std::fs::canonicalize(path).ok()?;
            let canonical_str = canonical.to_str()?;
            if canonical_str == path {
                return None; // Same path, no point retrying.
            }
            self.query_dpkg_single(canonical_str)
        })
    }

    fn query_dpkg_single(&self, path: &str) -> Option<(String, String)> {
        // dpkg -S <path>  →  "libssl3:amd64: /usr/lib/…/libssl.so.3"
        let out = Command::new("dpkg")
            .args(["-S", path])
            .output()
            .ok()?;

        if !out.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        // dpkg -S output may contain "diversion" header lines before the
        // actual ownership line, e.g.:
        //   diversion by libc6 from: /lib64/ld-linux-x86-64.so.2
        //   diversion by libc6 to: /lib64/ld-linux-x86-64.so.2.orig
        //   libc6:amd64: /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
        // Skip all "diversion" lines; use the first real ownership line.
        let ownership_line = stdout
            .lines()
            .find(|l| !l.trim_start().starts_with("diversion"))?;
        // ownership_line looks like: "libgmp10:i386: /usr/lib/i386-linux-gnu/libgmp.so.10"
        // Split on ": " to isolate the "name:arch" qualifier from the file path.
        let pkg_with_arch = ownership_line.splitn(2, ": ").next()?.trim().to_string();
        // pkg_with_arch = "libgmp10:i386"; strip arch for the display name.
        let pkg_name = pkg_with_arch.split(':').next().unwrap_or(&pkg_with_arch).to_string();

        // Use the arch-qualified name so dpkg-query returns exactly one version.
        // Without :arch, dpkg-query concatenates versions for all installed archs
        // (e.g. amd64 + i386) with no separator, corrupting the version string.
        let ver_out = Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", &pkg_with_arch])
            .output()
            .ok()?;

        if !ver_out.status.success() {
            return Some((pkg_name, "unknown".to_string()));
        }

        let version = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();
        Some((pkg_name, version))
    }

    // ---- pacman -------------------------------------------------------------

    fn query_pacman(&self, path: &str) -> Option<(String, String)> {
        // pacman -Qo <path>  →  "/usr/lib/… is owned by openssl 3.1.2-1"
        let out = Command::new("pacman")
            .args(["-Qo", path])
            .output()
            .ok()?;

        if !out.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        // "… is owned by <name> <version>"
        let parts: Vec<&str> = stdout.split_whitespace().collect();
        let owned_idx = parts.iter().position(|&w| w == "owned")?;
        let name = parts.get(owned_idx + 2)?.to_string();
        let version = parts.get(owned_idx + 3)?.to_string();
        Some((name, version))
    }

    // ---- rpm ----------------------------------------------------------------

    fn query_rpm(&self, path: &str) -> Option<(String, String)> {
        // rpm -qf <path> --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n'
        let out = Command::new("rpm")
            .args([
                "-qf",
                path,
                "--queryformat",
                "%{NAME} %{VERSION}-%{RELEASE}",
            ])
            .output()
            .ok()?;

        if !out.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut parts = stdout.trim().splitn(2, ' ');
        let name = parts.next()?.to_string();
        let version = parts.next().unwrap_or("unknown").to_string();
        Some((name, version))
    }

    // ------------------------------------------------------------------
    // Local identification via SHA-256
    // ------------------------------------------------------------------

    fn identify_local(&self, path: &Path) -> ComponentIdentity {
        let hash = compute_sha256(path).unwrap_or_else(|| "sha256:error".to_string());
        ComponentIdentity::LocalFile { hash }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 helper
// ---------------------------------------------------------------------------

/// Compute SHA-256 of the file at `path` and return `"sha256:<hex>"`.
/// Returns `None` if the file cannot be read (might be a transient build
/// artefact that was already deleted).
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

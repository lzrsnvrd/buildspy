//! Output schema (Report / Component) and component resolution.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::identity::{compute_sha256, ComponentIdentity, IdentityEngine};
use crate::reachability::types::ReachabilityResult;

// ---------------------------------------------------------------------------
// Output schema
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
pub struct Report {
    pub timestamp: String,
    pub build_command: String,
    pub project_dir: String,
    pub exit_code: Option<i32>,
    pub components: Vec<Component>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<Vec<ReachabilityResult>>,
}

/// Variant order matches the desired sort order in the output report.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    EcosystemPackage,
    LocalFile,
    SystemPackage,
    SystemUnknown,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct Component {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Pre-computed PURL for ecosystem_package components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// VCS or download URL for vendored subproject components (e.g. from a
    /// Meson `.wrap` file).  Absent for system packages and bare local files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_url: Option<String>,
    pub path: String,
    #[serde(rename = "type")]
    pub component_type: ComponentType,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Drain the event channel, filter irrelevant paths and build orchestrators,
/// then resolve each path to a `Component` with deduplication.  Finally add
/// the runtime dependencies (`DT_NEEDED` closure) of the ELF artifacts the
/// build touched, which the linker does not open when it produces a `.so`.
///
/// `include_toolchain` keeps what the build tools open for themselves: the
/// orchestrators' file opens and the libraries the loader maps into the
/// compilers, linkers and shell utilities.
pub fn collect_components(
    path_rx: &mut tokio::sync::mpsc::UnboundedReceiver<(String, u32)>,
    pid_to_comm: &HashMap<u32, String>,
    pid_to_cwd: &HashMap<u32, PathBuf>,
    project_dir: &Path,
    engine: &IdentityEngine,
    include_toolchain: bool,
) -> HashMap<String, Component> {
    use super::{deps, filter, resolver};

    // Phase 1: drain the channel, filter noise, normalise paths.
    let mut unique_paths: HashSet<String> = HashSet::new();
    // Every non-system file the build touched, whatever its name or opener:
    // the linked ELF artifacts among them (executables have no extension)
    // seed the runtime-dependency walk in phase 3.
    let mut touched: HashSet<PathBuf> = HashSet::new();
    while let Ok((raw, opener_pid)) = path_rx.try_recv() {
        if resolver::is_virtual(&raw) {
            continue;
        }
        let cwd = pid_to_cwd
            .get(&opener_pid)
            .map(PathBuf::as_path)
            .unwrap_or(project_dir);
        let normalized = resolver::normalize(&raw, cwd);
        if !resolver::is_system_path(&normalized) {
            touched.insert(normalized.clone());
        }

        let opener_comm = pid_to_comm.get(&opener_pid).map(String::as_str).unwrap_or("");
        if !include_toolchain && filter::is_build_orchestrator(opener_comm) {
            log::debug!("skip ({}): {}", opener_comm, raw);
            continue;
        }
        if resolver::is_relevant(&raw) {
            unique_paths.insert(normalized.to_string_lossy().to_string());
        }
    }
    log::info!("Collected {} unique relevant paths.", unique_paths.len());

    // Executables and shared libraries among the touched files, and the ELF
    // kinds (word size + machine) the build targets.  With the host's own kind
    // — the toolchain's — these are the only kinds a real dependency can have.
    let artifacts: Vec<PathBuf> = touched
        .into_iter()
        .filter(|p| {
            deps::read_elf_header(p).is_some_and(|h| matches!(h.e_type, deps::ET_EXEC | deps::ET_DYN))
        })
        .collect();
    let mut kinds: HashSet<deps::ElfKind> = artifacts
        .iter()
        .filter_map(|p| deps::read_elf_header(p).map(|h| h.kind))
        .collect();
    kinds.extend(deps::host_kind());

    // Runtime dependencies of the artifacts — what `ldd` lists.  Computed up
    // front: phase 2 needs them to tell a system library the project uses from
    // one the loader mapped into a build tool, and phase 3 adds those the build
    // never opened.
    let runtime = deps::collect_closure(&artifacts);
    let runtime_set: HashSet<&Path> = runtime.iter().map(PathBuf::as_path).collect();

    // Phase 2: resolve identities and deduplicate.
    let project_root = std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let mut components: HashMap<String, Component> = HashMap::new();
    // Headers from outside the project and the package manager's reach,
    // grouped per library (see `include_root_entry`).
    let mut external_headers: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
    for opened in &unique_paths {
        let target = resolver::library_symlink_target(Path::new(opened));
        if let Some(t) = &target {
            log::debug!("library symlink: {} → {}", opened, t.display());
        }
        let path = target.as_deref().unwrap_or(Path::new(opened));
        let path_str: &str = &path.to_string_lossy();

        if !path.is_file() {
            continue;
        }

        // The linker searches every multiarch dir for a soname and opens the
        // same-named i386 copy before rejecting it; so does the loader of each
        // tool.  Such a probe is not a dependency.
        let shared_library = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(resolver::is_shared_library_name);
        if shared_library {
            if let Some(h) = deps::read_elf_header(path) {
                if !kinds.contains(&h.kind) {
                    log::debug!("skip foreign-arch library probe: {path_str}");
                    continue;
                }
            }
        }

        // Every compiler, linker and shell utility the build runs has its own
        // libraries mapped by the loader (cc1plus → libisl, ld → libbfd,
        // cp → libselinux), and GCC's LTO plugin is dlopen'ed by the linker.
        // A system library is the project's only as a link input (`-lfoo`) or
        // as a runtime dependency of what the build produced.
        if shared_library
            && !include_toolchain
            && is_toolchain_runtime(Path::new(opened), path, &runtime_set)
        {
            log::debug!("skip toolchain runtime library: {opened}");
            continue;
        }

        if !resolver::is_system_path(path) {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "h" | "hpp" | "hxx" | "hh" | "H" | "inl" | "tcc")
                && !engine.is_in_meson_subproject(path)
            {
                // The project's own headers are not components.  One from
                // outside it — /usr/local, /opt, a sibling checkout, a conan or
                // vcpkg cache — is a dependency, and for a header-only library
                // the only trace the build leaves.
                let inside_project = path.starts_with(&project_root)
                    || std::fs::canonicalize(path).is_ok_and(|c| c.starts_with(&project_root));
                if !inside_project {
                    external_headers
                        .entry(include_root_entry(path))
                        .or_default()
                        .insert(path.to_path_buf());
                }
                continue;
            }
        }

        let comp = resolve_component(path_str, path, engine);
        components.entry(component_key(&comp, path, engine)).or_insert(comp);
    }
    for (entry, headers) in &external_headers {
        let comp = external_headers_component(entry, headers);
        components.entry(format!("include:{}", entry.display())).or_insert(comp);
    }

    // Phase 3: runtime dependencies of the artifacts.  The linker only opens
    // the libraries named on its command line when it produces a `.so`, not
    // what those libraries need in turn.
    let mut added = 0usize;
    for lib in &runtime {
        let comp = resolve_component(&lib.to_string_lossy(), lib, engine);
        if let std::collections::hash_map::Entry::Vacant(slot) =
            components.entry(component_key(&comp, lib, engine))
        {
            log::debug!("runtime dependency not seen during the build: {}", lib.display());
            slot.insert(comp);
            added += 1;
        }
    }
    log::info!(
        "Runtime dependencies: {} shared libraries needed by {} build artifact(s), {} not seen \
         during the build.",
        runtime.len(),
        artifacts.len(),
        added
    );

    components
}

/// Whether a shared library the build opened (`opened`, resolved to `path`)
/// is a build tool's own runtime rather than a dependency of the project:
/// a program-private library under `/usr/libexec` (GCC's `liblto_plugin.so`,
/// also reachable through a `/usr/lib/gcc/…` symlink), or a system library
/// that is neither a link input nor in the artifacts' `DT_NEEDED` closure.
///
/// Libraries outside the system prefixes are left alone: a vendored or
/// sibling-project `libfoo.so` is often a regular file the linker is handed
/// by path, and its artifact's closure may not resolve back to it.
fn is_toolchain_runtime(opened: &Path, path: &Path, runtime: &HashSet<&Path>) -> bool {
    use super::resolver;

    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if canonical.starts_with("/usr/libexec") {
        return true;
    }
    // ar, nm and ranlib load every LTO plugin in `bfd-plugins` — unversioned
    // `.so` symlinks (to liblto_plugin.so, LLVMgold.so) shaped like link inputs.
    if opened.components().any(|c| c.as_os_str() == "bfd-plugins") {
        return true;
    }
    resolver::is_system_path(&canonical)
        && !resolver::is_link_input(opened)
        && !runtime.contains(canonical.as_path())
}

/// The library a header from outside the project belongs to, as far as its
/// path tells: the entry right under the first `include` directory
/// (`/usr/local/include/nlohmann/json.hpp` → `/usr/local/include/nlohmann`;
/// `/usr/local/include/zmq.h` is its own entry), else the header's directory.
fn include_root_entry(header: &Path) -> PathBuf {
    let parts: Vec<_> = header.components().collect();
    match parts.iter().position(|c| c.as_os_str() == "include") {
        Some(i) if i + 1 < parts.len() => parts[..=i + 1].iter().collect(),
        _ => header.parent().unwrap_or(header).to_path_buf(),
    }
}

/// One `local_file` component for the headers the build opened under `entry`.
/// A single header keeps its own hash; a directory gets one over every header
/// opened in it — a fingerprint of what the build used, not a library version.
fn external_headers_component(entry: &Path, headers: &BTreeSet<PathBuf>) -> Component {
    use sha2::{Digest, Sha256};

    let hash = match headers.iter().next() {
        Some(only) if headers.len() == 1 && only == entry => compute_sha256(only),
        _ => {
            let mut hasher = Sha256::new();
            for header in headers {
                let relative = header.strip_prefix(entry).unwrap_or(header);
                hasher.update(relative.to_string_lossy().as_bytes());
                hasher.update(compute_sha256(header).unwrap_or_default().as_bytes());
            }
            Some(format!("sha256:{}", hex::encode(hasher.finalize())))
        }
    };
    let name = entry.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string();
    Component {
        name,
        version: None,
        arch: None,
        src_name: None,
        hash: Some(hash.unwrap_or_else(|| "sha256:error".to_string())),
        purl: None,
        vcs_url: None,
        path: entry.to_string_lossy().to_string(),
        component_type: ComponentType::LocalFile,
    }
}

/// Deduplication key: one component per system package, per unowned library
/// (version-insensitive), per Meson subproject, and per local file.
fn component_key(comp: &Component, path: &Path, engine: &IdentityEngine) -> String {
    match comp.component_type {
        ComponentType::SystemPackage => comp.name.clone(),
        ComponentType::SystemUnknown => soname_base(&comp.name),
        // Meson subproject headers: all files from the same subproject
        // deduplicate to a single component keyed by the subproject name.
        ComponentType::LocalFile if engine.is_in_meson_subproject(path) => {
            format!("meson:{}", comp.name)
        }
        _ => comp.path.clone(),
    }
}

/// Strip the version suffix from a shared-library filename to get a stable
/// deduplication key.
pub fn soname_base(name: &str) -> String {
    let base = if let Some(pos) = name.find(".so") {
        &name[..pos]
    } else {
        name
    };
    base.strip_prefix("lib").unwrap_or(base).to_string()
}

/// Convert a path + its `ComponentIdentity` into the output `Component` struct.
pub fn resolve_component(
    path_str: &str,
    path: &Path,
    engine: &IdentityEngine,
) -> Component {
    match engine.identify(path) {
        ComponentIdentity::SystemPackage { name, version, arch, src_name } => Component {
            name,
            version: Some(version),
            arch,
            src_name,
            hash: None,
            purl: None,
            vcs_url: None,
            path: path_str.to_string(),
            component_type: ComponentType::SystemPackage,
        },
        ComponentIdentity::LocalFile { hash, name_hint, version_hint, vcs_url } => {
            let name = name_hint.unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.strip_prefix("lib").unwrap_or(s))
                    .unwrap_or("unknown")
                    .to_string()
            });
            Component {
                name,
                version: version_hint,
                arch: None,
                src_name: None,
                hash: Some(hash),
                purl: None,
                vcs_url,
                path: path_str.to_string(),
                component_type: ComponentType::LocalFile,
            }
        }
        ComponentIdentity::UnknownSystem => {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            Component {
                name,
                version: None,
                arch: None,
                src_name: None,
                hash: None,
                purl: None,
                vcs_url: None,
                path: path_str.to_string(),
                component_type: ComponentType::SystemUnknown,
            }
        }
    }
}

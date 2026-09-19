//! Output schema (Report / Component) and component resolution.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::identity::{ComponentIdentity, IdentityEngine};
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
pub fn collect_components(
    path_rx: &mut tokio::sync::mpsc::UnboundedReceiver<(String, u32)>,
    pid_to_comm: &HashMap<u32, String>,
    pid_to_cwd: &HashMap<u32, PathBuf>,
    project_dir: &Path,
    engine: &IdentityEngine,
    include_orchestrators: bool,
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
        if !include_orchestrators && filter::is_build_orchestrator(opener_comm) {
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

    // Phase 2: resolve identities and deduplicate.
    let mut components: HashMap<String, Component> = HashMap::new();
    for opened in &unique_paths {
        let target = resolver::library_symlink_target(Path::new(opened));
        if let Some(t) = &target {
            log::debug!("library symlink: {} → {}", opened, t.display());
        }
        let path = target.as_deref().unwrap_or(Path::new(opened));
        let path_str: &str = &path.to_string_lossy();

        if !path.exists() {
            continue;
        }

        // The linker searches every multiarch dir for a soname and opens the
        // same-named i386 copy before rejecting it; so does the loader of each
        // tool.  Such a probe is not a dependency.
        if path_str.contains(".so") {
            if let Some(h) = deps::read_elf_header(path) {
                if !kinds.contains(&h.kind) {
                    log::debug!("skip foreign-arch library probe: {path_str}");
                    continue;
                }
            }
        }

        if !resolver::is_system_path(path) {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "h" | "hpp" | "hxx" | "hh" | "H" | "inl" | "tcc") {
                // Keep headers from Meson subprojects; drop all other local headers.
                if !engine.is_in_meson_subproject(path) {
                    continue;
                }
            }
        }

        let comp = resolve_component(path_str, path, engine);
        components.entry(component_key(&comp, path, engine)).or_insert(comp);
    }

    // Phase 3: runtime dependencies of the artifacts — what `ldd` lists.  The
    // linker only opens the libraries named on its command line when it
    // produces a `.so`, not what those libraries need in turn.
    let runtime = deps::collect_closure(&artifacts);
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

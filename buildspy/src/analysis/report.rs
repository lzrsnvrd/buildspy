//! Output schema (Report / Component) and component resolution.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::identity::{ComponentIdentity, IdentityEngine};

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
/// then resolve each path to a `Component` with deduplication.
pub fn collect_components(
    path_rx: &mut tokio::sync::mpsc::UnboundedReceiver<(String, u32)>,
    pid_to_comm: &HashMap<u32, String>,
    pid_to_cwd: &HashMap<u32, PathBuf>,
    project_dir: &Path,
    engine: &IdentityEngine,
    include_orchestrators: bool,
) -> HashMap<String, Component> {
    use super::{filter, resolver};

    // Phase 1: drain the channel, filter noise, normalise paths.
    let mut unique_paths: HashSet<String> = HashSet::new();
    while let Ok((raw, opener_pid)) = path_rx.try_recv() {
        let opener_comm = pid_to_comm.get(&opener_pid).map(String::as_str).unwrap_or("");
        if !include_orchestrators && filter::is_build_orchestrator(opener_comm) {
            log::debug!("skip ({}): {}", opener_comm, raw);
            continue;
        }
        if resolver::is_relevant(&raw) {
            let cwd = pid_to_cwd
                .get(&opener_pid)
                .map(PathBuf::as_path)
                .unwrap_or(project_dir);
            let normalized = resolver::normalize(&raw, cwd);
            unique_paths.insert(normalized.to_string_lossy().to_string());
        }
    }
    log::info!("Collected {} unique relevant paths.", unique_paths.len());

    // Phase 2: resolve identities and deduplicate.
    let mut components: HashMap<String, Component> = HashMap::new();
    for path_str in &unique_paths {
        let path = Path::new(path_str);

        if !path.exists() {
            continue;
        }

        if !resolver::is_system_path(path) {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "h" | "hpp" | "hxx" | "hh" | "H" | "inl" | "tcc") {
                continue;
            }
        }

        let comp = resolve_component(path_str, path, engine);
        let key = match comp.component_type {
            ComponentType::SystemPackage => comp.name.clone(),
            ComponentType::SystemUnknown => soname_base(&comp.name),
            _ => path_str.to_string(),
        };
        components.entry(key).or_insert(comp);
    }

    components
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

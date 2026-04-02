//! Output schema (Report / Component) and component resolution.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::identity::{ComponentIdentity, IdentityEngine};

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
    pub path: String,
    #[serde(rename = "type")]
    pub component_type: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Drain the event channel, filter irrelevant paths and build orchestrators,
/// then resolve each path to a `Component` with deduplication.
///
/// This is the post-build analysis phase: all events have already been
/// collected by the time this is called.
pub fn collect_components(
    path_rx: &mut tokio::sync::mpsc::UnboundedReceiver<(String, u32)>,
    pid_to_comm: &HashMap<u32, String>,
    pid_to_cwd: &HashMap<u32, PathBuf>,
    project_dir: &Path,
    engine: &IdentityEngine,
) -> HashMap<String, Component> {
    use crate::{proc_watcher, resolver};

    // Phase 1: drain the channel, filter noise, normalise paths.
    let mut unique_paths: HashSet<String> = HashSet::new();
    while let Ok((raw, opener_pid)) = path_rx.try_recv() {
        let opener_comm = pid_to_comm.get(&opener_pid).map(String::as_str).unwrap_or("");
        if proc_watcher::is_build_orchestrator(opener_comm) {
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

        // Skip failed openat() attempts (file no longer on disk).
        if !path.exists() {
            continue;
        }

        // Drop local header files — the project's own source, not dependencies.
        if !resolver::is_system_path(path) {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "h" | "hpp" | "hxx" | "hh" | "H" | "inl" | "tcc") {
                continue;
            }
        }

        let comp = resolve_component(path_str, path, engine, project_dir);
        let key = match comp.component_type.as_str() {
            "system_package" => comp.name.clone(),
            "system_unknown" => soname_base(&comp.name),
            _ => path_str.to_string(),
        };
        components.entry(key).or_insert(comp);
    }

    components
}

/// Strip the version suffix from a shared-library filename to get a stable
/// deduplication key.
///
/// Examples:
///   `libssl.so.3`     → `libssl`
///   `libfoo.so.1.2.3` → `libfoo`
///   `libbar.so`       → `libbar`
///   `libstdc++.so.6`  → `libstdc++`
pub fn soname_base(name: &str) -> String {
    // The name stored in Component is the file_stem of the path, which may
    // still contain ".so" if the path was e.g. "libssl.so.3" (file_stem gives
    // "libssl.so").  Strip everything from ".so" onward.
    let base = if let Some(pos) = name.find(".so") {
        &name[..pos]
    } else {
        name
    };
    // Strip leading "lib" prefix for readability (same as resolve_component).
    base.strip_prefix("lib").unwrap_or(base).to_string()
}

/// Convert a path + its `ComponentIdentity` into the output `Component` struct.
pub fn resolve_component(
    path_str: &str,
    path: &Path,
    engine: &IdentityEngine,
    _project_dir: &Path,
) -> Component {
    match engine.identify(path) {
        ComponentIdentity::SystemPackage { name, version, arch, src_name } => Component {
            name,
            version: Some(version),
            arch,
            src_name,
            hash: None,
            purl: None,
            path: path_str.to_string(),
            component_type: "system_package".to_string(),
        },
        ComponentIdentity::LocalFile { hash } => {
            // Use the file stem as the component name.
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                // Strip leading "lib" prefix for readability.
                .map(|s| s.strip_prefix("lib").unwrap_or(s))
                .unwrap_or("unknown")
                .to_string();

            Component {
                name,
                version: None,
                arch: None,
                src_name: None,
                hash: Some(hash),
                purl: None,
                path: path_str.to_string(),
                component_type: "local_file".to_string(),
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
                path: path_str.to_string(),
                component_type: "system_unknown".to_string(),
            }
        }
    }
}

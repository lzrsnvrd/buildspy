pub mod cargo;
pub mod golang;
pub mod npm;
pub mod python;

use std::{collections::HashSet, path::Path};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EcosystemComponent {
    pub name: String,
    pub version: String,
    /// One of: "cargo", "npm", "pypi", "golang".
    pub ecosystem: &'static str,
    /// Pre-computed PURL for this component.
    pub purl: String,
    /// True for dependencies that are only used during development/testing.
    pub is_dev: bool,
}

// ---------------------------------------------------------------------------
// Top-level entry point
// ---------------------------------------------------------------------------

/// Scan `project_dir` for lock files, parse each, and return all discovered
/// ecosystem components.
///
/// If `include_dev` is `false`, packages marked as dev-only are excluded.
pub fn detect(
    project_dir: &Path,
    pid_to_comm: &std::collections::HashMap<u32, String>,
    include_dev: bool,
) -> Vec<EcosystemComponent> {
    let mut results: Vec<EcosystemComponent> = Vec::new();

    results.extend(cargo::detect(project_dir, pid_to_comm));
    results.extend(npm::detect(project_dir, pid_to_comm));
    results.extend(python::detect(project_dir, pid_to_comm));
    results.extend(golang::detect(project_dir, pid_to_comm));

    if !include_dev {
        results.retain(|c| !c.is_dev);
    }

    // Deduplicate by (ecosystem, name, version).
    let mut seen: HashSet<String> = HashSet::new();
    results.retain(|c| {
        seen.insert(format!("{}:{}@{}", c.ecosystem, c.name, c.version))
    });

    results
}

// ---------------------------------------------------------------------------
// Shared filesystem helper
// ---------------------------------------------------------------------------

/// Recursively find all files named `filename` inside `dir`, up to `max_depth`
/// directory levels deep.
///
/// Skips common noise directories that never contain meaningful lock files:
/// build output, installed packages, VCS metadata, caches.
pub fn find_files(dir: &Path, filename: &str, max_depth: usize) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    walk(dir, filename, max_depth, 0, &mut out);
    out
}

fn walk(
    dir: &Path,
    filename: &str,
    max_depth: usize,
    depth: usize,
    out: &mut Vec<std::path::PathBuf>,
) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(
                name,
                "target"
                    | "node_modules"
                    | ".git"
                    | "__pycache__"
                    | ".venv"
                    | "venv"
                    | "env"
                    | "vendor"
                    | ".tox"
                    | "dist"
                    | "build"
                    | ".cache"
                    | ".mypy_cache"
                    | ".pytest_cache"
            ) {
                continue;
            }
            walk(&path, filename, max_depth, depth + 1, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
            out.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared PURL version encoder
// ---------------------------------------------------------------------------

/// Percent-encode characters that are special in a PURL version component.
pub fn encode_version(v: &str) -> String {
    v.replace('+', "%2B").replace(':', "%3A")
}

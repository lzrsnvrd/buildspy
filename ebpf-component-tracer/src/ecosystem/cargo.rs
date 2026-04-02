//! Cargo.lock parser.
//!
//! Emits `pkg:cargo/<name>@<version>` PURLs for all registry/git dependencies.
//! Local workspace crates (no `source` field) are skipped — they are the
//! project itself, not external dependencies.

use std::{collections::HashMap, path::Path};

use serde::Deserialize;

use super::{encode_version, find_files, EcosystemComponent};

// ---------------------------------------------------------------------------
// Cargo.lock schema (TOML)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CargoLock {
    package: Option<Vec<CargoPackage>>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    /// Absent for local workspace members; present for registry/git deps.
    source: Option<String>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn detect(
    project_dir: &Path,
    pid_to_comm: &HashMap<u32, String>,
) -> Vec<EcosystemComponent> {
    let cargo_ran = pid_to_comm
        .values()
        .any(|c| matches!(c.as_str(), "cargo" | "rustc" | "rustdoc" | "clippy-driver"));

    let lock_files = find_files(project_dir, "Cargo.lock", 5);

    if !cargo_ran && lock_files.is_empty() {
        return vec![];
    }

    let mut results = Vec::new();
    for lock_path in lock_files {
        let Ok(content) = std::fs::read_to_string(&lock_path) else { continue };
        match parse_cargo_lock(&content) {
            Ok(components) => {
                log::debug!(
                    "ecosystem/cargo: {} packages from {}",
                    components.len(),
                    lock_path.display()
                );
                results.extend(components);
            }
            Err(e) => {
                log::warn!(
                    "ecosystem/cargo: failed to parse {}: {}",
                    lock_path.display(),
                    e
                );
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

fn parse_cargo_lock(content: &str) -> Result<Vec<EcosystemComponent>, toml::de::Error> {
    let lock: CargoLock = toml::from_str(content)?;
    let packages = lock.package.unwrap_or_default();

    Ok(packages
        .into_iter()
        .filter(|p| {
            // Keep only packages coming from a registry or git source.
            p.source
                .as_deref()
                .map(|s| s.starts_with("registry+") || s.starts_with("git+"))
                .unwrap_or(false)
        })
        .map(|p| {
            let purl = format!("pkg:cargo/{}@{}", p.name, encode_version(&p.version));
            EcosystemComponent {
                name: p.name,
                version: p.version,
                ecosystem: "cargo",
                purl,
                is_dev: false, // Cargo.lock does not distinguish dev deps
            }
        })
        .collect())
}

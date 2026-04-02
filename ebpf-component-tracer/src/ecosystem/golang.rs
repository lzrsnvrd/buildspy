//! go.sum parser.
//!
//! `go.sum` contains a line per module version (plus one for the go.mod file
//! itself).  We keep only the module lines (skip `/go.mod` variants) and emit
//! `pkg:golang/<module-path>@<version>` PURLs.
//!
//! Slashes inside the module path are kept unencoded — they act as PURL
//! namespace/name separators per the PURL spec for the `golang` type.

use std::{collections::HashMap, path::Path};

use super::{find_files, EcosystemComponent};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn detect(
    project_dir: &Path,
    pid_to_comm: &HashMap<u32, String>,
) -> Vec<EcosystemComponent> {
    let go_ran = pid_to_comm.values().any(|c| c == "go");
    let lock_files = find_files(project_dir, "go.sum", 5);

    if !go_ran && lock_files.is_empty() {
        return vec![];
    }

    let mut results = Vec::new();
    for path in lock_files {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let components = parse_go_sum(&content);
        log::debug!(
            "ecosystem/golang: {} modules from {}",
            components.len(),
            path.display()
        );
        results.extend(components);
    }
    results
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

fn parse_go_sum(content: &str) -> Vec<EcosystemComponent> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        // Format: `<module> <version>[/go.mod] <hash>`
        let mut parts = line.splitn(3, ' ');
        let Some(module) = parts.next() else { continue };
        let Some(version_field) = parts.next() else { continue };

        // Skip the go.mod-only hash lines — they validate the module manifest
        // but don't represent actual compiled code dependencies.
        if version_field.ends_with("/go.mod") {
            continue;
        }

        let version = version_field.to_string();
        let purl = format!("pkg:golang/{}@{}", module, version.replace('+', "%2B"));

        out.push(EcosystemComponent {
            name: module.to_string(),
            version,
            ecosystem: "golang",
            purl,
            is_dev: false, // go.sum does not distinguish test/dev modules
        });
    }
    out
}

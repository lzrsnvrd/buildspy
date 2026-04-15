//! Python lock-file parsers.
//!
//! Supported files (in descending priority / fidelity):
//! - `Pipfile.lock`  — JSON, exact pinned versions, dev vs prod sections
//! - `poetry.lock`   — TOML, exact pinned versions, category/groups metadata
//! - `requirements.txt` — plain text, only exact `==` pins are captured
//!
//! Emits `pkg:pypi/<name>@<version>` PURLs.
//! Package names are normalised per PEP 503 (lowercase, `-`/`_`/`.` → `-`).

use std::{collections::HashMap, path::Path};

use serde::Deserialize;
use serde_json::Value;

use super::{find_files, EcosystemComponent};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn detect(
    project_dir: &Path,
    pid_to_comm: &HashMap<u32, String>,
) -> Vec<EcosystemComponent> {
    let pip_ran = pid_to_comm.values().any(|c| {
        c.starts_with("pip") || c.starts_with("python") || matches!(c.as_str(), "uv" | "hatch" | "pdm")
    });

    let mut results = Vec::new();

    for path in find_files(project_dir, "Pipfile.lock", 5) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        match parse_pipfile_lock(&content) {
            Ok(c) => {
                log::debug!("ecosystem/python: {} packages from {}", c.len(), path.display());
                results.extend(c);
            }
            Err(e) => log::warn!("ecosystem/python: failed to parse {}: {}", path.display(), e),
        }
    }

    for path in find_files(project_dir, "poetry.lock", 5) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        match parse_poetry_lock(&content) {
            Ok(c) => {
                log::debug!("ecosystem/python: {} packages from {}", c.len(), path.display());
                results.extend(c);
            }
            Err(e) => log::warn!("ecosystem/python: failed to parse {}: {}", path.display(), e),
        }
    }

    for path in find_files(project_dir, "requirements.txt", 5) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let c = parse_requirements_txt(&content);
        if !c.is_empty() {
            log::debug!("ecosystem/python: {} packages from {}", c.len(), path.display());
            results.extend(c);
        }
    }

    if !pip_ran && results.is_empty() {
        return vec![];
    }

    results
}

// ---------------------------------------------------------------------------
// Pipfile.lock  (JSON)
//
// {
//   "_meta": { ... },
//   "default": { "requests": { "version": "==2.31.0", ... } },
//   "develop": { "pytest":   { "version": "==7.4.3",  ... } }
// }
// ---------------------------------------------------------------------------

fn parse_pipfile_lock(content: &str) -> Result<Vec<EcosystemComponent>, serde_json::Error> {
    let root: Value = serde_json::from_str(content)?;
    let mut out = Vec::new();

    for (section, is_dev) in &[("default", false), ("develop", true)] {
        if let Some(deps) = root.get(section).and_then(Value::as_object) {
            for (name, meta) in deps {
                let Some(ver_raw) = meta.get("version").and_then(Value::as_str) else { continue };
                // Strip the "==" prefix that Pipfile.lock always uses.
                let version = ver_raw.trim_start_matches("==").to_string();
                out.push(make(name, &version, *is_dev));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// poetry.lock  (TOML)
//
// [[package]]
// name = "requests"
// version = "2.31.0"
// category = "main"      ← poetry v1
// groups = ["main"]      ← poetry v2
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PoetryLock {
    package: Option<Vec<PoetryPackage>>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    /// poetry v1 field: "main" | "dev"
    category: Option<String>,
    /// poetry v2 field: ["main"] | ["dev"] | ["dev", "test"]
    #[serde(default)]
    groups: Vec<String>,
}

fn parse_poetry_lock(content: &str) -> Result<Vec<EcosystemComponent>, toml::de::Error> {
    let lock: PoetryLock = toml::from_str(content)?;
    Ok(lock.package.unwrap_or_default().into_iter().map(|p| {
        let is_dev = p.category.as_deref() == Some("dev")
            || (!p.groups.is_empty() && p.groups.iter().all(|g| g != "main"));
        make(&p.name, &p.version, is_dev)
    }).collect())
}

// ---------------------------------------------------------------------------
// requirements.txt  (plain text, exact pins only)
//
// Captures lines of the form `name==version` (with optional env markers after
// `;`).  Loose specifiers (>=, ~=, etc.) are intentionally skipped because
// they don't identify a specific version.
// ---------------------------------------------------------------------------

fn parse_requirements_txt(content: &str) -> Vec<EcosystemComponent> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Strip environment markers ("; python_version >= '3.8'").
        let line = line.split(';').next().unwrap_or(line).trim();
        // Accept only exact pins.
        if let Some((name, version)) = line.split_once("==") {
            let name = name.trim();
            let version = version.trim();
            // Skip git/URL references that accidentally contain "==".
            if name.contains('/') || version.contains('/') {
                continue;
            }
            out.push(make(name, version, false));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an `EcosystemComponent` with a normalised PyPI PURL.
fn make(name: &str, version: &str, is_dev: bool) -> EcosystemComponent {
    let purl = pypi_purl(name, version);
    EcosystemComponent {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: "pypi",
        purl,
        is_dev,
    }
}

/// Build a `pkg:pypi/<name>@<version>` PURL.
///
/// Name is normalised per PEP 503: lowercase and `[-_.]` collapsed to `-`.
fn pypi_purl(name: &str, version: &str) -> String {
    let normalized: String = name
        .chars()
        .map(|c| match c {
            '_' | '.' => '-',
            other => other.to_ascii_lowercase(),
        })
        .collect();
    format!("pkg:pypi/{}@{}", normalized, version.replace('+', "%2B"))
}

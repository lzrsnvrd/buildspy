//! npm / yarn lock-file parsers.
//!
//! Supported files:
//! - `package-lock.json` (lockfileVersion 1, 2, and 3)
//! - `yarn.lock` (v1 / yarn classic format)
//!
//! Emits `pkg:npm/<name>@<version>` PURLs.
//! Scoped packages (`@scope/name`) are encoded as `pkg:npm/%40scope/name@...`.

use std::{collections::HashMap, path::Path};

use serde_json::Value;

use super::{encode_version, find_files, EcosystemComponent};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn detect(
    project_dir: &Path,
    pid_to_comm: &HashMap<u32, String>,
) -> Vec<EcosystemComponent> {
    let npm_ran = pid_to_comm
        .values()
        .any(|c| matches!(c.as_str(), "npm" | "node" | "yarn" | "pnpm" | "npx" | "corepack"));

    if !npm_ran {
        return vec![];
    }

    let mut results = Vec::new();

    for lock_path in find_files(project_dir, "package-lock.json", 5) {
        let Ok(content) = std::fs::read_to_string(&lock_path) else { continue };
        match parse_package_lock(&content) {
            Ok(components) => {
                log::debug!(
                    "ecosystem/npm: {} packages from {}",
                    components.len(),
                    lock_path.display()
                );
                results.extend(components);
            }
            Err(e) => log::warn!(
                "ecosystem/npm: failed to parse {}: {}",
                lock_path.display(),
                e
            ),
        }
    }

    for lock_path in find_files(project_dir, "yarn.lock", 5) {
        let Ok(content) = std::fs::read_to_string(&lock_path) else { continue };
        let components = parse_yarn_lock(&content);
        log::debug!(
            "ecosystem/npm: {} packages from {}",
            components.len(),
            lock_path.display()
        );
        results.extend(components);
    }

    results
}

// ---------------------------------------------------------------------------
// package-lock.json
// ---------------------------------------------------------------------------

fn parse_package_lock(content: &str) -> Result<Vec<EcosystemComponent>, serde_json::Error> {
    let root: Value = serde_json::from_str(content)?;
    let lockfile_version = root.get("lockfileVersion").and_then(Value::as_u64).unwrap_or(1);

    let mut components = Vec::new();

    if lockfile_version >= 2 {
        // v2 / v3: flat "packages" map keyed by "node_modules/<name>".
        if let Some(packages) = root.get("packages").and_then(Value::as_object) {
            for (key, pkg) in packages {
                // Empty key is the root project itself.
                if key.is_empty() {
                    continue;
                }
                // Strip the "node_modules/" prefix to get the package name.
                // Nested scoped packages look like "node_modules/@scope/name".
                let name = key
                    .strip_prefix("node_modules/")
                    .unwrap_or(key.as_str());

                let Some(version) = pkg.get("version").and_then(Value::as_str) else { continue };
                let is_dev = pkg.get("dev").and_then(Value::as_bool).unwrap_or(false);

                components.push(make(name, version, is_dev));
            }
        }
    } else {
        // v1: nested "dependencies" map.
        parse_v1_deps(root.get("dependencies").and_then(Value::as_object), &mut components);
    }

    Ok(components)
}

fn parse_v1_deps(
    deps: Option<&serde_json::Map<String, Value>>,
    out: &mut Vec<EcosystemComponent>,
) {
    let Some(deps) = deps else { return };
    for (name, pkg) in deps {
        let Some(version) = pkg.get("version").and_then(Value::as_str) else { continue };
        let is_dev = pkg.get("dev").and_then(Value::as_bool).unwrap_or(false);
        out.push(make(name, version, is_dev));
        // Recurse into bundled nested dependencies.
        parse_v1_deps(pkg.get("dependencies").and_then(Value::as_object), out);
    }
}

// ---------------------------------------------------------------------------
// yarn.lock (v1 / classic format)
//
// Format overview:
// ```
// # yarn lockfile v1
//
// "express@^4.18.2":
//   version "4.18.2"
//   resolved "..."
//   integrity sha512-...
//
// "@babel/core@^7.0.0", "@babel/core@^7.12.13":
//   version "7.23.5"
// ```
//
// Lines NOT starting with whitespace are package declaration headers ending in
// `:`.  The `version "x.y.z"` line inside each stanza is what we care about.
// yarn.lock does not encode dev vs prod, so `is_dev` is always false.
// ---------------------------------------------------------------------------

fn parse_yarn_lock(content: &str) -> Vec<EcosystemComponent> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            if trimmed.is_empty() {
                current_name = None;
            }
            continue;
        }

        if !line.starts_with(' ') && !line.starts_with('\t') {
            // Package declaration: one or more comma-separated specifiers ending with `:`.
            let decl = trimmed.trim_end_matches(':');
            // Take the first specifier (before any comma) to extract the name.
            let first = decl.split(',').next().unwrap_or(decl).trim().trim_matches('"');
            current_name = yarn_name(first).map(str::to_string);
        } else if let Some(ref name) = current_name {
            // Inside a stanza — look for `  version "x.y.z"`.
            if let Some(rest) = trimmed.strip_prefix("version ") {
                let version = rest.trim().trim_matches('"').to_string();
                out.push(make(name, &version, false));
                current_name = None; // one version per stanza
            }
        }
    }
    out
}

/// Extract the bare package name from a yarn specifier.
///
/// - `express@^4.18.2`       → `"express"`
/// - `@babel/core@^7.0.0`    → `"@babel/core"`
fn yarn_name(specifier: &str) -> Option<&str> {
    if let Some(rest) = specifier.strip_prefix('@') {
        // Scoped package: find the second `@`.
        let at = rest.find('@')?;
        Some(&specifier[..at + 1])
    } else {
        let at = specifier.find('@')?;
        Some(&specifier[..at])
    }
}

// ---------------------------------------------------------------------------
// PURL helpers
// ---------------------------------------------------------------------------

fn npm_purl(name: &str, version: &str) -> String {
    // Scoped packages: @babel/core → %40babel/core in the PURL name component.
    let encoded_name = if let Some(rest) = name.strip_prefix('@') {
        format!("%40{}", rest)
    } else {
        name.to_string()
    };
    format!("pkg:npm/{}@{}", encoded_name, encode_version(version))
}

fn make(name: &str, version: &str, is_dev: bool) -> EcosystemComponent {
    EcosystemComponent {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: "npm",
        purl: npm_purl(name, version),
        is_dev,
    }
}

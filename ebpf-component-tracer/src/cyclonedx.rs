//! CycloneDX 1.6 BOM serializer.
//!
//! Produces a standards-compliant CycloneDX JSON BOM with no scanner-specific
//! extensions.  PURLs follow the PURL spec so any compatible scanner
//! (Grype, OSV-scanner, Trivy, …) can consume the output.

use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// OS / distro detection
// ---------------------------------------------------------------------------

fn read_os_release() -> HashMap<String, String> {
    let Ok(content) = fs::read_to_string("/etc/os-release") else {
        return HashMap::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.to_string(), v.trim_matches('"').to_string()))
        })
        .collect()
}

/// Returns `"ubuntu-24.04"`, `"debian-12"`, etc., or `"linux"` as fallback.
pub fn detect_distro() -> String {
    let os = read_os_release();
    let id = os.get("ID").map(String::as_str).unwrap_or("linux");
    let version = os.get("VERSION_ID").map(String::as_str).unwrap_or_default();
    if version.is_empty() {
        id.to_string()
    } else {
        format!("{id}-{version}")
    }
}

fn purl_type_for_distro(distro: &str) -> &'static str {
    if distro.starts_with("ubuntu") || distro.starts_with("debian") {
        "deb"
    } else if distro.starts_with("fedora")
        || distro.starts_with("rhel")
        || distro.starts_with("centos")
        || distro.starts_with("rocky")
        || distro.starts_with("almalinux")
    {
        "rpm"
    } else if distro.starts_with("arch") || distro.starts_with("manjaro") {
        "alpm"
    } else {
        "generic"
    }
}

// ---------------------------------------------------------------------------
// PURL helpers
// ---------------------------------------------------------------------------

fn purl_encode(v: &str) -> String {
    v.replace('+', "%2B").replace(':', "%3A")
}

pub fn system_purl(
    name: &str,
    version: &str,
    arch: Option<&str>,
    src_name: Option<&str>,
    distro: &str,
) -> String {
    let purl_type = purl_type_for_distro(distro);
    let namespace = distro.split('-').next().unwrap_or(distro);
    let ver = purl_encode(version);

    // Build qualifiers in alphabetical order (PURL spec recommendation).
    let mut qualifiers = Vec::new();
    if let Some(a) = arch {
        qualifiers.push(format!("arch={a}"));
    }
    qualifiers.push(format!("distro={distro}"));
    // `upstream` qualifier: the source package name when it differs from the
    // binary package name.  Helps CVE databases link binary packages to the
    // upstream project where the vulnerability was filed.
    if let Some(src) = src_name {
        qualifiers.push(format!("upstream={src}"));
    }

    format!("pkg:{purl_type}/{namespace}/{name}@{ver}?{}", qualifiers.join("&"))
}

pub fn local_purl(name: &str, hash: &str) -> String {
    format!("pkg:generic/{name}@{}", purl_encode(hash))
}

// ---------------------------------------------------------------------------
// CycloneDX 1.6 schema types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub bom_format: &'static str,
    pub spec_version: &'static str,
    pub version: u32,
    pub serial_number: String,
    pub metadata: Metadata,
    pub components: Vec<CdxComponent>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Metadata {
    pub timestamp: String,
    /// CycloneDX 1.6: `tools` is `{"components": [...]}`, not a bare array.
    pub tools: ToolsWrapper,
    pub component: CdxComponent,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ToolsWrapper {
    pub components: Vec<Tool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tool {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CdxComponent {
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<CdxHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CdxHash {
    pub alg: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub occurrences: Vec<Occurrence>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Occurrence {
    pub location: String,
}

// ---------------------------------------------------------------------------
// Internal component type (bridges main.rs → cyclonedx.rs)
// ---------------------------------------------------------------------------

pub struct InternalComponent {
    pub name: String,
    pub version: Option<String>,
    pub arch: Option<String>,
    pub src_name: Option<String>,
    pub hash: Option<String>,
    pub path: String,
    pub component_type: String,
}

pub struct ReportRef<'a> {
    pub timestamp: &'a str,
    pub project_dir: &'a str,
    pub components: &'a [InternalComponent],
}

// ---------------------------------------------------------------------------
// BOM construction
// ---------------------------------------------------------------------------

pub fn build_bom(report: &ReportRef<'_>, distro: &str) -> Bom {
    let project_name = Path::new(report.project_dir)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let (os_name, os_version) = distro.split_once('-').unwrap_or((distro, ""));

    // Standard CycloneDX operating-system component — identifies the host OS
    // so scanners can resolve the correct vulnerability database.
    let os_component = CdxComponent {
        bom_ref: Some("os-component".to_string()),
        component_type: "operating-system".to_string(),
        name: os_name.to_string(),
        version: if os_version.is_empty() { None } else { Some(os_version.to_string()) },
        purl: None,
        hashes: vec![],
        evidence: None,
    };

    let mut components = vec![os_component];
    components.extend(report.components.iter().filter_map(|c| to_cdx_component(c, distro)));

    Bom {
        schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
        bom_format: "CycloneDX",
        spec_version: "1.6",
        version: 1,
        serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
        metadata: Metadata {
            timestamp: report.timestamp.to_string(),
            tools: ToolsWrapper {
                components: vec![Tool {
                    tool_type: "application".to_string(),
                    name: "ebpf-component-tracer".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }],
            },
            component: CdxComponent {
                bom_ref: Some("root-component".to_string()),
                component_type: "application".to_string(),
                name: project_name.to_string(),
                version: None,
                purl: None,
                hashes: vec![],
                evidence: None,
            },
        },
        components,
    }
}

fn to_cdx_component(c: &InternalComponent, distro: &str) -> Option<CdxComponent> {
    match c.component_type.as_str() {
        "system_package" => {
            let version = c.version.as_deref().unwrap_or("unknown");
            let purl = if version != "unknown" {
                Some(system_purl(
                    &c.name,
                    version,
                    c.arch.as_deref(),
                    c.src_name.as_deref(),
                    distro,
                ))
            } else {
                None
            };
            Some(CdxComponent {
                bom_ref: purl.clone(),
                component_type: "library".to_string(),
                name: c.name.clone(),
                version: Some(version.to_string()),
                purl,
                hashes: vec![],
                evidence: Some(Evidence {
                    occurrences: vec![Occurrence { location: c.path.clone() }],
                }),
            })
        }
        "local_file" => {
            let hash_str = c.hash.as_deref().unwrap_or("sha256:error");
            let hex = hash_str.strip_prefix("sha256:").unwrap_or(hash_str);
            let purl = Some(local_purl(&c.name, hash_str));
            Some(CdxComponent {
                bom_ref: purl.clone(),
                component_type: "library".to_string(),
                name: c.name.clone(),
                version: Some(hash_str.to_string()),
                purl,
                hashes: if hex != "error" {
                    vec![CdxHash { alg: "SHA-256".to_string(), content: hex.to_string() }]
                } else {
                    vec![]
                },
                evidence: Some(Evidence {
                    occurrences: vec![Occurrence { location: c.path.clone() }],
                }),
            })
        }
        "system_unknown" => Some(CdxComponent {
            bom_ref: None,
            component_type: "library".to_string(),
            name: c.name.clone(),
            version: None,
            purl: None,
            hashes: vec![],
            evidence: Some(Evidence {
                occurrences: vec![Occurrence { location: c.path.clone() }],
            }),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Output path helper
// ---------------------------------------------------------------------------

pub fn cdx_output_path(report_path: &Path) -> std::path::PathBuf {
    let stem = report_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("report");
    let parent = report_path.parent().unwrap_or(Path::new("."));
    parent.join(format!("{stem}.cdx.json"))
}

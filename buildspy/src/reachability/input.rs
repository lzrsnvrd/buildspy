use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct VulnerableTarget {
    /// CVE identifier, e.g. "CVE-2023-38545".
    pub cve: Option<String>,
    /// Symbol name to check reachability for, e.g. "inflate".
    pub symbol: String,
    /// Originating library — display hint only, not used for symbol matching.
    pub library: Option<String>,
}

pub fn load_targets(path: &Path) -> Result<Vec<VulnerableTarget>> {
    let data = std::fs::read_to_string(path)?;
    let targets: Vec<VulnerableTarget> = serde_json::from_str(&data)?;
    Ok(targets)
}

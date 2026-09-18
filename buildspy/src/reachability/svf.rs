//! SVF points-to call-graph extractor — Phase 3.
//!
//! The one thing LLVM-IR direct-call analysis ([`LlvmExtractor`]) cannot do is
//! resolve calls through **function pointers** and C++ function objects — those
//! stay `indirect_calls_present`. [SVF](https://github.com/SVF-tools/SVF) solves
//! this with Andersen's points-to analysis: its `wpa` tool turns `call %fp` into
//! concrete callee edges.
//!
//! ## `wpa` invocation
//!
//! ```text
//! wpa -ander -model-consts -model-arrays -dump-callgraph <file.bc>
//! ```
//!
//! `wpa` writes `callgraph_final.dot` (post-analysis, indirect calls resolved)
//! and `callgraph_initial.dot` to the **current directory**, so we run it in a
//! throwaway temp dir and read the final graph back.
//!
//! `-model-consts` and `-model-arrays` are **both** required, and both are off
//! by default. The canonical function-pointer idiom is a `static` dispatch table
//! (`static fp_t table[] = {a, b}; table[i]()`), which lowers to a constant
//! global array. Without `-model-consts` SVF does not model constant objects at
//! all and without `-model-arrays` it does not model the GEP offset, so in
//! either case the call site resolves to nothing (`IndEdgeSolved 0`) and the
//! whole point of running SVF is lost. Measured on such a table: neither flag or
//! `-model-consts` alone → 0 resolved edges; both → the edge appears.
//!
//! ## `callgraph_final.dot` format (LLVM `GraphWriter` + SVF `DOTGraphTraits`)
//!
//! ```text
//! digraph "Call Graph" {
//!   Node0x55..90 [shape=record,label="{CallGraphNode ID: 0 \{fun: main\}|{<s0>1}}"];
//!   Node0x55..90:s0 -> Node0x55..20[color=black];     // direct call
//!   Node0x55..20 [shape=record,label="{CallGraphNode ID: 1 \{fun: run\}|{<s0>2}}"];
//!   Node0x55..20:s0 -> Node0x55..80[color=red];       // RESOLVED indirect call
//!   Node0x55..80 [shape=record,label="{CallGraphNode ID: 2 \{fun: secret\}}"];
//!   Node0x55..99 [shape=Mrecord,label="{CallGraphNode ID: 3 \{fun: printf\}}"]; // external
//! }
//! ```
//!
//!   * Node id `Node0x..` → function name is embedded in the label as
//!     `\{fun: NAME\}`; `shape=record` marks an internal (defined) function,
//!     `shape=Mrecord` an external declaration.
//!   * `color=black` = direct edge, `color=red` = indirect edge resolved by the
//!     points-to analysis. **Both are real callee edges** — that is the payoff —
//!     so `indirect_callers` comes back empty.
//!   * The edge source carries a **record port** (`Node0x..:s0`) naming the call
//!     site within the caller's label; the target does not. Ports must be
//!     stripped before the node id is looked up, or every edge is dropped.
//!
//! `dlopen`/`dlsym` remain fundamentally unresolvable (the symbol is chosen at
//! runtime); such call sites simply have no outgoing edge, which BFS reports as
//! `not_reachable` — the honest static answer.
//!
//! SVF can abort on some inputs (e.g. SVF-tools/SVF#469), so any `wpa` failure
//! degrades gracefully to [`LlvmExtractor`] rather than dropping the artifact.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};

use super::demangle::demangle;
use super::extractor::{ArtifactCallGraph, CallGraphExtractor};
use super::llvm::LlvmExtractor;
use super::util::{env_override, which, ScratchDir};

pub struct SvfExtractor {
    wpa_bin: PathBuf,
    /// Used if `wpa` fails at runtime, so a crash never loses the artifact.
    fallback: LlvmExtractor,
}

impl SvfExtractor {
    pub fn new(wpa_bin: PathBuf, devirtualize: bool) -> Self {
        Self {
            wpa_bin,
            fallback: LlvmExtractor::new(devirtualize),
        }
    }

    fn run(&self, artifact: &Path) -> Result<ArtifactCallGraph> {
        let work = ScratchDir::new("svf")?;

        let output = Command::new(&self.wpa_bin)
            .arg("-ander")
            // Both needed to resolve dispatch through constant tables; see the
            // module docs.
            .arg("-model-consts")
            .arg("-model-arrays")
            .arg("-dump-callgraph")
            .arg(std::fs::canonicalize(artifact).unwrap_or_else(|_| artifact.to_path_buf()))
            .current_dir(work.path())
            .output()
            .with_context(|| format!("failed to run {}", self.wpa_bin.display()))?;

        if !output.status.success() {
            bail!(
                "{} failed on {}: {}",
                self.wpa_bin.display(),
                artifact.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let dot_path = find_callgraph_dot(work.path())
            .with_context(|| format!("{} produced no callgraph dot file", self.wpa_bin.display()))?;
        let dot = std::fs::read_to_string(&dot_path)
            .with_context(|| format!("failed to read {}", dot_path.display()))?;

        Ok(parse_callgraph_dot(&dot))
    }
}

impl CallGraphExtractor for SvfExtractor {
    fn extract(&self, artifact: &Path) -> Result<ArtifactCallGraph> {
        match self.run(artifact) {
            Ok(ag) => Ok(ag),
            Err(e) => {
                log::warn!(
                    "reachability: SVF failed on {} ({e}); falling back to direct-call analysis \
                     (function pointers stay Unknown).",
                    artifact.display()
                );
                self.fallback.extract(artifact)
            }
        }
    }
}

/// Locate `wpa` (SVF) on `$PATH`, honouring a `BUILDSPY_WPA` override.
pub fn find_wpa() -> Option<PathBuf> {
    env_override("BUILDSPY_WPA").or_else(|| which("wpa"))
}

/// Prefer the post-analysis graph; fall back to the initial one, then any
/// `callgraph*.dot` (naming has varied across SVF versions).
fn find_callgraph_dot(dir: &Path) -> Option<PathBuf> {
    for name in ["callgraph_final.dot", "callgraph_initial.dot"] {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    std::fs::read_dir(dir).ok()?.filter_map(|e| e.ok()).find_map(|e| {
        let p = e.path();
        let name = p.file_name()?.to_str()?;
        (name.starts_with("callgraph") && name.ends_with(".dot")).then_some(p)
    })
}

/// Parse an SVF/LLVM `GraphWriter` call-graph dot file into an
/// [`ArtifactCallGraph`]. Two passes: node ids → names, then edges.
fn parse_callgraph_dot(dot: &str) -> ArtifactCallGraph {
    let mut id_to_name: HashMap<String, String> = HashMap::new();
    let mut defined: HashSet<String> = HashSet::new();
    let mut known_symbols: HashSet<String> = HashSet::new();

    // Pass 1: node definitions (`Node0x.. [shape=..,label="..{fun: NAME}.."]`).
    for line in dot.lines() {
        let line = line.trim();
        if line.contains("->") || !line.contains("label=") {
            continue;
        }
        let Some(name) = extract_fun(line) else {
            continue;
        };
        let id = node_token(line).to_string();
        let name = demangle(name);
        // "Mrecord" contains "record", so test the external marker first.
        if !line.contains("Mrecord") {
            defined.insert(name.clone());
        }
        known_symbols.insert(name.clone());
        id_to_name.insert(id, name);
    }

    // Pass 2: edges (`Node0x.. -> Node0x..[color=..]`). Direct (black) and
    // resolved-indirect (red) edges are both concrete callee edges.
    let mut edges: Vec<(String, String)> = Vec::new();
    for line in dot.lines() {
        let line = line.trim();
        let Some((lhs, rhs)) = line.split_once("->") else {
            continue;
        };
        let src = node_token(lhs);
        let dst = node_token(rhs);
        if let (Some(s), Some(d)) = (id_to_name.get(src), id_to_name.get(dst)) {
            edges.push((s.clone(), d.clone()));
        }
    }

    let has_symbol_table = !id_to_name.is_empty();
    let main_entry = find_main(&defined);
    let exported_entries: Vec<String> = defined.iter().cloned().collect();

    ArtifactCallGraph {
        edges,
        // SVF resolves function-pointer dispatch into concrete edges above, so
        // nothing is left as an unresolved indirect caller.
        indirect_callers: Vec::new(),
        known_symbols,
        has_symbol_table,
        main_entry,
        exported_entries,
    }
}

/// Extract the leading `Node0x..` identifier from a line or edge side,
/// discarding any `:sN` record port on the edge source.
fn node_token(s: &str) -> &str {
    let s = s.trim();
    let end = s
        .find(|c: char| c.is_whitespace() || c == '[' || c == ';' || c == ':')
        .unwrap_or(s.len());
    &s[..end]
}

/// Pull `NAME` out of a label's `\{fun: NAME\}` (or `{fun: NAME}`) fragment.
fn extract_fun(line: &str) -> Option<&str> {
    let start = line.find("fun: ")? + "fun: ".len();
    let rest = &line[start..];
    // The name ends at the closing brace, escaped as `\}` inside a record label.
    let end = rest
        .find("\\}")
        .or_else(|| rest.find('}'))
        .unwrap_or(rest.len());
    let name = rest[..end].trim();
    (!name.is_empty()).then_some(name)
}

fn find_main(defined: &HashSet<String>) -> Option<String> {
    if defined.contains("main") {
        return Some("main".to_string());
    }
    defined
        .iter()
        .find(|n| n.ends_with("::main") || n.contains("::main::h"))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verbatim shape of a real `callgraph_final.dot` (SVF on LLVM 21): main →
    // run (direct), and the function-pointer call run → secret RESOLVED by
    // points-to (color=red). Note the `:sN` record ports on edge sources and the
    // `|{<s0>N}` call-site list appended to caller labels.
    const SAMPLE: &str = r#"digraph "Call Graph" {
	label="Call Graph";

	Node0x5590 [shape=record,label="{CallGraphNode ID: 0 \{fun: main\}|{<s0>1|<s1>3}}"];
	Node0x5590:s0 -> Node0x5620[color=black];
	Node0x5590:s1 -> Node0x5699[color=black];
	Node0x5620 [shape=record,label="{CallGraphNode ID: 1 \{fun: run\}|{<s0>2}}"];
	Node0x5620:s0 -> Node0x5680[color=red];
	Node0x5680 [shape=record,label="{CallGraphNode ID: 2 \{fun: secret\}}"];
	Node0x5699 [shape=Mrecord,label="{CallGraphNode ID: 3 \{fun: printf\}}"];
}
"#;

    #[test]
    fn parses_nodes_and_names() {
        let cg = parse_callgraph_dot(SAMPLE);
        assert!(cg.has_symbol_table);
        for f in ["main", "run", "secret", "printf"] {
            assert!(cg.known_symbols.contains(f), "missing symbol {f}");
        }
        assert_eq!(cg.main_entry.as_deref(), Some("main"));
    }

    #[test]
    fn resolves_direct_and_indirect_edges() {
        let cg = parse_callgraph_dot(SAMPLE);
        assert!(cg.edges.contains(&("main".to_string(), "run".to_string())));
        // The red (indirect, points-to-resolved) edge must be a real edge.
        assert!(cg.edges.contains(&("run".to_string(), "secret".to_string())));
    }

    #[test]
    fn no_unresolved_indirect_callers() {
        let cg = parse_callgraph_dot(SAMPLE);
        assert!(cg.indirect_callers.is_empty());
    }

    #[test]
    fn external_functions_excluded_from_defined() {
        let cg = parse_callgraph_dot(SAMPLE);
        // printf is Mrecord (external) → known but not "exported/defined".
        assert!(cg.known_symbols.contains("printf"));
        assert!(!cg.exported_entries.contains(&"printf".to_string()));
    }
}

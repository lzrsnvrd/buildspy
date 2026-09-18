//! LLVM bitcode call-graph extractor.
//!
//! Runs `opt` over an LLVM bitcode (`.bc`) file and parses the textual
//! call-graph dump. Whole-program bitcode (built with `-flto`) contains the
//! entire project call graph including static archives and inline functions,
//! so this backend sees edges the linear ELF disassembler cannot.
//!
//! ## Producing input bitcode
//!
//! ```bash
//! clang -flto=full -fwhole-program-vtables \
//!       -Wl,--plugin-opt=emit-llvm -o my_app src/*.c   # → my_app.bc
//! ```
//!
//! ## `opt` invocation
//!
//! ```text
//! opt -passes=print-callgraph -disable-output <file.bc>
//! ```
//!
//! The call graph is written to **stderr** in this shape:
//!
//! ```text
//! Call graph node <<null function>><<0x..>>  #uses=0
//!   CS<None> calls function 'compute'          <- externally-visible roots
//! Call graph node for function: 'compute'<<0x..>>  #uses=2
//!   CS<0x..> calls function 'mid'              <- real direct edge
//!   CS<0x..> calls external node               <- real indirect call site
//! Call graph node for function: 'printf'<<0x..>>  #uses=1
//!   CS<None> calls external node               <- external declaration (no body)
//! ```
//!
//! Two subtleties the parser relies on:
//!   * The `<<null function>>` node is a synthetic root whose callees are the
//!     module's externally-visible functions — not real caller→callee edges.
//!   * `CS<0x..>` marks a real call site; `CS<None>` is a placeholder emitted
//!     for the null root and for bodyless external declarations. Only a
//!     `CS<0x..> calls external node` line is a genuine unresolved indirect
//!     call — `CS<None> calls external node` (e.g. `printf`) is not.
//!
//! Names in the dump are Itanium-mangled for C++, so they are demangled here
//! via the shared [`demangle`] helper.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};

use super::demangle::demangle;
use super::extractor::{ArtifactCallGraph, CallGraphExtractor};
use super::util::which;

pub struct LlvmExtractor {
    /// Run `wholeprogramdevirt` before printing the call graph to resolve C++
    /// virtual calls (requires bitcode built with `-fwhole-program-vtables`).
    devirtualize: bool,
}

impl LlvmExtractor {
    pub fn new(devirtualize: bool) -> Self {
        Self { devirtualize }
    }

    fn passes(&self) -> &'static str {
        if self.devirtualize {
            "wholeprogramdevirt,print-callgraph"
        } else {
            "print-callgraph"
        }
    }
}

impl CallGraphExtractor for LlvmExtractor {
    fn extract(&self, artifact: &Path) -> Result<ArtifactCallGraph> {
        let opt = find_opt().with_context(|| {
            "LLVM `opt` not found. Reachability analysis of LLVM bitcode needs the \
             LLVM tools: install them (e.g. `apt install llvm` — provides `opt-NN`) \
             or point BUILDSPY_OPT at an `opt` binary."
        })?;

        let output = Command::new(&opt)
            .arg(format!("-passes={}", self.passes()))
            .arg("-disable-output")
            .arg(artifact)
            .output()
            .with_context(|| format!("failed to run {}", opt.display()))?;

        // The call-graph printer writes to stderr; opt also reports parse
        // errors there, so surface stderr on a non-zero exit.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            bail!(
                "{} failed on {}: {}",
                opt.display(),
                artifact.display(),
                stderr.trim()
            );
        }

        Ok(parse_call_graph(&stderr))
    }
}

/// Parse the textual output of `opt -passes=print-callgraph`.
fn parse_call_graph(text: &str) -> ArtifactCallGraph {
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut indirect: HashSet<String> = HashSet::new();
    let mut known_symbols: HashSet<String> = HashSet::new();
    let mut defined: HashSet<String> = HashSet::new();
    let mut null_root_callees: HashSet<String> = HashSet::new();

    let mut current: Option<String> = None;
    let mut in_null_root = false;

    for line in text.lines() {
        // --- node header ---------------------------------------------------
        if line.starts_with("Call graph node") {
            if line.contains("<<null function>>") {
                in_null_root = true;
                current = None;
            } else if let Some(name) = quoted_after(line, "for function: '") {
                let name = demangle(name);
                known_symbols.insert(name.clone());
                defined.insert(name.clone());
                current = Some(name);
                in_null_root = false;
            }
            continue;
        }

        // --- call-site line ------------------------------------------------
        let t = line.trim_start();
        if !t.starts_with("CS<") {
            continue;
        }
        let cs_is_none = t.starts_with("CS<None>");

        if let Some(callee) = quoted_after(t, "calls function '") {
            let callee = demangle(callee);
            known_symbols.insert(callee.clone());
            if in_null_root {
                // Synthetic root: callees are externally-visible symbols, not
                // real edges.
                null_root_callees.insert(callee);
            } else if let Some(cur) = &current {
                edges.push((cur.clone(), callee));
            }
        } else if t.contains("calls external node") {
            // A real indirect call site carries an address (`CS<0x..>`); the
            // `CS<None>` variant is just a bodyless external declaration.
            if !in_null_root && !cs_is_none {
                if let Some(cur) = &current {
                    indirect.insert(cur.clone());
                }
            }
        }
    }

    // Externally-visible functions defined in this module = the null root's
    // callees. May include imported declarations (e.g. `printf`); harmless as
    // BFS entry points since those reach nothing in-graph.
    let exported_entries: Vec<String> = null_root_callees.into_iter().collect();
    let main_entry = find_main(&defined);
    // Bitcode always carries symbol names; an empty node set means we parsed
    // nothing usable, which classify() should treat like a stripped binary.
    let has_symbol_table = !defined.is_empty();

    ArtifactCallGraph {
        edges,
        indirect_callers: indirect.into_iter().collect(),
        known_symbols,
        has_symbol_table,
        main_entry,
        exported_entries,
    }
}

/// Extract the text between `marker` and the next single quote.
///
/// e.g. `quoted_after("CS<0x1> calls function 'foo'", "calls function '")`
/// → `Some("foo")`.
fn quoted_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

fn find_main(defined: &HashSet<String>) -> Option<String> {
    if defined.contains("main") {
        return Some("main".to_string());
    }
    // Rust binaries expose a mangled `::main`.
    defined
        .iter()
        .find(|n| n.ends_with("::main") || n.contains("::main::h"))
        .cloned()
}

/// Locate an `opt` binary. Distros ship it version-suffixed (`opt-18`), so
/// there is often no bare `opt` on PATH; try common suffixes and honour an
/// explicit `BUILDSPY_OPT` override.
fn find_opt() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BUILDSPY_OPT") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    const CANDIDATES: &[&str] = &[
        "opt", "opt-20", "opt-19", "opt-18", "opt-17", "opt-16", "opt-15", "opt-14",
    ];
    for name in CANDIDATES {
        if let Some(p) = which(name) {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Representative `opt -passes=print-callgraph` output (LLVM 18).
    const SAMPLE: &str = "\
Call graph node <<null function>><<0x1>>  #uses=0
  CS<None> calls function 'compute'
  CS<None> calls function 'main'
  CS<None> calls function 'printf'

Call graph node for function: 'compute'<<0x2>>  #uses=2
  CS<0xa> calls function 'mid'
  CS<0xb> calls external node
  CS<0xc> calls function 'leaf'

Call graph node for function: 'leaf'<<0x3>>  #uses=2

Call graph node for function: 'main'<<0x4>>  #uses=1
  CS<0xd> calls function 'compute'
  CS<0xe> calls function 'printf'

Call graph node for function: 'mid'<<0x5>>  #uses=1
  CS<0xf> calls function 'leaf'

Call graph node for function: 'printf'<<0x6>>  #uses=2
  CS<None> calls external node
";

    #[test]
    fn parses_direct_edges() {
        let cg = parse_call_graph(SAMPLE);
        assert!(cg.has_symbol_table);
        assert!(cg.edges.contains(&("main".to_string(), "compute".to_string())));
        assert!(cg.edges.contains(&("compute".to_string(), "mid".to_string())));
        assert!(cg.edges.contains(&("mid".to_string(), "leaf".to_string())));
    }

    #[test]
    fn real_indirect_call_is_marked() {
        let cg = parse_call_graph(SAMPLE);
        // `compute` has a `CS<0x..> calls external node` → genuine indirect.
        assert!(cg.indirect_callers.contains(&"compute".to_string()));
    }

    #[test]
    fn external_declaration_is_not_indirect() {
        let cg = parse_call_graph(SAMPLE);
        // `printf` is a bodyless declaration (`CS<None> calls external node`).
        assert!(!cg.indirect_callers.contains(&"printf".to_string()));
    }

    #[test]
    fn null_root_is_not_a_caller() {
        let cg = parse_call_graph(SAMPLE);
        // The synthetic root must not contribute edges.
        assert!(!cg.edges.iter().any(|(c, _)| c.contains("null")));
    }

    #[test]
    fn main_entry_detected() {
        let cg = parse_call_graph(SAMPLE);
        assert_eq!(cg.main_entry.as_deref(), Some("main"));
    }
}

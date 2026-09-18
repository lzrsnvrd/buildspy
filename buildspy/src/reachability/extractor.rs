use std::{collections::HashSet, path::Path};

use anyhow::Result;

pub enum EntryPoints {
    /// Single executable: start BFS from `main`.
    Main,
    /// Shared library: start BFS from every exported function.
    AllExported,
}

pub struct ArtifactCallGraph {
    /// Direct call edges: (caller_name, callee_name).
    pub edges: Vec<(String, String)>,
    /// Functions that contain at least one unresolvable indirect call.
    pub indirect_callers: Vec<String>,
    /// All symbol names observable in this binary (imports + defined functions).
    /// Used to determine whether a target can possibly be reached before running BFS.
    pub known_symbols: HashSet<String>,
    /// False when the binary is stripped — func_ranges are empty, call graph cannot be built.
    pub has_symbol_table: bool,
    /// Name of the `main` function (or best equivalent) for `EntryPoints::Main`.
    pub main_entry: Option<String>,
    /// Names of all exported functions for `EntryPoints::AllExported`.
    pub exported_entries: Vec<String>,
}

/// Abstracts the call-graph extraction backend.
///
/// Currently implemented by `ElfExtractor` (ELF + capstone disassembly).
/// Future backends could use LLVM bitcode, DWARF call-graph sections, etc.
pub trait CallGraphExtractor: Send + Sync {
    fn extract(&self, artifact: &Path) -> Result<ArtifactCallGraph>;
}

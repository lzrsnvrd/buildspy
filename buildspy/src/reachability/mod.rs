//! CVE reachability analysis: is a vulnerable function reachable from `main`?
//!
//! Shared-library reachability is layered into three levels of increasing cost
//! and decreasing return (see `docs/reachability-plan.md`):
//!
//!   * **Level 1 — boundary reachability (implicit, zero-cost).** When the CVE
//!     symbol is itself a `.so` API that the program (or its static deps)
//!     imports, it appears in the ELF PLT/GOT and thus in the call graph's
//!     `known_symbols`. [`classify`] then answers `reachable` / `not_reachable`
//!     with no library loading at all. This is the default and needs no flag.
//!   * **Level 2 — partial intra-`.so` graph (opt-in via `follow_shared`).**
//!     Pull in the transitive `DT_NEEDED` closure ([`deps::collect_so_closure`])
//!     and run each `.so` through [`ElfExtractor`], merging the exported→exported
//!     and exported→import edges. This makes multi-hop chains across the public
//!     API contour (e.g. `curl_easy_perform → SSL_connect`) visible. Gaps become
//!     honest `Unknown`.
//!   * **Level 3 — debuginfo (not implemented here).** Recovers internal `.so`
//!     function boundaries but not the function-pointer dispatch that dominates
//!     libssl/libcrypto, so it does not raise the precision ceiling — omitted by
//!     design.

pub mod capture;
pub mod input;
pub mod types;

mod callgraph;
mod demangle;
mod deps;
mod elf;
mod extractor;
mod llvm;
mod svf;
mod util;

pub use capture::BitcodeCapture;
pub use extractor::EntryPoints;

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use self::{
    callgraph::CallGraph,
    elf::ElfExtractor,
    extractor::CallGraphExtractor,
    input::VulnerableTarget,
    llvm::LlvmExtractor,
    svf::SvfExtractor,
    types::{Reachability, ReachabilityResult, UnknownReason},
};

/// Pick a call-graph extractor for `artifact` from its magic bytes:
/// LLVM bitcode (`BC\xC0\xDE`) → [`SvfExtractor`] when a `wpa` path is supplied
/// (points-to resolution of function pointers), otherwise [`LlvmExtractor`];
/// everything else (ELF and unreadable files) → [`ElfExtractor`], which reports
/// its own parse errors.
fn make_extractor(
    artifact: &Path,
    devirtualize: bool,
    wpa: Option<&Path>,
) -> Box<dyn CallGraphExtractor> {
    if is_llvm_bitcode(artifact) {
        match wpa {
            Some(w) => Box::new(SvfExtractor::new(w.to_path_buf(), devirtualize)),
            None => Box::new(LlvmExtractor::new(devirtualize)),
        }
    } else {
        Box::new(ElfExtractor)
    }
}

fn is_llvm_bitcode(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    // Raw bitcode `BC\xC0\xDE`, or the bitcode-wrapper header `0x0B17C0DE`.
    magic == [0x42, 0x43, 0xC0, 0xDE] || magic == [0xDE, 0xC0, 0x17, 0x0B]
}

/// High-level reachability analysis facade.
///
/// By default the extractor is chosen per artifact from its magic bytes
/// (ELF vs LLVM bitcode). Pass a fixed backend with `with_extractor` to
/// override auto-detection.
pub struct ReachabilityAnalyzer {
    /// Forced backend; when `None`, an extractor is picked per artifact.
    override_extractor: Option<Box<dyn CallGraphExtractor>>,
    /// Resolve C++ virtual calls in LLVM bitcode (LlvmExtractor only).
    devirtualize: bool,
    /// Level 2: follow the `DT_NEEDED` closure of ELF artifacts and merge each
    /// shared object's partial call graph.
    follow_shared: bool,
    /// Phase 3: use SVF's `wpa` points-to analysis for LLVM bitcode so calls
    /// through function pointers are resolved (falls back to LlvmExtractor when
    /// `wpa` is unavailable).
    points_to: bool,
    /// ELF artifacts to seed the Level 2 `DT_NEEDED` walk from, when they differ
    /// from the analysed artifacts. Bitcode capture replaces each binary with a
    /// `.bc`, which carries no `DT_NEEDED` — the original ELF still does.
    shared_roots: Vec<PathBuf>,
}

impl ReachabilityAnalyzer {
    pub fn new() -> Self {
        Self {
            override_extractor: None,
            devirtualize: false,
            follow_shared: false,
            points_to: false,
            shared_roots: Vec::new(),
        }
    }

    /// Enable C++ devirtualization for LLVM bitcode artifacts.
    pub fn with_devirtualize(mut self, devirtualize: bool) -> Self {
        self.devirtualize = devirtualize;
        self
    }

    /// Enable Level 2 shared-library following (see module docs).
    pub fn with_follow_shared(mut self, follow_shared: bool) -> Self {
        self.follow_shared = follow_shared;
        self
    }

    /// Enable SVF points-to resolution of function-pointer calls (Phase 3).
    pub fn with_points_to(mut self, points_to: bool) -> Self {
        self.points_to = points_to;
        self
    }

    /// Seed the Level 2 `DT_NEEDED` walk from these ELF paths instead of the
    /// analysed artifacts (see [`Self::shared_roots`]).
    pub fn with_shared_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.shared_roots = roots;
        self
    }

    pub fn with_extractor(extractor: Box<dyn CallGraphExtractor>) -> Self {
        Self {
            override_extractor: Some(extractor),
            devirtualize: false,
            follow_shared: false,
            points_to: false,
            shared_roots: Vec::new(),
        }
    }

    /// Analyze one or more artifacts (ELF and/or LLVM bitcode) against a list
    /// of CVE targets.
    ///
    /// `entry_mode` controls the BFS entry point(s):
    ///   - `Main`        → `main` function (executables)
    ///   - `AllExported` → every exported symbol (shared libraries)
    pub fn analyze(
        &self,
        artifacts: &[&Path],
        targets: &[VulnerableTarget],
        entry_mode: EntryPoints,
    ) -> Vec<ReachabilityResult> {
        let mut cg = CallGraph::new();
        let mut entries: Vec<String> = Vec::new();

        // Resolve `wpa` once when points-to is requested; warn (and fall back to
        // direct-call analysis) if SVF is not installed.
        let wpa = if self.points_to {
            let found = svf::find_wpa();
            if found.is_none() {
                log::warn!(
                    "reachability: --reachability-points-to set but SVF `wpa` not found in PATH; \
                     falling back to direct-call analysis (function pointers stay Unknown). \
                     Install SVF or set BUILDSPY_WPA. See https://github.com/SVF-tools/SVF"
                );
            }
            found
        } else {
            None
        };

        for &artifact in artifacts {
            // Either the forced backend, or one auto-detected for this artifact.
            let auto;
            let extractor: &dyn CallGraphExtractor = match &self.override_extractor {
                Some(e) => e.as_ref(),
                None => {
                    auto = make_extractor(artifact, self.devirtualize, wpa.as_deref());
                    auto.as_ref()
                }
            };
            match extractor.extract(artifact) {
                Ok(ag) => {
                    let artifact_entries = match entry_mode {
                        EntryPoints::Main => ag.main_entry.iter().cloned().collect::<Vec<_>>(),
                        EntryPoints::AllExported => ag.exported_entries.clone(),
                    };
                    entries.extend(artifact_entries);
                    cg.merge(ag);
                }
                Err(e) => {
                    log::error!(
                        "reachability: failed to extract call graph from {}: {e}",
                        artifact.display()
                    );
                }
            }
        }

        if self.follow_shared {
            let roots: Vec<&Path> = if self.shared_roots.is_empty() {
                artifacts.to_vec()
            } else {
                self.shared_roots.iter().map(PathBuf::as_path).collect()
            };
            self.merge_shared_closure(&mut cg, &roots);
        }

        if entries.is_empty() {
            // Fallback: try "main" by name even if not found via symbol table.
            entries.push("main".to_string());
        }

        targets
            .iter()
            .map(|t| {
                let reachability = classify(&cg, &entries, &t.symbol);
                ReachabilityResult::from_target(t, reachability)
            })
            .collect()
    }

    /// Level 2: analyse every `.so` in the artifacts' `DT_NEEDED` closure with
    /// [`ElfExtractor`] and merge the results into `cg`. Entries are left
    /// untouched — this only enriches the graph so BFS from `main` can cross the
    /// `.so` boundary. Artifacts and libraries are analysed at most once.
    fn merge_shared_closure(&self, cg: &mut CallGraph, artifacts: &[&Path]) {
        // Seed with the artifacts themselves so a library given explicitly (and
        // also reachable via DT_NEEDED) is not analysed twice.
        let mut analyzed: HashSet<PathBuf> = artifacts.iter().map(|a| canonical(a)).collect();
        let elf = ElfExtractor;
        let mut merged = 0usize;

        for &artifact in artifacts {
            for so in deps::collect_so_closure(artifact) {
                if !analyzed.insert(so.clone()) {
                    continue;
                }
                match elf.extract(&so) {
                    Ok(ag) => {
                        cg.merge(ag);
                        merged += 1;
                    }
                    Err(e) => {
                        log::debug!("reachability: skip shared object {}: {e}", so.display());
                    }
                }
            }
        }

        if merged > 0 {
            log::info!("reachability: merged {merged} shared-library graph(s) (follow-shared).");
        }
    }
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn classify(cg: &CallGraph, entries: &[String], symbol: &str) -> Reachability {
    if !cg.has_symbol_table {
        return Reachability::Unknown(UnknownReason::NoSymbolTable);
    }
    if !cg.target_observable(symbol) {
        return Reachability::Unknown(UnknownReason::TargetNotObservable);
    }

    let mut best = Reachability::NotReachable;
    for entry in entries {
        match cg.bfs(entry, symbol) {
            r @ Reachability::Reachable { .. } => return r,
            r @ Reachability::Unknown(_) => best = r, // Unknown > NotReachable
            Reachability::NotReachable => {}
        }
    }
    best
}

use serde::{Deserialize, Serialize};

use super::input::VulnerableTarget;

// Internal analysis result — not serialized directly.
pub enum Reachability {
    Reachable { chain: Vec<String> },
    NotReachable,
    Unknown(UnknownReason),
}

pub enum UnknownReason {
    /// Symbol is neither imported nor defined in this binary (likely library-internal).
    TargetNotObservable,
    /// BFS did not reach target, but indirect calls (function pointers, vtables)
    /// were present in the reachable set — reachability undetermined.
    IndirectCallsPresent { count: usize },
    /// Binary has no symbol table (stripped); call graph cannot be built.
    NoSymbolTable,
}

/// Serializable output record for one CVE target.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReachabilityResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// true = reachable, false = not reachable, null = undetermined.
    pub reachable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<String>,
}

impl ReachabilityResult {
    pub fn from_target(target: &VulnerableTarget, r: Reachability) -> Self {
        let (reachable, chain, unknown_reason) = match r {
            Reachability::Reachable { chain } => (Some(true), Some(chain), None),
            Reachability::NotReachable => (Some(false), None, None),
            Reachability::Unknown(reason) => {
                let s = match reason {
                    UnknownReason::TargetNotObservable => "target_not_observable".to_string(),
                    UnknownReason::IndirectCallsPresent { count } => {
                        format!("indirect_calls_present:{count}")
                    }
                    UnknownReason::NoSymbolTable => "no_symbol_table".to_string(),
                };
                (None, None, Some(s))
            }
        };
        Self {
            cve: target.cve.clone(),
            symbol: target.symbol.clone(),
            library: target.library.clone(),
            reachable,
            chain,
            unknown_reason,
        }
    }
}

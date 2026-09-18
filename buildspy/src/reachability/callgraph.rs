use std::collections::{HashMap, HashSet, VecDeque};

use super::{
    extractor::ArtifactCallGraph,
    types::{Reachability, UnknownReason},
};

pub struct CallGraph {
    /// Forward edges: caller → {callees}.
    edges: HashMap<String, HashSet<String>>,
    indirect_callers: HashSet<String>,
    known_symbols: HashSet<String>,
    pub has_symbol_table: bool,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
            indirect_callers: HashSet::new(),
            known_symbols: HashSet::new(),
            has_symbol_table: false,
        }
    }

    pub fn merge(&mut self, ag: ArtifactCallGraph) {
        if ag.has_symbol_table {
            self.has_symbol_table = true;
        }
        for (caller, callee) in ag.edges {
            self.edges.entry(caller).or_default().insert(callee);
        }
        for s in ag.indirect_callers {
            self.indirect_callers.insert(s);
        }
        for s in ag.known_symbols {
            self.known_symbols.insert(s);
        }
    }

    pub fn target_observable(&self, target: &str) -> bool {
        self.known_symbols.contains(target)
    }

    /// BFS from `entry` looking for `target`.
    ///
    /// Precondition: caller must check `target_observable` and `has_symbol_table`
    /// before calling this — those cases are not re-checked here.
    pub fn bfs(&self, entry: &str, target: &str) -> Reachability {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut parent: HashMap<String, String> = HashMap::new();

        queue.push_back(entry.to_string());
        visited.insert(entry.to_string());

        while let Some(current) = queue.pop_front() {
            let empty = HashSet::new();
            let callees = self.edges.get(&current).unwrap_or(&empty);

            for callee in callees {
                if callee.as_str() == target {
                    let mut chain = vec![callee.clone()];
                    let mut cur = current.clone();
                    chain.push(cur.clone());
                    while let Some(p) = parent.get(&cur) {
                        chain.push(p.clone());
                        cur = p.clone();
                    }
                    chain.reverse();
                    return Reachability::Reachable { chain };
                }

                if !visited.contains(callee.as_str()) {
                    visited.insert(callee.clone());
                    parent.insert(callee.clone(), current.clone());
                    queue.push_back(callee.clone());
                }
            }
        }

        let indirect_count = visited
            .iter()
            .filter(|v| self.indirect_callers.contains(v.as_str()))
            .count();

        if indirect_count > 0 {
            Reachability::Unknown(UnknownReason::IndirectCallsPresent { count: indirect_count })
        } else {
            Reachability::NotReachable
        }
    }
}

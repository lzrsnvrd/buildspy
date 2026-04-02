//! Process tracking: PID discovery via /proc and build-orchestrator filtering.

use std::{
    collections::{HashSet, VecDeque},
    path::Path,
    time::Duration,
};

/// Build-orchestration tools whose file opens should NOT be reported as
/// project dependencies.  These tools open their own runtime libraries
/// (cmake → libjsoncpp, make → libc, ninja → libc++, …) which have nothing
/// to do with the project being built.
///
/// Compilers, linkers, and assemblers are intentionally NOT listed here —
/// the headers and libraries they open ARE the project's dependencies.
pub const BUILD_ORCHESTRATORS: &[&str] = &[
    // CMake family
    "cmake", "ccmake", "cmake3", "ctest", "cpack",
    // Make family
    "make", "gmake", "mingw32-make",
    // Ninja
    "ninja", "samu",
    // Meson / autotools
    "meson", "autoconf", "automake", "configure",
    // Package-config helpers
    "pkg-config", "pkgconf",
    // Shells used as build glue (sh/bash open their own libc, not project libs)
    "sh", "bash", "dash", "zsh", "fish",
    // Python / Perl (used by meson, autotools)
    "python3", "python", "perl",
];

/// Continuously discover descendant PIDs of `root_pid` and send them to `tx`.
///
/// Sends `root_pid` itself first so the caller can register it immediately.
/// Polls every 25 ms and stops when `root_pid` disappears from `/proc`.
/// This is a user-space complement to the `sched_process_fork` tracepoint
/// which can miss forks on some kernels (clone3, vfork).
pub async fn watch_children(root_pid: u32, tx: tokio::sync::mpsc::UnboundedSender<u32>) {
    // Seed the caller with the root PID so it can register comm/cwd.
    let _ = tx.send(root_pid);

    let mut known: HashSet<u32> = HashSet::new();
    known.insert(root_pid);
    loop {
        for pid in discover_new_children(&known) {
            known.insert(pid);
            let _ = tx.send(pid);
        }
        if !Path::new(&format!("/proc/{root_pid}")).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Returns true if the process `comm` name belongs to a build orchestrator
/// whose file opens should be filtered out.
pub fn is_build_orchestrator(comm: &str) -> bool {
    // Strip version suffixes: "python3.11" → "python3", "bash5" → "bash"
    let base = comm
        .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .trim_end_matches('-');
    BUILD_ORCHESTRATORS.contains(&comm) || BUILD_ORCHESTRATORS.contains(&base)
}

/// Scan /proc to find PIDs that are children (or deeper descendants) of any
/// PID in `known` but not yet in `known`.
///
/// Uses `/proc/<pid>/task/<pid>/children` when available (CONFIG_PROC_CHILDREN),
/// falling back to reading PPid from `/proc/<pid>/status` for every process
/// visible in /proc.
pub fn discover_new_children(known: &HashSet<u32>) -> Vec<u32> {
    // Fast path: kernel exposes direct children list per thread.
    if let Some(pids) = discover_via_children_file(known) {
        return pids;
    }
    // Slow path: walk all of /proc and match by PPid.
    discover_via_proc_scan(known)
}

/// Try /proc/<pid>/task/<pid>/children.  Returns None if the file is missing
/// on this kernel (CONFIG_PROC_CHILDREN not set).
fn discover_via_children_file(known: &HashSet<u32>) -> Option<Vec<u32>> {
    let mut new_pids = Vec::new();
    let mut any_file_found = false;
    let mut queue: VecDeque<u32> = known.iter().copied().collect();
    let mut visited: HashSet<u32> = known.clone();

    while let Some(pid) = queue.pop_front() {
        let path = format!("/proc/{pid}/task/{pid}/children");
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        any_file_found = true;
        for child_str in content.split_whitespace() {
            if let Ok(child) = child_str.parse::<u32>() {
                if visited.insert(child) {
                    new_pids.push(child);
                    queue.push_back(child);
                }
            }
        }
    }

    if any_file_found {
        Some(new_pids)
    } else {
        // No children files found – this kernel may not have CONFIG_PROC_CHILDREN.
        None
    }
}

/// Fallback: read PPid from every /proc/<pid>/status and build descendants.
fn discover_via_proc_scan(known: &HashSet<u32>) -> Vec<u32> {
    let mut ppid_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return vec![];
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let status_path = entry.path().join("status");
        let Ok(content) = std::fs::read_to_string(status_path) else {
            continue;
        };
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                if let Ok(ppid) = rest.trim().parse::<u32>() {
                    ppid_map.insert(pid, ppid);
                    break;
                }
            }
        }
    }

    // BFS: find all descendants of any known PID.
    let mut new_pids = Vec::new();
    let mut visited: HashSet<u32> = known.clone();
    let mut queue: VecDeque<u32> = known.iter().copied().collect();

    while let Some(ancestor) = queue.pop_front() {
        for (&pid, &ppid) in &ppid_map {
            if ppid == ancestor && visited.insert(pid) {
                new_pids.push(pid);
                queue.push_back(pid);
            }
        }
    }

    new_pids
}

//! Helpers for reading per-process metadata from /proc.

use std::path::PathBuf;

/// Read the comm name (process name) for `pid`, trimmed of whitespace.
/// Returns an empty string if the file is unreadable (process already exited).
pub fn read_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Read the current working directory of `pid` via `/proc/<pid>/cwd`.
/// Returns `None` if the symlink is unreadable.
pub fn read_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

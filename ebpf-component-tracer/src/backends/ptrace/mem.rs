//! Process-memory and /proc helpers for the ptrace backend.

use std::io::{Read, Seek, SeekFrom};

use tokio::sync::mpsc::UnboundedSender;

/// Read the `openat` pathname argument from a stopped tracee's memory and
/// send it on `path_tx`.  `ptr` is the value of the `rsi` register.
pub fn emit_path(path_tx: &UnboundedSender<(String, u32)>, pid: u32, ptr: u64) {
    if let Some(path) = read_path_from_mem(pid, ptr) {
        if !path.is_empty() {
            let _ = path_tx.send((path, pid));
        }
    }
}

/// Read a null-terminated string from a ptrace-stopped process's virtual
/// memory via `/proc/<pid>/mem`.  The process is stopped, so the read is
/// race-free.
fn read_path_from_mem(pid: u32, ptr: u64) -> Option<String> {
    if ptr == 0 {
        return None;
    }
    let mut file = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    file.seek(SeekFrom::Start(ptr)).ok()?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 {
        return None;
    }
    String::from_utf8(buf[..end].to_vec()).ok()
}

/// Read the parent PID (`PPid:`) from `/proc/{pid}/status`.
///
/// Used as a FORK-race fallback when `child_to_parent` has no entry for a
/// child that exits before its parent's `PTRACE_EVENT_FORK/CLONE/VFORK` is
/// processed.  At the time of the call the child is a regular zombie so the
/// file is still readable.
pub fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

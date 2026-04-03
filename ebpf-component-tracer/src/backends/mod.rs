//! Tracing backend abstraction.
//!
//! `TracingSession` decouples `main` from the concrete mechanism used to
//! intercept `openat` calls (eBPF ring-buffer or ptrace syscall-stop).
//!
//! Both backends produce the same three channels:
//!   * `path_rx`   – `(path, opener_pid)` file-open events
//!   * `new_pid_rx`– new PIDs discovered in the process tree (for comm/cwd metadata)
//!   * `exit_rx`   – build exit code; resolves only after all events are flushed

pub mod ebpf;
pub mod proc_watcher;
pub mod ptrace;

use std::path::Path;

use anyhow::Result;
use tokio::sync::{mpsc::UnboundedReceiver, oneshot};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A live tracing session.  Owned by `main` for the duration of the build.
pub struct TracingSession {
    /// `(absolute_path, opener_pid)` from every `openat` call made by the build.
    pub path_rx: UnboundedReceiver<(String, u32)>,
    /// PIDs newly discovered in the build process tree.  Use to collect
    /// `/proc/<pid>/comm` and `/proc/<pid>/cwd` for later filtering.
    pub new_pid_rx: UnboundedReceiver<u32>,
    /// Resolves with the build's exit code once the build process has exited
    /// *and* the backend has finished flushing any in-flight events.
    pub exit_rx: oneshot::Receiver<Option<i32>>,
    /// If the backend supports graceful shutdown (ptrace), calling this will
    /// SIGKILL the build process group and unblock `exit_rx`.
    /// None for backends that handle cleanup themselves (eBPF).
    pub shutdown: Option<Box<dyn FnOnce() + Send + 'static>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// eBPF ring-buffer (requires Linux ≥ 4.4 with BPF support and CAP_BPF).
    Ebpf,
    /// ptrace syscall interception (works on any Linux kernel, requires SYS_PTRACE).
    Ptrace,
    /// Try eBPF first; fall back to ptrace if eBPF is unavailable.
    Auto,
}

impl Backend {
    pub fn from_str(s: &str) -> Self {
        match s {
            "ebpf"  => Backend::Ebpf,
            "ptrace" => Backend::Ptrace,
            _ => Backend::Auto,
        }
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Start a tracing session using the requested backend.
pub fn start_session(
    backend: Backend,
    cmd: &[String],
    cwd: &Path,
    verbose: bool,
) -> Result<TracingSession> {
    match backend {
        Backend::Ebpf => ebpf::start(cmd, cwd, verbose),
        Backend::Ptrace => ptrace::start(cmd, cwd, verbose),
        Backend::Auto => {
            match ebpf::start(cmd, cwd, verbose) {
                Ok(session) => {
                    log::info!("Backend: eBPF.");
                    Ok(session)
                }
                Err(e) => {
                    log::warn!("eBPF unavailable ({e}), falling back to ptrace.");
                    ptrace::start(cmd, cwd, verbose)
                }
            }
        }
    }
}


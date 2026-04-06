//! ptrace tracing backend.
//!
//! Intercepts `openat(2)` calls and follows the complete process tree via
//! `PTRACE_O_TRACEFORK`, `PTRACE_O_TRACECLONE`, and `PTRACE_O_TRACEVFORK`.
//!
//! # Trace mode selection
//!
//! On startup the backend tries to install a seccomp-bpf filter (see
//! [`seccomp`]) in the child process.  If the kernel supports it (Linux ≥
//! 3.5) the event loop uses **`PTRACE_CONT`** and receives a single
//! `PTRACE_EVENT_SECCOMP` stop only for `openat` calls, reducing overhead by
//! roughly two orders of magnitude.  On older kernels the backend falls back
//! to **`PTRACE_SYSCALL`** which stops on every syscall entry and exit.
//!
//! The trace mode is communicated from the child process to the tracer thread
//! via a one-byte pipe written in `pre_exec` (after fork, before exec).
//!
//! # Architecture note
//!
//! Currently only x86_64 is supported because `getregs` and the syscall
//! register layout are architecture-specific.
//!
//! # Thread model
//!
//! Linux ptrace ties the "tracer" identity to the specific OS thread that
//! forked the tracee.  The child is therefore spawned *and* the entire event
//! loop runs inside a single dedicated `std::thread`.

mod seccomp;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("the ptrace backend currently only supports x86_64");

use std::{
    io::{Read, Seek, SeekFrom},
    os::{raw::c_int, unix::process::CommandExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
};

use anyhow::{Context, Result};
use nix::{
    sys::{
        ptrace,
        ptrace::Options,
        signal::{killpg, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{gettid, Pid},
};
use tokio::sync::mpsc::UnboundedSender;

use super::TracingSession;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `openat(2)` syscall number on x86_64.
const OPENAT_NR: u64 = 257;

/// `PTRACE_EVENT_SECCOMP` — delivered when a seccomp filter returns
/// `SECCOMP_RET_TRACE`.  The value is not (yet) exposed by the nix crate as
/// a named constant, so we define it here.
const PTRACE_EVENT_SECCOMP: i32 = 7;

// ---------------------------------------------------------------------------
// Trace mode
// ---------------------------------------------------------------------------

/// How the ptrace event loop intercepts `openat` calls.
///
/// Chosen once at startup based on whether the seccomp-bpf filter was
/// successfully installed in the child process.
#[derive(Clone, Copy, Debug)]
enum TraceMode {
    /// seccomp-bpf filter active.
    ///
    /// Processes are resumed with `PTRACE_CONT`.  The only syscall that
    /// generates a ptrace stop is `openat(2)`, delivered as
    /// `PTRACE_EVENT_SECCOMP`.  No entry/exit pair tracking required.
    Seccomp,

    /// Full syscall interception (kernel < 3.5 fallback).
    ///
    /// Processes are resumed with `PTRACE_SYSCALL`.  Every syscall produces
    /// an entry stop and an exit stop; the event loop tracks which PIDs are
    /// currently inside a syscall to distinguish the two.
    FullSyscall,
}

// ---------------------------------------------------------------------------
// No-op SIGUSR1 handler
// ---------------------------------------------------------------------------

/// No-op handler: receiving SIGUSR1 simply interrupts blocking syscalls
/// (e.g. `waitpid`) so the ptrace thread can check flags or log status.
/// `SA_RESTART` is intentionally absent so the interrupt is not suppressed.
extern "C" fn sigusr1_noop(_: c_int) {}

// ---------------------------------------------------------------------------
// Public entry-point
// ---------------------------------------------------------------------------

/// Spawn the build command under ptrace and return a `TracingSession`.
pub fn start(cmd: &[String], cwd: &Path, verbose: bool) -> Result<TracingSession> {
    let (path_tx, path_rx) = tokio::sync::mpsc::unbounded_channel::<(String, u32)>();
    let (new_pid_tx, new_pid_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<Option<i32>>();

    // Shutdown flag and TID of the ptrace thread.  The shutdown closure sets
    // the flag and sends SIGUSR1 to the ptrace thread, interrupting its
    // blocking `waitpid` so it can detect the flag.
    let shutdown = Arc::new(AtomicBool::new(false));
    let ptrace_tid = Arc::new(AtomicI32::new(0));

    let shutdown_for_thread = Arc::clone(&shutdown);
    let tid_for_thread = Arc::clone(&ptrace_tid);

    let cmd: Vec<String> = cmd.to_vec();
    let cwd: PathBuf = cwd.to_path_buf();

    // The ptrace thread forks the child AND runs the event loop — all on the
    // same OS thread, as required by the Linux ptrace API.
    std::thread::Builder::new()
        .name("ptrace-loop".into())
        .spawn(move || {
            // Install a no-op SIGUSR1 handler without SA_RESTART so that
            // `waitpid` is interrupted (returns EINTR) on receipt.
            unsafe {
                let sa = SigAction::new(
                    SigHandler::Handler(sigusr1_noop),
                    SaFlags::empty(),
                    SigSet::empty(),
                );
                let _ = sigaction(Signal::SIGUSR1, &sa);
            }

            tid_for_thread.store(gettid().as_raw(), Ordering::Release);

            // ------------------------------------------------------------------
            // Pipe for seccomp status (child → parent).
            //
            // The child writes one byte in pre_exec: 1 = filter installed,
            // 0 = fallback needed.  The tracer reads this byte before entering
            // the event loop to choose the correct TraceMode.
            // ------------------------------------------------------------------
            let mut pipe_fds = [-1i32; 2];
            if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
                log::error!("ptrace: pipe() failed — cannot determine trace mode");
                let _ = exit_tx.send(None);
                return;
            }
            let (seccomp_read_fd, seccomp_write_fd) = (pipe_fds[0], pipe_fds[1]);

            // Prevent the read end from leaking into the build process.
            unsafe { libc::fcntl(seccomp_read_fd, libc::F_SETFD, libc::FD_CLOEXEC) };

            // ------------------------------------------------------------------
            // Spawn the child.
            // ------------------------------------------------------------------
            let mut command = std::process::Command::new(&cmd[0]);
            command.args(&cmd[1..]).current_dir(&cwd);

            // pre_exec runs after fork, before exec, in the child process.
            // Only async-signal-safe operations are allowed here.
            unsafe {
                command.pre_exec(move || {
                    // Read end not needed in the child.
                    libc::close(seccomp_read_fd);

                    // Attempt to install the seccomp-bpf filter.
                    let ok = seccomp::try_install();

                    // Notify the parent of the outcome.
                    let byte: u8 = ok as u8;
                    libc::write(
                        seccomp_write_fd,
                        (&raw const byte).cast::<libc::c_void>(),
                        1,
                    );
                    libc::close(seccomp_write_fd);

                    // Register this process as a ptrace tracee.  Must come
                    // after seccomp so the initial exec-stop fires with the
                    // filter already in place.
                    ptrace::traceme()
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                });
            }

            let child = match command.spawn() {
                Ok(c) => c,
                Err(e) => {
                    log::error!("ptrace: failed to spawn '{}': {e}", cmd[0]);
                    unsafe {
                        libc::close(seccomp_read_fd);
                        libc::close(seccomp_write_fd);
                    }
                    let _ = exit_tx.send(None);
                    return;
                }
            };

            // ------------------------------------------------------------------
            // Read the seccomp status byte written by the child in pre_exec.
            // ------------------------------------------------------------------

            // Close the write end in the parent so that read() below returns
            // EOF (rather than blocking forever) if the child fails to write.
            unsafe { libc::close(seccomp_write_fd) };

            let mut status_byte = [0u8; 1];
            let n = unsafe {
                libc::read(
                    seccomp_read_fd,
                    status_byte.as_mut_ptr().cast::<libc::c_void>(),
                    1,
                )
            };
            unsafe { libc::close(seccomp_read_fd) };

            let mode = if n == 1 && status_byte[0] == 1 {
                log::info!("ptrace: seccomp-bpf filter active — stopping only on openat(2)");
                TraceMode::Seccomp
            } else {
                log::warn!(
                    "ptrace: seccomp-bpf unavailable (kernel < 3.5?) — \
                     tracing all syscalls; build will be significantly slower"
                );
                TraceMode::FullSyscall
            };

            let child_pid = child.id();
            log::info!("Build started (PID {child_pid}) via ptrace backend ({mode:?} mode).");
            let _ = new_pid_tx.send(child_pid);

            ptrace_loop(child_pid, mode, path_tx, new_pid_tx, exit_tx, verbose, shutdown_for_thread);

            // The child is already reaped inside ptrace_loop; Drop::drop on
            // `child` will call a harmless waitpid that returns ECHILD.
            drop(child);
        })
        .context("failed to spawn ptrace thread")?;

    let our_pid = std::process::id() as i32;

    // Watchdog: every 10 s of silence poke the ptrace thread via SIGUSR1.
    // The thread will then log comm + wchan for every still-alive process.
    // This uses the same SIGUSR1/EINTR path as shutdown but without setting
    // the shutdown flag, so the loop just logs and continues.
    {
        let tid_watch = Arc::clone(&ptrace_tid);
        let shutdown_watch = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("ptrace-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(10));
                if shutdown_watch.load(Ordering::Acquire) {
                    break;
                }
                let tid = tid_watch.load(Ordering::Acquire);
                if tid != 0 {
                    unsafe { libc::tgkill(our_pid, tid, libc::SIGUSR1) };
                }
            })
            .ok();
    }

    let shutdown_fn: Box<dyn FnOnce() + Send + 'static> = Box::new(move || {
        shutdown.store(true, Ordering::Release);
        let tid = ptrace_tid.load(Ordering::Acquire);
        if tid != 0 {
            unsafe { libc::tgkill(our_pid, tid, libc::SIGUSR1) };
        }
    });

    Ok(TracingSession { path_rx, new_pid_rx, exit_rx, shutdown: Some(shutdown_fn) })
}

// ---------------------------------------------------------------------------
// Resume helpers
// ---------------------------------------------------------------------------

/// Resume a ptrace-stopped tracee, optionally delivering a signal.
///
/// In `Seccomp` mode the tracee is continued with `PTRACE_CONT`; in
/// `FullSyscall` mode with `PTRACE_SYSCALL` so the next syscall stop is
/// delivered.  `ESRCH` is silently ignored (process already exited).
fn resume(pid: Pid, sig: Option<Signal>, mode: TraceMode) {
    let result = match mode {
        TraceMode::Seccomp => ptrace::cont(pid, sig),
        TraceMode::FullSyscall => ptrace::syscall(pid, sig),
    };
    if let Err(e) = result {
        if e != nix::errno::Errno::ESRCH {
            log::warn!(
                "ptrace: failed to resume PID {}: {} (signal={:?}) — tracee may be stuck",
                pid, e, sig
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ptrace event loop
// ---------------------------------------------------------------------------

fn ptrace_loop(
    root_pid: u32,
    mode: TraceMode,
    path_tx: UnboundedSender<(String, u32)>,
    new_pid_tx: UnboundedSender<u32>,
    exit_tx: tokio::sync::oneshot::Sender<Option<i32>>,
    verbose: bool,
    shutdown: Arc<AtomicBool>,
) {
    let root = Pid::from_raw(root_pid as i32);

    // Wait for the initial exec-stop (SIGTRAP) triggered by PTRACE_TRACEME.
    match waitpid(root, None) {
        Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {}
        Ok(other) => {
            log::error!("ptrace: unexpected initial stop: {:?}", other);
            let _ = exit_tx.send(None);
            return;
        }
        Err(e) => {
            log::error!("ptrace: initial waitpid failed: {e}");
            let _ = exit_tx.send(None);
            return;
        }
    }

    // Build the option set based on the active trace mode.
    //
    // Seccomp mode: PTRACE_O_TRACESECCOMP enables PTRACE_EVENT_SECCOMP stops.
    //   PTRACE_O_TRACESYSGOOD is omitted — no PTRACE_SYSCALL stops are issued.
    //
    // FullSyscall mode: PTRACE_O_TRACESYSGOOD sets bit 7 of the signal in
    //   PtraceSyscall events so they are distinguishable from real SIGTRAPs.
    let base_options = Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACEEXEC;

    let options = match mode {
        TraceMode::Seccomp => base_options | Options::PTRACE_O_TRACESECCOMP,
        TraceMode::FullSyscall => base_options | Options::PTRACE_O_TRACESYSGOOD,
    };

    if let Err(e) = ptrace::setoptions(root, options) {
        log::error!("ptrace: setoptions failed: {e}");
        let _ = exit_tx.send(None);
        return;
    }

    resume(root, None, mode);
    log::debug!("ptrace: event loop started (root PID {root_pid}, {mode:?})");

    // ------------------------------------------------------------------
    // Per-loop state
    // ------------------------------------------------------------------

    // PIDs announced via fork/clone events but whose first waitpid stop has
    // not been processed yet.
    let mut pending_children: std::collections::HashSet<u32> =
        std::collections::HashSet::new();

    // All PIDs currently believed to be alive — used by the watchdog to
    // log stall diagnostics.
    let mut alive_pids: std::collections::HashSet<u32> =
        std::collections::HashSet::new();
    alive_pids.insert(root_pid);

    // Maps each child PID to its ptrace-parent PID.
    //
    // Used to re-deliver SIGCHLD after processing a child's exit event.
    //
    // Under ptrace, the kernel may deliver SIGCHLD to a parent process (which
    // we intercept and inject) *before* the tracer has acknowledged the child's
    // exit via waitpid.  During that window the child is in "ptrace-zombie"
    // state and is invisible to the parent's `waitpid(WNOHANG)`.  The parent's
    // SIGCHLD handler therefore finds nothing, returns, and the parent re-enters
    // pselect/epoll — blocking forever, because no second SIGCHLD arrives.
    //
    // Fix: when we process Exited(child) (which ends the ptrace-zombie window),
    // send a fresh SIGCHLD to the parent.  If the original SIGCHLD fired first
    // the parent gets a second delivery and correctly reaps the zombie on the
    // second attempt.  If the original SIGCHLD fires after Exited the parent
    // gets two deliveries but handles both safely via `waitpid(WNOHANG)`.
    let mut child_to_parent: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();

    // FullSyscall-only: tracks which PIDs are currently inside a syscall so
    // we can distinguish entry stops (where we read the path) from exit stops.
    let mut in_syscall: std::collections::HashSet<u32> = std::collections::HashSet::new();

    let mut stall_count: u32 = 0;
    let mut exit_code: Option<i32> = None;

    // ------------------------------------------------------------------
    // Main event loop
    // ------------------------------------------------------------------
    loop {
        let status = match waitpid(None, Some(WaitPidFlag::__WALL)) {
            Ok(s) => {
                // Any real event resets the stall counter.
                stall_count = 0;
                s
            }
            Err(nix::errno::Errno::ECHILD) => break, // all tracees gone
            Err(nix::errno::Errno::EINTR) => {
                // SIGUSR1 from watchdog or shutdown closure.
                if shutdown.load(Ordering::Acquire) {
                    log::info!(
                        "ptrace: shutdown requested — sending SIGKILL to build process group"
                    );
                    let pgid = Pid::from_raw(root_pid as i32);
                    let _ = killpg(pgid, Signal::SIGKILL);
                    // Drain remaining tracees to avoid zombies.
                    loop {
                        match waitpid(None, Some(WaitPidFlag::__WALL)) {
                            Err(_) => break,
                            Ok(WaitStatus::Stopped(pid, _))
                            | Ok(WaitStatus::PtraceSyscall(pid)) => {
                                let _ = ptrace::detach(pid, Some(Signal::SIGKILL));
                            }
                            Ok(_) => {}
                        }
                    }
                    break;
                }

                // Watchdog ping — log alive processes and their wait channels.
                stall_count += 1;
                let mut alive: Vec<u32> = alive_pids.iter().copied().collect();
                alive.sort_unstable();
                log::warn!(
                    "ptrace: stall #{stall_count} — {} process(es) still alive:",
                    alive.len()
                );
                for pid in &alive {
                    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .unwrap_or_else(|_| "<exited>\n".into());
                    let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan"))
                        .unwrap_or_default();
                    let ppid = std::fs::read_to_string(format!("/proc/{pid}/status"))
                        .unwrap_or_default()
                        .lines()
                        .find(|l| l.starts_with("PPid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("?")
                        .to_string();

                    // /proc/{pid}/syscall: "nr arg0 arg1 … sp pc"
                    // Decode the syscall number and — for poll/select/wait4 —
                    // the key argument so we can see what the process blocks on.
                    let syscall_raw = std::fs::read_to_string(format!("/proc/{pid}/syscall"))
                        .unwrap_or_default();
                    let syscall_info = decode_syscall_line(syscall_raw.trim());

                    log::warn!(
                        "  PID {pid} (ppid={ppid}): comm={}, wchan={}, syscall=[{}]",
                        comm.trim(),
                        wchan.trim(),
                        syscall_info,
                    );
                }
                continue;
            }
            Err(e) => {
                log::error!("ptrace: waitpid error: {e}");
                break;
            }
        };

        match status {
            // ----------------------------------------------------------
            // Process exited normally.
            // ----------------------------------------------------------
            WaitStatus::Exited(pid, code) => {
                log::debug!("ptrace: Exited({pid}, {code})");
                let pid_u32 = pid.as_raw() as u32;
                in_syscall.remove(&pid_u32);
                pending_children.remove(&pid_u32);
                alive_pids.remove(&pid_u32);
                // Re-deliver SIGCHLD to the parent now that the ptrace-zombie
                // window is closed and the child is visible to waitpid(2).
                // See the child_to_parent comment for the full explanation.
                //
                // Race fallback: if the child's initial stop arrived in
                // waitpid *before* the parent's PTRACE_EVENT_FORK/CLONE/VFORK,
                // child_to_parent has no entry yet.  In that case read the PPid
                // from /proc (the child is a regular zombie so the file is still
                // readable) and send SIGCHLD directly.  Without this fallback the
                // parent would block in pselect6 forever because no second SIGCHLD
                // is ever delivered once we process the Exited event.
                let parent_pid = child_to_parent.remove(&pid_u32).or_else(|| {
                    let ppid = read_ppid(pid_u32);
                    if ppid.is_some() {
                        log::debug!(
                            "ptrace: Exited({pid}) — FORK race: child_to_parent empty, \
                             read PPid={ppid:?} from /proc"
                        );
                    }
                    ppid
                });
                if let Some(parent_pid) = parent_pid {
                    if alive_pids.contains(&parent_pid) {
                        log::debug!(
                            "ptrace: Exited({pid}) — re-sending SIGCHLD to parent {parent_pid}"
                        );
                        let _ = nix::sys::signal::kill(
                            Pid::from_raw(parent_pid as i32),
                            Signal::SIGCHLD,
                        );
                    }
                }
                if pid == root {
                    exit_code = Some(code);
                    // Root exited — descendants will be detached automatically
                    // when this thread exits.
                    break;
                }
            }

            // ----------------------------------------------------------
            // Process killed by a signal.
            // ----------------------------------------------------------
            WaitStatus::Signaled(pid, sig, _core) => {
                log::debug!("ptrace: Signaled({pid}, {sig})");
                let pid_u32 = pid.as_raw() as u32;
                in_syscall.remove(&pid_u32);
                pending_children.remove(&pid_u32);
                alive_pids.remove(&pid_u32);
                // Same SIGCHLD re-delivery as for Exited (including the FORK
                // race fallback via read_ppid).
                let parent_pid = child_to_parent.remove(&pid_u32).or_else(|| {
                    let ppid = read_ppid(pid_u32);
                    if ppid.is_some() {
                        log::debug!(
                            "ptrace: Signaled({pid}) — FORK race: child_to_parent empty, \
                             read PPid={ppid:?} from /proc"
                        );
                    }
                    ppid
                });
                if let Some(parent_pid) = parent_pid {
                    if alive_pids.contains(&parent_pid) {
                        log::debug!(
                            "ptrace: Signaled({pid}, {sig}) — re-sending SIGCHLD to parent {parent_pid}"
                        );
                        let _ = nix::sys::signal::kill(
                            Pid::from_raw(parent_pid as i32),
                            Signal::SIGCHLD,
                        );
                    }
                }
                if pid == root {
                    exit_code = None;
                    break;
                }
            }

            // ----------------------------------------------------------
            // Syscall entry/exit stop (FullSyscall mode only).
            //
            // PTRACE_O_TRACESYSGOOD sets bit 7 of the stop signal, which nix
            // surfaces as WaitStatus::PtraceSyscall.
            // ----------------------------------------------------------
            WaitStatus::PtraceSyscall(pid) => {
                let pid_u32 = pid.as_raw() as u32;

                if in_syscall.remove(&pid_u32) {
                    // Syscall EXIT — nothing to record, just resume.
                    log::debug!("ptrace: PtraceSyscall({pid}) EXIT");
                } else {
                    // Syscall ENTRY — check for openat.
                    in_syscall.insert(pid_u32);
                    if let Ok(regs) = ptrace::getregs(pid) {
                        if verbose && regs.orig_rax == 61 {
                            // wait4 — log the waited-for PID for hang diagnostics.
                            log::debug!(
                                "ptrace: PtraceSyscall({pid}) ENTRY syscall=61 \
                                 (wait4 for pid={})",
                                regs.rdi as i64
                            );
                        } else {
                            log::debug!(
                                "ptrace: PtraceSyscall({pid}) ENTRY syscall={}",
                                regs.orig_rax
                            );
                        }
                        if regs.orig_rax == OPENAT_NR {
                            emit_path(&path_tx, pid_u32, regs.rsi);
                        }
                    } else {
                        log::debug!("ptrace: PtraceSyscall({pid}) ENTRY (getregs failed)");
                    }
                }

                resume(pid, None, mode);
            }

            // ----------------------------------------------------------
            // ptrace event: fork / clone / vfork / exec / seccomp.
            // ----------------------------------------------------------
            WaitStatus::PtraceEvent(pid, _sig, event) => {
                let pid_u32 = pid.as_raw() as u32;

                match event {
                    // FORK=1, VFORK=2, CLONE=3
                    1 | 2 | 3 => {
                        let kind = match event { 1 => "FORK", 2 => "VFORK", _ => "CLONE" };
                        if let Ok(new_raw) = ptrace::getevent(pid) {
                            let new_pid = new_raw as u32;
                            child_to_parent.insert(new_pid, pid_u32);
                            let _ = new_pid_tx.send(new_pid);

                            if alive_pids.contains(&new_pid) {
                                // Race: the child's initial stop was processed by
                                // waitpid *before* this PTRACE_EVENT_FORK/CLONE/VFORK.
                                // The child is already running (or may have already
                                // exited).  Do NOT insert into pending_children — that
                                // would cause the next signal-delivery stop for this
                                // child to be silently swallowed as a second "initial
                                // stop", losing the signal (e.g. SIGTERM from make).
                                log::debug!(
                                    "ptrace: PtraceEvent({pid}, {kind}) → child {new_pid} \
                                     (initial stop already processed — skip pending_children)"
                                );
                            } else {
                                // Normal case: FORK event arrives before the child's
                                // initial stop.
                                log::debug!(
                                    "ptrace: PtraceEvent({pid}, {kind}) → child {new_pid}"
                                );
                                pending_children.insert(new_pid);
                                alive_pids.insert(new_pid);
                            }
                        } else {
                            log::debug!(
                                "ptrace: PtraceEvent({pid}, {kind}) → getevent failed"
                            );
                        }
                    }

                    // EXEC=4
                    4 => {
                        log::debug!("ptrace: PtraceEvent({pid}, EXEC)");
                        // The process has replaced its image.  Any in-progress syscall
                        // tracking for this PID is now stale — execve itself was the last
                        // syscall and its exit stop will never arrive.  Clear the state so
                        // the first syscall in the new image is treated as an entry stop.
                        in_syscall.remove(&pid_u32);
                    }

                    // SECCOMP=7 — openat via seccomp filter (Seccomp mode only)
                    e if e == PTRACE_EVENT_SECCOMP => {
                        log::debug!("ptrace: PtraceEvent({pid}, SECCOMP) → openat");
                        if let Ok(regs) = ptrace::getregs(pid) {
                            // Sanity-check: the filter only traces openat, but
                            // verify so a future filter extension doesn't silently
                            // misinterpret other syscalls.
                            if regs.orig_rax == OPENAT_NR {
                                emit_path(&path_tx, pid_u32, regs.rsi);
                            } else {
                                log::debug!(
                                    "ptrace: SECCOMP stop for unexpected syscall {} on PID {pid}",
                                    regs.orig_rax
                                );
                            }
                        }
                    }

                    _ => {
                        log::debug!("ptrace: PtraceEvent({pid}, event={event})");
                    }
                }

                resume(pid, None, mode);
            }

            // ----------------------------------------------------------
            // Signal-delivery stop or a new child's first stop.
            // ----------------------------------------------------------
            WaitStatus::Stopped(pid, sig) => {
                let pid_u32 = pid.as_raw() as u32;

                if pending_children.remove(&pid_u32) || !alive_pids.contains(&pid_u32) {
                    // Initial stop for a newly-forked/cloned child.
                    //
                    // Two cases land here:
                    //   (a) pid is in pending_children — normal case, FORK event
                    //       was processed before the child's first stop.
                    //   (b) pid is unknown (not in alive_pids) — race: the child's
                    //       first stop arrived in waitpid *before* the parent's
                    //       PTRACE_EVENT_FORK/CLONE/VFORK was returned.  Per the
                    //       Linux ptrace manual this ordering is not guaranteed.
                    //       In both cases the correct action is to resume without
                    //       injecting any signal; the child inherits ptrace options
                    //       from its parent so no setoptions call is needed.
                    log::debug!("ptrace: Stopped({pid}, {sig}) — initial child stop");
                    alive_pids.insert(pid_u32);
                    resume(pid, None, mode);
                } else if sig == Signal::SIGTRAP {
                    // exec-stop or similar — do not re-inject SIGTRAP.
                    log::debug!("ptrace: Stopped({pid}, SIGTRAP) — exec-stop");
                    resume(pid, None, mode);
                } else if matches!(
                    sig,
                    Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                ) {
                    // Stopping signals must NOT be injected back.
                    //
                    // Injecting SIGSTOP (or any group-stop signal) via
                    // ptrace::cont causes the tracee to enter a group-stop.
                    // Under traditional ptrace (PTRACE_TRACEME) that group-stop
                    // is reported to the tracer as another Stopped(pid, SIGSTOP)
                    // event — creating an infinite inject→stop→report loop that
                    // permanently prevents the process from running and deadlocks
                    // anything waiting for it.
                    //
                    // In a build context there is no terminal job control, so
                    // suppressing these signals is safe and the correct choice.
                    log::debug!(
                        "ptrace: Stopped({pid}, {sig}) — suppressing stopping signal \
                         (injecting would cause a group-stop loop)"
                    );
                    resume(pid, None, mode);
                } else {
                    // Genuine signal — inject it so the process sees it.
                    log::debug!("ptrace: Stopped({pid}, {sig}) — injecting signal");
                    resume(pid, Some(sig), mode);
                }
            }

            WaitStatus::Continued(_) | WaitStatus::StillAlive => {}
        }
    }

    log::info!(
        "ptrace: build finished (exit code: {}).",
        exit_code.map(|c| c.to_string()).unwrap_or_else(|| "signal".to_string())
    );

    let _ = exit_tx.send(exit_code);
}

// ---------------------------------------------------------------------------
// Syscall decoder for watchdog diagnostics
// ---------------------------------------------------------------------------

/// Parse a `/proc/{pid}/syscall` line and return a human-readable summary.
///
/// Kernel format: `nr arg0 arg1 arg2 arg3 arg4 arg5 sp pc`
/// where `nr` is written as a plain **decimal** integer and `argN` as `0x`-prefixed hex.
/// Returns `"running"` if the process is not currently blocked in a syscall.
fn decode_syscall_line(raw: &str) -> String {
    if raw == "running" || raw.is_empty() {
        return "running".into();
    }

    let parts: Vec<&str> = raw.split_ascii_whitespace().collect();
    if parts.is_empty() {
        return raw.to_string();
    }

    // The kernel writes the syscall number as a plain decimal integer (no 0x prefix).
    // Parse as decimal first; fall back to hex for any non-standard kernels.
    let nr = parts[0]
        .parse::<u64>()
        .or_else(|_| u64::from_str_radix(parts[0].trim_start_matches("0x"), 16))
        .unwrap_or(u64::MAX);

    // Retrieve the n-th syscall argument (0-based).  Arguments occupy parts[1..],
    // since parts[0] is the syscall number.  All argument values are hex in the file.
    let arg = |n: usize| -> u64 {
        parts
            .get(n + 1)
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0)
    };

    match nr {
        // wait4(pid, wstatus, options, rusage)
        61 => {
            let wait_pid = arg(0) as i64;
            format!("wait4(pid={wait_pid})")
        }
        // waitid(idtype, id, infop, options, rusage)
        247 => {
            let id = arg(1) as i64;
            format!("waitid(id={id})")
        }
        // poll(fds, nfds, timeout_ms)
        7 => {
            let nfds    = arg(1);
            let timeout = arg(2) as i64; // -1 = infinite
            if timeout < 0 {
                format!("poll(nfds={nfds}, timeout=∞)")
            } else {
                format!("poll(nfds={nfds}, timeout={timeout}ms)")
            }
        }
        // ppoll(fds, nfds, tmo_p, sigmask, sigsetsize)
        271 => {
            let nfds    = arg(1);
            let tmo_ptr = arg(2); // NULL pointer = infinite timeout
            if tmo_ptr == 0 {
                format!("ppoll(nfds={nfds}, timeout=∞)")
            } else {
                format!("ppoll(nfds={nfds})")
            }
        }
        // select(nfds, readfds, writefds, exceptfds, timeout)
        23 => format!("select(nfds={})", arg(0)),
        // pselect6(nfds, readfds, writefds, exceptfds, timeout_p, sigmask)
        270 => {
            let nfds    = arg(0);
            let tmo_ptr = arg(4); // NULL pointer = infinite timeout
            if tmo_ptr == 0 {
                format!("pselect6(nfds={nfds}, timeout=∞)")
            } else {
                format!("pselect6(nfds={nfds})")
            }
        }
        // epoll_wait(epfd, events, maxevents, timeout_ms)
        // epoll_pwait(epfd, events, maxevents, timeout_ms, sigmask, sigsetsize)
        // epoll_pwait2(epfd, events, maxevents, timeout_ts, sigmask)
        232 | 281 | 441 => {
            let timeout = arg(3) as i64; // arg3 = timeout_ms (-1 = infinite)
            if timeout < 0 {
                "epoll_wait(timeout=∞)".into()
            } else {
                format!("epoll_wait(timeout={timeout}ms)")
            }
        }
        // futex(uaddr, futex_op, val, ...)
        202 => format!("futex(op=0x{:x})", arg(1)),
        // read(fd, buf, count)
        0 => format!("read(fd={})", arg(0)),
        // nanosleep / clock_nanosleep
        35 | 230 => "nanosleep".into(),
        _ => format!("syscall#{nr}"),
    }
}

// ---------------------------------------------------------------------------
// PPid lookup
// ---------------------------------------------------------------------------

/// Read the parent PID (`PPid:` field) from `/proc/{pid}/status`.
///
/// Called from the `Exited`/`Signaled` handlers as a fallback for the race
/// where the child exits before the parent's `PTRACE_EVENT_FORK/CLONE/VFORK`
/// is processed, leaving `child_to_parent` without an entry.  At the time of
/// the call the child has just transitioned from ptrace-zombie to regular
/// zombie, so `/proc/{pid}/status` is still readable.
fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Path reading
// ---------------------------------------------------------------------------

/// Read the `openat` pathname argument from the stopped tracee's memory and
/// send it on `path_tx`.  `ptr` is the value of the `rsi` register.
fn emit_path(path_tx: &UnboundedSender<(String, u32)>, pid: u32, ptr: u64) {
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

    let mem_path = format!("/proc/{pid}/mem");
    let mut file = std::fs::File::open(&mem_path).ok()?;
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

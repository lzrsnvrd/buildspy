//! ptrace tracing backend.
//!
//! Intercepts `openat` syscalls using `PTRACE_SYSCALL` and automatically
//! follows the entire process tree via `PTRACE_O_TRACEFORK`,
//! `PTRACE_O_TRACECLONE`, and `PTRACE_O_TRACEVFORK`.
//!
//! This backend works on any Linux kernel that supports ptrace (effectively
//! all kernels back to 2.6) and requires only `CAP_SYS_PTRACE`, which is
//! available by default when running as root.
//!
//! Architecture note: currently only x86_64 is supported because `getregs`
//! and the syscall register layout are architecture-specific.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("the ptrace backend currently only supports x86_64");

use std::{
    collections::HashSet,
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

// sys_enter_openat on x86_64
const OPENAT_NR: u64 = 257;

// ---------------------------------------------------------------------------
// Public entry-point
// ---------------------------------------------------------------------------

/// Spawn the build command under ptrace and return a `TracingSession`.
///
/// # Why the child is spawned inside the ptrace thread
///
/// Linux ptrace ties the "tracer" identity to the specific OS thread (task)
/// that forked the tracee: only that thread can call `waitpid` and issue
/// further `ptrace` requests on the child.  If we spawned the child in a
/// tokio worker thread and then ran the ptrace loop in a different `std::thread`,
/// every `ptrace::setoptions` / `ptrace::syscall` call would fail with ESRCH.
///
/// The fix: the dedicated ptrace thread is responsible for both `fork`+`exec`
/// (via `Command::spawn`) and for the entire ptrace event loop, keeping all
/// ptrace operations on a single OS thread.
/// No-op SIGUSR1 handler — just interrupts blocking syscalls (waitpid returns EINTR).
extern "C" fn sigusr1_noop(_: c_int) {}

pub fn start(cmd: &[String], cwd: &Path, verbose: bool) -> Result<TracingSession> {
    let (path_tx, path_rx) = tokio::sync::mpsc::unbounded_channel::<(String, u32)>();
    let (new_pid_tx, new_pid_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<Option<i32>>();

    // shutdown flag + TID of ptrace thread (filled in by the thread itself).
    // The shutdown fn sets the flag and sends SIGUSR1 to the ptrace thread,
    // which interrupts its blocking waitpid() and lets it detect the flag.
    let shutdown = Arc::new(AtomicBool::new(false));
    let ptrace_tid = Arc::new(AtomicI32::new(0));

    let shutdown_for_thread = Arc::clone(&shutdown);
    let tid_for_thread = Arc::clone(&ptrace_tid);

    // Clone owned values so they can be moved into the thread.
    let cmd: Vec<String> = cmd.to_vec();
    let cwd: PathBuf = cwd.to_path_buf();

    // The ptrace thread forks the child AND runs the event loop — all on the
    // same OS thread, which is required by the Linux ptrace API.
    std::thread::Builder::new()
        .name("ptrace-loop".into())
        .spawn(move || {
            // Install a no-op SIGUSR1 handler so that sending SIGUSR1 to this
            // thread causes waitpid() to return EINTR rather than killing us.
            // SaFlags::empty() means no SA_RESTART, so blocking syscalls are
            // interrupted.
            unsafe {
                let sa = SigAction::new(
                    SigHandler::Handler(sigusr1_noop),
                    SaFlags::empty(),
                    SigSet::empty(),
                );
                let _ = sigaction(Signal::SIGUSR1, &sa);
            }

            // Store our TID so the shutdown closure can wake us via tgkill.
            tid_for_thread.store(gettid().as_raw(), Ordering::Release);

            // Build and spawn the child with PTRACE_TRACEME set in pre_exec.
            // Safety: ptrace(PTRACE_TRACEME) is async-signal-safe; the child
            // immediately exec()s, so tokio state in the child is irrelevant.
            let mut command = std::process::Command::new(&cmd[0]);
            command.args(&cmd[1..]).current_dir(&cwd);
            unsafe {
                command.pre_exec(|| {
                    ptrace::traceme()
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                });
            }

            let child = match command.spawn() {
                Ok(c) => c,
                Err(e) => {
                    log::error!("ptrace: failed to spawn '{}': {e}", cmd[0]);
                    let _ = exit_tx.send(None);
                    return;
                }
            };

            let child_pid = child.id();
            log::info!("Build started (PID {child_pid}) via ptrace backend.");

            // Send root PID so main can collect its comm/cwd immediately.
            let _ = new_pid_tx.send(child_pid);

            ptrace_loop(child_pid, path_tx, new_pid_tx, exit_tx, verbose, shutdown_for_thread);

            // child dropped here; waitpid in ptrace_loop already reaped the
            // process, so Child::drop's implicit wait is a harmless ECHILD.
            drop(child);
        })
        .context("failed to spawn ptrace thread")?;

    let our_pid = std::process::id() as i32;
    let shutdown_fn: Box<dyn FnOnce() + Send + 'static> = Box::new(move || {
        shutdown.store(true, Ordering::Release);
        // Wake the ptrace thread from its blocking waitpid() via tgkill(SIGUSR1).
        let tid = ptrace_tid.load(Ordering::Acquire);
        if tid != 0 {
            unsafe { libc::tgkill(our_pid, tid, libc::SIGUSR1) };
        }
    });

    Ok(TracingSession { path_rx, new_pid_rx, exit_rx, shutdown: Some(shutdown_fn) })
}

// ---------------------------------------------------------------------------
// ptrace event loop (runs in a dedicated OS thread)
// ---------------------------------------------------------------------------

fn resume(pid: Pid, sig: Option<Signal>, verbose: bool) {
    if let Err(e) = ptrace::syscall(pid, sig) {
        // ESRCH means the process already exited between the waitpid and here – harmless.
        // Any other error means we failed to resume a stopped tracee, which will cause a deadlock.
        if e != nix::errno::Errno::ESRCH {
            log::warn!("ptrace: failed to resume PID {}: {} (signal={:?}) — tracee may be stuck", pid, e, sig);
        } else if verbose {
            log::debug!("ptrace: ESRCH resuming PID {} (already exited, harmless)", pid);
        }
    }
}

fn ptrace_loop(
    root_pid: u32,
    path_tx: UnboundedSender<(String, u32)>,
    new_pid_tx: UnboundedSender<u32>,
    exit_tx: tokio::sync::oneshot::Sender<Option<i32>>,
    verbose: bool,
    shutdown: Arc<AtomicBool>,
) {
    let root = Pid::from_raw(root_pid as i32);

    // ------------------------------------------------------------------
    // Wait for the initial exec-stop (SIGTRAP) that ptrace delivers after
    // the child calls execve().  We set our options before resuming.
    // ------------------------------------------------------------------
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

    let options = Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACEEXEC;

    if let Err(e) = ptrace::setoptions(root, options) {
        log::error!("ptrace: setoptions failed: {e}");
        let _ = exit_tx.send(None);
        return;
    }

    // Start syscall tracing on the root process.
    if let Err(e) = ptrace::syscall(root, None) {
        log::error!("ptrace: initial PTRACE_SYSCALL failed: {e}");
        let _ = exit_tx.send(None);
        return;
    }

    log::debug!("ptrace: event loop started for root PID {root_pid}");

    // ------------------------------------------------------------------
    // State for the event loop.
    // ------------------------------------------------------------------

    // PIDs currently inside a syscall (used to distinguish entry from exit).
    let mut in_syscall: HashSet<u32> = HashSet::new();

    // PIDs we know about from fork/clone events but whose initial waitpid
    // stop we haven't processed yet.
    let mut pending_children: HashSet<u32> = HashSet::new();

    // All PIDs we've ever seen – used to report which ones are still alive
    // when the loop stalls (no events for several seconds).
    let mut alive_pids: HashSet<u32> = HashSet::new();
    alive_pids.insert(root_pid);

    // Count of consecutive StillAlive polls with no event (each ~10 ms).
    let mut still_alive_count: u32 = 0;

    let mut exit_code: Option<i32> = None;

    // ------------------------------------------------------------------
    // Main event loop
    // ------------------------------------------------------------------
    loop {
        let status = match waitpid(None, Some(WaitPidFlag::__WALL)) {
            Ok(s) => s,
            // No more traced children – the build is done.
            Err(nix::errno::Errno::ECHILD) => break,
            // SIGUSR1 from the shutdown fn – check the flag.
            Err(nix::errno::Errno::EINTR) => {
                if shutdown.load(Ordering::Acquire) {
                    log::info!("ptrace: shutdown requested – sending SIGKILL to build process group.");
                    let pgid = Pid::from_raw(root_pid as i32);
                    let _ = killpg(pgid, Signal::SIGKILL);
                    // Drain remaining tracees so no zombies are left.
                    loop {
                        match waitpid(None, Some(WaitPidFlag::__WALL)) {
                            Err(_) => break,
                            Ok(WaitStatus::Stopped(pid, _)) | Ok(WaitStatus::PtraceSyscall(pid)) => {
                                let _ = ptrace::detach(pid, Some(Signal::SIGKILL));
                            }
                            Ok(_) => {}
                        }
                    }
                    break;
                }
                // Spurious EINTR – re-log stall info and keep going.
                still_alive_count += 1;
                if still_alive_count % 5 == 0 {
                    let mut alive: Vec<u32> = alive_pids.iter().copied().collect();
                    alive.sort_unstable();
                    log::warn!(
                        "ptrace: waitpid interrupted ({} times) – {} process(es) still alive: {:?}",
                        still_alive_count,
                        alive.len(),
                        alive,
                    );
                    for pid in &alive {
                        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                            .unwrap_or_else(|_| "<exited>".into());
                        let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan"))
                            .unwrap_or_default();
                        log::warn!("  PID {pid}: comm={}, wchan={}", comm.trim(), wchan.trim());
                    }
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
                if pid == root {
                    exit_code = Some(code);
                    // Root build process exited → we are done.  Any remaining
                    // traced descendants (daemon helpers, etc.) will be
                    // automatically detached by the kernel when this thread
                    // exits (they receive SIGCONT and resume normally).
                    break;
                }
            }

            // ----------------------------------------------------------
            // Process killed by a signal.
            // ----------------------------------------------------------
            WaitStatus::Signaled(pid, sig, _core) => {
                log::debug!("ptrace: Signaled({pid}, {sig})");
                let pid_u32 = pid.as_raw() as u32;
                pending_children.remove(&pid_u32);
                alive_pids.remove(&pid_u32);
                if pid == root {
                    exit_code = None;
                    break;
                }
            }

            // ----------------------------------------------------------
            // Syscall entry or exit (PTRACE_O_TRACESYSGOOD sets bit 7).
            // ----------------------------------------------------------
            WaitStatus::PtraceSyscall(pid) => {
                let pid_u32 = pid.as_raw() as u32;

                if in_syscall.remove(&pid_u32) {
                    // Syscall EXIT – nothing to do, just resume.
                    log::debug!("ptrace: PtraceSyscall({pid}) EXIT");
                } else {
                    // Syscall ENTRY – check if it's openat.
                    in_syscall.insert(pid_u32);
                    if let Ok(regs) = ptrace::getregs(pid) {
                        // wait4/waitpid: log which PID is being waited for (rdi arg).
                        // Useful for diagnosing hangs where the build waits for a
                        // long-running test server.
                        if regs.orig_rax == 61 {
                            let wait_pid = regs.rdi as i64;
                            log::debug!(
                                "ptrace: PtraceSyscall({pid}) ENTRY syscall=61 (wait4 for pid={wait_pid})"
                            );
                        } else {
                            log::debug!("ptrace: PtraceSyscall({pid}) ENTRY syscall={}", regs.orig_rax);
                        }
                        if regs.orig_rax == OPENAT_NR {
                            // rsi = second argument = pointer to the pathname string.
                            if let Some(path) = read_path_from_mem(pid_u32, regs.rsi) {
                                if !path.is_empty() {
                                    let _ = path_tx.send((path, pid_u32));
                                }
                            }
                        }
                    } else {
                        log::debug!("ptrace: PtraceSyscall({pid}) ENTRY (getregs failed)");
                    }
                }

                resume(pid, None, verbose);
            }

            // ----------------------------------------------------------
            // ptrace event: fork / clone / vfork / exec.
            // ----------------------------------------------------------
            WaitStatus::PtraceEvent(pid, _sig, event) => {
                match event {
                    // PTRACE_EVENT_FORK=1, PTRACE_EVENT_VFORK=2, PTRACE_EVENT_CLONE=3
                    1 | 2 | 3 => {
                        let kind = match event { 1 => "FORK", 2 => "VFORK", _ => "CLONE" };
                        if let Ok(new_raw) = ptrace::getevent(pid) {
                            let new_pid = new_raw as u32;
                            log::debug!("ptrace: PtraceEvent({pid}, {kind}) → new child {new_pid}");
                            pending_children.insert(new_pid);
                            alive_pids.insert(new_pid);
                            let _ = new_pid_tx.send(new_pid);
                        } else {
                            log::debug!("ptrace: PtraceEvent({pid}, {kind}) → getevent failed");
                        }
                    }
                    // PTRACE_EVENT_EXEC=4 – child replaced its image, resume.
                    4 => {
                        log::debug!("ptrace: PtraceEvent({pid}, EXEC)");
                    }
                    _ => {
                        log::debug!("ptrace: PtraceEvent({pid}, event={event})");
                    }
                }
                resume(pid, None, verbose);
            }

            // ----------------------------------------------------------
            // Regular signal-delivery stop or a new child's first stop.
            // ----------------------------------------------------------
            WaitStatus::Stopped(pid, sig) => {
                let pid_u32 = pid.as_raw() as u32;

                if pending_children.remove(&pid_u32) {
                    // New child's initial ptrace-stop – begin syscall tracing.
                    log::debug!("ptrace: Stopped({pid}, {sig}) — initial child stop, resuming");
                    resume(pid, None, verbose);
                } else if sig == Signal::SIGTRAP {
                    // exec-stop or similar SIGTRAP – don't deliver as a signal.
                    log::debug!("ptrace: Stopped({pid}, SIGTRAP) — exec-stop, resuming");
                    resume(pid, None, verbose);
                } else {
                    // Genuine signal – inject it so the process sees it.
                    log::debug!("ptrace: Stopped({pid}, {sig}) — injecting signal");
                    resume(pid, Some(sig), verbose);
                }
            }

            WaitStatus::Continued(pid) => {
                log::debug!("ptrace: Continued({pid})");
            }
            WaitStatus::StillAlive => {}
        }
    }

    log::info!(
        "ptrace: build finished (exit code: {}).",
        exit_code.map(|c| c.to_string()).unwrap_or_else(|| "signal".to_string())
    );

    let _ = exit_tx.send(exit_code);
}

// ---------------------------------------------------------------------------
// Read a null-terminated string from a ptrace-stopped process's memory.
// We use /proc/<pid>/mem (process is stopped, so memory is stable).
// ---------------------------------------------------------------------------

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

    // Find the null terminator.
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 {
        return None;
    }

    String::from_utf8(buf[..end].to_vec()).ok()
}

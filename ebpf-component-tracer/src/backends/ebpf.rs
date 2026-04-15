//! eBPF tracing backend.
//!
//! Attaches three tracepoints (sched_process_fork, sched_process_exit,
//! sys_enter_openat) and reads events from a ring buffer.
//!
//! Public surface: `start()` which returns a `TracingSession`.

use std::{
    collections::HashSet,
    os::unix::io::AsRawFd,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use ebpf_component_tracer_common::{FileEvent, EVENT_KIND_FORK};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use super::TracingSession;

// ---------------------------------------------------------------------------
// Embedded eBPF bytecode (compiled by build.rs via aya-build).
// ---------------------------------------------------------------------------

static EBPF_BYTECODE: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-tracer-bpf"));

// ---------------------------------------------------------------------------
// Public entry-point
// ---------------------------------------------------------------------------

/// Initialise the eBPF subsystem, spawn the build command, and return a
/// `TracingSession` that emits events until the build exits.
pub fn start(cmd: &[String], cwd: &Path, verbose: bool) -> Result<TracingSession> {
    let mut bpf = load(verbose)?;

    // Extract the ring buffer BEFORE wrapping bpf in Arc so we avoid
    // keeping a mutable borrow alive.
    let ring_buf = take_ring_buf(&mut bpf)?;

    // Insert our own TGID before fork so sched_process_fork fires correctly.
    let our_tgid = std::process::id();
    pid_filter_insert(&mut bpf, our_tgid)?;

    // Spawn the child build process.
    let child = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(cwd)
        .spawn()
        .with_context(|| format!("failed to spawn '{}'", cmd[0]))?;

    let child_pid = child.id().ok_or_else(|| anyhow!("could not retrieve child PID"))?;
    log::info!("Build started (PID {child_pid}) via eBPF backend.");

    // Insert child PID as a safety net for the window before fork tracepoint.
    pid_filter_insert(&mut bpf, child_pid)?;
    pid_filter_remove(&mut bpf, our_tgid);

    // Move bpf into an Arc for the exit/cleanup task.
    let bpf = Arc::new(Mutex::new(bpf));

    // PID metadata channel: the drain thread sends child PIDs discovered via
    // Fork events (and lazily on first Open from an unknown PID).  main uses
    // these to read /proc/<pid>/comm and /proc/<pid>/cwd.
    let (new_pid_tx, new_pid_rx) = unbounded_channel::<u32>();

    // Ring-buffer event task: drains FILE_EVENTS, handles Fork/Open events.
    let (path_tx, path_rx) = unbounded_channel::<(String, u32)>();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let drain_done_rx = spawn_event_task(ring_buf, path_tx, new_pid_tx, Arc::clone(&stop_flag));

    // Exit task: wait for the child, flush the ring buffer, then signal done.
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<Option<i32>>();
    tokio::spawn(async move {
        let mut child = child;
        let code = match child.wait().await {
            Ok(status) => status.code(),
            Err(e) => {
                log::error!("eBPF: error waiting for child: {e}");
                None
            }
        };
        // Allow the ring buffer 300 ms to flush any remaining events.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Signal the drain thread to perform its final drain and exit.
        stop_flag.store(true, Ordering::Release);

        // Wait for the drain thread to fully finish — this guarantees that every
        // event has been sent to path_tx before we signal main to read path_rx.
        // Without this wait, collect_components (which uses try_recv) could run
        // before the drain thread's final drain, losing events.
        let _ = drain_done_rx.await;

        // Read and log diagnostic counters before detaching tracepoints.
        if let Ok(b) = bpf.lock() {
            let dropped = read_dropped_count(&b);
            if dropped > 0 {
                log::warn!(
                    "eBPF ring buffer dropped {dropped} event(s) — some paths may be missing. \
                     Consider increasing the ring buffer size further."
                );
            } else {
                log::debug!("eBPF ring buffer: no events dropped.");
            }

            let failed = read_failed_pid_inserts(&b);
            if failed > 0 {
                log::warn!(
                    "eBPF PID_FILTER: failed to insert {failed} PID(s) during fork — \
                     those processes were not tracked; early openat calls may have been missed."
                );
            }
        }

        let _ = exit_tx.send(code);
        // Dropping bpf here detaches all tracepoints.
        drop(bpf);
    });

    Ok(TracingSession { path_rx, new_pid_rx, exit_rx, shutdown: None })
}

// ---------------------------------------------------------------------------
// eBPF helpers
// ---------------------------------------------------------------------------

fn load(verbose: bool) -> Result<Ebpf> {
    let mut bpf = Ebpf::load(EBPF_BYTECODE)
        .context("failed to load eBPF bytecode – are you running as root?")?;

    if verbose {
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            log::warn!("eBPF logger unavailable: {e}");
        }
    }

    attach_tracepoint(&mut bpf, "sched_process_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut bpf, "sched_process_exit", "sched", "sched_process_exit")?;
    attach_tracepoint(&mut bpf, "sys_enter_openat", "syscalls", "sys_enter_openat")?;

    // sys_enter_open: legacy open() syscall, x86-64 only (SYS_open = 2).
    // Absent on arm64/riscv64 which have only openat — skip gracefully.
    if let Err(e) = attach_tracepoint(&mut bpf, "sys_enter_open", "syscalls", "sys_enter_open") {
        log::debug!("sys_enter_open tracepoint unavailable (non-x86 or kernel config): {e}");
    }

    // sys_enter_openat2: requires Linux >= 5.6 (SYS_openat2 = 437).
    if let Err(e) = attach_tracepoint(&mut bpf, "sys_enter_openat2", "syscalls", "sys_enter_openat2") {
        log::debug!("sys_enter_openat2 tracepoint unavailable (kernel < 5.6?): {e}");
    }

    log::info!("eBPF tracepoints attached.");

    Ok(bpf)
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    tracepoint_name: &str,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .with_context(|| format!("program '{prog_name}' not found in eBPF object"))?
        .try_into()
        .with_context(|| format!("'{prog_name}' is not a TracePoint program"))?;

    program.load().with_context(|| format!("failed to load '{prog_name}'"))?;
    program.attach(category, tracepoint_name).with_context(|| {
        format!("failed to attach '{prog_name}' to {category}/{tracepoint_name}")
    })?;

    log::debug!("Attached {category}/{tracepoint_name}.");
    Ok(())
}

fn take_ring_buf(bpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    let map = bpf
        .take_map("FILE_EVENTS")
        .ok_or_else(|| anyhow!("FILE_EVENTS map not found"))?;
    RingBuf::try_from(map).context("failed to convert map to RingBuf")
}

pub fn pid_filter_insert(bpf: &mut Ebpf, pid: u32) -> Result<()> {
    let pid_map = bpf.map_mut("PID_FILTER").context("PID_FILTER map not found")?;
    let mut pf =
        AyaHashMap::<_, u32, u8>::try_from(pid_map).context("failed to wrap PID_FILTER")?;
    pf.insert(pid, 1u8, 0).context("failed to insert PID into PID_FILTER")
}

pub fn pid_filter_remove(bpf: &mut Ebpf, pid: u32) {
    if let Some(pid_map) = bpf.map_mut("PID_FILTER") {
        if let Ok(mut pf) = AyaHashMap::<_, u32, u8>::try_from(pid_map) {
            let _ = pf.remove(&pid);
        }
    }
}

// ---------------------------------------------------------------------------
// Ring-buffer event task
// ---------------------------------------------------------------------------

/// Drains the ring buffer on a dedicated OS thread using `libc::poll`.
///
/// Handles two event kinds from `FILE_EVENTS`:
/// * `EVENT_KIND_FORK` — emitted by `sched_process_fork` after a successful
///   `PID_FILTER` insert.  The child is guaranteed alive at this point, so we
///   immediately notify `new_pid_tx`; main reads `/proc/<pid>/comm` and
///   `/proc/<pid>/cwd` while the child is still running.
/// * `EVENT_KIND_OPEN` (default) — a file-open event.  If the opener PID has
///   not been seen before (multi-core race: child ran before the fork tracepoint
///   fired), we lazily send it to `new_pid_tx` as well; the child is guaranteed
///   alive because it just called openat.
///
/// Returns a oneshot `Receiver` that resolves when the thread has fully
/// finished its final drain.  The exit task must `.await` this before sending
/// `exit_tx`.
fn spawn_event_task(
    ring_buf: RingBuf<MapData>,
    path_tx: UnboundedSender<(String, u32)>,
    new_pid_tx: UnboundedSender<u32>,
    stop: Arc<AtomicBool>,
) -> tokio::sync::oneshot::Receiver<()> {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    std::thread::spawn(move || {
        let mut ring_buf = ring_buf;
        let mut known_pids: HashSet<u32> = HashSet::new();
        let fd = ring_buf.as_raw_fd();

        loop {
            // Wait up to 10 ms for new data; short timeout lets us check the
            // stop flag frequently without busy-spinning.
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut pfd, 1, 10) };

            drain_ring_buf(&mut ring_buf, &path_tx, &new_pid_tx, &mut known_pids);

            if stop.load(Ordering::Acquire) {
                // Final drain after stop signal — catches events that arrived
                // in the 300 ms window after the build exited.
                drain_ring_buf(&mut ring_buf, &path_tx, &new_pid_tx, &mut known_pids);
                break;
            }
        }

        // Both senders are dropped here, closing their channels.
        // done_tx signals the exit task that all events have been sent.
        let _ = done_tx.send(());
    });

    done_rx
}

fn read_dropped_count(bpf: &Ebpf) -> u64 {
    let Some(map) = bpf.map("DROPPED_EVENTS") else { return 0 };
    let Ok(arr) = PerCpuArray::<_, u32>::try_from(map) else { return 0 };
    let Ok(values) = arr.get(&0, 0) else { return 0 };
    values.iter().map(|v| *v as u64).sum()
}

fn read_failed_pid_inserts(bpf: &Ebpf) -> u64 {
    let Some(map) = bpf.map("FAILED_PID_INSERTS") else { return 0 };
    let Ok(arr) = PerCpuArray::<_, u32>::try_from(map) else { return 0 };
    let Ok(values) = arr.get(&0, 0) else { return 0 };
    values.iter().map(|v| *v as u64).sum()
}

fn drain_ring_buf(
    rb: &mut RingBuf<MapData>,
    path_tx: &UnboundedSender<(String, u32)>,
    new_pid_tx: &UnboundedSender<u32>,
    known_pids: &mut HashSet<u32>,
) {
    let mut n_fork = 0u64;
    let mut n_open = 0u64;

    while let Some(item) = rb.next() {
        if item.len() < std::mem::size_of::<FileEvent>() {
            log::warn!("eBPF drain: short item ({} bytes, expected {}), skipping",
                item.len(), std::mem::size_of::<FileEvent>());
            continue;
        }
        // Safety: eBPF always writes a complete FileEvent.
        let event: &FileEvent = unsafe { &*(item.as_ptr() as *const FileEvent) };

        if event.kind == EVENT_KIND_FORK {
            n_fork += 1;
            // Child is alive right now (fork tracepoint fires before child runs).
            // Notify main so it can read /proc/<pid>/comm and /proc/<pid>/cwd.
            if known_pids.insert(event.pid) {
                let _ = new_pid_tx.send(event.pid);
            }
            continue;
        }

        n_open += 1;
        // EVENT_KIND_OPEN (or any unknown kind treated as open).
        // If we haven't seen this PID before, the fork event either hasn't
        // arrived yet (multi-core race) or was never emitted (PID_FILTER
        // insert failed).  The process is alive right now — it just called
        // openat — so notify main for lazy metadata resolution.
        if known_pids.insert(event.pid) {
            let _ = new_pid_tx.send(event.pid);
        }

        let filename_len =
            (event.filename_len as usize).min(ebpf_component_tracer_common::MAX_FILENAME_LEN);
        let raw = match std::str::from_utf8(&event.filename[..filename_len]) {
            Ok(s) => s.trim_end_matches('\0').to_string(),
            Err(_) => String::from_utf8_lossy(&event.filename[..filename_len])
                .trim_end_matches('\0')
                .to_string(),
        };

        if !raw.is_empty() {
            let _ = path_tx.send((raw, event.pid));
        }
    }

    if n_fork + n_open > 0 {
        log::debug!("eBPF drain: {} fork + {} open events", n_fork, n_open);
    }
}

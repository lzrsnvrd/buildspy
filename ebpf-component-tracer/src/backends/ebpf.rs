//! eBPF tracing backend.
//!
//! Attaches three tracepoints (sched_process_fork, sched_process_exit,
//! sys_enter_openat) and reads events from a ring buffer.
//!
//! Public surface: `start()` which returns a `TracingSession`.

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use ebpf_component_tracer_common::FileEvent;
use tokio::{
    io::unix::AsyncFd,
    sync::mpsc::{unbounded_channel, UnboundedSender},
};

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

    // Move bpf into an Arc so the PID-fanout task and the exit/cleanup task
    // can both use it without duplicating the handle.
    let bpf = Arc::new(Mutex::new(bpf));

    // Ring-buffer event task.
    let (path_tx, path_rx) = unbounded_channel::<(String, u32)>();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    spawn_event_task(ring_buf, path_tx, stop_rx);

    // PID tracking: proc_watcher discovers new children; a fan-out task inserts
    // them into the eBPF PID filter AND forwards them to the external channel.
    let (int_pid_tx, mut int_pid_rx) = unbounded_channel::<u32>();
    let (new_pid_tx, new_pid_rx) = unbounded_channel::<u32>();
    tokio::spawn(super::proc_watcher::watch_children(child_pid, int_pid_tx));

    let bpf_for_pids = Arc::clone(&bpf);
    tokio::spawn(async move {
        while let Some(pid) = int_pid_rx.recv().await {
            if let Ok(mut b) = bpf_for_pids.lock() {
                if let Err(e) = pid_filter_insert(&mut b, pid) {
                    log::warn!("eBPF: failed to track PID {pid}: {e}");
                }
            }
            let _ = new_pid_tx.send(pid);
        }
    });

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
        let _ = stop_tx.send(());
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

fn spawn_event_task(
    ring_buf: RingBuf<MapData>,
    path_tx: UnboundedSender<(String, u32)>,
    stop_rx: tokio::sync::oneshot::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::new(ring_buf) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!("AsyncFd::new failed: {e}");
                return;
            }
        };
        let mut stop_rx = stop_rx;
        loop {
            tokio::select! {
                _ = &mut stop_rx => {
                    // Non-blocking final drain before shutdown.
                    drain_ring_buf(async_fd.get_mut(), &path_tx);
                    break;
                }
                result = async_fd.readable_mut() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(e) => { log::error!("poll error: {e}"); break; }
                    };
                    drain_ring_buf(guard.get_inner_mut(), &path_tx);
                    guard.clear_ready();
                }
            }
        }
    });
}

fn drain_ring_buf(rb: &mut RingBuf<MapData>, tx: &UnboundedSender<(String, u32)>) {
    while let Some(item) = rb.next() {
        let len = std::mem::size_of::<FileEvent>();
        if item.len() < len {
            continue;
        }
        // Safety: eBPF always writes a complete FileEvent.
        let event: &FileEvent = unsafe { &*(item.as_ptr() as *const FileEvent) };

        let filename_len =
            (event.filename_len as usize).min(ebpf_component_tracer_common::MAX_FILENAME_LEN);
        let raw = match std::str::from_utf8(&event.filename[..filename_len]) {
            Ok(s) => s.trim_end_matches('\0').to_string(),
            Err(_) => String::from_utf8_lossy(&event.filename[..filename_len])
                .trim_end_matches('\0')
                .to_string(),
        };

        if !raw.is_empty() {
            let _ = tx.send((raw, event.pid));
        }
    }
}

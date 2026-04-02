//! eBPF helpers: tracepoint attachment, ring-buffer extraction and event task.

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use ebpf_component_tracer_common::FileEvent;
use tokio::io::unix::AsyncFd;

/// Insert a PID into the eBPF `PID_FILTER` map so its file opens are tracked.
pub fn pid_filter_insert(bpf: &mut Ebpf, pid: u32) -> Result<()> {
    let pid_map = bpf.map_mut("PID_FILTER").context("PID_FILTER map not found")?;
    let mut pf =
        AyaHashMap::<_, u32, u8>::try_from(pid_map).context("failed to wrap PID_FILTER")?;
    pf.insert(pid, 1u8, 0)
        .context("failed to insert PID into PID_FILTER")
}

/// Remove a PID from the eBPF `PID_FILTER` map.  Best-effort: silently ignores
/// errors (the PID may already have exited and been evicted by the kernel).
pub fn pid_filter_remove(bpf: &mut Ebpf, pid: u32) {
    if let Some(pid_map) = bpf.map_mut("PID_FILTER") {
        if let Ok(mut pf) = AyaHashMap::<_, u32, u8>::try_from(pid_map) {
            let _ = pf.remove(&pid);
        }
    }
}

/// Attach a named tracepoint program from the loaded eBPF object.
pub fn attach_tracepoint(
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

    program
        .load()
        .with_context(|| format!("failed to load '{prog_name}'"))?;
    program
        .attach(category, tracepoint_name)
        .with_context(|| {
            format!("failed to attach '{prog_name}' to {category}/{tracepoint_name}")
        })?;

    log::debug!("Attached {category}/{tracepoint_name}.");
    Ok(())
}

/// Extract the FILE_EVENTS ring buffer from the eBPF object.
///
/// Uses `take_map` so that the ring buffer can be moved into a separate task
/// while `bpf` remains alive and continues owning other maps (e.g. PID_FILTER).
pub fn take_ring_buf(bpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    let map = bpf
        .take_map("FILE_EVENTS")
        .ok_or_else(|| anyhow!("FILE_EVENTS map not found"))?;
    RingBuf::try_from(map).context("failed to convert map to RingBuf")
}

/// Spawn the event-collection task.
///
/// Reads `FileEvent` items from the ring buffer and forwards
/// `(path, opener_pid)` pairs to `path_tx` until `stop_rx` fires.
/// On shutdown a final non-blocking drain is performed before the task exits.
pub fn spawn_event_task(
    ring_buf: RingBuf<MapData>,
    path_tx: tokio::sync::mpsc::UnboundedSender<(String, u32)>,
    stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
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
                // Shutdown signal from main task.
                _ = &mut stop_rx => {
                    // NON-BLOCKING final drain.
                    //
                    // DO NOT call async_fd.readable_mut().await here.
                    // If the ring buffer is already empty (all events were
                    // drained in the loop below), that future never resolves
                    // and the task hangs forever, preventing the report from
                    // being written.
                    //
                    // rb.next() is non-blocking: it returns None immediately
                    // when the buffer is empty, which is what we want.
                    drain_ring_buf(async_fd.get_mut(), &path_tx);
                    break;
                }

                // New data in the ring buffer.
                result = async_fd.readable_mut() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(e) => {
                            log::error!("poll error: {e}");
                            break;
                        }
                    };
                    drain_ring_buf(guard.get_inner_mut(), &path_tx);
                    guard.clear_ready();
                }
            }
        }
    })
}

/// Drain all available items from a `RingBuf` and forward `(path, opener_pid)`
/// tuples to `tx`.  Non-blocking: returns immediately when the buffer is empty.
fn drain_ring_buf(
    rb: &mut RingBuf<MapData>,
    tx: &tokio::sync::mpsc::UnboundedSender<(String, u32)>,
) {
    while let Some(item) = rb.next() {
        let len = std::mem::size_of::<FileEvent>();
        if item.len() < len {
            continue;
        }
        // Safety: We verified the slice is at least as large as FileEvent.
        // The eBPF program always writes a complete FileEvent.
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

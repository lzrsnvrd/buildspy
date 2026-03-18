//! eBPF kernel programs for the ebpf-component-tracer.
//!
//! Three tracepoints are attached:
//!  * `sched/sched_process_fork`  – propagates tracking to child processes.
//!  * `sched/sched_process_exit`  – removes exited PIDs from the filter.
//!  * `syscalls/sys_enter_openat` – captures file paths opened by tracked PIDs.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::debug;
use ebpf_component_tracer_common::{FileEvent, MAX_FILENAME_LEN};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Set of PIDs we care about.  The user-space inserts the root build-command
/// PID; the `sched_process_fork` program adds every descendant automatically.
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

/// Ring buffer used to stream `FileEvent` records to user-space.
/// 16 MiB should be plenty for even large builds.
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);

// ---------------------------------------------------------------------------
// sched_process_fork  –  propagate PID tracking to child processes
//
// Tracepoint format (from /sys/kernel/tracing/events/sched/sched_process_fork):
//   offset  0-7:   common header  (u16 type, u8 flags, u8 preempt, i32 pid)
//   offset  8-23:  parent_comm[16]
//   offset 24-27:  parent_pid (pid_t / i32)
//   offset 28-43:  child_comm[16]
//   offset 44-47:  child_pid (pid_t / i32)
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match unsafe { try_fork(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    // Use bpf_get_current_pid_tgid() >> 32 for the parent TGID.
    //
    // WHY NOT ctx.read_at(24)?
    //   The tracepoint field parent_pid stores parent->pid which is the kernel
    //   thread-ID (TID), not the thread-group-ID (TGID = userspace process ID).
    //   For multi-threaded build tools (cmake, ninja) the fork may happen on a
    //   worker thread where TID != TGID. Our filter stores TGIDs, so comparing
    //   against TID would miss those forks entirely.
    //
    // bpf_get_current_pid_tgid() is called in the context of the forking task,
    // so its upper 32 bits give the parent's TGID regardless of which thread
    // initiated the fork.
    let parent_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // child_pid at offset 44 is the new process's TID which equals its TGID
    // because it is the main (and only) thread of the new process.
    let child_tgid: u32 = ctx.read_at(44)?;

    if PID_FILTER.get(&parent_tgid).is_some() {
        let _ = PID_FILTER.insert(&child_tgid, &1u8, 0);
        debug!(ctx, "fork: tracking child {} (parent tgid {})", child_tgid, parent_tgid);
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// sched_process_exit  –  clean up exited PIDs to keep the map lean
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid  = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    // Only remove when the main thread exits (TID == TGID).
    // Removing on a worker-thread exit would prematurely untrack
    // multi-threaded build tools (cmake, ninja, …) still running.
    if tid == tgid {
        let _ = PID_FILTER.remove(&tgid);
    }
    0
}

// ---------------------------------------------------------------------------
// sys_enter_openat  –  capture file paths opened by tracked processes
//
// Tracepoint format (x86-64 kernel, verified via format file):
//   offset  0-7:   common header
//   offset  8-15:  __syscall_nr (int + 4-byte padding)
//   offset 16-23:  dfd  (long)
//   offset 24-31:  filename pointer (const char __user *)
//   offset 32-39:  flags (long)
//   offset 40-47:  mode (umode_t as long)
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match unsafe { try_openat(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    // Only track processes in the filter map.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if PID_FILTER.get(&tgid).is_none() {
        return Ok(0);
    }

    // Read the user-space pointer to the filename string.
    let filename_ptr: u64 = ctx.read_at(24)?;
    if filename_ptr == 0 {
        return Ok(0);
    }

    // Reserve space in the ring buffer and populate it.
    let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) else {
        return Ok(0);
    };

    let event = &mut *entry.as_mut_ptr();
    event.pid = tgid;
    event.filename_len = 0;

    // bpf_probe_read_user_str_bytes writes into the slice and returns the
    // subslice that was actually written (including the null terminator).
    let dest = core::slice::from_raw_parts_mut(event.filename.as_mut_ptr(), MAX_FILENAME_LEN);
    match bpf_probe_read_user_str_bytes(filename_ptr as *const u8, dest) {
        Ok(written) => {
            // bpf_probe_read_user_str_bytes already strips the null terminator
            // from the returned slice, so written.len() is the exact string length.
            event.filename_len = written.len() as u32;
            entry.submit(0);
        }
        Err(_) => {
            entry.discard(0);
        }
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// Required panic handler for no_std BPF binaries.
// ---------------------------------------------------------------------------
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF verifier won't allow infinite loops, so this is never reached.
    unsafe { core::hint::unreachable_unchecked() }
}

//! eBPF kernel programs for the ebpf-component-tracer.
//!
//! Tracepoints attached:
//!  * `sched/sched_process_fork`      – propagates tracking to child processes.
//!  * `sched/sched_process_exit`      – removes exited PIDs from the filter.
//!  * `syscalls/sys_enter_open`       – captures open() calls (x86-64 only).
//!  * `syscalls/sys_enter_openat`     – captures openat() calls.
//!  * `syscalls/sys_enter_openat2`    – captures openat2() calls (Linux ≥ 5.6).
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use aya_log_ebpf::debug;
use aya_log_ebpf::info;
use ebpf_component_tracer_common::{FileEvent, MAX_FILENAME_LEN};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Set of PIDs we care about.  The user-space inserts the root build-command
/// PID; the `sched_process_fork` program adds every descendant automatically.
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(65536, 0);

/// Ring buffer used to stream `FileEvent` records to user-space.
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 26, 0);

/// Per-CPU counter of events dropped due to a full ring buffer.
#[map]
static DROPPED_EVENTS: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU counter of PID_FILTER insert failures in the fork tracepoint.
/// A non-zero value means some child processes were not tracked immediately;
/// proc_watcher serves as a fallback but with ~5 ms latency.
#[map]
static FAILED_PID_INSERTS: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

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
        if PID_FILTER.insert(&child_tgid, &1u8, 0).is_err() {
            // Insert failed (map full or BPF runtime error).  Count it so
            // user-space can warn; proc_watcher will recover with ~5 ms delay.
            info!(ctx, "problems with inserting in PID_FILTER");
            if let Some(c) = FAILED_PID_INSERTS.get_ptr_mut(0) {
                *c += 1;
            }
        } else {
            debug!(ctx, "fork: tracking child {} (parent tgid {})", child_tgid, parent_tgid);
        }
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
// Shared helper: emit a FileEvent for a tracked process.
//
// Called from all three open-syscall tracepoints.  `#[inline(always)]` keeps
// the BPF verifier happy by avoiding BPF-to-BPF call overhead and ensuring
// the helper is analysed in-context for each call site.
// ---------------------------------------------------------------------------
#[inline(always)]
unsafe fn emit_open_event(_ctx: &TracePointContext, filename_ptr: u64) -> Result<u32, i64> {
    if filename_ptr == 0 {
        return Ok(0);
    }

    // Only track processes in the filter map.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if PID_FILTER.get(&tgid).is_none() {
        return Ok(0);
    }

    // Reserve space in the ring buffer and populate it.
    let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) else {
        if let Some(counter) = DROPPED_EVENTS.get_ptr_mut(0) {
            *counter += 1;
        }
        return Ok(0);
    };

    let event = &mut *entry.as_mut_ptr();
    event.pid = tgid;
    event.filename_len = 0;

    let dest = core::slice::from_raw_parts_mut(event.filename.as_mut_ptr(), MAX_FILENAME_LEN);
    match bpf_probe_read_user_str_bytes(filename_ptr as *const u8, dest) {
        Ok(written) => {
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
// sys_enter_open  –  legacy open() syscall (x86-64: syscall #2)
//
// Tracepoint format:
//   offset  0-7:   common header
//   offset  8-15:  __syscall_nr (int + 4-byte padding)
//   offset 16-23:  filename pointer (const char __user *)   ← arg1
//   offset 24-31:  flags (long)
//   offset 32-39:  mode  (long)
//
// NOTE: This tracepoint does not exist on architectures that lack SYS_open
// (arm64, riscv64, …).  User-space skips attachment gracefully if absent.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match unsafe { try_open(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_open(ctx: &TracePointContext) -> Result<u32, i64> {
    let filename_ptr: u64 = ctx.read_at(16)?;
    emit_open_event(ctx, filename_ptr)
}

// ---------------------------------------------------------------------------
// sys_enter_openat  –  openat() syscall (syscall #257 on x86-64)
//
// Tracepoint format:
//   offset  0-7:   common header
//   offset  8-15:  __syscall_nr (int + padding)
//   offset 16-23:  dfd     (long)                          ← arg1
//   offset 24-31:  filename pointer (const char __user *)  ← arg2
//   offset 32-39:  flags   (long)
//   offset 40-47:  mode    (long)
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match unsafe { try_openat(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    let filename_ptr: u64 = ctx.read_at(24)?;
    emit_open_event(ctx, filename_ptr)
}

// ---------------------------------------------------------------------------
// sys_enter_openat2  –  openat2() syscall (Linux ≥ 5.6, syscall #437)
//
// Tracepoint format:
//   offset  0-7:   common header
//   offset  8-15:  __syscall_nr (int + padding)
//   offset 16-23:  dfd      (long)                         ← arg1
//   offset 24-31:  pathname pointer (const char __user *)  ← arg2
//   offset 32-39:  how      (struct open_how * as long)
//   offset 40-47:  usize    (size_t as long)
//
// NOTE: Attachment fails gracefully on kernels < 5.6.
// ---------------------------------------------------------------------------
#[tracepoint]
pub fn sys_enter_openat2(ctx: TracePointContext) -> u32 {
    match unsafe { try_openat2(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_openat2(ctx: &TracePointContext) -> Result<u32, i64> {
    let filename_ptr: u64 = ctx.read_at(24)?;
    emit_open_event(ctx, filename_ptr)
}

// ---------------------------------------------------------------------------
// Required panic handler for no_std BPF binaries.
// ---------------------------------------------------------------------------
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF verifier won't allow infinite loops, so this is never reached.
    unsafe { core::hint::unreachable_unchecked() }
}

//! seccomp-bpf filter for the ptrace backend.
//!
//! Installs a minimal classic-BPF (cBPF) filter that routes only `openat(2)`
//! to the ptrace tracer via `SECCOMP_RET_TRACE`, and passes every other
//! syscall through with `SECCOMP_RET_ALLOW` — no ptrace stop, no overhead.
//!
//! This reduces the number of ptrace events from O(all syscalls) down to
//! O(openat calls only), cutting tracing overhead by two orders of magnitude
//! compared to plain `PTRACE_SYSCALL`.
//!
//! # Kernel compatibility
//!
//! `SECCOMP_MODE_FILTER` and `SECCOMP_RET_TRACE` require Linux ≥ 3.5
//! (released July 2012).  On older kernels `try_install` returns `false`
//! and the caller must fall back to full `PTRACE_SYSCALL` interception.
//!
//! # Usage
//!
//! Call `try_install` from inside a `pre_exec` hook — after `fork(2)`, before
//! `exec(2)`.  The function only performs async-signal-safe operations and
//! never panics.

use libc::{sock_filter, sock_fprog};

// ---------------------------------------------------------------------------
// Classic-BPF instruction encoding
// ---------------------------------------------------------------------------
//
// These are cBPF opcodes as defined in <linux/filter.h>.  We define them
// explicitly rather than relying on libc so we don't depend on a minimum libc
// version and the intent stays readable next to the filter program.

const BPF_LD:  u16 = 0x00; // load into accumulator
const BPF_JMP: u16 = 0x05; // jump
const BPF_RET: u16 = 0x06; // return (ends the program)
const BPF_W:   u16 = 0x00; // 32-bit operand width
const BPF_ABS: u16 = 0x20; // absolute memory offset addressing
const BPF_JEQ: u16 = 0x10; // jump if equal
const BPF_K:   u16 = 0x00; // use the constant k operand

// ---------------------------------------------------------------------------
// seccomp_data field offsets  (<linux/seccomp.h> / <linux/filter.h>)
// ---------------------------------------------------------------------------

/// Offset of `nr` (syscall number) within `struct seccomp_data`.
const OFF_NR: u32 = 0;
/// Offset of `arch` (AUDIT_ARCH_*) within `struct seccomp_data`.
const OFF_ARCH: u32 = 4;

// ---------------------------------------------------------------------------
// Architecture and syscall constants (x86_64 only)
// ---------------------------------------------------------------------------

/// `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// `openat(2)` syscall number on x86_64.
const SYS_OPENAT: u32 = 257;

// ---------------------------------------------------------------------------
// seccomp return actions
// ---------------------------------------------------------------------------

/// Allow the syscall — no ptrace stop, no overhead.
const RET_ALLOW: u32 = 0x7fff_0000;
/// Deliver a `PTRACE_EVENT_SECCOMP` stop to the tracer.
const RET_TRACE: u32 = 0x7ff0_0000;
/// Kill the offending thread (used for the unexpected-arch safety check).
const RET_KILL: u32 = 0x0000_0000;

// ---------------------------------------------------------------------------
// BPF instruction helpers
// ---------------------------------------------------------------------------

#[inline]
fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter { code, jt: 0, jf: 0, k }
}

#[inline]
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

// ---------------------------------------------------------------------------
// Filter program
// ---------------------------------------------------------------------------

/// Build the seccomp BPF program.
///
/// The generated program has this logic:
///
/// ```text
/// [0] LD   arch
/// [1] JEQ  AUDIT_ARCH_X86_64  → true: goto [3]; false: fall through to [2]
/// [2] RET  KILL                (unexpected architecture — should never happen)
/// [3] LD   nr
/// [4] JEQ  SYS_OPENAT          → true: goto [6]; false: fall through to [5]
/// [5] RET  ALLOW
/// [6] RET  TRACE
/// ```
fn build_filter() -> [sock_filter; 7] {
    [
        // Check architecture.
        stmt(BPF_LD  | BPF_W | BPF_ABS,  OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K,  AUDIT_ARCH_X86_64, 1, 0),
        stmt(BPF_RET | BPF_K,             RET_KILL),

        // Check syscall number.
        stmt(BPF_LD  | BPF_W | BPF_ABS,  OFF_NR),
        jump(BPF_JMP | BPF_JEQ | BPF_K,  SYS_OPENAT, 1, 0),
        stmt(BPF_RET | BPF_K,             RET_ALLOW),
        stmt(BPF_RET | BPF_K,             RET_TRACE),
    ]
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Attempt to install the seccomp-bpf filter in the **current process**.
///
/// Designed to be called from inside a `pre_exec` hook — after `fork(2)`,
/// before `exec(2)`.  All operations are async-signal-safe.
///
/// Returns `true` if the filter was successfully installed (caller should use
/// `PTRACE_CONT` + handle `PTRACE_EVENT_SECCOMP`), or `false` if the kernel
/// does not support `SECCOMP_MODE_FILTER` or the call was otherwise rejected
/// (caller must fall back to full `PTRACE_SYSCALL` interception).
///
/// # Safety
///
/// Must be called in a single-threaded context (i.e., between `fork` and
/// `exec`).  All syscalls issued here are async-signal-safe.
pub(super) unsafe fn try_install() -> bool {
    let filter = build_filter();
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut sock_filter,
    };

    // PR_SET_NO_NEW_PRIVS (= 38) is required to install a seccomp filter
    // without CAP_SYS_ADMIN.  Available since Linux 3.5 — same minimum
    // version as SECCOMP_MODE_FILTER, so we treat its failure as "no seccomp".
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_usize, 0_usize, 0_usize, 0_usize) != 0 {
        return false;
    }

    // Install the filter.  The pointer is cast to c_ulong because prctl(2) is
    // variadic; on x86_64 a pointer fits in an unsigned long.
    if libc::prctl(
        libc::PR_SET_SECCOMP,
        libc::SECCOMP_MODE_FILTER as usize,
        (&prog as *const sock_fprog).addr(),
        0_usize,
        0_usize,
    ) != 0
    {
        return false;
    }

    true
}

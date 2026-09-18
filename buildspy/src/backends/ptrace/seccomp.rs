//! seccomp-bpf filter for the ptrace backend.
//!
//! Installs a minimal classic-BPF (cBPF) filter that routes only the open
//! syscalls listed in [`super::syscalls`] to the ptrace tracer via
//! `SECCOMP_RET_TRACE`, and passes every other syscall through with
//! `SECCOMP_RET_ALLOW` — no ptrace stop, no overhead.
//!
//! This reduces the number of ptrace events from O(all syscalls) down to
//! O(open calls only), cutting tracing overhead by two orders of magnitude
//! compared to plain `PTRACE_SYSCALL`.
//!
//! # Tracer lifetime
//!
//! A filter can never be removed, and `SECCOMP_RET_TRACE` with no tracer
//! attached fails the syscall with `ENOSYS`.  A process that outlives the
//! tracer would therefore fail every open from then on — the event loop must
//! never leave a tracee running untraced (see `ORPHAN_GRACE` in `mod.rs`).
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

use super::syscalls::{
    PathArg, AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, I386_OPEN, I386_OPENAT, I386_OPENAT2,
    X86_64_OPEN, X86_64_OPENAT, X86_64_OPENAT2,
};

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
// seccomp return actions
// ---------------------------------------------------------------------------

/// Allow the syscall — no ptrace stop, no overhead.
const RET_ALLOW: u32 = 0x7fff_0000;
/// Deliver a `PTRACE_EVENT_SECCOMP` stop to the tracer.  The low 16 bits
/// (`SECCOMP_RET_DATA`) reach the tracer via `PTRACE_GETEVENTMSG`.
const RET_TRACE: u32 = 0x7ff0_0000;

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

/// `if acc == k` falls through to the next instruction, else skips `jf`.
#[inline]
fn jeq(k: u32, jf: u8) -> sock_filter {
    jump(BPF_JMP | BPF_JEQ | BPF_K, k, 0, jf)
}

/// Trace the syscall, telling the tracer where its pathname is.
#[inline]
fn ret_trace(arg: PathArg) -> sock_filter {
    stmt(BPF_RET | BPF_K, RET_TRACE | arg as u32)
}

// ---------------------------------------------------------------------------
// Filter program
// ---------------------------------------------------------------------------

/// Build the seccomp BPF program.
///
/// The generated program has this logic (jumps are relative: a skip of `n`
/// lands `n + 1` instructions ahead):
///
/// ```text
///  [0] LD   arch
///  [1] JEQ  AUDIT_ARCH_X86_64   → true: [2]; false: [10]
///  [2] LD   nr
///  [3] JEQ  openat  (257)       → true: [4]; false: [5]
///  [4] RET  TRACE | Rsi
///  [5] JEQ  openat2 (437)       → true: [6]; false: [7]
///  [6] RET  TRACE | Rsi
///  [7] JEQ  open    (2)         → true: [8]; false: [9]
///  [8] RET  TRACE | Rdi
///  [9] RET  ALLOW
/// [10] JEQ  AUDIT_ARCH_I386     → true: [11]; false: [18]  (acc still = arch)
/// [11] LD   nr
/// [12] JEQ  openat  (295)       → true: [13]; false: [14]
/// [13] RET  TRACE | Ecx
/// [14] JEQ  openat2 (437)       → true: [15]; false: [16]
/// [15] RET  TRACE | Ecx
/// [16] JEQ  open    (5)         → true: [17]; false: [18]
/// [17] RET  TRACE | Ebx
/// [18] RET  ALLOW                (any other arch: never kill the build)
/// ```
fn build_filter() -> [sock_filter; 19] {
    [
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jeq(AUDIT_ARCH_X86_64, 8),

        // x86_64
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
        jeq(X86_64_OPENAT, 1),
        ret_trace(PathArg::Rsi),
        jeq(X86_64_OPENAT2, 1),
        ret_trace(PathArg::Rsi),
        jeq(X86_64_OPEN, 1),
        ret_trace(PathArg::Rdi),
        stmt(BPF_RET | BPF_K, RET_ALLOW),

        // i386
        jeq(AUDIT_ARCH_I386, 7),
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
        jeq(I386_OPENAT, 1),
        ret_trace(PathArg::Ecx),
        jeq(I386_OPENAT2, 1),
        ret_trace(PathArg::Ecx),
        jeq(I386_OPEN, 1),
        ret_trace(PathArg::Ebx),

        stmt(BPF_RET | BPF_K, RET_ALLOW),
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

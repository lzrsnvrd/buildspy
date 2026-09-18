//! The pathname-taking open syscalls recorded by the ptrace backend.
//!
//! Shared by the seccomp filter (which decides what to trace) and the event
//! loop (which reads the pathname), so both agree on what counts as an open.
//!
//! Two x86 ABIs are covered: native x86_64, and i386 — used by 32-bit
//! processes and by `int $0x80` from 64-bit code.  Same set as the eBPF
//! backend (`open`, `openat`, `openat2`).  The x32 ABI (x86_64 numbers with
//! bit 30 set) is not traced; it is disabled in most distribution kernels.

use libc::user_regs_struct;

/// `AUDIT_ARCH_X86_64` — `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
pub(super) const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `AUDIT_ARCH_I386` — `EM_386 | __AUDIT_ARCH_LE`.
pub(super) const AUDIT_ARCH_I386: u32 = 0x4000_0003;

// Syscall numbers (<asm/unistd_64.h> / <asm/unistd_32.h>).
pub(super) const X86_64_OPEN: u32 = 2;
pub(super) const X86_64_OPENAT: u32 = 257;
pub(super) const X86_64_OPENAT2: u32 = 437;
pub(super) const I386_OPEN: u32 = 5;
pub(super) const I386_OPENAT: u32 = 295;
pub(super) const I386_OPENAT2: u32 = 437;

/// `__USER32_CS` — the code segment of 32-bit user processes on x86_64.
const USER32_CS: u64 = 0x23;

/// Register holding the pathname argument of a traced open syscall.
///
/// The seccomp filter returns this as the `SECCOMP_RET_DATA` of its
/// `SECCOMP_RET_TRACE` action; the tracer reads it back via
/// `PTRACE_GETEVENTMSG`, so it never has to re-derive the ABI itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PathArg {
    /// x86_64 `open` — first argument.
    Rdi = 1,
    /// x86_64 `openat` / `openat2` — second argument.
    Rsi = 2,
    /// i386 `open` — first argument.
    Ebx = 3,
    /// i386 `openat` / `openat2` — second argument.
    Ecx = 4,
}

impl PathArg {
    /// Decode the tag the seccomp filter attached to a `PTRACE_EVENT_SECCOMP`
    /// stop.  `None` for anything the filter does not emit.
    pub fn from_seccomp_data(data: u64) -> Option<Self> {
        match data {
            1 => Some(Self::Rdi),
            2 => Some(Self::Rsi),
            3 => Some(Self::Ebx),
            4 => Some(Self::Ecx),
            _ => None,
        }
    }

    /// Classify a syscall-entry stop (FullSyscall mode, no filter to ask).
    ///
    /// The ABI is inferred from the code segment, so an `int $0x80` issued by
    /// 64-bit code is misread as x86_64 — an accepted gap of the fallback mode.
    pub fn for_syscall(regs: &user_regs_struct) -> Option<Self> {
        let nr = u32::try_from(regs.orig_rax).ok()?;
        if regs.cs == USER32_CS {
            match nr {
                I386_OPEN => Some(Self::Ebx),
                I386_OPENAT | I386_OPENAT2 => Some(Self::Ecx),
                _ => None,
            }
        } else {
            match nr {
                X86_64_OPEN => Some(Self::Rdi),
                X86_64_OPENAT | X86_64_OPENAT2 => Some(Self::Rsi),
                _ => None,
            }
        }
    }

    /// The pathname pointer in the tracee's address space.
    pub fn pointer(self, regs: &user_regs_struct) -> u64 {
        match self {
            Self::Rdi => regs.rdi,
            Self::Rsi => regs.rsi,
            // i386 arguments are 32-bit; the kernel ignores the upper half.
            Self::Ebx => regs.rbx & 0xffff_ffff,
            Self::Ecx => regs.rcx & 0xffff_ffff,
        }
    }
}

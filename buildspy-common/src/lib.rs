//! Shared types between eBPF kernel programs and user-space.
//! Compiled in `no_std` mode for the kernel, `std` mode for user-space.
#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum length of a file path captured by eBPF.
pub const MAX_FILENAME_LEN: usize = 256;

/// `FileEvent.kind` — a file-open event from `sys_enter_open*`.
pub const EVENT_KIND_OPEN: u8 = 0;
/// `FileEvent.kind` — a process-fork event from `sched_process_fork`.
/// `filename` is unused; `pid` is the child TGID.
pub const EVENT_KIND_FORK: u8 = 1;

/// Event emitted by the eBPF tracepoints into the `FILE_EVENTS` ring buffer.
///
/// Two kinds share the same layout:
/// * `EVENT_KIND_OPEN` — `pid` is the opener TGID, `filename[..filename_len]`
///   is the path passed to `open`/`openat`/`openat2`.
/// * `EVENT_KIND_FORK` — `pid` is the child TGID, `filename_len` is 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    /// Thread-group ID of the relevant process (opener or new child).
    pub pid: u32,
    /// Number of valid bytes in `filename` (0 for fork events).
    pub filename_len: u32,
    /// Event kind: `EVENT_KIND_OPEN` or `EVENT_KIND_FORK`.
    pub kind: u8,
    /// Explicit padding to keep `filename` at a predictable offset.
    pub _pad: [u8; 3],
    /// Path passed to open syscall; unused for fork events.
    pub filename: [u8; MAX_FILENAME_LEN],
}

// Safety: FileEvent is repr(C), Copy, and contains no references or padding
// that would make it unsafe to interpret as raw bytes.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}

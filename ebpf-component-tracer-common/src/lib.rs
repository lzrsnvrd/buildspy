//! Shared types between eBPF kernel programs and user-space.
//! Compiled in `no_std` mode for the kernel, `std` mode for user-space.
#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum length of a file path captured by eBPF.
pub const MAX_FILENAME_LEN: usize = 256;

/// Event emitted by the `sys_enter_openat` tracepoint.
/// Contains the PID of the process and the path it tried to open.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    /// Thread-group ID (== PID in single-threaded processes).
    pub pid: u32,
    /// Number of valid bytes in `filename` (excluding null terminator).
    pub filename_len: u32,
    /// Null-terminated path, zero-padded to MAX_FILENAME_LEN.
    pub filename: [u8; MAX_FILENAME_LEN],
}

// Safety: FileEvent is repr(C), Copy, and contains no references or padding
// that would make it unsafe to interpret as raw bytes.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}

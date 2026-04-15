//! Watchdog diagnostics for the ptrace event loop.
//!
//! Decodes `/proc/<pid>/syscall` lines into human-readable summaries for
//! stall reporting when `waitpid` is interrupted by SIGUSR1.

/// Parse a `/proc/{pid}/syscall` line and return a human-readable summary.
///
/// Kernel format: `nr arg0 arg1 arg2 arg3 arg4 arg5 sp pc`
/// where `nr` is a plain decimal integer and `argN` is `0x`-prefixed hex.
/// Returns `"running"` if the process is not currently blocked in a syscall.
pub fn decode_syscall_line(raw: &str) -> String {
    if raw == "running" || raw.is_empty() {
        return "running".into();
    }

    let parts: Vec<&str> = raw.split_ascii_whitespace().collect();
    if parts.is_empty() {
        return raw.to_string();
    }

    let nr = parts[0]
        .parse::<u64>()
        .or_else(|_| u64::from_str_radix(parts[0].trim_start_matches("0x"), 16))
        .unwrap_or(u64::MAX);

    // Retrieve the n-th syscall argument (0-based); all values are hex.
    let arg = |n: usize| -> u64 {
        parts
            .get(n + 1)
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0)
    };

    match nr {
        61  => format!("wait4(pid={})", arg(0) as i64),
        247 => format!("waitid(id={})", arg(1) as i64),
        7 => {
            let timeout = arg(2) as i64;
            if timeout < 0 { format!("poll(nfds={}, timeout=∞)", arg(1)) }
            else            { format!("poll(nfds={}, timeout={timeout}ms)", arg(1)) }
        }
        271 => {
            let nfds = arg(1);
            if arg(2) == 0 { format!("ppoll(nfds={nfds}, timeout=∞)") }
            else            { format!("ppoll(nfds={nfds})") }
        }
        23  => format!("select(nfds={})", arg(0)),
        270 => {
            let nfds = arg(0);
            if arg(4) == 0 { format!("pselect6(nfds={nfds}, timeout=∞)") }
            else            { format!("pselect6(nfds={nfds})") }
        }
        232 | 281 | 441 => {
            let timeout = arg(3) as i64;
            if timeout < 0 { "epoll_wait(timeout=∞)".into() }
            else            { format!("epoll_wait(timeout={timeout}ms)") }
        }
        202 => format!("futex(op=0x{:x})", arg(1)),
        0   => format!("read(fd={})", arg(0)),
        35 | 230 => "nanosleep".into(),
        _   => format!("syscall#{nr}"),
    }
}

# Design decisions and hard-won lessons

This document records the non-obvious constraints and bugs that shaped the current
implementation. Read before touching the relevant code.

---

## Backends

### ptrace: WNOHANG is a fatal regression

`waitpid` in the ptrace event loop must be blocking (no `WNOHANG`).
Using `WNOHANG` causes `waitpid` to return immediately with `ECHILD` or `0`
whenever the tracee hasn't exited yet, causing the loop to terminate early
and miss most process events.

### ptrace: FORK race — child arrives before parent's PTRACE_EVENT_FORK

Linux does not guarantee that `PTRACE_EVENT_FORK/CLONE/VFORK` is returned by
`waitpid` before the child's first stop. Two code paths handle this:

1. **Child before event** (`alive_pids` doesn't contain the child when
   `PTRACE_EVENT_FORK` fires): the FORK event must NOT insert into
   `pending_children` — the child is already running; inserting would cause
   the next signal stop for that child to be silently swallowed as a fake
   "initial stop", losing the signal (e.g. SIGTERM from make).

2. **Exit before event** (child exits before `child_to_parent` is populated):
   `Exited`/`Signaled` handlers fall back to `mem::read_ppid()` to get the
   parent PID from `/proc/<pid>/status` (readable while the child is a
   regular zombie).

### ptrace: SIGCHLD re-delivery after ptrace-zombie window

Under ptrace, the kernel may deliver `SIGCHLD` to the parent while the child
is in "ptrace-zombie" state — invisible to the parent's `waitpid(WNOHANG)`.
The parent's SIGCHLD handler finds nothing and re-enters `pselect6`/`epoll`,
blocking forever because no second SIGCHLD arrives.

Fix: when `Exited(child)` is processed (which ends the ptrace-zombie window),
send a fresh `SIGCHLD` to the parent. Idempotent: if the original fires first,
the parent handles it; if second, it re-runs `waitpid` safely.

### ptrace: stopping signals must not be injected

Injecting `SIGSTOP`/`SIGTSTP`/`SIGTTIN`/`SIGTTOU` via `ptrace::cont` causes
the tracee to enter group-stop. Under `PTRACE_TRACEME` that stop is reported
back to the tracer as another `Stopped(pid, SIGSTOP)` — creating an infinite
inject→stop→report loop that permanently deadlocks the process.

In a build context there is no terminal job control, so suppressing these
signals is correct.

### eBPF: BTF required

`build.rs` passes `-Clink-arg=--btf`. Without BTF the ELF loader fails when
attaching tracepoints on kernels that require relocations.

### eBPF: tracepoint field offsets are read at runtime, not hardcoded

Tracepoint context layouts change between kernel versions (example: modern
kernels use `__data_loc char[]` for `parent_comm`/`child_comm` in
`sched_process_fork`, shifting `child_pid` from offset 44 to 20; syscall
tracepoints use spaces instead of tabs in their format files).

At startup `backends/ebpf/mod.rs` reads each tracepoint's
`/sys/kernel/tracing/events/<cat>/<event>/format` (falling back to debugfs),
parses the `offset:N` value for the relevant field, and injects it into the
eBPF binary via `EbpfLoader::set_global` before loading.  The eBPF program
accesses the offset through a `#[no_mangle] static` in `.rodata`, so the
kernel-side code never contains a literal number.

If tracefs is unavailable the hardcoded compile-time default is used and a
warning is logged — the binary keeps working but may silently misread events
on a kernel with a non-standard layout.

### eBPF: PID discovery via ring buffer, not proc polling

`proc_watcher::watch_children` (poll `/proc` for new PIDs) was removed.
The kernel `sched_process_fork` tracepoint emits `EVENT_KIND_FORK` into
`FILE_EVENTS` after a successful `PID_FILTER` insert. User-space also lazily
sends the first-seen PID from any open event (the process is alive because it
just called `openat`). No polling needed.

### eBPF: BPF verifier requires full initialization (kernel ≥ 5.16)

All bytes of a ring-buffer reservation must be written before `submit`.
Fork events must explicitly zero `event.filename`; otherwise the verifier
rejects the program.

### eBPF: exit_rx drain

After `select!` exits via `exit_rx`, `new_pid_rx.try_recv()` is drained to
completion. Without this drain, late PIDs arriving in the ~300 ms flush window
are lost and their comm/cwd metadata is missing from the report.

---

## Analysis

### DpkgIndex is in-memory, never subprocess

Shelling out to `dpkg -S` for every path is O(N) subprocess spawns and takes
minutes for a large build. The in-memory index is built once from
`/var/lib/dpkg/info/*.list` (paths → pkg key) and `/var/lib/dpkg/status`
(pkg key → version). Lookups are O(1).

### Symlink resolution at index time, not event time

On merged-usr systems `/lib` is a symlink to `usr/lib`. The dynamic linker
opens `/lib/x86_64-linux-gnu/libc.so.6` but dpkg records it as
`/usr/lib/x86_64-linux-gnu/libc.so.6`. When a direct lookup fails,
`query_dpkg_indexed` calls `fs::canonicalize` once and retries. This is the
only filesystem call in the hot path; it is cached so it happens at most once
per unique path.

### CycloneDX must be scanner-agnostic

No `aquasecurity:trivy:*` or tool-specific extension fields. Only standard
CycloneDX 1.6 fields. PURL types follow the spec (`deb`, `rpm`, `alpm`,
`generic`) so any compatible scanner (Grype, OSV-scanner, Trivy) can consume
the output.

### OSV vulnerability scanning is disabled

The OSV API is blocked by the corporate proxy. The `vuln-scan` feature was
removed entirely. Do not re-add network calls without testing connectivity.

---

## Output

The tool writes two files:

- `report.json` — custom schema (`Report` + `Component[]` with `ComponentType` enum)
- `<stem>.cdx.json` — CycloneDX 1.6 BOM

`ComponentType` serializes with `#[serde(rename_all = "snake_case")]`:
`system_package`, `local_file`, `system_unknown`, `ecosystem_package`.
The variant order in the enum also defines the sort order in the output report.

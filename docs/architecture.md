# Architecture

## Workspace layout

```
build_analyzer/
├── Cargo.toml                        workspace root (default-members excludes ebpf crate)
├── buildspy/                         user-space binary
│   ├── build.rs                      compiles the eBPF crate via aya-build
│   └── src/
│       ├── main.rs                   CLI, event loop, report assembly
│       ├── proc_info.rs              read_comm / read_cwd helpers (/proc/<pid>/…)
│       ├── backends/
│       │   ├── mod.rs                TracingSession type + Backend enum + factory
│       │   ├── ebpf/
│       │   │   └── mod.rs            eBPF backend: load bytecode, ring-buffer drain
│       │   └── ptrace/
│       │       ├── mod.rs            ptrace backend: spawn + event loop
│       │       ├── diagnostics.rs    decode_syscall_line (watchdog stall reporting)
│       │       ├── mem.rs            emit_path, read_path_from_mem, read_ppid
│       │       └── seccomp.rs        install seccomp-bpf filter in child
│       ├── analysis/
│       │   ├── mod.rs
│       │   ├── filter.rs             BUILD_ORCHESTRATORS list + is_build_orchestrator()
│       │   ├── resolver.rs           is_relevant(), normalize(), is_system_path()
│       │   ├── identity.rs           IdentityEngine: dpkg/pacman/rpm lookup + SHA-256
│       │   ├── report.rs             Report / Component / ComponentType; collect_components()
│       │   └── cyclonedx.rs          CycloneDX 1.6 BOM builder
│       └── ecosystem/
│           ├── mod.rs                concurrent scanner entry point
│           ├── cargo.rs              Cargo.lock parser
│           ├── npm.rs                package-lock.json / yarn.lock
│           ├── python.rs             poetry.lock / requirements.txt
│           └── golang.rs             go.mod / go.sum
├── buildspy-common/
│   └── src/lib.rs                    FileEvent struct (no_std + std dual-build)
└── buildspy-ebpf/
    └── src/main.rs                   kernel eBPF program (no_std, bpfel-unknown-none)
```

The eBPF crate is compiled by `build.rs` via `aya-build`, not by the default workspace build.
It is listed in `[workspace.members]` only so aya-build can locate it, but excluded from
`default-members` so `cargo build` at the root doesn't try to compile it for the host target.

---

## Data flow

```
Build process
     │  openat(2) syscall
     ▼
┌────────────┐   FileEvent (ring buf)   ┌──────────────────┐
│ eBPF kern  │ ──────────────────────▶  │ drain thread     │
│ (openat    │                          │ (std::thread)    │
│  fork/exit │   pid via fork event     │                  │
│  tracepts) │                          │  path_tx ──────▶ │
└────────────┘                          │  new_pid_tx ───▶ │
                                        └──────────────────┘
     OR

Build process
     │  openat(2) syscall
     ▼
┌────────────┐
│ ptrace     │  PTRACE_EVENT_SECCOMP /
│ (seccomp   │  PTRACE_SYSCALL stop
│  or full   │  read rsi → /proc/pid/mem
│  syscall)  │  path_tx / new_pid_tx
└────────────┘

Both backends produce the same three channels into TracingSession:

  path_rx     : (String, u32)     – (absolute_path, opener_pid)
  new_pid_rx  : u32               – newly discovered PIDs (for /proc metadata)
  exit_rx     : Option<i32>       – build exit code, sent after all events are flushed

main.rs event loop:
  tokio::select! {
    new_pid_rx  → read /proc/<pid>/comm + cwd into pid_to_comm / pid_to_cwd
    exit_rx     → break, then drain new_pid_rx with try_recv()
    ctrl_c      → call shutdown(), await exit_rx
  }

Post-build analysis pipeline (all synchronous, after exit_rx fires):
  collect_components()
    │  drain path_rx (try_recv)
    │  filter: is_build_orchestrator(comm) → skip
    │  filter: is_relevant(path) → skip
    │  normalize(path, cwd) → absolute canonical path
    │  IdentityEngine::identify(path) → ComponentIdentity
    │  dedup by component key
    ▼
  + ecosystem::detect() (concurrent lock-file scan)
    ▼
  Report (report.json)  +  CycloneDX BOM (*.cdx.json)
```

---

## Key types

### `TracingSession` (`backends/mod.rs`)

```rust
pub struct TracingSession {
    pub path_rx:    UnboundedReceiver<(String, u32)>,
    pub new_pid_rx: UnboundedReceiver<u32>,
    pub exit_rx:    oneshot::Receiver<Option<i32>>,
    pub shutdown:   Option<Box<dyn FnOnce() + Send + 'static>>,
}
```

`exit_rx` resolves only **after** the backend has flushed all in-flight events.
`shutdown` is `Some` only for ptrace; eBPF handles cleanup itself via drop.

### `FileEvent` (`buildspy-common/src/lib.rs`)

```rust
#[repr(C)]
pub struct FileEvent {
    pub pid:          u32,      // TGID of opener (open) or new child (fork)
    pub filename_len: u32,      // 0 for fork events
    pub kind:         u8,       // EVENT_KIND_OPEN=0, EVENT_KIND_FORK=1
    pub _pad:         [u8; 3],
    pub filename:     [u8; 256],
}  // total: 268 bytes
```

The BPF verifier requires all bytes written before submit (≥ kernel 5.16).
Fork events must explicitly zero `event.filename`.

### `ComponentType` (`analysis/report.rs`)

```rust
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    EcosystemPackage,  // from lock files
    LocalFile,         // local build artifact, identified by SHA-256
    SystemPackage,     // identified by dpkg / pacman / rpm
    SystemUnknown,     // on system prefix but not in package DB
}
```

Variant order defines the sort order in the output report.

---

## eBPF kernel program

Five tracepoints in `buildspy-ebpf/src/main.rs`:

| Tracepoint | Purpose |
|---|---|
| `sched/sched_process_fork` | Insert child PID into `PID_FILTER`; emit `EVENT_KIND_FORK` to ring buf |
| `sched/sched_process_exit` | Remove PID from `PID_FILTER` |
| `syscalls/sys_enter_openat` | Capture filename → ring buf (all kernels) |
| `syscalls/sys_enter_open` | Same, x86-64 legacy syscall (optional, skipped gracefully) |
| `syscalls/sys_enter_openat2` | Same, Linux ≥ 5.6 (optional, skipped gracefully) |

Kernel maps:
- `PID_FILTER: HashMap<u32, u8>` — max 65 536 PIDs
- `FILE_EVENTS: RingBuf` — 64 MiB, streams to user space
- `DROPPED_EVENTS: PerCpuArray<u32>` — incremented on ring-buf full
- `FAILED_PID_INSERTS: PerCpuArray<u32>` — incremented on PID_FILTER insert failure

**Tracepoint field offsets** are read at startup from
`/sys/kernel/tracing/events/<cat>/<event>/format` (fallback: debugfs) and
injected into the eBPF binary before loading via `EbpfLoader::set_global`.
The four patched globals and their compile-time defaults are:

| Global | Tracepoint | Field | Default |
|---|---|---|---|
| `FORK_CHILD_PID_OFFSET` | `sched/sched_process_fork` | `child_pid` | 20 |
| `OPEN_FILENAME_OFFSET` | `syscalls/sys_enter_open` | `filename` | 16 |
| `OPENAT_FILENAME_OFFSET` | `syscalls/sys_enter_openat` | `filename` | 24 |
| `OPENAT2_FILENAME_OFFSET` | `syscalls/sys_enter_openat2` | `filename` | 24 |

If the format file is missing (tracefs not mounted) the default is used and a
warning is logged. The binary therefore survives kernel upgrades without
recompilation.

---

## ptrace backend internals

Trace mode is chosen once at startup:

- **Seccomp** (preferred): child installs `seccomp-bpf` filter returning `SECCOMP_RET_TRACE`
  for `openat` only. Tracer uses `PTRACE_CONT`; gets `PTRACE_EVENT_SECCOMP` stops only.
- **FullSyscall** (fallback, kernel < 3.5): tracer uses `PTRACE_SYSCALL`; every syscall
  produces an entry + exit stop. Overhead ~100× higher.

Mode is communicated child → tracer via a one-byte pipe written in `pre_exec`.

The tracer thread:
1. Forks the child (must be same OS thread as the event loop — Linux ptrace requirement)
2. Runs `ptrace_loop` until `ECHILD` or shutdown
3. Sends exit code on `exit_tx`

Key state in the event loop:
- `pending_children`: PIDs announced by `PTRACE_EVENT_FORK` before their first stop
- `alive_pids`: all live PIDs (for watchdog stall logging)
- `child_to_parent`: needed to re-deliver `SIGCHLD` after ptrace-zombie window closes
- `in_syscall`: `FullSyscall` only — distinguishes entry from exit stops

---

## Identity resolution

`IdentityEngine` (analysis/identity.rs):
1. Detects package manager once at startup (`dpkg` / `pacman` / `rpm`)
2. For dpkg: builds in-memory index from `/var/lib/dpkg/info/*.list` (paths → pkg key)
   and `/var/lib/dpkg/status` (pkg key → version + source). O(1) lookups, no subprocesses.
3. On merged-usr systems `/lib → /usr/lib`; direct lookup fails, then retries with
   `fs::canonicalize`. Symlinks resolved at index-build time, not at event time.
4. Cache: `Mutex<HashMap<path, result>>` — same path never resolved twice.

---

## Ecosystem lock-file scanning

`ecosystem::detect()` runs four parsers (Cargo / npm / Python / Go).
Each parser first checks whether its package manager actually ran during the build
(via `pid_to_comm`): if not, the parser returns immediately without touching the
filesystem. This ensures that lock files present in the project tree but unrelated
to the current build are not included in the report.

If the package manager did run, the parser scans `project_dir` for its lock file,
parses all pinned dependencies, and returns them. Results are deduplicated;
`dev`-only dependencies are flagged and omitted unless `--ecosystem-dev` is set.

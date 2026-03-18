//! ebpf-component-tracer – user-space entry point.
//!
//! Usage:
//!   sudo ebpf-tracer [OPTIONS] -- <build command>
//!
//! Example:
//!   sudo ebpf-tracer -- cmake --build ./build
//!   sudo ebpf-tracer --output deps.json -- meson compile -C build

mod identity;
mod resolver;

use std::{
    collections::HashSet,
    collections::VecDeque,
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{HashMap as AyaHashMap, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use aya_log::EbpfLogger;
use chrono::Utc;
use clap::Parser;
use ebpf_component_tracer_common::FileEvent;
use identity::{ComponentIdentity, IdentityEngine};
use serde::{Deserialize, Serialize};
use tokio::io::unix::AsyncFd;

// ---------------------------------------------------------------------------
// Embedded eBPF bytecode (compiled by build.rs via aya-build).
// `include_bytes_aligned!` aligns the data to 32 bytes as required by Aya's
// ELF parser.  aya-build places the binary at OUT_DIR/<binary-name>.
// ---------------------------------------------------------------------------
static EBPF_BYTECODE: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf-tracer-bpf"));

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "eBPF-powered SCA tracer – records every library/header opened during a build"
)]
struct Cli {
    /// Path for the JSON report (default: report.json).
    #[arg(short, long, default_value = "report.json")]
    output: PathBuf,

    /// Project root used to distinguish local from system files.
    /// Defaults to the current working directory.
    #[arg(short, long)]
    project_dir: Option<PathBuf>,

    /// Enable verbose eBPF log output (requires `RUST_LOG=debug`).
    #[arg(short, long)]
    verbose: bool,

    /// The build command and its arguments (everything after `--`).
    #[arg(last = true, required = true)]
    build_command: Vec<String>,
}

// ---------------------------------------------------------------------------
// Output schema
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
struct Report {
    timestamp: String,
    build_command: String,
    project_dir: String,
    exit_code: Option<i32>,
    components: Vec<Component>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
struct Component {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    path: String,
    #[serde(rename = "type")]
    component_type: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialise logging.
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level),
    )
    .init();

    // Resolve project root.
    let project_dir = cli
        .project_dir
        .clone()
        .unwrap_or_else(|| env::current_dir().expect("failed to get cwd"));

    let build_command_str = cli.build_command.join(" ");
    log::info!("Build command : {}", build_command_str);
    log::info!("Project dir   : {}", project_dir.display());
    log::info!("Output        : {}", cli.output.display());

    // ------------------------------------------------------------------
    // Load eBPF object and attach tracepoints.
    // ------------------------------------------------------------------
    let mut bpf = Ebpf::load(EBPF_BYTECODE)
        .context("failed to load eBPF bytecode – are you running as root?")?;

    if cli.verbose {
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            log::warn!("eBPF logger unavailable: {e}");
        }
    }

    attach_tracepoint(&mut bpf, "sched_process_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut bpf, "sched_process_exit", "sched", "sched_process_exit")?;
    attach_tracepoint(&mut bpf, "sys_enter_openat", "syscalls", "sys_enter_openat")?;
    log::info!("eBPF tracepoints attached.");

    // ------------------------------------------------------------------
    // Take ownership of the ring buffer (moves it out of `bpf`).
    // This lets us move `ring_buf` into a separate task while `bpf`
    // stays alive in main and owns the PID_FILTER map.
    // ------------------------------------------------------------------
    let ring_buf_map = bpf
        .take_map("FILE_EVENTS")
        .ok_or_else(|| anyhow!("FILE_EVENTS map not found"))?;
    let ring_buf = RingBuf::try_from(ring_buf_map)
        .context("failed to convert map to RingBuf")?;

    // ------------------------------------------------------------------
    // Spawn the event-collection task.
    // ------------------------------------------------------------------
    let (path_tx, mut path_rx) =
        tokio::sync::mpsc::unbounded_channel::<(String, u32)>();
    let (stop_tx, mut stop_rx) =
        tokio::sync::oneshot::channel::<()>();

    let event_task = tokio::spawn(async move {
        let mut async_fd = match AsyncFd::new(ring_buf) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!("AsyncFd::new failed: {e}");
                return;
            }
        };

        loop {
            tokio::select! {
                // Shutdown signal from main task.
                _ = &mut stop_rx => {
                    // NON-BLOCKING final drain.
                    //
                    // DO NOT call async_fd.readable_mut().await here.
                    // If the ring buffer is already empty (all events were
                    // drained in the loop below), that future never resolves
                    // and the task hangs forever, preventing the report from
                    // being written.
                    //
                    // rb.next() is non-blocking: it returns None immediately
                    // when the buffer is empty, which is what we want.
                    drain_ring_buf(async_fd.get_mut(), &path_tx);
                    break;
                }

                // New data in the ring buffer.
                result = async_fd.readable_mut() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(e) => {
                            log::error!("poll error: {e}");
                            break;
                        }
                    };
                    drain_ring_buf(guard.get_inner_mut(), &path_tx);
                    guard.clear_ready();
                }
            }
        }
    });

    // ------------------------------------------------------------------
    // Spawn the build command — race-free PID tracking.
    //
    // Strategy:
    //   1. Insert OUR OWN TGID into the filter BEFORE the fork so that
    //      sched_process_fork (which uses bpf_get_current_pid_tgid >> 32 for
    //      the parent TGID) fires correctly even when tokio uses a worker
    //      thread to do the fork.
    //   2. After spawn, also insert child_pid explicitly as a safety net for
    //      the tiny window before sched_process_fork fires.
    //   3. Remove our own TGID so we don't track our own file opens.
    // ------------------------------------------------------------------
    let our_tgid = std::process::id();
    {
        let pid_map = bpf
            .map_mut("PID_FILTER")
            .context("PID_FILTER map not found")?;
        let mut pid_filter =
            AyaHashMap::<_, u32, u8>::try_from(pid_map)
                .context("failed to wrap PID_FILTER")?;
        pid_filter
            .insert(our_tgid, 1u8, 0)
            .context("failed to insert our TGID into filter")?;
    }

    let mut child = tokio::process::Command::new(&cli.build_command[0])
        .args(&cli.build_command[1..])
        .current_dir(&project_dir)
        .spawn()
        .with_context(|| format!("failed to spawn '{}'", cli.build_command[0]))?;

    let child_pid = child
        .id()
        .ok_or_else(|| anyhow!("could not retrieve child PID"))?;

    log::info!("Build started (PID {}).", child_pid);

    // Remove our TGID and ensure child_pid is tracked.
    {
        let pid_map = bpf
            .map_mut("PID_FILTER")
            .context("PID_FILTER map not found")?;
        let mut pid_filter =
            AyaHashMap::<_, u32, u8>::try_from(pid_map)
                .context("failed to wrap PID_FILTER")?;
        // sched_process_fork should have added child_pid already; inserting
        // again is idempotent and covers the rare race window.
        pid_filter
            .insert(child_pid, 1u8, 0)
            .context("failed to insert child PID into filter")?;
        // Stop tracking our own process so our file opens don't pollute results.
        let _ = pid_filter.remove(&our_tgid);
    }

    // ------------------------------------------------------------------
    // Wait for the build to finish, while a background task continuously
    // scans /proc to discover new child PIDs and insert them into the
    // eBPF filter.  This is a reliable user-space complement to the
    // sched_process_fork tracepoint which can miss forks on some kernel
    // versions or when processes are spawned via clone3/vfork.
    // ------------------------------------------------------------------
    let (new_pid_tx, mut new_pid_rx) =
        tokio::sync::mpsc::unbounded_channel::<u32>();

    // Cache: PID → process name (comm), used to filter build-tool opens.
    let mut pid_to_comm: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();

    // Seed the watcher with the direct child PID.
    let _ = new_pid_tx.send(child_pid);

    tokio::spawn(async move {
        let mut known: HashSet<u32> = HashSet::new();
        known.insert(child_pid);
        loop {
            for pid in discover_new_children(&known) {
                known.insert(pid);
                let _ = new_pid_tx.send(pid);
            }
            // Stop once the root process no longer exists in /proc.
            if !Path::new(&format!("/proc/{}", child_pid)).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });

    let exit_status = loop {
        tokio::select! {
            // New child PID discovered by proc-watcher.
            Some(pid) = new_pid_rx.recv() => {
                if let Some(pid_map) = bpf.map_mut("PID_FILTER") {
                    if let Ok(mut pf) =
                        AyaHashMap::<_, u32, u8>::try_from(pid_map)
                    {
                        let _ = pf.insert(pid, 1u8, 0);
                    }
                }
                // Read process name while the process is still alive.
                let comm = std::fs::read_to_string(
                    format!("/proc/{pid}/comm"))
                    .unwrap_or_default();
                let comm = comm.trim().to_string();
                log::debug!("proc-watcher: tracking PID {} ({})", pid, comm);
                pid_to_comm.insert(pid, comm);
            }
            // Build process finished.
            result = child.wait() => {
                break result.context("failed to wait for child")?;
            }
        }
    };

    log::info!(
        "Build finished (exit code: {}).",
        exit_status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string())
    );

    // Give the ring buffer a moment to flush the last batch of events.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Signal the event task to drain and stop.
    let _ = stop_tx.send(());
    let _ = event_task.await;

    // ------------------------------------------------------------------
    // Collect unique, relevant paths.
    // Build-orchestrator opens (cmake, make, ninja, …) are excluded because
    // they reflect the orchestrator's own runtime dependencies, not the
    // project's.  Only opens from compilers, linkers, and custom scripts
    // are kept.
    // ------------------------------------------------------------------
    let mut unique_paths: HashSet<String> = HashSet::new();
    while let Ok((raw, opener_pid)) = path_rx.try_recv() {
        let opener_comm = pid_to_comm
            .get(&opener_pid)
            .map(String::as_str)
            .unwrap_or("");
        if is_build_orchestrator(opener_comm) {
            log::debug!("skip ({}): {}", opener_comm, raw);
            continue;
        }
        if resolver::is_relevant(&raw) {
            let normalized = resolver::normalize(&raw, &project_dir);
            unique_paths.insert(normalized.to_string_lossy().to_string());
        }
    }
    log::info!("Collected {} unique relevant paths.", unique_paths.len());

    // ------------------------------------------------------------------
    // Resolve identities and deduplicate.
    //
    // Deduplication strategy:
    //   • SystemPackage  → key = package name.  Dozens of headers from the
    //     same package collapse into one component.
    //   • UnknownSystem  → key = soname base (strip version suffix).
    //     libssl.so.3 and libssl.so.3.0.2 → one "libssl" entry.
    //   • LocalFile      → skip headers (.h/.hpp/…) from outside system
    //     prefixes — those are the project's own source, not dependencies.
    //     Keep .so and .a files; key = path.
    // ------------------------------------------------------------------
    let engine = IdentityEngine::new();
    // HashMap key → Component (first-seen wins for same key).
    let mut components: std::collections::HashMap<String, Component> =
        std::collections::HashMap::new();

    for path_str in &unique_paths {
        let path = Path::new(path_str);

        // Skip paths that don't exist on disk.  These are failed openat()
        // attempts — e.g. the dynamic linker probing rpath directories for a
        // library that isn't there.  We only care about files that were
        // successfully opened and read.
        if !path.exists() {
            continue;
        }

        // Drop local header files — they are the project's own source,
        // not external dependencies worth reporting.
        if !resolver::is_system_path(path) {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            let is_header = matches!(
                ext,
                "h" | "hpp" | "hxx" | "hh" | "H" | "inl" | "tcc"
            );
            if is_header {
                continue;
            }
        }

        let comp = resolve_component(path_str, path, &engine, &project_dir);

        let key = match comp.component_type.as_str() {
            "system_package" => comp.name.clone(),
            "system_unknown" => soname_base(&comp.name),
            _ => path_str.to_string(), // local files: path is the key
        };

        components.entry(key).or_insert(comp);
    }

    // ------------------------------------------------------------------
    // Build and write the report.
    // ------------------------------------------------------------------
    let mut component_list: Vec<Component> = components.into_values().collect();
    // Sort deterministically: system packages first, then local files.
    component_list.sort_by(|a, b| {
        a.component_type
            .cmp(&b.component_type)
            .then(a.name.cmp(&b.name))
    });

    let report = Report {
        timestamp: Utc::now().to_rfc3339(),
        build_command: build_command_str,
        project_dir: project_dir.to_string_lossy().to_string(),
        exit_code: exit_status.code(),
        components: component_list,
    };

    let json =
        serde_json::to_string_pretty(&report).context("failed to serialise report")?;
    std::fs::write(&cli.output, &json)
        .with_context(|| format!("failed to write {}", cli.output.display()))?;

    log::info!(
        "Report written to {} ({} components).",
        cli.output.display(),
        report.components.len()
    );
    println!("{}", json);

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build-orchestration tools whose file opens should NOT be reported as
/// project dependencies.  These tools open their own runtime libraries
/// (cmake → libjsoncpp, make → libc, ninja → libc++, …) which have nothing
/// to do with the project being built.
///
/// Compilers, linkers, and assemblers are intentionally NOT listed here —
/// the headers and libraries they open ARE the project's dependencies.
const BUILD_ORCHESTRATORS: &[&str] = &[
    // CMake family
    "cmake", "ccmake", "cmake3", "ctest", "cpack",
    // Make family
    "make", "gmake", "mingw32-make",
    // Ninja
    "ninja", "samu",
    // Meson / autotools
    "meson", "autoconf", "automake", "configure",
    // Package-config helpers
    "pkg-config", "pkgconf",
    // Shells used as build glue (sh/bash open their own libc, not project libs)
    "sh", "bash", "dash", "zsh", "fish",
    // Python / Perl (used by meson, autotools)
    "python3", "python", "perl",
];

/// Strip the version suffix from a shared-library filename to get a stable
/// deduplication key.
///
/// Examples:
///   `libssl.so.3`     → `libssl`
///   `libfoo.so.1.2.3` → `libfoo`
///   `libbar.so`       → `libbar`
///   `libstdc++.so.6`  → `libstdc++`
fn soname_base(name: &str) -> String {
    // The name stored in Component is the file_stem of the path, which may
    // still contain ".so" if the path was e.g. "libssl.so.3" (file_stem gives
    // "libssl.so").  Strip everything from ".so" onward.
    let base = if let Some(pos) = name.find(".so") {
        &name[..pos]
    } else {
        name
    };
    // Strip leading "lib" prefix for readability (same as resolve_component).
    base.strip_prefix("lib").unwrap_or(base).to_string()
}

/// Returns true if the process `comm` name belongs to a build orchestrator
/// whose file opens should be filtered out.
fn is_build_orchestrator(comm: &str) -> bool {
    // Strip version suffixes: "python3.11" → "python3", "bash5" → "bash"
    let base = comm
        .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .trim_end_matches('-');
    BUILD_ORCHESTRATORS.contains(&comm) || BUILD_ORCHESTRATORS.contains(&base)
}

/// Scan /proc to find PIDs that are children (or deeper descendants) of any
/// PID in `known` but not yet in `known`.
///
/// Uses `/proc/<pid>/task/<pid>/children` when available (CONFIG_PROC_CHILDREN),
/// falling back to reading PPid from `/proc/<pid>/status` for every process
/// visible in /proc.
fn discover_new_children(known: &HashSet<u32>) -> Vec<u32> {
    // Fast path: kernel exposes direct children list per thread.
    if let Some(pids) = discover_via_children_file(known) {
        return pids;
    }
    // Slow path: walk all of /proc and match by PPid.
    discover_via_proc_scan(known)
}

/// Try /proc/<pid>/task/<pid>/children.  Returns None if the file is missing
/// on this kernel (CONFIG_PROC_CHILDREN not set).
fn discover_via_children_file(known: &HashSet<u32>) -> Option<Vec<u32>> {
    let mut new_pids = Vec::new();
    let mut any_file_found = false;
    let mut queue: VecDeque<u32> = known.iter().copied().collect();
    let mut visited: HashSet<u32> = known.clone();

    while let Some(pid) = queue.pop_front() {
        let path = format!("/proc/{pid}/task/{pid}/children");
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        any_file_found = true;
        for child_str in content.split_whitespace() {
            if let Ok(child) = child_str.parse::<u32>() {
                if visited.insert(child) {
                    new_pids.push(child);
                    queue.push_back(child);
                }
            }
        }
    }

    if any_file_found {
        Some(new_pids)
    } else {
        // No children files found – this kernel may not have CONFIG_PROC_CHILDREN.
        None
    }
}

/// Fallback: read PPid from every /proc/<pid>/status and build descendants.
fn discover_via_proc_scan(known: &HashSet<u32>) -> Vec<u32> {
    let mut ppid_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return vec![];
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let status_path = entry.path().join("status");
        let Ok(content) = std::fs::read_to_string(status_path) else {
            continue;
        };
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                if let Ok(ppid) = rest.trim().parse::<u32>() {
                    ppid_map.insert(pid, ppid);
                    break;
                }
            }
        }
    }

    // BFS: find all descendants of any known PID.
    let mut new_pids = Vec::new();
    let mut visited: HashSet<u32> = known.clone();
    let mut queue: VecDeque<u32> = known.iter().copied().collect();

    while let Some(ancestor) = queue.pop_front() {
        for (&pid, &ppid) in &ppid_map {
            if ppid == ancestor && visited.insert(pid) {
                new_pids.push(pid);
                queue.push_back(pid);
            }
        }
    }

    new_pids
}

/// Attach a named tracepoint program from the loaded eBPF object.
fn attach_tracepoint(
    bpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    tracepoint_name: &str,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .with_context(|| format!("program '{prog_name}' not found in eBPF object"))?
        .try_into()
        .with_context(|| format!("'{prog_name}' is not a TracePoint program"))?;

    program
        .load()
        .with_context(|| format!("failed to load '{prog_name}'"))?;
    program
        .attach(category, tracepoint_name)
        .with_context(|| {
            format!("failed to attach '{prog_name}' to {category}/{tracepoint_name}")
        })?;

    log::debug!("Attached {category}/{tracepoint_name}.");
    Ok(())
}

/// Drain all available items from a `RingBuf` and forward `(path, opener_pid)`
/// tuples to `tx`.  Non-blocking: returns immediately when the buffer is empty.
fn drain_ring_buf(
    rb: &mut RingBuf<aya::maps::MapData>,
    tx: &tokio::sync::mpsc::UnboundedSender<(String, u32)>,
) {
    while let Some(item) = rb.next() {
        let len = std::mem::size_of::<FileEvent>();
        if item.len() < len {
            continue;
        }
        // Safety: We verified the slice is at least as large as FileEvent.
        // The eBPF program always writes a complete FileEvent.
        let event: &FileEvent = unsafe { &*(item.as_ptr() as *const FileEvent) };

        let filename_len = (event.filename_len as usize).min(ebpf_component_tracer_common::MAX_FILENAME_LEN);
        let raw = match std::str::from_utf8(&event.filename[..filename_len]) {
            Ok(s) => s.trim_end_matches('\0').to_string(),
            Err(_) => String::from_utf8_lossy(&event.filename[..filename_len])
                .trim_end_matches('\0')
                .to_string(),
        };

        if !raw.is_empty() {
            let _ = tx.send((raw, event.pid));
        }
    }
}

/// Convert a path + its `ComponentIdentity` into the output `Component` struct.
fn resolve_component(
    path_str: &str,
    path: &Path,
    engine: &IdentityEngine,
    _project_dir: &Path,
) -> Component {
    match engine.identify(path) {
        ComponentIdentity::SystemPackage { name, version } => Component {
            name,
            version: Some(version),
            hash: None,
            path: path_str.to_string(),
            component_type: "system_package".to_string(),
        },
        ComponentIdentity::LocalFile { hash } => {
            // Use the file stem as the component name.
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                // Strip leading "lib" prefix for readability.
                .map(|s| s.strip_prefix("lib").unwrap_or(s))
                .unwrap_or("unknown")
                .to_string();

            Component {
                name,
                version: None,
                hash: Some(hash),
                path: path_str.to_string(),
                component_type: "local_file".to_string(),
            }
        }
        ComponentIdentity::UnknownSystem => {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            Component {
                name,
                version: None,
                hash: None,
                path: path_str.to_string(),
                component_type: "system_unknown".to_string(),
            }
        }
    }
}

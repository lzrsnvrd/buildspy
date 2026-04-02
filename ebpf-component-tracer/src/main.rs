//! ebpf-component-tracer – user-space entry point.
//!
//! Usage:
//!   sudo ebpf-tracer [OPTIONS] -- <build command>
//!
//! Example:
//!   sudo ebpf-tracer -- cmake --build ./build
//!   sudo ebpf-tracer --output deps.json -- meson compile -C build

mod cyclonedx;
mod ebpf;
mod ecosystem;
mod identity;
mod proc_watcher;
mod report;
mod resolver;

use std::{
    collections::HashMap,
    env,
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use aya::Ebpf;
use aya_log::EbpfLogger;
use chrono::Utc;
use clap::Parser;
use identity::IdentityEngine;
use report::{Component, Report};

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

    /// Include dev/test dependencies from lock files (default: prod-only).
    #[arg(long)]
    ecosystem_dev: bool,

    /// The build command and its arguments (everything after `--`).
    #[arg(last = true, required = true)]
    build_command: Vec<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    let project_dir = cli
        .project_dir
        .clone()
        .unwrap_or_else(|| env::current_dir().expect("failed to get cwd"));

    let build_command_str = cli.build_command.join(" ");
    log::info!("Build command : {}", build_command_str);
    log::info!("Project dir   : {}", project_dir.display());
    log::info!("Output        : {}", cli.output.display());

    // ------------------------------------------------------------------
    // Load eBPF and start event collection.
    // ------------------------------------------------------------------
    let mut bpf = load_ebpf(cli.verbose)?;
    let ring_buf = ebpf::take_ring_buf(&mut bpf)?;

    let (path_tx, mut path_rx) = tokio::sync::mpsc::unbounded_channel::<(String, u32)>();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let event_task = ebpf::spawn_event_task(ring_buf, path_tx, stop_rx);

    // ------------------------------------------------------------------
    // Spawn build command with race-free PID tracking.
    // See inline comments in `spawn_build` for the three-step strategy.
    // ------------------------------------------------------------------
    let (mut child, child_pid) = spawn_build(&mut bpf, &cli, &project_dir)?;

    // ------------------------------------------------------------------
    // Run the build: watch for new child PIDs and wait for completion.
    // ------------------------------------------------------------------
    let (new_pid_tx, mut new_pid_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
    let mut pid_to_comm: HashMap<u32, String> = HashMap::new();
    let mut pid_to_cwd: HashMap<u32, PathBuf> = HashMap::new();

    tokio::spawn(proc_watcher::watch_children(child_pid, new_pid_tx));

    let exit_status = loop {
        tokio::select! {
            Some(pid) = new_pid_rx.recv() => {
                if let Err(e) = ebpf::pid_filter_insert(&mut bpf, pid) {
                    log::warn!("failed to track PID {pid}: {e}");
                }
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_default();
                let comm = comm.trim().to_string();
                log::debug!("proc-watcher: tracking PID {} ({})", pid, comm);
                pid_to_comm.insert(pid, comm);
                if let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd")) {
                    pid_to_cwd.insert(pid, cwd);
                }
            }
            result = child.wait() => {
                break result.context("failed to wait for child")?;
            }
        }
    };

    log::info!(
        "Build finished (exit code: {}).",
        exit_status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".to_string())
    );

    // Give the ring buffer a moment to flush, then shut down the event task.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = stop_tx.send(());
    let _ = event_task.await;

    // ------------------------------------------------------------------
    // Post-build analysis: resolve paths → components + ecosystem scan.
    // ------------------------------------------------------------------
    let engine = IdentityEngine::new();
    let mut components =
        report::collect_components(&mut path_rx, &pid_to_comm, &pid_to_cwd, &project_dir, &engine);

    let eco_components = ecosystem::detect(&project_dir, &pid_to_comm, cli.ecosystem_dev);
    log::info!("Ecosystem components: {}.", eco_components.len());
    for c in eco_components {
        let key = format!("eco:{}:{}@{}", c.ecosystem, c.name, c.version);
        components.entry(key).or_insert(Component {
            name: c.name,
            version: Some(c.version),
            arch: None,
            src_name: None,
            hash: None,
            purl: Some(c.purl),
            path: format!("ecosystem:{}", c.ecosystem),
            component_type: "ecosystem_package".to_string(),
        });
    }

    // ------------------------------------------------------------------
    // Build, sort and write the reports.
    // ------------------------------------------------------------------
    let mut component_list: Vec<Component> = components.into_values().collect();
    component_list.sort_by(|a, b| {
        a.component_type.cmp(&b.component_type).then(a.name.cmp(&b.name))
    });

    let report = Report {
        timestamp: Utc::now().to_rfc3339(),
        build_command: build_command_str,
        project_dir: project_dir.to_string_lossy().to_string(),
        exit_code: exit_status.code(),
        components: component_list,
    };

    let json = serde_json::to_string_pretty(&report).context("failed to serialise report")?;
    std::fs::write(&cli.output, &json)
        .with_context(|| format!("failed to write {}", cli.output.display()))?;
    log::info!("Report written to {} ({} components).", cli.output.display(), report.components.len());

    let distro = cyclonedx::detect_distro();
    let bom = cyclonedx::build_bom(
        &cyclonedx::ReportRef {
            timestamp: &report.timestamp,
            project_dir: &report.project_dir,
            components: &report.components,
        },
        &distro,
    );
    let cdx_path = cyclonedx::cdx_output_path(&cli.output);
    let cdx_json = serde_json::to_string_pretty(&bom).context("failed to serialise CycloneDX BOM")?;
    std::fs::write(&cdx_path, &cdx_json)
        .with_context(|| format!("failed to write {}", cdx_path.display()))?;
    log::info!("CycloneDX BOM written to {}.", cdx_path.display());

    println!("{}", json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load the eBPF object, optionally enable the kernel-side logger, and attach
/// the three required tracepoints.
fn load_ebpf(verbose: bool) -> Result<Ebpf> {
    let mut bpf = Ebpf::load(EBPF_BYTECODE)
        .context("failed to load eBPF bytecode – are you running as root?")?;

    if verbose {
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            log::warn!("eBPF logger unavailable: {e}");
        }
    }

    ebpf::attach_tracepoint(&mut bpf, "sched_process_fork", "sched", "sched_process_fork")?;
    ebpf::attach_tracepoint(&mut bpf, "sched_process_exit", "sched", "sched_process_exit")?;
    ebpf::attach_tracepoint(&mut bpf, "sys_enter_openat", "syscalls", "sys_enter_openat")?;
    log::info!("eBPF tracepoints attached.");

    Ok(bpf)
}

/// Spawn the build command with race-free PID filter setup.
///
/// Strategy:
///   1. Insert OUR OWN TGID into the filter BEFORE the fork so that
///      `sched_process_fork` fires correctly even when tokio uses a worker
///      thread to do the fork.
///   2. After spawn, also insert `child_pid` explicitly as a safety net for
///      the tiny window before `sched_process_fork` fires.
///   3. Remove our own TGID so we don't track our own file opens.
fn spawn_build(
    bpf: &mut Ebpf,
    cli: &Cli,
    project_dir: &std::path::Path,
) -> Result<(tokio::process::Child, u32)> {
    let our_tgid = std::process::id();
    ebpf::pid_filter_insert(bpf, our_tgid)?;

    let child = tokio::process::Command::new(&cli.build_command[0])
        .args(&cli.build_command[1..])
        .current_dir(project_dir)
        .spawn()
        .with_context(|| format!("failed to spawn '{}'", cli.build_command[0]))?;

    let child_pid = child
        .id()
        .ok_or_else(|| anyhow!("could not retrieve child PID"))?;
    log::info!("Build started (PID {}).", child_pid);

    // Inserting child_pid is idempotent; covers the rare race before the fork tracepoint fires.
    ebpf::pid_filter_insert(bpf, child_pid)?;
    ebpf::pid_filter_remove(bpf, our_tgid);

    Ok((child, child_pid))
}

//! buildspy – user-space entry point.
//!
//! Usage:
//!   sudo buildspy [OPTIONS] -- <build command>
//!
//! Examples:
//!   sudo buildspy -- cmake --build ./build
//!   sudo buildspy --backend ptrace -- make -j$(nproc)
//!   sudo buildspy --output deps.json -- meson compile -C build

mod analysis;
mod backends;
mod ecosystem;
mod proc_info;

use std::{collections::HashMap, env, path::PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;

use analysis::{
    cyclonedx,
    identity::IdentityEngine,
    report::{Component, ComponentType, Report},
};
use backends::{Backend, TracingSession};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "SCA tracer – records every library/header opened during a build"
)]
struct Cli {
    /// Path for the JSON report (default: report.json).
    #[arg(short, long, default_value = "report.json")]
    output: PathBuf,

    /// Project root used to distinguish local from system files.
    /// Defaults to the current working directory.
    #[arg(short, long)]
    project_dir: Option<PathBuf>,

    /// Enable verbose log output.
    #[arg(short, long)]
    verbose: bool,

    /// Include dev/test dependencies from lock files (default: prod-only).
    #[arg(long)]
    ecosystem_dev: bool,

    /// Include file opens from build orchestrators (cmake, make, ninja, …).
    /// By default these are filtered out because they are not project dependencies.
    /// Use this flag to compare against tools that include toolchain/orchestrator files.
    #[arg(long)]
    include_orchestrators: bool,

    /// Tracing backend to use.
    /// "ebpf"  – eBPF ring-buffer (requires Linux ≥ 4.4 + CAP_BPF).
    /// "ptrace" – ptrace syscall interception (any kernel, CAP_SYS_PTRACE).
    /// "auto"  – try eBPF first, fall back to ptrace (default).
    #[arg(long, default_value = "auto")]
    backend: String,

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
    // Start the tracing session.
    // ------------------------------------------------------------------
    let backend = Backend::from_str(&cli.backend);
    let mut session: TracingSession =
        backends::start_session(backend, &cli.build_command, &project_dir, cli.verbose)?;

    // ------------------------------------------------------------------
    // Run the build: collect PID metadata and wait for completion.
    // ------------------------------------------------------------------
    let mut pid_to_comm: HashMap<u32, String> = HashMap::new();
    let mut pid_to_cwd: HashMap<u32, PathBuf> = HashMap::new();

    let exit_code = loop {
        tokio::select! {
            Some(pid) = session.new_pid_rx.recv() => {
                let comm = proc_info::read_comm(pid);
                log::debug!("Tracking PID {} ({})", pid, comm);
                pid_to_comm.insert(pid, comm);
                if let Some(cwd) = proc_info::read_cwd(pid) {
                    pid_to_cwd.insert(pid, cwd);
                }
            }
            result = &mut session.exit_rx => {
                // exit_rx resolves only after the backend has flushed all events.
                let code = result.ok().flatten();
                log::info!(
                    "Build finished (exit code: {}).",
                    code.map(|c| c.to_string()).unwrap_or_else(|| "signal".to_string())
                );
                break code;
            }
            _ = tokio::signal::ctrl_c() => {
                log::warn!("Interrupted – shutting down build and generating partial report.");
                if let Some(shutdown_fn) = session.shutdown.take() {
                    shutdown_fn();
                }
                // Wait for the ptrace thread to finish draining and send exit_rx.
                let code = (&mut session.exit_rx).await.ok().flatten();
                break code;
            }
        }
    };

    while let Ok(pid) = session.new_pid_rx.try_recv() {
        pid_to_comm.insert(pid, proc_info::read_comm(pid));
        if let Some(cwd) = proc_info::read_cwd(pid) {
            pid_to_cwd.insert(pid, cwd);
        }
    }

    // ------------------------------------------------------------------
    // Post-build analysis: resolve paths → components + ecosystem scan.
    // ------------------------------------------------------------------
    let engine = IdentityEngine::new(&project_dir);
    let mut components = analysis::report::collect_components(
        &mut session.path_rx,
        &pid_to_comm,
        &pid_to_cwd,
        &project_dir,
        &engine,
        cli.include_orchestrators,
    );

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
            vcs_url: None,
            path: format!("ecosystem:{}", c.ecosystem),
            component_type: ComponentType::EcosystemPackage,
        });
    }

    // ------------------------------------------------------------------
    // Build, sort and write the reports.
    // ------------------------------------------------------------------
    let mut component_list: Vec<Component> = components.into_values().collect();
    component_list.sort_by(|a, b| a.component_type.cmp(&b.component_type).then(a.name.cmp(&b.name)));

    let report = Report {
        timestamp: Utc::now().to_rfc3339(),
        build_command: build_command_str,
        project_dir: project_dir.to_string_lossy().to_string(),
        exit_code,
        components: component_list,
    };

    let json = serde_json::to_string_pretty(&report).context("failed to serialise report")?;
    std::fs::write(&cli.output, &json)
        .with_context(|| format!("failed to write {}", cli.output.display()))?;
    log::info!(
        "Report written to {} ({} components).",
        cli.output.display(),
        report.components.len()
    );

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
    let cdx_json =
        serde_json::to_string_pretty(&bom).context("failed to serialise CycloneDX BOM")?;
    std::fs::write(&cdx_path, &cdx_json)
        .with_context(|| format!("failed to write {}", cdx_path.display()))?;
    log::info!("CycloneDX BOM written to {}.", cdx_path.display());

    println!("{}", json);
    Ok(())
}

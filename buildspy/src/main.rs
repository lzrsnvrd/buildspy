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
mod reachability;

use std::{collections::HashMap, env, path::{Path, PathBuf}};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;

use analysis::{
    cyclonedx,
    identity::IdentityEngine,
    report::{Component, ComponentType, Report},
};
use backends::{Backend, TracingSession};
use reachability::{
    BitcodeCapture,
    EntryPoints,
    input::load_targets,
    ReachabilityAnalyzer,
};

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

    /// Include what the build tools open for themselves: file opens from build
    /// orchestrators (cmake, make, ninja, …) and the toolchain's own runtime
    /// libraries (cc1plus → libisl/libmpfr, ld → libbfd, cp → libselinux, GCC's
    /// LTO plugin, …). By default these are filtered out because they are not
    /// project dependencies.
    /// Use this flag to compare against tools that include toolchain/orchestrator files.
    #[arg(long)]
    include_orchestrators: bool,

    /// Tracing backend to use.
    /// "ebpf"  – eBPF ring-buffer (requires Linux ≥ 4.4 + CAP_BPF).
    /// "ptrace" – ptrace syscall interception (any kernel, CAP_SYS_PTRACE).
    /// "auto"  – try eBPF first, fall back to ptrace (default).
    #[arg(long, default_value = "auto")]
    backend: String,

    /// Path to a targets.json file listing CVE symbols to check for reachability.
    /// Format: [{"cve": "CVE-…", "symbol": "inflate", "library": "zlib"}]
    #[arg(long, value_name = "TARGETS_JSON")]
    reachability: Option<PathBuf>,

    /// Binary to analyse for reachability: an ELF executable/shared object, or
    /// an LLVM bitcode (`.bc`) file (format auto-detected). May be repeated to
    /// combine artifacts. Required when --reachability is specified.
    #[arg(long = "reachability-binary", value_name = "PATH")]
    reachability_binary: Vec<PathBuf>,

    /// Resolve C++ virtual calls when analysing LLVM bitcode reachability by
    /// running `wholeprogramdevirt` before the call graph is built. Requires
    /// bitcode compiled with `-fwhole-program-vtables`; ignored for ELF inputs.
    #[arg(long)]
    reachability_vtables: bool,

    /// Follow shared libraries when analysing reachability (Level 2): walk the
    /// transitive DT_NEEDED closure of each ELF artifact and merge every `.so`'s
    /// partial call graph, so chains crossing the `.so` boundary become visible.
    /// Off by default; disassembling large libraries adds runtime cost.
    #[arg(long)]
    reachability_follow_shared: bool,

    /// Use SVF points-to analysis (the `wpa` tool) for LLVM bitcode reachability
    /// so calls through function pointers / C++ objects are resolved instead of
    /// reported as indirect. Requires SVF installed (or BUILDSPY_WPA); warns and
    /// falls back to direct-call analysis if `wpa` is not found.
    #[arg(long)]
    reachability_points_to: bool,

    /// Capture whole-program LLVM bitcode from the traced build: inject gllvm's
    /// `gclang`/`gclang++` as CC/CXX, then recover one `.bc` per
    /// --reachability-binary with `get-bc` and analyse that instead of the ELF.
    /// Needs gllvm installed (or BUILDSPY_GCLANG / BUILDSPY_GET_BC); falls back
    /// to ELF analysis if anything is missing. Roughly doubles compile time.
    #[arg(long)]
    reachability_capture_bitcode: bool,

    /// The build command and its arguments (everything after `--`).
    #[arg(last = true, required = true)]
    build_command: Vec<String>,
}

// ---------------------------------------------------------------------------
// Bitcode capture
// ---------------------------------------------------------------------------

/// Preflight `--reachability-capture-bitcode`.
///
/// Every failure degrades to ELF-level analysis rather than aborting: the build
/// is the user's primary artifact, and a missing analysis tool is no reason to
/// refuse to run it.
fn prepare_capture(cli: &Cli) -> Option<BitcodeCapture> {
    if !cli.reachability_capture_bitcode {
        return None;
    }
    if cli.reachability.is_none() || cli.reachability_binary.is_empty() {
        log::warn!(
            "--reachability-capture-bitcode has no effect without --reachability and \
             --reachability-binary; skipping capture (the build is not slowed down)."
        );
        return None;
    }

    match BitcodeCapture::prepare(cli.reachability_vtables, cli.verbose) {
        Ok(capture) => match capture.init_store() {
            Ok(()) => {
                log::info!(
                    "Bitcode capture: injecting gllvm as CC/CXX (compile time roughly doubles)."
                );
                Some(capture)
            }
            Err(e) => {
                log::warn!("Bitcode capture disabled ({e}); falling back to ELF analysis.");
                None
            }
        },
        Err(e) => {
            log::warn!("Bitcode capture disabled: {e}. Falling back to ELF analysis.");
            None
        }
    }
}

/// Swap each artifact for the whole-program bitcode recovered from it, keeping
/// the original path when capture is off or recovery fails.
fn recover_bitcode(capture: Option<&BitcodeCapture>, binaries: &[PathBuf]) -> Vec<PathBuf> {
    let Some(capture) = capture else {
        return binaries.to_vec();
    };
    binaries
        .iter()
        .map(|binary| match capture.recover(binary) {
            Ok(bc) => {
                log::info!(
                    "Bitcode capture: recovered whole-program bitcode for {} → {}.",
                    binary.display(),
                    bc.display()
                );
                bc
            }
            Err(e) => {
                log::warn!(
                    "Bitcode capture: {e}. Falling back to ELF analysis of {}.",
                    binary.display()
                );
                binary.clone()
            }
        })
        .collect()
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
    // Bitcode capture preflight (must precede the build: it works by
    // substituting the compiler in the build's environment).
    // ------------------------------------------------------------------
    let capture = prepare_capture(&cli);
    let build_env = capture.as_ref().map(BitcodeCapture::build_env).unwrap_or_default();
    for (k, v) in &build_env {
        log::debug!("Build env    : {k}={v}");
    }

    // ------------------------------------------------------------------
    // Start the tracing session.
    // ------------------------------------------------------------------
    let backend = Backend::from_str(&cli.backend);
    let mut session: TracingSession = backends::start_session(
        backend,
        &cli.build_command,
        &project_dir,
        cli.verbose,
        &build_env,
    )?;

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
    // Reachability analysis (optional).
    // ------------------------------------------------------------------
    let reachability_results = if let Some(targets_path) = &cli.reachability {
        match load_targets(targets_path) {
            Err(e) => {
                log::error!("Failed to load reachability targets: {e}");
                None
            }
            Ok(_) if cli.reachability_binary.is_empty() => {
                log::warn!(
                    "--reachability specified but no --reachability-binary given; skipping analysis."
                );
                None
            }
            Ok(targets) => {
                // With capture on, each binary is replaced by the whole-program
                // bitcode recovered from it; the originals still seed the
                // DT_NEEDED walk, which bitcode cannot.
                let recovered = recover_bitcode(capture.as_ref(), &cli.reachability_binary);
                let artifacts: Vec<&Path> = recovered.iter().map(PathBuf::as_path).collect();
                let analyzer = ReachabilityAnalyzer::new()
                    .with_devirtualize(cli.reachability_vtables)
                    .with_follow_shared(cli.reachability_follow_shared)
                    .with_points_to(cli.reachability_points_to)
                    .with_shared_roots(cli.reachability_binary.clone());
                let results = analyzer.analyze(&artifacts, &targets, EntryPoints::Main);
                log::info!(
                    "Reachability: analysed {} targets against {} artifact(s).",
                    results.len(),
                    artifacts.len()
                );
                Some(results)
            }
        }
    } else {
        None
    };

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
        reachability: reachability_results,
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

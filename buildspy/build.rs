//! Build script: compiles the eBPF crate via `aya-build` and places the
//! resulting bytecode in `OUT_DIR` so the main binary can embed it with
//! `aya::include_bytes_aligned!`.
//!
//! Key differences from a plain `cargo build`:
//!  * Uses the nightly toolchain automatically.
//!  * Passes `-Clink-arg=--btf` so the linker emits BTF sections required by
//!    Aya's ELF parser.
//!  * Strips RUSTC / RUSTC_WORKSPACE_WRAPPER env vars that the outer stable
//!    cargo injects, avoiding rustc version mismatches.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ebpf_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../buildspy-ebpf");

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "buildspy-ebpf",
            root_dir: ebpf_dir,
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Nightly,
    )?;

    Ok(())
}

# CLAUDE.md

**build_analyzer** is a Software Composition Analysis (SCA) tool that traces every library,
header, and source file opened during a build. It intercepts `openat` syscalls and produces
`report.json` (custom schema) and `bom.cdx.json` (CycloneDX 1.6 SBOM).

Full documentation: [docs/architecture.md](docs/architecture.md) · [docs/design-decisions.md](docs/design-decisions.md)

---

## Build & run

```bash
# Prerequisites (one-time)
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# Build
cargo build -p ebpf-component-tracer
cargo build --release -p ebpf-component-tracer

# Run (CAP_BPF for eBPF, CAP_SYS_PTRACE for ptrace)
sudo ./target/debug/ebpf-component-tracer -- cmake --build ./build
sudo ./target/debug/ebpf-component-tracer --backend ptrace -- make -j$(nproc)
```

## Tests

```bash
cargo test -p ebpf-component-tracer
```

Tests live in `ebpf-component-tracer/src/analysis/resolver.rs`.

---

## Workspace

| Crate | Role |
|---|---|
| `ebpf-component-tracer` | User-space binary |
| `ebpf-component-tracer-common` | Shared `FileEvent` struct (`no_std` + `repr(C)`) |
| `ebpf-component-tracer-ebpf` | Kernel eBPF program; compiled by `build.rs` via nightly |

The eBPF crate is in `[workspace.members]` for aya-build but excluded from
`default-members` to avoid compiling it for the host target.

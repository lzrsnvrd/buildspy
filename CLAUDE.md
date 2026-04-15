# CLAUDE.md

**buildspy** is a Software Composition Analysis (SCA) tool that traces every library,
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
cargo build -p buildspy
cargo build --release -p buildspy

# Run (CAP_BPF for eBPF, CAP_SYS_PTRACE for ptrace)
sudo ./target/debug/buildspy -- cmake --build ./build
sudo ./target/debug/buildspy --backend ptrace -- make -j$(nproc)
```

## Tests

```bash
cargo test -p buildspy
```

Tests live in `buildspy/src/analysis/resolver.rs`.

---

## Workspace

| Crate | Role |
|---|---|
| `buildspy` | User-space binary |
| `buildspy-common` | Shared `FileEvent` struct (`no_std` + `repr(C)`) |
| `buildspy-ebpf` | Kernel eBPF program; compiled by `build.rs` via nightly |

The eBPF crate is in `[workspace.members]` for aya-build but excluded from
`default-members` to avoid compiling it for the host target.

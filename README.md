# build_analyzer

A Software Composition Analysis (SCA) tool that traces every library, header, and
source file opened during a build process. Intercepts `openat` syscalls at the kernel
level and produces a dependency report and a CycloneDX 1.6 SBOM.

## Features

- **Two tracing backends**: eBPF (low overhead, requires `CAP_BPF`) or ptrace (any kernel, requires `CAP_SYS_PTRACE`). Auto-selects eBPF and falls back to ptrace.
- **System package resolution**: maps file paths to dpkg / pacman / rpm package names and versions using an in-memory index (no subprocess per file).
- **Ecosystem lock-file scanning**: reads `Cargo.lock`, `package-lock.json`, `yarn.lock`, `poetry.lock`, `requirements.txt`, `go.mod`, `go.sum` concurrently.
- **Two output formats**: `report.json` (custom schema) and `bom.cdx.json` (CycloneDX 1.6).

## Requirements

- Linux kernel ≥ 4.4 (for eBPF backend); any Linux kernel works with `--backend ptrace`
- x86\_64 (ptrace backend is x86\_64-only; eBPF works on any supported arch)
- Rust stable + nightly toolchain (nightly compiles the eBPF kernel program)
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker)

## Installation

```bash
# Install toolchain dependencies
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# Build
cargo build --release -p ebpf-component-tracer
```

The binary is at `target/release/ebpf-component-tracer`.

## Usage

```bash
# eBPF backend (default; requires root or CAP_BPF)
sudo ./ebpf-component-tracer -- cmake --build ./build

# ptrace backend (slower but works without CAP_BPF)
sudo ./ebpf-component-tracer --backend ptrace -- make -j$(nproc)

# Custom output path
sudo ./ebpf-component-tracer --output deps.json -- ninja -C build

# Include dev dependencies from lock files
sudo ./ebpf-component-tracer --ecosystem-dev -- cargo build
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--output` / `-o` | `report.json` | Path for the JSON report |
| `--project-dir` / `-p` | current directory | Root for distinguishing local vs. system files |
| `--backend` | `auto` | `auto` \| `ebpf` \| `ptrace` |
| `--ecosystem-dev` | off | Include dev/test dependencies from lock files |
| `--verbose` / `-v` | off | Debug log output |

## Output

Two files are written after the build completes.

**`report.json`**
```json
{
  "timestamp": "2025-01-01T00:00:00Z",
  "build_command": "cmake --build ./build",
  "exit_code": 0,
  "components": [
    {
      "name": "openssl",
      "version": "3.0.2-0ubuntu1.18",
      "path": "/usr/lib/x86_64-linux-gnu/libssl.so.3",
      "type": "system_package",
      "purl": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04"
    }
  ]
}
```

**`report.cdx.json`** — CycloneDX 1.6 BOM, consumable by Grype, Trivy, OSV-scanner, etc.

### Component types

| `type` | Meaning |
|---|---|
| `system_package` | Identified by dpkg / pacman / rpm |
| `local_file` | Local build artifact; identified by SHA-256 |
| `ecosystem_package` | From a lock file (Cargo, npm, pip, Go modules) |
| `system_unknown` | On a system path but not in the package DB |

## License

Apache 2.0 — see [LICENSE](LICENSE).

# buildspy

A Software Composition Analysis (SCA) tool that traces every library, header, and
source file opened during a build process. Intercepts `openat` syscalls at the kernel
level and produces a dependency report and a CycloneDX 1.6 SBOM.

## Features

- **Two tracing backends**: eBPF (low overhead, requires `CAP_BPF`) or ptrace (any kernel, requires `CAP_SYS_PTRACE`). Auto-selects eBPF and falls back to ptrace.
- **System package resolution**: maps file paths to dpkg / pacman / rpm package names and versions using an in-memory index (no subprocess per file).
- **Ecosystem lock-file scanning**: reads `Cargo.lock`, `package-lock.json`, `yarn.lock`, `poetry.lock`, `requirements.txt`, `go.mod`, `go.sum` concurrently.
- **Two output formats**: `report.json` (custom schema) and `bom.cdx.json` (CycloneDX 1.6).
- **Reachability analysis** (optional): given a CVE's vulnerable function, decides whether it is reachable from `main` — with an honest `true` / `false` / `unknown` result. See [docs/reachability.md](docs/reachability.md).

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
cargo build --release -p buildspy
```

The binary is at `target/release/buildspy`.

## Usage

```bash
# eBPF backend (default; requires root or CAP_BPF)
sudo ./buildspy -- cmake --build ./build

# ptrace backend (slower but works without CAP_BPF)
sudo ./buildspy --backend ptrace -- make -j$(nproc)

# Custom output path
sudo ./buildspy --output deps.json -- ninja -C build

# Include dev dependencies from lock files
sudo ./buildspy --ecosystem-dev -- cargo build
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--output` / `-o` | `report.json` | Path for the JSON report |
| `--project-dir` / `-p` | current directory | Root for distinguishing local vs. system files |
| `--backend` | `auto` | `auto` \| `ebpf` \| `ptrace` |
| `--ecosystem-dev` | off | Include dev/test dependencies from lock files |
| `--include-orchestrators` | off | Include files opened by build orchestrators (cmake, make, ninja, …), normally filtered out |
| `--verbose` / `-v` | off | Debug log output |

Reachability analysis adds `--reachability`, `--reachability-binary`, and a few
refinement flags; see [docs/reachability.md](docs/reachability.md).

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

## Reachability analysis (optional)

An SBOM tells you a vulnerable library is *present*; it does not tell you whether
the vulnerable code is ever *callable*. Pass `--reachability` with a list of CVE
symbols and a build artifact to find out:

```bash
sudo ./buildspy \
  --reachability targets.json \
  --reachability-binary ./build/my_app \
  -- cmake --build ./build
```

```json
// targets.json
[
  { "cve": "CVE-2022-37434", "symbol": "inflate", "library": "zlib" }
]
```

Each target resolves to an honest `true` / `false` / `null` (undetermined), with
a concrete call `chain` when reachable, added to `report.json`:

```json
{
  "reachability": [
    {
      "cve": "CVE-2022-37434",
      "symbol": "inflate",
      "reachable": true,
      "chain": ["main", "read_archive", "zlib_decompress", "inflate"]
    }
  ]
}
```

The artifact may be an ELF binary or LLVM bitcode (auto-detected), and optional
flags trade extra tooling for precision — following shared libraries, resolving
C++ virtual calls, or resolving function pointers with SVF points-to analysis.

The highest-precision backends need whole-program LLVM bitcode, which
`--reachability-capture-bitcode` produces from your **unmodified build**: buildspy
substitutes [gllvm](https://github.com/SRI-CSL/gllvm)'s compiler wrappers into the
traced build's environment and reassembles the bitcode afterwards. No Makefile or
CMakeLists edits; if anything is missing it warns and falls back to ELF analysis.

See **[docs/reachability.md](docs/reachability.md)** for the full guide.

## License

Apache 2.0 — see [LICENSE](LICENSE).

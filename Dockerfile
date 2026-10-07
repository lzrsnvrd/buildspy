# syntax=docker/dockerfile:1
#
# Builds the `buildspy` binary and packages it into a runtime image with a
# common C/C++ toolchain, so a build can be traced via `docker run` without
# installing Rust, nightly, bpf-linker or LLVM on the host.
#
# Usage:
#   docker build -t buildspy .
#   docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
#       -v "$PWD":/workspace -w /workspace \
#       buildspy --backend ptrace -- cmake --build build
#
# See the "Docker" section in README.md for backend/capability details.

########################################
# 1. Builder: stable Rust (buildspy) + nightly Rust (buildspy-ebpf) + bpf-linker
########################################
FROM rust:1-bookworm AS builder

# bpf-linker links against LLVM's static libs at build time (not needed at
# runtime: the eBPF bytecode it produces is embedded into the buildspy binary
# by build.rs). Debian bookworm's default repo only has LLVM 14, so pull a
# newer LLVM from the official apt.llvm.org repo.
#
# bpf-linker's LLVM requirement moves with its own release, and the latest
# release on crates.io can need an LLVM newer than what apt.llvm.org has
# packaged yet (bpf-linker 0.11.x needs LLVM 23, unavailable as of this
# writing). Pin both to a combination that is known to link cleanly.
ARG LLVM_VERSION=19
ARG BPF_LINKER_VERSION=0.10.2

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates lsb-release software-properties-common \
        build-essential \
    && curl -fsSL https://apt.llvm.org/llvm.sh -o /tmp/llvm.sh \
    && chmod +x /tmp/llvm.sh \
    && /tmp/llvm.sh "$LLVM_VERSION" \
    && apt-get install -y --no-install-recommends \
        "llvm-$LLVM_VERSION-dev" "libpolly-$LLVM_VERSION-dev" \
    && rm -rf /var/lib/apt/lists/* /tmp/llvm.sh

# apt.llvm.org only installs version-suffixed binaries (llvm-config-19, not
# llvm-config); point bpf-linker's build script at it directly.
ENV LLVM_PREFIX=/usr/lib/llvm-${LLVM_VERSION}

RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker --version "$BPF_LINKER_VERSION"

WORKDIR /src
COPY . .

RUN cargo build --release -p buildspy

########################################
# 2. Runtime: buildspy binary + a default C/C++ build toolchain
########################################
FROM debian:bookworm-slim AS runtime

# build-essential/cmake/ninja/git/pkg-config cover the project's own examples
# (`cmake --build`, `make -j`). Tracing another ecosystem (cargo, npm, go, ...)
# needs that ecosystem's toolchain too — extend this image with `FROM buildspy`
# and install it, rather than bundling every ecosystem here by default.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/buildspy /usr/local/bin/buildspy

WORKDIR /workspace
ENTRYPOINT ["buildspy"]
CMD ["--help"]

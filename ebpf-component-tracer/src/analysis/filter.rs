//! Build-orchestrator filter.
//!
//! Identifies processes whose file opens should be excluded from the SCA
//! report.  Build orchestrators (make, cmake, ninja, …) open their own
//! runtime libraries which are not dependencies of the project being built.
//! Compilers and linkers are intentionally excluded from this list.

/// Build-orchestration tools whose file opens should NOT be reported.
pub const BUILD_ORCHESTRATORS: &[&str] = &[
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
    // Shells used as build glue
    "sh", "bash", "dash", "zsh", "fish",
    // Python / Perl (used by meson, autotools)
    "python3", "python", "perl",
];

/// Returns `true` if the process `comm` belongs to a build orchestrator.
pub fn is_build_orchestrator(comm: &str) -> bool {
    // Strip version suffixes: "python3.11" → "python3", "bash5" → "bash"
    let base = comm
        .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .trim_end_matches('-');
    BUILD_ORCHESTRATORS.contains(&comm) || BUILD_ORCHESTRATORS.contains(&base)
}

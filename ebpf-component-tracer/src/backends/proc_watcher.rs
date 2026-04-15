//! Build-orchestrator list and filtering helper.

/// Build-orchestration tools whose file opens should NOT be reported as
/// project dependencies.  These tools open their own runtime libraries
/// (cmake → libjsoncpp, make → libc, ninja → libc++, …) which have nothing
/// to do with the project being built.
///
/// Compilers, linkers, and assemblers are intentionally NOT listed here —
/// the headers and libraries they open ARE the project's dependencies.
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
    // Shells used as build glue (sh/bash open their own libc, not project libs)
    "sh", "bash", "dash", "zsh", "fish",
    // Python / Perl (used by meson, autotools)
    "python3", "python", "perl",
];

/// Returns true if the process `comm` name belongs to a build orchestrator
/// whose file opens should be filtered out.
pub fn is_build_orchestrator(comm: &str) -> bool {
    // Strip version suffixes: "python3.11" → "python3", "bash5" → "bash"
    let base = comm
        .trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .trim_end_matches('-');
    BUILD_ORCHESTRATORS.contains(&comm) || BUILD_ORCHESTRATORS.contains(&base)
}

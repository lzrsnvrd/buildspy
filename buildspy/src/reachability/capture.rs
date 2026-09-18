//! Whole-program bitcode capture — see `docs/bitcode-capture.md`.
//!
//! [`LlvmExtractor`](super::llvm) and [`SvfExtractor`](super::svf) are far more
//! precise than the ELF backend, but they need whole-program LLVM bitcode, which
//! normally means re-running the build by hand with the right flags. This module
//! removes that step: buildspy substitutes the compiler for the traced build and
//! reassembles the bitcode afterwards, so the user edits nothing.
//!
//! The compiler side is delegated wholesale to [gllvm] (`gclang` / `gclang++` /
//! `get-bc`), the Go rewrite of `wllvm`. Parsing compiler invocations (compile vs
//! link, `@response` files, `-x` overrides, multiple sources, assembly) is the
//! genuinely bug-prone part, and gllvm has hardened it for years. buildspy is the
//! orchestrator: it finds the tools, injects the environment, and hands the
//! recovered `.bc` to the existing extractors.
//!
//! ## How gllvm works (verified against gllvm 1.3.1)
//!
//! `gclang` compiles every TU **twice** — once normally, once with `-emit-llvm`
//! — writing the bitcode as a hidden sidecar next to the object (`foo.o` →
//! `.foo.o.bc`) and recording that sidecar's absolute path in a non-alloc
//! `.llvm_bc` ELF section on the object. The linker concatenates those sections,
//! so every binary and archive self-describes the bitcode it was built from.
//! `get-bc` reads the section back and `llvm-link`s the pieces into one module.
//!
//! ## Bitcode-only flags
//!
//! `LLVM_BITCODE_GENERATION_FLAGS` is appended to the **bitcode** compile only,
//! never to the real object. buildspy uses it for `-fno-inline` (and
//! `-fwhole-program-vtables` under `--reachability-vtables`): at `-O2` inlining
//! collapses `foo → bar` edges and can erase a fully-inlined function as a
//! symbol, which would yield a false `not_reachable`. The un-inlined graph is a
//! conservative *may-reach* superset — the safe direction.
//!
//! ## What buildspy does **not** control
//!
//! The `.bc` sidecars are written into the build tree by gllvm, not into a
//! buildspy-owned directory (`WLLVM_BC_STORE` only receives redundant *copies*,
//! consulted by `get-bc` when a sidecar has since been deleted). They are hidden
//! dotfiles beside each object and buildspy deliberately does not delete files
//! from the user's tree; `make clean` will usually miss them. buildspy owns only
//! the store and the recovered whole-program `.bc`, both under `/tmp` and both
//! removed when the run ends.
//!
//! [gllvm]: https://github.com/SRI-CSL/gllvm

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};

use super::util::{env_override, which, ScratchDir};

/// The ELF section `gclang` uses to record bitcode sidecar paths.
const BITCODE_SECTION: &str = ".llvm_bc";

/// LLVM major versions probed when a tool is only installed version-suffixed.
const LLVM_MAJORS: &[u32] = &[21, 20, 19, 18, 17, 16, 15, 14];

/// A prepared bitcode capture: located gllvm tools plus the scratch state for
/// one buildspy run.
pub struct BitcodeCapture {
    gclang: PathBuf,
    gclangxx: PathBuf,
    get_bc: PathBuf,
    /// `llvm-link` for `get-bc -l`, version-matched to the clang gclang will use.
    /// `None` leaves get-bc to find `llvm-link` itself.
    llvm_link: Option<PathBuf>,
    /// Passed as `LLVM_COMPILER_PATH` when a bare `clang` is not on `$PATH`.
    /// `None` means "leave gllvm's compiler choice alone".
    compiler_path: Option<PathBuf>,
    /// Flags appended to the bitcode compile only.
    bc_flags: Vec<String>,
    /// Bitcode store and recovered modules; removed on drop.
    scratch: ScratchDir,
    verbose: bool,
}

impl BitcodeCapture {
    /// Preflight: locate `gclang`, `gclang++`, `get-bc` and a matching
    /// `llvm-link`. Fails with an install hint; the caller is expected to warn
    /// and continue with ELF-level analysis rather than abort the build.
    pub fn prepare(devirtualize: bool, verbose: bool) -> Result<Self> {
        let gclang = find_gllvm_tool("gclang", Some("BUILDSPY_GCLANG")).ok_or_else(missing_gllvm)?;
        // gllvm installs all three side by side, so a sibling lookup is the most
        // reliable fallback when only `$PATH` or the override names one of them.
        let gclangxx = find_gllvm_tool("gclang++", Some("BUILDSPY_GCLANGXX"))
            .or_else(|| sibling(&gclang, "gclang++"))
            .ok_or_else(missing_gllvm)?;
        let get_bc = find_gllvm_tool("get-bc", Some("BUILDSPY_GET_BC"))
            .or_else(|| sibling(&gclang, "get-bc"))
            .ok_or_else(missing_gllvm)?;

        let (compiler_path, llvm_link) = resolve_llvm_toolchain();
        if llvm_link.is_none() {
            log::warn!(
                "bitcode capture: no `llvm-link` found; `get-bc` will have to locate one itself. \
                 Install the LLVM tools (e.g. `apt install llvm`) or set BUILDSPY_LLVM_LINK."
            );
        }

        // `-fno-inline` keeps the call graph a may-reach over-approximation; see
        // the module docs.
        //
        // The devirtualization set is all three flags or nothing, and each is
        // load-bearing (verified on clang 18 / LLVM 18):
        //   * `-fwhole-program-vtables` emits the vtable type metadata that
        //     LlvmExtractor's `wholeprogramdevirt` pass consumes;
        //   * `-flto` because clang refuses the above without it ("invalid
        //     argument '-fwhole-program-vtables' only allowed with '-flto'");
        //   * `-fvisibility=hidden` because otherwise clang emits
        //     `llvm.public.type.test` — "this hierarchy may be extended
        //     elsewhere" — which `wholeprogramdevirt` cannot act on, making the
        //     whole pass a silent no-op. Hidden visibility yields
        //     `llvm.type.test` plus `!vcall_visibility`, and the virtual call
        //     resolves to a real edge.
        //
        // All of these reach the bitcode compile only, never the real object,
        // and the bitcode is analysed rather than linked — so changing symbol
        // visibility there has no effect on the shipped binary or on which
        // functions the call graph contains.
        let mut bc_flags = vec!["-fno-inline".to_string()];
        if devirtualize {
            bc_flags.extend(
                ["-flto", "-fwhole-program-vtables", "-fvisibility=hidden"]
                    .map(str::to_string),
            );
        }

        Ok(Self {
            gclang,
            gclangxx,
            get_bc,
            llvm_link,
            compiler_path,
            bc_flags,
            scratch: ScratchDir::new("bitcode")?,
            verbose,
        })
    }

    /// Environment injected into the traced build so gllvm wraps its compiles.
    ///
    /// Both `CC`/`CXX` are set unconditionally — substituting the compiler is
    /// the whole point — but `LLVM_COMPILER_PATH` is only set when buildspy had
    /// to go looking for clang, so an explicit user setting is never overridden.
    pub fn build_env(&self) -> Vec<(String, String)> {
        let mut env = vec![
            ("CC".to_string(), self.gclang.display().to_string()),
            ("CXX".to_string(), self.gclangxx.display().to_string()),
            (
                "LLVM_BITCODE_GENERATION_FLAGS".to_string(),
                self.bc_flags.join(" "),
            ),
            (
                "WLLVM_BC_STORE".to_string(),
                self.store_dir().display().to_string(),
            ),
        ];
        if let Some(dir) = &self.compiler_path {
            env.push(("LLVM_COMPILER_PATH".to_string(), dir.display().to_string()));
        }
        if self.verbose {
            env.push(("WLLVM_OUTPUT_LEVEL".to_string(), "INFO".to_string()));
        }
        env
    }

    /// Create the bitcode store. gllvm copies each sidecar here but does not
    /// create the directory itself, and silently warns if it is missing.
    pub fn init_store(&self) -> Result<()> {
        std::fs::create_dir_all(self.store_dir())
            .with_context(|| format!("failed to create {}", self.store_dir().display()))
    }

    fn store_dir(&self) -> PathBuf {
        self.scratch.path().join("store")
    }

    /// Recover one whole-program `.bc` from a binary built through `gclang`.
    ///
    /// The result lives in buildspy's scratch directory and is deleted when the
    /// run ends, so nothing is left behind in the build tree.
    pub fn recover(&self, binary: &Path) -> Result<PathBuf> {
        if !binary.exists() {
            bail!("{} does not exist", binary.display());
        }
        if !has_bitcode_section(binary) {
            bail!(
                "{} has no {BITCODE_SECTION} section — it was not built through gclang. \
                 CC/CXX are read at *configure* time by cmake/meson/autotools, so a traced \
                 `cmake --build …` cannot pick them up; trace the configure step as well \
                 (e.g. `buildspy … -- sh -c 'cmake -B build && cmake --build build'`)",
                binary.display()
            );
        }

        let stem = binary
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "artifact".to_string());
        let out = unique_path(self.scratch.path(), &format!("{stem}.bc"));

        let mut cmd = Command::new(&self.get_bc);
        // `-S`: fail loudly instead of silently emitting a partial module.
        cmd.arg("-S").arg("-o").arg(&out);
        if let Some(link) = &self.llvm_link {
            cmd.arg("-l").arg(link);
        }
        if self.verbose {
            cmd.arg("-v");
        }
        cmd.arg(binary);

        let output = cmd
            .output()
            .with_context(|| format!("failed to run {}", self.get_bc.display()))?;
        if !output.status.success() {
            bail!(
                "{} failed on {}: {}",
                self.get_bc.display(),
                binary.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        if !out.is_file() {
            bail!(
                "{} reported success but produced no bitcode at {}",
                self.get_bc.display(),
                out.display()
            );
        }
        Ok(out)
    }
}

fn missing_gllvm() -> anyhow::Error {
    anyhow::anyhow!(
        "gllvm not found. Bitcode capture needs `gclang`, `gclang++` and `get-bc`: install with \
         `go install github.com/SRI-CSL/gllvm/cmd/...@latest`, or set BUILDSPY_GCLANG / \
         BUILDSPY_GET_BC. See https://github.com/SRI-CSL/gllvm"
    )
}

/// Locate a gllvm tool: `BUILDSPY_*` override, then `$PATH`, then the Go install
/// directories. The last step matters because gllvm is a `go install` tool that
/// lands in `~/go/bin`, which is typically *not* on the sanitized `$PATH`
/// buildspy inherits when it is run under `sudo` for tracing privileges.
fn find_gllvm_tool(name: &str, override_var: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = override_var.and_then(env_override) {
        return Some(p);
    }
    if let Some(p) = which(name) {
        return Some(p);
    }
    go_bin_dirs()
        .into_iter()
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

fn go_bin_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(gobin) = std::env::var_os("GOBIN") {
        dirs.push(PathBuf::from(gobin));
    }
    if let Some(gopath) = std::env::var_os("GOPATH") {
        dirs.extend(std::env::split_paths(&gopath).map(|p| p.join("bin")));
    }
    for home in home_dirs() {
        dirs.push(home.join("go").join("bin"));
    }
    dirs
}

/// `$HOME`, plus the invoking user's home when running under `sudo` (which
/// resets `$HOME` to root's unless `-E` is given).
fn home_dirs() -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(home));
    }
    if let Ok(user) = std::env::var("SUDO_USER") {
        let home = PathBuf::from("/home").join(&user);
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    homes
}

fn sibling(tool: &Path, name: &str) -> Option<PathBuf> {
    let p = tool.parent()?.join(name);
    p.is_file().then_some(p)
}

/// Decide which clang gllvm should use and which `llvm-link` `get-bc` should
/// call, keeping the two on the same LLVM version.
///
/// Version skew is worth avoiding: `llvm-link` reads older bitcode but not
/// newer, so a `clang-19` build linked by `llvm-link-18` fails with an opaque
/// "invalid bitcode" error.
///
/// Returns `(LLVM_COMPILER_PATH, llvm-link)`. `LLVM_COMPILER_PATH` stays `None`
/// when the user already set it or when a bare `clang` is on `$PATH` — gllvm's
/// default is then already right and buildspy should not second-guess it.
fn resolve_llvm_toolchain() -> (Option<PathBuf>, Option<PathBuf>) {
    // Respect an explicit user setting completely.
    if let Some(dir) = std::env::var_os("LLVM_COMPILER_PATH").map(PathBuf::from) {
        let link = env_override("BUILDSPY_LLVM_LINK")
            .or_else(|| exists(dir.join("llvm-link")))
            .or_else(find_any_llvm_link);
        return (None, link);
    }

    let (compiler_path, clang) = match which("clang") {
        Some(clang) => (None, Some(clang)),
        None => match llvm_dirs().find_map(|dir| exists(dir.join("clang"))) {
            Some(clang) => (clang.parent().map(Path::to_path_buf), Some(clang)),
            None => {
                log::warn!(
                    "bitcode capture: no `clang` found — gllvm can only produce bitcode with \
                     clang. Install clang or set LLVM_COMPILER_PATH."
                );
                (None, None)
            }
        },
    };

    let link = env_override("BUILDSPY_LLVM_LINK")
        .or_else(|| clang.as_deref().and_then(|c| sibling(c, "llvm-link")))
        .or_else(|| clang.as_deref().and_then(clang_major).and_then(versioned_llvm_link))
        .or_else(find_any_llvm_link);

    (compiler_path, link)
}

/// `llvm-link` matching a specific LLVM major version.
fn versioned_llvm_link(major: u32) -> Option<PathBuf> {
    which(&format!("llvm-link-{major}"))
        .or_else(|| exists(PathBuf::from(format!("/usr/lib/llvm-{major}/bin/llvm-link"))))
}

/// Any `llvm-link` we can find, newest first — a last resort when the clang
/// version is unknown.
fn find_any_llvm_link() -> Option<PathBuf> {
    which("llvm-link").or_else(|| LLVM_MAJORS.iter().find_map(|&m| versioned_llvm_link(m)))
}

/// Versioned LLVM install directories, newest first.
fn llvm_dirs() -> impl Iterator<Item = PathBuf> {
    LLVM_MAJORS
        .iter()
        .map(|m| PathBuf::from(format!("/usr/lib/llvm-{m}/bin")))
        .filter(|d| d.is_dir())
}

/// Major version from `clang --version` ("… clang version 18.1.3 …").
fn clang_major(clang: &Path) -> Option<u32> {
    let out = Command::new(clang).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let rest = text.split("clang version ").nth(1)?;
    rest.split(['.', '-', ' ']).next()?.parse().ok()
}

fn exists(p: PathBuf) -> Option<PathBuf> {
    p.is_file().then_some(p)
}

/// Does this ELF carry gllvm's bitcode-path section?
fn has_bitcode_section(binary: &Path) -> bool {
    let Ok(bytes) = std::fs::read(binary) else {
        return false;
    };
    let Ok(elf) = goblin::elf::Elf::parse(&bytes) else {
        return false;
    };
    elf.section_headers.iter().any(|sh| {
        elf.shdr_strtab
            .get_at(sh.sh_name)
            .is_some_and(|n| n == BITCODE_SECTION)
    })
}

/// `dir/name`, suffixed if taken — two artifacts may share a basename.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    (1..).map(|n| dir.join(format!("{n}-{name}"))).find(|p| !p.exists()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clang_major_from_version_banner() {
        // Exercised through the same split logic clang_major uses.
        let text = "Ubuntu clang version 18.1.3 (1ubuntu1)\nTarget: x86_64-pc-linux-gnu\n";
        let major: u32 = text
            .split("clang version ")
            .nth(1)
            .unwrap()
            .split(['.', '-', ' '])
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(major, 18);
    }

    #[test]
    fn unique_path_suffixes_on_collision() {
        let dir = ScratchDir::new("test").unwrap();
        let first = unique_path(dir.path(), "app.bc");
        std::fs::write(&first, b"").unwrap();
        let second = unique_path(dir.path(), "app.bc");
        assert_ne!(first, second);
        assert!(second.file_name().unwrap().to_str().unwrap().ends_with("app.bc"));
    }

    #[test]
    fn non_elf_input_has_no_bitcode_section() {
        let dir = ScratchDir::new("test").unwrap();
        let f = dir.path().join("not-an-elf");
        std::fs::write(&f, b"BC\xc0\xde").unwrap();
        assert!(!has_bitcode_section(&f));
    }
}

//! Small helpers shared across call-graph extractors.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Minimal `$PATH` lookup — avoids pulling in a `which` dependency.
///
/// Returns the first existing `dir/bin` across `$PATH`.
pub fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}

/// Read a `BUILDSPY_*` tool override, accepting it only if it names a real file.
pub fn env_override(var: &str) -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os(var)?);
    p.is_file().then_some(p)
}

/// A uniquely-named temp directory, removed on drop.
///
/// Used wherever an external tool insists on writing into the current directory
/// (`wpa`), or where buildspy owns intermediate artifacts that must not be left
/// behind in the user's build tree (bitcode capture).
pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub fn new(prefix: &str) -> Result<Self> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("buildspy-{prefix}-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

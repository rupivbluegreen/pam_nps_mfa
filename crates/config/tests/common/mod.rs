//! Shared test helpers.
//!
//! These tests run as an ordinary (non-root) user, so real fixtures are
//! created in a throwaway temp directory at test time with explicit modes —
//! nothing world-readable is ever committed to the repo. The current user's
//! uid is learned from a file the test just created (via `MetadataExt::uid`),
//! so we never need `libc::getuid` / `unsafe` to discover it.

#![allow(dead_code)] // not every test file uses every helper

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp directory, recursively removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "pam_nps_cfg_test_{tag}_{}_{nanos}_{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Absolute path to `name` inside this temp dir.
    pub fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Write `contents` to `path`, then chmod it to exactly `mode`.
pub fn write_mode(path: &Path, contents: &[u8], mode: u32) {
    fs::write(path, contents).expect("write fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod fixture");
}

/// The owner uid of `path` (the current user, for a file the test created).
pub fn owner_uid(path: &Path) -> u32 {
    fs::metadata(path).expect("stat fixture").uid()
}

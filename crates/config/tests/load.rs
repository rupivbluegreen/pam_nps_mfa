//! End-to-end secure-load tests: O_NOFOLLOW open -> fstat -> permission check
//! -> read -> parse -> per-server secret load.
//!
//! These run as a non-root user, so they drive `config::load_with_expected_uid`
//! (the `#[doc(hidden)]` test seam) with the current user's uid as the required
//! owner. Production code calls `config::load`, which pins the required owner to
//! uid 0. Both paths share the exact same open/fstat/validate/read code; only
//! the injected `expected_uid` differs.

mod common;

use common::{owner_uid, write_mode, TempDir};
use config::{load_with_expected_uid, ConfigError, PermIssue, Protocol};
use std::os::unix::fs::symlink;
use std::path::Path;

/// Build a config file referencing `secret_path`, plus the secret file itself.
/// Returns (config_path, expected_uid).
fn scenario(dir: &TempDir, config_mode: u32, secret_mode: u32, secret_body: &[u8]) -> std::path::PathBuf {
    let secret_path = dir.child("nps1.secret");
    write_mode(&secret_path, secret_body, secret_mode);

    let config_path = dir.child("pam_nps.conf");
    let text = format!(
        "server 10.0.0.10:1812 {}\nprotocol mschapv2\ntimeout 60\n",
        secret_path.display()
    );
    write_mode(&config_path, text.as_bytes(), config_mode);
    config_path
}

#[test]
fn loads_valid_config_and_strips_one_trailing_newline() {
    let dir = TempDir::new("load_ok");
    let config_path = scenario(&dir, 0o600, 0o600, b"super-secret-value\n");
    let uid = owner_uid(&config_path);

    let cfg = load_with_expected_uid(&config_path, uid).expect("valid config loads");

    assert_eq!(cfg.protocol, Protocol::Mschapv2);
    assert_eq!(cfg.timeout, 60);
    assert_eq!(cfg.probe_timeout, 5, "defaulted");
    assert_eq!(cfg.servers.len(), 1);
    assert_eq!(cfg.servers[0].addr, "10.0.0.10:1812".parse().unwrap());
    // Exactly one trailing newline stripped.
    assert_eq!(cfg.servers[0].secret.expose_secret(), "super-secret-value");
}

#[test]
fn secret_without_trailing_newline_is_kept_verbatim() {
    let dir = TempDir::new("load_nonewline");
    let config_path = scenario(&dir, 0o600, 0o600, b"no-newline-secret");
    let uid = owner_uid(&config_path);

    let cfg = load_with_expected_uid(&config_path, uid).expect("loads");
    assert_eq!(cfg.servers[0].secret.expose_secret(), "no-newline-secret");
}

#[test]
fn rejects_0644_secret_file() {
    let dir = TempDir::new("load_0644_secret");
    // Config is fine (0600); the SECRET is group/other-readable (0644).
    let config_path = scenario(&dir, 0o600, 0o644, b"leaky\n");
    let uid = owner_uid(&config_path);

    match load_with_expected_uid(&config_path, uid) {
        Err(ConfigError::InsecurePermissions { path, issue }) => {
            assert!(path.ends_with("nps1.secret"), "the SECRET file is rejected");
            assert!(matches!(issue, PermIssue::GroupOrOtherAccessible { .. }));
        }
        other => panic!("expected InsecurePermissions on the secret, got {other:?}"),
    }
}

#[test]
fn rejects_0644_config_file() {
    let dir = TempDir::new("load_0644_config");
    let config_path = scenario(&dir, 0o644, 0o600, b"fine\n");
    let uid = owner_uid(&config_path);

    match load_with_expected_uid(&config_path, uid) {
        Err(ConfigError::InsecurePermissions { path, issue }) => {
            assert!(path.ends_with("pam_nps.conf"));
            assert!(matches!(issue, PermIssue::GroupOrOtherAccessible { .. }));
        }
        other => panic!("expected InsecurePermissions on the config, got {other:?}"),
    }
}

#[test]
fn rejects_symlinked_config_path_via_o_nofollow() {
    let dir = TempDir::new("load_symlink");
    // A perfectly good real config...
    let real = scenario(&dir, 0o600, 0o600, b"secret\n");
    let uid = owner_uid(&real);

    // ...reached through a symlink. O_NOFOLLOW must make the open fail so the
    // contents are never read (defeats a symlink swap).
    let link = dir.child("pam_nps.conf.link");
    symlink(&real, &link).expect("create symlink");

    match load_with_expected_uid(&link, uid) {
        Err(ConfigError::Open { path, .. }) => {
            assert_eq!(path, link);
        }
        other => panic!("expected Open error from O_NOFOLLOW, got {other:?}"),
    }
}

#[test]
fn rejects_symlinked_secret_path_via_o_nofollow() {
    let dir = TempDir::new("load_symlink_secret");
    let real_secret = dir.child("real.secret");
    write_mode(&real_secret, b"secret\n", 0o600);
    let link_secret = dir.child("nps1.secret"); // a symlink standing in for the secret
    symlink(&real_secret, &link_secret).expect("create secret symlink");

    let config_path = dir.child("pam_nps.conf");
    let text = format!(
        "server 10.0.0.10:1812 {}\nprotocol mschapv2\n",
        link_secret.display()
    );
    write_mode(&config_path, text.as_bytes(), 0o600);
    let uid = owner_uid(&config_path);

    match load_with_expected_uid(&config_path, uid) {
        Err(ConfigError::Open { path, .. }) => assert_eq!(path, link_secret),
        other => panic!("expected Open error on the symlinked secret, got {other:?}"),
    }
}

#[test]
fn rejects_non_regular_config_file_directory() {
    // Point the loader at a directory: O_NOFOLLOW opens it fine, but the fstat
    // type check rejects it before any read.
    let dir = TempDir::new("load_dir");
    let as_config: &Path = dir.path();
    let uid = owner_uid(as_config);

    match load_with_expected_uid(as_config, uid) {
        Err(ConfigError::InsecurePermissions {
            issue: PermIssue::NotRegularFile,
            ..
        }) => {}
        other => panic!("expected NotRegularFile, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_owner_when_root_required() {
    // Drive the production contract (expected_uid = 0) against a file we own as
    // a non-root user: it must be rejected as wrong-owner.
    let dir = TempDir::new("load_root_required");
    let config_path = scenario(&dir, 0o600, 0o600, b"secret\n");

    match load_with_expected_uid(&config_path, 0) {
        Err(ConfigError::InsecurePermissions {
            issue: PermIssue::WrongOwner { expected, .. },
            ..
        }) => assert_eq!(expected, 0),
        other => panic!("expected WrongOwner, got {other:?}"),
    }
}

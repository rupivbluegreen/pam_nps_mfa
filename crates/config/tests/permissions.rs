//! Permission-check logic tests.
//!
//! These run as a non-root user. The uid check is made testable by injecting
//! the *expected* owner uid into `config::validate_permissions`:
//!   - to test the mode/type logic, we pass the current user's uid (learned
//!     from a file we just created), so the owner check passes and the
//!     mode/type check is what decides;
//!   - to test the wrong-owner logic, we pass `0` (root) for a file we own, so
//!     the owner check is what fails.
//!
//! Production always calls `config::load`, which pins the expected uid to 0.

mod common;

use common::{owner_uid, write_mode, TempDir};
use config::{validate_permissions, PermIssue};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn accepts_regular_root_equivalent_file_with_0600() {
    // "root-equivalent" here means: owned by the uid we pass as expected.
    let dir = TempDir::new("perm_ok");
    let f = dir.child("secret");
    write_mode(&f, b"s3cr3t", 0o600);

    let meta = fs::metadata(&f).unwrap();
    let uid = owner_uid(&f);
    assert_eq!(
        validate_permissions(&meta, uid),
        Ok(()),
        "a 0600 regular file owned by the expected uid must pass"
    );
}

#[test]
fn rejects_group_or_other_bits_0644() {
    let dir = TempDir::new("perm_0644");
    let f = dir.child("secret");
    write_mode(&f, b"s3cr3t", 0o644);

    let meta = fs::metadata(&f).unwrap();
    let uid = owner_uid(&f); // owner check passes; the MODE is what fails
    match validate_permissions(&meta, uid) {
        Err(PermIssue::GroupOrOtherAccessible { mode }) => {
            assert_ne!(mode & 0o077, 0);
        }
        other => panic!("expected GroupOrOtherAccessible, got {other:?}"),
    }
}

#[test]
fn rejects_group_readable_0640() {
    let dir = TempDir::new("perm_0640");
    let f = dir.child("secret");
    write_mode(&f, b"s3cr3t", 0o640);

    let meta = fs::metadata(&f).unwrap();
    let uid = owner_uid(&f);
    assert!(matches!(
        validate_permissions(&meta, uid),
        Err(PermIssue::GroupOrOtherAccessible { .. })
    ));
}

#[test]
fn rejects_wrong_owner() {
    let dir = TempDir::new("perm_owner");
    let f = dir.child("secret");
    write_mode(&f, b"s3cr3t", 0o600);

    let meta = fs::metadata(&f).unwrap();
    // We own the file (non-root), but require uid 0 → wrong owner.
    match validate_permissions(&meta, 0) {
        Err(PermIssue::WrongOwner { found, expected }) => {
            assert_eq!(expected, 0);
            assert_eq!(found, owner_uid(&f));
            assert_ne!(found, 0, "test must run as non-root for this assertion");
        }
        other => panic!("expected WrongOwner, got {other:?}"),
    }
}

#[test]
fn rejects_non_regular_file_directory() {
    // A directory is checked as not-a-regular-file BEFORE owner/mode, so even
    // though we own it and it is 0700, the type check fires first.
    let dir = TempDir::new("perm_dir");
    let sub = dir.child("adir");
    fs::create_dir(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();

    let meta = fs::metadata(&sub).unwrap();
    let uid = owner_uid(&sub);
    assert_eq!(
        validate_permissions(&meta, uid),
        Err(PermIssue::NotRegularFile)
    );
}

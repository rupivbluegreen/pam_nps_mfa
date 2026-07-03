#![forbid(unsafe_code)]
//! Zeroizing secret wrappers for `pam_nps_mfa` (phase 4).
//!
//! Every type that owns key material — the RADIUS shared secret, and (in
//! later phases) the password, its UTF-16LE re-encoding, the NT hash, and the
//! derived DES keys — is held in one of these wrappers so that the bytes are
//! wiped from memory on drop and can never reach a log line.
//!
//! Security posture (CLAUDE.md hard rules; SECURITY_DESIGN.md §3/§7):
//! - Zeroize on drop (rule 8): every wrapper derives
//!   [`zeroize::ZeroizeOnDrop`], so the backing buffer is overwritten with
//!   zeroes when the value is dropped.
//! - No secret in `Debug`/`Display`/logs (rule 3): each wrapper hand-writes a
//!   *redacting* `Debug` (`"Secret…([REDACTED])"`) and implements **no**
//!   `Display`. There is no code path — at any log level — that formats the
//!   contents. Exposure is always explicit through an `expose_secret()` call.
//! - No leaking `PartialEq`: these types deliberately implement no `PartialEq`.
//!   Constant-time integrity comparison of authenticators/MACs lives in the
//!   `radius`/`mschapv2` crates using `subtle`; nothing here participates in a
//!   hot integrity path, and a derived `==` on a secret is exactly the kind of
//!   variable-time compare we do not want callers to reach for.
//!
//! This crate has no `unsafe` and depends only on `zeroize`.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned byte secret (e.g. a raw key or MAC input) that is zeroized on drop.
///
/// The contents are only reachable through [`SecretBytes::expose_secret`], so
/// every place a secret leaves the wrapper is greppable. `Debug` is redacting
/// and there is no `Display`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Take ownership of an existing byte buffer as a secret. The caller's
    /// `Vec` is moved in; no copy is made.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Copy a byte slice into a new secret buffer. Prefer [`from_vec`] when you
    /// already own the buffer, to avoid leaving a second copy behind.
    ///
    /// [`from_vec`]: SecretBytes::from_vec
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// Borrow the raw secret bytes. This is the single, explicit exposure
    /// point — its name is deliberately loud so uses are auditable.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of secret bytes held. Length is not itself secret content.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never reveal contents or even the length (CLAUDE.md rule 3).
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// An owned UTF-8 text secret — the RADIUS shared-secret file content — that is
/// zeroized on drop.
///
/// Contents are only reachable through [`SecretString::expose_secret`]. `Debug`
/// is redacting and there is no `Display`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString {
    text: String,
}

impl SecretString {
    /// Take ownership of an existing `String` as a secret. The string is moved
    /// in; no copy is made.
    #[must_use]
    pub fn from_string(text: String) -> Self {
        Self { text }
    }

    /// Copy a string slice into a new secret. Prefer [`from_string`] when you
    /// already own the `String`, to avoid leaving a second copy behind.
    ///
    /// (Deliberately not named `from_str`/`FromStr`: that trait is infallible
    /// and its `&str -> Self` shape invites accidental construction of secrets
    /// from arbitrary parsed text.)
    ///
    /// [`from_string`]: SecretString::from_string
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        Self {
            text: text.to_owned(),
        }
    }

    /// Borrow the raw secret text. The single, explicit exposure point.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.text
    }

    /// Length in bytes of the secret text. Not itself secret content.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether the secret text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

/// A growable byte scratch buffer that zeroizes on drop, with a redacting
/// `Debug`.
///
/// This is the type to read secret file bytes into before validating/decoding
/// them into a [`SecretString`]. It is preferable to a bare
/// `zeroize::Zeroizing<Vec<u8>>` for secret material because that type's
/// `Debug` delegates to `Vec<u8>` and would print the bytes — a rule-3 hazard.
/// `ZeroizingBytes` redacts instead.
#[derive(Zeroize, ZeroizeOnDrop, Default)]
pub struct ZeroizingBytes {
    bytes: Vec<u8>,
}

impl ZeroizingBytes {
    /// A new, empty scratch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// A new, empty scratch buffer with capacity reserved for `cap` bytes, so
    /// a single sized read does not reallocate (and thus does not leave an
    /// un-zeroized copy of the secret in a freed allocation).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(cap),
        }
    }

    /// Mutable access to the backing `Vec` for appending (e.g. `read_to_end`).
    #[must_use]
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// Borrow the buffered bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of buffered bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for ZeroizingBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ZeroizingBytes([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_roundtrips_without_copying_semantics() {
        let s = SecretBytes::from_vec(vec![1, 2, 3, 4]);
        assert_eq!(s.expose_secret(), &[1, 2, 3, 4]);
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());

        let s2 = SecretBytes::from_bytes(&[9, 9]);
        assert_eq!(s2.expose_secret(), &[9, 9]);
    }

    #[test]
    fn secret_string_roundtrips() {
        let s = SecretString::from_string(String::from("hunter2"));
        assert_eq!(s.expose_secret(), "hunter2");
        assert_eq!(s.len(), 7);
        assert!(!s.is_empty());

        let s2 = SecretString::from_text("abc");
        assert_eq!(s2.expose_secret(), "abc");

        let empty = SecretString::from_text("");
        assert!(empty.is_empty());
    }

    #[test]
    fn zeroizing_bytes_scratch() {
        let mut z = ZeroizingBytes::with_capacity(8);
        assert!(z.is_empty());
        z.as_mut_vec().extend_from_slice(b"secret-bytes");
        assert_eq!(z.as_slice(), b"secret-bytes");
        assert_eq!(z.len(), 12);
    }

    // Rule 3: the redacting Debug must never reveal the contents. If someone
    // later replaces these with a derived Debug, this test fails.
    #[test]
    fn debug_is_redacted_for_every_wrapper() {
        let b = SecretBytes::from_bytes(b"topsecretbytes");
        let dbg = format!("{b:?}");
        assert_eq!(dbg, "SecretBytes([REDACTED])");
        assert!(!dbg.contains("topsecret"));

        let s = SecretString::from_text("topsecretstring");
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "SecretString([REDACTED])");
        assert!(!dbg.contains("topsecret"));

        let mut z = ZeroizingBytes::new();
        z.as_mut_vec().extend_from_slice(b"topsecretscratch");
        let dbg = format!("{z:?}");
        assert_eq!(dbg, "ZeroizingBytes([REDACTED])");
        assert!(!dbg.contains("topsecret"));
    }
}

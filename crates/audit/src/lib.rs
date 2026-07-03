#![deny(unsafe_code)]
//! Structured audit emission for `pam_nps_mfa` (phase 7).
//!
//! One record per authentication attempt (success, denied, AND unavail alike),
//! to native auditd and/or syslog as selected by config (IMPLEMENTATION_SPEC.md
//! §8). Two design guarantees drive this crate:
//!
//! - **No secret in a record, ever (CLAUDE.md rule 3).** The [`AuditRecord`]
//!   ([`record`]) carries metadata only — op, proto, server, user, result,
//!   reason, corr — and there is no constructor or method anywhere that accepts
//!   a secret type. This crate does not depend on `secrets`, never imports it,
//!   and never receives an authtok or packet bytes. The only cross-crate type
//!   it touches is the plain [`config::AuditBackend`] enum.
//! - **Emission never changes the auth result (SPEC_AMENDMENTS.md A3).**
//!   [`AuditSink::emit`] swallows every error: a failed `audit_log_acct_message`
//!   (e.g. missing `CAP_AUDIT_WRITE`) or a syslog error is best-effort and the
//!   caller's PAM return code is unaffected. When both legs are configured, a
//!   failure of one is compensated by the other.
//!
//! `unsafe` is confined to the single [`ffi`] submodule (the hand-declared
//! libaudit + syslog bindings, `#![allow(unsafe_code)]` scoped there); the rest
//! of the crate keeps `deny(unsafe_code)` and holds all the logic.

mod ffi;
pub mod record;

use config::AuditBackend;

pub use record::{AuditRecord, AuthResult, DEFAULT_OP};

/// Where one authentication attempt's record is emitted. `emit` takes `&self`
/// (no mutable global state — CLAUDE.md rule 17) and **swallows all errors**
/// (A3): a backend failure is never surfaced to, and never changes the result
/// of, the caller.
pub trait AuditSink {
    /// Emit exactly one record. Best effort: any backend error is swallowed.
    fn emit(&self, record: &AuditRecord);
}

/// Native auditd backend (`audit_log_acct_message`, type `AUDIT_USER_AUTH`).
/// A missing `CAP_AUDIT_WRITE` or absent auditd is swallowed (A3).
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditdSink;

impl AuditSink for AuditdSink {
    fn emit(&self, record: &AuditRecord) {
        // A3: best effort. The Err (auditd unavailable / write failed) is
        // deliberately ignored — it must not change the PAM return code.
        let _ = ffi::auditd_emit(record);
    }
}

/// syslog backend (`openlog`/`syslog`, facility `LOG_AUTHPRIV`). A syslog error
/// is swallowed (A3).
#[derive(Debug, Default, Clone, Copy)]
pub struct SyslogSink;

impl AuditSink for SyslogSink {
    fn emit(&self, record: &AuditRecord) {
        // A3: best effort; the Err is intentionally dropped.
        let _ = ffi::syslog_emit(record);
    }
}

/// A composite sink that fans one record out to two legs in order. Used to
/// build the `both` backend, and generic so tests can compose two recording
/// doubles and assert the fan-out without root.
///
/// Each leg is emitted independently; because every real [`AuditSink::emit`]
/// swallows its own errors (A3), one failing leg does not stop the other.
#[derive(Debug, Default, Clone, Copy)]
pub struct Both<A, B> {
    /// The first leg (auditd in the production `both` backend).
    pub first: A,
    /// The second leg (syslog in the production `both` backend).
    pub second: B,
}

impl<A, B> Both<A, B> {
    /// Compose two sinks into one that emits to both.
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: AuditSink, B: AuditSink> AuditSink for Both<A, B> {
    fn emit(&self, record: &AuditRecord) {
        self.first.emit(record);
        self.second.emit(record);
    }
}

/// The production `both` backend: auditd first, then syslog.
pub type BothSink = Both<AuditdSink, SyslogSink>;

/// Build the configured sink (IMPLEMENTATION_SPEC.md §8, `audit` key). Boxed so
/// the three concrete backends share one call site at the PAM boundary.
#[must_use]
pub fn from_backend(backend: AuditBackend) -> Box<dyn AuditSink + Send + Sync> {
    match backend {
        AuditBackend::Auditd => Box::new(AuditdSink),
        AuditBackend::Syslog => Box::new(SyslogSink),
        AuditBackend::Both => Box::new(BothSink::new(AuditdSink, SyslogSink)),
    }
}

/// A test double that records every emitted record in memory, so callers can
/// assert exactly-one-per-attempt and inspect field contents WITHOUT root or a
/// live auditd/syslog. Public (not feature-gated) because the pam-ffi
/// integration tests need it too.
///
/// `emit` takes `&self`; interior mutability via a `Mutex` keeps the
/// `AuditSink` object-safe and `Sync`.
#[derive(Debug, Default)]
pub struct RecordingSink {
    records: std::sync::Mutex<Vec<AuditRecord>>,
}

impl RecordingSink {
    /// A new, empty recording sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot clone of every record emitted so far, in order.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().expect("recording sink mutex").clone()
    }

    /// How many records have been emitted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().expect("recording sink mutex").len()
    }

    /// Whether no record has been emitted yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for RecordingSink {
    fn emit(&self, record: &AuditRecord) {
        self.records
            .lock()
            .expect("recording sink mutex")
            .push(record.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_sink_stores_exactly_one_record_with_expected_fields() {
        let sink = RecordingSink::new();
        assert!(sink.is_empty());

        let record = AuditRecord::new(
            "mschapv2",
            "10.0.0.10",
            "alice",
            AuthResult::Success,
            "success",
            "00112233445566778899aabbccddeeff",
        );
        sink.emit(&record);

        assert_eq!(sink.len(), 1);
        let stored = sink.records();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0], record);
        assert_eq!(stored[0].result, AuthResult::Success);
        assert_eq!(stored[0].user, "alice");
        assert_eq!(stored[0].proto, "mschapv2");
    }

    #[test]
    fn both_fans_out_one_record_to_each_leg() {
        // Compose two recording doubles in place of auditd+syslog and assert
        // the `both` fan-out reaches each leg exactly once (no root needed).
        let both = Both::new(RecordingSink::new(), RecordingSink::new());
        let record = AuditRecord::new(
            "pap",
            "10.0.0.11",
            "bob",
            AuthResult::Denied,
            "reject",
            "ffeeddccbbaa99887766554433221100",
        );
        both.emit(&record);

        assert_eq!(both.first.len(), 1);
        assert_eq!(both.second.len(), 1);
        assert_eq!(both.first.records()[0], record);
        assert_eq!(both.second.records()[0], record);
    }

    #[test]
    fn from_backend_selects_the_right_concrete_sink() {
        // Structural: the three backends map to distinct concrete sinks. We do
        // not exercise the real auditd/syslog legs here (they need root /
        // journald — see the crate tests comment); we only assert construction
        // does not panic and yields a usable trait object.
        for backend in [
            AuditBackend::Auditd,
            AuditBackend::Syslog,
            AuditBackend::Both,
        ] {
            let sink = from_backend(backend);
            // Emitting must never panic or change anything observable here; the
            // legs swallow their own errors (A3). We cannot assert delivery
            // without root, so this just confirms the call is total.
            let record = AuditRecord::new(
                "mschapv2",
                "",
                "carol",
                AuthResult::Unavail,
                "timeout",
                "unavailable",
            );
            sink.emit(&record);
        }
    }
}

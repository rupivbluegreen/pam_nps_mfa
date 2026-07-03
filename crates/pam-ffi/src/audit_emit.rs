//! The single seam that turns one authentication attempt into exactly one
//! audit record (phase 7, IMPLEMENTATION_SPEC.md §8). 100% safe code — the
//! `unsafe` libaudit/syslog calls live in the `audit` crate's FFI shim.
//!
//! This is a small, testable helper on purpose: `emit_attempt` takes only
//! metadata — the protocol, username, correlation id, the deciding server, and
//! the flow's [`AuthReport`] (outcome + machine reason) — plus a `&dyn
//! AuditSink`, and calls `sink.emit` **once**. It receives NO authtok and NO
//! packet bytes; there is no parameter here that can carry a secret (CLAUDE.md
//! rule 3), which the `audit` crate enforces structurally (its record type has
//! no secret-bearing field).
//!
//! A3 (SPEC_AMENDMENTS.md): audit emission must never change the PAM return
//! code. Every `sink.emit` here is wrapped in `catch_unwind`, so even a sink
//! that panics internally cannot unwind into — and cannot alter the result of
//! — the caller.

use std::panic::{catch_unwind, AssertUnwindSafe};

use audit::{AuditRecord, AuditSink, AuthResult};
use config::Protocol;

use crate::flow::{AuthReport, PamOutcome};

/// The `proto=` token for a fixed protocol (IMPLEMENTATION_SPEC.md §8).
#[must_use]
pub fn proto_str(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Mschapv2 => "mschapv2",
        Protocol::Pap => "pap",
    }
}

/// The `proto=` token when the protocol is not yet known (a config-load
/// failure denies before the protocol is fixed).
pub const PROTO_UNKNOWN: &str = "unknown";

/// Map the flow's [`PamOutcome`] onto the record's three-valued
/// [`AuthResult`]. A clean Accept is `success`; an evaluated-and-rejected
/// credential is `denied`; everything the module could not complete
/// (unreachable, timeout, config error, broken conversation) is `unavail`.
#[must_use]
pub fn result_of(outcome: PamOutcome) -> AuthResult {
    match outcome {
        PamOutcome::Success => AuthResult::Success,
        PamOutcome::AuthErr => AuthResult::Denied,
        // A broken conversation is a failure to consult the second factor, not
        // a credential rejection: group it with unavailability.
        PamOutcome::Unavail | PamOutcome::ConvErr => AuthResult::Unavail,
    }
}

/// Map a raw PAM return code (from a boundary failure — a failed `pam_get_user`,
/// an undecodable/null authtok, a config error) onto the record's
/// [`AuthResult`]. `PAM_AUTH_ERR` is a `denied`; anything else non-success is
/// `unavail`.
#[must_use]
pub fn result_from_pam_code(code: i32) -> AuthResult {
    if code == crate::pam_codes::SUCCESS {
        AuthResult::Success
    } else if code == crate::pam_codes::AUTH_ERR {
        AuthResult::Denied
    } else {
        AuthResult::Unavail
    }
}

/// Emit one boundary record (before the protocol/backend is known) with an
/// empty server field. Used for the pre-config early returns so that EVERY
/// attempt — even a failed user fetch or a null authtok — emits exactly one
/// record (IMPLEMENTATION_SPEC.md §8: one record per attempt).
pub fn emit_boundary(
    sink: &dyn AuditSink,
    proto: &'static str,
    user: &str,
    corr: &str,
    result: AuthResult,
    reason: &'static str,
) {
    let record = AuditRecord::new(proto, String::new(), user, result, reason, corr);
    emit_once(sink, &record);
}

/// Emit exactly ONE record for this attempt through `sink` (A3: best effort,
/// panic-isolated). `proto` is the wire protocol token, `report` is the flow's
/// full result. The deciding server is rendered as its bare ip (no port), or
/// empty when none was reached.
pub fn emit_attempt(
    sink: &dyn AuditSink,
    proto: &'static str,
    user: &str,
    corr: &str,
    report: &AuthReport,
) {
    let server = report
        .server
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();
    let record = AuditRecord::new(
        proto,
        server,
        user,
        result_of(report.outcome),
        report.reason,
        corr,
    );
    emit_once(sink, &record);
}

/// Emit a single already-built record, isolating any panic from the sink so it
/// can never change the caller's PAM return code (A3).
pub fn emit_once(sink: &dyn AuditSink, record: &AuditRecord) {
    // AssertUnwindSafe: we only borrow `sink`/`record` immutably across the
    // boundary and observe nothing afterwards, so a panic leaves no broken
    // invariant. The Err (a panicking sink) is deliberately dropped.
    let _ = catch_unwind(AssertUnwindSafe(|| sink.emit(record)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::reason;

    #[test]
    fn result_of_maps_every_outcome() {
        assert_eq!(result_of(PamOutcome::Success), AuthResult::Success);
        assert_eq!(result_of(PamOutcome::AuthErr), AuthResult::Denied);
        assert_eq!(result_of(PamOutcome::Unavail), AuthResult::Unavail);
        assert_eq!(result_of(PamOutcome::ConvErr), AuthResult::Unavail);
    }

    #[test]
    fn proto_tokens_match_the_schema() {
        assert_eq!(proto_str(Protocol::Mschapv2), "mschapv2");
        assert_eq!(proto_str(Protocol::Pap), "pap");
    }

    #[test]
    fn emit_attempt_writes_one_record_with_the_expected_fields() {
        let sink = audit::RecordingSink::new();
        let report = AuthReport {
            outcome: PamOutcome::Success,
            server: Some("10.0.0.10:1812".parse().unwrap()),
            reason: reason::SUCCESS,
        };
        emit_attempt(&sink, proto_str(Protocol::Mschapv2), "alice", "corrhex", &report);

        assert_eq!(sink.len(), 1);
        let rec = &sink.records()[0];
        assert_eq!(rec.result, AuthResult::Success);
        assert_eq!(rec.proto, "mschapv2");
        assert_eq!(rec.user, "alice");
        // The bare ip (no port) is recorded.
        assert_eq!(rec.server, "10.0.0.10");
        assert_eq!(rec.reason, "success");
        assert_eq!(rec.corr, "corrhex");
    }

    #[test]
    fn emit_attempt_with_no_server_records_empty_server() {
        let sink = audit::RecordingSink::new();
        let report = AuthReport {
            outcome: PamOutcome::Unavail,
            server: None,
            reason: reason::ALL_UNREACHABLE,
        };
        emit_attempt(&sink, PROTO_UNKNOWN, "bob", "corrhex", &report);

        assert_eq!(sink.len(), 1);
        assert_eq!(sink.records()[0].server, "");
        assert_eq!(sink.records()[0].result, AuthResult::Unavail);
    }

    /// A3: a sink whose `emit` panics must not unwind into the caller. The
    /// helper returns normally and any surrounding computation is unaffected.
    #[test]
    fn a_panicking_sink_does_not_unwind_into_the_caller() {
        struct PanicSink;
        impl AuditSink for PanicSink {
            fn emit(&self, _record: &AuditRecord) {
                panic!("backend blew up");
            }
        }
        let report = AuthReport {
            outcome: PamOutcome::AuthErr,
            server: Some("10.0.0.10:1812".parse().unwrap()),
            reason: reason::REJECT,
        };
        // If the panic escaped, this test would abort. It returns, proving the
        // isolation, and the caller's own value is computed unchanged.
        emit_attempt(&PanicSink, proto_str(Protocol::Pap), "carol", "corrhex", &report);
        assert_eq!(report.outcome.pam_code(), crate::pam_codes::AUTH_ERR);
    }
}

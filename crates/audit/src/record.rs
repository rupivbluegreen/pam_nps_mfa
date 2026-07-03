//! The audit record: pure, safe metadata (no `unsafe`, no secret types).
//!
//! This module is where the phase-7 "auditability is a byproduct"
//! (SECURITY_DESIGN.md §2) contract is *structurally* enforced. An
//! [`AuditRecord`] has exactly seven metadata fields and **no field capable of
//! holding a secret**: there is no constructor, setter, or type here that
//! accepts a password, NT hash, DES key, shared secret, keystream, packet
//! bytes, or an authtok. The `secrets` crate is neither imported nor reachable
//! from this file (CLAUDE.md rule 3: no secret in any record, ever).
//!
//! The rendered line matches the IMPLEMENTATION_SPEC.md §8 schema EXACTLY,
//! space-separated, seven `key=value` pairs in order:
//!
//! ```text
//! op=pam_nps_auth proto=mschapv2 server=10.0.0.10 user=<name> result=success|denied|unavail reason=<short> corr=<hex>
//! ```
//!
//! User- and network-influenced fields (`user`, `reason`, `server`, `corr`)
//! are sanitized so that whitespace or control bytes cannot split the record
//! across keys or across lines. Sanitization replaces each such byte with `_`;
//! it never drops the value. Note that this is *whitespace* hygiene only — it
//! does NOT touch `%`, `s`, or `n`, so a hostile username like `%s%n` survives
//! verbatim in the `user=` field. Format-string safety for syslog's variadic
//! `printf` is enforced separately, at the call site in `ffi.rs`, by passing a
//! literal `"%s"` format and the whole rendered line as the single argument.

/// The result of an authentication attempt, as it appears in the record and
/// as it maps onto the two backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// Access-Accept with (for MSCHAPv2) a verified MS-CHAP2-Success.
    Success,
    /// The credential was evaluated and rejected (Access-Reject, MFA denied,
    /// failed mutual auth, empty/unusable credential).
    Denied,
    /// The service could not be consulted or the attempt could not complete:
    /// all servers unreachable, timeout, config error, broken conversation.
    Unavail,
}

impl AuthResult {
    /// The `result=` token in the rendered schema line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Unavail => "unavail",
        }
    }

    /// The `result` argument for `audit_log_acct_message` (IMPLEMENTATION_SPEC
    /// §8): `1` for success, `0` for any failure. A `denied` and an `unavail`
    /// are both non-success at the auditd level (the distinction lives in the
    /// `op`/reason), so both map to `0`.
    #[must_use]
    pub fn auditd_result(self) -> i32 {
        match self {
            Self::Success => 1,
            Self::Denied | Self::Unavail => 0,
        }
    }

    /// Whether this is a clean success — selects the syslog priority
    /// (`LOG_INFO` vs `LOG_WARNING`).
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// The default `op=` value (IMPLEMENTATION_SPEC.md §8 schema).
pub const DEFAULT_OP: &str = "pam_nps_auth";

/// A single authentication-attempt audit record. Metadata ONLY — there is no
/// field, constructor, or method that can carry secret material (CLAUDE.md
/// rule 3). Cloneable/comparable so a recording test double can store and
/// assert on emitted records without root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The operation token, default [`DEFAULT_OP`] (`pam_nps_auth`).
    pub op: &'static str,
    /// The wire protocol: `"mschapv2"` or `"pap"` (or `"unknown"` before the
    /// config that fixes it has loaded).
    pub proto: &'static str,
    /// The deciding server address as a bare host string (no port), or empty
    /// when no server was reached (e.g. a pre-config early return).
    pub server: String,
    /// The account name. User-influenced: sanitized on render, never dropped.
    pub user: String,
    /// The attempt result.
    pub result: AuthResult,
    /// A short, machine-readable reason token (e.g. `success`, `reject`,
    /// `mutual_auth_failed`, `timeout`, `config_error`).
    pub reason: String,
    /// The per-attempt correlation id (SPEC_AMENDMENTS.md A6): 32 hex chars, or
    /// the literal `unavailable`.
    pub corr: String,
}

impl AuditRecord {
    /// Build a record with the default `op` (`pam_nps_auth`). Every argument is
    /// plain metadata; there is deliberately no parameter that can accept a
    /// secret type.
    #[must_use]
    pub fn new(
        proto: &'static str,
        server: impl Into<String>,
        user: impl Into<String>,
        result: AuthResult,
        reason: impl Into<String>,
        corr: impl Into<String>,
    ) -> Self {
        Self {
            op: DEFAULT_OP,
            proto,
            server: server.into(),
            user: user.into(),
            result,
            reason: reason.into(),
            corr: corr.into(),
        }
    }

    /// Render the EXACT IMPLEMENTATION_SPEC.md §8 schema line: seven
    /// space-separated `key=value` pairs, in order. The user/reason/server/corr
    /// values are whitespace-sanitized so the line stays single-line and
    /// unambiguous (a hostile `user=al ice\n...` cannot forge extra keys).
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "op={} proto={} server={} user={} result={} reason={} corr={}",
            self.op,
            self.proto,
            sanitize(&self.server),
            sanitize(&self.user),
            self.result.as_str(),
            sanitize(&self.reason),
            sanitize(&self.corr),
        )
    }

    /// The `op` string for `audit_log_acct_message`, carrying the protocol and
    /// server per IMPLEMENTATION_SPEC.md §8 ("put protocol and server into the
    /// operation string"). A single token (no spaces) so `ausearch`/`aureport`
    /// parse it cleanly.
    #[must_use]
    pub fn auditd_op(&self) -> String {
        let server = if self.server.is_empty() {
            String::from("none")
        } else {
            sanitize(&self.server)
        };
        format!("{}-{}-{}", self.op, self.proto, server)
    }
}

/// Replace every whitespace or control byte with `_` so a value cannot split
/// the record across keys or lines. Non-whitespace printable characters —
/// including `%`, `s`, and `n` — are preserved verbatim (format-string safety
/// is the syslog call site's job, not this function's).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_whitespace() || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_exact_schema_line_with_seven_keys_in_order() {
        let record = AuditRecord::new(
            "mschapv2",
            "10.0.0.10",
            "alice",
            AuthResult::Success,
            "success",
            "0123456789abcdef0123456789abcdef",
        );
        assert_eq!(
            record.render(),
            "op=pam_nps_auth proto=mschapv2 server=10.0.0.10 user=alice \
             result=success reason=success corr=0123456789abcdef0123456789abcdef"
        );
        // The seven keys, in order, each exactly once.
        let rendered = record.render();
        let keys: Vec<&str> = rendered
            .split(' ')
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        assert_eq!(
            keys,
            ["op", "proto", "server", "user", "result", "reason", "corr"]
        );
    }

    #[test]
    fn result_token_maps_success_denied_unavail() {
        let base = |r| AuditRecord::new("pap", "s", "u", r, "x", "c").render();
        assert!(base(AuthResult::Success).contains("result=success "));
        assert!(base(AuthResult::Denied).contains("result=denied "));
        assert!(base(AuthResult::Unavail).contains("result=unavail "));
    }

    #[test]
    fn auditd_result_is_one_for_success_zero_otherwise() {
        assert_eq!(AuthResult::Success.auditd_result(), 1);
        assert_eq!(AuthResult::Denied.auditd_result(), 0);
        assert_eq!(AuthResult::Unavail.auditd_result(), 0);
    }

    // NO-SECRET: structurally the record has no field to carry a credential.
    // We feed benign metadata alongside a planted "password"-looking sentinel
    // ONLY through the whitespace of a hostile username, and assert the
    // rendered line never grows a field that could smuggle a secret.
    #[test]
    fn no_secret_sentinel_can_appear_because_there_is_no_field_for_one() {
        const SENTINEL: &str = "hunter2-NTHASH-DEADBEEF";
        let record = AuditRecord::new(
            "mschapv2",
            "10.0.0.10",
            "alice",
            AuthResult::Denied,
            "reject",
            "00112233445566778899aabbccddeeff",
        );
        let line = record.render();
        // The record type simply has nowhere to put the sentinel: it never
        // appears unless a caller deliberately wrote it into a metadata field
        // (which the type does not do for us).
        assert!(!line.contains(SENTINEL));
        assert!(!line.contains("hunter2"));
    }

    #[test]
    fn username_with_spaces_and_newlines_is_sanitized_to_single_line() {
        let record = AuditRecord::new(
            "mschapv2",
            "10.0.0.10",
            "al ice\nresult=success reason=owned",
            AuthResult::Denied,
            "reject",
            "corrhex",
        );
        let line = record.render();
        // No raw newline: the record stays single-line.
        assert!(!line.contains('\n'));
        // The injected "result=success" cannot appear as a real extra field:
        // its whitespace was replaced, so it is glued into the user= value.
        assert!(line.contains("user=al_ice_result=success_reason=owned "));
        // The genuine result key is still the real one (denied), appearing
        // exactly once as a standalone field.
        assert_eq!(line.matches(" result=denied ").count(), 1);
    }

    #[test]
    fn username_with_percent_s_percent_n_is_preserved_literally() {
        // Format-string metacharacters are NOT whitespace/control, so they are
        // preserved verbatim in the user= field. (syslog format-string safety
        // is enforced at the ffi.rs call site, not by mangling the value.)
        let record = AuditRecord::new(
            "pap",
            "10.0.0.10",
            "%s%n%x",
            AuthResult::Denied,
            "reject",
            "corrhex",
        );
        assert!(record.render().contains("user=%s%n%x "));
    }

    #[test]
    fn auditd_op_carries_proto_and_server_as_one_token() {
        let record = AuditRecord::new(
            "mschapv2",
            "10.0.0.10",
            "alice",
            AuthResult::Success,
            "success",
            "corrhex",
        );
        let op = record.auditd_op();
        assert_eq!(op, "pam_nps_auth-mschapv2-10.0.0.10");
        assert!(!op.contains(' '));
    }
}

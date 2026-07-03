#![forbid(unsafe_code)]
//! MSCHAPv2 engine for `pam_nps_mfa` (phase 2).
//!
//! RFC 2759 §9.2 math (NT hash, challenge hash, NT response, Authenticator
//! Response generation and constant-time verification) and the RFC 2548
//! Microsoft vendor attribute wire layout (IMPLEMENTATION_SPEC.md §5), built on
//! the radius crate's Vendor-Specific envelope (Vendor-Id 311).
//!
//! Security posture (CLAUDE.md hard rules):
//! - Fail closed: every parse/verify path returns `Result`/`bool`; malformed
//!   attacker-supplied input (MS-CHAP2-Success / MS-CHAP-Error strings, VSAs)
//!   denies, never panics, never succeeds (rules 1, 15).
//! - Mutual auth is mandatory: [`verify_access_accept`] denies unless the
//!   server's MS-CHAP2-Success authenticator matches, even on an Access-Accept
//!   (rule 6). The comparison is constant time via `subtle` (rule 7).
//! - Key material is wiped: the NT hash and the derived DES keys are
//!   password-equivalent and live in `zeroize::Zeroizing`, dropped as soon as
//!   the NT response and Success check are done (rule 8). `zeroize` is used
//!   directly; this crate does not depend on the `secrets` crate.
//! - md4 and single DES are intentionally weak and required by MSCHAPv2; they
//!   are not removed or "upgraded" (rule 9).
//! - A `getrandom` failure denies with no weak/zero fallback (rule 18).
//! - No secret is exposed via `Debug`/`Display`/logs (rule 3): credential-
//!   bearing types implement no `Debug`, and every error type carries only a
//!   static reason, never bytes.

mod crypto;
mod flow;
mod vsa;

pub use crypto::{
    challenge_hash, generate_authenticator_response, generate_nt_response, nt_password_hash,
    password_hash_hash, verify_authenticator_response,
};
pub use flow::{
    build_request, generate_challenges, verify_access_accept, verify_success, Challenges,
    MsChapV2Request,
};
pub use vsa::{
    encode_ms_chap2_response, encode_ms_chap_challenge, find_ms_chap2_success, find_ms_chap_error,
    parse_ms_chap2_success, parse_ms_chap_error, vendor_type, MsChapError, SuccessError,
};

/// The OS CSPRNG failed while generating challenges. The caller must deny the
/// authentication (CLAUDE.md rule 18); there is no fallback material. Carries
/// no bytes, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("system randomness unavailable; deny the authentication")
    }
}

impl std::error::Error for RngError {}

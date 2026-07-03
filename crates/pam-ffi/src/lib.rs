//! `pam-ffi`: the PAM module crate for `pam_nps_mfa` (phase 5).
//!
//! Layering (CLAUDE.md rule 2): every authentication *decision* lives in the
//! safe modules — [`flow`] (orchestration and the §7 return-code table),
//! [`conversation`] (prompting), [`options`] (pam.d arguments) and this
//! root (input gathering glue). `ffi.rs` is the single FFI shim: it declares
//! the libpam ABI by hand, converts pointers to checked Rust types, hosts the
//! exported `pam_sm_*` symbols (each body wrapped in `catch_unwind`, panic →
//! `PAM_AUTHINFO_UNAVAIL` — rule 10) and the A2 hardening calls. The
//! memory-safety lint policy is pinned in this crate's Cargo.toml
//! (`[lints.rust]`): denied crate-wide, with `ffi.rs` alone opting back in,
//! so `ffi.rs` is the only file under `src/` that names that lint at all.
//!
//! No mutable global state exists anywhere in the crate (rule 17): the
//! module is called concurrently and every piece of per-attempt state is a
//! local in these functions.

pub mod conversation;
mod ffi;
pub mod flow;
pub mod options;

use std::fmt::Write as _;
use std::path::Path;

use flow::AttemptContext;
use radius::UdpTransport;

/// Linux-PAM return codes and flag bits, from
/// `/usr/include/security/_pam_types.h`, declared by hand
/// (IMPLEMENTATION_SPEC.md §2 — no bindgen). The C-side item/style/limit
/// constants live in `ffi.rs`; these are the values the safe layer returns,
/// checks, and tests against.
pub mod pam_codes {
    pub const SUCCESS: i32 = 0;
    pub const SERVICE_ERR: i32 = 3;
    pub const SYSTEM_ERR: i32 = 4;
    pub const BUF_ERR: i32 = 5;
    pub const AUTH_ERR: i32 = 7;
    pub const CRED_INSUFFICIENT: i32 = 8;
    pub const AUTHINFO_UNAVAIL: i32 = 9;
    pub const USER_UNKNOWN: i32 = 10;
    pub const CONV_ERR: i32 = 19;
    pub const IGNORE: i32 = 25;
    pub const ABORT: i32 = 26;
    /// `PAM_DISALLOW_NULL_AUTHTOK` flag bit.
    pub const DISALLOW_NULL_AUTHTOK: i32 = 0x0001;
    /// `PAM_SILENT` flag bit.
    pub const SILENT: i32 = 0x8000;
}

/// The return code for a null (absent) authtok.
///
/// Always `PAM_AUTH_ERR`: with `PAM_DISALLOW_NULL_AUTHTOK` that is mandated
/// (CLAUDE.md rule 11; IMPLEMENTATION_SPEC.md §7), and without the flag an
/// absent password still cannot satisfy an NPS credential check — fail
/// closed (rule 1) forbids treating it as anything but an authentication
/// failure. Exposed so the return-code tests pin both flag states.
#[must_use]
pub fn null_authtok_return(_disallow_null: bool) -> i32 {
    pam_codes::AUTH_ERR
}

/// The safe body of `pam_sm_authenticate` (the exported symbol in `ffi.rs`
/// wraps this in `catch_unwind`). Gathers inputs through the shim, then runs
/// the protocol-agnostic [`flow::authenticate`].
pub(crate) fn sm_authenticate(pam: ffi::Pam, flags: i32, args: &[String]) -> i32 {
    // A2 hardening first: this process is about to hold a password; make it
    // non-dumpable before the credential exists.
    ffi::harden_process();

    let opts = options::parse(args);
    // A6: per-attempt correlation id for the (phase 7) audit records. Its
    // RNG failure yields "unavailable" and never denies by itself — the id
    // is not security material.
    let corr = corr_id();

    let username = match ffi::get_user(pam) {
        Ok(u) => u,
        Err(code) => return code,
    };

    let disallow_null = flags & pam_codes::DISALLOW_NULL_AUTHTOK != 0;
    let silent = flags & pam_codes::SILENT != 0;

    let fetched = if opts.use_first_pass {
        // use_first_pass: an earlier module's token or nothing; never prompt.
        ffi::get_authtok_item(pam)
    } else {
        // Default and try_first_pass: pam_get_authtok returns the existing
        // token and prompts (echo off) only when none is available (§7:
        // prompt only when it is not already available).
        ffi::get_authtok_prompting(pam)
    };
    let authtok = match fetched {
        Ok(Some(tok)) => tok,
        Ok(None) => return null_authtok_return(disallow_null),
        Err(code) => return code,
    };
    if authtok.is_empty() {
        // Rule 11: reject empty passwords → PAM_AUTH_ERR (§7 table).
        return pam_codes::AUTH_ERR;
    }
    // A2: best-effort mlock of OUR credential copy (PAM's buffer is PAM's).
    // Failure is hardening degradation, logged by the phase-7 audit backend,
    // never an authentication error.
    let _locked = ffi::mlock_best_effort(authtok.expose_secret().as_bytes());

    let config = match config::load(Path::new(&opts.config_path)) {
        Ok(c) => c,
        // Config error or permissive secret file: PAM_AUTHINFO_UNAVAIL, and
        // phase 7 emits the critical audit record here (§7 table; rule 12).
        Err(e) => return flow::outcome_for_config_error(&e).pam_code(),
    };

    let mut conv = conversation::PamConversation::new(pam, silent);
    // The real connected-UDP transport (phase 6), built from the loaded
    // config timing: the A1 two-stage probe/MFA windows, the identical-packet
    // retry count, and the optional client bind address. Fails CLOSED on any
    // transport error or timeout (PAM_AUTHINFO_UNAVAIL).
    let mut transport = UdpTransport::from_config(
        config.probe_timeout,
        config.timeout,
        config.retries,
        config.source_ip,
    );
    let ctx = AttemptContext {
        username: &username,
        password: &authtok,
        corr: &corr,
    };
    flow::authenticate(&ctx, &config, &mut conv, &mut transport).pam_code()
}

/// The safe body of `pam_sm_setcred`: this module manages no credentials —
/// `PAM_SUCCESS` (§7 table).
pub(crate) fn sm_setcred() -> i32 {
    pam_codes::SUCCESS
}

/// The safe body of `pam_sm_acct_mgmt`: account policy is NPS's job —
/// `PAM_IGNORE` (§7 table).
pub(crate) fn sm_acct_mgmt() -> i32 {
    pam_codes::IGNORE
}

/// SPEC_AMENDMENTS.md A6: 16 bytes from the OS CSPRNG as 32 hex chars; on
/// RNG failure the literal `unavailable` — never weak randomness, and never
/// a denial on this alone.
fn corr_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return String::from("unavailable");
    }
    let mut out = String::with_capacity(32);
    for b in bytes {
        // Writing to a String cannot fail; ignore the Result rather than
        // introduce a panic path (rule 10 hygiene).
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_authtok_is_auth_err_with_and_without_the_flag() {
        assert_eq!(null_authtok_return(true), pam_codes::AUTH_ERR);
        assert_eq!(null_authtok_return(false), pam_codes::AUTH_ERR);
    }

    #[test]
    fn trivial_entry_bodies_match_the_table() {
        assert_eq!(sm_setcred(), pam_codes::SUCCESS);
        assert_eq!(sm_acct_mgmt(), pam_codes::IGNORE);
    }

    #[test]
    fn corr_id_is_32_hex_chars() {
        let corr = corr_id();
        assert_eq!(corr.len(), 32);
        assert!(corr.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#![allow(unsafe_code)]
//! The libaudit + syslog FFI shim — the ONLY file in the audit crate (and,
//! together with the pam-ffi crate's libpam shim, in the whole workspace) that
//! may contain `unsafe` (CLAUDE.md rule 2; SPEC_AMENDMENTS.md A2).
//!
//! Deliberately close to zero logic: it hand-declares the C ABI (no bindgen —
//! IMPLEMENTATION_SPEC.md §2), formats already-safe metadata strings into
//! `CString`s, and calls the C functions. No authentication decision, and no
//! secret material, is ever visible here — the [`AuditRecord`] it receives
//! carries metadata only.
//!
//! Both emit functions return a `Result` the caller MAY ignore
//! (SPEC_AMENDMENTS.md A3): an audit emission failure — a missing
//! `CAP_AUDIT_WRITE`, `audit_open` returning `<0`, a syslog error — is
//! best-effort and NEVER changes the PAM return code.

use core::ffi::{c_char, c_int, c_uint};
use std::ffi::{CString, NulError};
use std::sync::OnceLock;

use crate::record::AuditRecord;

// ===========================================================================
// C constants, declared by hand (from /usr/include/libaudit.h,
// /usr/include/linux/audit.h, /usr/include/x86_64-linux-gnu/sys/syslog.h).
// ===========================================================================

/// `AUDIT_USER_AUTH` — a standard USER_AUTH event, so `ausearch -m USER_AUTH`
/// and `aureport` parse it natively (IMPLEMENTATION_SPEC.md §8).
const AUDIT_USER_AUTH: c_int = 1100;

/// `LOG_AUTHPRIV` facility: `(10 << 3)` = 80 (security/authorization, private).
const LOG_AUTHPRIV: c_int = 10 << 3;
/// `LOG_INFO` level (6) — used for a successful attempt.
const LOG_INFO: c_int = 6;
/// `LOG_WARNING` level (4) — used for a denied/unavail attempt.
const LOG_WARNING: c_int = 4;
/// `LOG_PID` option (0x01): include the pid in each line.
const LOG_PID: c_int = 0x01;
/// `LOG_NDELAY` option (0x08): open the socket immediately.
const LOG_NDELAY: c_int = 0x08;

/// `pgname` for `audit_log_acct_message` (the program that generated the
/// record). The installed `.so` is `pam_nps_mfa`.
const PGNAME: &str = "pam_nps_mfa";
/// The syslog `ident` (kept by `openlog`, see [`syslog_ident`]).
const SYSLOG_IDENT: &str = "pam_nps_mfa";

/// A literal `"%s"` format for the variadic `syslog`. FORMAT-STRING SAFETY:
/// the rendered record (which contains the network/user-influenced username)
/// is passed as the single `%s` ARGUMENT, never as the format string, so a
/// username containing `%n`/`%s` can neither crash nor read the varargs.
const SYSLOG_FMT: &[u8] = b"%s\0";

/// `unsigned int` "no numeric uid known" sentinel passed as the `id` argument
/// to `audit_log_acct_message` (the account is identified by name, not uid).
const NO_ID: c_uint = c_uint::MAX;

// ===========================================================================
// Hand-declared C ABI.
// ===========================================================================

extern "C" {
    // libaudit (link: -laudit, see build.rs).
    fn audit_open() -> c_int;
    fn audit_close(fd: c_int);
    fn audit_log_acct_message(
        audit_fd: c_int,
        r#type: c_int,
        pgname: *const c_char,
        op: *const c_char,
        name: *const c_char,
        id: c_uint,
        host: *const c_char,
        addr: *const c_char,
        tty: *const c_char,
        result: c_int,
    ) -> c_int;

    // syslog (libc).
    fn openlog(ident: *const c_char, option: c_int, facility: c_int);
    fn syslog(priority: c_int, format: *const c_char, ...);
    #[allow(dead_code)] // declared for ABI completeness; the module never closes syslog
    fn closelog();
}

/// Why a best-effort emit could not be attempted or completed. The caller
/// ignores this (A3); it exists only so a backend can fall back to the other
/// leg and so tests can reason about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    /// A metadata field had an interior NUL and could not become a `CString`.
    /// (Sanitized values do not, but this is the fail-safe path.)
    BadCString,
    /// `audit_open` returned `< 0` (e.g. no `CAP_AUDIT_WRITE`): the auditd leg
    /// was skipped.
    AuditUnavailable,
    /// `audit_log_acct_message` returned `< 0`.
    AuditWriteFailed,
}

impl From<NulError> for EmitError {
    fn from(_: NulError) -> Self {
        Self::BadCString
    }
}

// ===========================================================================
// auditd leg.
// ===========================================================================

/// Emit one record to native auditd via `audit_open` →
/// `audit_log_acct_message` → `audit_close`. Best effort (A3): if
/// `audit_open` fails (no `CAP_AUDIT_WRITE`, auditd not present) the leg is
/// skipped and `Err(AuditUnavailable)` is returned for the caller to ignore.
///
/// The username goes in `name`; the server ip in `addr`; the protocol+server
/// in `op` (IMPLEMENTATION_SPEC.md §8). `id` is [`NO_ID`] because no numeric
/// uid is known. `host`/`tty` are `NULL`.
pub fn auditd_emit(record: &AuditRecord) -> Result<(), EmitError> {
    let pgname = CString::new(PGNAME)?;
    let op = CString::new(record.auditd_op())?;
    let name = CString::new(sanitized_field(&record.user))?;
    // addr is optional; an empty server means "no server reached" → NULL.
    let addr = if record.server.is_empty() {
        None
    } else {
        Some(CString::new(sanitized_field(&record.server))?)
    };
    let addr_ptr = addr.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    let result = record.result.auditd_result();

    // SAFETY: `audit_open` takes no arguments and returns a fd or `< 0`.
    let fd = unsafe { audit_open() };
    if fd < 0 {
        return Err(EmitError::AuditUnavailable);
    }

    // SAFETY: all pointers are to live NUL-terminated `CString`s that outlive
    // the call (owned by locals above); `host`/`tty` are NULL, which libaudit
    // accepts; `fd` is the descriptor just opened. libaudit copies what it
    // needs before returning.
    let rc = unsafe {
        audit_log_acct_message(
            fd,
            AUDIT_USER_AUTH,
            pgname.as_ptr(),
            op.as_ptr(),
            name.as_ptr(),
            NO_ID,
            std::ptr::null(), // host
            addr_ptr,
            std::ptr::null(), // tty
            result,
        )
    };

    // SAFETY: `fd` is the descriptor returned by `audit_open` above and is not
    // used again after this close.
    unsafe { audit_close(fd) };

    if rc < 0 {
        return Err(EmitError::AuditWriteFailed);
    }
    Ok(())
}

// ===========================================================================
// syslog leg.
// ===========================================================================

/// Lazily initialize the syslog ident and `openlog` it exactly once, returning
/// the `'static` ident.
///
/// `openlog` keeps the ident POINTER rather than copying it
/// (IMPLEMENTATION_SPEC.md §8), so the `CString` must live for the rest of the
/// process. A `OnceLock<CString>` gives exactly that: it is never moved and
/// never dropped, so syslog will not later read freed memory. The `openlog`
/// call happens inside the initializer, so it runs once, before any `syslog`.
fn syslog_ident() -> &'static CString {
    static IDENT: OnceLock<CString> = OnceLock::new();
    IDENT.get_or_init(|| {
        // SYSLOG_IDENT is a static &str with no interior NUL.
        let ident = CString::new(SYSLOG_IDENT).expect("ident has no interior NUL");
        // SAFETY: `openlog` stores this pointer for the life of the process;
        // the OnceLock keeps the `CString` `'static` and never moves or drops
        // it, so the stored pointer stays valid for every later `syslog`.
        unsafe { openlog(ident.as_ptr(), LOG_PID | LOG_NDELAY, LOG_AUTHPRIV) };
        ident
    })
}

/// Emit one already-rendered record line to syslog (facility `LOG_AUTHPRIV`),
/// at `LOG_INFO` for a success and `LOG_WARNING` otherwise. Best effort (A3).
///
/// FORMAT-STRING SAFETY: `line` is passed as the single `%s` ARGUMENT with a
/// literal `"%s"` format (see [`SYSLOG_FMT`]); it is never the format string,
/// so a `%n`/`%s` inside the (user-influenced) username cannot be interpreted
/// by `printf`.
pub fn syslog_emit(record: &AuditRecord) -> Result<(), EmitError> {
    // Ensure openlog ran once with a 'static ident before we log.
    let _ident = syslog_ident();

    let line = CString::new(record.render())?;
    let priority = if record.result.is_success() {
        LOG_INFO
    } else {
        LOG_WARNING
    };

    // SAFETY: `SYSLOG_FMT` is a NUL-terminated `"%s"` literal; `line` is a live
    // NUL-terminated `CString` passed as the single vararg matching that one
    // `%s`. No user-controlled bytes are ever in the format position.
    unsafe {
        syslog(
            priority,
            SYSLOG_FMT.as_ptr().cast::<c_char>(),
            line.as_ptr(),
        );
    }
    Ok(())
}

/// Belt-and-braces: strip any interior NUL before a metadata string becomes a
/// `CString` for the auditd leg. The record's `render()` path already replaces
/// control bytes (NUL is one) with `_`, but the auditd leg formats raw fields,
/// so this keeps `CString::new` from failing on a hostile embedded NUL.
fn sanitized_field(s: &str) -> String {
    s.chars().map(|c| if c == '\0' { '_' } else { c }).collect()
}

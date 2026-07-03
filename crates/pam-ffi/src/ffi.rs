#![allow(unsafe_code)]
//! The libpam FFI shim — the ONLY file in this crate (and, together with the
//! audit crate's libaudit/syslog shim, in the whole workspace) that may
//! contain `unsafe` (CLAUDE.md rule 2; SPEC_AMENDMENTS.md A2).
//!
//! Everything here is deliberately close to zero logic: it declares the
//! Linux-PAM ABI by hand (no bindgen — IMPLEMENTATION_SPEC.md §2), converts
//! C pointers to and from checked Rust types, and calls libpam. All
//! authentication *decisions* live in the safe modules (`flow`,
//! `conversation`, `options`, the crate root).
//!
//! The exported `pam_sm_*` entry points also live here (the `no_mangle`
//! export is itself an operation the memory-safety lint guards) and each one
//! wraps its body in `catch_unwind`, mapping a caught panic to
//! `PAM_AUTHINFO_UNAVAIL` — no panic ever crosses the FFI boundary
//! (CLAUDE.md rule 10; the workspace pins `panic = "unwind"`).
//!
//! Secret handling at this boundary (CLAUDE.md rule 3/8; IMPLEMENTATION_SPEC
//! §7): the authtok PAM hands us is copied into a zeroizing
//! [`secrets::SecretString`]; PAM's own buffer is left alone (its lifetime is
//! PAM's responsibility). Conversation responses are malloc'd by the
//! application's conversation function and may contain a password: each
//! response string is copied into a `SecretString`, then its malloc'd bytes
//! are wiped with volatile writes before `libc::free`.
//!
//! Per SPEC_AMENDMENTS.md A2 this module also hosts the two libc hardening
//! calls: `prctl(PR_SET_DUMPABLE, 0)` and best-effort `mlock` of our
//! credential copy. An `mlock` failure is hardening degradation, never an
//! authentication error.

use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use secrets::SecretString;

use crate::pam_codes;

// ===========================================================================
// Linux-PAM constants (from /usr/include/security/_pam_types.h), by hand.
// Return codes live in `crate::pam_codes` (they are part of the safe API);
// the C-side item/style/limit constants live here.
// ===========================================================================

/// Item types for `pam_get_item` / `pam_set_item`.
#[allow(dead_code)] // the full set is declared for ABI completeness
pub(crate) mod item {
    use core::ffi::c_int;

    pub const PAM_SERVICE: c_int = 1;
    pub const PAM_USER: c_int = 2;
    pub const PAM_TTY: c_int = 3;
    pub const PAM_RHOST: c_int = 4;
    pub const PAM_CONV: c_int = 5;
    pub const PAM_AUTHTOK: c_int = 6;
    pub const PAM_OLDAUTHTOK: c_int = 7;
    pub const PAM_RUSER: c_int = 8;
}

/// Conversation message styles.
#[allow(dead_code)] // the full set is declared for ABI completeness
pub(crate) mod style {
    use core::ffi::c_int;

    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_PROMPT_ECHO_ON: c_int = 2;
    pub const PAM_ERROR_MSG: c_int = 3;
    pub const PAM_TEXT_INFO: c_int = 4;
}

/// Conversation limits.
pub(crate) const PAM_MAX_NUM_MSG: usize = 32;
pub(crate) const PAM_MAX_MSG_SIZE: usize = 512;
#[allow(dead_code)] // ABI completeness; responses are copied, never sized by us
pub(crate) const PAM_MAX_RESP_SIZE: usize = 512;

// ===========================================================================
// ABI types
// ===========================================================================

/// Opaque `pam_handle_t`.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

/// A copyable, non-null-checked wrapper for the handle libpam passed to this
/// call. Safe modules hold and pass this around; only functions in this file
/// ever look inside it. (Also keeps raw pointers out of every safe-module
/// signature, so no safe function can be handed an arbitrary pointer.)
#[derive(Clone, Copy)]
pub(crate) struct Pam(*mut PamHandle);

/// `struct pam_message`.
#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

/// `struct pam_response`. `resp` is malloc'd by the conversation and owned by
/// the caller after the conversation returns; it may contain a password.
#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

/// The conversation callback:
/// `int (*conv)(int num_msg, const struct pam_message **msg,
///              struct pam_response **resp, void *appdata_ptr)`.
type ConvFn = unsafe extern "C" fn(
    c_int,
    *const *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

/// `struct pam_conv`, retrieved via `pam_get_item(pamh, PAM_CONV, ..)`.
#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

extern "C" {
    fn pam_get_user(
        pamh: *mut PamHandle,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    #[allow(dead_code)] // declared for ABI completeness; nothing is set yet
    fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    /// Linux-PAM extension: returns the existing PAM_AUTHTOK item, or prompts
    /// (echo off, storing the result as the item) when none is available.
    fn pam_get_authtok(
        pamh: *mut PamHandle,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

// ===========================================================================
// Exported PAM entry points (IMPLEMENTATION_SPEC.md §7)
// ===========================================================================

/// `pam_sm_authenticate`: gather inputs at the boundary, then hand off to the
/// safe `crate::sm_authenticate`. A caught panic is `PAM_AUTHINFO_UNAVAIL`.
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let args = module_args(argc, argv);
        crate::sm_authenticate(Pam(pamh), flags, &args)
    }))
    .unwrap_or(pam_codes::AUTHINFO_UNAVAIL)
}

/// `pam_sm_setcred`: this module manages no credentials — `PAM_SUCCESS`
/// (IMPLEMENTATION_SPEC.md §7 return-code table).
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    catch_unwind(crate::sm_setcred).unwrap_or(pam_codes::AUTHINFO_UNAVAIL)
}

/// `pam_sm_acct_mgmt`: account policy is NPS's job — `PAM_IGNORE`
/// (IMPLEMENTATION_SPEC.md §7 return-code table).
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    catch_unwind(crate::sm_acct_mgmt).unwrap_or(pam_codes::AUTHINFO_UNAVAIL)
}

/// Copy the pam.d module arguments into owned strings. Module options are
/// operator-supplied configuration, not network input; an undecodable entry
/// is skipped (the safe options parser treats anything unknown as
/// ignore-with-debug-log).
fn module_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    if argv.is_null() || argc <= 0 {
        return Vec::new();
    }
    let count = argc as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: libpam passes an array of `argc` valid pointers, each to a
        // NUL-terminated string, live for the duration of this call.
        let p = unsafe { *argv.add(i) };
        if p.is_null() {
            continue;
        }
        // SAFETY: `p` is a valid NUL-terminated C string (see above); the
        // bytes are copied before this call returns.
        let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
        if let Ok(s) = core::str::from_utf8(bytes) {
            out.push(s.to_owned());
        }
    }
    out
}

// ===========================================================================
// Safe wrappers over libpam
// ===========================================================================

/// Fetch (prompting if necessary, via libpam's default prompt) the user name.
/// Fails closed on any libpam error, a null result, an undecodable name, or
/// an empty name.
pub(crate) fn get_user(pam: Pam) -> Result<String, i32> {
    if pam.0.is_null() {
        return Err(pam_codes::SYSTEM_ERR);
    }
    let mut user: *const c_char = ptr::null();
    // SAFETY: `pam.0` is the live handle libpam passed to this invocation;
    // `user` is a valid out-pointer; a null prompt selects libpam's default.
    let ret = unsafe { pam_get_user(pam.0, &mut user, ptr::null()) };
    if ret != pam_codes::SUCCESS {
        return Err(ret);
    }
    if user.is_null() {
        return Err(pam_codes::USER_UNKNOWN);
    }
    // SAFETY: libpam returned a NUL-terminated string it owns; the bytes are
    // copied before this call returns. The user name is not a secret.
    let bytes = unsafe { CStr::from_ptr(user) }.to_bytes();
    match core::str::from_utf8(bytes) {
        Ok(name) if !name.is_empty() => Ok(name.to_owned()),
        _ => Err(pam_codes::USER_UNKNOWN),
    }
}

/// Copy a PAM-owned authtok string into a zeroizing buffer. PAM's own buffer
/// is NOT wiped or freed — its lifetime is PAM's (IMPLEMENTATION_SPEC.md §7).
///
/// # Safety
/// `p` must be a non-null pointer to a NUL-terminated string that stays live
/// for the duration of this call.
unsafe fn copy_pam_authtok(p: *const c_char) -> Result<SecretString, i32> {
    let bytes = CStr::from_ptr(p).to_bytes();
    match core::str::from_utf8(bytes) {
        Ok(s) => Ok(SecretString::from_text(s)),
        // An undecodable token can never match a credential: deny.
        Err(_) => Err(pam_codes::AUTH_ERR),
    }
}

/// The authtok via `pam_get_authtok`: returns the existing PAM_AUTHTOK item
/// if an earlier module collected one, otherwise prompts echo-off with
/// libpam's default password prompt (spec §7: prompt only when not already
/// available). `Ok(None)` is a null authtok.
pub(crate) fn get_authtok_prompting(pam: Pam) -> Result<Option<SecretString>, i32> {
    if pam.0.is_null() {
        return Err(pam_codes::SYSTEM_ERR);
    }
    let mut tok: *const c_char = ptr::null();
    // SAFETY: live handle; valid out-pointer; null prompt = libpam default.
    let ret = unsafe { pam_get_authtok(pam.0, item::PAM_AUTHTOK, &mut tok, ptr::null()) };
    if ret != pam_codes::SUCCESS {
        return Err(ret);
    }
    if tok.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null NUL-terminated string owned by PAM, live for the call.
    unsafe { copy_pam_authtok(tok) }.map(Some)
}

/// The authtok strictly from the PAM_AUTHTOK item — never prompts
/// (`use_first_pass`). `Ok(None)` when no earlier module stored one.
pub(crate) fn get_authtok_item(pam: Pam) -> Result<Option<SecretString>, i32> {
    if pam.0.is_null() {
        return Err(pam_codes::SYSTEM_ERR);
    }
    let mut itemp: *const c_void = ptr::null();
    // SAFETY: live handle; valid out-pointer.
    let ret = unsafe { pam_get_item(pam.0.cast_const(), item::PAM_AUTHTOK, &mut itemp) };
    if ret != pam_codes::SUCCESS {
        return Err(ret);
    }
    if itemp.is_null() {
        return Ok(None);
    }
    // SAFETY: a non-null PAM_AUTHTOK item is a NUL-terminated string owned by
    // PAM, live for the call.
    unsafe { copy_pam_authtok(itemp.cast::<c_char>()) }.map(Some)
}

/// Run the application's conversation with `messages` (style, text) pairs and
/// return one optional reply per message.
///
/// Every malloc'd reply string is copied into a zeroizing [`SecretString`],
/// then its bytes are wiped with volatile writes and freed; the response
/// array itself is freed as well (Linux-PAM conversation ownership contract).
pub(crate) fn converse(
    pam: Pam,
    messages: &[(c_int, &str)],
) -> Result<Vec<Option<SecretString>>, i32> {
    if pam.0.is_null() {
        return Err(pam_codes::SYSTEM_ERR);
    }
    if messages.is_empty() || messages.len() > PAM_MAX_NUM_MSG {
        return Err(pam_codes::CONV_ERR);
    }

    let mut itemp: *const c_void = ptr::null();
    // SAFETY: live handle; valid out-pointer.
    let ret = unsafe { pam_get_item(pam.0.cast_const(), item::PAM_CONV, &mut itemp) };
    if ret != pam_codes::SUCCESS || itemp.is_null() {
        return Err(pam_codes::CONV_ERR);
    }
    // SAFETY: the PAM_CONV item is a `struct pam_conv` owned by libpam, live
    // for the duration of this call.
    let conv = unsafe { &*itemp.cast::<PamConv>() };
    let Some(conv_fn) = conv.conv else {
        return Err(pam_codes::CONV_ERR);
    };

    // Message texts: NUL-free and within PAM_MAX_MSG_SIZE (the safe
    // conversation layer clamps; this is the fail-closed backstop).
    let mut texts: Vec<CString> = Vec::with_capacity(messages.len());
    for (_, text) in messages {
        if text.len() >= PAM_MAX_MSG_SIZE {
            return Err(pam_codes::CONV_ERR);
        }
        texts.push(CString::new(*text).map_err(|_| pam_codes::CONV_ERR)?);
    }
    let msgs: Vec<PamMessage> = messages
        .iter()
        .zip(&texts)
        .map(|(&(msg_style, _), text)| PamMessage {
            msg_style,
            msg: text.as_ptr(),
        })
        .collect();
    // Linux-PAM convention: an array of num_msg pointers (each element also
    // points into one contiguous block, which keeps the Solaris reading of
    // the ABI working too).
    let msg_ptrs: Vec<*const PamMessage> = msgs.iter().map(ptr::from_ref).collect();

    let mut resp: *mut PamResponse = ptr::null_mut();
    // SAFETY: `msg_ptrs` holds messages.len() valid pointers that outlive the
    // call; `resp` is a valid out-pointer; appdata_ptr is passed through
    // untouched per the pam_conv contract.
    let ret = unsafe {
        conv_fn(
            messages.len() as c_int,
            msg_ptrs.as_ptr(),
            &mut resp,
            conv.appdata_ptr,
        )
    };
    if ret != pam_codes::SUCCESS {
        if !resp.is_null() {
            // Defensive: a conversation that fails must not return responses,
            // but if one did, wipe and free them rather than leak a password.
            // SAFETY: non-null `resp` is a malloc'd array of messages.len()
            // entries per the conversation ABI.
            unsafe { wipe_and_free_responses(resp, messages.len()) };
        }
        return Err(pam_codes::CONV_ERR);
    }
    if resp.is_null() {
        return Err(pam_codes::CONV_ERR);
    }

    let mut out: Vec<Option<SecretString>> = Vec::with_capacity(messages.len());
    let mut decode_failed = false;
    for i in 0..messages.len() {
        // SAFETY: `resp` is a malloc'd array of messages.len() pam_response
        // entries (conversation ABI); index `i` is in bounds.
        let p = unsafe { (*resp.add(i)).resp };
        if p.is_null() {
            out.push(None);
            continue;
        }
        // SAFETY: each non-null `resp` is a NUL-terminated malloc'd string we
        // now own. It may contain a password: copy into a zeroizing buffer...
        let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
        match core::str::from_utf8(bytes) {
            Ok(s) => out.push(Some(SecretString::from_text(s))),
            Err(_) => decode_failed = true,
        }
        // ...then wipe the malloc'd bytes and free them.
        // SAFETY: `p` is the same live malloc'd string; not used again after.
        unsafe { wipe_and_free_string(p) };
    }
    // SAFETY: the response array itself is one malloc'd block we own; every
    // element's string has already been freed above.
    unsafe { libc::free(resp.cast()) };

    if decode_failed {
        // `out` (with any already-copied secrets) drops and zeroizes here.
        return Err(pam_codes::CONV_ERR);
    }
    Ok(out)
}

/// Overwrite a NUL-terminated malloc'd string with zeros (volatile, so the
/// wipe is not optimized away) and free it.
///
/// # Safety
/// `p` must be a valid, NUL-terminated, malloc'd string owned by the caller,
/// not used again afterwards.
unsafe fn wipe_and_free_string(p: *mut c_char) {
    let len = libc::strlen(p);
    for i in 0..len {
        ptr::write_volatile(p.add(i), 0);
    }
    libc::free(p.cast());
}

/// Wipe and free every response string in a conversation response array, then
/// the array itself.
///
/// # Safety
/// `resp` must be a malloc'd array of `n` `pam_response` entries owned by the
/// caller, not used again afterwards.
unsafe fn wipe_and_free_responses(resp: *mut PamResponse, n: usize) {
    for i in 0..n {
        let p = (*resp.add(i)).resp;
        if !p.is_null() {
            wipe_and_free_string(p);
        }
    }
    libc::free(resp.cast());
}

// ===========================================================================
// libc hardening (SPEC_AMENDMENTS.md A2)
// ===========================================================================

/// Disable core dumps / non-privileged ptrace attachment for this process:
/// `prctl(PR_SET_DUMPABLE, 0)`. Best effort; a failure changes nothing about
/// the authentication decision.
pub(crate) fn harden_process() {
    // SAFETY: prctl with PR_SET_DUMPABLE takes integer arguments only; no
    // pointers, no memory is touched.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Best-effort `mlock` of a credential buffer so it cannot be swapped out.
/// Returns whether the lock succeeded; failure is logged by the caller (audit
/// backend, phase 7) and is NOT fatal — hardening, not an auth decision (A2).
pub(crate) fn mlock_best_effort(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    // SAFETY: `buf` is a live allocation for the duration of the call; mlock
    // only pins pages, it does not mutate or retain the memory.
    unsafe { libc::mlock(buf.as_ptr().cast(), buf.len()) == 0 }
}

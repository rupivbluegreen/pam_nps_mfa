//! dlopen smoke test: the built cdylib exports the three `pam_sm_*` symbols
//! and the trivial entry points return their §7 table codes.
//!
//! The primary proof of behavior is the FakeTransport flow suite
//! (`flow_return_codes.rs`); this test only proves symbol export and the
//! catch_unwind'd trivial entries. If the cdylib cannot be located (custom
//! CARGO_TARGET_DIR layouts, etc.) the test SKIPS rather than flaking the
//! gate; set `PAM_NPS_REQUIRE_DLOPEN=1` to make a missing .so a hard failure.
//! (Equivalent manual check: `nm -D target/debug/libpam_nps_mfa.so | grep
//! pam_sm_` must list pam_sm_authenticate, pam_sm_setcred, pam_sm_acct_mgmt.)
#![allow(unsafe_code)] // test-only dlopen; src/ keeps the crate-wide deny

use std::path::PathBuf;

fn cdylib_candidates() -> Vec<PathBuf> {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("target")
        });
    ["debug", "release"]
        .iter()
        .map(|profile| target_dir.join(profile).join("libpam_nps_mfa.so"))
        .collect()
}

#[test]
fn exported_pam_symbols_resolve_and_trivial_entries_behave() {
    let candidates = cdylib_candidates();
    let Some(path) = candidates.iter().find(|p| p.exists()) else {
        if std::env::var_os("PAM_NPS_REQUIRE_DLOPEN").is_some() {
            panic!("libpam_nps_mfa.so not found; looked at {candidates:?}");
        }
        eprintln!(
            "SKIP dlopen smoke test: libpam_nps_mfa.so not found at {candidates:?}; \
             the FakeTransport flow suite is the authoritative gate"
        );
        return;
    };

    type PamSmFn = unsafe extern "C" fn(
        *mut core::ffi::c_void,
        core::ffi::c_int,
        core::ffi::c_int,
        *const *const core::ffi::c_char,
    ) -> core::ffi::c_int;

    // SAFETY: loading our own just-built module and calling its exported
    // entry points, which are documented to tolerate a null handle by
    // failing closed (and are catch_unwind-wrapped).
    unsafe {
        let lib = libloading::Library::new(path).expect("dlopen libpam_nps_mfa.so");
        let authenticate: libloading::Symbol<'_, PamSmFn> = lib
            .get(b"pam_sm_authenticate\0")
            .expect("pam_sm_authenticate exported");
        let setcred: libloading::Symbol<'_, PamSmFn> = lib
            .get(b"pam_sm_setcred\0")
            .expect("pam_sm_setcred exported");
        let acct_mgmt: libloading::Symbol<'_, PamSmFn> = lib
            .get(b"pam_sm_acct_mgmt\0")
            .expect("pam_sm_acct_mgmt exported");

        // §7 table: pam_sm_setcred → PAM_SUCCESS (0);
        //           pam_sm_acct_mgmt → PAM_IGNORE (25).
        assert_eq!(setcred(std::ptr::null_mut(), 0, 0, std::ptr::null()), 0);
        assert_eq!(acct_mgmt(std::ptr::null_mut(), 0, 0, std::ptr::null()), 25);
        // A null handle must fail CLOSED: any deny code, never PAM_SUCCESS.
        assert_ne!(
            authenticate(std::ptr::null_mut(), 0, 0, std::ptr::null()),
            0
        );
    }
}

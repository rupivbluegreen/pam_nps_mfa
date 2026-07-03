fn main() {
    // Native auditd emission uses libaudit (`audit_open`,
    // `audit_log_acct_message`, `audit_close`), hand-declared in
    // `src/ffi.rs` (IMPLEMENTATION_SPEC.md §8/§9). Link it so
    // `cargo test -p audit` and the final cdylib resolve those symbols.
    // syslog (`openlog`/`syslog`/`closelog`) lives in libc, already linked.
    println!("cargo:rustc-link-lib=audit");
}

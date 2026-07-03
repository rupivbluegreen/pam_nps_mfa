fn main() {
    // Link directives per IMPLEMENTATION_SPEC.md section 9. The libpam and
    // libaudit bindings are hand-declared in the FFI submodules, not
    // generated, so the unsafe surface stays reviewable.
    println!("cargo:rustc-link-lib=pam");
    println!("cargo:rustc-link-lib=audit");
}

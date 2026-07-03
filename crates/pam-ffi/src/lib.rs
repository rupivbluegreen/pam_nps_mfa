#![deny(unsafe_code)]
// unsafe is permitted ONLY in the ffi submodule (CLAUDE.md rule 2): the
// hand-declared libpam bindings plus prctl/mlock hardening (amendment A2).

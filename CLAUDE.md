# CLAUDE.md

Guidance for any coding agent working in this repository. Read this first, then `IMPLEMENTATION_SPEC.md`, then `TEST_VECTORS.md`. If anything you are about to write conflicts with these files, stop and ask rather than guessing.

## What this project is

`pam_nps_mfa` is a PAM authentication module written in Rust. It turns a Linux host into a hardened RADIUS client for Microsoft NPS, so an NPS deployment with the Entra MFA extension can require a second factor on local and SSH logins. It supports two credential protocols selected by configuration: PAP and MSCHAPv2. MSCHAPv2 is the primary target. License is MIT. First platform is RHEL9, others follow once RHEL is stable.

This runs inside the privileged monitor of sshd and inside the address space of sudo, su, and login. Treat every line as security-critical. A memory bug here is root. A logic bug here is an authentication bypass.

## Hard rules, no exceptions

1. Fail closed. No code path returns `PAM_SUCCESS` as a result of an error, a timeout, a parse failure, or a failed integrity check. When in doubt, deny.

2. `#![forbid(unsafe_code)]` in every crate except two clearly named FFI submodules: the libpam shim and the libaudit shim. All `unsafe` lives there and nowhere else. Keep those shims as close to zero logic as possible.

3. No secret in any log, at any level, ever. Passwords, NT hashes, DES keys, the RADIUS shared secret, and derived keystream material never reach a log line, a panic message, or a `Debug` output. Secret types must not implement a `Debug` or `Display` that reveals their contents.

4. Verify crypto against the vectors before calling a module done. If a value in `TEST_VECTORS.md` does not match your output, the bug is in your code. Fix the code. Never edit a vector to make a test pass.

5. No protocol negotiation. The mode is read from config once and fixed for the process. When configured for MSCHAPv2, the module never emits a PAP request under any circumstance. There is no downgrade path a network peer can trigger.

6. MSCHAPv2 mutual authentication is mandatory. On Access-Accept, verify the server MS-CHAP2-Success authenticator and deny the login on mismatch even though the packet said accept. Compare it in constant time.

7. Constant-time comparison for every authenticator and MAC check, using `subtle`. No `==` on secret or integrity values.

8. Zeroize all key material on drop. Wipe the NT hash the moment the NT response and the Success check are done.

9. Do not use OpenSSL. Use the RustCrypto primitives named in the spec. MD4 and single DES are present on purpose because MSCHAPv2 requires them. Do not try to "upgrade" or remove them.

10. Panics must never cross the FFI boundary. Wrap each exported `pam_sm_*` function body in `catch_unwind` and map a panic to a deny return code.

11. Reject empty passwords, and honor `PAM_DISALLOW_NULL_AUTHTOK`.

12. Validate file permissions before trusting file contents. If the config file or any secret file is readable by group or other, refuse to run and log a critical event. A permissive secret is a hard failure, not a warning.

13. Do not invent configuration keys, attribute type numbers, or wire layouts. They are pinned in the spec. If the spec is missing something, ask.

14. Bind every response to its request. Accept a response only if the identifier, the source address and port, the Response Authenticator, and the Message-Authenticator all match the outstanding request. Discard anything else and keep waiting until timeout.

15. Bound all parsing. A malformed attribute or length denies the authentication. It never panics, never allocates from an unbounded attacker-supplied length, and never returns success.

16. Do not fail over on silence. Fail over to the next server only on an explicit transport error such as ICMP unreachable or connection refused. A silent server may already have issued an MFA push, so sending the same authentication to a second server would trigger a second push and a race between two approvals. On silence, wait out the MFA timeout on the current server, then deny.

17. No mutable global state. The module may be called concurrently, so all state stays local to the invocation.

18. A randomness failure denies. If `getrandom` fails when generating a Request Authenticator or a challenge, deny the authentication. Never fall back to weak or zero material.

## Build, test, lint loop

Run this loop every cycle. Do not report a phase complete until it is green.

```
cargo build --release
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
cargo deny check
```

The `md4` and `des` crates from RustCrypto are maintained and have no known CVE, so cargo-audit will most likely pass clean and you do not need to invent an exception for them. If a policy in `deny.toml` bans weak primitives, or an informational advisory does appear, record the specific ID with a comment pointing at this file and keep the crates. MSCHAPv2 mandates them. Do not remove them to make a lint pass.

The RADIUS response parser has a fuzz target. On nightly:

```
cargo fuzz run radius_response -- -max_total_time=120
```

## Phase order

Build in this order. Each phase has a gate that must pass before moving on. Do not start a later phase to "unblock" an earlier one.

1. RADIUS codec. Attribute encode and decode, Request Authenticator generation, Message-Authenticator compute and verify, Response Authenticator compute and verify, response-to-request binding. Gate: the RADIUS vectors in `TEST_VECTORS.md` pass, including the negative test where a flipped bit denies.

2. MSCHAPv2 engine. NT hash, challenge hash, NT response, Success authenticator generation and verification, MS-CHAP-Error parsing. Gate: all RFC 2759 vectors pass.

3. PAP engine. User-Password hiding, and the Access-Challenge plus State round-trip for TOTP. Gate: the PAP vector passes.

4. Config and secrets. Permission checks, zeroizing wrappers, sample config parses, permissive files are refused. Gate: rejects a 0644 secret file, parses the sample.

5. PAM FFI shim. Export the three symbols, fetch user and authtok, run the conversation, map return codes, `catch_unwind`. Gate: loads and behaves under `pamtester` against a stub backend.

6. Transport. Socket handling, bounded timeout, retransmission that respects NPS duplicate suppression, ordered server failover. Gate: completes an exchange against a local fake RADIUS responder.

7. Audit. Native auditd emission plus syslog, selectable by config. Gate: events appear in `ausearch` and in the journal with no secret fields.

8. Packaging. SELinux policy module and RPM spec. Gate: installs on RHEL9, runs with SELinux enforcing.

9. Real NPS. Manual integration against NPS with the Entra MFA extension. This is outside the agent loop and is done by a human. Do not claim the project is finished before this passes.

## Definition of done

All vectors pass. Clippy is clean with warnings denied. `cargo audit` and `cargo deny` are clean, apart from any documented MD4 or DES exception if one turns out to be needed. The fuzzer runs clean for the configured duration. The module loads, denies, and accepts correctly against a fake responder. A human has run it against a real NPS. Not before.

## Things that will tempt you and are wrong

Skipping the Success authenticator check because auth already "worked" on Accept. That is the impersonation gap. Do not skip it.

Returning `PAM_SUCCESS` when the server is unreachable so the login is not blocked. That is fail-open. Unreachable is `PAM_AUTHINFO_UNAVAIL` and the login is denied.

Reaching for OpenSSL because MD4 is awkward. It is not awkward in RustCrypto. Use `md4`.

Adding a PAP fallback when MSCHAPv2 fails. There is no fallback. Different protocol, fixed at config.

Logging the packet at debug level to help troubleshooting. The packet contains credential material. Log metadata only, never bytes of the credential attributes.

Building a silent block while the MFA push is outstanding. The user has no idea their phone is waiting and will think the session hung. In MSCHAPv2 push mode, send a `PAM_TEXT_INFO` message telling the user to approve the sign-in on their device before you wait on the socket.

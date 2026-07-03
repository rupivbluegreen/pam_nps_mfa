# pam_nps_mfa

A PAM authentication module, written in Rust, that turns a Linux host into a
hardened RADIUS client for Microsoft NPS — so an NPS deployment with the Entra
MFA extension can require a second factor on local and SSH logins.

**Status: pre-release, under active development. Phase 9 (validation against a
real NPS with the Entra MFA extension) has NOT been completed. Do not deploy.**

## What it does

- Speaks RADIUS (RFC 2865/3579) to NPS on the authentication path.
- Two credential protocols, fixed by configuration with no runtime
  negotiation or fallback: **MSCHAPv2** (primary; push/phone second factor,
  cleartext password never leaves the host) and **PAP** (full Entra MFA method
  set including TOTP via Access-Challenge/State).
- Fail-closed everywhere: any error, timeout, malformed response, or failed
  integrity check denies the login.
- Post-BlastRADIUS integrity: Message-Authenticator on every request, strict
  verification of Response Authenticator and response Message-Authenticator,
  full response-to-request binding.
- MSCHAPv2 mutual authentication is mandatory: the server's MS-CHAP2-Success
  authenticator is verified in constant time, and a mismatch denies even on
  Access-Accept.
- Structured audit records (native auditd and/or syslog), never containing
  secret material.

First platform: RHEL9. License: MIT.

## Packages

Pre-built packages are attached to [GitHub releases](https://github.com/rupivbluegreen/pam_nps_mfa/releases)
(all pre-release until phase 9 passes — verify against the attached
`SHA256SUMS` before installing):

| Platform | Package |
|---|---|
| RHEL 9 / AlmaLinux 9 / Rocky Linux 9 / CentOS Stream 9 | `el9` RPM (primary platform) |
| RHEL 10 family / CentOS Stream 10 | `el10` RPM |
| Fedora 42 | `fc42` RPM |
| Ubuntu 22.04 LTS / 24.04 LTS | `.deb` (`+ubuntu22.04` / `+ubuntu24.04`) |

Only the RHEL9 family has been through the phase-8 packaging gate; the other
targets are build- and install-verified in CI but otherwise untested. The
Ubuntu `.deb` ships no SELinux policy (not applicable on Ubuntu) and no
AppArmor profile — the confinement story there is the platform default.
CentOS Stream installs the el9/el10 RPMs, which CI verifies in fresh Stream
containers at release time.

## Security notes you must read before deploying

- **This code runs inside the privileged monitor of sshd and the address space
  of sudo, su, and login.** Treat every deployment decision accordingly.
- **IPsec is a required compensating control, not a suggestion.** MSCHAPv2
  reduces to a DES-56 keyspace for an on-path observer, and PAP's hiding is
  only as strong as the shared secret. NPS supports neither RadSec nor DTLS,
  so an ESP tunnel between host and NPS is the only acceptable transport.
- **Active Directory Protected Users cannot use MSCHAPv2** — the NTLM path it
  depends on is disabled for them. Confirm target accounts are not in
  Protected Users before committing to MSCHAPv2.
- **SSH public-key and GSSAPI authentication skip PAM entirely.** The shipped
  sshd configuration snippets (`KbdInteractiveAuthentication yes` plus an
  `AuthenticationMethods` value forcing the keyboard-interactive path) are
  required for accounts in scope, or the module is an open door.
- Keep a **break-glass local account** outside the RADIUS path so an NPS or
  network outage cannot lock every administrator out. Audit its use.

## Documentation

- [SECURITY_DESIGN.md](SECURITY_DESIGN.md) — threat model and security contract
- [IMPLEMENTATION_SPEC.md](IMPLEMENTATION_SPEC.md) — wire formats, config schema, PAM integration
- [TEST_VECTORS.md](TEST_VECTORS.md) — known-answer vectors (RFC 2759 §9.2 and deterministic RADIUS/PAP vectors)
- [SPEC_AMENDMENTS.md](SPEC_AMENDMENTS.md) — recorded deviations/additions to the spec
- [CLAUDE.md](CLAUDE.md) — rules for coding agents working in this repository

## Building

```
cargo build --release
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
cargo deny check
```

Requires `libpam` and `libaudit` development headers (`libpam0g-dev` and
`libaudit-dev` on Debian/Ubuntu; `pam-devel` and `audit-libs-devel` on RHEL).

# Spec Amendments

Recorded deviations from and additions to `IMPLEMENTATION_SPEC.md` /
`SECURITY_DESIGN.md`. Per CLAUDE.md rule 13, nothing here was invented
silently: A1 was approved by the project owner; A2–A6 are engineering
resolutions of internal spec ambiguities, recorded here so reviewers enforce
them rather than flag them. The owner can veto any of these.

## A1 — `probe_timeout` config key (owner-approved, 2026-07-03)

IMPLEMENTATION_SPEC §3 describes two-stage timing (a short transport probe
budget across the server list, then one long MFA-completion wait) but the §6
config schema had no key bounding the probe. New key:

```
probe_timeout 5    # seconds; per-server transport probe window
```

Semantics: for each server in configured order, send the Access-Request on a
connected UDP socket. If an explicit transport error (ICMP unreachable /
connection refused) arrives within `probe_timeout`, fail over to the next
server. If `probe_timeout` elapses in **silence**, that server is *committed*:
it alone absorbs the full `timeout` MFA wait (with `retries` identical-byte
retransmits), then the attempt is denied. Only one server ever enters the long
wait; the no-failover-on-silence rule (CLAUDE.md rule 16) is preserved.

Worst-case wall time ≈ `(N-1) * probe_timeout + timeout`. Size against sshd
`LoginGraceTime` with headroom.

## A2 — Placement of libc `unsafe` (syslog, prctl, mlock)

IMPLEMENTATION_SPEC §2 assigns libc for "syslog, mlock, prctl", but CLAUDE.md
rule 2 allows `unsafe` only in the two FFI shims. Resolution: the syslog FFI
(`openlog`/`syslog`/`closelog`) lives inside the **audit crate's FFI
submodule** (alongside libaudit); `prctl(PR_SET_DUMPABLE, 0)` and best-effort
`mlock` of credential buffers live inside the **pam-ffi crate's FFI
submodule**. There is no third unsafe location. `mlock` failure is logged and
non-fatal (hardening, not an authentication decision — rule 1 governs
success-from-error, not defense-in-depth degradation).

## A3 — Audit emission failure never changes the auth result

A failed `audit_log_acct_message` (e.g. missing CAP_AUDIT_WRITE) or syslog
error is best-effort reported via the other backend, and the PAM return code
is unaffected. Every attempt still tries to emit exactly one record per
configured backend.

## A4 — Reply-Message sanitization

Network-supplied Reply-Message text is stripped of control and non-printable
characters before it reaches the PAM conversation, to prevent terminal escape
injection at the login prompt. Multiple Reply-Message attributes concatenate
in order received.

## A5 — Probe socket uses `connect(2)`

The UDP client socket is `connect(2)`ed to the target server so that ICMP
port-unreachable / host-unreachable is delivered to userspace as an explicit
error (`ECONNREFUSED`/`EHOSTUNREACH`). This is the mechanism that
distinguishes "explicit transport error → fail over" from "silence → commit"
(rule 16). It also narrows the socket to the configured peer, complementing
the source-address check in response binding.

## A6 — Correlation id without a `uuid` dependency

IMPLEMENTATION_SPEC §2 pins the dependency set and does not include a `uuid`
crate. The audit `corr` field is generated as 16 bytes from `getrandom`
formatted as 32 hex characters. A `getrandom` failure here does not deny the
authentication (the id is not security material) but is never replaced by
weak randomness — the field is emitted as `corr=unavailable` instead.

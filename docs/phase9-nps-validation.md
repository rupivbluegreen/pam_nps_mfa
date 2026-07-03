# Phase 9 — Real-NPS Validation Checklist

**Status gate: the project is NOT "done" until every REQUIRED item below passes
on real RHEL9 hardware against a real Microsoft NPS with the Entra MFA
extension.** Packaging (phase 8) is a prerequisite, not the finish line. Nothing
in this file can be validated in CI, a container, or against the in-memory
transport fake — it is a human-driven checklist run on live infrastructure.

Do not sign off on partial results. Fail-closed is the design contract
(SECURITY_DESIGN §2): if an item is ambiguous, treat it as a FAIL.

---

## 0. Environment preconditions

- [ ] RHEL9 x86_64 host, SELinux **enforcing** (`getenforce` → `Enforcing`).
- [ ] Microsoft NPS reachable, with the **Entra (Azure AD) MFA extension**
      installed and a network policy that permits this host as a RADIUS client
      (matched by source IP **and** shared secret).
- [ ] **IPsec ESP transport** established between this host and NPS BEFORE any
      MSCHAPv2/PAP test (required control — see §5). Confirm with `ip xfrm state`
      / `ip xfrm policy` that RADIUS traffic to the NPS IP is inside the SA.
- [ ] Test accounts prepared in AD: at least one **in** Protected Users and one
      **not** in Protected Users; know each account's MFA method.
- [ ] `pam_nps_mfa` RPM installed from the phase-8 gate; `semodule -l | grep
      pam_nps_mfa` shows the policy loaded (the RPM %post loads it on an
      SELinux-enabled host).

---

## 1. Install / labeling sanity on the real host

- [ ] `ls -Z /usr/lib64/security/pam_nps_mfa.so` — module present, 0755 root:root.
- [ ] `ls -Z /etc/pam_nps/pam_nps.conf` — 0600 root:root **and** labeled
      `pam_nps_conf_t` (restorecon ran in %post).
- [ ] `ls -Z /etc/pam_nps/secret.d` — dir 0700 root:root, `pam_nps_conf_t`;
      each secret file 0600 root:root, `pam_nps_conf_t`.
- [ ] Loader rejects a permissive secret: `chmod 0640` a secret file, attempt a
      login, confirm **deny** + a critical audit event, then restore 0600.

---

## 2. Username matching — bare vs domain-qualified (IMPLEMENTATION_SPEC §5)

The User-Name attribute and the MSCHAPv2 challenge hash must use the
**byte-identical** string. A mismatch presents as "wrong password" even with the
correct password. Test BOTH forms against the real NPS and pin the one that
works for your directory:

- [ ] Bare account name (`user`).
- [ ] Domain-qualified `DOMAIN\user`.
- [ ] UPN form `user@realm`.
- [ ] Record which form NPS accepts; confirm the module sends that exact form in
      both User-Name and the challenge hash. Document the chosen form in the
      deployment runbook.

---

## 3. MSCHAPv2 path (default mode)

- [ ] **Access-Accept + MS-CHAP2-Success mutual auth**: a correct password with
      approved push yields `PAM_SUCCESS`, AND the module verifies the server's
      `S=` authenticator response in constant time. Deliberately confirm the
      verification is active (e.g. a lab NPS/proxy returning a tampered `S=` must
      **deny** even on an Accept). Skipping this check is an impersonation hole
      (SECURITY_DESIGN §9) — prove it is not skipped.
- [ ] Push approved on phone → `PAM_SUCCESS`.
- [ ] Push denied / timed out at NPS → `PAM_AUTH_ERR` (denied, not unavail).
- [ ] Wrong password → Access-Reject, `MS-CHAP-Error E=691` → `PAM_AUTH_ERR`.
- [ ] Expired password → `E=648` → clean deny with a "change it elsewhere"
      message (no CPW in v1).
- [ ] The `PAM_TEXT_INFO` "approve on your device" message reaches the SSH
      client before the wait (login does not appear to hang silently).

---

## 4. Protected Users constraint (SECURITY_DESIGN §9) — REQUIRED

- [ ] A **Protected Users** account attempting MSCHAPv2 **fails** (the group
      disables the NTLM path MSCHAPv2 needs). Confirm the failure is clean and
      the message is comprehensible.
- [ ] Confirm the intended real admin accounts are **not** in Protected Users,
      or have a separate primary-auth path. This is the 2 a.m.-incident landmine
      — validate it in daylight.

---

## 5. IPsec transport confirmed (REQUIRED control)

- [ ] Capture RADIUS traffic to NPS during an auth (`tcpdump host <nps>`): the
      RADIUS packets are inside **ESP**, not cleartext UDP/1812 on the wire.
- [ ] Deliberately break IPsec and confirm the deployment policy refuses to run
      MSCHAPv2/PAP on a bare wire (operational gate, not a module code path).

---

## 6. PAP path (Access-Challenge / State TOTP round-trip)

Only if PAP is in scope for the deployment (our own uses MSCHAPv2):

- [ ] Configure `protocol pap`, restart the service.
- [ ] First Access-Request → **Access-Challenge** with Reply-Message + State.
- [ ] The Reply-Message text (sanitized, amendment A4) is surfaced through the
      PAM conversation; the TOTP prompt appears.
- [ ] Second Access-Request echoes the **State** attribute unchanged and carries
      the TOTP → Access-Accept → `PAM_SUCCESS`.
- [ ] Multi-round challenge (if NPS issues more than one) keeps echoing State.
- [ ] Wrong TOTP → deny.

---

## 7. RADIUS integrity / RequireMsgAuth (SECURITY_DESIGN §5)

- [ ] With NPS **RequireMsgAuth enabled**: normal auth succeeds (module already
      sends Message-Authenticator on every request).
- [ ] With NPS **RequireMsgAuth disabled**: module still sends MA and still
      verifies the response MA; behavior unchanged.
- [ ] Strict mode (default `require_message_authenticator true`): a response
      **lacking** a Message-Authenticator is **rejected** (discarded, times out
      → `PAM_AUTHINFO_UNAVAIL`), not treated as an accept.
- [ ] Response binding: only a reply matching the outstanding request on
      identifier, source IP+port, Response Authenticator, and Message-
      Authenticator is accepted.

---

## 8. Failover & timeout timing (IMPLEMENTATION_SPEC §3, amendment A1)

- [ ] Two servers configured. First server returns ICMP unreachable (stop it) →
      module **fails over** to the second within `probe_timeout`.
- [ ] First server **silent** (drops packets, no ICMP) → module **commits** to
      it, absorbs the full `timeout` MFA wait, then denies. Does **not** fail
      over on silence (avoids double push).
- [ ] Worst-case wall time `(N-1)*probe_timeout + timeout` stays under
      `LoginGraceTime` with headroom (default 60s MFA vs 120s grace).
- [ ] All servers unreachable → `PAM_AUTHINFO_UNAVAIL` (distinct from
      `PAM_AUTH_ERR`).

---

## 9. sshd bypass closure (SECURITY_DESIGN §4) — REQUIRED

- [ ] With the shipped `sshd_config.snippet` applied, an in-scope account
      **cannot** log in with a public key alone — the keyboard-interactive PAM
      (NPS MFA) step is also required.
- [ ] GSSAPI auth is disabled / does not bypass PAM for in-scope accounts.
- [ ] Confirm `AuthenticationMethods` and `KbdInteractiveAuthentication yes`
      (+ `UsePAM yes`) are in effect (`sshd -T | grep -Ei
      'authenticationmethods|kbdinteractive|usepam'`).

---

## 10. Break-glass (SECURITY_DESIGN §11) — REQUIRED

- [ ] The local break-glass admin account logs in **while NPS is unreachable**
      (simulate an outage), proving admins are not locked out of every host.
- [ ] Break-glass login is outside the RADIUS path (its `Match` block does not
      invoke pam_nps_mfa.so).
- [ ] Break-glass use produces the expected **audit** trail (USER_AUTH + the
      authorized_keys/sudo watch).

---

## 11. Audit records (IMPLEMENTATION_SPEC §8)

- [ ] Every attempt emits exactly one record per configured backend.
- [ ] `ausearch -m USER_AUTH` shows the attempt with op/proto/server/user/result
      in standard fields; `aureport` parses it.
- [ ] **No secret material** anywhere in any record (password, NT hash, shared
      secret, credential bytes) — inspect success, denied, and unavail records.
- [ ] `corr=` correlation id ties request→outcome across auditd and syslog.
- [ ] Audit-emit failure (e.g. drop CAP_AUDIT_WRITE) does not change the PAM
      result (amendment A3).

---

## 12. SELinux enforcing (IMPLEMENTATION_SPEC §9)

- [ ] `getenforce` → `Enforcing` throughout the above tests.
- [ ] A full successful auth generates **no AVC denials**
      (`ausearch -m AVC -ts recent` is clean for sshd_t → radius_port_t,
      pam_nps_conf_t, and the audit socket).
- [ ] Temporarily set the domain permissive ONLY to diagnose an AVC, never as a
      shipped state — the module must run under a strictly `enforcing`,
      non-permissive `sshd_t`.

---

## Sign-off

- [ ] All REQUIRED items (§4, §5, §9, §10, plus §3 mutual-auth and §12) PASS on
      real hardware.
- [ ] Results, NPS policy names, chosen username form, and IPsec SA details
      recorded in the deployment runbook.

**Until this sheet is fully green on real hardware, pam_nps_mfa is not
production-ready and phase 9 is not complete.**

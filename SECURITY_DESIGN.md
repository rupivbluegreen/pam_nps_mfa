# pam_nps: Security Design and Threat Model

Working name (change before release): `pam_nps`. A PAM authentication module that turns a Linux host into a hardened RADIUS client for Microsoft NPS, so that an NPS deployment with the Entra MFA extension can gate local and SSH logins with a second factor.

Status: design for v1. Target platform RHEL9 first, other distributions after the RHEL path is stable. License MIT.

This document is the security contract for the project. If an implementation choice contradicts something here, this document wins until it is revised.

## 1. What the module is, and what it is not

The module speaks RADIUS to NPS on the authentication path. It supports two credential protocols, selected by configuration and fixed for the life of a process:

- PAP, which unlocks the full Entra MFA method set including TOTP and number matching. This mode exists for the wider open-source audience.
- MSCHAPv2, which restricts the second factor to push or phone but keeps the cleartext password off the wire. This is the mode our own deployment uses, on CISO instruction.

There is no protocol negotiation and no fallback between the two. The mode is read from config once and cannot be downgraded at runtime by anything on the network. A network attacker cannot strip MSCHAPv2 to force PAP, because the module will never emit a PAP request when configured for MSCHAPv2, and will fail closed instead.

The module is not an EAP supplicant. NPS EAP modes (PEAP, EAP-TLS) require a TLS-capable supplicant, which sshd and the PAM stack are not. Anyone who wants certificate-based primary auth should terminate that at a network access layer, not here. That boundary is deliberate and is documented so nobody files an issue asking for EAP-TLS in a PAM module.

## 2. Design principles

Everything below follows from five rules.

Fail closed. Any error, timeout, malformed response, failed integrity check, or unreachable server results in denied authentication. There is no code path where uncertainty produces success.

Minimize novel privileged code. The module runs inside the privileged monitor of sshd and inside the address space of sudo, su, and login. A memory-safety bug here is root, and a logic bug here is an auth bypass. We write in Rust, we forbid unsafe everywhere except one small FFI shim, and we keep the shim as close to zero logic as possible.

No secret outlives its use. Passwords, NT hashes, DES keys, shared secrets, and derived keystream material are wiped from memory the moment they are no longer needed, and are never written to logs, cores, or swap.

The network is hostile. Every byte that arrives from NPS is treated as attacker-controlled until it has passed integrity verification. The response parser is the primary remote attack surface and is hardened accordingly.

Auditability is a byproduct. Every authentication attempt produces a structured audit record with enough detail to reconstruct what happened, and with zero secret material in it.

## 3. Architecture

The crate is split so that the dangerous parts are small and isolated.

`pam-ffi` is the only place `unsafe` is allowed. It implements the C entry points that libpam calls (`pam_sm_authenticate`, `pam_sm_setcred`, and a benign `pam_sm_acct_mgmt`), converts the raw C pointers into checked Rust types, and immediately hands off to safe code. Every other crate carries `#![forbid(unsafe_code)]`.

`radius` builds and parses RADIUS packets, computes and verifies the Request Authenticator, Response Authenticator, and Message-Authenticator, and owns the socket handling. It has no knowledge of PAP or MSCHAPv2 beyond placing the attributes it is handed.

`mschapv2` implements RFC 2759 and the Microsoft vendor attributes: NT hash derivation, the challenge hash, the three-DES NT response, and, critically, verification of the server's Success authenticator for mutual authentication. It also parses MS-CHAP-Error so the module can report password-expired and lockout conditions correctly.

`pap` implements RFC 2865 User-Password hiding and the Access-Challenge and State round-trip used for TOTP.

`config` parses configuration, validates file permissions before trusting the contents, and refuses ambiguous input.

`secrets` provides zeroizing wrappers used by everything that touches key material.

`audit` emits structured records.

The build output is a single `.so`. Dependencies are limited to well-reviewed crates: the RustCrypto primitives (`md4`, `des`, `sha1`, `md-5`, `hmac`), `subtle` for constant-time comparison, `zeroize` for wiping, `getrandom` for randomness, and a minimal PAM binding. Using RustCrypto for MD4 and single DES is a deliberate choice: it avoids the OpenSSL 3 legacy-provider dance that plagues C implementations, and it keeps the broken-by-design primitives that MSCHAPv2 requires clearly quarantined in one place with a comment explaining why they are present.

## 4. Threat model

The assets worth protecting are the user's cleartext password, the NT hash (which is password equivalent), the RADIUS shared secret, and the integrity of the allow or deny decision itself.

The trust boundaries are three. Between the user and the module, the PAM conversation carries the password in process memory. Between the module and NPS, the RADIUS exchange crosses the network. Between NPS and Active Directory, primary authentication happens, which is outside our control.

The adversaries we design against:

A passive on-path observer who can capture RADIUS traffic. Against this adversary MSCHAPv2 leaks a crackable handshake (see section 9), and PAP leaks a keystream-hidden password whose safety depends on the shared secret. Neither is safe on a bare wire, which is why IPsec is a required compensating control, not a suggestion.

An active on-path or off-path attacker who tries to forge or replay a response to turn a deny into an accept. This is the BlastRADIUS class of attack. We defeat it with mandatory Message-Authenticator on every request, strict verification of both the Response Authenticator and the response Message-Authenticator, cryptographically random Request Authenticators, ephemeral randomized source ports, and strict binding of a response to its outstanding request.

An attacker who can send malformed packets to the client socket. Handled by the parser hardening in section 6. Any malformed input is a denied auth, never a crash and never an accept.

A local attacker who can read files or process memory. Handled by shared-secret file permissions, memory zeroization, swap and core-dump suppression, and never logging secrets.

An attacker who tries to bypass the module entirely. SSH public-key authentication and GSSAPI both skip the PAM auth stack completely. The module cannot fix this from inside PAM, so the deployment guide requires `AuthenticationMethods` and `KbdInteractiveAuthentication` settings that force the keyboard-interactive PAM path for any account in scope. This is called out loudly because it is the single most common way these deployments end up with an accidental open door.

## 5. RADIUS integrity, post-BlastRADIUS

Every Access-Request carries a Message-Authenticator attribute (RFC 3579), computed as HMAC-MD5 over the whole packet keyed by the shared secret, with the attribute field zeroed during computation and filled afterward. This is non-negotiable and is the same requirement NPS enforces when RequireMsgAuth is enabled. Assume the AD team will enable it, and behave correctly whether or not they do.

Every response is verified before a single attribute inside it is trusted. The Response Authenticator is recomputed and compared. The response Message-Authenticator, when present, is verified. By default the module runs in strict mode and rejects a response that lacks a Message-Authenticator; a documented, off-by-default relaxed mode exists only for legacy servers that genuinely cannot send it, and turning it on is logged as a security-relevant configuration event.

The Request Authenticator is sixteen bytes from the operating system CSPRNG on every request. It is never derived from time, never a counter, and never reused. For PAP this value seeds the keystream, so predictability there is fatal; for MSCHAPv2 it underpins replay resistance.

A response is accepted only if it matches the outstanding request on all of: packet identifier, source address and port equal to the configured server, a valid Response Authenticator, and a valid Message-Authenticator. Anything else is discarded. The UDP source port is ephemeral and OS-assigned so that an off-path attacker must guess the port as well as the identifier and authenticators.

## 6. The response parser

This is the crown jewels of attack surface, because it processes attacker-controllable bytes inside a privileged process. It is written to a stricter standard than the rest of the code.

Every attribute is bounds-checked. A RADIUS attribute is a type byte, a length byte, and a value of length minus two. A declared length below two, or a length that runs past the end of the buffer, is a fatal parse error. Vendor-specific attributes, which nest, are checked at both the outer and inner level. The header length field is checked against the number of bytes actually received. Packets larger than the RADIUS maximum are rejected before parsing. No allocation is ever sized directly from an attacker-supplied length without a hard cap.

Any parse failure denies the authentication. The parser has no path that returns success on questionable input. This parser is the first fuzz target (section 13), because a single missed bounds check here is the difference between a robust module and a remote crash in the SSH monitor.

## 7. Secrets and memory hygiene

Credential material lives in zeroizing buffers that wipe on drop: the password as received from PAM, its UTF-16LE re-encoding, the NT hash, the derived DES keys, the shared secret, and all keystream and MAC intermediates. The NT hash gets particular attention because it is password equivalent; it is wiped the instant the NT response and the Success-authenticator check are done.

Secret pages are locked to prevent them reaching swap, and the process requests that it not be dumpable so secrets cannot leak into a core file. In the common sshd case the monitor already sets a non-dumpable state, but the module does not rely on the host having done so.

No secret is ever logged, at any log level. The debug build has no mode that prints a password, an NT hash, a shared secret, or raw keystream. This is enforced by construction: the secret types do not implement a display or debug representation that reveals their contents.

## 8. Configuration and the shared secret

The RADIUS shared secret is a high-value credential and is treated like one. The configuration file that holds it must be owned by root and readable only by root. The module checks ownership and mode before reading the contents, and refuses to run if the file is group- or world-readable rather than silently proceeding. A permissive config is a hard failure, not a warning.

Per-host secrets are a first-class feature, because NPS identifies a RADIUS client by source address plus shared secret, and unique strong secrets per host limit the blast radius of any single host compromise. This fits a control plane that renders a signed policy bundle per host: the secret is just another rendered artifact. Secrets should be long random strings at the length limit NPS accepts, never dictionary words.

Configuration parsing fails closed on anything malformed or ambiguous. A half-parsed config never results in a usable authentication path.

## 9. MSCHAPv2 specifics and its honest weaknesses

The module generates both the Authenticator Challenge and the Peer Challenge from the CSPRNG, sixteen bytes each, fresh every attempt, never reused. It derives the NT hash as MD4 of the UTF-16LE password, computes the challenge hash as the first eight bytes of SHA1 over peer challenge, authenticator challenge, and username, and produces the twenty-four-byte NT response as three DES encryptions of that challenge hash under the NT hash split into three seven-byte keys.

On Access-Accept the module verifies the server's Success authenticator per RFC 2759 and compares it in constant time using `subtle`. This is mutual authentication and it is mandatory. Skipping it would let a party who can forge an Accept impersonate NPS, so a mismatch here denies the login even though the packet said accept. Many implementations quietly omit this check; ours does not.

On Access-Reject the MS-CHAP-Error attribute is parsed so that password-expired (E=648), authentication-failure (E=691), and account-lockout conditions surface as distinct, correct outcomes rather than a generic failure. Password change (MS-CHAP2-CPW) is deliberately out of scope for v1; an expired password produces a clear message telling the user to change it through a supported channel, and denies the login.

Now the part the CISO needs on record. MSCHAPv2 satisfies the requirement that the cleartext password never leaves the client, and it provides mutual authentication. It does not provide transport confidentiality. The MS-CHAP-Challenge and MS-CHAP2-Response attributes travel in the clear inside the RADIUS packet, and the handshake reduces to a single DES-56 keyspace, which means an on-path attacker who captures one exchange can recover the NT hash offline regardless of how strong the RADIUS shared secret is. That weakness is a property of the protocol and cannot be fixed inside the module.

The module therefore treats IPsec as a required control for MSCHAPv2 deployments, not an optional one. An ESP tunnel between the host and NPS removes the on-path capture, which is the only thing that makes captured MSCHAPv2 handshakes dangerous. Because NPS supports neither RADIUS-over-TLS nor DTLS, IPsec is the only transport option available, and the deployment guide will refuse to bless an MSCHAPv2 rollout that runs on a bare wire. This is the compensating control that makes the mandated choice safe.

One operational landmine that will bite the exact user population this is built for: members of the Active Directory Protected Users group cannot authenticate with MSCHAPv2, because Protected Users disables the NTLM path that MSCHAPv2 depends on. Privileged administrators are both the people most likely to be placed in Protected Users and the people most likely to need MFA on these hosts. Confirm the target accounts are not in Protected Users, or provide them a different primary-auth path, before committing to MSCHAPv2 for them. This constraint is documented prominently so it is discovered in design, not in a 2 a.m. incident.

## 10. PAP specifics

Provided for the wider audience, not for our deployment. The User-Password is hidden per RFC 2865 with the chained MD5 construction seeded by the random Request Authenticator. Because PAP supports the Entra MFA challenge flow, this mode implements the Access-Challenge and State round-trip: on a challenge, the module surfaces the Reply-Message through the PAM conversation, collects the TOTP, and resends with the State attribute echoed back unchanged. PAP deployments are also expected to run inside IPsec, for the same transport reasons.

## 11. PAM integration correctness

Wrong PAM return codes are their own security bug, because they change how the stack fails. The module maps outcomes precisely. A clean second-factor success is PAM_SUCCESS. An authentication failure, including a denied or timed-out MFA, is PAM_AUTH_ERR. A server that cannot be reached is PAM_AUTHINFO_UNAVAIL, distinct from failure, so the stack can be configured to die closed on unavailability rather than falling through. Empty passwords are rejected outright, and the module honors PAM_DISALLOW_NULL_AUTHTOK.

The module reads the password already collected by an earlier stack module when configured to (the try_first_pass and use_first_pass conventions) rather than blindly reprompting, and prompts with echo off only when it must. Failure messaging is uniform enough not to hand an attacker a user-enumeration oracle from the client side.

The recommended stack and sshd configuration ship with the module, including the AuthenticationMethods and KbdInteractiveAuthentication settings that close the public-key and GSSAPI bypass described in section 4. Break-glass access is part of the reference design: a local, MFA-exempt administrative account that lives entirely outside the RADIUS path, so that an NPS or network outage cannot lock every administrator out of every host. The break-glass account's use is heavily audited.

## 12. Transport, timeouts, and failover

Timeouts are bounded and must fit inside sshd's LoginGraceTime, with headroom. MSCHAPv2 with push means a single Access-Request that NPS holds open while the user approves on their phone, so the per-request timeout has to swallow the full approval window; Microsoft recommends at least sixty seconds, and the module defaults accordingly while staying under a sane LoginGraceTime.

Retransmission respects NPS behavior. The extension discards duplicate requests and continues discarding them for a short window after a successful response, to avoid double-prompting the user. So a retransmit resends the identical packet, with the same identifier and authenticator, rather than crafting a fresh one, and the retry count is small. Multiple NPS servers are tried in configured order, but failover happens only on an explicit transport error such as ICMP unreachable, not on silence. A silent server may already have issued a push, so retrying a second server would double-prompt the user and race two approvals. On silence the module waits out the MFA window on the current server and then denies. If every server fails at the transport level, the result is PAM_AUTHINFO_UNAVAIL and the login is denied.

## 13. Testing and assurance

The RADIUS response parser and the MSCHAPv2 attribute parser are continuous fuzz targets, because they consume attacker-controlled network input inside a privileged process. Known-answer vectors from RFC 2759 and RFC 2548 cover the MSCHAPv2 and vendor-attribute math. The Response Authenticator and Message-Authenticator verification have negative tests that confirm a single flipped bit denies the auth. A lab NPS with the Entra MFA extension is part of the release gate, because the Success authenticator handling and the State round-trip are exactly the places wire behavior diverges from the spec.

Supply chain: dependencies are pinned and reviewed, `cargo audit` and `cargo deny` run in CI, releases are signed, and an SBOM ships with each release. The unsafe FFI shim is reviewed line by line on every change. SELinux policy ships with the RPM so that sshd can reach the RADIUS port without anyone reaching for permissive mode.

## 14. Deliberately out of scope for v1

Password change over MSCHAPv2 (MS-CHAP2-CPW). EAP in any form. RADIUS accounting. Anything that negotiates protocol at runtime. Each of these is a conscious exclusion, not an oversight, and each is listed so reviewers can see the boundary.

## 15. Decisions needed before code

The project name and therefore the `.so` name and repo name. Whether native auditd emission is in v1 or whether v1 logs through syslog with auditd integration following. Whether the PAP challenge and State round-trip ships in v1 or waits, given that our own deployment does not use PAP. Whether v1 targets only the RHEL9 system OpenSSH and PAM stack, with Debian and SUSE packaging deferred until the RHEL path is proven.

# pam_nps_mfa: Implementation Specification

This pins the parts an agent must not reconstruct from memory: wire formats, attribute numbers, the crypto field layouts, the config schema, the PAM options and return codes, the auditd approach, dependency versions, and the build. It is the companion to `SECURITY_DESIGN.md` and `TEST_VECTORS.md`.

All multi-byte integers on the wire are big-endian. All lengths are in octets and include the field's own header unless stated.

## 1. Crate layout

```
pam_nps_mfa/
  crates/
    pam-ffi/      the only crate allowed unsafe; exports the C symbols, thin shim
    radius/       packet build and parse, authenticators, Message-Authenticator, socket
    mschapv2/     RFC 2759 math and the Microsoft vendor attributes
    pap/          User-Password hiding and the challenge/State round-trip
    config/       parsing and permission checks
    secrets/      zeroizing wrappers
    audit/        auditd (libaudit FFI submodule) plus syslog
  fuzz/           cargo-fuzz targets
  packaging/      rpm spec, SELinux policy
  CLAUDE.md
  IMPLEMENTATION_SPEC.md
  SECURITY_DESIGN.md
  TEST_VECTORS.md
  deny.toml
```

The build output is `pam_nps_mfa.so`, a single `cdylib`. Only `pam-ffi` sets `crate-type = ["cdylib"]`; the rest are normal libs.

Express the RADIUS request-and-response step as a trait, for example `RadiusTransport`, with the real UDP client as one implementation and an in-memory fake as another. This lets the codec, the failover logic, and the PAM plumbing be unit tested without a socket, and it is what the phase 5 and phase 6 gates lean on.

## 2. Dependencies, pinned

Use these versions as the floor and let Cargo pick compatible patch releases. Do not add anything not listed without recording why.

```
# crypto (RustCrypto)
md4        = "0.10"   # NT hash, intentionally weak, required by MSCHAPv2
des        = "0.8"    # single DES for the challenge response, required by MSCHAPv2
sha1       = "0.10"
md-5       = "0.10"   # RADIUS authenticators and keystream
hmac       = "0.12"   # Message-Authenticator (HMAC-MD5)

# hygiene
subtle     = "2.5"    # constant-time comparison
zeroize    = { version = "1.7", features = ["derive"] }
getrandom  = "0.2"    # OS CSPRNG for authenticators and challenges

# platform
libc       = "0.2"    # syslog, mlock, prctl

# dev
hex-literal = "0.4"   # test vectors only
```

`des` 0.8 uses the `cipher` 0.4 traits. Encrypt one block like:

```rust
use des::Des;
use des::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};
let cipher = Des::new(GenericArray::from_slice(&key8));
let mut block = GenericArray::clone_from_slice(&clear8);
cipher.encrypt_block(&mut block); // block now holds the 8-byte output
```

The libpam and libaudit bindings are declared by hand in the two FFI submodules rather than pulled from a crate, so the unsafe surface is fully visible and reviewable. Link flags come from `build.rs` (see section 9).

Set `panic = "unwind"` (the default) so the boundary `catch_unwind` works. Do not set `panic = "abort"`.

## 3. RADIUS packet format (RFC 2865)

```
0        1        2        3
+--------+--------+--------+--------+
|  Code  |   Id   |     Length      |
+--------+--------+--------+--------+
|                                   |
|          Authenticator            |   16 octets
|                                   |
+--------+--------+--------+--------+
|  Attributes ...                   |
```

Codes used: Access-Request = 1, Access-Accept = 2, Access-Reject = 3, Access-Challenge = 11.

Length covers the whole packet, header plus all attributes, minimum 20, maximum 4096. Reject anything outside that before parsing.

For an Access-Request the Authenticator field is the Request Authenticator: 16 octets from `getrandom`, fresh per request, never time-based, never reused.

### Attribute format

```
+--------+--------+--------+ ... 
|  Type  | Length |  Value (Length - 2 octets)
```

Length is the whole attribute including the two header octets. A Length below 2, or one that runs past the end of the packet, is a fatal parse error.

Attribute types this module uses:

```
1    User-Name
2    User-Password        (PAP only)
4    NAS-IP-Address       (optional)
18   Reply-Message
24   State                (echo back unchanged on challenge)
26   Vendor-Specific
32   NAS-Identifier
80   Message-Authenticator
```

### Message-Authenticator (type 80, RFC 3579 section 3.2)

Length is always 18 (2 header plus 16 value). Present on every Access-Request this module sends.

Compute: build the entire packet with all attributes in place, with the 16 value octets of the Message-Authenticator set to zero. Then

```
Message-Authenticator = HMAC-MD5(key = shared_secret, data = entire_packet_with_MA_zeroed)
```

Write the 16-octet result into the attribute value. Because the HMAC covers all attributes, the Message-Authenticator attribute is built last, after User-Name, the credential attributes, and any NAS attributes are already in the buffer. The position of the attribute in the packet does not change the HMAC, since the server verifies over the packet as received, so either order interoperates with NPS. RFC 3579 recommends placing it first if you prefer.

### Response Authenticator (RFC 2865 section 3)

On any response, verify before trusting any attribute inside it:

```
ResponseAuthenticator = MD5( Code | Id | Length | RequestAuthenticator | Attributes | shared_secret )
```

where `RequestAuthenticator` is the 16 octets from the request this is a response to, `Attributes` is the response attribute bytes exactly as received (Message-Authenticator left as received, that is, filled), and the result is compared in constant time against the Authenticator field of the received packet.

### Response Message-Authenticator

If the response carries a Message-Authenticator, verify it too:

```
expected = HMAC-MD5(key = shared_secret,
                    data = Code | Id | Length | RequestAuthenticator | Attributes_with_MA_zeroed)
```

Note that both response checks use the original Request Authenticator, not the response's own Authenticator field. In strict mode (default) a response with no Message-Authenticator is rejected.

### Response binding

Accept a response only when all of these match the outstanding request: the Identifier octet, the source IP and UDP port equal to the configured server, a valid Response Authenticator, and a valid Message-Authenticator. Otherwise discard and keep waiting until the timeout. The UDP source port for the request socket is ephemeral and OS-assigned.

### Request attributes

Every Access-Request carries at minimum User-Name, the credential attributes for the configured mode, and Message-Authenticator. Include NAS-Identifier from config, and NAS-IP-Address when configured. NPS network policy must be set to permit these. Do not send a Service-Type unless a deployment needs it to match an NPS policy; leave it configurable and off by default.

### Transport, timeouts, and failover

RADIUS is UDP. The client socket binds an ephemeral OS-assigned source port, and the configured source address if set. If `getrandom` fails while producing a Request Authenticator or a challenge, deny the authentication; never proceed with weak or zero material.

Failover between servers is only safe on an explicit transport error. Try servers in the order listed. On an ICMP unreachable, a connection-refused, or a routing failure, move to the next server. On plain silence, do not fail over. With the Entra MFA extension a silent server may already have issued a push to the user's device, and sending the same authentication to a second server would produce a second push and a race between two approvals. On silence, retransmit the identical packet a small bounded number of times to cover UDP loss (NPS suppresses these as duplicates, so they cause no extra push and do not reset the wait), then wait out the MFA timeout on that server, then deny.

Two-stage timing keeps this inside sshd's LoginGraceTime. A short probe budget covers reaching a live server at the transport level, and only one server ever enters the long MFA-completion wait. Size the config so that the transport probes across the server list, plus one MFA timeout, plus a margin, stay under LoginGraceTime. With the default LoginGraceTime of 120 seconds and a 60 second MFA timeout there is ample room. Do not set a per-server MFA timeout so high that a single server can consume the whole grace window.

Known limitation: because failover does not trigger on silence, a server that is reachable but wedged (no ICMP error, no RADIUS reply) will absorb the MFA wait on every attempt and the next server is never reached within a single attempt. If that becomes an availability problem, an optional health tracker that moves a repeatedly-timing-out server to the back of the list, or a per-attempt rotation of the server order, addresses it at the cost of deterministic ordering. This is a v1.1 consideration, not required for v1.

## 4. PAP mode (RFC 2865 section 5.2)

User-Password (type 2). Pad the password with zero octets up to the next multiple of 16, maximum 128 octets. Hide it block by block:

```
b(1) = MD5(secret | RequestAuthenticator)   c(1) = p(1) xor b(1)
b(i) = MD5(secret | c(i-1))                  c(i) = p(i) xor b(i)   for i > 1
```

The attribute value is the concatenation of the c blocks. The Request Authenticator here is the same random 16 octets used in the packet header, which is why its unpredictability is essential in PAP mode.

PAP supports the Entra MFA challenge flow. On Access-Challenge, read the Reply-Message and the State attribute, surface the Reply-Message text through the PAM conversation to collect the one-time code, and send a second Access-Request that echoes the State attribute back unchanged and carries the new credential. Keep echoing State across as many challenge rounds as the server uses.

## 5. MSCHAPv2 mode

The math is specified and verified in `TEST_VECTORS.md` against RFC 2759 section 9.2. This section pins the wire layout of the Microsoft attributes (RFC 2548). All are carried inside Vendor-Specific (type 26) with Vendor-Id 311 (0x00000137).

Vendor-Specific envelope:

```
| Type=26 | Length | Vendor-Id (4) = 0x00000137 | Vendor-Type (1) | Vendor-Length (1) | Data |
```

Vendor-Length includes the Vendor-Type and Vendor-Length octets, so Vendor-Length = 2 + len(Data). The outer Length = 6 + Vendor-Length.

### MS-CHAP-Challenge (Vendor-Type 11)

Data is the 16-octet Authenticator Challenge (the value your module generates with `getrandom`). Vendor-Length = 18, outer Length = 24.

### MS-CHAP2-Response (Vendor-Type 25)

Data is 50 octets, Vendor-Length = 52, outer Length = 58:

```
offset  size  field
0       1     Ident        (client-chosen; there is no upstream request to echo, and it is not part of the crypto, so any consistent value works)
1       1     Flags        (must be 0)
2       16    Peer-Challenge   (16 octets from getrandom)
18      8     Reserved     (must be all zero)
26      24    NT-Response  (the 24-octet value from generate_nt_response)
```

Username matching. The username fed into the challenge hash must be byte-for-byte identical to the string sent in the User-Name attribute. In AD deployments the qualified form (`DOMAIN\user` or `user@realm`) versus the bare account name is a frequent cause of failures that present as a wrong password even though the password is correct, because the client and NPS then hash different strings. This is invisible to the offline vectors, which use bare `User`. Pick one form, use it in both the User-Name attribute and the challenge hash, and confirm it against a real NPS in phase 9, testing both bare and qualified forms.

### MS-CHAP2-Success (Vendor-Type 26), in Access-Accept

Data is Ident (1 octet) followed by the authenticator response string, which begins with `S=` and 40 uppercase hex characters, optionally followed by ` M=<message>`. Parse out the `S=` value and verify it in constant time against your locally computed authenticator response. Mismatch denies the login.

### MS-CHAP-Error (Vendor-Type 2), in Access-Reject

Data is Ident (1 octet) followed by a string such as `E=691 R=1 C=<32 hex> V=3 M=<text>`. Parse the `E=` code and map it:

```
E=646   restricted logon hours     -> deny
E=647   account disabled           -> deny
E=648   password expired           -> deny, tell the user to change it elsewhere (no CPW in v1)
E=649   no dial-in permission      -> deny
E=691   authentication failure     -> deny
E=709   error changing password    -> deny
```

`R=1` means retry is allowed and `C=` carries a fresh challenge for a password change. v1 does not implement password change (MS-CHAP2-CPW), so treat E=648 as a clean deny with a clear message.

## 6. Configuration

Default path `/etc/pam_nps/pam_nps.conf`, override with the `config=` module option. The config file must be owned by root and mode 0600, and each secret file likewise. To avoid a check-then-use race and a symlink swap, do not stat the path and then open it. Open the file with `O_NOFOLLOW`, `fstat` the resulting descriptor, confirm it is a regular file owned by uid 0 with no group or other permission bits, and only then read from that same descriptor. If any check fails, refuse to run and log a critical audit event. A permissive or swappable secret is a hard failure, not a warning. Parsing fails closed on any malformed or ambiguous line.

Format is line-oriented `key value`, `#` starts a comment. Schema:

```
# one or more servers, tried in the order listed; each has its own secret file
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
server 10.0.0.11:1812 /etc/pam_nps/secret.d/nps2

protocol      mschapv2          # mschapv2 | pap  (fixed for the process, no fallback)
timeout       60                # seconds per server; must fit sshd LoginGraceTime with headroom
retries       1                 # retransmits of the identical packet per server
nas_identifier tunnel-host-01   # sent as NAS-Identifier (type 32)
nas_ip        10.20.0.5         # optional, sent as NAS-IP-Address (type 4)
source_ip     0.0.0.0           # optional bind address for the client socket
require_message_authenticator true   # strict; reject responses lacking MA
audit         both              # auditd | syslog | both
debug         false             # metadata only; never enables credential-byte logging
```

Each secret file contains only the shared secret for that server, as raw text with any trailing newline stripped. Secrets should be long random strings at the length NPS accepts, unique per host, rendered from the control-plane bundle.

## 7. PAM integration

Exported C symbols (from `pam-ffi`):

```
pam_sm_authenticate
pam_sm_setcred
pam_sm_acct_mgmt
```

Each wraps its body in `catch_unwind`. A caught panic returns `PAM_AUTHINFO_UNAVAIL`.

libpam functions the shim calls: `pam_get_user`, `pam_get_authtok` (or `pam_get_item` with `PAM_AUTHTOK` plus the conversation for prompting), `pam_get_item`, `pam_set_item`, and the conversation function for challenge prompts and Reply-Message display. Prompt for the password with echo off only when it is not already available.

In MSCHAPv2 push mode there is no interactive second prompt, so before blocking on the server, send a `PAM_TEXT_INFO` message through the conversation telling the user to approve the sign-in on their device. Otherwise the session appears to hang for up to a minute. The module holds no mutable global state and must be safe to call concurrently, so all per-attempt state stays local to the call. The module zeroizes its own copies of credential material; it does not try to wipe the buffer PAM owns, whose lifetime is PAM's responsibility.

Module options on the pam.d line (policy stays in the config file, not here):

```
config=<path>     override the config file path
try_first_pass    use a password from an earlier module if present, else prompt
use_first_pass    use a password from an earlier module, do not prompt; fail if absent
debug             enable metadata debug logging
```

Example stack entry:

```
auth  required  pam_nps_mfa.so  config=/etc/pam_nps/pam_nps.conf  try_first_pass
```

Return code mapping:

```
second factor succeeded (Access-Accept, Success verified)   -> PAM_SUCCESS
Access-Reject, or MFA denied, or MFA timed out at the server -> PAM_AUTH_ERR
empty password, or PAM_DISALLOW_NULL_AUTHTOK with null       -> PAM_AUTH_ERR
all servers unreachable, or no valid response before timeout  -> PAM_AUTHINFO_UNAVAIL
config error or permissive secret file                        -> PAM_AUTHINFO_UNAVAIL (log critical)
pam_sm_setcred                                                -> PAM_SUCCESS
pam_sm_acct_mgmt                                              -> PAM_IGNORE
```

A response that fails an integrity check is discarded, not treated as a Reject. If no valid response arrives before the timeout the result is `PAM_AUTHINFO_UNAVAIL`.

The reference sshd and stack configuration ships with the module and must set `KbdInteractiveAuthentication yes` and an `AuthenticationMethods` value that forces the keyboard-interactive PAM path for accounts in scope, because public-key and GSSAPI authentication skip the PAM auth stack entirely. It also defines a break-glass local account that lives outside the RADIUS path so an NPS or network outage cannot lock every administrator out. Break-glass use is audited.

## 8. Audit

Two backends, selected by the `audit` config key. Native auditd is the default expectation, syslog is always available as a companion or standalone.

Native auditd uses a small FFI to libaudit in the `audit` crate's FFI submodule: `audit_open`, `audit_log_acct_message`, `audit_close`. Use `audit_log_acct_message` with type `AUDIT_USER_AUTH` (1100) and result 1 for success or 0 for failure, so the record lands as a standard USER_AUTH event that `ausearch -m USER_AUTH` and `aureport` parse natively, with the operation, user, host, terminal, and result in their normal fields. Put the protocol and server into the operation string rather than inventing a free-form record. Link `-laudit` from `build.rs`.

syslog uses libc `openlog`/`syslog`/`closelog` with facility `LOG_AUTHPRIV`. `openlog` keeps the ident pointer rather than copying it, so pass a `'static CString` and never a borrowed or temporary Rust string, or syslog will later read freed memory.

Every authentication attempt emits one record. Field schema, key=value, space-separated:

```
op=pam_nps_auth proto=mschapv2 server=10.0.0.10 user=<name> result=success|denied|unavail reason=<short> corr=<uuid>
```

Never include a password, NT hash, shared secret, or any credential-attribute bytes. The username is included because it is standard for an auth audit record. Generate `corr` per attempt so a request and its outcome can be tied together across auditd and syslog.

## 9. Build, SELinux, packaging

`build.rs` emits the link directives:

```
cargo:rustc-link-lib=pam
cargo:rustc-link-lib=audit
```

The installed module goes to the platform PAM module directory, on RHEL9 `/usr/lib64/security/pam_nps_mfa.so`.

SELinux: sshd running as `sshd_t` must reach the RADIUS port, read the configuration and secret files, and write audit records. Ship a small policy module in `packaging/` that grants the `radius_port_t` access, read access to a dedicated type for `/etc/pam_nps`, and the audit write path, rather than relying on a boolean or on permissive mode. Writing to auditd also needs `CAP_AUDIT_WRITE`, which sshd already holds; confirm it is available in the module's context. The RPM installs and loads the policy.

RPM spec in `packaging/` builds the cdylib, installs the module, the SELinux policy, a sample config with 0600 and root ownership, and the reference pam.d and sshd snippets as documentation. `cargo audit` and `cargo deny` run in CI. The `md4` and `des` crates from RustCrypto are maintained and have no known CVE, so they are unlikely to fail cargo-audit on their own. If a `deny.toml` policy bans weak primitives, or an informational advisory appears, record the specific ID with a comment pointing at `CLAUDE.md` and keep the crates, since MSCHAPv2 requires them.

## 10. Out of scope for v1

Password change over MSCHAPv2 (MS-CHAP2-CPW). EAP in any form. RADIUS accounting. Any runtime protocol negotiation. Debian and SUSE packaging until the RHEL9 path is proven. Each is a deliberate boundary, listed so a reviewer can see it.

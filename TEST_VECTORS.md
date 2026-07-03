# pam_nps_mfa: Known-Answer Test Vectors

These are the self-checks that let an agent get the crypto right without a live NPS in the loop. The MSCHAPv2 set is from RFC 2759 section 9.2 and has been recomputed with real MD4, DES, SHA1, and HMAC-MD5 and confirmed to match the published values exactly. The PAP and RADIUS MAC vectors are deterministic, generated from fixed inputs, and round-trip through the client verification path.

If your code disagrees with a value here, the bug is in your code. Do not change these numbers.

All hex is big-endian, no separators.

## 1. MSCHAPv2 (RFC 2759 section 9.2)

Inputs:

```
password  = "clientPass"           (encoded UTF-16LE for the NT hash)
username  = "User"                 (ASCII, used only in the challenge hash)
AuthenticatorChallenge = 5B5D7C7D7B3F2F3E3C2C602132262628
PeerChallenge          = 21402324255E262A28295F2B3A337C7E
```

Expected outputs:

```
NtPasswordHash        = 44EBBA8D5312B8D611474411F56989AE
ChallengeHash         = D02E4386BCE91226
NtResponse            = 82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF
PasswordHashHash      = 41C00C584BD2D91C4017A2A12FA59F3F
AuthenticatorResponse = S=407A5589115FD0D6209F510FE9C04566932CDA56
```

Notes on how each is derived, so a mismatch tells you where to look:

- `NtPasswordHash` is MD4 of the password encoded as UTF-16LE. If this is wrong, your endianness or your MD4 is wrong.
- `ChallengeHash` is the first 8 octets of SHA1 over PeerChallenge, then AuthenticatorChallenge, then the ASCII username. Order matters. The username is not encoded to UTF-16 here. In a real deployment it must also be byte-identical to the User-Name attribute you send; see the username matching note in the spec, since a domain-qualified mismatch fails against NPS while passing these vectors.
- `NtResponse` pads the 16-octet NT hash to 21 octets with zeros, splits it into three 7-octet groups, expands each to an 8-octet DES key (each output octet holds a 7-bit slice in its high bits, low bit is parity and is ignored by DES), and DES-encrypts the ChallengeHash under each. Three 8-octet blocks concatenate to 24 octets.
- `PasswordHashHash` is MD4 of the raw 16 NT-hash octets. This is MD4 of bytes, not of a UTF-16 string. A common bug is running the UTF-16 path here.
- `AuthenticatorResponse` follows RFC 2759 section 8.7 using the two magic constants. Verify it in constant time against the server MS-CHAP2-Success value.

The two magic constants:

```
Magic1 (39 bytes) = ASCII "Magic server to client signing constant"
Magic2 (41 bytes) = ASCII "Pad to make it do more than one iteration"
```

## 2. PAP User-Password hiding (RFC 2865 section 5.2)

Deterministic vector.

```
secret               = "testing123"
RequestAuthenticator = 0F0E0D0C0B0A09080706050403020100
password             = "hello"

padded length        = 16  (password plus zero padding to a 16-octet boundary)
hidden User-Password = 3A54A292B2212540DB21D8962FA3939E
```

Single block here since the password is under 16 octets: `c(1) = "hello\0\0\0\0\0\0\0\0\0\0\0" xor MD5(secret | RequestAuthenticator)`.

## 3. RADIUS Access-Request Message-Authenticator (RFC 3579)

Deterministic vector. A minimal Access-Request with User-Name "User" and a Message-Authenticator, Identifier 42.

```
secret = "testing123"

packet with MA value zeroed (44 octets):
012A002C 0F0E0D0C0B0A09080706050403020100 010655736572 5012 00000000000000000000000000000000

Message-Authenticator = F4CC66C3929058ED76A7C8D409A381D1
```

Breakdown of the packet bytes: Code 01, Id 2A, Length 002C, then the 16-octet Request Authenticator, then User-Name (type 01, len 06, "User"), then Message-Authenticator (type 50 hex, len 12 hex, 16 zero octets). The HMAC-MD5 is keyed by the secret over the whole thing with those 16 octets zeroed, then written back in.

## 4. RADIUS Access-Accept response verification

Deterministic vector, the response to the request above. It carries a Reply-Message "OK" and a Message-Authenticator. Identifier 42, same secret and same Request Authenticator as section 3.

```
Response Message-Authenticator = 87EC197FEEC0F2A4E337D1632395EF08
Response Authenticator         = 415325D27047D5EF65667EBFB5B1200E

final on-wire response packet (42 octets):
022A002A 415325D27047D5EF65667EBFB5B1200E 12044F4B 5012 87EC197FEEC0F2A4E337D1632395EF08
```

Both response checks use the Request Authenticator from section 3, not the response's own Authenticator field. To verify as the client: recompute the Response Authenticator as MD5 over Code, Id, Length, RequestAuthenticator, the response attributes as received, then the secret, and compare to the Authenticator field. Recompute the Message-Authenticator as HMAC-MD5 over the packet with the Authenticator field replaced by the Request Authenticator and the Message-Authenticator value zeroed, and compare to the received value. A single flipped bit in either must deny.

## 5. Ready-to-use Rust test module

Match these function signatures in your implementation. `hex-literal` is a dev-dependency. Adjust module paths to your crate names, not the values.

```rust
// tests/vectors.rs
use hex_literal::hex;

// Expected API (implement these in the named crates):
//   mschapv2::nt_password_hash(password: &str) -> [u8; 16]
//   mschapv2::challenge_hash(peer: &[u8;16], auth: &[u8;16], username: &[u8]) -> [u8; 8]
//   mschapv2::generate_nt_response(auth: &[u8;16], peer: &[u8;16], username: &[u8], password: &str) -> [u8; 24]
//   mschapv2::password_hash_hash(nt_hash: &[u8;16]) -> [u8; 16]
//   mschapv2::generate_authenticator_response(password: &str, nt_response: &[u8;24],
//                                             peer: &[u8;16], auth: &[u8;16], username: &[u8]) -> String
//   mschapv2::verify_authenticator_response(expected: &str, received: &str) -> bool   // constant-time
//   pap::hide_password(password: &[u8], secret: &[u8], request_authenticator: &[u8;16]) -> Vec<u8>
//   radius::message_authenticator(packet_with_ma_zeroed: &[u8], secret: &[u8]) -> [u8; 16]
//   radius::response_authenticator(code: u8, id: u8, length: u16,
//                                  request_authenticator: &[u8;16],
//                                  attributes_ma_filled: &[u8], secret: &[u8]) -> [u8; 16]

const AUTH:  [u8;16] = hex!("5B5D7C7D7B3F2F3E3C2C602132262628");
const PEER:  [u8;16] = hex!("21402324255E262A28295F2B3A337C7E");
const USER:  &[u8]   = b"User";
const PASS:  &str    = "clientPass";

#[test]
fn nt_password_hash() {
    assert_eq!(mschapv2::nt_password_hash(PASS), hex!("44EBBA8D5312B8D611474411F56989AE"));
}

#[test]
fn challenge_hash() {
    assert_eq!(mschapv2::challenge_hash(&PEER, &AUTH, USER), hex!("D02E4386BCE91226"));
}

#[test]
fn nt_response() {
    assert_eq!(
        mschapv2::generate_nt_response(&AUTH, &PEER, USER, PASS),
        hex!("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
    );
}

#[test]
fn password_hash_hash() {
    let nt = mschapv2::nt_password_hash(PASS);
    assert_eq!(mschapv2::password_hash_hash(&nt), hex!("41C00C584BD2D91C4017A2A12FA59F3F"));
}

#[test]
fn authenticator_response() {
    let nt_resp = mschapv2::generate_nt_response(&AUTH, &PEER, USER, PASS);
    let s = mschapv2::generate_authenticator_response(PASS, &nt_resp, &PEER, &AUTH, USER);
    assert_eq!(s, "S=407A5589115FD0D6209F510FE9C04566932CDA56");
    assert!(mschapv2::verify_authenticator_response(&s, "S=407A5589115FD0D6209F510FE9C04566932CDA56"));
    assert!(!mschapv2::verify_authenticator_response(&s, "S=407A5589115FD0D6209F510FE9C04566932CDA57"));
}

#[test]
fn pap_hiding() {
    let ra = hex!("0F0E0D0C0B0A09080706050403020100");
    assert_eq!(
        pap::hide_password(b"hello", b"testing123", &ra),
        hex!("3A54A292B2212540DB21D8962FA3939E").to_vec()
    );
}

#[test]
fn request_message_authenticator() {
    let packet = hex!(
        "012A002C"
        "0F0E0D0C0B0A09080706050403020100"
        "010655736572"
        "501200000000000000000000000000000000"
    );
    assert_eq!(
        radius::message_authenticator(&packet, b"testing123"),
        hex!("F4CC66C3929058ED76A7C8D409A381D1")
    );
}

#[test]
fn response_authenticator() {
    let ra = hex!("0F0E0D0C0B0A09080706050403020100");
    // response attributes with Message-Authenticator filled: Reply-Message "OK" + MA
    let attrs = hex!("12044F4B" "5012" "87EC197FEEC0F2A4E337D1632395EF08");
    assert_eq!(
        radius::response_authenticator(2, 42, 42, &ra, &attrs, b"testing123"),
        hex!("415325D27047D5EF65667EBFB5B1200E")
    );
}
```

## 6. Malformed packets the parser must reject

Structural negatives for phase 1. Each is a response the parser must reject on structure alone, before and independent of any authenticator or MAC check, denying the authentication rather than crashing or accepting. Authenticator octets are zeroed because they are irrelevant to these cases. Use them as unit tests and as fuzz seeds.

```
M1  attribute Length below 2
    022A0016 00000000000000000000000000000000 0101
    (last attribute claims Length 01, which cannot hold its own header)

M2  attribute Length runs past the end of the packet
    022A0017 00000000000000000000000000000000 011F41
    (attribute type 01 claims Length 0x1F but only one value octet is present)

M3  vendor-specific inner length overruns the attribute
    022A001E 00000000000000000000000000000000 1A0A0000013719224041
    (VSA outer Length 0x0A, Vendor-Id 311, Vendor-Length 0x22 overruns the 2 data octets)

M4  header Length larger than the bytes received
    022A00FF 00000000000000000000000000000000
    (Length field claims 255 octets, only 20 received)

M5  header Length below the 20-octet minimum
    022A0013 00000000000000000000000000000000
    (Length field claims 19, below the RADIUS minimum)
```

None of these should ever return success, allocate from the attacker-supplied length, or panic. A parser that treats any of them as a valid or acceptable packet has a bug that a network peer can reach.

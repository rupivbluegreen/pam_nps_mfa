//! Known-answer tests for the MSCHAPv2 engine.
//!
//! Section-1 vectors are TEST_VECTORS.md §5 verbatim (RFC 2759 §9.2). The
//! remaining tests exercise the RFC 2548 vendor attribute wire layout and the
//! bounded, deny-not-panic parsing of attacker-supplied MS-CHAP2-Success and
//! MS-CHAP-Error strings and malformed VSAs.
//!
//! If a value here disagrees with the code, the bug is in the code
//! (CLAUDE.md rule 4) — never edit a vector.

use hex_literal::hex;
use mschapv2::vendor_type;
use mschapv2::{Challenges, MsChapError, SuccessError};

const AUTH: [u8; 16] = hex!("5B5D7C7D7B3F2F3E3C2C602132262628");
const PEER: [u8; 16] = hex!("21402324255E262A28295F2B3A337C7E");
const USER: &[u8] = b"User";
const PASS: &str = "clientPass";

// ---------------------------------------------------------------------------
// TEST_VECTORS.md §5 — RFC 2759 §9.2, verbatim.
// ---------------------------------------------------------------------------

#[test]
fn nt_password_hash() {
    assert_eq!(
        mschapv2::nt_password_hash(PASS),
        hex!("44EBBA8D5312B8D611474411F56989AE")
    );
}

#[test]
fn challenge_hash() {
    assert_eq!(
        mschapv2::challenge_hash(&PEER, &AUTH, USER),
        hex!("D02E4386BCE91226")
    );
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
    assert_eq!(
        mschapv2::password_hash_hash(&nt),
        hex!("41C00C584BD2D91C4017A2A12FA59F3F")
    );
}

#[test]
fn authenticator_response() {
    let nt_resp = mschapv2::generate_nt_response(&AUTH, &PEER, USER, PASS);
    let s = mschapv2::generate_authenticator_response(PASS, &nt_resp, &PEER, &AUTH, USER);
    assert_eq!(s, "S=407A5589115FD0D6209F510FE9C04566932CDA56");
    assert!(mschapv2::verify_authenticator_response(
        &s,
        "S=407A5589115FD0D6209F510FE9C04566932CDA56"
    ));
    assert!(!mschapv2::verify_authenticator_response(
        &s,
        "S=407A5589115FD0D6209F510FE9C04566932CDA57"
    ));
}

// ---------------------------------------------------------------------------
// RFC 2548 vendor attribute wire layout (IMPLEMENTATION_SPEC.md §5).
// ---------------------------------------------------------------------------

#[test]
fn ms_chap2_response_vsa_round_trip() {
    let nt_resp = mschapv2::generate_nt_response(&AUTH, &PEER, USER, PASS);
    let ident = 0x42u8;
    let value = mschapv2::encode_ms_chap2_response(ident, &PEER, &nt_resp);

    // Vendor-Specific value = Vendor-Id(4) + Vendor-Type(1) + Vendor-Length(1)
    // + Data(50) = 56 octets, so the outer Length is 56 + 2 = 58.
    assert_eq!(value.len(), 56);
    assert_eq!(&value[0..4], &hex!("00000137")); // Vendor-Id 311
    assert_eq!(value[4], vendor_type::MS_CHAP2_RESPONSE); // 25
    assert_eq!(value[5], 52); // Vendor-Length = 2 + 50

    // The 50-octet Data layout: Ident, Flags=0, Peer(16), Reserved(8)=0, NT(24).
    let data = &value[6..56];
    assert_eq!(data.len(), 50);
    assert_eq!(data[0], ident);
    assert_eq!(data[1], 0); // Flags
    assert_eq!(&data[2..18], &PEER); // Peer-Challenge
    assert_eq!(&data[18..26], &[0u8; 8]); // Reserved all zero
    assert_eq!(&data[26..50], &nt_resp); // NT-Response

    // Through the radius envelope the outer Length octet is 58.
    let attr = radius::encode_attribute(radius::attr::VENDOR_SPECIFIC, &value).unwrap();
    assert_eq!(attr[0], radius::attr::VENDOR_SPECIFIC); // 26
    assert_eq!(attr[1], 58); // outer Length
    assert_eq!(attr.len(), 58);
}

#[test]
fn ms_chap_challenge_vsa_layout() {
    let value = mschapv2::encode_ms_chap_challenge(&AUTH);
    // Vendor-Id(4) + Vendor-Type(1) + Vendor-Length(1) + Data(16) = 22 octets,
    // outer Length 24.
    assert_eq!(value.len(), 22);
    assert_eq!(&value[0..4], &hex!("00000137"));
    assert_eq!(value[4], vendor_type::MS_CHAP_CHALLENGE); // 11
    assert_eq!(value[5], 18); // Vendor-Length = 2 + 16
    assert_eq!(&value[6..22], &AUTH);

    let attr = radius::encode_attribute(radius::attr::VENDOR_SPECIFIC, &value).unwrap();
    assert_eq!(attr[1], 24); // outer Length
}

#[test]
fn ms_chap2_success_parse_extracts_s_value() {
    // Data = Ident(1) ++ "S=<40 hex>" ++ optional " M=<message>".
    let mut data = vec![0x42u8]; // Ident
    data.extend_from_slice(b"S=407A5589115FD0D6209F510FE9C04566932CDA56 M=Welcome");
    let s = mschapv2::parse_ms_chap2_success(&data).unwrap();
    assert_eq!(s, "S=407A5589115FD0D6209F510FE9C04566932CDA56");

    // And the extracted value verifies constant-time against our own.
    let nt_resp = mschapv2::generate_nt_response(&AUTH, &PEER, USER, PASS);
    let expected = mschapv2::generate_authenticator_response(PASS, &nt_resp, &PEER, &AUTH, USER);
    assert!(mschapv2::verify_success(&expected, &data));
}

#[test]
fn ms_chap2_success_lowercase_hex_normalizes_and_verifies() {
    // A server that emits lowercase hex must still verify (case-insensitive).
    let mut data = vec![0x00u8];
    data.extend_from_slice(b"S=407a5589115fd0d6209f510fe9c04566932cda56");
    let s = mschapv2::parse_ms_chap2_success(&data).unwrap();
    assert_eq!(s, "S=407A5589115FD0D6209F510FE9C04566932CDA56");
}

#[test]
fn high_level_build_and_verify_round_trip() {
    let challenges = Challenges {
        authenticator_challenge: AUTH,
        peer_challenge: PEER,
    };
    let req = mschapv2::build_request(USER, PASS, &challenges, 0x01);
    assert_eq!(
        req.expected_authenticator(),
        "S=407A5589115FD0D6209F510FE9C04566932CDA56"
    );

    // A matching server Success verifies; a single flipped hex denies.
    let mut good = vec![0x01u8];
    good.extend_from_slice(req.expected_authenticator().as_bytes());
    assert!(mschapv2::verify_success(req.expected_authenticator(), &good));

    let mut bad = vec![0x01u8];
    bad.extend_from_slice(b"S=407A5589115FD0D6209F510FE9C04566932CDA57");
    assert!(!mschapv2::verify_success(req.expected_authenticator(), &bad));
}

// ---------------------------------------------------------------------------
// MS-CHAP-Error mapping (IMPLEMENTATION_SPEC.md §5).
// ---------------------------------------------------------------------------

#[test]
fn ms_chap_error_maps_known_codes() {
    let mut e691 = vec![0x00u8]; // Ident
    e691.extend_from_slice(b"E=691 R=1 C=00000000000000000000000000000000 V=3 M=Auth failed");
    assert_eq!(
        mschapv2::parse_ms_chap_error(&e691),
        MsChapError::AuthenticationFailure
    );

    let mut e648 = vec![0x00u8];
    e648.extend_from_slice(b"E=648 R=0 V=3 M=Password expired");
    assert_eq!(
        mschapv2::parse_ms_chap_error(&e648),
        MsChapError::PasswordExpired
    );
}

#[test]
fn ms_chap_error_unknown_and_malformed_deny() {
    let mut e999 = vec![0x00u8];
    e999.extend_from_slice(b"E=999 R=0 V=3 M=Nonsense");
    assert_eq!(
        mschapv2::parse_ms_chap_error(&e999),
        MsChapError::Unknown(999)
    );

    // No E= token at all, and an empty Data: both deny without panic.
    let junk = vec![0x00u8, b'x', b'y', b'z'];
    assert_eq!(mschapv2::parse_ms_chap_error(&junk), MsChapError::Malformed);
    assert_eq!(mschapv2::parse_ms_chap_error(&[]), MsChapError::Malformed);
}

// ---------------------------------------------------------------------------
// Malformed-string / malformed-VSA negatives: deny, never panic
// (CLAUDE.md rules 1, 15; TEST_VECTORS.md §6 M3).
// ---------------------------------------------------------------------------

#[test]
fn ms_chap2_success_truncated_denies() {
    // "S=" followed by only 10 hex characters: too short.
    let mut data = vec![0x00u8];
    data.extend_from_slice(b"S=407A558911");
    assert_eq!(
        mschapv2::parse_ms_chap2_success(&data),
        Err(SuccessError::TooShort)
    );
    // Empty Data (no Ident even) also denies.
    assert_eq!(
        mschapv2::parse_ms_chap2_success(&[]),
        Err(SuccessError::TooShort)
    );
    // verify_success wraps the parse and denies too.
    assert!(!mschapv2::verify_success(
        "S=407A5589115FD0D6209F510FE9C04566932CDA56",
        &data
    ));
}

#[test]
fn ms_chap2_success_non_hex_denies() {
    // 40 characters after "S=" but a 'Z' is not hex.
    let mut data = vec![0x00u8];
    data.extend_from_slice(b"S=407A5589115FD0D6209F510FE9C04566932CDA5Z");
    assert_eq!(
        mschapv2::parse_ms_chap2_success(&data),
        Err(SuccessError::NotHex)
    );

    // Missing the "S=" prefix entirely.
    let mut data2 = vec![0x00u8];
    data2.extend_from_slice(b"X=407A5589115FD0D6209F510FE9C04566932CDA56");
    assert_eq!(
        mschapv2::parse_ms_chap2_success(&data2),
        Err(SuccessError::MissingSPrefix)
    );
}

#[test]
fn verify_authenticator_response_rejects_malformed_strings() {
    // Non-hex, wrong length, and missing prefix all deny in constant time.
    let good = "S=407A5589115FD0D6209F510FE9C04566932CDA56";
    assert!(!mschapv2::verify_authenticator_response(good, "S=zz"));
    assert!(!mschapv2::verify_authenticator_response(good, "407A5589"));
    assert!(!mschapv2::verify_authenticator_response("", good));
}

#[test]
fn vsa_inner_overrun_denies_without_panic() {
    // TEST_VECTORS.md §6 M3: a Vendor-Specific value whose inner Vendor-Length
    // (0x22 = 34) overruns the 2 data octets present. The radius envelope this
    // crate builds on rejects it; nothing panics or is trusted.
    let value = hex!("00000137" "19" "22" "4041");
    assert!(radius::decode_vendor_specific(&value).is_err());
}

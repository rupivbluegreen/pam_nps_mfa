//! PAP known-answer and behavioural vectors (TEST_VECTORS.md §5 plus the
//! phase-3 additions from the task brief).

use hex_literal::hex;
use pap::{build_challenge_response, hide_password, sanitize_reply_message, Challenge, PapError};
use radius::{attr, parse_response, Code, PacketBuilder};

/// Build a structurally valid Access-Challenge carrying the given
/// Reply-Message attributes (in order) and, optionally, a State attribute.
fn challenge_packet(id: u8, reply_msgs: &[&[u8]], state: Option<&[u8]>) -> Vec<u8> {
    let mut b = PacketBuilder::new(Code::AccessChallenge, id, [0u8; 16]);
    for m in reply_msgs {
        b = b.attribute(attr::REPLY_MESSAGE, m).unwrap();
    }
    if let Some(s) = state {
        b = b.attribute(attr::STATE, s).unwrap();
    }
    b.build().unwrap()
}

/// TEST_VECTORS.md §5, verbatim: single-block hiding of "hello".
#[test]
fn pap_hiding() {
    let ra = hex!("0F0E0D0C0B0A09080706050403020100");
    assert_eq!(
        pap::hide_password(b"hello", b"testing123", &ra),
        hex!("3A54A292B2212540DB21D8962FA3939E").to_vec()
    );
}

/// Two-block hiding: a 20-octet password pads to 32 octets, so block 2 is
/// keyed by c(1) — this exercises the chained `c(i-1)` feedback. The expected
/// value was computed with a reference implementation of RFC 2865 §5.2.
#[test]
fn pap_hiding_two_blocks() {
    let ra = hex!("0F0E0D0C0B0A09080706050403020100");
    let pw = b"0123456789abcdefghij"; // 20 octets -> pads to 32 (two blocks)

    let hidden = hide_password(pw, b"testing123", &ra);
    assert_eq!(hidden.len(), 32);
    assert_eq!(
        hidden,
        hex!("6200FCCDE9141377E318B9F44CC7F6F8114B57B8FFEA2BF7940F57D62B1B4960").to_vec()
    );

    // Block 1 depends only on the RequestAuthenticator, so hiding just the
    // first 16 octets reproduces the first block exactly.
    let first_block = hide_password(&pw[..16], b"testing123", &ra);
    assert_eq!(&hidden[..16], first_block.as_slice());

    // Block 2 must NOT reuse b(1): if the feedback were broken and every block
    // used MD5(secret || RA), block 2 would be p(2) xor b(1). Confirm it isn't.
    // Hiding an all-zero block yields exactly b(1) (since c(1) = 0 xor b(1)).
    let b1 = hide_password(&[0u8; 16], b"testing123", &ra);
    let mut p2 = [0u8; 16];
    p2[..4].copy_from_slice(&pw[16..20]); // "ghij" + zero padding
    let broken_block2: Vec<u8> = p2.iter().zip(b1.iter()).map(|(p, b)| p ^ b).collect();
    assert_ne!(&hidden[16..32], broken_block2.as_slice());
}

/// SPEC_AMENDMENTS A4: control/non-printable bytes are stripped before the
/// Reply-Message reaches the login prompt; printable ASCII and spaces survive.
#[test]
fn reply_message_sanitized() {
    // ESC + CSI colour sequence, a BEL, and a newline embedded in the text.
    let raw = b"\x1b[31mDANGER\x07\nkeep this 123";
    let clean = sanitize_reply_message(raw);

    assert_eq!(clean, "[31mDANGERkeep this 123");
    // The escape-introducer and control bytes are gone, so no live escape
    // sequence can reach the terminal.
    assert!(!clean.contains('\x1b'));
    assert!(!clean.contains('\x07'));
    assert!(!clean.contains('\n'));
    // High bytes are dropped too.
    assert_eq!(sanitize_reply_message(b"a\xff\x80b"), "ab");
}

/// State echo round-trip, including a second challenge round: the follow-up
/// Access-Request must carry the latest challenge's State byte-for-byte.
#[test]
fn state_echo_round_trip() {
    let ra = hex!("0F0E0D0C0B0A09080706050403020100");

    // ---- Round 1 ----
    let state1 = hex!("DEADBEEF0102030405060708");
    let pkt = challenge_packet(7, &[b"Enter the code from your app: "], Some(&state1));
    let parsed = parse_response(&pkt).unwrap();
    let ch = Challenge::from_response(&parsed).unwrap();
    assert_eq!(ch.prompt(), "Enter the code from your app: ");
    assert!(ch.has_state());
    assert_eq!(ch.state(), Some(&state1[..]));

    let req = ch
        .build_response(7, ra, b"alice", b"123456", b"testing123")
        .unwrap();
    let rparsed = parse_response(&req).unwrap();
    assert_eq!(rparsed.known_code(), Some(Code::AccessRequest));

    // The State comes back identical, exactly once.
    let echoed: Vec<&[u8]> = rparsed.attr_values(attr::STATE).collect();
    assert_eq!(echoed, vec![&state1[..]]);

    // A hidden User-Password is present ("123456" pads to one 16-octet block).
    let pw: Vec<&[u8]> = rparsed.attr_values(attr::USER_PASSWORD).collect();
    assert_eq!(pw.len(), 1);
    assert_eq!(pw[0].len(), 16);
    // ...and it is hidden, not the cleartext code.
    assert_ne!(&pw[0][..6], b"123456");

    // A Message-Authenticator is present.
    assert_eq!(rparsed.attr_values(attr::MESSAGE_AUTHENTICATOR).count(), 1);

    // ---- Round 2: a fresh State must be the one echoed next ----
    let state2 = hex!("CAFEBABE99");
    let pkt2 = challenge_packet(8, &[b"Re-enter code: "], Some(&state2));
    let parsed2 = parse_response(&pkt2).unwrap();
    let ch2 = Challenge::from_response(&parsed2).unwrap();
    let req2 = ch2
        .build_response(8, ra, b"alice", b"654321", b"testing123")
        .unwrap();
    let echoed2: Vec<&[u8]> = parse_response(&req2).unwrap().attr_values(attr::STATE).collect();
    assert_eq!(echoed2, vec![&state2[..]]);
}

/// Multiple Reply-Message attributes concatenate in received order (A4).
#[test]
fn reply_messages_concatenate() {
    let pkt = challenge_packet(3, &[b"Approve on ", b"your phone."], Some(b"S"));
    let parsed = parse_response(&pkt).unwrap();
    let ch = Challenge::from_response(&parsed).unwrap();
    assert_eq!(ch.prompt(), "Approve on your phone.");
}

/// Negative cases: a malformed challenge, a challenge with no State, and a
/// non-challenge response all deny without panicking (CLAUDE.md rules 1, 15).
#[test]
fn malformed_and_missing_state_deny_without_panic() {
    // M2 from TEST_VECTORS §6, retyped as an Access-Challenge (code 0x0B):
    // the trailing attribute claims Length 0x1F with one value octet present.
    let bad = hex!("0B2A0017" "00000000000000000000000000000000" "011F41");
    assert!(parse_response(&bad).is_err());

    // A truncated datagram (below the 20-octet minimum) also denies.
    assert!(parse_response(&hex!("0B2A0013")).is_err());

    // A well-formed challenge with no State: parsing succeeds but building the
    // follow-up fails closed (nothing to echo), never panics.
    let no_state = challenge_packet(9, &[b"code?"], None);
    let parsed = parse_response(&no_state).unwrap();
    let ch = Challenge::from_response(&parsed).unwrap();
    assert!(!ch.has_state());
    assert_eq!(
        ch.build_response(9, [0u8; 16], b"bob", b"000000", b"testing123"),
        Err(PapError::MissingState)
    );

    // More than one State is rejected.
    let mut b = PacketBuilder::new(Code::AccessChallenge, 4, [0u8; 16]);
    b = b.attribute(attr::STATE, b"one").unwrap();
    b = b.attribute(attr::STATE, b"two").unwrap();
    let two_state = b.build().unwrap();
    let parsed = parse_response(&two_state).unwrap();
    assert!(matches!(
        Challenge::from_response(&parsed),
        Err(PapError::MultipleState)
    ));

    // A non-challenge response (Access-Accept) is not a challenge.
    let accept = PacketBuilder::new(Code::AccessAccept, 1, [0u8; 16])
        .build()
        .unwrap();
    let parsed = parse_response(&accept).unwrap();
    assert!(matches!(
        Challenge::from_response(&parsed),
        Err(PapError::NotAChallenge)
    ));

    // An over-long code cannot be represented in PAP and denies cleanly.
    let long = vec![b'x'; pap::MAX_PASSWORD_LEN + 1];
    assert_eq!(
        build_challenge_response(1, [0u8; 16], b"bob", &long, b"S", b"testing123"),
        Err(PapError::PasswordTooLong)
    );
}

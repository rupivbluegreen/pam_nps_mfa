//! Known-answer vectors from TEST_VECTORS.md sections 3, 4, 5 and the
//! malformed-packet negatives from section 6. Per CLAUDE.md rule 4, if a
//! test here fails the bug is in the code, never in the vector.

use hex_literal::hex;

const SECRET: &[u8] = b"testing123";
const REQUEST_AUTHENTICATOR: [u8; 16] = hex!("0F0E0D0C0B0A09080706050403020100");

/// Section 4: the valid on-wire Access-Accept (42 octets).
const VALID_RESPONSE: [u8; 42] = hex!(
    "022A002A"
    "415325D27047D5EF65667EBFB5B1200E"
    "12044F4B"
    "5012"
    "87EC197FEEC0F2A4E337D1632395EF08"
);

// ---------------------------------------------------------------------------
// Section 5 vectors, exactly as published.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Section 6: malformed packets. Each must parse to Err (deny), never panic,
// never allocate from the attacker-supplied length.
// ---------------------------------------------------------------------------

#[test]
fn m1_attribute_length_below_2_denies() {
    let m1 = hex!("022A0016" "00000000000000000000000000000000" "0101");
    assert!(radius::parse_response(&m1).is_err());
}

#[test]
fn m2_attribute_length_past_end_denies() {
    let m2 = hex!("022A0017" "00000000000000000000000000000000" "011F41");
    assert!(radius::parse_response(&m2).is_err());
}

#[test]
fn m3_vendor_inner_length_overrun_denies() {
    let m3 = hex!("022A001E" "00000000000000000000000000000000" "1A0A0000013719224041");
    assert!(radius::parse_response(&m3).is_err());
}

#[test]
fn m4_header_length_larger_than_received_denies() {
    let m4 = hex!("022A00FF" "00000000000000000000000000000000");
    assert!(radius::parse_response(&m4).is_err());
}

#[test]
fn m5_header_length_below_minimum_denies() {
    let m5 = hex!("022A0013" "00000000000000000000000000000000");
    assert!(radius::parse_response(&m5).is_err());
}

// ---------------------------------------------------------------------------
// Section 4: response verification, positive and flipped-bit negative.
// ---------------------------------------------------------------------------

#[test]
fn valid_response_parses_and_both_checks_pass() {
    let parsed = radius::parse_response(&VALID_RESPONSE).expect("section 4 response is valid");
    assert_eq!(parsed.code(), 2);
    assert_eq!(parsed.known_code(), Some(radius::Code::AccessAccept));
    assert_eq!(parsed.id(), 42);
    let attrs: Vec<(u8, &[u8])> = parsed.attributes().collect();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].0, radius::attr::REPLY_MESSAGE);
    assert_eq!(attrs[0].1, b"OK");
    assert_eq!(attrs[1].0, radius::attr::MESSAGE_AUTHENTICATOR);

    assert!(radius::verify_response_authenticator(
        &VALID_RESPONSE,
        &REQUEST_AUTHENTICATOR,
        SECRET
    ));
    assert!(radius::verify_response_message_authenticator(
        &VALID_RESPONSE,
        &REQUEST_AUTHENTICATOR,
        SECRET
    ));
}

#[test]
fn flipped_bit_in_response_authenticator_denies() {
    let mut packet = VALID_RESPONSE;
    packet[4] ^= 0x01; // first octet of the Response Authenticator field
    assert!(!radius::verify_response_authenticator(
        &packet,
        &REQUEST_AUTHENTICATOR,
        SECRET
    ));

    // Restore and confirm the vector still verifies.
    packet[4] ^= 0x01;
    assert!(radius::verify_response_authenticator(
        &packet,
        &REQUEST_AUTHENTICATOR,
        SECRET
    ));
}

#[test]
fn flipped_bit_in_message_authenticator_denies() {
    // MA attribute: offset 20 (header) + 4 (Reply-Message) = 24; value at 26..42.
    let mut packet = VALID_RESPONSE;
    packet[26] ^= 0x80;
    assert!(!radius::verify_response_message_authenticator(
        &packet,
        &REQUEST_AUTHENTICATOR,
        SECRET
    ));

    // Restore and confirm the vector still verifies.
    packet[26] ^= 0x80;
    assert!(radius::verify_response_message_authenticator(
        &packet,
        &REQUEST_AUTHENTICATOR,
        SECRET
    ));
}

#[test]
fn wrong_secret_denies_both_checks() {
    assert!(!radius::verify_response_authenticator(
        &VALID_RESPONSE,
        &REQUEST_AUTHENTICATOR,
        b"testing124"
    ));
    assert!(!radius::verify_response_message_authenticator(
        &VALID_RESPONSE,
        &REQUEST_AUTHENTICATOR,
        b"testing124"
    ));
}

// ---------------------------------------------------------------------------
// Round-trip: build the section 3 request and check every byte.
// ---------------------------------------------------------------------------

#[test]
fn round_trip_builds_the_section_3_request() {
    let mut packet = radius::PacketBuilder::new(radius::Code::AccessRequest, 42, REQUEST_AUTHENTICATOR)
        .attribute(radius::attr::USER_NAME, b"User")
        .expect("User-Name fits")
        .message_authenticator_placeholder()
        .expect("placeholder fits")
        .build()
        .expect("packet fits");

    // Before filling, the packet must equal the section 3 zeroed-MA bytes.
    assert_eq!(
        packet[..],
        hex!(
            "012A002C"
            "0F0E0D0C0B0A09080706050403020100"
            "010655736572"
            "501200000000000000000000000000000000"
        )
    );

    radius::fill_message_authenticator(&mut packet, SECRET).expect("well-formed request");

    // The whole 44-octet packet with the MA filled in.
    assert_eq!(
        packet[..],
        hex!(
            "012A002C"
            "0F0E0D0C0B0A09080706050403020100"
            "010655736572"
            "5012F4CC66C3929058ED76A7C8D409A381D1"
        )
    );
}

// ---------------------------------------------------------------------------
// Binding, encoding bounds, and randomness (rule 18).
// ---------------------------------------------------------------------------

#[test]
fn request_binding_accepts_the_matching_response_only() {
    let binding = radius::RequestBinding::new(42, REQUEST_AUTHENTICATOR);
    assert!(binding.verify_response(&VALID_RESPONSE, SECRET));

    // Wrong identifier: same bytes bound to a different outstanding request.
    let other = radius::RequestBinding::new(43, REQUEST_AUTHENTICATOR);
    assert!(!other.verify_response(&VALID_RESPONSE, SECRET));

    // Wrong request authenticator.
    let stale = radius::RequestBinding::new(42, [0u8; 16]);
    assert!(!stale.verify_response(&VALID_RESPONSE, SECRET));

    // Malformed input never matches.
    assert!(!binding.verify_response(&[], SECRET));
}

#[test]
fn strict_binding_rejects_a_response_without_message_authenticator() {
    // Build a response carrying only Reply-Message "OK" with a correct
    // Response Authenticator but no Message-Authenticator.
    let attrs = hex!("12044F4B");
    let ra = radius::response_authenticator(2, 42, 24, &REQUEST_AUTHENTICATOR, &attrs, SECRET);
    let mut packet = Vec::new();
    packet.extend_from_slice(&hex!("022A0018"));
    packet.extend_from_slice(&ra);
    packet.extend_from_slice(&attrs);

    let strict = radius::RequestBinding::new(42, REQUEST_AUTHENTICATOR);
    assert!(!strict.verify_response(&packet, SECRET));

    let lax = radius::RequestBinding::new(42, REQUEST_AUTHENTICATOR)
        .require_message_authenticator(false);
    assert!(lax.verify_response(&packet, SECRET));
}

#[test]
fn attribute_value_over_253_octets_is_rejected() {
    let value = [0u8; 254];
    assert_eq!(
        radius::encode_attribute(radius::attr::STATE, &value),
        Err(radius::EncodeError::ValueTooLong)
    );
    // 253 octets is the maximum representable value and must succeed.
    let encoded = radius::encode_attribute(radius::attr::STATE, &value[..253]).unwrap();
    assert_eq!(encoded.len(), 255);
    assert_eq!(encoded[1], 255);
}

#[test]
fn vendor_specific_decoding_round_trip_and_bounds() {
    // MS-CHAP-Challenge-shaped VSA value: Vendor-Id 311, Vendor-Type 11,
    // Vendor-Length 18, 16 octets of data.
    let mut value = Vec::new();
    value.extend_from_slice(&311u32.to_be_bytes());
    value.push(11);
    value.push(18);
    value.extend_from_slice(&[0xAA; 16]);
    let vsa = radius::decode_vendor_specific(&value).expect("well-formed VSA");
    assert_eq!(vsa.vendor_id, radius::VENDOR_ID_MICROSOFT);
    assert_eq!(vsa.vendor_type, 11);
    assert_eq!(vsa.vendor_data, &[0xAA; 16][..]);

    // Inner Vendor-Length overrunning the outer value must deny (M3 shape).
    let m3_value = hex!("0000013719224041");
    assert!(radius::decode_vendor_specific(&m3_value).is_err());
    // Too short to hold Vendor-Id plus an inner header.
    assert!(radius::decode_vendor_specific(&hex!("0000013719")).is_err());
    // Inner Vendor-Length below 2.
    assert!(radius::decode_vendor_specific(&hex!("000001371901")).is_err());
}

#[test]
fn fresh_request_authenticators_come_from_the_csprng() {
    let a = radius::fresh_request_authenticator().expect("OS CSPRNG available");
    let b = radius::fresh_request_authenticator().expect("OS CSPRNG available");
    // Two fresh 128-bit values colliding (or being all zero) means the
    // generator is broken.
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 16]);
}

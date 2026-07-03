//! Fuzz the RADIUS response parser and both response verification paths.
//! These are the network-facing attack surface (CLAUDE.md rule 15): no
//! input may ever cause a panic, an unbounded allocation, or an accept.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Structural parse must never panic. On success, exercise the
    // vendor-specific decoder on every VSA it surfaced.
    if let Ok(parsed) = radius::parse_response(data) {
        let _ = parsed.known_code();
        for (attr_type, value) in parsed.attributes() {
            if attr_type == radius::attr::VENDOR_SPECIFIC {
                let _ = radius::decode_vendor_specific(value);
            }
        }
    }

    // Both verifiers must fail closed (false) without panicking, whatever
    // the input. The request authenticator and secret are fixed; the checks
    // exercise the bounded rewrite-and-MAC paths.
    let request_authenticator = [0u8; 16];
    let _ = radius::verify_response_authenticator(data, &request_authenticator, b"fuzz-secret");
    let _ = radius::verify_response_message_authenticator(
        data,
        &request_authenticator,
        b"fuzz-secret",
    );

    // Response binding is the composed deny path the PAM flow relies on.
    let binding = radius::RequestBinding::new(0x2A, request_authenticator);
    let _ = binding.verify_response(data, b"fuzz-secret");
});

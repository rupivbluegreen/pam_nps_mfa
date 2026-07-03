//! Authenticator and Message-Authenticator computation and verification
//! (RFC 2865 §3, RFC 3579 §3.2; IMPLEMENTATION_SPEC.md §3).
//!
//! Both response checks use the ORIGINAL Request Authenticator, never the
//! response's own Authenticator field. All comparisons of integrity values
//! are constant time (CLAUDE.md rule 7).

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use subtle::ConstantTimeEq;

use crate::attr;
use crate::parse::{declared_length, for_each_attribute, parse_response};

type HmacMd5 = Hmac<Md5>;

/// HMAC-MD5 over the concatenation of `parts`, keyed by `key`.
///
/// Returns `None` instead of panicking if the MAC could not be keyed; HMAC
/// accepts keys of any length, so that path is unreachable, but every caller
/// still fails closed on `None`.
fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> Option<[u8; 16]> {
    let mut mac = HmacMd5::new_from_slice(key).ok()?;
    for part in parts {
        mac.update(part);
    }
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    Some(out)
}

/// Compute the Message-Authenticator for an outgoing Access-Request
/// (RFC 3579 §3.2): HMAC-MD5 keyed by the shared secret over the entire
/// packet with the 16 Message-Authenticator value octets set to zero.
///
/// If keying ever failed the function returns an all-zero MAC, which no
/// correct peer will accept — fail closed, never a panic.
pub fn message_authenticator(packet_with_ma_zeroed: &[u8], secret: &[u8]) -> [u8; 16] {
    hmac_md5(secret, &[packet_with_ma_zeroed]).unwrap_or([0u8; 16])
}

/// Compute a Response Authenticator (RFC 2865 §3):
/// `MD5(Code | Id | Length | RequestAuthenticator | Attributes | secret)`
/// where `Attributes` are the response attribute octets exactly as received
/// (Message-Authenticator left filled).
pub fn response_authenticator(
    code: u8,
    id: u8,
    length: u16,
    request_authenticator: &[u8; 16],
    attributes_ma_filled: &[u8],
    secret: &[u8],
) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update([code, id]);
    hasher.update(length.to_be_bytes());
    hasher.update(request_authenticator);
    hasher.update(attributes_ma_filled);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// Verify the Response Authenticator of a received response against the
/// ORIGINAL Request Authenticator, in constant time.
///
/// Returns `false` (deny) on any structural defect or mismatch. Never
/// panics on any input.
pub fn verify_response_authenticator(
    packet: &[u8],
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> bool {
    // Full structural validation first; a malformed packet denies outright.
    if parse_response(packet).is_err() {
        return false;
    }
    let declared = match declared_length(packet) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let expected = response_authenticator(
        packet[0],
        packet[1],
        declared as u16, // declared <= 4096, always fits
        request_authenticator,
        &packet[20..declared],
        secret,
    );
    bool::from(expected[..].ct_eq(&packet[4..20]))
}

/// Verify the Message-Authenticator of a received response (RFC 3579):
/// `HMAC-MD5(secret, Code | Id | Length | RequestAuthenticator |
/// Attributes_with_MA_zeroed)` compared in constant time against the
/// received value. Uses the ORIGINAL Request Authenticator, not the
/// response's own Authenticator field.
///
/// Returns `false` (deny) if the packet is malformed, carries no
/// Message-Authenticator, carries more than one, its value is not 16
/// octets, or the MAC does not match. Never panics on any input.
pub fn verify_response_message_authenticator(
    packet: &[u8],
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> bool {
    if parse_response(packet).is_err() {
        return false;
    }
    let declared = match declared_length(packet) {
        Ok(d) => d,
        Err(_) => return false,
    };

    // Copy the attribute region so the received MA value can be zeroed.
    // Bounded: declared <= 4096, already validated.
    let mut attrs = packet[20..declared].to_vec();
    let mut received: Option<[u8; 16]> = None;
    let mut invalid = false;
    let walk = for_each_attribute(&packet[20..declared], |off, attr_type, value| {
        if attr_type == attr::MESSAGE_AUTHENTICATOR {
            if value.len() != 16 || received.is_some() {
                invalid = true; // wrong size or duplicate: deny
            } else {
                let mut ma = [0u8; 16];
                ma.copy_from_slice(value);
                received = Some(ma);
                attrs[off + 2..off + 18].fill(0);
            }
        }
        Ok(())
    });
    if walk.is_err() || invalid {
        return false;
    }
    let received = match received {
        Some(ma) => ma,
        None => return false, // no Message-Authenticator to verify: deny
    };

    let expected = match hmac_md5(secret, &[&packet[0..4], request_authenticator, &attrs]) {
        Some(mac) => mac,
        None => return false,
    };
    bool::from(expected.ct_eq(&received))
}

//! Response-to-request binding (CLAUDE.md rule 14).
//!
//! The transport layer additionally checks the source address and port; this
//! type covers the codec-level checks: the Identifier octet, the Response
//! Authenticator, and the Message-Authenticator.

use crate::auth::{verify_response_authenticator, verify_response_message_authenticator};
use crate::{attr, parse_response};

/// The fields of an outstanding Access-Request that a response must match.
///
/// Deliberately implements neither `Debug` nor `Display`.
pub struct RequestBinding {
    id: u8,
    request_authenticator: [u8; 16],
    require_message_authenticator: bool,
}

impl RequestBinding {
    /// Bind to a request by its Identifier and Request Authenticator.
    /// Strict mode: a response without a Message-Authenticator is rejected
    /// (IMPLEMENTATION_SPEC.md §3, the default).
    pub fn new(id: u8, request_authenticator: [u8; 16]) -> Self {
        Self {
            id,
            request_authenticator,
            require_message_authenticator: true,
        }
    }

    /// Override strict mode (config `require_message_authenticator false`).
    /// A present Message-Authenticator is always verified; this only governs
    /// whether an absent one denies.
    pub fn require_message_authenticator(mut self, required: bool) -> Self {
        self.require_message_authenticator = required;
        self
    }

    /// The Identifier this binding matches.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// The original Request Authenticator, needed by both response checks.
    pub fn request_authenticator(&self) -> &[u8; 16] {
        &self.request_authenticator
    }

    /// `true` only if the response is structurally valid, its Identifier
    /// matches, its Response Authenticator verifies against the original
    /// Request Authenticator, and its Message-Authenticator verifies (or is
    /// absent while strict mode is off). Anything else — including any
    /// malformed input — returns `false`: the caller discards the datagram
    /// and keeps waiting until its timeout. Never panics.
    pub fn verify_response(&self, packet: &[u8], secret: &[u8]) -> bool {
        let parsed = match parse_response(packet) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // The Identifier is public routing data, not an integrity value, so
        // a plain comparison is fine here.
        if parsed.id() != self.id {
            return false;
        }
        if !verify_response_authenticator(packet, &self.request_authenticator, secret) {
            return false;
        }
        let has_ma = parsed
            .attributes()
            .any(|(t, _)| t == attr::MESSAGE_AUTHENTICATOR);
        if has_ma {
            verify_response_message_authenticator(packet, &self.request_authenticator, secret)
        } else {
            !self.require_message_authenticator
        }
    }
}

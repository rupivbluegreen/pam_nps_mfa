#![forbid(unsafe_code)]
//! RADIUS codec for `pam_nps_mfa` (phase 1).
//!
//! Packet build and parse, Request Authenticator generation,
//! Message-Authenticator compute/verify (RFC 3579), Response Authenticator
//! compute/verify (RFC 2865), and response-to-request binding.
//!
//! Security posture (CLAUDE.md hard rules):
//! - Fail closed: every parse/verify path returns `Result` or `bool`;
//!   malformed input denies, never panics, never succeeds.
//! - Constant-time comparison (`subtle`) for every authenticator and MAC.
//! - Bounded parsing: packet length outside [20, 4096] is rejected before
//!   parsing; every attribute length is checked; VSA nesting is checked at
//!   both the outer attribute length and the inner Vendor-Length; no
//!   allocation is sized from an attacker-supplied length.
//! - A `getrandom` failure denies (rule 18); no weak or zero fallback.
//! - The shared secret is only ever a `&[u8]` parameter and is never logged,
//!   formatted, or stored by any type in this crate.

mod auth;
mod binding;
mod packet;
mod parse;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod transport;
mod udp;

pub use auth::{
    message_authenticator, response_authenticator, verify_response_authenticator,
    verify_response_message_authenticator,
};
pub use binding::RequestBinding;
pub use packet::{
    encode_attribute, fill_message_authenticator, fresh_request_authenticator, PacketBuilder,
};
pub use parse::{decode_vendor_specific, parse_response, ParsedResponse, VendorSpecific};
pub use transport::{RadiusTransport, TransportError};
pub use udp::UdpTransport;

/// Minimum RADIUS packet length in octets (header only), RFC 2865 §3.
pub const MIN_PACKET_LEN: usize = 20;
/// Maximum RADIUS packet length in octets, RFC 2865 §3.
pub const MAX_PACKET_LEN: usize = 4096;
/// Microsoft Vendor-Id for Vendor-Specific attributes (RFC 2548).
pub const VENDOR_ID_MICROSOFT: u32 = 311;

/// RADIUS packet codes used by this module (IMPLEMENTATION_SPEC.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Code {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccessChallenge = 11,
}

impl Code {
    /// The on-wire code octet.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Map a received code octet to a known code, `None` for anything else.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::AccessRequest),
            2 => Some(Self::AccessAccept),
            3 => Some(Self::AccessReject),
            11 => Some(Self::AccessChallenge),
            _ => None,
        }
    }
}

/// RADIUS attribute type numbers used by this module
/// (IMPLEMENTATION_SPEC.md §3; do not invent others — CLAUDE.md rule 13).
pub mod attr {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const NAS_IP_ADDRESS: u8 = 4;
    pub const REPLY_MESSAGE: u8 = 18;
    pub const STATE: u8 = 24;
    pub const VENDOR_SPECIFIC: u8 = 26;
    pub const NAS_IDENTIFIER: u8 = 32;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
}

/// Structural parse failure. Every variant denies the authentication.
///
/// Carries no packet bytes and no secret material, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than 20 octets received.
    PacketTooShort,
    /// More than 4096 octets received.
    PacketTooLong,
    /// The header Length field is below 20 or above 4096.
    LengthFieldInvalid,
    /// The header Length field claims more octets than were received.
    LengthExceedsDatagram,
    /// An attribute Length octet is below the 2-octet minimum.
    AttributeLengthInvalid,
    /// An attribute runs past the end of the packet.
    AttributeOverrun,
    /// A Vendor-Specific attribute is too short to hold Vendor-Id plus one
    /// inner header.
    VendorTooShort,
    /// An inner Vendor-Length is below 2 or overruns the outer attribute.
    VendorLengthInvalid,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::PacketTooShort => "packet shorter than the 20-octet RADIUS minimum",
            Self::PacketTooLong => "packet longer than the 4096-octet RADIUS maximum",
            Self::LengthFieldInvalid => "header Length field outside the 20..=4096 range",
            Self::LengthExceedsDatagram => "header Length field exceeds the received octets",
            Self::AttributeLengthInvalid => "attribute Length below the 2-octet minimum",
            Self::AttributeOverrun => "attribute runs past the end of the packet",
            Self::VendorTooShort => "vendor-specific attribute too short for its headers",
            Self::VendorLengthInvalid => "inner Vendor-Length invalid or overruns the attribute",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ParseError {}

/// Packet construction failure. Carries no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// Attribute value longer than 253 octets (Length is a single octet).
    ValueTooLong,
    /// Assembled packet would exceed the 4096-octet RADIUS maximum.
    PacketTooLong,
    /// The packet handed to `fill_message_authenticator` is not structurally
    /// valid.
    MalformedPacket,
    /// No Message-Authenticator attribute to fill.
    MissingMessageAuthenticator,
    /// More than one Message-Authenticator attribute present.
    DuplicateMessageAuthenticator,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::ValueTooLong => "attribute value exceeds the 253-octet maximum",
            Self::PacketTooLong => "packet would exceed the 4096-octet RADIUS maximum",
            Self::MalformedPacket => "packet is not structurally valid",
            Self::MissingMessageAuthenticator => "no Message-Authenticator attribute present",
            Self::DuplicateMessageAuthenticator => {
                "more than one Message-Authenticator attribute present"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for EncodeError {}

/// The OS CSPRNG failed. The caller must deny the authentication
/// (CLAUDE.md rule 18); there is no fallback material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("system randomness unavailable; deny the authentication")
    }
}

impl std::error::Error for RngError {}

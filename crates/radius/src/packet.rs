//! Attribute encoding and Access-Request assembly.

use crate::auth::message_authenticator;
use crate::parse::for_each_attribute;
use crate::{attr, Code, EncodeError, RngError, MAX_PACKET_LEN, MIN_PACKET_LEN};

/// Largest attribute value: 255 (one-octet Length) minus the 2-octet header.
const MAX_ATTR_VALUE_LEN: usize = 253;

/// Encode one attribute as `Type | Length | Value` with
/// `Length = value.len() + 2`. Values longer than 253 octets cannot be
/// represented and are rejected.
pub fn encode_attribute(attr_type: u8, value: &[u8]) -> Result<Vec<u8>, EncodeError> {
    if value.len() > MAX_ATTR_VALUE_LEN {
        return Err(EncodeError::ValueTooLong);
    }
    let total = value.len() + 2;
    let mut out = Vec::with_capacity(total);
    out.push(attr_type);
    out.push(total as u8);
    out.extend_from_slice(value);
    Ok(out)
}

/// Generate a fresh 16-octet Request Authenticator from the OS CSPRNG.
///
/// A `getrandom` failure returns `Err(RngError)` and the caller must deny
/// (CLAUDE.md rule 18). Never falls back to zero or time-based material.
pub fn fresh_request_authenticator() -> Result<[u8; 16], RngError> {
    let mut ra = [0u8; 16];
    getrandom::getrandom(&mut ra).map_err(|_| RngError)?;
    Ok(ra)
}

/// Assembles `Code | Id | Length | Authenticator | attributes`.
///
/// Deliberately implements neither `Debug` nor `Display`: the attribute
/// buffer can hold credential material (CLAUDE.md rule 3).
pub struct PacketBuilder {
    code: Code,
    id: u8,
    authenticator: [u8; 16],
    attributes: Vec<u8>,
}

impl PacketBuilder {
    /// Start a packet. For an Access-Request the authenticator is a fresh
    /// [`fresh_request_authenticator`] value.
    pub fn new(code: Code, id: u8, authenticator: [u8; 16]) -> Self {
        Self {
            code,
            id,
            authenticator,
            attributes: Vec::new(),
        }
    }

    /// Append one attribute. Fails if the value cannot fit a one-octet
    /// Length or the packet would exceed 4096 octets.
    pub fn attribute(mut self, attr_type: u8, value: &[u8]) -> Result<Self, EncodeError> {
        let encoded = encode_attribute(attr_type, value)?;
        if MIN_PACKET_LEN + self.attributes.len() + encoded.len() > MAX_PACKET_LEN {
            return Err(EncodeError::PacketTooLong);
        }
        self.attributes.extend_from_slice(&encoded);
        Ok(self)
    }

    /// Append a Message-Authenticator attribute (type 80, length 18) with
    /// its 16 value octets zeroed, to be filled by
    /// [`fill_message_authenticator`] after the packet is assembled.
    pub fn message_authenticator_placeholder(self) -> Result<Self, EncodeError> {
        self.attribute(attr::MESSAGE_AUTHENTICATOR, &[0u8; 16])
    }

    /// Assemble the final packet bytes with the Length field covering the
    /// whole packet.
    pub fn build(self) -> Result<Vec<u8>, EncodeError> {
        let total = MIN_PACKET_LEN + self.attributes.len();
        if total > MAX_PACKET_LEN {
            return Err(EncodeError::PacketTooLong);
        }
        let mut out = Vec::with_capacity(total);
        out.push(self.code.as_u8());
        out.push(self.id);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&self.authenticator);
        out.extend_from_slice(&self.attributes);
        Ok(out)
    }
}

/// Fill the Message-Authenticator of a fully assembled request in place:
/// zero the 16 value octets, compute HMAC-MD5 keyed by the shared secret
/// over the whole packet, and write the result back into the attribute
/// value (RFC 3579 §3.2).
///
/// The packet must be structurally valid, its Length field must equal the
/// buffer length, and it must carry exactly one Message-Authenticator of
/// length 18. Anything else is an error and nothing is written back.
pub fn fill_message_authenticator(packet: &mut [u8], secret: &[u8]) -> Result<(), EncodeError> {
    if packet.len() < MIN_PACKET_LEN || packet.len() > MAX_PACKET_LEN {
        return Err(EncodeError::MalformedPacket);
    }
    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if declared != packet.len() {
        return Err(EncodeError::MalformedPacket);
    }

    let mut ma_value_off: Option<usize> = None;
    let mut bad_length = false;
    let mut duplicate = false;
    let walk = for_each_attribute(&packet[MIN_PACKET_LEN..], |off, attr_type, value| {
        if attr_type == attr::MESSAGE_AUTHENTICATOR {
            if value.len() != 16 {
                bad_length = true;
            } else if ma_value_off.is_some() {
                duplicate = true;
            } else {
                ma_value_off = Some(MIN_PACKET_LEN + off + 2);
            }
        }
        Ok(())
    });
    if walk.is_err() || bad_length {
        return Err(EncodeError::MalformedPacket);
    }
    if duplicate {
        return Err(EncodeError::DuplicateMessageAuthenticator);
    }
    let off = ma_value_off.ok_or(EncodeError::MissingMessageAuthenticator)?;

    packet[off..off + 16].fill(0);
    let mac = message_authenticator(packet, secret);
    packet[off..off + 16].copy_from_slice(&mac);
    Ok(())
}

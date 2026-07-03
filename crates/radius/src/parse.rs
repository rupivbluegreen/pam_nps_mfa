//! Bounded response parsing. This is the primary network-facing attack
//! surface: every length is checked before use, no allocation is sized from
//! an attacker-supplied length, and any structural defect is a fatal error
//! that denies the authentication (CLAUDE.md rule 15).

use crate::{attr, Code, ParseError, MAX_PACKET_LEN, MIN_PACKET_LEN};

/// A structurally validated RADIUS response.
///
/// Structural validity says nothing about authenticity: callers must still
/// verify the Response Authenticator and the Message-Authenticator (see
/// [`crate::RequestBinding`]) before trusting any attribute in here.
pub struct ParsedResponse<'a> {
    code: u8,
    id: u8,
    authenticator: [u8; 16],
    attrs: Vec<(u8, &'a [u8])>,
}

impl<'a> ParsedResponse<'a> {
    /// The raw code octet as received.
    pub fn code(&self) -> u8 {
        self.code
    }

    /// The code mapped to a known [`Code`], `None` for anything else.
    pub fn known_code(&self) -> Option<Code> {
        Code::from_u8(self.code)
    }

    /// The Identifier octet.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// The Authenticator field as received (the Response Authenticator).
    pub fn authenticator(&self) -> &[u8; 16] {
        &self.authenticator
    }

    /// All attributes in received order as `(type, value)` pairs.
    pub fn attributes(&self) -> impl Iterator<Item = (u8, &'a [u8])> + '_ {
        self.attrs.iter().copied()
    }

    /// Values of every attribute of the given type, in received order.
    pub fn attr_values(&self, attr_type: u8) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.attrs
            .iter()
            .filter(move |(t, _)| *t == attr_type)
            .map(|(_, v)| *v)
    }
}

/// Validate the fixed header and return the declared packet length.
///
/// Enforces: received length within [20, 4096], declared Length within
/// [20, 4096], and declared Length not exceeding the received octets.
/// Trailing octets beyond the declared Length are padding per RFC 2865 §3
/// and are ignored by the caller.
pub(crate) fn declared_length(packet: &[u8]) -> Result<usize, ParseError> {
    if packet.len() < MIN_PACKET_LEN {
        return Err(ParseError::PacketTooShort);
    }
    if packet.len() > MAX_PACKET_LEN {
        return Err(ParseError::PacketTooLong);
    }
    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if !(MIN_PACKET_LEN..=MAX_PACKET_LEN).contains(&declared) {
        return Err(ParseError::LengthFieldInvalid);
    }
    if declared > packet.len() {
        return Err(ParseError::LengthExceedsDatagram);
    }
    Ok(declared)
}

/// Walk the attribute region, calling `f(offset, type, value)` for each
/// attribute, where `offset` is the attribute's start relative to `attrs`.
///
/// Every attribute Length is validated: below 2 or running past the end of
/// the region is a fatal error.
pub(crate) fn for_each_attribute<'a, F>(attrs: &'a [u8], mut f: F) -> Result<(), ParseError>
where
    F: FnMut(usize, u8, &'a [u8]) -> Result<(), ParseError>,
{
    let mut off = 0usize;
    while off < attrs.len() {
        if attrs.len() - off < 2 {
            // A lone type octet cannot hold its own header.
            return Err(ParseError::AttributeLengthInvalid);
        }
        let attr_type = attrs[off];
        let attr_len = usize::from(attrs[off + 1]);
        if attr_len < 2 {
            return Err(ParseError::AttributeLengthInvalid);
        }
        if attr_len > attrs.len() - off {
            return Err(ParseError::AttributeOverrun);
        }
        f(off, attr_type, &attrs[off + 2..off + attr_len])?;
        off += attr_len;
    }
    Ok(())
}

/// Validate the inner TLV structure of a Vendor-Specific attribute value:
/// a 4-octet Vendor-Id followed by one or more (Vendor-Type, Vendor-Length,
/// Data) entries that exactly fill the outer value. Each Vendor-Length
/// includes its own 2-octet header, so below 2 or overrunning the outer
/// attribute is fatal (test vector M3).
fn validate_vendor_specific(value: &[u8]) -> Result<(), ParseError> {
    if value.len() < 6 {
        return Err(ParseError::VendorTooShort);
    }
    let mut off = 4usize; // skip Vendor-Id
    while off < value.len() {
        if value.len() - off < 2 {
            return Err(ParseError::VendorLengthInvalid);
        }
        let vlen = usize::from(value[off + 1]);
        if vlen < 2 || vlen > value.len() - off {
            return Err(ParseError::VendorLengthInvalid);
        }
        off += vlen;
    }
    Ok(())
}

/// Parse a received response into code, id, authenticator, and attributes.
///
/// Rejects, before and independent of any authenticator check: packets
/// outside [20, 4096] octets, a Length field outside that range or larger
/// than the datagram, any attribute Length below 2 or overrunning the
/// packet, and any Vendor-Specific attribute whose inner Vendor-Length is
/// invalid. Never panics on any input.
pub fn parse_response(packet: &[u8]) -> Result<ParsedResponse<'_>, ParseError> {
    let declared = declared_length(packet)?;
    let mut authenticator = [0u8; 16];
    authenticator.copy_from_slice(&packet[4..20]);

    // Grows one entry per already-validated attribute (each >= 2 octets in a
    // <= 4096-octet packet), never from an attacker-supplied length.
    let mut attrs: Vec<(u8, &[u8])> = Vec::new();
    for_each_attribute(&packet[20..declared], |_off, attr_type, value| {
        if attr_type == attr::VENDOR_SPECIFIC {
            validate_vendor_specific(value)?;
        }
        attrs.push((attr_type, value));
        Ok(())
    })?;

    Ok(ParsedResponse {
        code: packet[0],
        id: packet[1],
        authenticator,
        attrs,
    })
}

/// A decoded Vendor-Specific attribute carrying exactly one inner TLV,
/// the layout of every Microsoft attribute this module consumes
/// (IMPLEMENTATION_SPEC.md §5).
pub struct VendorSpecific<'a> {
    pub vendor_id: u32,
    pub vendor_type: u8,
    pub vendor_data: &'a [u8],
}

/// Decode a Vendor-Specific attribute *value* (the octets after the outer
/// Type and Length) into Vendor-Id, Vendor-Type, and Vendor-Data.
///
/// Requires the single inner TLV to exactly fill the outer value:
/// `Vendor-Length == value.len() - 4`. Anything else is a fatal error.
pub fn decode_vendor_specific(value: &[u8]) -> Result<VendorSpecific<'_>, ParseError> {
    if value.len() < 6 {
        return Err(ParseError::VendorTooShort);
    }
    let vendor_id = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    let vendor_type = value[4];
    let vendor_len = usize::from(value[5]);
    if vendor_len < 2 || vendor_len != value.len() - 4 {
        return Err(ParseError::VendorLengthInvalid);
    }
    Ok(VendorSpecific {
        vendor_id,
        vendor_type,
        vendor_data: &value[6..],
    })
}

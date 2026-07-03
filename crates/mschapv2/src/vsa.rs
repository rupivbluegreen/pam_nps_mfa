//! RFC 2548 Microsoft vendor attribute wire layout (IMPLEMENTATION_SPEC.md
//! §5), built on the radius crate's Vendor-Specific envelope (Vendor-Id 311 =
//! 0x00000137).
//!
//! Encoders produce the Vendor-Specific *value* — the octets after the outer
//! Type and Length — ready to hand to `radius::PacketBuilder::attribute(
//! radius::attr::VENDOR_SPECIFIC, value)`, which prepends the outer header. The
//! outer Length is therefore `value.len() + 2`.
//!
//! Parsers operate on attacker-supplied bytes from the network and are fully
//! bounded (CLAUDE.md rule 15): a malformed S=/E= string or an overrunning
//! VSA denies and never panics.

/// Microsoft Vendor-Type numbers carried inside Vendor-Specific (type 26) with
/// Vendor-Id 311 (RFC 2548; IMPLEMENTATION_SPEC.md §5). Do not invent others
/// (CLAUDE.md rule 13).
pub mod vendor_type {
    /// MS-CHAP-Error, carried in an Access-Reject.
    pub const MS_CHAP_ERROR: u8 = 2;
    /// MS-CHAP-Challenge (the 16-octet Authenticator Challenge).
    pub const MS_CHAP_CHALLENGE: u8 = 11;
    /// MS-CHAP2-Response (the 50-octet client response).
    pub const MS_CHAP2_RESPONSE: u8 = 25;
    /// MS-CHAP2-Success, carried in an Access-Accept.
    pub const MS_CHAP2_SUCCESS: u8 = 26;
}

/// Build the Vendor-Specific *value* for one Microsoft attribute:
/// `Vendor-Id(4) ++ Vendor-Type(1) ++ Vendor-Length(1) ++ Data`, where
/// Vendor-Length includes its own two header octets (`2 + Data`). The Data
/// here is always a fixed small size, so the one-octet Vendor-Length never
/// overflows.
fn vsa_value(vtype: u8, data: &[u8]) -> Vec<u8> {
    let vendor_length = 2 + data.len();
    let mut v = Vec::with_capacity(6 + data.len());
    v.extend_from_slice(&radius::VENDOR_ID_MICROSOFT.to_be_bytes());
    v.push(vtype);
    v.push(vendor_length as u8);
    v.extend_from_slice(data);
    v
}

/// Encode MS-CHAP-Challenge (Vendor-Type 11): Data is the 16-octet
/// Authenticator Challenge. Vendor-Length 18, outer Length 24.
pub fn encode_ms_chap_challenge(auth_challenge: &[u8; 16]) -> Vec<u8> {
    vsa_value(vendor_type::MS_CHAP_CHALLENGE, auth_challenge)
}

/// Encode MS-CHAP2-Response (Vendor-Type 25). Data is 50 octets:
/// `Ident(1) ++ Flags(1)=0 ++ Peer-Challenge(16) ++ Reserved(8)=0 ++
/// NT-Response(24)`. Vendor-Length 52, outer Length 58.
///
/// `ident` is client-chosen; it is not part of the crypto, so any consistent
/// value works (IMPLEMENTATION_SPEC.md §5).
pub fn encode_ms_chap2_response(
    ident: u8,
    peer_challenge: &[u8; 16],
    nt_response: &[u8; 24],
) -> Vec<u8> {
    let mut data = [0u8; 50];
    data[0] = ident;
    data[1] = 0; // Flags must be 0.
    data[2..18].copy_from_slice(peer_challenge);
    // data[18..26] Reserved stays all zero.
    data[26..50].copy_from_slice(nt_response);
    vsa_value(vendor_type::MS_CHAP2_RESPONSE, &data)
}

/// A malformed MS-CHAP2-Success authenticator string. Every variant denies
/// the login (CLAUDE.md rule 6). Carries no bytes, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessError {
    /// Data too short to hold the Ident plus `"S=" + 40 hex`.
    TooShort,
    /// The response does not begin with `S=`.
    MissingSPrefix,
    /// The 40 characters after `S=` are not all hexadecimal.
    NotHex,
    /// Octets follow the `S=` value without the expected ` M=` separator.
    TrailingGarbage,
}

impl core::fmt::Display for SuccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::TooShort => "MS-CHAP2-Success data too short for the S= authenticator",
            Self::MissingSPrefix => "MS-CHAP2-Success response does not start with S=",
            Self::NotHex => "MS-CHAP2-Success S= value is not 40 hex characters",
            Self::TrailingGarbage => "MS-CHAP2-Success has trailing octets after the S= value",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SuccessError {}

/// Parse an MS-CHAP2-Success (Vendor-Type 26) Data field and extract the
/// authenticator response as a normalized `"S=" + 40 UPPERCASE hex` string.
///
/// `vendor_data` is the Data after the VSA envelope: `Ident(1)` followed by an
/// authenticator string beginning `S=` and 40 hex characters, optionally
/// `" M=<message>"`. Fully bounded; a malformed string denies and never
/// panics. Feed the result to [`crate::verify_authenticator_response`] against
/// the locally computed value for the constant-time mutual-auth check.
pub fn parse_ms_chap2_success(vendor_data: &[u8]) -> Result<String, SuccessError> {
    // Skip the one-octet Ident. Need at least Ident + "S=" + 40 hex.
    let s = vendor_data.get(1..).ok_or(SuccessError::TooShort)?;
    if s.len() < 42 {
        return Err(SuccessError::TooShort);
    }
    if &s[0..2] != b"S=" {
        return Err(SuccessError::MissingSPrefix);
    }
    let hex = &s[2..42];
    if !hex.iter().all(u8::is_ascii_hexdigit) {
        return Err(SuccessError::NotHex);
    }
    // Anything past the 40 hex octets must be the ` M=` message separator.
    if s.len() > 42 && s[42] != b' ' {
        return Err(SuccessError::TrailingGarbage);
    }

    let mut out = String::with_capacity(42);
    out.push_str("S=");
    for &c in hex {
        out.push(c.to_ascii_uppercase() as char);
    }
    Ok(out)
}

/// A parsed MS-CHAP-Error code (Vendor-Type 2). Every variant is a DENY; the
/// distinction only drives the audit reason and the user-facing message
/// (IMPLEMENTATION_SPEC.md §5). Carries no network bytes, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsChapError {
    /// E=646 — logon outside restricted hours.
    RestrictedHours,
    /// E=647 — account disabled.
    AccountDisabled,
    /// E=648 — password expired. v1 has no MS-CHAP2-CPW: deny and tell the
    /// user to change it elsewhere.
    PasswordExpired,
    /// E=649 — no dial-in permission.
    NoDialInPermission,
    /// E=691 — authentication failure (bad password / unknown user).
    AuthenticationFailure,
    /// E=709 — error changing password.
    ErrorChangingPassword,
    /// A numeric E= code outside the mapped set: generic deny.
    Unknown(u32),
    /// The error string could not be parsed at all: deny, never panic.
    Malformed,
}

impl MsChapError {
    /// Map a numeric `E=` code to a typed error.
    fn from_code(code: u32) -> Self {
        match code {
            646 => Self::RestrictedHours,
            647 => Self::AccountDisabled,
            648 => Self::PasswordExpired,
            649 => Self::NoDialInPermission,
            691 => Self::AuthenticationFailure,
            709 => Self::ErrorChangingPassword,
            other => Self::Unknown(other),
        }
    }

    /// A short, secret-free reason suitable for an audit record.
    pub fn reason(self) -> &'static str {
        match self {
            Self::RestrictedHours => "restricted-hours",
            Self::AccountDisabled => "account-disabled",
            Self::PasswordExpired => "password-expired",
            Self::NoDialInPermission => "no-dial-in",
            Self::AuthenticationFailure => "auth-failure",
            Self::ErrorChangingPassword => "error-changing-password",
            Self::Unknown(_) => "unknown-error-code",
            Self::Malformed => "malformed-error",
        }
    }
}

impl core::fmt::Display for MsChapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

/// Parse an MS-CHAP-Error (Vendor-Type 2) Data field into a typed code.
///
/// `vendor_data` is `Ident(1)` followed by a string such as
/// `E=691 R=1 C=<32 hex> V=3 M=<text>`. Extracts the `E=` code and maps it; an
/// unmapped numeric code becomes [`MsChapError::Unknown`] and an unparseable
/// string becomes [`MsChapError::Malformed`]. Fully bounded; never panics.
/// Every outcome is a deny.
pub fn parse_ms_chap_error(vendor_data: &[u8]) -> MsChapError {
    let s = match vendor_data.get(1..) {
        Some(s) => s,
        None => return MsChapError::Malformed,
    };
    match find_e_code(s) {
        Some(code) => MsChapError::from_code(code),
        None => MsChapError::Malformed,
    }
}

/// Find the `E=` token and read its decimal code. Bounded to at most 9 digits
/// so the accumulator cannot overflow (and `checked_*` guards it regardless).
fn find_e_code(s: &[u8]) -> Option<u32> {
    let start = s.windows(2).position(|w| w == b"E=")? + 2;
    let mut value: u32 = 0;
    let mut any = false;
    for (n, &c) in s[start..].iter().enumerate() {
        if !c.is_ascii_digit() {
            break;
        }
        if n >= 9 {
            return None; // implausibly long code
        }
        value = value.checked_mul(10)?.checked_add(u32::from(c - b'0'))?;
        any = true;
    }
    any.then_some(value)
}

/// Return the Data of the Microsoft Vendor-Specific attribute of the given
/// Vendor-Type from a parsed response, or `None` if absent. Each candidate VSA
/// is decoded through the bounded [`radius::decode_vendor_specific`], so an
/// overrunning inner Vendor-Length is skipped, not trusted.
fn find_vendor_data<'a>(response: &radius::ParsedResponse<'a>, vtype: u8) -> Option<&'a [u8]> {
    for value in response.attr_values(radius::attr::VENDOR_SPECIFIC) {
        if let Ok(vsa) = radius::decode_vendor_specific(value) {
            if vsa.vendor_id == radius::VENDOR_ID_MICROSOFT && vsa.vendor_type == vtype {
                return Some(vsa.vendor_data);
            }
        }
    }
    None
}

/// Locate the MS-CHAP2-Success (Vendor-Type 26) Data in a parsed Access-Accept.
pub fn find_ms_chap2_success<'a>(response: &radius::ParsedResponse<'a>) -> Option<&'a [u8]> {
    find_vendor_data(response, vendor_type::MS_CHAP2_SUCCESS)
}

/// Locate the MS-CHAP-Error (Vendor-Type 2) Data in a parsed Access-Reject.
pub fn find_ms_chap_error<'a>(response: &radius::ParsedResponse<'a>) -> Option<&'a [u8]> {
    find_vendor_data(response, vendor_type::MS_CHAP_ERROR)
}

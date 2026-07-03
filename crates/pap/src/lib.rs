#![forbid(unsafe_code)]
//! PAP engine for `pam_nps_mfa` (phase 3).
//!
//! Two responsibilities, both in IMPLEMENTATION_SPEC.md §4:
//!
//! 1. RFC 2865 §5.2 User-Password hiding ([`hide_password`] /
//!    [`try_hide_password`]).
//! 2. The Entra MFA Access-Challenge / State round-trip for a one-time code
//!    ([`Challenge`], [`build_challenge_response`], [`sanitize_reply_message`]).
//!
//! Security posture (CLAUDE.md hard rules):
//! - Fail closed (rule 1): every fallible path returns `Result`; malformed or
//!   under-specified input denies, never returns success.
//! - No secret in `Debug`/`Display`/logs (rule 3): [`PapError`] carries only
//!   fixed strings and the (secret-free) `radius::EncodeError`. No type here
//!   prints password, secret, or keystream bytes.
//! - Zeroize credential material (rule 8): the padded plaintext and the
//!   per-block keystream live in `zeroize::Zeroizing` and wipe on drop; the
//!   hidden-buffer copy used to assemble the follow-up request also wipes.
//! - Bounded parsing of network-supplied bytes (rule 15): the Access-Challenge
//!   Reply-Message and State are read through the `radius` bounded parser and
//!   never trusted for length; a malformed challenge denies and never panics.
//! - The State value is opaque: it is copied and echoed byte-for-byte, never
//!   parsed or interpreted.

use md5::{Digest, Md5};
use radius::{attr, fill_message_authenticator, Code, PacketBuilder, ParsedResponse};
use zeroize::Zeroizing;

/// Largest password PAP can represent: 128 octets after zero-padding to a
/// 16-octet boundary (RFC 2865 §5.2). A longer password cannot be hidden.
pub const MAX_PASSWORD_LEN: usize = 128;

/// A PAP-mode failure. Every variant denies the authentication.
///
/// Carries no password, secret, or keystream bytes, so it is safe to log
/// (CLAUDE.md rule 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PapError {
    /// Password longer than the 128-octet PAP maximum (cannot be represented).
    PasswordTooLong,
    /// A response handed to [`Challenge::from_response`] was not code 11.
    NotAChallenge,
    /// The Access-Challenge carried no State attribute to echo back.
    MissingState,
    /// The Access-Challenge carried more than one State attribute.
    MultipleState,
    /// Assembling the follow-up Access-Request failed (value too long, packet
    /// too long, etc.). Carries the secret-free `radius` cause.
    Encode(radius::EncodeError),
}

impl core::fmt::Display for PapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PasswordTooLong => f.write_str("password exceeds the 128-octet PAP maximum"),
            Self::NotAChallenge => f.write_str("response is not an Access-Challenge"),
            Self::MissingState => f.write_str("Access-Challenge carried no State to echo"),
            Self::MultipleState => f.write_str("Access-Challenge carried more than one State"),
            Self::Encode(e) => write!(f, "follow-up Access-Request assembly failed: {e}"),
        }
    }
}

impl std::error::Error for PapError {}

impl From<radius::EncodeError> for PapError {
    fn from(e: radius::EncodeError) -> Self {
        Self::Encode(e)
    }
}

/// Padded length for `n` password octets: the next multiple of 16, with a
/// one-block (16-octet) minimum so even an empty password yields a
/// well-formed single block (RFC 2865 §5.2). Empty passwords are rejected
/// upstream (CLAUDE.md rule 11); the minimum keeps this function total.
fn padded_len(n: usize) -> usize {
    n.div_ceil(16).max(1) * 16
}

/// Hide a (short-enough) password. Shared core for the fallible and infallible
/// public forms; callers guarantee `password.len() <= MAX_PASSWORD_LEN`.
fn hide_core(password: &[u8], secret: &[u8], request_authenticator: &[u8; 16]) -> Vec<u8> {
    let total = padded_len(password.len());

    // The padded cleartext is a copy of the password: wipe it on drop.
    let mut plain = Zeroizing::new(vec![0u8; total]);
    plain[..password.len()].copy_from_slice(password);

    // The hidden result (`out`) is on-wire ciphertext, not itself secret.
    let mut out = vec![0u8; total];
    for block in 0..(total / 16) {
        // b(1) = MD5(secret || RequestAuthenticator)
        // b(i) = MD5(secret || c(i-1))              for i > 1
        let mut hasher = Md5::new();
        hasher.update(secret);
        if block == 0 {
            hasher.update(&request_authenticator[..]);
        } else {
            hasher.update(&out[(block - 1) * 16..block * 16]);
        }
        // The keystream reveals the plaintext when XORed with the (public)
        // ciphertext, so it is as sensitive as the password: wipe it too.
        let mut keystream = Zeroizing::new([0u8; 16]);
        keystream.copy_from_slice(&hasher.finalize());

        let base = block * 16;
        for (dst, (p, k)) in out[base..base + 16]
            .iter_mut()
            .zip(plain[base..base + 16].iter().zip(keystream.iter()))
        {
            *dst = p ^ k;
        }
    }
    out
}

/// Hide a User-Password (RFC 2865 §5.2), returning the attribute value.
///
/// This is the exact signature pinned by TEST_VECTORS.md §5. Because it cannot
/// report an error, a password longer than [`MAX_PASSWORD_LEN`] (which PAP
/// cannot represent) is clamped to 128 octets; the resulting credential is
/// rejected by NPS (fail closed) rather than panicking. The PAM layer calls
/// [`try_hide_password`] and denies on [`PapError::PasswordTooLong`] instead of
/// relying on this clamp.
pub fn hide_password(password: &[u8], secret: &[u8], request_authenticator: &[u8; 16]) -> Vec<u8> {
    let clamped = &password[..password.len().min(MAX_PASSWORD_LEN)];
    hide_core(clamped, secret, request_authenticator)
}

/// Fallible User-Password hiding: rejects a password that PAP cannot represent
/// (> [`MAX_PASSWORD_LEN`] octets) instead of clamping. Preferred by the PAM
/// layer so an over-long password denies cleanly.
pub fn try_hide_password(
    password: &[u8],
    secret: &[u8],
    request_authenticator: &[u8; 16],
) -> Result<Vec<u8>, PapError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(PapError::PasswordTooLong);
    }
    Ok(hide_core(password, secret, request_authenticator))
}

/// Sanitize network-supplied Reply-Message text for display at the login
/// prompt (SPEC_AMENDMENTS A4).
///
/// Keeps printable ASCII — space (0x20) through tilde (0x7E) — and drops
/// everything else: control characters (including ESC, CR, LF, BEL, TAB), DEL,
/// and all high bytes. This removes the escape-introducer bytes a peer would
/// need to inject a terminal escape sequence into the prompt.
pub fn sanitize_reply_message(raw: &[u8]) -> String {
    raw.iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b))
        .map(|&b| b as char)
        .collect()
}

/// A structurally validated Access-Challenge (code 11), reduced to the two
/// things PAP needs: the sanitized Reply-Message prompt and the opaque State.
///
/// Implements neither `Debug` nor `Display`: while State is not itself a
/// credential, keeping it out of formatting matches the crate's no-print
/// posture for network-supplied material (CLAUDE.md rule 3).
pub struct Challenge {
    prompt: String,
    state: Option<Vec<u8>>,
}

impl Challenge {
    /// Read a parsed Access-Challenge: concatenate and sanitize every
    /// Reply-Message (type 18) in received order, and capture the opaque State
    /// (type 24).
    ///
    /// Fails closed if the response is not an Access-Challenge, or if it
    /// carries more than one State attribute (RFC 2865 permits exactly one).
    /// A challenge with no State parses successfully with `state == None`; the
    /// follow-up build then denies via [`PapError::MissingState`].
    pub fn from_response(resp: &ParsedResponse) -> Result<Self, PapError> {
        if resp.known_code() != Some(Code::AccessChallenge) {
            return Err(PapError::NotAChallenge);
        }

        // Multiple Reply-Message attributes concatenate in order (A4).
        let mut raw = Vec::new();
        for value in resp.attr_values(attr::REPLY_MESSAGE) {
            raw.extend_from_slice(value);
        }
        let prompt = sanitize_reply_message(&raw);

        // State is opaque: copy it verbatim, never parse it.
        let mut states = resp.attr_values(attr::STATE);
        let state = states.next().map(<[u8]>::to_vec);
        if state.is_some() && states.next().is_some() {
            return Err(PapError::MultipleState);
        }

        Ok(Self { prompt, state })
    }

    /// The sanitized text to show the user when prompting for the one-time
    /// code.
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// The opaque State bytes to echo back, if the challenge carried one.
    pub fn state(&self) -> Option<&[u8]> {
        self.state.as_deref()
    }

    /// Whether this challenge carried a State attribute.
    pub fn has_state(&self) -> bool {
        self.state.is_some()
    }

    /// Build the follow-up Access-Request for this challenge round: it echoes
    /// this challenge's State unchanged and carries `one_time_code` as the new
    /// hidden User-Password.
    ///
    /// Across multiple challenge rounds, call this on the *latest* challenge so
    /// the newest State is echoed. Denies via [`PapError::MissingState`] if the
    /// challenge carried no State.
    pub fn build_response(
        &self,
        id: u8,
        request_authenticator: [u8; 16],
        username: &[u8],
        one_time_code: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, PapError> {
        let state = self.state.as_deref().ok_or(PapError::MissingState)?;
        build_challenge_response(
            id,
            request_authenticator,
            username,
            one_time_code,
            state,
            secret,
        )
    }
}

/// Assemble a follow-up Access-Request that echoes `state` byte-for-byte and
/// carries `one_time_code` as a freshly hidden User-Password (the TOTP), plus
/// User-Name and a filled Message-Authenticator (IMPLEMENTATION_SPEC.md §4).
///
/// `state` is written verbatim, so a challenge's State survives unchanged
/// through as many rounds as the server uses. `request_authenticator` must be
/// a fresh value (`radius::fresh_request_authenticator`) — it both keys the
/// User-Password keystream and anchors response binding.
pub fn build_challenge_response(
    id: u8,
    request_authenticator: [u8; 16],
    username: &[u8],
    one_time_code: &[u8],
    state: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, PapError> {
    // Hidden buffer is derived from the one-time code; wipe our copy on drop
    // once it has been written into the packet.
    let hidden = Zeroizing::new(try_hide_password(
        one_time_code,
        secret,
        &request_authenticator,
    )?);

    let mut packet = PacketBuilder::new(Code::AccessRequest, id, request_authenticator)
        .attribute(attr::USER_NAME, username)?
        .attribute(attr::USER_PASSWORD, hidden.as_slice())?
        .attribute(attr::STATE, state)?
        .message_authenticator_placeholder()?
        .build()?;
    fill_message_authenticator(&mut packet, secret)?;
    Ok(packet)
}

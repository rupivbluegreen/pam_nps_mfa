//! Protocol-agnostic authentication orchestration. 100% safe code: this
//! module makes every authentication decision and never touches a pointer.
//!
//! The core entry point, [`authenticate`], takes already-gathered inputs
//! (username, authtok), the loaded config, a [`Conversation`] object, and a
//! [`RadiusTransport`] object — so the whole return-code table
//! (IMPLEMENTATION_SPEC.md §7) is unit-testable with the in-memory
//! `radius::test_support::FakeTransport` and a fake conversation, no live
//! PAM handle or socket required.
//!
//! Security posture (CLAUDE.md hard rules):
//! - Fail closed (rule 1): every error, timeout, parse failure, or integrity
//!   failure maps to a deny code; the only [`PamOutcome::Success`] is a
//!   fully verified Access-Accept.
//! - The protocol is fixed by config (rule 5): the match on
//!   [`config::Protocol`] is the only branch, and no code path ever emits
//!   the other protocol's attributes.
//! - Mutual auth is mandatory (rule 6): an MSCHAPv2 Access-Accept without a
//!   constant-time-verified MS-CHAP2-Success is `AuthErr`.
//! - Response binding (rule 14): the transport's accept closure is
//!   `RequestBinding::verify_response`, so an integrity-failed datagram is
//!   *discarded* — never treated as a Reject — and the wait continues.
//! - No failover on silence (rule 16): only `TransportError::Unreachable`
//!   advances to the next server; `Timeout` (and any other error) ends the
//!   attempt as `Unavail`.
//! - No mutable global state (rule 17): everything here is local.
//! - RNG failure denies (rule 18): a failed Request Authenticator or
//!   challenge generation is an immediate deny; nothing is sent.

use config::{Config, Protocol};
use radius::{
    attr, fill_message_authenticator, fresh_request_authenticator, parse_response, Code,
    EncodeError, PacketBuilder, RadiusTransport, RequestBinding, TransportError,
};
use secrets::SecretString;

use crate::conversation::{prompt_response, Conversation};
use crate::pam_codes;

/// Shown before blocking on the MSCHAPv2 push wait, so the session does not
/// look hung while the user's phone is waiting (CLAUDE.md: no silent block).
pub const PUSH_NOTICE: &str =
    "A sign-in request was sent to your MFA device. Approve it there to continue.";

/// Shown on an MS-CHAP-Error E=648 deny; v1 has no MS-CHAP2-CPW, so the user
/// must change the password elsewhere (IMPLEMENTATION_SPEC.md §5).
pub const PASSWORD_EXPIRED_NOTICE: &str =
    "Your password has expired. Change it through your organization's password reset process, then try again.";

/// Upper bound on PAP Access-Challenge rounds. The Entra flow uses one; a
/// server demanding more than this is misbehaving and the attempt is denied
/// (bounded loop, fail closed).
const MAX_CHALLENGE_ROUNDS: usize = 8;

/// The typed authentication outcome, mapped 1:1 onto the return-code table
/// in IMPLEMENTATION_SPEC.md §7 by [`PamOutcome::pam_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamOutcome {
    /// Second factor succeeded: Access-Accept with (for MSCHAPv2) a verified
    /// MS-CHAP2-Success.
    Success,
    /// Authentication failed: Access-Reject, MFA denied or timed out at the
    /// server, failed mutual auth, or an unusable credential.
    AuthErr,
    /// The authentication service could not be consulted: all servers
    /// unreachable, no valid response before the timeout, config error,
    /// or local RNG failure.
    Unavail,
    /// The PAM conversation is broken; nothing could be asked or shown.
    ConvErr,
}

impl PamOutcome {
    /// The PAM return code for this outcome (IMPLEMENTATION_SPEC.md §7).
    #[must_use]
    pub fn pam_code(self) -> i32 {
        match self {
            Self::Success => pam_codes::SUCCESS,
            Self::AuthErr => pam_codes::AUTH_ERR,
            Self::Unavail => pam_codes::AUTHINFO_UNAVAIL,
            Self::ConvErr => pam_codes::CONV_ERR,
        }
    }
}

/// Per-attempt inputs already gathered at the PAM boundary. All state is
/// local to the invocation (rule 17).
pub struct AttemptContext<'a> {
    /// The user name — this exact byte string goes into User-Name AND into
    /// the MSCHAPv2 challenge hash (IMPLEMENTATION_SPEC.md §5: they must be
    /// byte-for-byte identical).
    pub username: &'a str,
    /// The first-factor password, in a zeroizing buffer.
    pub password: &'a SecretString,
    /// Audit correlation id (SPEC_AMENDMENTS.md A6); consumed by the phase-7
    /// audit emission, carried here so the flow can hand it to the audit
    /// record alongside the outcome.
    pub corr: &'a str,
}

/// Every config failure — unreadable, malformed, or a permissive/swappable
/// secret file — is `PAM_AUTHINFO_UNAVAIL` with a critical log
/// (IMPLEMENTATION_SPEC.md §7; CLAUDE.md rule 12). Never an `AuthErr` (the
/// credential was not evaluated) and never a success.
#[must_use]
pub fn outcome_for_config_error(_error: &config::ConfigError) -> PamOutcome {
    PamOutcome::Unavail
}

/// Phase-5 stand-in for the real connected-UDP transport (phase 6): every
/// exchange fails with a local transport error, so a live PAM stack running
/// this build fails CLOSED with `PAM_AUTHINFO_UNAVAIL` — never a success and
/// never a hang.
pub struct UnwiredTransport;

impl RadiusTransport for UnwiredTransport {
    fn exchange(
        &mut self,
        _request: &[u8],
        _accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::Io)
    }
}

/// Run one authentication attempt. See the module docs for the guarantees;
/// see IMPLEMENTATION_SPEC.md §7 for the outcome table this implements.
pub fn authenticate(
    ctx: &AttemptContext<'_>,
    config: &Config,
    conv: &mut dyn Conversation,
    transport: &mut dyn RadiusTransport,
) -> PamOutcome {
    if ctx.username.is_empty() {
        return PamOutcome::AuthErr;
    }
    // Rule 11: an empty password never authenticates. (The PAM boundary has
    // already rejected null/empty tokens; this is the fail-closed backstop
    // for direct callers of the flow.)
    if ctx.password.is_empty() {
        return PamOutcome::AuthErr;
    }
    // config::parse guarantees at least one server; fail closed regardless.
    if config.servers.is_empty() {
        return PamOutcome::Unavail;
    }
    match config.protocol {
        Protocol::Mschapv2 => mschapv2_flow(ctx, config, conv, transport),
        Protocol::Pap => pap_flow(ctx, config, conv, transport),
    }
}

// ===========================================================================
// MSCHAPv2 (push) flow
// ===========================================================================

fn mschapv2_flow(
    ctx: &AttemptContext<'_>,
    config: &Config,
    conv: &mut dyn Conversation,
    transport: &mut dyn RadiusTransport,
) -> PamOutcome {
    let mut push_notice_sent = false;

    for server in &config.servers {
        let secret = server.secret.expose_secret().as_bytes();

        // Fresh material per server attempt; RNG failure denies (rule 18).
        let Ok(request_authenticator) = fresh_request_authenticator() else {
            return PamOutcome::Unavail;
        };
        // The Identifier is public routing data; a random octet is fine.
        let id = request_authenticator[0];
        let Ok(challenges) = mschapv2::generate_challenges() else {
            return PamOutcome::Unavail;
        };

        // §5 username note: the SAME string feeds the challenge hash (inside
        // build_request) and the User-Name attribute (below).
        let request = mschapv2::build_request(
            ctx.username.as_bytes(),
            ctx.password.expose_secret(),
            &challenges,
            id,
        );
        let packet = match build_mschapv2_packet(
            ctx.username,
            &request,
            id,
            request_authenticator,
            config,
            secret,
        ) {
            Ok(p) => p,
            // No valid request could be formed (e.g. over-long User-Name);
            // nothing was sent and no credential was evaluated.
            Err(_) => return PamOutcome::Unavail,
        };

        // Tell the user BEFORE blocking on the push wait (spec §7; CLAUDE.md
        // "silent block"). Once per attempt, not per server.
        if !push_notice_sent {
            if conv.info(PUSH_NOTICE).is_err() {
                return PamOutcome::ConvErr;
            }
            push_notice_sent = true;
        }

        // Rule 14: the accept closure binds the response to THIS request
        // (id, Response Authenticator, Message-Authenticator — all against
        // the original Request Authenticator). Anything else is discarded
        // and the transport keeps waiting. Source address/port binding is
        // the transport's job (phase 6).
        let binding = RequestBinding::new(id, request_authenticator)
            .require_message_authenticator(config.require_message_authenticator);
        match transport.exchange(&packet, &mut |datagram| {
            binding.verify_response(datagram, secret)
        }) {
            // Explicit transport error: fail over to the next server.
            Err(TransportError::Unreachable) => continue,
            // Silence (or a local I/O failure) is NOT failover (rule 16): a
            // silent server may already have pushed to the user's device.
            Err(TransportError::Timeout | TransportError::Io) => return PamOutcome::Unavail,
            Ok(response) => return mschapv2_response_outcome(&response, &request, conv),
        }
    }
    // Every configured server was explicitly unreachable.
    PamOutcome::Unavail
}

fn mschapv2_response_outcome(
    response: &[u8],
    request: &mschapv2::MsChapV2Request,
    conv: &mut dyn Conversation,
) -> PamOutcome {
    // The binding already parsed and verified this datagram; re-parse for the
    // typed view and fail closed if anything is off anyway.
    let Ok(parsed) = parse_response(response) else {
        return PamOutcome::Unavail;
    };
    match parsed.known_code() {
        Some(Code::AccessAccept) => {
            // Rule 6: mutual authentication. An Accept whose MS-CHAP2-Success
            // is absent or mismatched (constant-time compare) is a DENY even
            // though the packet said accept — that is the impersonation gap.
            if mschapv2::verify_access_accept(&parsed, request.expected_authenticator()) {
                PamOutcome::Success
            } else {
                PamOutcome::AuthErr
            }
        }
        Some(Code::AccessReject) => {
            // Access-Reject covers MFA denied and MFA timed out at the
            // server: all AuthErr. The MS-CHAP-Error E-code only shapes the
            // user message; messaging stays uniform (no enumeration oracle)
            // except the spec-mandated E=648 password-expired notice.
            if let Some(data) = mschapv2::find_ms_chap_error(&parsed) {
                if mschapv2::parse_ms_chap_error(data) == mschapv2::MsChapError::PasswordExpired {
                    // Best effort: the outcome is already a deny.
                    let _ = conv.info(PASSWORD_EXPIRED_NOTICE);
                }
            }
            PamOutcome::AuthErr
        }
        // MSCHAPv2 push mode has no interactive challenge; an
        // Access-Challenge (or any unknown code) is a deny, not a prompt.
        _ => PamOutcome::AuthErr,
    }
}

fn build_mschapv2_packet(
    username: &str,
    request: &mschapv2::MsChapV2Request,
    id: u8,
    request_authenticator: [u8; 16],
    config: &Config,
    secret: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let mut builder = PacketBuilder::new(Code::AccessRequest, id, request_authenticator)
        .attribute(attr::USER_NAME, username.as_bytes())?
        .attribute(attr::VENDOR_SPECIFIC, request.ms_chap_challenge())?
        .attribute(attr::VENDOR_SPECIFIC, request.ms_chap2_response())?;
    builder = add_nas_attributes(builder, config)?;
    let mut packet = builder.message_authenticator_placeholder()?.build()?;
    fill_message_authenticator(&mut packet, secret)?;
    Ok(packet)
}

// ===========================================================================
// PAP (Access-Challenge / State) flow
// ===========================================================================

fn pap_flow(
    ctx: &AttemptContext<'_>,
    config: &Config,
    conv: &mut dyn Conversation,
    transport: &mut dyn RadiusTransport,
) -> PamOutcome {
    for server in &config.servers {
        let secret = server.secret.expose_secret().as_bytes();

        let Ok(request_authenticator) = fresh_request_authenticator() else {
            return PamOutcome::Unavail;
        };
        let id = request_authenticator[0];

        // Hide the first-factor password (RFC 2865 §5.2). Over-long is a
        // credential PAP cannot represent: deny without sending anything.
        let hidden = match pap::try_hide_password(
            ctx.password.expose_secret().as_bytes(),
            secret,
            &request_authenticator,
        ) {
            Ok(h) => h,
            Err(_) => return PamOutcome::AuthErr,
        };
        let packet = match build_pap_packet(
            ctx.username,
            &hidden,
            id,
            request_authenticator,
            config,
            secret,
        ) {
            Ok(p) => p,
            Err(_) => return PamOutcome::Unavail,
        };

        let binding = RequestBinding::new(id, request_authenticator)
            .require_message_authenticator(config.require_message_authenticator);
        match transport.exchange(&packet, &mut |datagram| {
            binding.verify_response(datagram, secret)
        }) {
            Err(TransportError::Unreachable) => continue,
            Err(TransportError::Timeout | TransportError::Io) => return PamOutcome::Unavail,
            // A response arrived: this server owns the attempt from here on
            // (its State conversation cannot move to another server).
            Ok(response) => return pap_rounds(ctx, config, conv, transport, secret, response),
        }
    }
    PamOutcome::Unavail
}

/// One round's disposition: either the attempt is decided, or the server
/// asked for another factor.
enum Round {
    Done(PamOutcome),
    Challenge(pap::Challenge),
}

fn pap_rounds(
    ctx: &AttemptContext<'_>,
    config: &Config,
    conv: &mut dyn Conversation,
    transport: &mut dyn RadiusTransport,
    secret: &[u8],
    mut response: Vec<u8>,
) -> PamOutcome {
    for _round in 0..MAX_CHALLENGE_ROUNDS {
        let round = {
            let Ok(parsed) = parse_response(&response) else {
                return PamOutcome::Unavail;
            };
            match parsed.known_code() {
                // PAP has no mutual authentication; the Accept's authenticity
                // rests on the verified Response/Message-Authenticator.
                Some(Code::AccessAccept) => Round::Done(PamOutcome::Success),
                Some(Code::AccessReject) => Round::Done(PamOutcome::AuthErr),
                Some(Code::AccessChallenge) => match pap::Challenge::from_response(&parsed) {
                    Ok(challenge) => Round::Challenge(challenge),
                    // Structurally bad challenge (e.g. multiple State): deny.
                    Err(_) => Round::Done(PamOutcome::AuthErr),
                },
                _ => Round::Done(PamOutcome::AuthErr),
            }
        };

        let challenge = match round {
            Round::Done(outcome) => return outcome,
            Round::Challenge(challenge) => challenge,
        };

        // Surface the (sanitized — A4) Reply-Message and collect the code.
        let code = match prompt_response(conv, challenge.prompt()) {
            Ok(code) => code,
            Err(_) => return PamOutcome::ConvErr,
        };
        if code.is_empty() {
            return PamOutcome::AuthErr; // rule 11 applies to the OTP too
        }

        let Ok(request_authenticator) = fresh_request_authenticator() else {
            return PamOutcome::Unavail;
        };
        let id = request_authenticator[0];
        // Echo the newest State byte-for-byte; a challenge without State
        // cannot be answered (MissingState) — deny.
        let follow_up = match challenge.build_response(
            id,
            request_authenticator,
            ctx.username.as_bytes(),
            code.expose_secret().as_bytes(),
            secret,
        ) {
            Ok(p) => p,
            Err(_) => return PamOutcome::AuthErr,
        };

        let binding = RequestBinding::new(id, request_authenticator)
            .require_message_authenticator(config.require_message_authenticator);
        // Mid-conversation there is no failover of any kind: the State is
        // bound to this server. Any transport error ends the attempt.
        match transport.exchange(&follow_up, &mut |datagram| {
            binding.verify_response(datagram, secret)
        }) {
            Ok(next) => response = next,
            Err(_) => return PamOutcome::Unavail,
        }
    }
    // The server demanded more challenge rounds than we allow: deny.
    PamOutcome::AuthErr
}

fn build_pap_packet(
    username: &str,
    hidden_password: &[u8],
    id: u8,
    request_authenticator: [u8; 16],
    config: &Config,
    secret: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let mut builder = PacketBuilder::new(Code::AccessRequest, id, request_authenticator)
        .attribute(attr::USER_NAME, username.as_bytes())?
        .attribute(attr::USER_PASSWORD, hidden_password)?;
    builder = add_nas_attributes(builder, config)?;
    let mut packet = builder.message_authenticator_placeholder()?.build()?;
    fill_message_authenticator(&mut packet, secret)?;
    Ok(packet)
}

// ===========================================================================
// Shared
// ===========================================================================

fn add_nas_attributes(
    mut builder: PacketBuilder,
    config: &Config,
) -> Result<PacketBuilder, EncodeError> {
    if let Some(nas_identifier) = &config.nas_identifier {
        builder = builder.attribute(attr::NAS_IDENTIFIER, nas_identifier.as_bytes())?;
    }
    if let Some(nas_ip) = config.nas_ip {
        builder = builder.attribute(attr::NAS_IP_ADDRESS, &nas_ip.octets())?;
    }
    Ok(builder)
}

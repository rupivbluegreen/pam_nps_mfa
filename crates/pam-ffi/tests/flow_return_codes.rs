//! The IMPLEMENTATION_SPEC.md §7 return-code table, driven end-to-end
//! through `flow::authenticate` with the in-memory
//! `radius::test_support::FakeTransport` (playing an honest or hostile NPS,
//! computing real authenticators from the intercepted request) and a
//! scripted fake conversation. No socket, no live PAM handle.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use config::{AuditBackend, Config, Protocol, Server};
use pam_nps_mfa::conversation::{ConvError, Conversation, DEFAULT_OTP_PROMPT};
use pam_nps_mfa::flow::{self, AttemptContext, PamOutcome, PUSH_NOTICE};
use pam_nps_mfa::{null_authtok_return, pam_codes};
use radius::test_support::FakeTransport;
use radius::TransportError;
use secrets::SecretString;

const SECRET: &[u8] = b"radius-shared-secret";
const USERNAME: &str = "User";
const PASSWORD: &str = "clientPass";
const OTP: &str = "123456";

// ===========================================================================
// Test doubles and packet helpers
// ===========================================================================

struct FakeConversation {
    replies: VecDeque<String>,
    log: Rc<RefCell<Vec<String>>>,
}

impl FakeConversation {
    fn new(replies: &[&str], log: Rc<RefCell<Vec<String>>>) -> Self {
        Self {
            replies: replies.iter().map(|r| (*r).to_owned()).collect(),
            log,
        }
    }
}

impl Conversation for FakeConversation {
    fn info(&mut self, text: &str) -> Result<(), ConvError> {
        self.log.borrow_mut().push(format!("info:{text}"));
        Ok(())
    }

    fn prompt_echo_off(&mut self, prompt: &str) -> Result<SecretString, ConvError> {
        self.log.borrow_mut().push(format!("prompt:{prompt}"));
        self.replies
            .pop_front()
            .map(|r| SecretString::from_text(&r))
            .ok_or(ConvError::Failed)
    }
}

fn test_config(protocol: Protocol, server_count: usize) -> Config {
    let servers = (0..server_count)
        .map(|i| Server {
            addr: format!("10.0.0.{}:1812", 10 + i).parse().unwrap(),
            secret: SecretString::from_text(std::str::from_utf8(SECRET).unwrap()),
        })
        .collect();
    Config {
        servers,
        protocol,
        timeout: 60,
        probe_timeout: 5,
        retries: 1,
        nas_identifier: Some("tunnel-host-01".to_owned()),
        nas_ip: None,
        source_ip: None,
        require_message_authenticator: true,
        audit: AuditBackend::Both,
        debug: false,
    }
}

/// Run one attempt and return the outcome plus the conversation log.
fn run(
    config: &Config,
    password: &str,
    replies: &[&str],
    transport: &mut FakeTransport,
) -> (PamOutcome, Vec<String>) {
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut conv = FakeConversation::new(replies, log.clone());
    let password = SecretString::from_text(password);
    let ctx = AttemptContext {
        username: USERNAME,
        password: &password,
        corr: "test-corr",
    };
    let outcome = flow::authenticate(&ctx, config, &mut conv, transport);
    let log = log.borrow().clone();
    (outcome, log)
}

fn request_authenticator_of(request: &[u8]) -> [u8; 16] {
    let mut ra = [0u8; 16];
    ra.copy_from_slice(&request[4..20]);
    ra
}

/// Build a fully authentic server response: correct Response Authenticator
/// and Message-Authenticator computed (like a real NPS) from the request's
/// id and Request Authenticator with the shared secret.
fn server_response(code: u8, id: u8, req_auth: &[u8; 16], attrs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut attr_bytes = Vec::new();
    for (attr_type, value) in attrs {
        attr_bytes.extend(radius::encode_attribute(*attr_type, value).unwrap());
    }
    // Message-Authenticator placeholder, filled below.
    let ma_value_off = attr_bytes.len() + 2;
    attr_bytes.extend(radius::encode_attribute(radius::attr::MESSAGE_AUTHENTICATOR, &[0u8; 16]).unwrap());

    let length = (20 + attr_bytes.len()) as u16;
    // Response MA = HMAC-MD5(secret, Code|Id|Length|RequestAuth|Attrs with MA zeroed).
    let mut ma_input = vec![code, id];
    ma_input.extend(length.to_be_bytes());
    ma_input.extend(req_auth);
    ma_input.extend(&attr_bytes);
    let ma = radius::message_authenticator(&ma_input, SECRET);
    attr_bytes[ma_value_off..ma_value_off + 16].copy_from_slice(&ma);

    let resp_auth = radius::response_authenticator(code, id, length, req_auth, &attr_bytes, SECRET);
    let mut packet = vec![code, id];
    packet.extend(length.to_be_bytes());
    packet.extend(resp_auth);
    packet.extend(attr_bytes);
    packet
}

/// Microsoft Vendor-Specific value: Vendor-Id 311 ++ Vendor-Type ++
/// Vendor-Length ++ Data (RFC 2548).
fn ms_vsa(vendor_type: u8, data: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(6 + data.len());
    value.extend_from_slice(&radius::VENDOR_ID_MICROSOFT.to_be_bytes());
    value.push(vendor_type);
    value.push((2 + data.len()) as u8);
    value.extend_from_slice(data);
    value
}

/// Extract the MSCHAPv2 material an honest server would read from the
/// Access-Request: (ident, authenticator challenge, peer challenge,
/// NT response).
fn extract_mschapv2(request: &[u8]) -> (u8, [u8; 16], [u8; 16], [u8; 24]) {
    let parsed = radius::parse_response(request).expect("request parses");
    let mut auth_challenge = [0u8; 16];
    let mut peer_challenge = [0u8; 16];
    let mut nt_response = [0u8; 24];
    let mut ident = 0u8;
    for value in parsed.attr_values(radius::attr::VENDOR_SPECIFIC) {
        let vsa = radius::decode_vendor_specific(value).unwrap();
        if vsa.vendor_id != radius::VENDOR_ID_MICROSOFT {
            continue;
        }
        match vsa.vendor_type {
            11 => auth_challenge.copy_from_slice(vsa.vendor_data),
            25 => {
                ident = vsa.vendor_data[0];
                peer_challenge.copy_from_slice(&vsa.vendor_data[2..18]);
                nt_response.copy_from_slice(&vsa.vendor_data[26..50]);
            }
            _ => {}
        }
    }
    (ident, auth_challenge, peer_challenge, nt_response)
}

/// An honest NPS: Access-Accept carrying an MS-CHAP2-Success computed from
/// `server_password` (which must equal the client's for mutual auth to
/// verify).
fn mschapv2_accept_responder(server_password: &'static str) -> impl FnMut(&[u8]) -> Vec<Vec<u8>> {
    move |request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        let (ident, auth_challenge, peer_challenge, nt_response) = extract_mschapv2(request);
        let authenticator_response = mschapv2::generate_authenticator_response(
            server_password,
            &nt_response,
            &peer_challenge,
            &auth_challenge,
            USERNAME.as_bytes(),
        );
        let mut success_data = vec![ident];
        success_data.extend_from_slice(authenticator_response.as_bytes());
        vec![server_response(
            2,
            id,
            &ra,
            &[(radius::attr::VENDOR_SPECIFIC, ms_vsa(26, &success_data))],
        )]
    }
}

// ===========================================================================
// §7 return-code table: MSCHAPv2
// ===========================================================================

/// Table row: second factor succeeded (Accept + Success verified) → PAM_SUCCESS.
#[test]
fn mschapv2_accept_with_valid_success_is_pam_success() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(mschapv2_accept_responder(PASSWORD));

    let (outcome, log) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::Success);
    assert_eq!(outcome.pam_code(), pam_codes::SUCCESS);
    // The push notice was shown (before the blocking wait).
    assert!(log.contains(&format!("info:{PUSH_NOTICE}")));
}

/// Rule 6: an Accept whose MS-CHAP2-Success does not verify is a DENY
/// (impersonation gap) → PAM_AUTH_ERR.
#[test]
fn mschapv2_accept_with_bad_success_is_pam_auth_err() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    // The "server" signs with a different password: S= cannot verify.
    transport.push_reply(mschapv2_accept_responder("not-the-user-password"));

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
    assert_eq!(outcome.pam_code(), pam_codes::AUTH_ERR);
}

/// Rule 6 corollary: an Accept carrying NO MS-CHAP2-Success at all is a DENY.
#[test]
fn mschapv2_accept_without_success_attribute_is_pam_auth_err() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(2, id, &ra, &[])]
    });

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
}

/// Table row: Access-Reject (MFA denied / timed out at the server) →
/// PAM_AUTH_ERR.
#[test]
fn mschapv2_reject_is_pam_auth_err() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        let mut error_data = vec![1u8];
        error_data.extend_from_slice(b"E=691 R=0 V=3");
        vec![server_response(
            3,
            id,
            &ra,
            &[(radius::attr::VENDOR_SPECIFIC, ms_vsa(2, &error_data))],
        )]
    });

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
    assert_eq!(outcome.pam_code(), pam_codes::AUTH_ERR);
}

/// MSCHAPv2 push mode has no interactive challenge: an authentic
/// Access-Challenge is a deny, never a prompt.
#[test]
fn mschapv2_unexpected_challenge_is_pam_auth_err() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(
            11,
            id,
            &ra,
            &[(radius::attr::STATE, b"STATE-X".to_vec())],
        )]
    });

    let (outcome, log) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
    assert!(!log.iter().any(|l| l.starts_with("prompt:")));
}

/// CLAUDE.md "silent block": the PAM_TEXT_INFO push notice is delivered
/// BEFORE the flow blocks on the transport.
#[test]
fn mschapv2_push_notice_precedes_the_transport_wait() {
    let config = test_config(Protocol::Mschapv2, 1);
    let events = Rc::new(RefCell::new(Vec::new()));

    let mut transport = FakeTransport::new();
    let transport_events = events.clone();
    transport.push_reply(move |_request| {
        transport_events.borrow_mut().push("exchange".to_owned());
        Vec::new() // silence: no datagram ever accepted
    });

    let mut conv = FakeConversation::new(&[], events.clone());
    let password = SecretString::from_text(PASSWORD);
    let ctx = AttemptContext {
        username: USERNAME,
        password: &password,
        corr: "test-corr",
    };
    let outcome = flow::authenticate(&ctx, &config, &mut conv, &mut transport);

    assert_eq!(outcome, PamOutcome::Unavail); // silence → timeout → unavail
    let events = events.borrow().clone();
    assert_eq!(
        events,
        vec![format!("info:{PUSH_NOTICE}"), "exchange".to_owned()]
    );
}

// ===========================================================================
// §7 return-code table: credential preconditions
// ===========================================================================

/// Table row: empty password → PAM_AUTH_ERR (rule 11).
#[test]
fn empty_authtok_is_pam_auth_err() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(mschapv2_accept_responder(PASSWORD)); // must never be reached

    let (outcome, _) = run(&config, "", &[], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
    assert_eq!(outcome.pam_code(), pam_codes::AUTH_ERR);
    assert_eq!(transport.exchanges(), 0, "nothing may be sent for an empty password");
}

/// Table row: PAM_DISALLOW_NULL_AUTHTOK with a null token → PAM_AUTH_ERR.
/// (A null token also denies without the flag: it cannot authenticate.)
#[test]
fn null_authtok_is_pam_auth_err_with_and_without_disallow_null() {
    assert_eq!(null_authtok_return(true), pam_codes::AUTH_ERR);
    assert_eq!(null_authtok_return(false), pam_codes::AUTH_ERR);
}

#[test]
fn empty_username_is_pam_auth_err() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut conv = FakeConversation::new(&[], log);
    let password = SecretString::from_text(PASSWORD);
    let ctx = AttemptContext {
        username: "",
        password: &password,
        corr: "test-corr",
    };
    assert_eq!(
        flow::authenticate(&ctx, &config, &mut conv, &mut transport),
        PamOutcome::AuthErr
    );
    assert_eq!(transport.exchanges(), 0);
}

// ===========================================================================
// §7 return-code table: transport and config failures
// ===========================================================================

/// Table row: no valid response before the timeout → PAM_AUTHINFO_UNAVAIL.
/// Rule 16: silence on the first server must NOT fail over to the second.
#[test]
fn transport_timeout_is_pam_authinfo_unavail_and_never_fails_over() {
    let config = test_config(Protocol::Mschapv2, 2);
    let mut transport = FakeTransport::new();
    transport.push_error(TransportError::Timeout);
    transport.push_reply(mschapv2_accept_responder(PASSWORD)); // must never be reached

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::Unavail);
    assert_eq!(outcome.pam_code(), pam_codes::AUTHINFO_UNAVAIL);
    assert_eq!(
        transport.exchanges(),
        1,
        "silence must not fail over (rule 16): a silent server may already have pushed"
    );
}

/// Table row: all servers unreachable → PAM_AUTHINFO_UNAVAIL. An explicit
/// transport error IS allowed to fail over, so both servers are tried.
#[test]
fn all_servers_unreachable_is_pam_authinfo_unavail() {
    let config = test_config(Protocol::Mschapv2, 2);
    let mut transport = FakeTransport::new();
    transport.push_error(TransportError::Unreachable);
    transport.push_error(TransportError::Unreachable);

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::Unavail);
    assert_eq!(outcome.pam_code(), pam_codes::AUTHINFO_UNAVAIL);
    assert_eq!(transport.exchanges(), 2, "each server was probed once");
}

/// Failover on an explicit transport error reaches the second server and a
/// verified Accept there still succeeds.
#[test]
fn unreachable_then_reachable_server_succeeds() {
    let config = test_config(Protocol::Mschapv2, 2);
    let mut transport = FakeTransport::new();
    transport.push_error(TransportError::Unreachable);
    transport.push_reply(mschapv2_accept_responder(PASSWORD));

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::Success);
    assert_eq!(transport.exchanges(), 2);
}

/// Rule 14 + §7: an integrity-failed datagram is DISCARDED (not a Reject);
/// with nothing else arriving the attempt times out → PAM_AUTHINFO_UNAVAIL.
#[test]
fn integrity_failed_response_is_discarded_then_timeout_is_unavail() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        // A would-be Accept whose Response Authenticator is corrupted.
        let mut forged = server_response(2, id, &ra, &[]);
        forged[4] ^= 0xFF;
        vec![forged]
    });

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::Unavail, "a forgery is not a Reject");
    assert_eq!(outcome.pam_code(), pam_codes::AUTHINFO_UNAVAIL);
}

/// Strict mode (config default): an otherwise-valid response with NO
/// Message-Authenticator is discarded, not trusted.
#[test]
fn response_without_message_authenticator_is_discarded_in_strict_mode() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        // Valid Response Authenticator, but no Message-Authenticator at all.
        let attrs: Vec<u8> = Vec::new();
        let length = 20u16;
        let resp_auth = radius::response_authenticator(2, id, length, &ra, &attrs, SECRET);
        let mut packet = vec![2, id];
        packet.extend(length.to_be_bytes());
        packet.extend(resp_auth);
        vec![packet]
    });

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::Unavail);
}

/// Table row: config error / permissive secret file → PAM_AUTHINFO_UNAVAIL.
/// Exercised against a real 0644 config file through config::load's
/// open-fstat-validate pipeline.
#[test]
fn config_permission_error_is_pam_authinfo_unavail() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!(
        "pam_nps_mfa_permissive_{}.conf",
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1").unwrap();
        writeln!(f, "protocol mschapv2").unwrap();
    }
    // Group/other-readable: must be refused before contents are trusted
    // (CLAUDE.md rule 12), regardless of who owns it.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let err = config::load(&path).expect_err("permissive config must be refused");
    let outcome = flow::outcome_for_config_error(&err);
    let _ = std::fs::remove_file(&path);

    assert_eq!(outcome, PamOutcome::Unavail);
    assert_eq!(outcome.pam_code(), pam_codes::AUTHINFO_UNAVAIL);
}

// ===========================================================================
// PAP: challenge/State round-trip
// ===========================================================================

/// PAP happy path across an Access-Challenge round: the initial request
/// hides the password correctly; the follow-up echoes State byte-for-byte
/// and hides the prompted OTP; the final Accept is PAM_SUCCESS.
#[test]
fn pap_challenge_state_round_trip_succeeds() {
    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();

    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        // The initial request hides the first-factor password (RFC 2865 §5.2).
        let parsed = radius::parse_response(request).unwrap();
        let hidden: Vec<u8> = parsed
            .attr_values(radius::attr::USER_PASSWORD)
            .next()
            .expect("User-Password present")
            .to_vec();
        assert_eq!(hidden, pap::hide_password(PASSWORD.as_bytes(), SECRET, &ra));
        vec![server_response(
            11,
            id,
            &ra,
            &[
                (radius::attr::REPLY_MESSAGE, b"Enter your code".to_vec()),
                (radius::attr::STATE, b"STATE-1".to_vec()),
            ],
        )]
    });
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        let parsed = radius::parse_response(request).unwrap();
        // The follow-up echoes the State byte-for-byte...
        let state: Vec<u8> = parsed
            .attr_values(radius::attr::STATE)
            .next()
            .expect("State echoed")
            .to_vec();
        assert_eq!(state, b"STATE-1");
        // ...and carries the prompted OTP as a freshly hidden User-Password.
        let hidden: Vec<u8> = parsed
            .attr_values(radius::attr::USER_PASSWORD)
            .next()
            .expect("User-Password present")
            .to_vec();
        assert_eq!(hidden, pap::hide_password(OTP.as_bytes(), SECRET, &ra));
        vec![server_response(2, id, &ra, &[])]
    });

    let (outcome, log) = run(&config, PASSWORD, &[OTP], &mut transport);
    assert_eq!(outcome, PamOutcome::Success);
    assert_eq!(outcome.pam_code(), pam_codes::SUCCESS);
    // The (sanitized) Reply-Message text was used as the prompt.
    assert!(log.contains(&"prompt:Enter your code".to_owned()), "log: {log:?}");
    assert_eq!(transport.exchanges(), 2);
}

/// A challenge whose Reply-Message is all control bytes falls back to the
/// default prompt (A4 sanitization end-to-end).
#[test]
fn pap_challenge_with_unprintable_reply_message_uses_fallback_prompt() {
    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(
            11,
            id,
            &ra,
            &[
                (radius::attr::REPLY_MESSAGE, b"\x1b\x07\x00\x0a".to_vec()),
                (radius::attr::STATE, b"STATE-1".to_vec()),
            ],
        )]
    });
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(2, id, &ra, &[])]
    });

    let (outcome, log) = run(&config, PASSWORD, &[OTP], &mut transport);
    assert_eq!(outcome, PamOutcome::Success);
    assert!(log.contains(&format!("prompt:{DEFAULT_OTP_PROMPT}")), "log: {log:?}");
}

/// PAP Access-Reject → PAM_AUTH_ERR.
#[test]
fn pap_reject_is_pam_auth_err() {
    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(3, id, &ra, &[])]
    });

    let (outcome, _) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
    assert_eq!(outcome.pam_code(), pam_codes::AUTH_ERR);
}

/// A challenge with no State cannot be answered (fail closed → AuthErr,
/// nothing further is sent).
#[test]
fn pap_challenge_without_state_is_pam_auth_err() {
    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(
            11,
            id,
            &ra,
            &[(radius::attr::REPLY_MESSAGE, b"Enter your code".to_vec())],
        )]
    });

    let (outcome, _) = run(&config, PASSWORD, &[OTP], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
    assert_eq!(transport.exchanges(), 1);
}

/// An empty OTP reply is rejected (rule 11) without sending a follow-up.
#[test]
fn pap_empty_otp_is_pam_auth_err() {
    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(
            11,
            id,
            &ra,
            &[(radius::attr::STATE, b"STATE-1".to_vec())],
        )]
    });

    let (outcome, _) = run(&config, PASSWORD, &[""], &mut transport);
    assert_eq!(outcome, PamOutcome::AuthErr);
    assert_eq!(transport.exchanges(), 1);
}

// ===========================================================================
// Outcome → return-code mapping (the whole table in one place)
// ===========================================================================

#[test]
fn outcome_mapping_matches_spec_section_7() {
    assert_eq!(PamOutcome::Success.pam_code(), 0); // PAM_SUCCESS
    assert_eq!(PamOutcome::AuthErr.pam_code(), 7); // PAM_AUTH_ERR
    assert_eq!(PamOutcome::Unavail.pam_code(), 9); // PAM_AUTHINFO_UNAVAIL
    assert_eq!(PamOutcome::ConvErr.pam_code(), 19); // PAM_CONV_ERR
}

// ===========================================================================
// Rule 14 (positive): the wait CONTINUES past a discarded datagram.
// ===========================================================================

/// Rule 14 positive path: within a SINGLE exchange the "server" first offers
/// two integrity-failing datagrams — a forged Accept (corrupted Response
/// Authenticator) and a valid-Response-Authenticator-but-missing-Message-
/// Authenticator Accept (discarded in strict mode) — and THEN the authentic
/// Access-Accept carrying a verifiable MS-CHAP2-Success. The accept closure
/// (`RequestBinding::verify_response`) must reject the first two and accept
/// the third, so the wait keeps going and the outcome is PAM_SUCCESS. This
/// proves a discarded forgery does not end the wait (contrast with
/// `integrity_failed_response_is_discarded_then_timeout_is_unavail`, where
/// nothing authentic follows and the attempt times out).
///
/// The existing `FakeTransport` already expresses "multiple datagrams in one
/// exchange": a `push_reply` responder returns `Vec<Vec<u8>>` and
/// `exchange` offers each to the accept closure in order. No extension of
/// `test_support.rs` was needed.
#[test]
fn mschapv2_forged_datagrams_discarded_then_authentic_accept_is_pam_success() {
    let config = test_config(Protocol::Mschapv2, 1);
    let mut transport = FakeTransport::new();

    // Reuse the honest-NPS responder for the authentic, verifiable Accept.
    let mut authentic = mschapv2_accept_responder(PASSWORD);
    transport.push_reply(move |request| {
        let id = request[1];
        let ra = request_authenticator_of(request);

        // (1) Forged Accept: flip a byte of the Response Authenticator.
        let mut bad_response_authenticator = server_response(2, id, &ra, &[]);
        bad_response_authenticator[4] ^= 0xFF;

        // (2) Valid Response Authenticator but NO Message-Authenticator:
        //     discarded because strict mode is the config default.
        let attrs: Vec<u8> = Vec::new();
        let length = 20u16;
        let resp_auth = radius::response_authenticator(2, id, length, &ra, &attrs, SECRET);
        let mut missing_message_authenticator = vec![2, id];
        missing_message_authenticator.extend(length.to_be_bytes());
        missing_message_authenticator.extend(resp_auth);

        // (3) The authentic Accept the wait must reach.
        let mut datagrams = vec![bad_response_authenticator, missing_message_authenticator];
        datagrams.extend(authentic(request));
        datagrams
    });

    let (outcome, log) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(
        outcome,
        PamOutcome::Success,
        "the wait must continue past two discarded datagrams to the authentic Accept"
    );
    assert_eq!(outcome.pam_code(), pam_codes::SUCCESS);
    assert_eq!(
        transport.exchanges(),
        1,
        "all three datagrams were offered within a SINGLE exchange"
    );
    assert!(log.contains(&format!("info:{PUSH_NOTICE}")));
}

// ===========================================================================
// Rule 1 (bounded loop): PAP multi-round Challenge/State and MAX_CHALLENGE_ROUNDS.
// ===========================================================================

/// Rule 1: several Access-Challenge rounds then an Accept succeed, and each
/// follow-up echoes the NEWEST State byte-for-byte (never a stale one) while
/// carrying that round's OTP from the conversation as a freshly hidden
/// User-Password.
#[test]
fn pap_multi_round_challenge_state_echoes_newest_state_and_otp_then_succeeds() {
    const OTP1: &str = "111111";
    const OTP2: &str = "222222";
    const OTP3: &str = "333333";

    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();

    // Exchange 1: initial request (hides the first-factor password) -> Challenge STATE-1.
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        let parsed = radius::parse_response(request).unwrap();
        let hidden: Vec<u8> = parsed
            .attr_values(radius::attr::USER_PASSWORD)
            .next()
            .expect("User-Password present")
            .to_vec();
        assert_eq!(hidden, pap::hide_password(PASSWORD.as_bytes(), SECRET, &ra));
        vec![server_response(
            11,
            id,
            &ra,
            &[
                (radius::attr::REPLY_MESSAGE, b"Enter your code".to_vec()),
                (radius::attr::STATE, b"STATE-1".to_vec()),
            ],
        )]
    });
    // Exchange 2: must echo STATE-1 and carry hide(OTP1) -> Challenge STATE-2.
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        let parsed = radius::parse_response(request).unwrap();
        let state: Vec<u8> = parsed
            .attr_values(radius::attr::STATE)
            .next()
            .expect("State echoed")
            .to_vec();
        assert_eq!(state, b"STATE-1", "round 2 must echo the newest State");
        let hidden: Vec<u8> = parsed
            .attr_values(radius::attr::USER_PASSWORD)
            .next()
            .expect("User-Password present")
            .to_vec();
        assert_eq!(hidden, pap::hide_password(OTP1.as_bytes(), SECRET, &ra));
        vec![server_response(
            11,
            id,
            &ra,
            &[
                (radius::attr::REPLY_MESSAGE, b"Enter your code".to_vec()),
                (radius::attr::STATE, b"STATE-2".to_vec()),
            ],
        )]
    });
    // Exchange 3: must echo STATE-2 (not the stale STATE-1) and carry hide(OTP2) -> Challenge STATE-3.
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        let parsed = radius::parse_response(request).unwrap();
        let state: Vec<u8> = parsed
            .attr_values(radius::attr::STATE)
            .next()
            .expect("State echoed")
            .to_vec();
        assert_eq!(state, b"STATE-2", "round 3 must echo the NEWEST State, not a stale one");
        let hidden: Vec<u8> = parsed
            .attr_values(radius::attr::USER_PASSWORD)
            .next()
            .expect("User-Password present")
            .to_vec();
        assert_eq!(hidden, pap::hide_password(OTP2.as_bytes(), SECRET, &ra));
        vec![server_response(
            11,
            id,
            &ra,
            &[
                (radius::attr::REPLY_MESSAGE, b"Enter your code".to_vec()),
                (radius::attr::STATE, b"STATE-3".to_vec()),
            ],
        )]
    });
    // Exchange 4: must echo STATE-3 and carry hide(OTP3) -> Accept.
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        let parsed = radius::parse_response(request).unwrap();
        let state: Vec<u8> = parsed
            .attr_values(radius::attr::STATE)
            .next()
            .expect("State echoed")
            .to_vec();
        assert_eq!(state, b"STATE-3", "final round must echo the NEWEST State");
        let hidden: Vec<u8> = parsed
            .attr_values(radius::attr::USER_PASSWORD)
            .next()
            .expect("User-Password present")
            .to_vec();
        assert_eq!(hidden, pap::hide_password(OTP3.as_bytes(), SECRET, &ra));
        vec![server_response(2, id, &ra, &[])]
    });

    let (outcome, log) = run(&config, PASSWORD, &[OTP1, OTP2, OTP3], &mut transport);
    assert_eq!(outcome, PamOutcome::Success);
    assert_eq!(outcome.pam_code(), pam_codes::SUCCESS);
    assert_eq!(transport.exchanges(), 4, "initial request + three challenge rounds");
    assert_eq!(
        log.iter().filter(|l| l.as_str() == "prompt:Enter your code").count(),
        3,
        "one OTP prompt per challenge round"
    );
}

/// Rule 1 (bounded loop): a server that keeps issuing Access-Challenge past
/// MAX_CHALLENGE_ROUNDS (=8) must be denied — NOT looped unbounded. The fake
/// always has another challenge to give (12 scripted, more than the flow can
/// ever consume), so the ONLY possible reason for termination is the bound.
/// The flow denies with PAM_AUTH_ERR after exactly 9 exchanges (the initial
/// request plus 8 bounded challenge rounds).
#[test]
fn pap_challenge_rounds_exceeding_max_is_pam_auth_err() {
    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();

    // Always answer with a fresh Access-Challenge (distinct State each time);
    // far more than the flow's bound so exhaustion of the script can never be
    // the cause of the deny.
    for round in 0u16..12 {
        let state = format!("STATE-{round}").into_bytes();
        transport.push_reply(move |request| {
            let id = request[1];
            let ra = request_authenticator_of(request);
            vec![server_response(
                11,
                id,
                &ra,
                &[
                    (radius::attr::REPLY_MESSAGE, b"Enter your code".to_vec()),
                    (radius::attr::STATE, state.clone()),
                ],
            )]
        });
    }

    // Enough OTP replies that the conversation never runs dry (8 prompts occur).
    let otps = vec![OTP; 12];
    let (outcome, _) = run(&config, PASSWORD, &otps, &mut transport);
    assert_eq!(
        outcome,
        PamOutcome::AuthErr,
        "exceeding MAX_CHALLENGE_ROUNDS denies (fail closed), not an unbounded loop"
    );
    assert_eq!(outcome.pam_code(), pam_codes::AUTH_ERR);
    assert_eq!(
        transport.exchanges(),
        9,
        "bounded at MAX_CHALLENGE_ROUNDS=8: initial request + 8 challenge rounds"
    );
}

// ===========================================================================
// Conversation-failure path: broken PAM conversation -> PAM_CONV_ERR.
// ===========================================================================

/// A PAP challenge arrives but the conversation cannot deliver the OTP prompt
/// (no reply scripted -> `prompt_echo_off` returns `ConvError::Failed`). The
/// flow maps it to PamOutcome::ConvErr -> PAM_CONV_ERR, and sends no follow-up.
#[test]
fn pap_conversation_failure_on_otp_prompt_is_pam_conv_err() {
    let config = test_config(Protocol::Pap, 1);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(
            11,
            id,
            &ra,
            &[
                (radius::attr::REPLY_MESSAGE, b"Enter your code".to_vec()),
                (radius::attr::STATE, b"STATE-1".to_vec()),
            ],
        )]
    });

    // No OTP reply scripted: the conversation fails when prompted.
    let (outcome, log) = run(&config, PASSWORD, &[], &mut transport);
    assert_eq!(outcome, PamOutcome::ConvErr);
    assert_eq!(outcome.pam_code(), pam_codes::CONV_ERR);
    assert!(
        log.iter().any(|l| l.starts_with("prompt:")),
        "the OTP prompt was attempted"
    );
    assert_eq!(
        transport.exchanges(),
        1,
        "no follow-up is sent after a conversation failure"
    );
}

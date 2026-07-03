//! Phase 7 wiring: EXACTLY ONE audit record per authentication attempt.
//!
//! Each case drives the real `flow::authenticate_report` end-to-end through the
//! in-memory `radius::test_support::FakeTransport` (an honest or hostile NPS),
//! then hands the resulting `AuthReport` to the phase-7 helper
//! `audit_emit::emit_attempt` with a `RecordingSink` and asserts the record
//! count and `result` field. No root, no live auditd/journald (those need
//! root / RHEL and are exercised only in the manual phase-9 gate — see the
//! audit crate's ffi.rs). A3 is checked with a sink that panics.

use std::collections::VecDeque;

use audit::{AuditRecord, AuditSink, AuthResult, RecordingSink};
use config::{AuditBackend, Config, Protocol, Server};
use pam_nps_mfa::audit_emit;
use pam_nps_mfa::conversation::{ConvError, Conversation};
use pam_nps_mfa::flow::{self, AttemptContext, AuthReport, PamOutcome};
use radius::test_support::FakeTransport;
use radius::TransportError;
use secrets::SecretString;

const SECRET: &[u8] = b"radius-shared-secret";
const USERNAME: &str = "User";
const PASSWORD: &str = "clientPass";
const CORR: &str = "00112233445566778899aabbccddeeff";

// ---------------------------------------------------------------------------
// Minimal doubles / packet helpers (mirrors flow_return_codes.rs).
// ---------------------------------------------------------------------------

struct FakeConversation {
    replies: VecDeque<String>,
}

impl FakeConversation {
    fn new(replies: &[&str]) -> Self {
        Self {
            replies: replies.iter().map(|r| (*r).to_owned()).collect(),
        }
    }
}

impl Conversation for FakeConversation {
    fn info(&mut self, _text: &str) -> Result<(), ConvError> {
        Ok(())
    }
    fn prompt_echo_off(&mut self, _prompt: &str) -> Result<SecretString, ConvError> {
        self.replies
            .pop_front()
            .map(|r| SecretString::from_text(&r))
            .ok_or(ConvError::Failed)
    }
}

fn test_config(protocol: Protocol) -> Config {
    Config {
        servers: vec![Server {
            addr: "10.0.0.10:1812".parse().unwrap(),
            secret: SecretString::from_text(std::str::from_utf8(SECRET).unwrap()),
        }],
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

fn run_report(config: &Config, replies: &[&str], transport: &mut FakeTransport) -> AuthReport {
    let mut conv = FakeConversation::new(replies);
    let password = SecretString::from_text(PASSWORD);
    let ctx = AttemptContext {
        username: USERNAME,
        password: &password,
        corr: CORR,
    };
    flow::authenticate_report(&ctx, config, &mut conv, transport)
}

fn request_authenticator_of(request: &[u8]) -> [u8; 16] {
    let mut ra = [0u8; 16];
    ra.copy_from_slice(&request[4..20]);
    ra
}

fn server_response(code: u8, id: u8, req_auth: &[u8; 16], attrs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut attr_bytes = Vec::new();
    for (attr_type, value) in attrs {
        attr_bytes.extend(radius::encode_attribute(*attr_type, value).unwrap());
    }
    let ma_value_off = attr_bytes.len() + 2;
    attr_bytes
        .extend(radius::encode_attribute(radius::attr::MESSAGE_AUTHENTICATOR, &[0u8; 16]).unwrap());

    let length = (20 + attr_bytes.len()) as u16;
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

fn ms_vsa(vendor_type: u8, data: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(6 + data.len());
    value.extend_from_slice(&radius::VENDOR_ID_MICROSOFT.to_be_bytes());
    value.push(vendor_type);
    value.push((2 + data.len()) as u8);
    value.extend_from_slice(data);
    value
}

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

/// Drive the flow, emit through a RecordingSink, and return the (single)
/// stored record. Asserts exactly one record was produced.
fn emit_and_take_one(config: &Config, replies: &[&str], transport: &mut FakeTransport) -> AuditRecord {
    let report = run_report(config, replies, transport);
    let sink = RecordingSink::new();
    audit_emit::emit_attempt(
        &sink,
        audit_emit::proto_str(config.protocol),
        USERNAME,
        CORR,
        &report,
    );
    assert_eq!(sink.len(), 1, "exactly one record per attempt");
    sink.records().pop().unwrap()
}

// ---------------------------------------------------------------------------
// One record per attempt, correct result token.
// ---------------------------------------------------------------------------

#[test]
fn good_mschapv2_accept_emits_one_success_record() {
    let config = test_config(Protocol::Mschapv2);
    let mut transport = FakeTransport::new();
    transport.push_reply(mschapv2_accept_responder(PASSWORD));

    let record = emit_and_take_one(&config, &[], &mut transport);
    assert_eq!(record.result, AuthResult::Success);
    assert_eq!(record.reason, "success");
    assert_eq!(record.proto, "mschapv2");
    assert_eq!(record.user, USERNAME);
    assert_eq!(record.server, "10.0.0.10");
    assert_eq!(record.corr, CORR);
    // Rule 3: the record carries no credential bytes — assert the password and
    // shared secret never appear in the rendered line.
    let line = record.render();
    assert!(!line.contains(PASSWORD));
    assert!(!line.contains(std::str::from_utf8(SECRET).unwrap()));
}

#[test]
fn mschapv2_reject_emits_one_denied_record() {
    let config = test_config(Protocol::Mschapv2);
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

    let record = emit_and_take_one(&config, &[], &mut transport);
    assert_eq!(record.result, AuthResult::Denied);
    assert_eq!(record.reason, "reject");
    assert_eq!(record.server, "10.0.0.10");
}

#[test]
fn mschapv2_bad_success_emits_one_denied_record_with_mutual_auth_reason() {
    let config = test_config(Protocol::Mschapv2);
    let mut transport = FakeTransport::new();
    // Server signs with the wrong password: the Accept's S= cannot verify.
    transport.push_reply(mschapv2_accept_responder("not-the-user-password"));

    let record = emit_and_take_one(&config, &[], &mut transport);
    assert_eq!(record.result, AuthResult::Denied);
    assert_eq!(record.reason, "mutual_auth_failed");
}

#[test]
fn transport_timeout_emits_one_unavail_record() {
    let config = test_config(Protocol::Mschapv2);
    let mut transport = FakeTransport::new();
    transport.push_error(TransportError::Timeout);

    let record = emit_and_take_one(&config, &[], &mut transport);
    assert_eq!(record.result, AuthResult::Unavail);
    assert_eq!(record.reason, "timeout");
    // The committed server is recorded even though it went silent.
    assert_eq!(record.server, "10.0.0.10");
}

#[test]
fn config_error_emits_one_unavail_record_via_boundary() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    // A permissive (0644) config is refused by config::load before its
    // contents are trusted (rule 12). The boundary emits result=unavail
    // reason=config_error to syslog in production; here we exercise the same
    // helper against a RecordingSink so it is assertable without root.
    let path = std::env::temp_dir().join(format!(
        "pam_nps_mfa_audit_permissive_{}.conf",
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1").unwrap();
        writeln!(f, "protocol mschapv2").unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = config::load(&path).expect_err("permissive config refused");
    let _ = std::fs::remove_file(&path);

    let outcome = flow::outcome_for_config_error(&err);
    assert_eq!(outcome, PamOutcome::Unavail);

    let sink = RecordingSink::new();
    audit_emit::emit_boundary(
        &sink,
        audit_emit::PROTO_UNKNOWN,
        USERNAME,
        CORR,
        audit_emit::result_from_pam_code(outcome.pam_code()),
        flow::reason::CONFIG_ERROR,
    );
    assert_eq!(sink.len(), 1);
    let record = &sink.records()[0];
    assert_eq!(record.result, AuthResult::Unavail);
    assert_eq!(record.reason, "config_error");
    assert_eq!(record.proto, "unknown");
    // No server was reached before the config failed to load.
    assert_eq!(record.server, "");
}

#[test]
fn pap_accept_emits_one_success_record() {
    let config = test_config(Protocol::Pap);
    let mut transport = FakeTransport::new();
    transport.push_reply(|request| {
        let id = request[1];
        let ra = request_authenticator_of(request);
        vec![server_response(2, id, &ra, &[])]
    });

    let record = emit_and_take_one(&config, &[], &mut transport);
    assert_eq!(record.result, AuthResult::Success);
    assert_eq!(record.proto, "pap");
}

// ---------------------------------------------------------------------------
// A3: a failing/ panicking audit backend NEVER changes the PAM return code.
// ---------------------------------------------------------------------------

/// A sink whose `emit` panics — models a backend blowing up mid-emit.
struct PanicSink;
impl AuditSink for PanicSink {
    fn emit(&self, _record: &AuditRecord) {
        panic!("audit backend panicked");
    }
}

#[test]
fn a3_panicking_sink_does_not_change_the_returned_pam_code() {
    let config = test_config(Protocol::Mschapv2);
    let mut transport = FakeTransport::new();
    transport.push_reply(mschapv2_accept_responder(PASSWORD));

    let report = run_report(&config, &[], &mut transport);
    // The code the caller will return, computed BEFORE the emit.
    let code_before = report.outcome.pam_code();
    assert_eq!(code_before, pam_nps_mfa::pam_codes::SUCCESS);

    // Emitting through a panicking sink must not unwind and must not alter the
    // outcome. If the panic escaped, the test process would abort here.
    audit_emit::emit_attempt(
        &PanicSink,
        audit_emit::proto_str(config.protocol),
        USERNAME,
        CORR,
        &report,
    );

    // The return code is unchanged after the (isolated) failed emit.
    assert_eq!(report.outcome.pam_code(), code_before);
}

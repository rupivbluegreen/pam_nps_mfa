//! Parser tests (grammar only, no filesystem/permissions).
//!
//! The parser is exercised on already-in-memory text via `config::parse`,
//! independent of the secure-file-loading path — see `permissions.rs` and
//! `load.rs` for that half.

use config::{parse, AuditBackend, ParseError, Protocol};

/// A minimal, fully valid config: exactly the two required keys.
const MINIMAL: &str = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
";

#[test]
fn parses_minimal_required_only_and_defaults_the_rest() {
    let c = parse(MINIMAL).expect("minimal config parses");
    assert_eq!(c.servers.len(), 1);
    assert_eq!(
        c.servers[0].addr,
        "10.0.0.10:1812".parse().unwrap()
    );
    assert_eq!(
        c.servers[0].secret_path,
        std::path::Path::new("/etc/pam_nps/secret.d/nps1")
    );
    assert_eq!(c.protocol, Protocol::Mschapv2);

    // Documented defaults for omitted optional keys.
    assert_eq!(c.probe_timeout, 5, "probe_timeout defaults to 5 (A1)");
    assert_eq!(c.timeout, 60);
    assert_eq!(c.retries, 1);
    assert!(c.require_message_authenticator, "strict by default");
    assert_eq!(c.audit, AuditBackend::Both);
    assert!(!c.debug);
    assert_eq!(c.nas_identifier, None);
    assert_eq!(c.nas_ip, None);
    assert_eq!(c.source_ip, None);
}

#[test]
fn parses_all_schema_keys_in_order() {
    let text = "\
# comment line
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
server 10.0.0.11:1812 /etc/pam_nps/secret.d/nps2

protocol      pap
timeout       90
probe_timeout 7
retries       2
nas_identifier tunnel-host-01
nas_ip        10.20.0.5
source_ip     0.0.0.0
require_message_authenticator false
audit         syslog
debug         true
";
    let c = parse(text).expect("full config parses");

    assert_eq!(c.servers.len(), 2);
    assert_eq!(c.servers[0].addr, "10.0.0.10:1812".parse().unwrap());
    assert_eq!(c.servers[1].addr, "10.0.0.11:1812".parse().unwrap());
    assert_eq!(
        c.servers[1].secret_path,
        std::path::Path::new("/etc/pam_nps/secret.d/nps2")
    );
    assert_eq!(c.protocol, Protocol::Pap);
    assert_eq!(c.timeout, 90);
    assert_eq!(c.probe_timeout, 7);
    assert_eq!(c.retries, 2);
    assert_eq!(c.nas_identifier.as_deref(), Some("tunnel-host-01"));
    assert_eq!(c.nas_ip, Some("10.20.0.5".parse().unwrap()));
    assert_eq!(c.source_ip, Some("0.0.0.0".parse().unwrap()));
    assert!(!c.require_message_authenticator);
    assert_eq!(c.audit, AuditBackend::Syslog);
    assert!(c.debug);
}

#[test]
fn probe_timeout_is_read_when_present() {
    let text = format!("{MINIMAL}probe_timeout 12\n");
    let c = parse(&text).expect("parses");
    assert_eq!(c.probe_timeout, 12);
}

#[test]
fn inline_comments_and_blank_lines_are_ignored() {
    let text = "\
# a full-line comment
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1   # trailing comment

protocol mschapv2 # inline
";
    let c = parse(text).expect("parses with comments");
    assert_eq!(c.servers.len(), 1);
    assert_eq!(c.protocol, Protocol::Mschapv2);
}

#[test]
fn rejects_duplicate_scalar_key() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
protocol pap
";
    match parse(text) {
        Err(ParseError::DuplicateKey { line, key }) => {
            assert_eq!(line, 3);
            assert_eq!(key, "protocol");
        }
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
}

#[test]
fn rejects_unknown_key() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
frobnicate 1
";
    match parse(text) {
        Err(ParseError::UnknownKey { line, key }) => {
            assert_eq!(line, 3);
            assert_eq!(key, "frobnicate");
        }
        other => panic!("expected UnknownKey, got {other:?}"),
    }
}

#[test]
fn rejects_bad_integer() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
timeout notanumber
";
    match parse(text) {
        Err(ParseError::MalformedValue { key, .. }) => assert_eq!(key, "timeout"),
        other => panic!("expected MalformedValue, got {other:?}"),
    }
}

#[test]
fn rejects_negative_integer() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
retries -1
";
    assert!(matches!(
        parse(text),
        Err(ParseError::MalformedValue { .. })
    ));
}

#[test]
fn rejects_bad_protocol_enum() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol sslv3
";
    match parse(text) {
        Err(ParseError::MalformedValue { key, .. }) => assert_eq!(key, "protocol"),
        other => panic!("expected MalformedValue, got {other:?}"),
    }
}

#[test]
fn rejects_bad_audit_enum() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
audit smoke-signals
";
    assert!(matches!(
        parse(text),
        Err(ParseError::MalformedValue { .. })
    ));
}

#[test]
fn rejects_bad_bool() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
require_message_authenticator yes
";
    assert!(matches!(
        parse(text),
        Err(ParseError::MalformedValue { .. })
    ));
}

#[test]
fn rejects_bad_ip() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2
nas_ip 999.1.1.1
";
    assert!(matches!(
        parse(text),
        Err(ParseError::MalformedValue { .. })
    ));
}

#[test]
fn rejects_server_without_port() {
    let text = "\
server 10.0.0.10 /etc/pam_nps/secret.d/nps1
protocol mschapv2
";
    match parse(text) {
        Err(ParseError::MalformedValue { key, .. }) => assert_eq!(key, "server"),
        other => panic!("expected MalformedValue for server, got {other:?}"),
    }
}

#[test]
fn rejects_server_with_wrong_token_count() {
    // Missing the secret path.
    let text = "\
server 10.0.0.10:1812
protocol mschapv2
";
    assert!(matches!(
        parse(text),
        Err(ParseError::MalformedValue { .. })
    ));
}

#[test]
fn rejects_scalar_with_extra_tokens() {
    let text = "\
server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1
protocol mschapv2 extra
";
    assert!(matches!(
        parse(text),
        Err(ParseError::MalformedValue { .. })
    ));
}

#[test]
fn rejects_missing_server() {
    let text = "protocol mschapv2\n";
    assert_eq!(
        parse(text),
        Err(ParseError::MissingRequired { key: "server" })
    );
}

#[test]
fn rejects_missing_protocol() {
    let text = "server 10.0.0.10:1812 /etc/pam_nps/secret.d/nps1\n";
    assert_eq!(
        parse(text),
        Err(ParseError::MissingRequired { key: "protocol" })
    );
}

#[test]
fn parses_committed_sample_conf() {
    // The committed packaging sample must parse and match the schema. It is
    // read as text and parsed only — its placeholder secret paths are never
    // opened here.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.conf");
    let text = std::fs::read_to_string(&path).expect("read sample.conf");
    let c = parse(&text).expect("sample.conf parses");

    assert_eq!(c.servers.len(), 2);
    assert_eq!(c.protocol, Protocol::Mschapv2);
    assert_eq!(c.timeout, 60);
    assert_eq!(c.probe_timeout, 5);
    assert_eq!(c.retries, 1);
    assert_eq!(c.nas_identifier.as_deref(), Some("tunnel-host-01"));
    assert_eq!(c.nas_ip, Some("10.20.0.5".parse().unwrap()));
    assert_eq!(c.source_ip, Some("0.0.0.0".parse().unwrap()));
    assert!(c.require_message_authenticator);
    assert_eq!(c.audit, AuditBackend::Both);
    assert!(!c.debug);
}

//! Real-socket tests for the connected-UDP [`radius::UdpTransport`] (phase 6),
//! exercised over `127.0.0.1` against in-test RADIUS responders.
//!
//! These prove the wire behavior the in-memory `FakeTransport` cannot: the
//! two-stage A1 timing, identical-byte retransmission, the source-binding that
//! `connect(2)` gives, and — most importantly — that the ONLY fail-over
//! trigger is an explicit transport error (CLAUDE.md rule 16):
//!
//! * (A) happy path: a byte-correct Access-Accept is accepted.
//! * (B) silence → `Timeout`, and the flow does NOT fail over to a 2nd server.
//! * (C) explicit ICMP `ECONNREFUSED` → `Unreachable` → fail over succeeds.
//! * (D) a forged reply (bad authenticator) is discarded, never accepted.
//! * (E) on silence the identical request bytes are retransmitted.
//! * (F) an explicit `ECONNREFUSED` AFTER the commit boundary → `Timeout`
//!   (NOT `Unreachable`), and the flow does NOT fail over — the rule-16
//!   double-push regression. Compare (C): the SAME refused-port event yields
//!   `Unreachable` only while still inside the probe window.
//! * (G) a server that is silent through the probe window and whose socket is
//!   then dropped mid-stage-2 still denies with `Timeout` and no fail-over.
//!
//! Timings are injected as sub-second [`Duration`]s so the whole suite runs in
//! a couple of seconds, with generous margins.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use radius::{
    attr, fill_message_authenticator, fresh_request_authenticator, message_authenticator,
    parse_response, response_authenticator, Code, PacketBuilder, RadiusTransport, RequestBinding,
    TransportError, UdpTransport,
};

/// The shared secret both sides key their authenticators with.
const SECRET: &[u8] = b"loopback-shared-secret-not-a-real-one";

// ---------------------------------------------------------------------------
// Request / response construction helpers
// ---------------------------------------------------------------------------

/// Build a byte-correct Access-Request (User-Name + Message-Authenticator),
/// returning the packet, its Identifier, and its Request Authenticator so a
/// responder and a [`RequestBinding`] can be keyed to it.
fn build_request() -> (Vec<u8>, u8, [u8; 16]) {
    let request_authenticator = fresh_request_authenticator().expect("OS RNG");
    let id = request_authenticator[0];
    let mut packet = PacketBuilder::new(Code::AccessRequest, id, request_authenticator)
        .attribute(attr::USER_NAME, b"User")
        .expect("User-Name")
        .message_authenticator_placeholder()
        .expect("MA placeholder")
        .build()
        .expect("build request");
    fill_message_authenticator(&mut packet, SECRET).expect("fill MA");
    (packet, id, request_authenticator)
}

/// Build a byte-correct Access-Accept over a *received* request: it carries a
/// single Message-Authenticator attribute and echoes the request's Identifier
/// and Request Authenticator, so [`RequestBinding::verify_response`] accepts
/// it. `id_override` forges a wrong Identifier; `corrupt_auth` flips a bit of
/// the Response Authenticator. Either makes an honest binding reject it.
fn build_accept(request: &[u8], id_override: Option<u8>, corrupt_auth: bool) -> Vec<u8> {
    let req_id = request[1];
    let mut req_auth = [0u8; 16];
    req_auth.copy_from_slice(&request[4..20]);
    let id = id_override.unwrap_or(req_id);

    // Header (20) + one Message-Authenticator attribute (2 header + 16 value).
    let length: u16 = 20 + 18;
    let mut packet = vec![0u8; length as usize];
    packet[0] = Code::AccessAccept.as_u8();
    packet[1] = id;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[20] = attr::MESSAGE_AUTHENTICATOR;
    packet[21] = 18;
    // MA value [22..38] stays zero for the HMAC computation.

    // Response Message-Authenticator: the verifier substitutes the ORIGINAL
    // Request Authenticator for the Authenticator field, so set the field to
    // it before hashing the whole (MA-zeroed) packet.
    packet[4..20].copy_from_slice(&req_auth);
    let ma = message_authenticator(&packet, SECRET);
    packet[22..38].copy_from_slice(&ma);

    // Response Authenticator over the attributes with the MA now filled.
    let ra = response_authenticator(
        Code::AccessAccept.as_u8(),
        id,
        length,
        &req_auth,
        &packet[20..length as usize],
        SECRET,
    );
    packet[4..20].copy_from_slice(&ra);

    if corrupt_auth {
        packet[4] ^= 0xFF;
    }
    packet
}

// ---------------------------------------------------------------------------
// Responder threads (bind in the calling thread so the port is live before we
// return; UDP buffers the first datagram even if recv is not reached yet).
// ---------------------------------------------------------------------------

fn bound_socket() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
    let addr = socket.local_addr().expect("local addr");
    (socket, addr)
}

/// A responder that replies to the first request with a byte-correct
/// Access-Accept, then exits.
fn spawn_accepting() -> SocketAddr {
    let (socket, addr) = bound_socket();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        if let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let reply = build_accept(&buf[..n], None, false);
            let _ = socket.send_to(&reply, peer);
        }
    });
    addr
}

/// A responder that answers every request with a *forged* Access-Accept
/// (corrupted Response Authenticator), counting how many it sent. It has a
/// read timeout so the thread eventually exits.
fn spawn_forging() -> (SocketAddr, Arc<AtomicUsize>) {
    let (socket, addr) = bound_socket();
    socket
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("read timeout");
    let sent = Arc::new(AtomicUsize::new(0));
    let sent_thread = Arc::clone(&sent);
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let reply = build_accept(&buf[..n], None, true);
            if socket.send_to(&reply, peer).is_ok() {
                sent_thread.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (addr, sent)
}

/// A responder that never replies but records every datagram it receives
/// (byte-for-byte), so a test can assert retransmits are identical. Has a read
/// timeout so the thread exits.
fn spawn_silent_recording() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let (socket, addr) = bound_socket();
    socket
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("read timeout");
    let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let received_thread = Arc::clone(&received);
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, _peer)) = socket.recv_from(&mut buf) {
            received_thread.lock().unwrap().push(buf[..n].to_vec());
        }
    });
    (addr, received)
}

/// A `127.0.0.1` port with no listener: sending to it draws an ICMP
/// port-unreachable, delivered on the connected socket as `ECONNREFUSED`.
fn refused_addr() -> SocketAddr {
    let (socket, addr) = bound_socket();
    drop(socket);
    addr
}

/// A responder that is silent (never replies) for `hold` after receiving its
/// first datagram, then DROPS its socket — closing the port. Retransmits that
/// arrive while it holds are buffered on the still-open port (no ICMP); once
/// `hold` elapses and the socket is dropped, the port is refused. Used to model
/// a server that goes silent through the probe window and then dies mid-stage-2
/// (case G). The bind happens in the calling thread so the port is live before
/// this returns.
fn spawn_silent_then_drop(hold: Duration) -> SocketAddr {
    let (socket, addr) = bound_socket();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        // Block for the first datagram so the drop is anchored to the exchange
        // actually starting; a read timeout keeps the thread from hanging if it
        // never arrives.
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let _ = socket.recv_from(&mut buf);
        thread::sleep(hold);
        drop(socket);
    });
    addr
}

// ---------------------------------------------------------------------------
// (A) Happy path
// ---------------------------------------------------------------------------

#[test]
fn happy_path_accepts_a_byte_correct_access_accept() {
    let addr = spawn_accepting();
    let (request, id, req_auth) = build_request();
    let binding = RequestBinding::new(id, req_auth);

    let mut transport = UdpTransport::new(
        Duration::from_millis(200),
        Duration::from_secs(1),
        1,
        None,
    );
    let result = transport.exchange(addr, &request, &mut |d| binding.verify_response(d, SECRET));

    let datagram = result.expect("a verified Access-Accept is returned");
    let parsed = parse_response(&datagram).expect("structurally valid");
    assert_eq!(parsed.known_code(), Some(Code::AccessAccept));
    assert!(
        binding.verify_response(&datagram, SECRET),
        "the accepted datagram must pass the same binding the accept closure used"
    );
}

// ---------------------------------------------------------------------------
// (B) Silence → Timeout, and the flow does NOT fail over
// ---------------------------------------------------------------------------

#[test]
fn silence_times_out_and_does_not_fail_over() {
    // Server 1 is silent; server 2 must never be contacted (rule 16).
    let (addr1, _rec1) = spawn_silent_recording();
    let (addr2, received2) = spawn_silent_recording();
    let (request, id, req_auth) = build_request();
    let binding = RequestBinding::new(id, req_auth);

    let mut transport = UdpTransport::new(
        Duration::from_millis(100),
        Duration::from_millis(500),
        0,
        None,
    );

    // Mirror flow.rs: iterate servers; ONLY Unreachable advances to the next.
    let mut final_result = None;
    for addr in [addr1, addr2] {
        match transport.exchange(addr, &request, &mut |d| binding.verify_response(d, SECRET)) {
            Err(TransportError::Unreachable) => continue,
            other => {
                final_result = Some(other);
                break;
            }
        }
    }

    assert_eq!(
        final_result,
        Some(Err(TransportError::Timeout)),
        "a silent server yields Timeout after the MFA wait"
    );
    assert!(
        received2.lock().unwrap().is_empty(),
        "silence must NOT fail over to the second server (rule 16)"
    );
}

// ---------------------------------------------------------------------------
// (C) Explicit ICMP error → Unreachable → fail over succeeds
// ---------------------------------------------------------------------------

#[test]
fn explicit_error_fails_over_to_a_reachable_server() {
    let refused = refused_addr();
    let reachable = spawn_accepting();
    let (request, id, req_auth) = build_request();
    let binding = RequestBinding::new(id, req_auth);

    let mut transport = UdpTransport::new(
        Duration::from_millis(300),
        Duration::from_secs(1),
        0,
        None,
    );

    // Server 1 (refused) must be Unreachable; only then do we reach server 2.
    let first = transport.exchange(refused, &request, &mut |d| binding.verify_response(d, SECRET));
    assert_eq!(
        first,
        Err(TransportError::Unreachable),
        "a refused port must surface as an explicit transport error"
    );

    let second =
        transport.exchange(reachable, &request, &mut |d| binding.verify_response(d, SECRET));
    let datagram = second.expect("the reachable server's Accept is returned after fail-over");
    assert_eq!(
        parse_response(&datagram).unwrap().known_code(),
        Some(Code::AccessAccept)
    );
}

// ---------------------------------------------------------------------------
// (D) A forged reply is discarded, never accepted
// ---------------------------------------------------------------------------

#[test]
fn forged_reply_is_discarded_and_times_out() {
    let (addr, sent) = spawn_forging();
    let (request, id, req_auth) = build_request();
    let binding = RequestBinding::new(id, req_auth);

    let mut transport = UdpTransport::new(
        Duration::from_millis(100),
        Duration::from_millis(400),
        0,
        None,
    );
    let result = transport.exchange(addr, &request, &mut |d| binding.verify_response(d, SECRET));

    assert_eq!(
        result,
        Err(TransportError::Timeout),
        "a forged datagram must be discarded, never accepted, and the wait runs out"
    );
    assert!(
        sent.load(Ordering::SeqCst) >= 1,
        "the responder must have actually delivered a forgery for it to be discarded"
    );
}

// ---------------------------------------------------------------------------
// (E) Retransmission resends the identical request bytes
// ---------------------------------------------------------------------------

#[test]
fn silence_retransmits_the_identical_request_bytes() {
    let (addr, received) = spawn_silent_recording();
    let (request, id, req_auth) = build_request();
    let binding = RequestBinding::new(id, req_auth);

    // retries = 2 across a 150ms probe window: sends at 0, 50, 100ms.
    let mut transport = UdpTransport::new(
        Duration::from_millis(150),
        Duration::from_millis(500),
        2,
        None,
    );
    let result = transport.exchange(addr, &request, &mut |d| binding.verify_response(d, SECRET));
    assert_eq!(result, Err(TransportError::Timeout));

    let seen = received.lock().unwrap();
    assert!(
        seen.len() > 1,
        "silence must trigger at least one retransmit; saw {} datagram(s)",
        seen.len()
    );
    for datagram in seen.iter() {
        assert_eq!(
            datagram, &request,
            "each retransmit must be byte-identical (same Identifier and Authenticator, \
             not a freshly built packet) so NPS suppresses it as a duplicate (rule 16)"
        );
    }
}

// ---------------------------------------------------------------------------
// (F) An explicit ECONNREFUSED AFTER commit → Timeout (NOT Unreachable),
//     no fail-over. The core rule-16 double-push regression (udp.rs ~L264-268).
// ---------------------------------------------------------------------------

#[test]
fn late_explicit_error_after_commit_denies_without_failover() {
    // The commit boundary in `UdpTransport::exchange` is exactly
    // `start.elapsed() >= probe_timeout`. Setting `probe_timeout == 0` commits
    // the server from t=0, so the `ECONNREFUSED` that a refused port delivers on
    // the client's first `recv` is — by construction — an explicit transport
    // error strictly AFTER commit. That drives the exact fixed branch
    //     IoClass::Unreachable => { if elapsed < probe { Unreachable } else { Timeout } }
    // down its `else` (terminal-deny) arm every time.
    //
    // Why probe == 0 rather than a timed socket-drop: with this transport the
    // client stops transmitting at the probe boundary (retransmits are spaced
    // strictly inside `probe_timeout`), so it never sends into stage 2 and thus
    // can never ELICIT a fresh ICMP after commit on loopback — a timed drop can
    // only produce silence (case G) or, if it lands during the probe window, a
    // legitimate pre-commit fail-over (case C). Collapsing the probe window to
    // zero is the one deterministic way to place a real `ECONNREFUSED` in the
    // post-commit branch with a real socket.
    //
    // Determinism: `elapsed >= Duration::ZERO` is ALWAYS true, so the outcome is
    // independent of scheduling jitter. And if the ICMP were ever missed (it is
    // not on loopback — case C depends on it), `recv` would simply time out and
    // stage 2 would still return `Timeout` at `mfa_timeout`. So the assertion
    // "Timeout, never Unreachable" holds on every path; ONLY a reverted fix
    // (returning `Unreachable` post-commit) can make it fail. Contrast case (C):
    // the identical refused-port event with a non-zero probe window yields
    // `Unreachable` and DOES fail over.
    let refused = refused_addr();
    let (addr2, received2) = spawn_silent_recording();
    let (request, id, req_auth) = build_request();
    let binding = RequestBinding::new(id, req_auth);

    let mut transport = UdpTransport::new(
        Duration::ZERO,             // probe window collapsed: committed at t=0
        Duration::from_millis(500), // stage-2 budget (a silence fallback stays fast)
        0,                          // no retransmits; the first recv sees ECONNREFUSED
        None,
    );

    // Mirror flow.rs: iterate servers; ONLY Unreachable advances to the next.
    let mut final_result = None;
    for addr in [refused, addr2] {
        match transport.exchange(addr, &request, &mut |d| binding.verify_response(d, SECRET)) {
            Err(TransportError::Unreachable) => continue,
            other => {
                final_result = Some(other);
                break;
            }
        }
    }

    assert_eq!(
        final_result,
        Some(Err(TransportError::Timeout)),
        "an explicit transport error AFTER commit must be a terminal deny (Timeout), \
         never Unreachable — otherwise the flow fails over and races a SECOND push (rule 16)"
    );
    assert!(
        received2.lock().unwrap().is_empty(),
        "a post-commit explicit error must NOT fail over to the second server (rule 16); \
         server 2 saw {} datagram(s)",
        received2.lock().unwrap().len()
    );
}

// ---------------------------------------------------------------------------
// (G) Silent through the probe window, then the socket is dropped mid-stage-2:
//     still Timeout, still no fail-over (the realistic rule-16 scenario).
// ---------------------------------------------------------------------------

#[test]
fn silent_through_probe_then_dropped_denies_without_failover() {
    // Server 1 receives the request, stays silent through the whole probe
    // window, and only then (well past commit, still inside the MFA wait) closes
    // its socket. Because the client never transmits into stage 2, the closed
    // port is never hit and no ICMP is elicited: the exchange runs out the MFA
    // budget and denies with Timeout. This is the wire realisation of the bug
    // report's scenario — a committed server that dies mid-wait must still deny
    // WITHOUT contacting a second server (which could push again).
    //
    // Timing (all well-separated so it cannot flake into a pre-commit fail-over):
    //   probe_timeout = 80ms   -> retransmits at 20/40/60ms, all inside probe.
    //   drop after     = 250ms -> 170ms past the last transmit AND past commit,
    //                             so every client datagram reached the port while
    //                             it was still open (buffered, no ICMP).
    //   mfa_timeout   = 500ms  -> stage 2 elapses in silence -> Timeout.
    let addr1 = spawn_silent_then_drop(Duration::from_millis(250));
    let (addr2, received2) = spawn_silent_recording();
    let (request, id, req_auth) = build_request();
    let binding = RequestBinding::new(id, req_auth);

    let mut transport = UdpTransport::new(
        Duration::from_millis(80),
        Duration::from_millis(500),
        3,
        None,
    );

    let mut final_result = None;
    for addr in [addr1, addr2] {
        match transport.exchange(addr, &request, &mut |d| binding.verify_response(d, SECRET)) {
            Err(TransportError::Unreachable) => continue,
            other => {
                final_result = Some(other);
                break;
            }
        }
    }

    assert_eq!(
        final_result,
        Some(Err(TransportError::Timeout)),
        "a committed server that goes silent and then dies mid-stage-2 must deny with Timeout"
    );
    assert!(
        received2.lock().unwrap().is_empty(),
        "a committed-then-dead server must NOT fail over (rule 16); server 2 saw {} datagram(s)",
        received2.lock().unwrap().len()
    );
}

//! In-memory [`RadiusTransport`] fake for driving the PAM flow (phase 5) and
//! the transport-layer tests (phase 6) without a socket.
//!
//! Only compiled with `feature = "test-support"`. Nothing here touches the
//! network or holds secret material: scripted responders receive the raw
//! request bytes and produce the datagrams "the server" answers with, so a
//! test can play an honest NPS (computing real authenticators from the
//! request) or a hostile one (corrupted datagrams that the accept closure
//! must discard).

use std::collections::VecDeque;
use std::net::SocketAddr;

use crate::transport::{RadiusTransport, TransportError};

/// A scripted server turn: given the request bytes, the datagrams to offer to
/// the accept closure, in order. Deliberately not `Send`-bound so tests can
/// capture `Rc<RefCell<..>>` event logs.
pub type Responder = Box<dyn FnMut(&[u8]) -> Vec<Vec<u8>>>;

enum Step {
    /// Offer the produced datagrams to `accept` in order; the first accepted
    /// one is the exchange result. If none is accepted the exchange times
    /// out, exactly like the real transport discarding forgeries until the
    /// deadline (CLAUDE.md rule 14).
    Reply(Responder),
    /// The exchange fails with this transport error.
    Error(TransportError),
}

/// Replays scripted steps, one per [`RadiusTransport::exchange`] call, and
/// records every request it was handed for later assertions.
///
/// An exhausted script behaves as silence: `Err(TransportError::Timeout)`.
/// That is the fail-closed default — a flow that performs more exchanges than
/// the test scripted observes a timeout, never a success.
#[derive(Default)]
pub struct FakeTransport {
    steps: VecDeque<Step>,
    /// Every request handed to [`RadiusTransport::exchange`], in call order.
    pub requests: Vec<Vec<u8>>,
    /// The server address handed to each [`RadiusTransport::exchange`] call,
    /// in call order. Lets a test assert which server the flow contacted
    /// (e.g. that silence did NOT fail over to a second server — rule 16).
    pub servers: Vec<SocketAddr>,
}

impl FakeTransport {
    /// An empty script (every exchange times out).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the next exchange to answer with the datagrams the responder
    /// computes from the request bytes.
    pub fn push_reply<F>(&mut self, responder: F)
    where
        F: FnMut(&[u8]) -> Vec<Vec<u8>> + 'static,
    {
        self.steps.push_back(Step::Reply(Box::new(responder)));
    }

    /// Script the next exchange to offer these fixed datagrams, ignoring the
    /// request bytes.
    pub fn push_datagrams(&mut self, datagrams: Vec<Vec<u8>>) {
        self.push_reply(move |_req| datagrams.clone());
    }

    /// Script the next exchange to fail with `error`.
    pub fn push_error(&mut self, error: TransportError) {
        self.steps.push_back(Step::Error(error));
    }

    /// How many exchanges the flow performed so far.
    #[must_use]
    pub fn exchanges(&self) -> usize {
        self.requests.len()
    }
}

impl RadiusTransport for FakeTransport {
    fn exchange(
        &mut self,
        server: SocketAddr,
        request: &[u8],
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        self.requests.push(request.to_vec());
        self.servers.push(server);
        match self.steps.pop_front() {
            None => Err(TransportError::Timeout),
            Some(Step::Error(error)) => Err(error),
            Some(Step::Reply(mut responder)) => {
                for datagram in responder(request) {
                    if accept(&datagram) {
                        return Ok(datagram);
                    }
                }
                // Every offered datagram was discarded by the binding check:
                // the wait runs out. A discarded forgery is NOT a Reject.
                Err(TransportError::Timeout)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(n: u8) -> SocketAddr {
        format!("10.0.0.{n}:1812").parse().unwrap()
    }

    #[test]
    fn scripted_error_then_reply() {
        let mut t = FakeTransport::new();
        t.push_error(TransportError::Unreachable);
        t.push_datagrams(vec![vec![1, 2], vec![3, 4]]);

        assert_eq!(
            t.exchange(srv(10), b"a", &mut |_| true),
            Err(TransportError::Unreachable)
        );
        assert_eq!(
            t.exchange(srv(11), b"b", &mut |d| d == [3, 4]),
            Ok(vec![3, 4])
        );
        assert_eq!(t.exchanges(), 2);
        assert_eq!(t.requests, vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(t.servers, vec![srv(10), srv(11)]);
    }

    #[test]
    fn exhausted_script_and_all_discarded_are_timeouts() {
        let mut t = FakeTransport::new();
        t.push_datagrams(vec![vec![9, 9]]);
        // All datagrams rejected by the accept closure -> timeout.
        assert_eq!(
            t.exchange(srv(10), b"x", &mut |_| false),
            Err(TransportError::Timeout)
        );
        // Script exhausted -> timeout (fail closed).
        assert_eq!(
            t.exchange(srv(10), b"y", &mut |_| true),
            Err(TransportError::Timeout)
        );
    }
}

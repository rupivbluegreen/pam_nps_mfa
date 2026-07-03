//! Transport abstraction (IMPLEMENTATION_SPEC.md §1).
//!
//! The RADIUS request-and-response step is a trait so the codec, the
//! failover logic, and the PAM plumbing can be unit tested without a socket
//! (phase 5) and backed by a real connected UDP socket later (phase 6).
//! No UDP implementation lives here yet.

/// Transport-level outcome of one exchange attempt.
///
/// The distinction matters for failover (CLAUDE.md rule 16): only
/// [`TransportError::Unreachable`] permits moving to the next server.
/// Silence is [`TransportError::Timeout`] and the attempt is denied without
/// failover, because a silent server may already have issued an MFA push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Explicit transport error (ICMP unreachable, connection refused).
    /// Failover to the next configured server is permitted.
    Unreachable,
    /// No accepted response before the deadline. Deny; do not fail over.
    Timeout,
    /// Any other local I/O failure. Deny.
    Io,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Unreachable => "server explicitly unreachable",
            Self::Timeout => "no valid response before the timeout",
            Self::Io => "local transport I/O failure",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TransportError {}

/// One RADIUS request/response exchange against a single server.
///
/// Implementations send `request` (retransmitting the identical bytes per
/// their retry policy), then deliver each received datagram to `accept`.
/// A datagram for which `accept` returns `false` — wrong Identifier, wrong
/// source, failed authenticator — is discarded and the wait continues until
/// the deadline (CLAUDE.md rule 14). The first accepted datagram is
/// returned. Implementations must cap the received datagram at 4096 octets.
pub trait RadiusTransport {
    fn exchange(
        &mut self,
        request: &[u8],
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory double: replays scripted datagrams in order.
    /// A reusable `FakeTransport` for the PAM flow arrives in phase 5.
    struct ScriptedTransport {
        datagrams: Vec<Vec<u8>>,
        next: usize,
    }

    impl RadiusTransport for ScriptedTransport {
        fn exchange(
            &mut self,
            _request: &[u8],
            accept: &mut dyn FnMut(&[u8]) -> bool,
        ) -> Result<Vec<u8>, TransportError> {
            while self.next < self.datagrams.len() {
                let datagram = self.datagrams[self.next].clone();
                self.next += 1;
                if accept(&datagram) {
                    return Ok(datagram);
                }
            }
            Err(TransportError::Timeout)
        }
    }

    #[test]
    fn non_matching_datagrams_are_discarded_not_returned() {
        let mut transport = ScriptedTransport {
            datagrams: vec![vec![0x02, 0x01], vec![0x02, 0x2A]],
            next: 0,
        };
        let got = transport
            .exchange(b"request", &mut |d: &[u8]| d.get(1) == Some(&0x2A))
            .expect("second datagram matches");
        assert_eq!(got, vec![0x02, 0x2A]);
    }

    #[test]
    fn silence_is_a_timeout_not_a_response() {
        let mut transport = ScriptedTransport {
            datagrams: vec![vec![0x02, 0x01]],
            next: 0,
        };
        let got = transport.exchange(b"request", &mut |_d: &[u8]| false);
        assert_eq!(got, Err(TransportError::Timeout));
    }
}

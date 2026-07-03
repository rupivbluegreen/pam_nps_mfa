//! Connected-UDP RADIUS transport (phase 6).
//!
//! One [`UdpTransport::exchange`] drives a single server through the
//! two-stage timing of SPEC_AMENDMENTS.md A1 on a `connect(2)`ed socket
//! (A5), so that the fail-over rules of CLAUDE.md rule 16 fall out of the
//! kernel's ICMP delivery rather than a guess:
//!
//! * A fresh [`std::net::UdpSocket`] is bound to `(source_ip or 0.0.0.0):0`
//!   per call — an ephemeral OS-assigned source port, never reused
//!   (CLAUDE.md rule 5 / SECURITY_DESIGN.md §5). This is the source
//!   address/port half of response binding: the connected socket makes the
//!   kernel drop any datagram whose source is not the connected peer, so the
//!   `accept` closure only ever sees datagrams from the right server and is
//!   left to check the Identifier, Response Authenticator, and
//!   Message-Authenticator (rule 14).
//! * `connect(2)` to the server means an ICMP port/host/net-unreachable is
//!   delivered to userspace as an explicit `send`/`recv` error
//!   (`ECONNREFUSED` / `EHOSTUNREACH` / `ENETUNREACH`). That — and only that —
//!   maps to [`TransportError::Unreachable`], the sole fail-over trigger
//!   (rule 16). A silent server is never a fail-over; it commits and is
//!   waited out.
//!
//! ## Two-stage timing (A1)
//!
//! Stage 1 is the `probe_timeout` window: it covers reaching a live server at
//! the transport level, and the identical request is retransmitted up to
//! `retries` times, spaced across that window, to cover UDP loss (NPS
//! suppresses these as duplicates — same Identifier and Authenticator — so
//! they cause no second push and do not reset the wait, rule 16). An explicit
//! transport error *within this window* returns [`TransportError::Unreachable`]
//! and the flow fails over. If `probe_timeout` elapses in silence the server
//! is *committed*: it may already have issued an MFA push, so from the commit
//! boundary onward an explicit transport error is a terminal deny
//! ([`TransportError::Timeout`], NO fail-over), exactly like silence — sending
//! the same authentication to a second server would race two approvals
//! (rule 16 / SPEC_AMENDMENTS.md A1).
//!
//! Stage 2 keeps waiting on that committed server until the total elapsed
//! time reaches `mfa_timeout` (the full MFA-approval window). If it elapses
//! with no accepted datagram and no explicit error, the exchange returns
//! [`TransportError::Timeout`]; the flow maps that to `PAM_AUTHINFO_UNAVAIL`
//! and does **not** fail over, because a silent server may already have
//! pushed to the user's device.
//!
//! Because the flow denies (no fail-over) on `Timeout`, only ONE server ever
//! enters the long committed wait; servers that error are probed and skipped
//! fast. Worst-case wall clock across `N` configured servers is therefore
//! about `(N - 1) * probe_timeout + mfa_timeout` (the first `N-1` servers
//! each erroring just under `probe_timeout`, the last committing for the full
//! `mfa_timeout`). Size these against sshd's `LoginGraceTime` with headroom:
//! at the defaults (`probe_timeout 5`, `timeout 60`, and a handful of
//! servers) this stays well under the default 120-second grace window.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::transport::{RadiusTransport, TransportError};
use crate::MAX_PACKET_LEN;

/// A read timeout is never set to zero (`std` rejects a zero-duration
/// timeout, and on some platforms it would mean "block forever"). Right at a
/// scheduling boundary the wait is floored to this.
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

/// Connected-UDP RADIUS transport implementing the A1 two-stage timing.
///
/// Holds only timing configuration — no socket, no secret, no per-attempt
/// state — so a single instance can drive every server in the configured
/// list, one [`exchange`](RadiusTransport::exchange) per server, and is
/// trivially safe to use across concurrent PAM invocations (each call owns
/// its own freshly bound socket).
pub struct UdpTransport {
    /// Stage-1 transport probe window and the span across which retransmits
    /// are spaced.
    probe_timeout: Duration,
    /// Total per-server wait (the full MFA-approval window). Must be at least
    /// `probe_timeout`; a shorter value simply collapses stage 2.
    mfa_timeout: Duration,
    /// Identical-packet retransmits per server (in addition to the first
    /// send), spaced across `probe_timeout`.
    retries: u32,
    /// Optional bind address for the client socket; `None` binds `0.0.0.0`.
    source_ip: Option<Ipv4Addr>,
}

/// Classification of an [`io::Error`] into the three outcomes the timing loop
/// cares about.
enum IoClass {
    /// The read timed out (`WouldBlock`/`TimedOut`): a silence tick.
    Silence,
    /// An explicit transport error (ICMP unreachable / connection refused):
    /// the one fail-over trigger (rule 16), and only inside the probe window.
    Unreachable,
    /// The syscall was interrupted by a signal (`EINTR`). `std`'s `UdpSocket`
    /// does not auto-retry this, so a benign signal (SIGCHLD/SIGWINCH/sshd's
    /// `LoginGraceTime` SIGALRM, all plausible in the hosting process) surfaces
    /// here mid-wait. It is NOT a failure: resume the same operation with the
    /// remaining budget, denying nothing (rule 1 governs errors, not signals).
    Retry,
    /// Any other local I/O failure: deny.
    Local,
}

/// Map an [`io::Error`] to an [`IoClass`]. `ECONNREFUSED`, `EHOSTUNREACH`, and
/// `ENETUNREACH` are the explicit transport errors; a receive timeout is
/// silence; everything else is a local failure.
fn classify(error: &io::Error) -> IoClass {
    match error.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable => IoClass::Unreachable,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IoClass::Silence,
        io::ErrorKind::Interrupted => IoClass::Retry,
        _ => IoClass::Local,
    }
}

/// Send `request` on the connected `socket`, transparently resuming on `EINTR`
/// (a signal is not a transport failure and must not deny a login the user may
/// already have approved — rule 1). Every other error is mapped by
/// [`send_error`]; an explicit transport error here still fails over, which is
/// correct because all sends happen at t=0 or during the probe window.
fn send_request(socket: &UdpSocket, request: &[u8]) -> Result<(), TransportError> {
    loop {
        match socket.send(request) {
            Ok(_) => return Ok(()),
            Err(error) if matches!(classify(&error), IoClass::Retry) => continue,
            Err(error) => return Err(send_error(&error)),
        }
    }
}

/// Map an error seen on `send`/`connect` (never a legitimate timeout) to a
/// [`TransportError`]: an explicit transport error fails over, anything else
/// is a local failure that denies.
fn send_error(error: &io::Error) -> TransportError {
    match classify(error) {
        IoClass::Unreachable => TransportError::Unreachable,
        _ => TransportError::Io,
    }
}

/// The spacing between the identical-packet retransmits across the stage-1
/// probe window. With `retries` retransmits placed strictly inside
/// `probe_timeout`, they land at `interval, 2*interval, ..., retries*interval`.
fn retransmit_interval(probe_timeout: Duration, retries: u32) -> Duration {
    // `retries + 1` is always >= 1, so this never divides by zero.
    probe_timeout / (retries + 1)
}

impl UdpTransport {
    /// Construct directly from [`Duration`]s. Tests use this with sub-second
    /// values so the suite runs quickly.
    #[must_use]
    pub fn new(
        probe_timeout: Duration,
        mfa_timeout: Duration,
        retries: u32,
        source_ip: Option<Ipv4Addr>,
    ) -> Self {
        Self {
            probe_timeout,
            mfa_timeout,
            retries,
            source_ip,
        }
    }

    /// Construct from the config timing, which is in whole seconds
    /// (IMPLEMENTATION_SPEC.md §6 + SPEC_AMENDMENTS.md A1): `probe_timeout`
    /// (stage-1 probe window), `timeout` (the full MFA wait), `retries`, and
    /// the optional client bind address.
    #[must_use]
    pub fn from_config(
        probe_timeout_secs: u32,
        mfa_timeout_secs: u32,
        retries: u32,
        source_ip: Option<Ipv4Addr>,
    ) -> Self {
        Self::new(
            Duration::from_secs(u64::from(probe_timeout_secs)),
            Duration::from_secs(u64::from(mfa_timeout_secs)),
            retries,
            source_ip,
        )
    }

    /// Bind a fresh ephemeral-port socket and `connect(2)` it to `server`.
    fn connect(&self, server: SocketAddr) -> Result<UdpSocket, TransportError> {
        let bind_addr = SocketAddr::new(
            IpAddr::V4(self.source_ip.unwrap_or(Ipv4Addr::UNSPECIFIED)),
            0,
        );
        let socket = UdpSocket::bind(bind_addr).map_err(|_| TransportError::Io)?;
        socket.connect(server).map_err(|e| send_error(&e))?;
        Ok(socket)
    }
}

impl RadiusTransport for UdpTransport {
    fn exchange(
        &mut self,
        server: SocketAddr,
        request: &[u8],
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        let socket = self.connect(server)?;

        // First transmission.
        send_request(&socket, request)?;

        let start = Instant::now();
        let interval = retransmit_interval(self.probe_timeout, self.retries);
        let mut retransmits_left = self.retries;
        // Elapsed offset of the next retransmit (only meaningful while
        // `retransmits_left > 0`).
        let mut next_retransmit = interval;

        // A single 4096-octet buffer: `recv` truncates a larger datagram to
        // this, which then fails `accept`. The datagram is thus capped at the
        // RADIUS maximum with no attacker-sized allocation.
        let mut buf = [0u8; MAX_PACKET_LEN];

        loop {
            let elapsed = start.elapsed();
            if elapsed >= self.mfa_timeout {
                // Stage 2 elapsed in silence: committed server, deny. NEVER a
                // fail-over (rule 16).
                return Err(TransportError::Timeout);
            }

            // Wake at the sooner of the next scheduled retransmit or the total
            // MFA deadline.
            let mut wake = self.mfa_timeout;
            if retransmits_left > 0 {
                wake = wake.min(next_retransmit);
            }
            let read_timeout = wake.saturating_sub(elapsed).max(MIN_READ_TIMEOUT);
            if socket.set_read_timeout(Some(read_timeout)).is_err() {
                return Err(TransportError::Io);
            }

            match socket.recv(&mut buf) {
                Ok(n) => {
                    // `n <= MAX_PACKET_LEN` always (buffer size); the cap is
                    // structural.
                    let datagram = &buf[..n.min(MAX_PACKET_LEN)];
                    if accept(datagram) {
                        return Ok(datagram.to_vec());
                    }
                    // Wrong Identifier / failed authenticator / missing MA:
                    // discard and keep waiting (rule 14). Never fail over,
                    // never accept.
                }
                Err(error) => match classify(&error) {
                    // Explicit transport error. A1 commit boundary: fail over
                    // ONLY while still inside the probe window. Once committed
                    // (silent past `probe_timeout`) the server may already have
                    // pushed, so a LATE explicit error is a terminal deny —
                    // never a second server, never a double push (rule 16 /
                    // SPEC_AMENDMENTS.md A1). Re-read the clock (recv may have
                    // blocked up to the read timeout) so the boundary is exact.
                    IoClass::Unreachable => {
                        if start.elapsed() < self.probe_timeout {
                            return Err(TransportError::Unreachable);
                        }
                        return Err(TransportError::Timeout);
                    }
                    // A silence tick: retransmit the IDENTICAL bytes if a
                    // retransmit is due and budget remains.
                    IoClass::Silence => {
                        if retransmits_left > 0 && start.elapsed() >= next_retransmit {
                            send_request(&socket, request)?;
                            retransmits_left -= 1;
                            next_retransmit += interval;
                        }
                    }
                    // EINTR: a signal interrupted the recv. Resume waiting with
                    // the remaining budget (the loop top recomputes the read
                    // timeout from `elapsed`); do NOT consume a retransmit and
                    // do NOT deny.
                    IoClass::Retry => {}
                    // Any other local I/O failure denies.
                    IoClass::Local => return Err(TransportError::Io),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the private `classify` mapping. `classify` and `IoClass`
    //! are module-private, so these live inside `udp.rs` (tests only — no
    //! change to any production logic). This pins the two classifications the
    //! rule-16 fix leans on: an explicit transport error is `Unreachable` (the
    //! sole fail-over trigger, gated by the commit boundary in `exchange`), and
    //! a signal (`EINTR`) is `Retry` (resume the wait, never a deny).

    use super::{classify, IoClass};
    use std::io;

    /// `matches!` against the private, non-`Debug` `IoClass` so a mismatch is a
    /// hard test failure with a readable message.
    fn assert_classified(kind: io::ErrorKind, expected: &str) {
        let class = classify(&io::Error::from(kind));
        let ok = match expected {
            "Silence" => matches!(class, IoClass::Silence),
            "Unreachable" => matches!(class, IoClass::Unreachable),
            "Retry" => matches!(class, IoClass::Retry),
            "Local" => matches!(class, IoClass::Local),
            other => panic!("unknown expected class {other}"),
        };
        assert!(ok, "{kind:?} must classify as {expected}");
    }

    #[test]
    fn interrupted_is_retry_not_a_deny() {
        // EINTR: a benign signal mid-wait. The wait resumes; it must never be
        // Unreachable (fail-over) or Local (deny).
        assert_classified(io::ErrorKind::Interrupted, "Retry");
    }

    #[test]
    fn explicit_transport_errors_are_unreachable() {
        // ECONNREFUSED / EHOSTUNREACH / ENETUNREACH: the only fail-over trigger
        // (rule 16), and only inside the probe window (enforced by `exchange`).
        assert_classified(io::ErrorKind::ConnectionRefused, "Unreachable");
        assert_classified(io::ErrorKind::HostUnreachable, "Unreachable");
        assert_classified(io::ErrorKind::NetworkUnreachable, "Unreachable");
    }

    #[test]
    fn receive_timeouts_are_silence() {
        // A read timeout (WouldBlock/TimedOut): a silence tick, not a deny.
        assert_classified(io::ErrorKind::WouldBlock, "Silence");
        assert_classified(io::ErrorKind::TimedOut, "Silence");
    }

    #[test]
    fn other_errors_are_local_failures() {
        // Anything else denies locally (rule 1), never fails over.
        assert_classified(io::ErrorKind::PermissionDenied, "Local");
        assert_classified(io::ErrorKind::Other, "Local");
    }
}

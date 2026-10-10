//! Reproduction of an open str0m issue: a viewer that
//! behaves like Safari did against a local daemon (2026-10-01, observed
//! behavior) never connects, because str0m's controlled ICE agent (`is`
//! 0.11.1, `IceAgent::evaluate_nomination`) sends on a pair the viewer
//! nominated before any check of ours on it succeeded, and never moves to the
//! valid ICE-TCP pair the viewer nominates next. RFC 8445 §7.3.1.5 and §8.1.1
//! select only valid (succeeded) nominated pairs.
//!
//! The daemon side is the real `lotse_webrtc::Session`, in memory, on a clock
//! the test moves. The viewer side has two halves, as Safari had:
//!
//! - UDP: hand-made RFC 8489 Binding requests from two viewer ports carrying
//!   USE-CANDIDATE (aggressive nomination, RFC 8445 §7.1.2). Nothing the
//!   daemon sends to those ports arrives: Safari never received the daemon's
//!   UDP. A str0m viewer cannot produce this half, because a controlling str0m
//!   only nominates pairs whose checks succeeded.
//! - TCP: the str0m viewer with an active ICE-TCP candidate (RFC 6544), a
//!   real ICE and DTLS peer, so DTLS completes as soon as the daemon sends
//!   over TCP.
//!
//! The nomination test is ignored until str0m is fixed; it lives in `lotse-testing`
//! so its lines stay out of the coverage gate while it is ignored. Run it
//! with `cargo nextest run -p lotse-testing --run-ignored only t7_`. The
//! two control tests run the same harness without the nomination and pass
//! today, so a failure of the nomination test is str0m's, not the harness's.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::clock::{Clock as _, SystemClock};
use lotse_core::codec::Codec;
use lotse_core::session::{
    IceCredentials, SessionEngine as _, SessionEvent, SessionLimits, SessionOutput, SessionRequest,
    Transport,
};
use lotse_testing::viewer::{Outgoing, Viewer};
use lotse_webrtc::{Session, State};

/// The daemon's UDP host candidate.
const DAEMON: &str = "192.0.2.10:18556";
/// The daemon's passive ICE-TCP host candidate.
const DAEMON_TCP: &str = "192.0.2.10:18557";
/// The viewer's TCP side: the str0m viewer's active candidate.
const VIEWER_TCP: &str = "192.0.2.20:40000";
/// The viewer's two UDP ports, learned by the daemon as peer-reflexive
/// (Safari offered only mDNS host candidates, which the engine ignores).
const VIEWER_UDP: [&str; 2] = ["192.0.2.20:51941", "192.0.2.20:51942"];
/// The PRIORITY Safari sent from each UDP port (2026-10-01, observed): type
/// preference 110, the peer-reflexive one (RFC 8445 §5.1.2.2, §7.1.1), and
/// a local preference per port. Both rank above every TCP pair.
const VIEWER_UDP_PRIORITY: [u32; 2] = [1_845_501_695, 1_845_501_439];
/// How often the UDP ports check again: Safari's retransmissions and later
/// checks keep arriving while it tries TCP.
const UDP_RECHECK: Duration = Duration::from_millis(500);

/// A minimal STUN Binding request encoder (RFC 8489), the ICE attributes of
/// RFC 8445 §7.1 included. Independent of the engine under test.
mod stun {
    use hmac::{Hmac, Mac as _};

    /// The magic cookie (RFC 8489 §5).
    const MAGIC_COOKIE: u32 = 0x2112_a442;
    /// The Binding method, request class (RFC 8489 §5, §18.2).
    const BINDING_REQUEST: u16 = 0x0001;
    /// USERNAME (RFC 8489 §14.3, §18.3).
    const USERNAME: u16 = 0x0006;
    /// MESSAGE-INTEGRITY (RFC 8489 §14.5, §18.3).
    const MESSAGE_INTEGRITY: u16 = 0x0008;
    /// FINGERPRINT (RFC 8489 §14.7, §18.3).
    const FINGERPRINT: u16 = 0x8028;
    /// PRIORITY (RFC 8445 §7.1.1, §16.1).
    const PRIORITY: u16 = 0x0024;
    /// USE-CANDIDATE (RFC 8445 §7.1.2, §16.1).
    const USE_CANDIDATE: u16 = 0x0025;
    /// ICE-CONTROLLING (RFC 8445 §7.1.3, §16.1).
    const ICE_CONTROLLING: u16 = 0x802a;
    /// What FINGERPRINT's CRC-32 is combined with by XOR (RFC 8489 §14.7).
    const FINGERPRINT_XOR: u32 = 0x5354_554e;

    /// What one request carries.
    pub(super) struct Request<'a> {
        /// The transaction ID (RFC 8489 §5).
        pub(super) transaction: [u8; 12],
        /// `<receiver ufrag>:<sender ufrag>` (RFC 8445 §7.2.2).
        pub(super) username: &'a str,
        /// The receiver's ice-pwd, the short-term credential key (RFC 8489 §9.1.1).
        pub(super) password: &'a str,
        /// PRIORITY (RFC 8445 §7.1.1).
        pub(super) priority: u32,
        /// The ICE-CONTROLLING tie-breaker (RFC 8445 §7.1.3).
        pub(super) tie_breaker: u64,
        /// USE-CANDIDATE present (RFC 8445 §7.1.2).
        pub(super) use_candidate: bool,
    }

    /// One attribute, padded to a multiple of 4 bytes (RFC 8489 §14).
    fn attribute(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out.resize(out.len().next_multiple_of(4), 0);
    }

    /// Sets the header's message length to `len` bytes after the header
    /// (RFC 8489 §5).
    fn set_length(message: &mut [u8], len: usize) {
        message[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    }

    /// CRC-32 of ISO/IEC 13239 (the one of ITU-T V.42), which FINGERPRINT
    /// uses (RFC 8489 §14.7).
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0_u32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// The encoded Binding request: USERNAME, PRIORITY, ICE-CONTROLLING,
    /// USE-CANDIDATE when asked, MESSAGE-INTEGRITY, then FINGERPRINT last
    /// (RFC 8489 §14.5, §14.7; RFC 8445 §7.1).
    pub(super) fn binding_request(request: &Request<'_>) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        message.extend_from_slice(&[0, 0]);
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(&request.transaction);
        attribute(&mut message, USERNAME, request.username.as_bytes());
        attribute(&mut message, PRIORITY, &request.priority.to_be_bytes());
        attribute(
            &mut message,
            ICE_CONTROLLING,
            &request.tie_breaker.to_be_bytes(),
        );
        if request.use_candidate {
            attribute(&mut message, USE_CANDIDATE, &[]);
        }
        // §14.5: the HMAC covers the message up to the attribute before
        // MESSAGE-INTEGRITY, with the length already counting it (24 bytes).
        let len = message.len() - 20 + 24;
        set_length(&mut message, len);
        let mut mac =
            Hmac::<sha1::Sha1>::new_from_slice(request.password.as_bytes()).expect("any key");
        mac.update(&message);
        let integrity = mac.finalize().into_bytes();
        attribute(&mut message, MESSAGE_INTEGRITY, &integrity);
        // §14.7: the CRC covers everything before FINGERPRINT, with the
        // length already counting it (8 bytes).
        let len = message.len() - 20 + 8;
        set_length(&mut message, len);
        let fingerprint = crc32(&message) ^ FINGERPRINT_XOR;
        attribute(&mut message, FINGERPRINT, &fingerprint.to_be_bytes());
        message
    }

    #[test]
    fn rfc8489_14_7_the_fingerprint_crc_is_iso_13239_crc32() {
        // The standard check value of CRC-32/ISO-HDLC.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn rfc8489_14_the_request_is_padded_and_ends_in_integrity_and_fingerprint() {
        let message = binding_request(&Request {
            transaction: [7; 12],
            username: "abc:de",
            password: "pw",
            priority: 1,
            tie_breaker: 2,
            use_candidate: true,
        });
        assert_eq!(&message[0..2], &[0, 1]);
        let len = usize::from(u16::from_be_bytes([message[2], message[3]]));
        assert_eq!(message.len(), 20 + len);
        assert_eq!(len % 4, 0);
        // USERNAME 6 bytes padded to 8, PRIORITY, ICE-CONTROLLING,
        // USE-CANDIDATE, MESSAGE-INTEGRITY, FINGERPRINT.
        assert_eq!(len, (4 + 8) + (4 + 4) + (4 + 8) + 4 + (4 + 20) + (4 + 4));
        assert_eq!(
            &message[message.len() - 8..message.len() - 6],
            &[0x80, 0x28]
        );
        assert_eq!(
            &message[message.len() - 32..message.len() - 30],
            &[0x00, 0x08]
        );
    }
}

/// What the viewer's UDP ports send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpChecks {
    /// Nothing: a viewer on TCP alone.
    Silent,
    /// Binding requests without USE-CANDIDATE.
    Unnominated,
    /// Binding requests with USE-CANDIDATE, as Safari sent them.
    Nominating,
}

/// Datagrams the daemon sent somewhere, by kind (RFC 7983 §7 first-byte
/// demultiplexing).
#[derive(Debug, Default, Clone)]
struct Tally {
    /// STUN (first byte 0–3).
    stun: usize,
    /// DTLS (20–63) and SRTP/SRTCP (128–191): what only goes on the
    /// selected pair.
    dtls_or_srtp: usize,
    /// Where the DTLS and SRTP went: the selected pair's remote end.
    dtls_or_srtp_to: Vec<SocketAddr>,
}

impl Tally {
    fn count(&mut self, payload: &[u8], destination: SocketAddr) {
        if payload.first().is_some_and(|&b| b <= 3) {
            self.stun += 1;
        } else {
            self.dtls_or_srtp += 1;
            if !self.dtls_or_srtp_to.contains(&destination) {
                self.dtls_or_srtp_to.push(destination);
            }
        }
    }
}

/// The daemon's session and the Safari-like viewer, with what is in flight.
struct Safari {
    session: Session,
    viewer: Viewer,
    now: Instant,
    events: Vec<SessionEvent>,
    session_timeout: Option<Instant>,
    /// Daemon datagrams to the viewer's TCP side, delivered.
    to_viewer: Vec<(SocketAddr, Vec<u8>)>,
    /// Viewer datagrams to the daemon.
    to_daemon: Vec<Outgoing>,
    /// What the daemon sent to the viewer's UDP ports, all lost.
    to_dead_udp: Tally,
    /// What the daemon sent over TCP.
    to_tcp: Tally,
    /// What the UDP ports send.
    udp: UdpChecks,
    /// The viewer's ufrag, from its offer.
    viewer_ufrag: String,
    /// The daemon's ufrag and ice-pwd, from its answer.
    daemon_ufrag: String,
    daemon_pwd: String,
    /// When the UDP ports check next.
    next_udp_check: Instant,
    /// Transaction IDs handed out.
    transactions: u32,
}

/// The value of the first `a=<name>:` line of `sdp`.
fn sdp_attribute(sdp: &str, name: &str) -> String {
    let prefix = format!("a={name}:");
    sdp.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no {prefix} in {sdp}"))
        .trim()
        .to_owned()
}

impl Safari {
    /// The session answers the viewer's offer; the UDP ports send `udp`.
    fn new(udp: UdpChecks) -> (Self, String) {
        let now = SystemClock.now();
        lotse_webrtc::install_crypto_provider();
        let viewer = Viewer::new_tcp(VIEWER_TCP.parse().unwrap(), now).expect("a viewer");
        let request = SessionRequest {
            offer: viewer.offer().to_owned(),
            ice: IceCredentials {
                ufrag: "lotseufrag".into(),
                pass: "lotsepassword0123456789ab".into(),
            },
            candidates: vec![DAEMON.parse().unwrap()],
            tcp_candidates: vec![DAEMON_TCP.parse().unwrap()],
            video: Arc::new(Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            }),
            audio: None,
            backchannel: None,
            orientation: lotse_core::Orientation::default(),
            limits: SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let (session, answer) = Session::answer(&request, now).expect("an answer");
        let mut safari = Self {
            session,
            now,
            events: Vec::new(),
            session_timeout: None,
            to_viewer: Vec::new(),
            to_daemon: Vec::new(),
            to_dead_udp: Tally::default(),
            to_tcp: Tally::default(),
            udp,
            viewer_ufrag: sdp_attribute(viewer.offer(), "ice-ufrag"),
            daemon_ufrag: sdp_attribute(&answer, "ice-ufrag"),
            daemon_pwd: sdp_attribute(&answer, "ice-pwd"),
            viewer,
            next_udp_check: now,
            transactions: 0,
        };
        safari.drain();
        (safari, answer)
    }

    /// Moves what the session wants sent: TCP to the viewer, UDP to the
    /// viewer's ports, where it is lost.
    fn drain(&mut self) {
        loop {
            match self.session.poll() {
                SessionOutput::Transmit {
                    transport,
                    source,
                    destination,
                    payload,
                    ..
                } => match transport {
                    Transport::Tcp => {
                        self.to_tcp.count(&payload, destination);
                        self.to_viewer.push((source, payload));
                    }
                    Transport::Udp => {
                        assert!(
                            VIEWER_UDP.iter().any(|a| a.parse() == Ok(destination)),
                            "UDP to an address the viewer never used: {destination}"
                        );
                        self.to_dead_udp.count(&payload, destination);
                    }
                },
                SessionOutput::Event(event) => self.events.push(event),
                SessionOutput::Timeout(at) => {
                    self.session_timeout = Some(at);
                    return;
                }
            }
        }
    }

    /// One Binding request from each UDP port, unless they are silent.
    fn udp_checks(&mut self) {
        if self.udp == UdpChecks::Silent || self.now < self.next_udp_check {
            return;
        }
        self.next_udp_check = self.now + UDP_RECHECK;
        let username = format!("{}:{}", self.daemon_ufrag, self.viewer_ufrag);
        for (addr, priority) in VIEWER_UDP.iter().zip(VIEWER_UDP_PRIORITY) {
            self.transactions += 1;
            let mut transaction = [0_u8; 12];
            transaction[8..].copy_from_slice(&self.transactions.to_be_bytes());
            let request = stun::binding_request(&stun::Request {
                transaction,
                username: &username,
                password: &self.daemon_pwd,
                priority,
                tie_breaker: 0x5afa_71e0_0000_0007,
                use_candidate: self.udp == UdpChecks::Nominating,
            });
            self.session.handle_datagram(
                self.now,
                Transport::Udp,
                addr.parse().unwrap(),
                DAEMON.parse().unwrap(),
                &request,
            );
            self.drain();
        }
    }

    /// Advances at most 10 ms, to the next timeout when sooner, and moves
    /// what is in flight.
    fn step(&mut self) {
        let earliest = [
            self.session_timeout,
            self.viewer.next_timeout(),
            (self.udp != UdpChecks::Silent).then_some(self.next_udp_check),
        ]
        .into_iter()
        .flatten()
        .min();
        let floor = self.now + Duration::from_millis(1);
        let cap = self.now + Duration::from_millis(10);
        self.now = earliest.map_or(cap, |at| at.clamp(floor, cap));
        self.session.handle_timeout(self.now);
        self.drain();
        self.udp_checks();
        self.viewer.timeout(self.now, &mut self.to_daemon);
        for (source, bytes) in std::mem::take(&mut self.to_viewer) {
            self.viewer
                .receive(self.now, source, &bytes, &mut self.to_daemon);
        }
        for datagram in std::mem::take(&mut self.to_daemon) {
            assert!(datagram.tcp, "the viewer's str0m half is TCP only");
            self.session.handle_datagram(
                self.now,
                Transport::Tcp,
                datagram.source,
                datagram.destination,
                &datagram.payload,
            );
            self.drain();
        }
    }

    fn connected(&self) -> bool {
        self.session.state() == State::Connected && self.viewer.is_connected()
    }

    fn closed(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, SessionEvent::Closed { .. }))
    }

    /// Safari's order: its UDP checks reach the daemon first, then it
    /// applies the answer and its TCP side starts. Runs until both ends are
    /// connected, the session closes, or the connect timeout has passed.
    fn run(&mut self, answer: &str) -> Duration {
        let start = self.now;
        self.udp_checks();
        self.viewer
            .accept_answer(answer, &mut self.to_daemon)
            .expect("the answer applies");
        let give_up = start + SessionLimits::default().connect_timeout + Duration::from_secs(1);
        while !self.connected() && !self.closed() && self.now < give_up {
            self.step();
        }
        self.now - start
    }

    /// What happened, for the assertion messages.
    fn report(&self, elapsed: Duration) -> String {
        format!(
            "after {elapsed:?}: session {:?}, viewer connected {}, viewer ICE {:?}; \
             daemon -> dead viewer UDP: {} STUN, {} DTLS/SRTP (to {:?}); \
             daemon -> viewer TCP: {} STUN, {} DTLS/SRTP (to {:?}); events {:?}",
            self.session.state(),
            self.viewer.is_connected(),
            self.viewer.ice_states(),
            self.to_dead_udp.stun,
            self.to_dead_udp.dtls_or_srtp,
            self.to_dead_udp.dtls_or_srtp_to,
            self.to_tcp.stun,
            self.to_tcp.dtls_or_srtp,
            self.to_tcp.dtls_or_srtp_to,
            self.events,
        )
    }

    /// The outcome every variant must reach: connected within the connect
    /// timeout, DTLS over TCP, and nothing but STUN to the dead UDP ports.
    fn assert_connected_over_tcp(&self, elapsed: Duration) {
        let report = self.report(elapsed);
        assert!(self.connected(), "never connected: {report}");
        assert!(
            elapsed < SessionLimits::default().connect_timeout,
            "{report}"
        );
        assert!(self.to_tcp.dtls_or_srtp > 0, "no DTLS over TCP: {report}");
        assert_eq!(
            self.to_dead_udp.dtls_or_srtp, 0,
            "DTLS/SRTP sent to a UDP pair whose checks never succeeded: {report}"
        );
    }
}

/// Safari's sequence. Its UDP ports nominate their pairs with
/// USE-CANDIDATE before any check of ours on them can succeed (none ever
/// does: Safari never receives our UDP); then it nominates the ICE-TCP pair,
/// whose checks succeed. A controlled agent must select only the valid
/// nominated pair (RFC 8445 §7.3.1.5, §8.1.1), so DTLS runs over TCP and the
/// session connects. With str0m 0.24.0 / `is` 0.11.1 the send path stays on
/// the first UDP port, DTLS never completes and the session closes
/// `ice_failed`.
///
/// Run: `cargo nextest run -p lotse-testing --run-ignored only t7_`.
#[test]
#[ignore = "fails until str0m selects only valid nominated pairs; run with --run-ignored"]
fn t7_rfc8445_7_3_1_5_a_safari_like_viewer_that_nominates_a_dead_udp_pair_first_connects_over_ice_tcp()
 {
    let (mut safari, answer) = Safari::new(UdpChecks::Nominating);
    let elapsed = safari.run(&answer);
    safari.assert_connected_over_tcp(elapsed);
}

/// Control for the nomination test: the same viewer and sequence, but the
/// UDP checks carry no USE-CANDIDATE. Nothing nominates the dead pairs, so
/// the ICE-TCP pair the viewer nominates is selected (RFC 8445 §7.3.1.5)
/// and the session connects today: the harness is sound, and the
/// nomination test's failure is the nomination's.
#[test]
fn rfc8445_7_3_1_5_unnominated_udp_checks_leave_the_ice_tcp_pair_to_be_selected() {
    let (mut safari, answer) = Safari::new(UdpChecks::Unnominated);
    let elapsed = safari.run(&answer);
    safari.assert_connected_over_tcp(elapsed);
    assert!(safari.to_dead_udp.stun > 0, "{}", safari.report(elapsed));
}

/// Control for the nomination test: the same harness without any UDP: the viewer connects
/// over passive ICE-TCP (RFC 6544).
#[test]
fn rfc6544_the_harness_alone_connects_over_ice_tcp() {
    let (mut safari, answer) = Safari::new(UdpChecks::Silent);
    let elapsed = safari.run(&answer);
    safari.assert_connected_over_tcp(elapsed);
    assert_eq!(safari.to_dead_udp.stun, 0, "{}", safari.report(elapsed));
}

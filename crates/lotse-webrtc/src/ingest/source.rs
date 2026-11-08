//! One WebRTC camera source and the I/O of its attempts: the signaling
//! channel opened through the client's relay, one UDP socket per host
//! address on an ephemeral port, the [`IngestEngine`] driven by datagrams,
//! signals and the injected clock, and what it outputs carried onto the
//! tracks through `lotse_codec`'s RTP receive path.
//!
//! How an attempt ends, and the code its signaling channel closes with:
//!
//! | what happened | the source's error | close code |
//! |---|---|---|
//! | no relay, or the open refused | `Unreachable` | (none opened) |
//! | no host address enumerated (the UDP front door off) | `Unreachable` | `internal_error` |
//! | no host address could be bound | `Unreachable` | `ice_failed` |
//! | no answer within 20 s of the attempt's start | `Timeout` | `answer_timeout` |
//! | an answer the engine cannot apply | `Protocol` | `invalid_answer` |
//! | the relay refused a signal of the source's (`signal_rejected`) | `Protocol` | `internal_error` |
//! | the camera failed before its answer | `Unreachable("camera: code: message")` | `camera_error` |
//! | the camera failed after it | `Ended("camera: code: message")` | `camera_error` |
//! | not connected 27 s into the attempt (10 s after a later answer, 28 s at most) | `Timeout` | `ice_failed` |
//! | consent lost (RFC 7675) | `Ended` | `consent_lost` |
//! | the camera's DTLS `close_notify` | `Ended` | `peer_closed` |
//! | the relaying client went away | `Ended("signaling client gone")` | `signaling_lost` |
//! | cancelled | `Ended` | `source_stopped` |
//!
//! A cancel is honored at once: the engine closes (`close_notify`, RTCP
//! BYE) and is disconnected, its close datagrams sent without waiting.
//!
//! The tracks are declared at the answer and the source is ready once ICE
//! and DTLS are up: until then the runner's ready timeout bounds the
//! attempt, not its stall watchdog, so a camera that takes seconds to
//! connect is not cut off as stalled. The attempt's own deadlines count
//! from its start, the wait for a relaying client included, and end
//! before that ready timeout ([`super::engine::ATTEMPT_BUDGET`]), so one
//! that never connects ends as `ice_failed`. The offer and its candidates
//! go to the relay at once, at most [`MAX_HOSTS`] of them, which its queue
//! holds, so nothing waits on the relay. The loop waits on the cancel,
//! the signals, the host sockets (in turn, so a busy one starves none) and
//! the engine's timeout; an engine timeout that came due meanwhile is
//! handled before the I/O that woke the loop, so I/O that is always ready,
//! or that came at or after a deadline, neither postpones nor replaces it.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use lotse_codec::rtp_ingest::RtpTracks;
use lotse_core::codec::Kind;
use lotse_core::signaling::{LocalSignal, REJECTED, RemoteSignal, SignalingChannel, close};
use lotse_core::source::{Source, SourceCtx, SourceDescriptor, SourceError};
use lotse_core::task::BoxFuture;
use lotse_core::track::Track;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use super::engine::{IngestEnd, IngestEngine, IngestOutput, IngestTrack};
use super::factory::PROTOCOL;
use super::options::{WebRtcOptions, normalized};

/// The receive buffer: a datagram above the path MTU does not come from
/// a WebRTC peer, and one cut short fails its SRTP check.
const RECEIVE_BUFFER: usize = 2_048;

/// A validated WebRTC camera source: no address, its options only.
#[derive(Debug, Clone)]
pub struct WebRtcSource {
    /// The options.
    options: WebRtcOptions,
}

impl WebRtcSource {
    /// The source with `options`, checked by the factory.
    pub const fn new(options: WebRtcOptions) -> Self {
        Self { options }
    }
}

impl Source for WebRtcSource {
    fn describe(&self) -> SourceDescriptor {
        SourceDescriptor {
            protocol: PROTOCOL,
            url: None,
            options: normalized(&self.options),
        }
    }

    /// Every option changes the offer, so the key is all of them.
    fn connection_options(&self) -> serde_json::Value {
        normalized(&self.options)
    }

    fn run(&self, ctx: SourceCtx) -> BoxFuture<'static, SourceError> {
        Box::pin(attempt(self.options.clone(), ctx))
    }
}

/// One host socket: its address, the one its candidate names, and the
/// socket.
type Host = (SocketAddr, UdpSocket);

/// Binds one UDP socket on an ephemeral port per address of `addrs`; an
/// address that does not bind is logged and skipped.
async fn bind(addrs: &[IpAddr]) -> Vec<Host> {
    let mut hosts = Vec::new();
    for ip in addrs {
        let bound = UdpSocket::bind(SocketAddr::new(*ip, 0)).await;
        match bound.and_then(|socket| Ok((socket.local_addr()?, socket))) {
            Ok(host) => hosts.push(host),
            Err(err) => {
                tracing::warn!(%ip, error = %err, "webrtc: host address not bound; no candidate on it");
            }
        }
    }
    hosts
}

/// The host sockets, read in turn.
struct Hosts {
    /// The sockets.
    sockets: Vec<Host>,
    /// The one read first next time: the one after the last that had a
    /// datagram, so a socket that always has one starves none of the
    /// others.
    next: usize,
}

impl Hosts {
    /// The next datagram on any of the sockets, into `buf`: the index of
    /// the socket it came in on, and its sender and length or the error.
    /// The sockets are polled from the one after the last read.
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = (usize, io::Result<(SocketAddr, usize)>)> + 'a {
        std::future::poll_fn(move |cx| {
            let count = self.sockets.len();
            let turn = self.sockets.iter().enumerate().cycle().skip(self.next);
            for (index, (_, socket)) in turn.take(count) {
                let mut read = ReadBuf::new(buf);
                if let Poll::Ready(received) = socket.poll_recv_from(cx, &mut read) {
                    let len = read.filled().len();
                    self.next = index.wrapping_add(1);
                    return Poll::Ready((index, received.map(|from| (from, len))));
                }
            }
            Poll::Pending
        })
    }
}

impl Attempt {
    /// Sends `payload` from the host socket bound to `source` to
    /// `destination`, without waiting: a datagram that does not fit the
    /// socket's buffer now is lost, as on the wire, and counted.
    fn transmit(&mut self, source: SocketAddr, destination: SocketAddr, payload: &[u8]) {
        let socket = self.hosts.sockets.iter().find(|(addr, _)| *addr == source);
        let sent =
            socket.is_some_and(|(_, socket)| socket.try_send_to(payload, destination).is_ok());
        self.dropped = self.dropped.saturating_add(u64::from(!sent));
    }
}

/// What woke the attempt's loop, short of its end (the cancel, the
/// client gone), which the loop takes itself.
enum Woke {
    /// A signal from the client.
    Signal(RemoteSignal),
    /// A datagram on host socket `.0`.
    Datagram(usize, io::Result<(SocketAddr, usize)>),
}

/// The end of an attempt by cancel.
fn cancelled() -> IngestEnd {
    IngestEnd {
        error: SourceError::Ended("webrtc: cancelled".into()),
        close: close::SOURCE_STOPPED,
        message: "cancelled".to_owned(),
    }
}

/// The end of an attempt by the relaying client going away.
fn client_gone() -> IngestEnd {
    IngestEnd {
        error: SourceError::Ended("signaling client gone".into()),
        close: close::SIGNALING_LOST,
        message: "the signaling client is gone".to_owned(),
    }
}

/// One attempt's engine and I/O.
struct Attempt {
    /// The engine.
    engine: IngestEngine,
    /// The host sockets.
    hosts: Hosts,
    /// The RTP receive path.
    rtp: RtpTracks,
    /// The video's index, its track and its keyframes before this
    /// attempt, while the attempt waits for its first.
    waiting: Option<(usize, Arc<Track>, u64)>,
    /// The receive buffer.
    buf: Vec<u8>,
    /// Datagrams the sockets did not take.
    dropped: u64,
}

impl Attempt {
    /// Carries the engine's outputs until it waits: datagrams sent,
    /// tracks declared, the source ready once connected, packets and
    /// Sender Reports through the RTP receive path.
    /// `Ok` with when it wants the time next; `Err` with how the attempt
    /// ended, by the engine or by the receive path (the camera's
    /// timestamps keep jumping).
    fn drain(&mut self, ctx: &mut SourceCtx) -> Result<Instant, IngestEnd> {
        loop {
            match self.engine.poll() {
                IngestOutput::Timeout(at) => return Ok(at),
                IngestOutput::Ended(end) => return Err(end),
                IngestOutput::Transmit {
                    source,
                    destination,
                    payload,
                } => self.transmit(source, destination, &payload),
                IngestOutput::Tracks(tracks) => self.declare(ctx, tracks),
                IngestOutput::Connected => ctx.tracks.ready(),
                IngestOutput::Rtp {
                    index,
                    packet,
                    arrival,
                } => {
                    self.rtp
                        .receive(index, packet, arrival, ctx)
                        .map_err(|error| IngestEnd {
                            message: error.to_string(),
                            error,
                            close: close::INTERNAL_ERROR,
                        })?;
                    self.keyframe(index);
                }
                IngestOutput::SenderReport {
                    index,
                    ntp,
                    rtp_ts,
                    arrival,
                } => self.rtp.sender_report(index, ntp, rtp_ts, arrival, ctx),
            }
        }
    }

    /// Declares `tracks`, the ones the answer negotiated, and carries each
    /// on the RTP receive path; the source is ready once connected.
    fn declare(&mut self, ctx: &mut SourceCtx, tracks: Vec<IngestTrack>) {
        for negotiated in tracks {
            let declared = negotiated.declared;
            let track =
                ctx.tracks
                    .declare(declared.kind, declared.codec.clone(), declared.clock_rate);
            if declared.kind == Kind::Video {
                let before = track.stats().keyframes;
                self.waiting = Some((negotiated.index, Arc::clone(&track), before));
            }
            self.rtp
                .carry(negotiated.index, track, negotiated.pt, &declared);
        }
    }

    /// After a packet of stream `index`: once the video track counted a
    /// keyframe of this attempt, the engine stops asking for the first
    /// one.
    fn keyframe(&mut self, index: usize) {
        if let Some((video, track, before)) = &self.waiting
            && *video == index
            && track.stats().keyframes > *before
        {
            self.engine.keyframe_seen();
            self.waiting = None;
        }
    }

    /// Takes what woke the loop at `now`; `Some` with how the attempt
    /// ended.
    fn woke(&mut self, event: Woke, now: Instant) -> Option<IngestEnd> {
        match event {
            Woke::Signal(RemoteSignal::Answer(sdp)) => self.engine.accept_answer(now, &sdp),
            Woke::Signal(RemoteSignal::Candidate(candidate)) => {
                self.engine.add_remote_candidate(now, &candidate);
            }
            Woke::Signal(RemoteSignal::Failed { code, message }) if code == REJECTED => {
                // The relay refused what the source sent: the fault is
                // lotse's, not the camera's.
                let message = format!("webrtc: the relay refused a signal: {message}");
                return Some(IngestEnd {
                    error: SourceError::Protocol(message.clone()),
                    close: close::INTERNAL_ERROR,
                    message,
                });
            }
            Woke::Signal(RemoteSignal::Failed { code, message }) => {
                let message = format!("camera: {code}: {message}");
                let error = if self.engine.answered() {
                    SourceError::Ended(message.clone())
                } else {
                    SourceError::Unreachable(message.clone())
                };
                return Some(IngestEnd {
                    error,
                    close: close::CAMERA_ERROR,
                    message,
                });
            }
            Woke::Datagram(index, received) => {
                let local = self.hosts.sockets.get(index).map(|(addr, _)| *addr);
                let received = received
                    .inspect_err(|err| tracing::debug!(error = %err, "webrtc: receive failed"));
                if let (Some(local), Ok((from, len))) = (local, received) {
                    let datagram = self.buf.get(..len).unwrap_or_default();
                    self.engine.receive(now, from, local, datagram);
                }
            }
        }
        None
    }

    /// Ends the attempt as `end` says: the engine closed and its close
    /// output sent, `channel` closed with the code and message, the error
    /// returned.
    fn finish(mut self, channel: SignalingChannel, end: IngestEnd) -> SourceError {
        self.engine.close();
        while let IngestOutput::Transmit {
            source,
            destination,
            payload,
        } = self.engine.poll()
        {
            self.transmit(source, destination, &payload);
        }
        tracing::debug!(
            dropped = self.dropped,
            code = end.close,
            "webrtc: attempt over"
        );
        channel.close(end.close, end.message);
        end.error
    }
}

/// The most host addresses an attempt gathers on. Its offer carries one
/// candidate line per address and trickles each again, then the
/// end-of-candidates indication: 16 keeps that within what the relay
/// queues at once ([`lotse_core::signaling::OUTGOING_CAPACITY`], so handing them over never
/// waits), within the supervisor's budget of a signal's candidates (its
/// `MAX_WORKER_CANDIDATES`, 64) and the offer far under
/// [`super::engine::MAX_OFFER_BYTES`] (an IPv6 candidate line is about 100 bytes, the rest
/// of the offer three KiB). A host with more addresses than this has no
/// camera to reach on most of them.
pub const MAX_HOSTS: usize = 16;

/// How well an address of the supervisor's list reaches a camera, lower
/// first: the first one, the address of the default route (the
/// supervisor lists it first), then private IPv4 (RFC 1918, the home LAN a
/// camera is on), other IPv4, unique-local IPv6 (RFC 4193), other IPv6.
fn rank(at: usize, ip: IpAddr) -> u8 {
    match ip {
        _ if at == 0 => 0,
        IpAddr::V4(v4) if v4.is_private() => 1,
        IpAddr::V4(_) => 2,
        IpAddr::V6(v6) if v6.is_unique_local() => 3,
        IpAddr::V6(_) => 4,
    }
}

/// The host addresses of `addrs` an attempt gathers on: the [`MAX_HOSTS`]
/// that [`rank`] puts first, in the supervisor's order, which str0m keeps
/// as the candidates' preference.
fn preferred(addrs: &[IpAddr]) -> Vec<IpAddr> {
    let mut ranked: Vec<(u8, usize, IpAddr)> = addrs
        .iter()
        .enumerate()
        .map(|(at, ip)| (rank(at, *ip), at, *ip))
        .collect();
    ranked.sort_unstable();
    let listed = ranked.len();
    ranked.truncate(MAX_HOSTS);
    tracing::debug!(
        listed,
        kept = ranked.len(),
        "webrtc: host addresses to gather on, the preferred of those listed"
    );
    ranked.sort_unstable_by_key(|(_, at, _)| *at);
    ranked.into_iter().map(|(_, _, ip)| ip).collect()
}

/// Hands the offer, the host candidates and the end-of-candidates
/// indication to the relay at once, without waiting: there are at most
/// [`MAX_HOSTS`] + 2 of them, which
/// [`lotse_core::signaling::OUTGOING_CAPACITY`] holds. One the
/// relay does not take (it is gone, which shows on `incoming`) is counted
/// in the line logged.
fn hand_over(engine: &IngestEngine, channel: &SignalingChannel) {
    let candidates = engine.local_candidates();
    let signals = candidates.len().saturating_add(1);
    let unsent = std::iter::once(LocalSignal::Offer(engine.offer_sdp().to_owned()))
        .chain(candidates.into_iter().map(LocalSignal::Candidate))
        .map(|signal| channel.outgoing.try_send(signal).is_err())
        .filter(|unsent| *unsent)
        .count();
    tracing::debug!(
        signals,
        unsent,
        "webrtc: offer and candidates handed to the relay"
    );
}

/// One connection attempt of a source with `options`.
async fn attempt(options: WebRtcOptions, mut ctx: SourceCtx) -> SourceError {
    let started = ctx.time.now();
    let Some(relay) = ctx.signaling.clone() else {
        return SourceError::Unreachable("webrtc: no signaling relay to the client".into());
    };
    let open = tokio::select! {
        biased;
        () = ctx.cancel.cancelled() => return SourceError::Ended("webrtc: cancelled".into()),
        open = relay.open() => open,
    };
    let channel = match open {
        Ok(channel) => channel,
        Err(refused) => {
            return SourceError::Unreachable(format!("webrtc: signaling refused: {refused}"));
        }
    };
    tracing::debug!(signal = %channel.id, addrs = ?channel.local_addrs, "webrtc: signaling channel open");
    if channel.local_addrs.is_empty() {
        // The supervisor enumerated no host address: the daemon's WebRTC
        // UDP front door is off. No candidate can be gathered, now or on
        // a retry, so no offer is made.
        let reason = "no host address to gather on: the WebRTC UDP front door is off";
        tracing::warn!("webrtc: {reason}");
        channel.close(close::INTERNAL_ERROR, reason.to_owned());
        return SourceError::Unreachable(format!("webrtc: {reason}"));
    }
    let hosts = bind(&preferred(&channel.local_addrs)).await;
    let addrs: Vec<SocketAddr> = hosts.iter().map(|(addr, _)| *addr).collect();
    let mut engine = match IngestEngine::offer(&options, &addrs, started, ctx.time.now()) {
        Ok(engine) => engine,
        Err(reason) => {
            let error = SourceError::Unreachable(format!("webrtc: {reason}"));
            channel.close(close::ICE_FAILED, reason);
            return error;
        }
    };
    // Its losses and refusals in the connection's counters, as the RTSP
    // source counts them.
    engine.count_into(ctx.tracks.ingest());
    hand_over(&engine, &channel);
    let attempt = Attempt {
        engine,
        hosts: Hosts {
            sockets: hosts,
            next: 0,
        },
        rtp: RtpTracks::new(PROTOCOL),
        waiting: None,
        buf: vec![0_u8; RECEIVE_BUFFER],
        dropped: 0,
    };
    Box::pin(run(attempt, channel, &mut ctx)).await
}

/// Runs `attempt` on `channel` until it ends: the offer and the host
/// candidates go out as the relay takes them, meanwhile the deadlines and
/// the signals in keep being served.
async fn run(
    mut attempt: Attempt,
    mut channel: SignalingChannel,
    ctx: &mut SourceCtx,
) -> SourceError {
    loop {
        let wake = match attempt.drain(ctx) {
            Ok(wake) => wake,
            Err(end) => return attempt.finish(channel, end),
        };
        // A new timer each time: str0m's next timeout moves with nearly
        // every datagram, so one kept would rarely be the one due.
        let mut sleeping = ctx
            .time
            .sleep(wake.saturating_duration_since(ctx.time.now()));
        let event = tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => Err(cancelled()),
            signal = channel.incoming.recv() => signal.map(|signal| Some(Woke::Signal(signal))).ok_or_else(client_gone),
            (index, received) = attempt.hosts.recv(&mut attempt.buf) => Ok(Some(Woke::Datagram(index, received))),
            () = &mut sleeping => Ok(None),
        };
        let now = ctx.time.now();
        let end = match event {
            Err(end) => Some(end),
            Ok(None) => {
                attempt.engine.handle_timeout(now);
                None
            }
            Ok(Some(event)) => {
                // The engine's timeout first when it came due meanwhile:
                // I/O that is always ready, or that came with it (an
                // answer, a handshake's last datagram, after their
                // deadline), neither postpones nor replaces a deadline.
                if now >= wake {
                    attempt.engine.handle_timeout(now);
                }
                if attempt.engine.is_ended() {
                    None
                } else {
                    attempt.woke(event, now)
                }
            }
        };
        if let Some(end) = end {
            return attempt.finish(channel, end);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn rfc8445_5_1_1_the_preferred_host_addresses_are_kept_in_their_order() {
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        // The default route's first, whatever it is; then 5 of each class
        // in a mixed order, the global IPv6 ones last and cut.
        let mut listed = vec![ip("2001:db8::1")];
        for n in 1..=5 {
            listed.push(ip(&format!("2001:db8::1:{n}")));
            listed.push(ip(&format!("fd00::{n}")));
            listed.push(ip(&format!("198.51.100.{n}")));
            listed.push(ip(&format!("192.168.1.{n}")));
        }
        let kept = preferred(&listed);
        assert_eq!(kept.len(), MAX_HOSTS);
        let expected: Vec<IpAddr> = listed
            .iter()
            .copied()
            .filter(|ip| *ip == listed[0] || !ip.to_string().starts_with("2001:db8::1:"))
            .collect();
        assert_eq!(kept, expected);
        // Under the bound, all of them, as listed.
        assert_eq!(preferred(&listed[..4]), listed[..4]);
        assert_eq!(rank(0, ip("2001:db8::1")), 0);
        assert_eq!(rank(1, ip("192.168.1.1")), 1);
        assert_eq!(rank(1, ip("198.51.100.1")), 2);
        assert_eq!(rank(1, ip("fd00::1")), 3);
        assert_eq!(rank(1, ip("2001:db8::1")), 4);
    }

    #[tokio::test]
    async fn a_receive_that_failed_or_on_no_socket_reaches_nothing() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local = socket.local_addr().unwrap();
        let now = lotse_core::clock::Clock::now(&lotse_core::clock::SystemClock);
        let options = WebRtcOptions {
            data_channel: None,
            audio: false,
        };
        let mut attempt = Attempt {
            engine: IngestEngine::offer(&options, &[local], now, now).unwrap(),
            hosts: Hosts {
                sockets: vec![(local, socket)],
                next: 0,
            },
            rtp: RtpTracks::new(PROTOCOL),
            waiting: None,
            buf: vec![0_u8; RECEIVE_BUFFER],
            dropped: 0,
        };
        let from: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let failed = Woke::Datagram(0, Err(io::Error::other("refused")));
        assert!(attempt.woke(failed, now).is_none());
        // A datagram on a socket the attempt does not have.
        assert!(
            attempt
                .woke(Woke::Datagram(1, Ok((from, 4))), now)
                .is_none()
        );
        assert_eq!(attempt.engine.stats().bad_datagrams, 0);
        // The same on the one it has is the engine's (and not one it reads).
        assert!(
            attempt
                .woke(Woke::Datagram(0, Ok((from, 4))), now)
                .is_none()
        );
        assert_eq!(attempt.engine.stats().bad_datagrams, 1);
    }

    #[tokio::test]
    async fn the_host_sockets_are_read_in_turn_so_a_busy_one_starves_none() {
        let mut sockets = Vec::new();
        for _ in 0..2 {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            sockets.push((socket.local_addr().unwrap(), socket));
        }
        let (first, second) = (sockets[0].0, sockets[1].0);
        let mut hosts = Hosts { sockets, next: 0 };
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        for n in 0..3_u8 {
            sender.send_to(&[n], first).await.unwrap();
        }
        sender.send_to(&[10], second).await.unwrap();
        let mut buf = vec![0_u8; 16];
        let mut read = Vec::new();
        for _ in 0..4 {
            let (index, received) = hosts.recv(&mut buf).await;
            let (from, len) = received.unwrap();
            assert_eq!(from, sender.local_addr().unwrap());
            read.push((index, buf[..len].to_vec()));
        }
        // The busy first socket in turn with the second, not before it.
        assert_eq!(
            read,
            [(0, vec![0]), (1, vec![10]), (0, vec![1]), (0, vec![2])]
        );
        assert_eq!(hosts.next, 1);
    }
}

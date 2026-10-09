//! RTP over UDP, opt-in per stream (`transport: "udp"`): the relay
//! translates between retina, which keeps speaking TCP interleaved to the
//! loopback relay, and a camera that sends its media as UDP datagrams.
//!
//! retina 0.4's own UDP transport cannot be used behind the relay: it binds
//! its ports on the local address of its connection, which is the
//! relay's `127.0.0.1`, so the camera could never reach them, and its
//! datagrams would bypass the relay's checks below. So the relay rewrites the two messages
//! that carry the transport (RFC 2326 §12.39): retina's `SETUP` asks for
//! `interleaved=N-M`, the camera sees `client_port=P-Q` instead, a fresh
//! RTP/RTCP pair this module bound (RFC 3550 §11: RTP on the even port,
//! RTCP on the next); the camera's answer with `server_port` (and
//! `source`) reaches retina as `interleaved=N-M`. Every datagram that
//! passes then goes to retina as an interleaved frame on that channel
//! (RFC 2326 §10.12), after the answer to `PLAY`, so retina reads the
//! media exactly as it reads a TCP camera's.
//!
//! What passes is decided here, per datagram, without a buffer:
//!
//! - It must come from the camera's media ports: the `source` of the
//!   answer, else the address of the RTSP endpoint the relay connected to
//!   (RFC 2326 §12.39 `source`), and its `server_port` pair if the answer
//!   named one, since the camera receives there and sends from there
//!   (symmetric RTP and RTCP, RFC 4961 §3 and §4; RFC 7826 §18.54
//!   `src_addr`). Without `server_port` RFC 2326 names no port, so any
//!   port of that address passes. Anything else (a stray or spoofed
//!   sender on the LAN) is refused and counted: no port is latched on
//!   (RFC 7362), and a named `source` that stays silent is not replaced
//!   by the endpoint. A `source` no camera can send from ends the attempt
//!   before anything is sent there ([`refused_source`]): another family
//!   than the endpoint's, or one RFC 1122 §3.2.1.3 rules out as the
//!   source of a datagram from another host, loopback among them, so a
//!   camera elsewhere cannot have the relay take media from, and send
//!   reports to, whatever listens on this host.
//! - An RTP datagram must carry a version 2 header (RFC 3550 §5.1) from the
//!   synchronization source the first one carried; an RTCP datagram a
//!   version 2 header (RFC 3550 §6.4).
//! - A duplicate, or a packet up to [`MAX_MISORDER`] behind the highest
//!   sequence number passed (RFC 3550 §A.1), is dropped and counted as out
//!   of order: retina, reading TCP, ends the session on a backward step,
//!   and waiting for a reordered packet would be a reorder buffer. Its gap
//!   was counted as loss when the later packet passed. A larger step back
//!   is a new sequence, passed for retina to judge as over TCP.
//!
//! The pairs listen on the wildcard address of the camera's family, so the
//! kernel answers on whichever interface the camera reaches; the address
//! check above, not the bind, says who may send. retina keeps the control
//! connection alive (`GET_PARAMETER` or `OPTIONS` at half the session
//! timeout) and sends one `TEARDOWN` on it at the end, both through the
//! relay unchanged. Once the camera's connection is gone while the
//! session is not over, the relay frames retina's `TEARDOWN` from what it
//! writes and the camera's answer on a fresh connection
//! ([`UdpRelay::orphaned_request`], [`UdpRelay::fresh_answer`]).
//!
//! The relay reports to the camera, which retina does not
//! ([`crate::rtcp`]): every datagram from the camera's media ports with a
//! valid header counts, the ones dropped as out of order too, since they
//! were received (RFC 3550 §6.4.1), and each stream's Receiver Reports go
//! from its RTCP port to the camera's, the answer's `server_port` pair
//! or, without one, the port the camera's RTCP came from.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use lotse_core::clock::Clock;
use lotse_core::ingest::IngestCounters;
use lotse_core::source::SourceError;
use lotse_core::throttle::Throttle;
use retina::rtsp::msg::{Headers, Message, Response};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::error::camera_text;
use crate::framer::{Framed, Framer};
use crate::rtcp::{HEAD, ReceiverReports, Report};
use crate::tap::interleaved as answered_channel;

/// RFC 3550 §A.1 `MAX_MISORDER`: a packet at most this many sequence
/// numbers behind the highest one is reordered (or a duplicate at 0), not
/// a new sequence.
const MAX_MISORDER: u16 = 100;

/// The most datagrams held between the camera's first datagram and the
/// answer to `PLAY`, which retina must read before any media: 256, a
/// keyframe's worth at camera bitrates. More are refused and counted.
const MAX_QUEUED: usize = 256;

/// The most bytes those datagrams take as interleaved frames: 2 MiB,
/// 256 frames of 8 KiB, so the count above stays the bound for any
/// camera that keeps its datagrams near the path MTU, while 256 of the
/// largest datagrams can no longer hold 16 MiB. More are refused and
/// counted.
const MAX_QUEUED_BYTES: usize = 2_097_152;

/// The receive buffer: the largest UDP payload there is, so a datagram is
/// never cut, and its length always fits the interleaved frame's 16 bits
/// (RFC 2326 §10.12).
pub(crate) const MAX_DATAGRAM: usize = 65_535;

/// An RTP header with nothing to say (version 2, payload type 0,
/// synchronization source 0), sent once to the camera's RTP port so a
/// connection-tracking firewall between lets its datagrams back in; the
/// camera discards it. retina 0.4 sends the same.
const HOLE_PUNCH_RTP: [u8; 12] = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// An empty RTCP Receiver Report (RFC 3550 §6.4.2, packet type 201) for
/// the camera's RTCP port, for the same reason.
const HOLE_PUNCH_RTCP: [u8; 8] = [0x80, 201, 0, 1, 0, 0, 0, 0];

/// Candidates tried for one RTP/RTCP pair before the attempt fails.
const PAIR_TRIES: usize = 16;

/// The wildcard address of `camera`'s family, where the pairs listen.
const fn wildcard(camera: IpAddr) -> IpAddr {
    match camera {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// An RTP/RTCP port pair on `ip` (RFC 3550 §11): RTP on an even port,
/// RTCP on the next one. The first socket takes an ephemeral port and its
/// neighbor completes the pair; a neighbor in use (another camera's pair,
/// a viewer's ICE socket, another process on a busy host) moves the pair
/// to another ephemeral port, up to [`PAIR_TRIES`] times, as other RTSP
/// clients do (observed 2026-10-07: retina 0.4.21 `UdpPair::for_ip` tries
/// 10 random even ports in 5000..65000, ffmpeg's `libavformat/rtsp.c`
/// walks the even ports of `min_port`..`max_port` from a random offset).
fn bind_pair(ip: IpAddr) -> io::Result<(StdUdpSocket, StdUdpSocket)> {
    pair_among(|| StdUdpSocket::bind((ip, 0)))
}

/// A pair around the first of up to [`PAIR_TRIES`] sockets `candidate`
/// binds whose neighbor is free. A candidate whose neighbor is taken
/// stays bound until the end, so the next one is a new port; the last
/// candidate's error, or `candidate`'s own, fails the pair.
fn pair_among(
    mut candidate: impl FnMut() -> io::Result<StdUdpSocket>,
) -> io::Result<(StdUdpSocket, StdUdpSocket)> {
    let mut taken = Vec::new();
    while taken.len() < PAIR_TRIES.saturating_sub(1) {
        let first = candidate()?;
        let port = first.local_addr()?.port();
        match neighbor_of(&first) {
            Ok(neighbor) => return ordered(first, neighbor),
            Err(err) => {
                taken.push(first);
                tracing::debug!(
                    port,
                    tries = taken.len(),
                    error = %err,
                    "rtsp udp: the port pair's other half is taken; trying another pair"
                );
            }
        }
    }
    let first = candidate()?;
    let neighbor = neighbor_of(&first)?;
    ordered(first, neighbor)
}

/// Binds the port that completes `first`'s pair, the one that differs in
/// the lowest bit. Ephemeral ports start above 1023, so it is never port
/// 0.
fn neighbor_of(first: &StdUdpSocket) -> io::Result<StdUdpSocket> {
    let local = first.local_addr()?;
    StdUdpSocket::bind(SocketAddr::new(local.ip(), local.port() ^ 1))
}

/// `first` and its `neighbor` as a pair, the even port (RTP) first.
fn ordered(
    first: StdUdpSocket,
    neighbor: StdUdpSocket,
) -> io::Result<(StdUdpSocket, StdUdpSocket)> {
    Ok(if first.local_addr()?.port() & 1 == 0 {
        (first, neighbor)
    } else {
        (neighbor, first)
    })
}

/// A non-blocking pair, ready for the runtime, with its RTP port.
fn listening_pair(ip: IpAddr) -> io::Result<(StdUdpSocket, StdUdpSocket, u16)> {
    let (media, control) = bind_pair(ip)?;
    let port = media.local_addr()?.port();
    media.set_nonblocking(true)?;
    control.set_nonblocking(true)?;
    Ok((media, control, port))
}

/// Sends one empty packet from the RTP and the RTCP socket to the
/// camera's ports at `source`, for firewalls that track connections;
/// without named ports there is nowhere to send. Sent before the sockets
/// join the runtime, whose `try_send_to` would see no write readiness
/// yet.
fn punch(sockets: [&StdUdpSocket; 2], source: IpAddr, ports: Option<(u16, u16)>) {
    let Some((media_port, control_port)) = ports else {
        return;
    };
    let [media, control] = sockets;
    let sends = [
        (media, media_port, &HOLE_PUNCH_RTP[..]),
        (control, control_port, &HOLE_PUNCH_RTCP[..]),
    ];
    for (socket, port, packet) in sends {
        if let Err(err) = socket.send_to(packet, SocketAddr::new(source, port)) {
            tracing::debug!(error = %err, port, "rtsp udp: firewall hole punch not sent");
        }
    }
}

/// No pair could be bound: the attempt fails like an unreachable camera
/// and backs off.
fn no_pair(err: &io::Error) -> SourceError {
    SourceError::Unreachable(format!(
        "rtsp udp: no RTP/RTCP port pair to receive on: {err}"
    ))
}

/// Receiving on a pair failed: the attempt ends.
pub(crate) fn receive_failed(err: &io::Error) -> SourceError {
    SourceError::Ended(format!("rtsp udp: receiving media failed: {err}"))
}

/// The parameters of a `Transport` header (RFC 2326 §12.39), trimmed.
fn params(transport: &str) -> impl Iterator<Item = &str> {
    transport.split(';').map(str::trim)
}

/// The first channel of the `interleaved` pair in retina's `SETUP`
/// (RFC 2326 §12.39); retina always names one, so a missing one reads as 0.
fn interleaved_channel(transport: &str) -> u8 {
    params(transport)
        .find_map(|param| param.strip_prefix("interleaved="))
        .and_then(|range| range.split('-').next())
        .and_then(|first| first.trim().parse().ok())
        .unwrap_or_default()
}

/// What a camera's `SETUP` answer says about the way its media takes
/// (RFC 2326 §12.39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Over UDP, from `source` (`None`: the camera's own address) and its
    /// `server_port` pair, RTP first (`None`: not named).
    Udp {
        /// The `source` parameter.
        source: Option<IpAddr>,
        /// The `server_port` parameter's RTP port.
        server_port: Option<u16>,
    },
    /// The camera chose TCP interleaved after all.
    Interleaved,
}

/// Reads a camera's `SETUP` answer; an error for a `source` that is not an
/// address or a `server_port` that is not a port pair.
fn parse_answer(transport: &str) -> Result<Answer, String> {
    let mut source = None;
    let mut server_port = None;
    for param in params(transport) {
        if param.starts_with("interleaved=") {
            return Ok(Answer::Interleaved);
        }
        if let Some(value) = param.strip_prefix("source=") {
            let address = value.trim().parse::<IpAddr>();
            source = Some(address.map_err(|_| format!("source {value:?} is not an address"))?);
        } else if let Some(value) = param.strip_prefix("server_port=") {
            server_port = Some(server_port_of(value)?);
        }
    }
    Ok(Answer::Udp {
        source,
        server_port,
    })
}

/// Why the `named` source of a `SETUP` answer is refused for the camera
/// whose RTSP endpoint is `endpoint`; `None` when its media may come
/// from there. Both are compared as what they are, an IPv4-mapped
/// address as IPv4 (RFC 4291 §2.5.5.2).
///
/// SPEC-DEVIATION: RFC 2326 §12.39 lets the camera name any address.
/// The relay's pair listens on the endpoint's family only, so a source
/// of the other family could never be heard; and RFC 1122 §3.2.1.3 lets
/// no host send from an unspecified, broadcast or multicast address, nor
/// a loopback address appear outside its host, so a camera elsewhere
/// that names one either errs or points the relay's punches, reports and
/// accepted media at this host's own services. Another host of the
/// endpoint's family is taken at its word, a link-local one included
/// (RFC 3927): the camera could send its media from there anyway.
fn refused_source(named: IpAddr, endpoint: IpAddr) -> Option<&'static str> {
    let (named, endpoint) = (named.to_canonical(), endpoint.to_canonical());
    if named.is_ipv4() != endpoint.is_ipv4() {
        Some("of another address family than the camera's RTSP endpoint")
    } else if named.is_unspecified() {
        Some("unspecified")
    } else if named.is_multicast() {
        Some("multicast")
    } else if matches!(named, IpAddr::V4(v4) if v4.is_broadcast()) {
        Some("the broadcast address")
    } else if named.is_loopback() && !endpoint.is_loopback() {
        Some("loopback while the camera's RTSP endpoint is not")
    } else {
        None
    }
}

/// The RTP port of a `server_port` value: `P-Q` with `Q = P + 1`, or `P`
/// alone, RTCP then on the next port (RFC 3550 §11).
fn server_port_of(value: &str) -> Result<u16, String> {
    let bad = || format!("server_port {value:?} is not an RTP/RTCP port pair");
    let mut ports = value.split('-').map(|port| port.trim().parse::<u16>().ok());
    let first = ports.next().flatten().ok_or_else(bad)?;
    let next = first.checked_add(1).ok_or_else(bad)?;
    match (ports.next(), ports.next()) {
        (None, _) => Ok(first),
        (Some(Some(given)), None) if given == next => Ok(first),
        _ => Err(bad()),
    }
}

/// `raw`, a whole message whose last `body_len` bytes are its body, with
/// every `name` header line replaced by `name: value`; everything else
/// stays byte for byte.
fn with_header(raw: &[u8], body_len: usize, name: &str, value: &str) -> Vec<u8> {
    let (head, body) = raw
        .split_at_checked(raw.len().saturating_sub(body_len))
        .unwrap_or((raw, &[]));
    let mut out = Vec::with_capacity(raw.len().saturating_add(value.len()));
    for line in head.split_inclusive(|&b| b == b'\n') {
        let named = line
            .iter()
            .position(|&b| b == b':')
            .and_then(|colon| line.get(..colon))
            .is_some_and(|key| key.trim_ascii().eq_ignore_ascii_case(name.as_bytes()));
        if named {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        } else {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(body);
    out
}

/// A message's `CSeq` (RFC 2326 §12.17), trimmed.
fn cseq(headers: &Headers) -> Option<String> {
    headers.get("CSeq").map(|value| value.trim().to_owned())
}

/// What becomes of one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// On to retina.
    Pass,
    /// Refused before it was read, and why.
    Rejected(&'static str),
    /// A duplicate, or later than a packet that passed.
    OutOfOrder,
}

/// The order check on one pair's RTP datagrams.
#[derive(Debug, Default)]
struct Gate {
    /// The synchronization source of the first packet that passed.
    ssrc: Option<u32>,
    /// The highest sequence number passed.
    highest: Option<u16>,
}

impl Gate {
    /// Judges one RTP datagram (RFC 3550 §5.1) and, passed, remembers it.
    fn rtp(&mut self, datagram: &[u8]) -> Verdict {
        let header = (
            datagram.first(),
            datagram.get(2..4).and_then(|b| <[u8; 2]>::try_from(b).ok()),
            datagram
                .get(8..12)
                .and_then(|b| <[u8; 4]>::try_from(b).ok()),
        );
        let (Some(&first), Some(seq), Some(ssrc)) = header else {
            return Verdict::Rejected("shorter than an RTP header");
        };
        if first >> 6 != 2 {
            return Verdict::Rejected("not RTP version 2");
        }
        let (seq, ssrc) = (u16::from_be_bytes(seq), u32::from_be_bytes(ssrc));
        if self.ssrc.is_some_and(|locked| locked != ssrc) {
            return Verdict::Rejected("from another synchronization source");
        }
        if self
            .highest
            .is_some_and(|highest| highest.wrapping_sub(seq) < MAX_MISORDER)
        {
            return Verdict::OutOfOrder;
        }
        self.ssrc = Some(ssrc);
        self.highest = Some(seq);
        Verdict::Pass
    }
}

/// Whether `datagram` starts with an RTCP version 2 header (RFC 3550
/// §6.4): four bytes, the version in the top two bits.
fn rtcp_header(datagram: &[u8]) -> bool {
    datagram.len() >= 4 && datagram.first().is_some_and(|first| first >> 6 == 2)
}

/// One stream's media pair, answered by the camera.
#[derive(Debug)]
struct Pair {
    /// retina's RTP channel; RTCP is on the next one.
    channel: u8,
    /// Receives RTP.
    rtp: UdpSocket,
    /// Receives RTCP.
    rtcp: UdpSocket,
    /// Where the camera sends from: the answer's `source`, else the RTSP
    /// endpoint's address (RFC 2326 §12.39), never another; never one
    /// [`refused_source`] refuses.
    source: IpAddr,
    /// The camera's RTP and RTCP ports, when its answer named them: where
    /// it receives and, symmetric (RFC 4961 §3), sends from.
    ports: Option<(u16, u16)>,
    /// The order check on the RTP datagrams.
    gate: Gate,
    /// Where the camera's last RTCP came from: where the reports go when
    /// its answer named no ports, the port it receives RTCP on if its RTCP
    /// is symmetric (RFC 4961 §3).
    rtcp_from: Option<SocketAddr>,
}

impl Pair {
    /// Whether a datagram from `from` on the RTP (or RTCP) socket comes
    /// from the camera's media port.
    fn accepts(&self, from: SocketAddr, rtcp: bool) -> bool {
        from.ip() == self.source
            && self.ports.is_none_or(|(media_port, control_port)| {
                from.port() == if rtcp { control_port } else { media_port }
            })
    }
}

/// A `SETUP` the camera has not answered yet, with the pair it offers.
#[derive(Debug)]
struct PendingSetup {
    /// The request's `CSeq`.
    cseq: Option<String>,
    /// retina's RTP channel.
    channel: u8,
    /// The pair's RTP socket.
    rtp: StdUdpSocket,
    /// The pair's RTCP socket.
    rtcp: StdUdpSocket,
    /// The pair's RTP port, as the request names it.
    client_port: u16,
}

/// A datagram one of the pairs received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Received {
    /// Which pair.
    pair: usize,
    /// On its RTCP socket.
    rtcp: bool,
    /// The sender.
    from: SocketAddr,
    /// Its length in the buffer.
    pub(crate) len: usize,
}

/// The relay's UDP side for one connection attempt: the translation of
/// both directions' RTSP and the media pairs.
#[derive(Debug)]
pub(crate) struct UdpRelay {
    /// The camera's address: where its media comes from unless its answer
    /// names a `source`.
    camera: IpAddr,
    /// retina's requests.
    retina: Framer,
    /// The camera's responses.
    from_camera: Framer,
    /// The `SETUP` waiting for its answer.
    setup: Option<PendingSetup>,
    /// The `CSeq` of the `PLAY` waiting for its answer.
    play: Option<String>,
    /// The answer to `PLAY` went to retina: datagrams go straight on.
    playing: bool,
    /// retina sent its `TEARDOWN` (RFC 2326 §10.7): the session is over,
    /// and the camera may close.
    teardown: bool,
    /// The answered pairs, by index.
    pairs: Vec<Pair>,
    /// Interleaved frames of datagrams that came before the `PLAY` answer,
    /// at most [`MAX_QUEUED`].
    queued: Vec<Vec<u8>>,
    /// The bytes `queued` holds, at most [`MAX_QUEUED_BYTES`].
    queued_bytes: usize,
    /// Where losses and refusals are counted.
    ingest: Arc<IngestCounters>,
    /// The time, for the log's rate limits.
    clock: Arc<dyn Clock>,
    /// The rate limit of the refused-datagram warning.
    rejected: Throttle,
    /// The rate limit of the out-of-order line.
    reordered: Throttle,
    /// The rate limit of the line about interleaved media on a UDP stream.
    stray: Throttle,
    /// The receiver reports.
    reports: ReceiverReports,
    /// The rate limit of the line about a report not sent.
    unsent: Throttle,
}

impl UdpRelay {
    /// The UDP side of an attempt to the camera at `camera`, counting into
    /// `ingest`.
    /// `reports` keeps the receiver reports.
    pub(crate) fn new(
        camera: IpAddr,
        ingest: Arc<IngestCounters>,
        clock: Arc<dyn Clock>,
        reports: ReceiverReports,
    ) -> Self {
        Self {
            camera,
            retina: Framer::default(),
            from_camera: Framer::default(),
            setup: None,
            play: None,
            playing: false,
            teardown: false,
            pairs: Vec::new(),
            queued: Vec::new(),
            queued_bytes: 0,
            ingest,
            clock,
            rejected: Throttle::default(),
            reordered: Throttle::default(),
            stray: Throttle::default(),
            reports,
            unsent: Throttle::default(),
        }
    }

    /// The time the relay keeps.
    pub(crate) fn clock(&self) -> &dyn Clock {
        &*self.clock
    }

    /// When the next receiver report is due.
    pub(crate) fn report_due(&self) -> Option<Instant> {
        self.reports.due()
    }

    /// Sends the receiver reports due now: from the RTCP port of a stream
    /// over UDP, appended to `out` as interleaved frames for the camera's
    /// connection for a stream it answered with TCP interleaved.
    pub(crate) async fn report(&mut self, out: &mut Vec<u8>) {
        for report in self.reports.take_due(self.clock.now()) {
            let Some(pair) = self
                .pairs
                .iter()
                .find(|pair| pair.channel == report.channel)
            else {
                report.interleave(out);
                continue;
            };
            let to = pair
                .ports
                .map(|(_, control_port)| SocketAddr::new(pair.source, control_port))
                .or(pair.rtcp_from);
            // A datagram socket seldom waits; `try_send_to` would fail
            // until the runtime saw the socket writable once.
            let sent = match to {
                Some(to) => Some((to, pair.rtcp.send_to(&report.packet, to).await)),
                None => None,
            };
            Self::sent(&mut self.unsent, &*self.clock, &report, sent);
        }
    }

    /// Logs a report that did not leave, rate-limited.
    fn sent(
        unsent: &mut Throttle,
        clock: &dyn Clock,
        report: &Report,
        sent: Option<(SocketAddr, io::Result<usize>)>,
    ) {
        let why = match sent {
            Some((_, Ok(_))) => return,
            Some((to, Err(err))) => format!("sending to {to} failed: {err}"),
            None => "the camera named no RTCP port and sent no RTCP yet".to_owned(),
        };
        if let Some(count) = unsent.hit(clock.now()) {
            tracing::debug!(
                channel = report.channel,
                count,
                reason = why,
                "rtsp udp: receiver report not sent"
            );
        }
    }

    /// Takes bytes retina wrote and appends to `out` what goes to the
    /// camera: its requests as they are, a `SETUP` asking for UDP instead
    /// of its interleaved channels.
    pub(crate) fn retina_wrote(
        &mut self,
        bytes: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SourceError> {
        self.retina.pending.extend_from_slice(bytes);
        while let Some(framed) = self.retina.next().map_err(|why| {
            SourceError::Protocol(format!("rtsp udp: retina's request is unreadable: {why}"))
        })? {
            let Framed {
                head,
                raw,
                body_len,
            } = framed;
            match head {
                Message::Request(request) if &*request.method == "SETUP" => {
                    self.ask_udp(&request.headers, &raw, body_len, out)?;
                }
                Message::Request(request) => {
                    match &*request.method {
                        "PLAY" => self.play = cseq(&request.headers),
                        "TEARDOWN" => self.teardown = true,
                        _ => {}
                    }
                    out.extend_from_slice(&raw);
                }
                Message::Response(_) | Message::Data(_) => out.extend_from_slice(&raw),
            }
        }
        Ok(())
    }

    /// Binds a pair for retina's `SETUP` and appends the request to `out`
    /// with `client_port` naming it in place of the interleaved channels.
    fn ask_udp(
        &mut self,
        headers: &Headers,
        raw: &[u8],
        body_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), SourceError> {
        let channel = interleaved_channel(headers.get("Transport").map_or("", |value| value));
        let (media, control, client_port) =
            listening_pair(wildcard(self.camera)).map_err(|err| no_pair(&err))?;
        let transport = format!(
            "RTP/AVP/UDP;unicast;client_port={client_port}-{}",
            client_port | 1
        );
        out.extend_from_slice(&with_header(raw, body_len, "Transport", &transport));
        tracing::debug!(
            channel,
            client_port,
            "rtsp udp: SETUP asks for RTP over UDP"
        );
        self.setup = Some(PendingSetup {
            cseq: cseq(headers),
            channel,
            rtp: media,
            rtcp: control,
            client_port,
        });
        Ok(())
    }

    /// Takes bytes the camera sent and appends to `out` what goes to
    /// retina: whole messages, the answers to `SETUP` translated back.
    pub(crate) fn camera_sent(
        &mut self,
        bytes: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SourceError> {
        self.from_camera.pending.extend_from_slice(bytes);
        while let Some(framed) = self.from_camera.next().map_err(|why| {
            tracing::warn!(error = %why, "rtsp udp: unreadable RTSP from the camera; refused");
            SourceError::Protocol(format!("the camera's RTSP is unreadable: {why}"))
        })? {
            match &framed.head {
                Message::Response(response) => self.response(response, &framed, out)?,
                Message::Data(data) if self.carries(data.channel_id) => {
                    if let Some(count) = self.stray.hit(self.clock.now()) {
                        tracing::debug!(
                            channel = data.channel_id,
                            count,
                            "rtsp udp: interleaved media on a UDP stream's channel dropped"
                        );
                    }
                }
                Message::Data(data) => {
                    let body = framed.body();
                    let head = body.get(..HEAD).unwrap_or(body);
                    self.reports.packet(data.channel_id, head, self.clock.now());
                    out.extend_from_slice(&framed.raw);
                }
                Message::Request(_) => out.extend_from_slice(&framed.raw),
            }
        }
        Ok(())
    }

    /// Whether retina sent its `TEARDOWN`: the session is over, and the
    /// camera closing its connection is expected.
    pub(crate) const fn tearing_down(&self) -> bool {
        self.teardown
    }

    /// Takes bytes retina wrote once the camera's connection is gone and
    /// returns its `TEARDOWN` request, as retina wrote it, once whole
    /// (RFC 2326 §10.7). retina's other messages are dropped: nothing
    /// answers them now. The camera's framer starts over, for the answer
    /// on a fresh connection.
    pub(crate) fn orphaned_request(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, SourceError> {
        self.retina.pending.extend_from_slice(bytes);
        while let Some(framed) = self.retina.next().map_err(|why| {
            SourceError::Protocol(format!("rtsp udp: retina's request is unreadable: {why}"))
        })? {
            match &framed.head {
                Message::Request(request) if &*request.method == "TEARDOWN" => {
                    self.teardown = true;
                    self.from_camera = Framer::default();
                    return Ok(Some(framed.raw));
                }
                _ => tracing::debug!(
                    "rtsp udp: retina's message dropped; the camera's connection is gone"
                ),
            }
        }
        Ok(None)
    }

    /// Takes bytes the camera sent on a fresh connection after an
    /// [`Self::orphaned_request`] and returns its answer, whole, once it is
    /// there; anything else it sends is dropped.
    pub(crate) fn fresh_answer(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, SourceError> {
        self.from_camera.pending.extend_from_slice(bytes);
        while let Some(framed) = self.from_camera.next().map_err(|why| {
            SourceError::Protocol(format!("the camera's RTSP is unreadable: {why}"))
        })? {
            if let Message::Response(_) = &framed.head {
                return Ok(Some(framed.raw));
            }
        }
        Ok(None)
    }

    /// Whether `channel` belongs to a stream whose media comes over UDP.
    fn carries(&self, channel: u8) -> bool {
        self.pairs.iter().any(|pair| pair.channel == channel & !1)
    }

    /// One whole response from the camera, appended to `out`.
    fn response(
        &mut self,
        response: &Response,
        framed: &Framed,
        out: &mut Vec<u8>,
    ) -> Result<(), SourceError> {
        let cseq = cseq(&response.headers);
        if let Some(setup) = self.setup.take_if(|setup| setup.cseq == cseq) {
            return self.answer(setup, response, framed, out);
        }
        out.extend_from_slice(&framed.raw);
        if cseq.is_some() && self.play == cseq && response.status_code.is_success() {
            self.play = None;
            self.playing = true;
            tracing::debug!(
                streams = self.pairs.len(),
                queued = self.queued.len(),
                "rtsp udp: PLAY answered; media goes on to retina"
            );
            for frame in self.queued.drain(..) {
                out.extend_from_slice(&frame);
            }
            self.queued_bytes = 0;
        }
        Ok(())
    }

    /// The camera's answer to a `SETUP` this relay asked UDP for: refused,
    /// passed on as it is and the pair released; over UDP, the pair kept
    /// for the answer's ports and the answer passed on with retina's
    /// interleaved channels; interleaved after all, passed on as it is.
    fn answer(
        &mut self,
        setup: PendingSetup,
        response: &Response,
        framed: &Framed,
        out: &mut Vec<u8>,
    ) -> Result<(), SourceError> {
        let channel = setup.channel;
        if !response.status_code.is_success() {
            tracing::debug!(
                status = response.status_code.as_u16(),
                channel,
                "rtsp udp: SETUP refused; its port pair released"
            );
            out.extend_from_slice(&framed.raw);
            return Ok(());
        }
        let transport = response.headers.get("Transport").map_or("", |value| value);
        let (source, server_port) = match parse_answer(transport) {
            Ok(Answer::Udp {
                source,
                server_port,
            }) => (source, server_port),
            Ok(Answer::Interleaved) => {
                tracing::info!(
                    channel,
                    "rtsp udp: the camera answered with TCP interleaved; this stream's media comes over TCP"
                );
                if let Some(answered) = answered_channel(transport) {
                    self.reports.set_up(answered);
                }
                out.extend_from_slice(&framed.raw);
                return Ok(());
            }
            Err(why) => {
                let (transport, why) = (camera_text(transport), camera_text(&why));
                tracing::warn!(transport, error = %why, "rtsp udp: unreadable SETUP answer; refused");
                return Err(SourceError::Protocol(format!(
                    "the camera's SETUP answer has the Transport {transport:?}: {why} (RFC 2326 §12.39)"
                )));
            }
        };
        let source = match source {
            Some(named) => match refused_source(named, self.camera) {
                Some(why) => {
                    tracing::warn!(
                        channel,
                        source = %named,
                        endpoint = %self.camera,
                        reason = why,
                        "rtsp udp: SETUP answer names a source no camera can send from; refused"
                    );
                    return Err(SourceError::Protocol(format!(
                        "the camera's SETUP answer names the source {named}, which is {why} \
                         (RFC 2326 §12.39, RFC 1122 §3.2.1.3)"
                    )));
                }
                None => named,
            },
            None => self.camera,
        };
        let ports = server_port.map(|port| (port, port.saturating_add(1)));
        tracing::info!(
            channel,
            client_port = setup.client_port,
            %source,
            endpoint = %self.camera,
            server_port,
            "rtsp udp: media over UDP"
        );
        punch([&setup.rtp, &setup.rtcp], source, ports);
        let pair = Pair {
            channel,
            rtp: UdpSocket::from_std(setup.rtp).map_err(|err| no_pair(&err))?,
            rtcp: UdpSocket::from_std(setup.rtcp).map_err(|err| no_pair(&err))?,
            source,
            ports,
            gate: Gate::default(),
            rtcp_from: None,
        };
        self.reports.set_up(channel);
        let interleaved = format!("RTP/AVP/TCP;unicast;interleaved={channel}-{}", channel | 1);
        out.extend_from_slice(&with_header(
            &framed.raw,
            framed.body_len,
            "Transport",
            &interleaved,
        ));
        self.pairs.push(pair);
        Ok(())
    }

    /// The next datagram on any pair into `buf`, the pairs polled from
    /// `start` round so none starves; pending while there is none.
    pub(crate) async fn recv(&self, start: usize, buf: &mut [u8]) -> io::Result<Received> {
        std::future::poll_fn(|cx| {
            let count = self.pairs.len();
            let first = start.checked_rem(count).unwrap_or(0);
            let round = self
                .pairs
                .iter()
                .enumerate()
                .cycle()
                .skip(first)
                .take(count);
            for (index, pair) in round {
                for (rtcp, socket) in [(false, &pair.rtp), (true, &pair.rtcp)] {
                    let mut read = ReadBuf::new(&mut *buf);
                    if let Poll::Ready(received) = socket.poll_recv_from(cx, &mut read) {
                        let len = read.filled().len();
                        return Poll::Ready(received.map(|from| Received {
                            pair: index,
                            rtcp,
                            from,
                            len,
                        }));
                    }
                }
            }
            Poll::Pending
        })
        .await
    }

    /// One datagram a pair received: refused, dropped as out of order, or
    /// appended to `out` as an interleaved frame on the pair's channel
    /// (held until `PLAY` is answered).
    pub(crate) fn datagram(&mut self, received: Received, payload: &[u8], out: &mut Vec<u8>) {
        let Some(pair) = self.pairs.get_mut(received.pair) else {
            return;
        };
        let channel = pair.channel | u8::from(received.rtcp);
        let verdict = if !pair.accepts(received.from, received.rtcp) {
            Verdict::Rejected("not from the camera's media port")
        } else if !received.rtcp {
            pair.gate.rtp(payload)
        } else if rtcp_header(payload) {
            Verdict::Pass
        } else {
            Verdict::Rejected("not RTCP version 2")
        };
        if matches!(verdict, Verdict::Pass | Verdict::OutOfOrder) {
            if received.rtcp {
                pair.rtcp_from = Some(received.from);
            }
            let head = payload.get(..HEAD).unwrap_or(payload);
            self.reports.packet(channel, head, self.clock.now());
        }
        let frame_len = payload.len().saturating_add(4);
        let held = !self.playing
            && (self.queued.len() >= MAX_QUEUED
                || self.queued_bytes.saturating_add(frame_len) > MAX_QUEUED_BYTES);
        let verdict = match verdict {
            Verdict::Pass if held => Verdict::Rejected("more than the queue holds before PLAY"),
            other => other,
        };
        match verdict {
            Verdict::Pass => {}
            Verdict::Rejected(reason) => {
                self.ingest.count_rejected();
                if let Some(count) = self.rejected.hit(self.clock.now()) {
                    tracing::warn!(
                        from = %received.from,
                        channel,
                        reason,
                        count,
                        "rtsp udp: datagram refused"
                    );
                }
                return;
            }
            Verdict::OutOfOrder => {
                self.ingest.count_out_of_order();
                if let Some(count) = self.reordered.hit(self.clock.now()) {
                    tracing::debug!(
                        channel,
                        count,
                        "rtsp udp: duplicate or reordered RTP packet dropped"
                    );
                }
                return;
            }
        }
        let len = u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes();
        let mut frame = Vec::with_capacity(frame_len);
        frame.extend_from_slice(&[b'$', channel]);
        frame.extend_from_slice(&len);
        frame.extend_from_slice(payload);
        if self.playing {
            out.append(&mut frame);
        } else {
            self.queued_bytes = self.queued_bytes.saturating_add(frame.len());
            self.queued.push(frame);
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

    use std::time::Duration;

    use lotse_core::clock::SystemClock;

    use super::*;

    const SETUP: &[u8] = b"SETUP rtsp://127.0.0.1:41000/stream/track0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\nUser-Agent: lotse\r\n\r\n";
    const PLAY: &[u8] =
        b"PLAY rtsp://127.0.0.1:41000/stream/ RTSP/1.0\r\nCSeq: 4\r\nSession: 1\r\n\r\n";
    const DESCRIBED: &[u8] =
        b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: 5\r\n\r\nv=0\r\n";

    /// Every log line's fields are evaluated, as in production at
    /// `trace`; the lines go nowhere.
    fn traced() {
        let _installed = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(io::sink)
            .try_init();
    }

    fn new_relay() -> (UdpRelay, Arc<IngestCounters>) {
        relay_for(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    /// A relay for the camera whose RTSP endpoint is `camera`.
    fn relay_for(camera: IpAddr) -> (UdpRelay, Arc<IngestCounters>) {
        traced();
        let ingest = Arc::new(IngestCounters::default());
        let relay = UdpRelay::new(
            camera,
            Arc::clone(&ingest),
            Arc::new(SystemClock),
            ReceiverReports::new(Arc::default(), crate::rtcp::Seed::random()),
        );
        (relay, ingest)
    }

    /// The `client_port` the request in `out` names.
    fn client_port(out: &[u8]) -> u16 {
        let text = String::from_utf8_lossy(out);
        let at = text.find("client_port=").unwrap() + "client_port=".len();
        text[at..].split('-').next().unwrap().parse().unwrap()
    }

    fn answer(transport: &str) -> Vec<u8> {
        format!(
            "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 1;timeout=60\r\nTransport: {transport}\r\n\r\n"
        )
        .into_bytes()
    }

    fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 96];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 1]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.push(0xaa);
        packet
    }

    /// A relay past DESCRIBE with one stream set up over UDP from the
    /// camera's `server` socket: the relay and the client port.
    fn set_up(server: &UdpSocket) -> (UdpRelay, Arc<IngestCounters>) {
        let (mut relay, ingest) = new_relay();
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        out.clear();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        let port = client_port(&out);
        let server_port = server.local_addr().unwrap().port();
        out.clear();
        let transport = format!(
            "RTP/AVP/UDP;unicast;client_port={port}-{};server_port={server_port}-{};ssrc=1",
            port + 1,
            server_port + 1
        );
        relay.camera_sent(&answer(&transport), &mut out).unwrap();
        (relay, ingest)
    }

    /// The next datagram the relay's pairs receive, bounded.
    async fn next(relay: &UdpRelay, buf: &mut [u8]) -> Received {
        tokio::select! {
            received = relay.recv(0, buf) => received.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no datagram within 5 s"),
        }
    }

    #[test]
    fn rfc3550_11_pairs_put_rtp_on_the_even_port_and_rtcp_on_the_next() {
        // Ephemeral ports come both ways; every pair is even, then odd.
        let (mut even, mut odd) = (false, false);
        // A neighbor another test holds leaves that try out.
        let pairs = (0..200).filter_map(|_| {
            let first = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = first.local_addr().unwrap().port();
            let neighbor = neighbor_of(&first).ok()?;
            Some((port, ordered(first, neighbor).unwrap()))
        });
        for (port, (media, control)) in pairs {
            let (even_port, odd_port) = (
                media.local_addr().unwrap().port(),
                control.local_addr().unwrap().port(),
            );
            assert_eq!((even_port % 2, odd_port), (0, even_port + 1));
            assert!(port == even_port || port == odd_port);
            even |= port.is_multiple_of(2);
            odd |= port % 2 == 1;
        }
        assert!(even && odd);
        let (rtp, _rtcp) = bind_pair(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert!(rtp.local_addr().unwrap().ip().is_loopback());
        // A neighbor in use fails the pair.
        let first = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = first.local_addr().unwrap().port();
        // Held here, or by someone else: in use either way.
        let _taken = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, port ^ 1));
        assert!(neighbor_of(&first).is_err());
        assert_eq!(
            wildcard(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            wildcard(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
        let err = io::Error::other("boom");
        assert!(
            matches!(no_pair(&err), SourceError::Unreachable(m) if m.contains("port pair") && m.contains("boom"))
        );
        assert!(
            matches!(receive_failed(&err), SourceError::Ended(m) if m.contains("receiving media failed: boom"))
        );
    }

    /// A candidate on loopback whose neighbor is taken: bound into `held`
    /// here, or already by someone else.
    fn blocked_candidate(held: &mut Vec<StdUdpSocket>) -> io::Result<StdUdpSocket> {
        let first = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = first.local_addr()?.port();
        if let Ok(neighbor) = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, port ^ 1)) {
            held.push(neighbor);
        }
        Ok(first)
    }

    #[test]
    fn rfc3550_11_a_taken_neighbor_moves_the_pair_to_another_candidate() {
        traced();
        let mut held = Vec::new();
        let mut blocked = Vec::new();
        let (media, control) = pair_among(|| {
            if blocked.is_empty() {
                let first = blocked_candidate(&mut held)?;
                blocked.push(first.local_addr()?.port());
                Ok(first)
            } else {
                StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            }
        })
        .expect("another candidate completes a pair");
        let (even, odd) = (
            media.local_addr().unwrap().port(),
            control.local_addr().unwrap().port(),
        );
        assert_eq!((even % 2, odd), (0, even + 1));
        assert_ne!(even / 2, blocked[0] / 2, "not the blocked candidate's pair");
    }

    #[test]
    fn rfc3550_11_a_pair_takes_its_last_try_then_gives_up_and_a_failed_bind_at_once() {
        traced();
        let mut held = Vec::new();
        let mut ports = Vec::new();
        let err = pair_among(|| {
            let first = blocked_candidate(&mut held)?;
            ports.push(first.local_addr()?.port());
            Ok(first)
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
        assert_eq!(ports.len(), PAIR_TRIES);
        // The candidates tried stay bound until the end: each try a new port.
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), PAIR_TRIES);
        // The last try may still complete a pair.
        let mut tries = 0;
        let (media, _control) = pair_among(|| {
            tries += 1;
            if tries < PAIR_TRIES {
                blocked_candidate(&mut held)
            } else {
                StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            }
        })
        .expect("the last candidate's pair");
        assert_eq!(tries, PAIR_TRIES);
        assert!(media.local_addr().unwrap().port().is_multiple_of(2));
        let mut calls = 0;
        let err = pair_among(|| {
            calls += 1;
            Err(io::Error::other("no sockets left"))
        })
        .unwrap_err();
        assert_eq!((calls, err.to_string()), (1, "no sockets left".to_owned()));
    }

    #[test]
    fn rfc2326_12_39_transports_are_read_as_cameras_write_them() {
        assert_eq!(
            interleaved_channel("RTP/AVP/TCP;unicast;interleaved=2-3"),
            2
        );
        assert_eq!(
            interleaved_channel("RTP/AVP/TCP;unicast; interleaved= 4"),
            4
        );
        assert_eq!(interleaved_channel("RTP/AVP/TCP;unicast"), 0);
        let udp = |source, server_port| {
            Ok(Answer::Udp {
                source,
                server_port,
            })
        };
        assert_eq!(
            parse_answer("RTP/AVP;unicast;client_port=5000-5001"),
            udp(None, None)
        );
        assert_eq!(
            parse_answer(
                "RTP/AVP/UDP;unicast;client_port=5000-5001;server_port=6970-6971;ssrc=1A2B"
            ),
            udp(None, Some(6970))
        );
        assert_eq!(
            parse_answer("RTP/AVP;unicast; source=192.168.1.10 ;server_port=6970"),
            udp(Some("192.168.1.10".parse().unwrap()), Some(6970))
        );
        assert_eq!(
            parse_answer("RTP/AVP/TCP;unicast;interleaved=0-1;server_port=x"),
            Ok(Answer::Interleaved)
        );
        assert!(
            parse_answer("RTP/AVP;source=cam.local")
                .unwrap_err()
                .contains("not an address")
        );
        for bad in [
            "x",
            "6970-6972",
            "6970-6971-6972",
            "6970-x",
            "65535",
            "-6971",
            "",
        ] {
            assert!(server_port_of(bad).is_err(), "{bad}");
            assert!(
                parse_answer(&format!("RTP/AVP;server_port={bad}")).is_err(),
                "{bad}"
            );
        }
        assert_eq!(server_port_of(" 6970 - 6971 "), Ok(6970));
        assert_eq!(server_port_of("65534-65535"), Ok(65534));
    }

    #[test]
    fn a_header_is_replaced_and_everything_else_kept_byte_for_byte() {
        let raw = b"RTSP/1.0 200 OK\r\nCSeq: 3\r\ntransport : old\nX-Transport: keep\r\n\r\nbody";
        let out = with_header(raw, 4, "Transport", "new");
        assert_eq!(
            out,
            b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nTransport: new\r\nX-Transport: keep\r\n\r\nbody"
        );
        // A body that claims more than the message holds leaves it as is.
        assert_eq!(with_header(b"x", 9, "Transport", "new"), b"x");
    }

    #[test]
    fn rfc3550_a_1_the_gate_drops_duplicates_and_late_packets_and_refuses_strangers() {
        let mut gate = Gate::default();
        assert_eq!(
            gate.rtp(&[0x80; 11]),
            Verdict::Rejected("shorter than an RTP header")
        );
        let mut v1 = rtp(1, 7);
        v1[0] = 0x40;
        assert_eq!(gate.rtp(&v1), Verdict::Rejected("not RTP version 2"));
        assert_eq!(gate.rtp(&rtp(10, 7)), Verdict::Pass);
        assert_eq!(
            gate.rtp(&rtp(11, 8)),
            Verdict::Rejected("from another synchronization source")
        );
        assert_eq!(gate.rtp(&rtp(10, 7)), Verdict::OutOfOrder, "a duplicate");
        assert_eq!(gate.rtp(&rtp(12, 7)), Verdict::Pass);
        assert_eq!(gate.rtp(&rtp(11, 7)), Verdict::OutOfOrder, "late");
        assert_eq!(gate.rtp(&rtp(500, 7)), Verdict::Pass, "a gap passes");
        // MAX_MISORDER behind is a new sequence, not a reordering.
        assert_eq!(
            gate.rtp(&rtp(500 - MAX_MISORDER + 1, 7)),
            Verdict::OutOfOrder
        );
        assert_eq!(gate.rtp(&rtp(500 - MAX_MISORDER, 7)), Verdict::Pass);
        // Across the wrap.
        let mut gate = Gate::default();
        assert_eq!(gate.rtp(&rtp(0xffff, 1)), Verdict::Pass);
        assert_eq!(gate.rtp(&rtp(0, 1)), Verdict::Pass);
        assert_eq!(gate.rtp(&rtp(0xfffe, 1)), Verdict::OutOfOrder);
        assert!(rtcp_header(&[0x80, 200, 0, 1]));
        assert!(!rtcp_header(&[0x80, 200, 0]));
        assert!(!rtcp_header(&[0x40, 200, 0, 1]));
        assert!(!rtcp_header(&[]));
    }

    #[tokio::test]
    async fn rfc2326_12_39_setup_asks_for_udp_and_the_answer_reaches_retina_as_interleaved() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut relay, _ingest) = new_relay();
        assert!(format!("{relay:?}").starts_with("UdpRelay"));
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        assert_eq!(out, DESCRIBED);
        out.clear();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        let request = String::from_utf8(out.clone()).unwrap();
        let port = client_port(&out);
        assert_eq!(port % 2, 0, "RTP on the even port");
        assert!(
            request.contains(&format!(
                "\r\nTransport: RTP/AVP/UDP;unicast;client_port={port}-{}\r\n",
                port + 1
            )),
            "{request}"
        );
        assert!(
            request
                .starts_with("SETUP rtsp://127.0.0.1:41000/stream/track0 RTSP/1.0\r\nCSeq: 3\r\n")
        );
        assert!(request.ends_with("User-Agent: lotse\r\n\r\n"), "{request}");
        out.clear();
        let server_port = server.local_addr().unwrap().port();
        relay
            .camera_sent(
                &answer(&format!("RTP/AVP/UDP;unicast;client_port={port}-{};server_port={server_port}-{};ssrc=1A2B", port + 1, server_port + 1)),
                &mut out,
            )
            .unwrap();
        let answered = String::from_utf8(out.clone()).unwrap();
        assert!(
            answered.contains("\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n"),
            "{answered}"
        );
        assert!(answered.contains("Session: 1;timeout=60"));
        // The hole punches reached the camera's RTP port (and RTCP's
        // next one, which nothing holds here).
        let mut buf = [0_u8; 64];
        let (len, from) = tokio::select! {
            received = server.recv_from(&mut buf) => received.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no hole punch within 5 s"),
        };
        assert_eq!((&buf[..len], from.port()), (&HOLE_PUNCH_RTP[..], port));
        assert_eq!(relay.pairs.len(), 1);
        assert!(relay.carries(3) && relay.carries(2) && !relay.carries(4));
    }

    #[tokio::test]
    async fn datagrams_wait_for_the_play_answer_then_flow_as_interleaved_frames() {
        // The camera's own pair: RTP, then RTCP on the next port.
        let (media, control, _) = listening_pair(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        let (server, rtcp_server) = (
            UdpSocket::from_std(media).unwrap(),
            UdpSocket::from_std(control).unwrap(),
        );
        let (mut relay, ingest) = set_up(&server);
        let client = relay.pairs[0].rtp.local_addr().unwrap().port();
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, client));
        let mut out = Vec::new();
        relay.retina_wrote(PLAY, &mut out).unwrap();
        assert_eq!(out, PLAY);
        // Media before the answer to PLAY is held.
        server.send_to(&rtp(1, 9), to).await.unwrap();
        let mut buf = vec![0_u8; MAX_DATAGRAM];
        let received = next(&relay, &mut buf).await;
        out.clear();
        relay.datagram(received, &buf[..received.len], &mut out);
        assert!(out.is_empty());
        assert_eq!(relay.queued.len(), 1);
        // The answer goes first, then the held frame.
        relay
            .camera_sent(
                b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 1\r\n\r\n",
                &mut out,
            )
            .unwrap();
        let mut expected =
            b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 1\r\n\r\n$\x02\x00\x0d".to_vec();
        expected.extend_from_slice(&rtp(1, 9));
        assert_eq!(out, expected);
        // RTCP goes on the next channel; a datagram that is not RTCP is
        // refused.
        let control = SocketAddr::from((Ipv4Addr::LOCALHOST, client + 1));
        rtcp_server
            .send_to(&[0x80, 200, 0, 0], control)
            .await
            .unwrap();
        let received = next(&relay, &mut buf).await;
        out.clear();
        relay.datagram(received, &buf[..received.len], &mut out);
        assert_eq!(out, b"$\x03\x00\x04\x80\xc8\x00\x00");
        rtcp_server
            .send_to(&[0x00, 200, 0, 0], control)
            .await
            .unwrap();
        let received = next(&relay, &mut buf).await;
        out.clear();
        relay.datagram(received, &buf[..received.len], &mut out);
        assert!(out.is_empty());
        assert_eq!(ingest.snapshot().datagrams_rejected, 1);
        // After the answer: straight on; a duplicate is dropped and counted.
        for seq in [2, 2] {
            server.send_to(&rtp(seq, 9), to).await.unwrap();
            let received = next(&relay, &mut buf).await;
            out.clear();
            relay.datagram(received, &buf[..received.len], &mut out);
        }
        assert!(out.is_empty(), "the duplicate");
        assert_eq!(ingest.snapshot().packets_out_of_order, 1);
        // A stranger on the RTP port is refused.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger.send_to(&rtp(3, 9), to).await.unwrap();
        let received = next(&relay, &mut buf).await;
        out.clear();
        relay.datagram(received, &buf[..received.len], &mut out);
        assert!(out.is_empty());
        assert!(ingest.snapshot().datagrams_rejected >= 1);
        // A pair the relay does not have is nothing.
        relay.datagram(
            Received {
                pair: 9,
                ..received
            },
            &[],
            &mut out,
        );
        assert!(out.is_empty());
    }

    /// A relay on `clock` with the video's clock rate handed over, past
    /// DESCRIBE, with retina's SETUP for channels 2-3 sent.
    fn reporting_relay(clock: &Arc<lotse_core::clock::FakeClock>) -> UdpRelay {
        traced();
        let rates = Arc::new(crate::rtcp::SetupRates::default());
        rates.push(90_000);
        let time: Arc<dyn Clock> = Arc::<lotse_core::clock::FakeClock>::clone(clock);
        let mut relay = UdpRelay::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Arc::default(),
            time,
            ReceiverReports::new(rates, crate::rtcp::Seed::random()),
        );
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        relay
    }

    /// One RTP datagram of `seq` from `from` on pair 0.
    fn heard(relay: &mut UdpRelay, from: SocketAddr, rtcp: bool, packet: &[u8]) {
        let received = Received {
            pair: 0,
            rtcp,
            from,
            len: packet.len(),
        };
        relay.datagram(received, packet, &mut Vec::new());
    }

    /// An RR's report block fields: (extended highest, LSR).
    fn block_of(packet: &[u8]) -> (u32, u32) {
        assert_eq!(&packet[..2], &[0x81, 201]);
        let word = |at: usize| u32::from_be_bytes(packet[at..at + 4].try_into().unwrap());
        (word(16), word(24))
    }

    #[tokio::test]
    async fn rfc3550_6_4_2_reports_go_from_the_streams_rtcp_port_to_the_cameras() {
        use lotse_core::clock::FakeClock;

        let clock = Arc::new(FakeClock::from_system());
        let mut relay = reporting_relay(&clock);
        let (media, control, server_port) =
            listening_pair(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        let control = UdpSocket::from_std(control).unwrap();
        let mut out = Vec::new();
        relay
            .camera_sent(
                &answer(&format!(
                    "RTP/AVP;unicast;server_port={server_port}-{}",
                    server_port + 1
                )),
                &mut out,
            )
            .unwrap();
        let from = media.local_addr().unwrap();
        assert_eq!(relay.report_due(), None);
        // Counted though out of order (RFC 3550 §6.4.1); an SR for LSR.
        for seq in [1, 2, 4, 3] {
            heard(&mut relay, from, false, &rtp(seq, 9));
        }
        let mut sr = vec![
            0x80, 200, 0, 6, 0, 0, 0, 9, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0, 0,
        ];
        sr.extend_from_slice(&[0; 12]);
        heard(&mut relay, control.local_addr().unwrap(), true, &sr);
        let due = relay.report_due().unwrap();
        clock.advance(due - clock.now());
        out.clear();
        relay.report(&mut out).await;
        assert!(out.is_empty(), "nothing on the connection");
        let mut buf = [0_u8; 256];
        let mut punch = [0_u8; 256];
        // The firewall hole punch came first: an empty RR.
        let (n, _) = control.recv_from(&mut punch).await.unwrap();
        assert_eq!(&punch[..n], &HOLE_PUNCH_RTCP);
        let (n, sender) = tokio::select! {
            got = control.recv_from(&mut buf) => got.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no report"),
        };
        assert_eq!(block_of(&buf[..n]), (4, 0xabcd_ef01));
        // From the pair's RTCP port, the odd one (RFC 3550 §11).
        assert_eq!(sender.port(), rtcp_port_of(&relay));
        assert_eq!(sender.port() % 2, 1);
        assert_eq!(
            relay.report_due().map(|next| next > clock.now()),
            Some(true)
        );
    }

    fn rtcp_port_of(relay: &UdpRelay) -> u16 {
        relay.pairs[0].rtcp.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn rfc3550_6_4_2_without_named_ports_reports_follow_the_cameras_rtcp_or_wait() {
        use lotse_core::clock::FakeClock;

        let clock = Arc::new(FakeClock::from_system());
        let mut relay = reporting_relay(&clock);
        let mut out = Vec::new();
        relay
            .camera_sent(&answer("RTP/AVP;unicast"), &mut out)
            .unwrap();
        out.clear();
        let camera = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = camera.local_addr().unwrap();
        heard(&mut relay, from, false, &rtp(1, 9));
        heard(&mut relay, from, false, &rtp(2, 9));
        // No RTCP from the camera yet: nowhere to send, nothing breaks.
        clock.advance(Duration::from_secs(4));
        relay.report(&mut out).await;
        assert!(out.is_empty());
        let mut sr = vec![0x80, 200, 0, 6];
        sr.extend_from_slice(&[0; 24]);
        heard(&mut relay, from, true, &sr);
        clock.advance(Duration::from_secs(7));
        relay.report(&mut out).await;
        let mut buf = [0_u8; 256];
        let (n, _) = tokio::select! {
            got = camera.recv_from(&mut buf) => got.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no report"),
        };
        assert_eq!(
            &buf[..2],
            &[0x80, 201],
            "nothing new since the last: no block"
        );
        assert_eq!(n, 8 + 36);
        // A send that fails is logged, not fatal: a port nothing can reach.
        relay.pairs[0].rtcp_from = Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        clock.advance(Duration::from_secs(7));
        relay.report(&mut out).await;
        // Again within the log's rate limit: counted, not logged.
        clock.advance(Duration::from_secs(7));
        relay.report(&mut out).await;
        assert!(out.is_empty());
        assert!(relay.report_due().is_some(), "still scheduled");
    }

    #[tokio::test]
    async fn rfc2326_10_12_a_stream_the_camera_answered_interleaved_reports_on_the_connection() {
        use lotse_core::clock::FakeClock;

        let clock = Arc::new(FakeClock::from_system());
        let mut relay = reporting_relay(&clock);
        let mut out = Vec::new();
        relay
            .camera_sent(&answer("RTP/AVP/TCP;unicast;interleaved=4-5"), &mut out)
            .unwrap();
        out.clear();
        for seq in [1_u16, 2] {
            let mut frame = vec![b'$', 4, 0, 13];
            frame.extend_from_slice(&rtp(seq, 9));
            relay.camera_sent(&frame, &mut out).unwrap();
        }
        clock.advance(Duration::from_secs(4));
        out.clear();
        relay.report(&mut out).await;
        assert_eq!(&out[..2], &[b'$', 5]);
        assert_eq!(block_of(&out[4..]).0, 2);
    }

    #[tokio::test]
    async fn the_queue_before_play_is_bounded() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut relay, ingest) = set_up(&server);
        let from = server.local_addr().unwrap();
        let mut out = Vec::new();
        for seq in 0..=u16::try_from(MAX_QUEUED).unwrap() {
            let received = Received {
                pair: 0,
                rtcp: false,
                from,
                len: 13,
            };
            relay.datagram(received, &rtp(seq, 1), &mut out);
        }
        assert_eq!(relay.queued.len(), MAX_QUEUED);
        assert_eq!(ingest.snapshot().datagrams_rejected, 1);
    }

    #[tokio::test]
    async fn the_queue_before_play_is_bounded_in_bytes() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut relay, ingest) = set_up(&server);
        let from = server.local_addr().unwrap();
        let mut out = Vec::new();
        // Frames of 64 KiB, their 4 interleaved bytes included: the bound
        // holds exactly this many, far fewer than MAX_QUEUED.
        let fits = MAX_QUEUED_BYTES / 65_536;
        assert!(fits < MAX_QUEUED);
        for seq in 0..u16::try_from(fits).unwrap() {
            let mut packet = rtp(seq, 1);
            packet.resize(65_536 - 4, 0);
            let received = Received {
                pair: 0,
                rtcp: false,
                from,
                len: packet.len(),
            };
            relay.datagram(received, &packet, &mut out);
        }
        assert_eq!(relay.queued.len(), fits);
        assert_eq!(ingest.snapshot().datagrams_rejected, 0);
        // Full to the byte: even the smallest RTP packet is refused.
        let packet = rtp(u16::try_from(fits).unwrap(), 1);
        let received = Received {
            pair: 0,
            rtcp: false,
            from,
            len: packet.len(),
        };
        relay.datagram(received, &packet, &mut out);
        assert_eq!(relay.queued.len(), fits);
        assert_eq!(ingest.snapshot().datagrams_rejected, 1);
        assert!(out.is_empty());
    }

    #[test]
    fn rfc1122_3_2_1_3_a_source_no_camera_can_send_from_is_refused() {
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let (lan, lan6) = (ip("192.0.2.10"), ip("2001:db8::10"));
        for (endpoint, named, reason) in [
            (lan, "2001:db8::11", "another address family"),
            (lan6, "192.0.2.11", "another address family"),
            (lan6, "::ffff:192.0.2.11", "another address family"),
            (lan, "0.0.0.0", "unspecified"),
            (lan6, "::", "unspecified"),
            (lan, "::ffff:0.0.0.0", "unspecified"),
            (lan, "224.0.0.1", "multicast"),
            (lan6, "ff02::1", "multicast"),
            (lan, "255.255.255.255", "broadcast"),
            (lan, "127.0.0.1", "loopback"),
            (lan, "127.1.2.3", "loopback"),
            (lan, "::ffff:127.0.0.1", "loopback"),
            (lan6, "::1", "loopback"),
            (lan6, "::ffff:127.0.0.1", "another address family"),
            (ip("::1"), "::ffff:127.0.0.1", "another address family"),
        ] {
            let why = refused_source(ip(named), endpoint);
            assert!(
                why.is_some_and(|why| why.contains(reason)),
                "{named} for {endpoint}: {why:?}"
            );
        }
        for (endpoint, named) in [
            // Another host: RFC 2326 §12.39 allows it.
            (lan, "192.0.2.11"),
            (lan, "192.0.2.10"),
            // Zero-configuration cameras (RFC 3927).
            (lan, "169.254.1.1"),
            (lan6, "2001:db8::11"),
            (lan6, "fe80::1"),
            // A camera on this host may send from loopback.
            (ip("127.0.0.1"), "127.0.0.2"),
            (ip("::1"), "::1"),
            // An IPv4-mapped endpoint is an IPv4 one (RFC 4291 §2.5.5.2).
            (ip("::ffff:127.0.0.1"), "127.0.0.2"),
        ] {
            assert_eq!(
                refused_source(ip(named), endpoint),
                None,
                "{named} for {endpoint}"
            );
        }
    }

    #[tokio::test]
    async fn rfc2326_12_39_a_refused_source_ends_the_attempt_and_an_accepted_one_is_heard() {
        let camera: IpAddr = "192.0.2.10".parse().unwrap();
        let (mut relay, _ingest) = relay_for(camera);
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        out.clear();
        let err = relay
            .camera_sent(&answer("RTP/AVP;unicast;source=127.0.0.1"), &mut out)
            .unwrap_err();
        assert!(
            matches!(&err, SourceError::Protocol(m)
                if m.contains("source 127.0.0.1") && m.contains("loopback")
                    && m.contains("RFC 1122 §3.2.1.3")),
            "{err:?}"
        );
        assert!(out.is_empty() && relay.pairs.is_empty());
        // Another host of the camera's family is taken at its word.
        let (mut relay, _ingest) = relay_for(camera);
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        relay
            .camera_sent(&answer("RTP/AVP;unicast;source=192.0.2.11"), &mut out)
            .unwrap();
        let named: IpAddr = "192.0.2.11".parse().unwrap();
        assert_eq!(relay.pairs[0].source, named);
        assert!(relay.pairs[0].accepts(SocketAddr::new(named, 5000), false));
        assert!(!relay.pairs[0].accepts(SocketAddr::new(camera, 5000), false));
    }

    #[tokio::test]
    async fn answers_are_matched_to_their_request_by_cseq_rfc2326_12_17() {
        let (mut relay, _ingest) = new_relay();
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        // A late answer to another request leaves the SETUP waiting.
        out.clear();
        let other = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nTransport: x\r\n\r\n";
        relay.camera_sent(other, &mut out).unwrap();
        assert_eq!(out, other);
        assert!(relay.setup.is_some());
        relay
            .camera_sent(&answer("RTP/AVP;unicast;server_port=6970-6971"), &mut out)
            .unwrap();
        assert!(relay.setup.is_none() && relay.pairs.len() == 1);
        // Only the answer to PLAY starts the media.
        relay.retina_wrote(PLAY, &mut out).unwrap();
        relay
            .camera_sent(b"RTSP/1.0 200 OK\r\nCSeq: 3\r\n\r\n", &mut out)
            .unwrap();
        assert!(!relay.playing);
        relay
            .camera_sent(
                b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 1\r\n\r\n",
                &mut out,
            )
            .unwrap();
        assert!(relay.playing);
    }

    #[tokio::test]
    async fn answers_that_refuse_or_choose_tcp_pass_unchanged_and_bad_ones_are_refused() {
        // 461: passed on for retina to report, the pair released.
        let (mut relay, _ingest) = new_relay();
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        out.clear();
        let refused = b"RTSP/1.0 461 Unsupported Transport\r\nCSeq: 3\r\n\r\n";
        relay.camera_sent(refused, &mut out).unwrap();
        assert_eq!(out, refused);
        assert!(relay.setup.is_none() && relay.pairs.is_empty());
        // Interleaved after all: passed on, and its media too.
        relay.retina_wrote(SETUP, &mut out).unwrap();
        out.clear();
        let tcp = answer("RTP/AVP/TCP;unicast;interleaved=2-3");
        relay.camera_sent(&tcp, &mut out).unwrap();
        assert_eq!(out, tcp);
        assert!(relay.pairs.is_empty());
        out.clear();
        relay.camera_sent(b"$\x02\x00\x01z", &mut out).unwrap();
        assert_eq!(out, b"$\x02\x00\x01z");
        // An answer whose Transport cannot be read ends the attempt.
        relay.retina_wrote(SETUP, &mut out).unwrap();
        let err = relay
            .camera_sent(&answer("RTP/AVP;unicast;server_port=1-3"), &mut out)
            .unwrap_err();
        assert!(
            matches!(err, SourceError::Protocol(ref m) if m.contains("RFC 2326 §12.39")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn rfc2326_12_39_an_unreadable_transport_reaches_the_error_capped() {
        let (mut relay, _ingest) = new_relay();
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        relay.retina_wrote(SETUP, &mut out).unwrap();
        // 40 KiB of a camera's text in the header and in the parameter the
        // reason quotes (control characters do not pass the framer).
        let junk = format!("\"{}", "x".repeat(40 * 1024));
        let err = relay
            .camera_sent(&answer(&format!("RTP/AVP;unicast;source={junk}")), &mut out)
            .unwrap_err();
        assert!(matches!(err, SourceError::Protocol(_)), "{err:?}");
        let message = err.to_string();
        let message = message
            .strip_prefix("source protocol error: ")
            .unwrap_or(&message);
        assert!(
            message.len() < 2 * crate::error::CAMERA_TEXT_BYTES + 100,
            "{message}"
        );
        assert!(
            message.starts_with(
                r#"the camera's SETUP answer has the Transport "RTP/AVP;unicast;source=\"xxx"#
            ),
            "{message}"
        );
        assert!(
            message.contains(r#"xxx": source "\"xxx"#),
            "the reason Debug-escapes the value: {message}"
        );
        assert!(message.ends_with("(RFC 2326 §12.39)"), "{message}");
    }

    #[tokio::test]
    async fn interleaved_media_on_a_udp_channel_is_dropped_and_requests_pass() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (mut relay, _ingest) = set_up(&server);
        let mut out = Vec::new();
        // Dropped; the second within the summary interval is not logged.
        relay
            .camera_sent(b"$\x03\x00\x01z$\x02\x00\x01z", &mut out)
            .unwrap();
        assert!(out.is_empty());
        let request = b"SET_PARAMETER rtsp://127.0.0.1/ RTSP/1.0\r\nCSeq: 9\r\n\r\n";
        relay.camera_sent(request, &mut out).unwrap();
        assert_eq!(out, request);
        // retina's own answers or frames, should it send any, pass too.
        out.clear();
        relay
            .retina_wrote(
                b"RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n$\x00\x00\x01y",
                &mut out,
            )
            .unwrap();
        assert_eq!(out, b"RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n$\x00\x00\x01y");
    }

    #[test]
    fn rfc2326_10_7_an_orphaned_teardown_is_framed_and_so_is_its_fresh_answer() {
        let (mut relay, _ingest) = new_relay();
        let mut out = Vec::new();
        relay.camera_sent(DESCRIBED, &mut out).unwrap();
        // The camera's connection broke inside a message: the fresh
        // connection's answer is framed from the start.
        relay.camera_sent(b"RTSP/1.0 200", &mut out).unwrap();
        assert!(!relay.tearing_down());
        let teardown =
            b"TEARDOWN rtsp://127.0.0.1:41000/stream/ RTSP/1.0\r\nCSeq: 6\r\nSession: 1\r\n\r\n";
        let keepalive = b"GET_PARAMETER rtsp://127.0.0.1:41000/stream/ RTSP/1.0\r\nCSeq: 5\r\nSession: 1\r\n\r\n";
        let mut written = keepalive.to_vec();
        written.extend_from_slice(&teardown[..10]);
        assert_eq!(relay.orphaned_request(&written).unwrap(), None);
        assert_eq!(
            relay.orphaned_request(&teardown[10..]).unwrap().as_deref(),
            Some(&teardown[..])
        );
        assert!(relay.tearing_down());
        let answer = b"RTSP/1.0 200 OK\r\nCSeq: 6\r\nSession: 1\r\n\r\n";
        assert_eq!(relay.fresh_answer(&answer[..12]).unwrap(), None);
        assert_eq!(
            relay.fresh_answer(&answer[12..]).unwrap().as_deref(),
            Some(&answer[..])
        );
        // Unreadable either way.
        assert!(relay.orphaned_request(b"\x01\x02 junk\r\n\r\n").is_err());
        assert!(relay.fresh_answer(b"\x01\x02 junk\r\n\r\n").is_err());
    }

    #[test]
    fn rfc2326_10_7_a_fresh_answer_passes_and_strays_are_dropped() {
        let (mut relay, _ingest) = new_relay();
        let teardown = b"TEARDOWN rtsp://127.0.0.1:41000/stream/ RTSP/1.0\r\nCSeq: 6\r\n\r\n";
        assert!(relay.orphaned_request(teardown).unwrap().is_some());
        let answer = b"RTSP/1.0 200 OK\r\nCSeq: 6\r\nSession: 1 ;timeout=60\r\n\r\n";
        let mut sent = b"$\x00\x00\x01z".to_vec();
        sent.extend_from_slice(answer);
        assert_eq!(
            relay.fresh_answer(&sent).unwrap().as_deref(),
            Some(&answer[..])
        );
        // retina's TEARDOWN through the relay as usual marks the session over.
        let (mut relay, _ingest) = new_relay();
        let mut out = Vec::new();
        relay.retina_wrote(teardown, &mut out).unwrap();
        assert_eq!(out, teardown);
        assert!(relay.tearing_down());
    }

    #[tokio::test]
    async fn unreadable_rtsp_either_way_ends_the_attempt() {
        let (mut relay, _ingest) = new_relay();
        let mut out = Vec::new();
        let err = relay
            .camera_sent(b"\x01\x02 junk\r\n\r\n", &mut out)
            .unwrap_err();
        assert!(
            matches!(err, SourceError::Protocol(ref m) if m.contains("unreadable")),
            "{err:?}"
        );
        let err = relay
            .retina_wrote(b"\x01\x02 junk\r\n\r\n", &mut out)
            .unwrap_err();
        assert!(
            matches!(err, SourceError::Protocol(ref m) if m.contains("retina's request")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn the_camera_is_heard_only_from_its_media_ports_and_the_punch_needs_them() {
        let (media_socket, control_socket, _) =
            listening_pair(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        let camera = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // An IPv6 source for IPv4 sockets: the punch fails and is only
        // logged.
        traced();
        punch(
            [&media_socket, &control_socket],
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            Some((6970, 6971)),
        );
        punch([&media_socket, &control_socket], camera, None);
        let mut pair = Pair {
            channel: 0,
            rtp: UdpSocket::from_std(media_socket).unwrap(),
            rtcp: UdpSocket::from_std(control_socket).unwrap(),
            source: camera,
            ports: Some((6970, 6971)),
            gate: Gate::default(),
            rtcp_from: None,
        };
        assert!(format!("{pair:?}").starts_with("Pair"));
        assert!(pair.accepts(SocketAddr::new(camera, 6970), false));
        assert!(pair.accepts(SocketAddr::new(camera, 6971), true));
        assert!(!pair.accepts(SocketAddr::new(camera, 6971), false));
        assert!(!pair.accepts(SocketAddr::new(camera, 6970), true));
        assert!(!pair.accepts("192.0.2.1:6970".parse().unwrap(), false));
        pair.ports = None;
        assert!(pair.accepts(SocketAddr::new(camera, 1), false));
        assert!(pair.accepts(SocketAddr::new(camera, 2), true));
        // No pairs: nothing to receive.
        let (relay, _ingest) = new_relay();
        let mut buf = [0_u8; 16];
        tokio::select! {
            _ = relay.recv(0, &mut buf) => panic!("no pairs, no datagrams"),
            () = SystemClock.sleep(Duration::from_millis(20)) => {}
        }
    }
}

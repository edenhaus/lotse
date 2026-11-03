//! RTP over UDP, opt-in per stream (`transport: "udp"`): the RTP/RTCP port
//! pairs the source binds for retina's sans-I/O core, the checks every
//! datagram passes before the core reads it, and the pairs' I/O, which
//! the driver ([`crate::driver`]) runs beside the control connection.
//!
//! retina's core asks the camera for UDP in its `SETUP` with the
//! `client_port` pair it is given (RFC 2326 §12.39; RFC 3550 §11: RTP on
//! an even port, RTCP on the next), reads the answer's `source` and
//! `server_port`, queues the firewall hole punches once it knows the
//! camera's ports (an RTP header with nothing to say and an empty RTCP
//! Receiver Report, which the camera discards), queues the receiver
//! reports while the session plays (RFC 3550 §6.4.2), and reads the
//! datagrams handed to it. Without `server_port` it learns each port from
//! the first datagram of that channel it reads, symmetric RTP (RFC 4961
//! §3 and §4): no hole is punched then, and its reports wait for the
//! camera's first RTCP.
//!
//! The pairs listen on the wildcard address of the camera's family, so
//! the kernel answers on whichever interface the camera reaches, and stay
//! unconnected: a refused hole punch (ICMP) never turns into an error on
//! them. What the core sends goes out with `send_to` its peer, and a send
//! that fails (a full socket buffer) is logged and dropped, as a lost
//! datagram would be. The checks below, not the bind, say who may send.
//!
//! What reaches the core is decided here, per datagram ([`Check`]), with
//! retina's own check of the sender's address behind it:
//!
//! - It must come from the camera's media ports: the `source` of the
//!   answer, else the address of the camera's RTSP endpoint (RFC 2326
//!   §12.39 `source`), and its `server_port` pair if the answer named one,
//!   since the camera receives there and sends from there (symmetric RTP
//!   and RTCP, RFC 4961 §3 and §4; RFC 7826 §18.54 `src_addr`). Without
//!   `server_port` RFC 2326 names no port, so any port of that address
//!   passes, which is also the core's rule. Anything else (a stray or
//!   spoofed sender on the LAN) is refused and counted: no port is latched
//!   on (RFC 7362), and a named `source` that stays silent is not replaced
//!   by the endpoint. A `source` no camera can send from ends the attempt
//!   before anything is sent there ([`refused_source`]): another family
//!   than the endpoint's, or one RFC 1122 §3.2.1.3 rules out as the
//!   source of a datagram from another host, loopback among them, so a
//!   camera elsewhere cannot have the source take media from, and send
//!   punches and reports to, whatever listens on this host.
//! - It must be a packet the core reads: an RTP packet that retina's own
//!   header check passes (RFC 3550 §5.1), from the synchronization source
//!   the first one carried, or an RTCP compound packet whose packets the
//!   common header frames (RFC 3550 §6.1, §6.4). The core takes a packet
//!   it cannot read for the session's error, as over TCP, where its
//!   framing would be lost with it; a datagram is one packet, so here it
//!   is refused and counted instead, and the session goes on.
//! - Another synchronization source is refused and counted too, until it
//!   sends [`MIN_SEQUENTIAL`] packets in a row (RFC 3550 §A.1 probation):
//!   then the camera restarted its RTP session (§8.2, after its BYE or a
//!   reboot), and the attempt ends with a protocol error, so the source
//!   reconnects at once, as retina's own wrong-source error over TCP
//!   would have it, rather than refuse every packet until the stall
//!   watchdog. One stray never switches the stream; a stray that came
//!   first and took the lock is replaced the same way. retina checks the
//!   source a `SETUP` answer's `ssrc=` names itself, and ends the session
//!   on a packet from another.
//!
//! No reorder buffer: retina's is its reorderer's `max_delay`
//! ([`udp_options`]), off by decision. Over TCP retina reorders with no
//! delay, so it drops a packet that arrives after a later one (its
//! reorderer's `Pushed::Late`), and RTP over UDP keeps that: waiting for a
//! reordered packet would add the wait to every packet behind it, the
//! latency lotse exists to keep low. A duplicate, or a packet up to
//! [`MAX_MISORDER`] behind the highest sequence number passed (RFC 3550
//! §A.1), still reaches the core, which counts it as received for its
//! reports (§6.4.1) and drops it; here it is counted as out of order. Its
//! gap was counted as loss when the later packet passed. A jump further
//! back, or [`MAX_DROPOUT`] or more ahead, is a stray that leaves the
//! highest sequence number where it is, unless the next packet follows
//! it: the sender restarted, as retina's reorderer takes it too.
//!
//! retina reads a `SETUP` answer's `Transport` more strictly than the
//! relay lotse ran before did: a `server_port` of one port, or spaces
//! around the parameters' `;`, are not taken as the relay took them; the
//! fork lotse pins is to accept both.
//!
//! The core is read only while the session plays: before the answer to
//! `PLAY` the camera's datagrams wait in the sockets' buffers. A session
//! whose control connection the camera closes ends there (the driver's
//! [`crate::driver::Error::Closed`]), while the camera may keep sending:
//! RFC 2326 §1.1 does not tie the session to the connection, so retina's
//! `TEARDOWN` goes on a fresh one
//! ([`retina::client::TeardownAction::Connect`]).

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use lotse_core::ingest::IngestCounters;
use lotse_core::source::SourceError;
use lotse_core::throttle::Throttle;
use retina::buf::MarkBuf;
use retina::client::{ChannelType, SessionCore, UdpPeer, UdpTransmit, UdpTransportOptions};
use retina::rtp::{PacketHeader, ReorderOptions};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::driver::Error;

/// RFC 3550 §A.1 `MAX_MISORDER`: a packet at most this many sequence
/// numbers behind the highest one is reordered (or a duplicate at 0), not
/// a new sequence; retina's reorderer draws the line at the same place.
const MAX_MISORDER: u16 = 100;

/// RFC 3550 §A.1 `MAX_DROPOUT`: a jump ahead of less than this many is
/// loss; a larger jump either way is a stray, or the sender's restart once
/// the next packet follows it, as retina's reorderer takes it.
const MAX_DROPOUT: u16 = 3000;

/// RFC 3550 §A.1 `MIN_SEQUENTIAL`: sequential packets a new synchronization
/// source sends before it counts as the camera's.
const MIN_SEQUENTIAL: u8 = 2;

/// The receive buffer: the largest UDP payload there is, so a datagram is
/// never cut, and its length always fits the core's 16 bits.
const MAX_DATAGRAM: usize = 65_535;

/// The most datagrams one socket hands the core per wake-up: a busy
/// stream cannot starve the others, nor the control connection, which the
/// driver reads in the same poll. A keyframe of a few hundred packets
/// takes a few wake-ups.
const MAX_READS: usize = 64;

/// What the core's UDP streams are set up with: no reorder buffer
/// (`max_delay` zero), so a late packet is dropped at once, as over TCP.
pub(crate) fn udp_options() -> UdpTransportOptions {
    UdpTransportOptions::default().reorder(ReorderOptions::default().max_delay(Duration::ZERO))
}

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
pub(crate) fn bind_pair(ip: IpAddr) -> io::Result<(StdUdpSocket, StdUdpSocket)> {
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

/// Why the `named` source of a `SETUP` answer is refused for the camera
/// whose RTSP endpoint is `endpoint`; `None` when its media may come
/// from there. Both are compared as what they are, an IPv4-mapped
/// address as IPv4 (RFC 4291 §2.5.5.2).
///
/// SPEC-DEVIATION: RFC 2326 §12.39 lets the camera name any address.
/// A stream's pair listens on the endpoint's family only, so a source
/// of the other family could never be heard; and RFC 1122 §3.2.1.3 lets
/// no host send from an unspecified, broadcast or multicast address, nor
/// a loopback address appear outside its host, so a camera elsewhere
/// that names one either errs or points the source's punches, reports
/// and accepted media at this host's own services. Another host of the
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

/// No pair could be bound: the attempt fails like an unreachable camera
/// and backs off.
fn no_pair(err: &io::Error) -> SourceError {
    SourceError::Unreachable(format!(
        "rtsp udp: no RTP/RTCP port pair to receive on: {err}"
    ))
}

/// One of a pair's sockets, as the driver uses it; a test seam for a
/// socket that fails.
pub(crate) trait Socket: fmt::Debug + Send {
    /// Receives one datagram into `buf`: its sender.
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>>;

    /// Sends `data` to `to` at once, or fails, a full buffer too.
    fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<usize>;
}

impl Socket for UdpSocket {
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        Self::poll_recv_from(self, cx, buf)
    }

    /// Straight to the kernel: tokio's `try_send_to` fails until the
    /// runtime saw the socket writable once, which a hole punch right
    /// after `SETUP` would not wait for, and a datagram seldom waits.
    fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<usize> {
        socket2::SockRef::from(self).send_to(data, &to.into())
    }
}

/// One stream's RTP/RTCP pair, bound for its `SETUP`.
#[derive(Debug)]
pub(crate) struct Pair {
    /// Receives RTP, and sends the RTP hole punch.
    rtp: Box<dyn Socket>,
    /// Receives RTCP, and sends the RTCP hole punch and the reports.
    rtcp: Box<dyn Socket>,
    /// The RTP port, even; RTCP is on the next.
    port: u16,
}

impl Pair {
    /// A pair on the wildcard address of `camera`'s family, ready for the
    /// runtime; none bound fails the attempt as unreachable.
    pub(crate) fn bind(camera: IpAddr) -> Result<Self, SourceError> {
        Self::bind_on(wildcard(camera))
    }

    /// A pair on `ip`.
    fn bind_on(ip: IpAddr) -> Result<Self, SourceError> {
        Self::listening(ip).map_err(|err| no_pair(&err))
    }

    /// [`Pair::bind_on`] before its error is typed.
    fn listening(ip: IpAddr) -> io::Result<Self> {
        let (media, control) = bind_pair(ip)?;
        let port = media.local_addr()?.port();
        media.set_nonblocking(true)?;
        control.set_nonblocking(true)?;
        Ok(Self {
            rtp: Box::new(UdpSocket::from_std(media)?),
            rtcp: Box::new(UdpSocket::from_std(control)?),
            port,
        })
    }

    /// A pair of `media` (RTP) and `control` (RTCP), whose `port` the
    /// `SETUP` names.
    #[cfg(test)]
    pub(crate) fn of(media: Box<dyn Socket>, control: Box<dyn Socket>, port: u16) -> Self {
        Self {
            rtp: media,
            rtcp: control,
            port,
        }
    }

    /// The RTP port, which the `SETUP`'s `client_port` names.
    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    /// The socket of `channel`.
    fn socket(&self, channel: ChannelType) -> &dyn Socket {
        match channel {
            ChannelType::Rtp => &*self.rtp,
            ChannelType::Rtcp => &*self.rtcp,
        }
    }
}

/// What becomes of one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// On to the core.
    Pass,
    /// On to the core, which drops it: a duplicate, or later than a packet
    /// that passed.
    Late,
    /// Refused before the core read it, and why.
    Refused(&'static str),
    /// A new synchronization source, [`MIN_SEQUENTIAL`] packets in a row:
    /// the camera restarted its session (RFC 3550 §8.2).
    SsrcChanged {
        /// The one the stream had.
        from: u32,
        /// The one it sends now.
        to: u32,
    },
}

/// The checks on one stream's datagrams.
#[derive(Debug)]
struct Check {
    /// Where the camera sends from: the answer's `source`, else the RTSP
    /// endpoint's address (RFC 2326 §12.39), never one [`refused_source`]
    /// refuses.
    source: IpAddr,
    /// The camera's RTP and RTCP ports, when its answer named them: where
    /// it receives and, symmetric (RFC 4961 §3), sends from.
    ports: Option<(u16, u16)>,
    /// The synchronization source of the first RTP packet that passed.
    ssrc: Option<u32>,
    /// Another synchronization source heard since the last packet of
    /// `ssrc`: its last sequence number and how many came in a row.
    newcomer: Option<(u32, u16, u8)>,
    /// The highest sequence number passed.
    highest: Option<u16>,
    /// One past the sequence number of the last stray (RFC 3550 §A.1
    /// `bad_seq`): a packet with it restarts the sequence.
    stray: Option<u16>,
}

impl Check {
    /// The checks for the camera's media from `source`, and from its
    /// `server_port` pair if the answer named its RTP port.
    fn new(source: IpAddr, server_port: Option<u16>) -> Self {
        Self {
            source: source.to_canonical(),
            ports: server_port.map(|port| (port, port.saturating_add(1))),
            ssrc: None,
            newcomer: None,
            highest: None,
            stray: None,
        }
    }

    /// Whether a datagram from `from` on the RTP (or RTCP) socket comes
    /// from the camera's media port.
    fn accepts(&self, from: SocketAddr, rtcp: bool) -> bool {
        from.ip().to_canonical() == self.source
            && self.ports.is_none_or(|(media_port, control_port)| {
                from.port() == if rtcp { control_port } else { media_port }
            })
    }

    /// Judges one datagram from `from` on the RTP (or RTCP) socket and,
    /// passed, remembers it.
    fn judge(&mut self, rtcp: bool, from: SocketAddr, datagram: &[u8]) -> Verdict {
        if !self.accepts(from, rtcp) {
            Verdict::Refused("not from the camera's media port")
        } else if rtcp {
            if rtcp_compound(datagram) {
                Verdict::Pass
            } else {
                Verdict::Refused("not an RTCP compound packet")
            }
        } else {
            self.rtp(datagram)
        }
    }

    /// Judges one RTP datagram (RFC 3550 §5.1) and, passed, remembers it.
    fn rtp(&mut self, datagram: &[u8]) -> Verdict {
        let Ok(packet) = PacketHeader::validate(datagram) else {
            return Verdict::Refused("not an RTP packet");
        };
        let (seq, ssrc) = (packet.header.sequence_number(), packet.header.ssrc());
        if let Some(locked) = self.ssrc.filter(|&locked| locked != ssrc) {
            return self.newcomer(locked, ssrc, seq);
        }
        self.ssrc = Some(ssrc);
        self.newcomer = None;
        self.sequence(seq)
    }

    /// A packet of `ssrc`, `seq`, while the stream's is `locked`: refused,
    /// and once [`MIN_SEQUENTIAL`] came in a row, the camera's new source.
    fn newcomer(&mut self, locked: u32, ssrc: u32, seq: u16) -> Verdict {
        let run = match self.newcomer {
            Some((last_ssrc, last_seq, run))
                if last_ssrc == ssrc && last_seq.wrapping_add(1) == seq =>
            {
                run.saturating_add(1)
            }
            _ => 1,
        };
        self.newcomer = Some((ssrc, seq, run));
        if run < MIN_SEQUENTIAL {
            Verdict::Refused("from another synchronization source")
        } else {
            Verdict::SsrcChanged {
                from: locked,
                to: ssrc,
            }
        }
    }

    /// Where `seq` falls behind the highest passed (RFC 3550 §A.1): late
    /// up to [`MAX_MISORDER`] behind (a duplicate at 0), the new highest
    /// up to [`MAX_DROPOUT`] ahead, else a stray that leaves the highest
    /// where it is, unless it follows the last stray: the sender restarted.
    fn sequence(&mut self, seq: u16) -> Verdict {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            return Verdict::Pass;
        };
        if highest.wrapping_sub(seq) < MAX_MISORDER {
            return Verdict::Late;
        }
        if seq.wrapping_sub(highest) < MAX_DROPOUT || self.stray == Some(seq) {
            self.highest = Some(seq);
            self.stray = None;
        } else {
            self.stray = Some(seq.wrapping_add(1));
        }
        Verdict::Pass
    }
}

/// Whether `datagram` is an RTCP compound packet the core reads: one or
/// more packets the common header frames (version 2, the length in 32-bit
/// words), padding on the last one only (RFC 3550 §6.1, §6.4.1), as
/// retina checks it.
fn rtcp_compound(datagram: &[u8]) -> bool {
    let mut rest = datagram;
    loop {
        let Ok((packet, next)) = retina::rtcp::PacketRef::parse(rest) else {
            return false;
        };
        if next.is_empty() {
            return true;
        }
        if packet.has_padding() {
            return false;
        }
        rest = next;
    }
}

/// Writes `datagram` into the free space of `buf`, the core's receive
/// buffer for its stream, which may wrap: the core marks it received.
fn put(buf: &mut MarkBuf, datagram: &[u8]) {
    let (first, second) = buf.spare_capacity(datagram.len());
    let (head, tail) = datagram
        .split_at_checked(first.len())
        .unwrap_or((datagram, &[]));
    if let Some(into) = first.get_mut(..head.len()) {
        into.copy_from_slice(head);
    }
    if let Some(into) = second.get_mut(..tail.len()) {
        into.copy_from_slice(tail);
    }
}

/// One stream over UDP: its pair and the checks on what it receives.
#[derive(Debug)]
struct Stream {
    /// The pair.
    pair: Pair,
    /// The checks.
    check: Check,
}

/// The UDP side of one session: the pairs of its streams set up over UDP,
/// by stream index, the counters and the log's rate limits.
#[derive(Debug)]
pub(crate) struct Streams {
    /// The camera's RTSP endpoint: where its media comes from unless an
    /// answer names a `source`.
    endpoint: IpAddr,
    /// The streams, each with its index among the session's.
    pairs: Vec<(usize, Stream)>,
    /// One datagram, as received; empty until a stream is set up.
    datagram: Vec<u8>,
    /// Where refusals and late packets are counted.
    ingest: Arc<IngestCounters>,
    /// The rate limit of the refused-datagram warning.
    refused: Throttle,
    /// The rate limit of the late-packet line.
    late: Throttle,
    /// The rate limit of the line about a datagram not sent.
    unsent: Throttle,
    /// Why the stream ends, once a check said so: handed out on the next
    /// receive, after what the core took in before it.
    ended: Option<Error>,
}

impl Streams {
    /// No stream yet, for the camera whose RTSP endpoint is `endpoint`.
    pub(crate) fn new(endpoint: IpAddr) -> Self {
        Self {
            endpoint,
            pairs: Vec::new(),
            datagram: Vec::new(),
            ingest: Arc::default(),
            refused: Throttle::default(),
            late: Throttle::default(),
            unsent: Throttle::default(),
            ended: None,
        }
    }

    /// Counts refusals and late packets into `ingest`.
    pub(crate) fn count_into(&mut self, ingest: Arc<IngestCounters>) {
        self.ingest = ingest;
    }

    /// The stream at `index` was set up over UDP on `pair`, the camera
    /// sending from `peer`, which retina names for every UDP stream, else
    /// from the RTSP endpoint on ports unknown; an error, and nothing
    /// kept, when `peer` names a source no camera can send from
    /// ([`refused_source`]).
    pub(crate) fn set_up(
        &mut self,
        index: usize,
        pair: Pair,
        peer: Option<&UdpPeer>,
    ) -> Result<(), SourceError> {
        let (named, server_port) =
            peer.map_or((self.endpoint, None), |peer| (peer.ip, peer.rtp_port));
        self.answered(index, pair, named, server_port)
    }

    /// [`Streams::set_up`] with the camera sending from `named`, its RTP
    /// port `server_port` if the answer named one.
    fn answered(
        &mut self,
        index: usize,
        pair: Pair,
        named: IpAddr,
        server_port: Option<u16>,
    ) -> Result<(), SourceError> {
        if let Some(why) = refused_source(named, self.endpoint) {
            tracing::warn!(
                stream = index,
                source = %named,
                endpoint = %self.endpoint,
                reason = why,
                "rtsp udp: SETUP answer names a source no camera can send from; refused"
            );
            return Err(SourceError::Protocol(format!(
                "the camera's SETUP answer names the source {named}, which is {why} \
                 (RFC 2326 §12.39, RFC 1122 §3.2.1.3)"
            )));
        }
        tracing::info!(
            stream = index,
            client_port = pair.port,
            source = %named,
            endpoint = %self.endpoint,
            server_port,
            "rtsp udp: media over UDP"
        );
        self.pairs.retain(|(set_up, _)| *set_up != index);
        let check = Check::new(named, server_port);
        self.pairs.push((index, Stream { pair, check }));
        self.datagram.resize(MAX_DATAGRAM, 0);
        Ok(())
    }

    /// Sends what the core queued for a stream's socket to its peer; a
    /// send that fails is logged, rate-limited, and dropped.
    pub(crate) fn send(&mut self, transmit: &UdpTransmit, now: Instant) {
        let index = transmit.stream_i;
        // One stream at most: [`Streams::set_up`] replaces a stream's pair.
        for (_, stream) in self.pairs.iter().filter(|(set_up, _)| *set_up == index) {
            let socket = stream.pair.socket(transmit.channel_type);
            if let Err(err) = socket.send_to(&transmit.data, transmit.peer)
                && let Some(count) = self.unsent.hit(now)
            {
                tracing::debug!(
                    stream = index,
                    channel = ?transmit.channel_type,
                    to = %transmit.peer,
                    error = %err,
                    count,
                    "rtsp udp: datagram not sent"
                );
            }
        }
    }

    /// Hands `core`, which plays, what the sockets of its UDP streams
    /// received, RTCP before RTP, at most [`MAX_READS`] datagrams per
    /// socket, at `now`: ready when one arrived, pending while none did,
    /// and the core's error for a socket that failed; a new
    /// synchronization source ends the stream on the receive after
    /// ([`Verdict::SsrcChanged`]).
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        core: &mut SessionCore,
        now: Instant,
    ) -> Poll<Result<(), Error>> {
        if let Some(ended) = self.ended.take() {
            return Poll::Ready(Err(ended));
        }
        let mut received = false;
        for (index, stream) in &mut self.pairs {
            let index = *index;
            if !core.is_udp(index) {
                continue;
            }
            for channel in [ChannelType::Rtcp, ChannelType::Rtp] {
                for _ in 0..MAX_READS {
                    let mut buf = ReadBuf::new(&mut self.datagram);
                    let from = match stream.pair.socket(channel).poll_recv_from(cx, &mut buf) {
                        Poll::Pending => break,
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(Error::Session(
                                core.udp_recv_error(index, err),
                            )));
                        }
                        Poll::Ready(Ok(from)) => from,
                    };
                    received = true;
                    let datagram = buf.filled();
                    let rtcp = channel == ChannelType::Rtcp;
                    match stream.check.judge(rtcp, from, datagram) {
                        Verdict::Pass => {}
                        Verdict::Late => {
                            self.ingest.count_out_of_order();
                            if let Some(count) = self.late.hit(now) {
                                tracing::debug!(
                                    stream = index,
                                    count,
                                    "rtsp udp: duplicate or late RTP packet; retina drops it"
                                );
                            }
                        }
                        Verdict::SsrcChanged { from, to } => {
                            tracing::warn!(
                                stream = index,
                                from = format_args!("{from:08x}"),
                                to = format_args!("{to:08x}"),
                                "rtsp udp: the camera changed its synchronization source; ending the attempt"
                            );
                            // What came before is handed out first.
                            self.ended = Some(Error::Refused(SourceError::Protocol(format!(
                                "the camera changed its RTP synchronization source from {from:08x} to {to:08x} (RFC 3550 §8.2): a new session"
                            ))));
                            return Poll::Ready(Ok(()));
                        }
                        Verdict::Refused(reason) => {
                            self.ingest.count_rejected();
                            if let Some(count) = self.refused.hit(now) {
                                tracing::warn!(
                                    %from,
                                    stream = index,
                                    rtcp,
                                    reason,
                                    count,
                                    "rtsp udp: datagram refused"
                                );
                            }
                            continue;
                        }
                    }
                    // At most `MAX_DATAGRAM` bytes: it fits.
                    let len = u16::try_from(datagram.len()).unwrap_or(u16::MAX);
                    put(core.udp_buf(index), datagram);
                    core.udp_received_from(index, channel, len, from, now);
                }
            }
        }
        if received {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
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

    use std::future::poll_fn;

    use lotse_core::clock::{Clock as _, SystemClock};
    use retina::client::SessionOptions;

    use super::*;

    /// Every log line's fields are evaluated, as in production at
    /// `trace`; the lines go nowhere.
    fn traced() {
        let _installed = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(io::sink)
            .try_init();
    }

    fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 96];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 1]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.push(0xaa);
        packet
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn from(text: &str) -> SocketAddr {
        text.parse().unwrap()
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

    /// Candidates for [`pair_among`] on loopback: the first `blocked` ones
    /// with their neighbor taken (bound into `held`), then any; each one's
    /// port goes to `tried`. One closure type for every test, so one
    /// instance of [`pair_among`] serves them all.
    fn candidates<'a>(
        blocked: usize,
        held: &'a mut Vec<StdUdpSocket>,
        tried: &'a mut Vec<u16>,
    ) -> impl FnMut() -> io::Result<StdUdpSocket> + 'a {
        move || {
            let first = if tried.len() < blocked {
                blocked_candidate(held)?
            } else {
                StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?
            };
            tried.push(first.local_addr()?.port());
            Ok(first)
        }
    }

    #[test]
    fn rfc3550_11_a_taken_neighbor_moves_the_pair_to_another_candidate() {
        traced();
        let (mut held, mut tried) = (Vec::new(), Vec::new());
        let (media, control) = pair_among(candidates(1, &mut held, &mut tried))
            .expect("another candidate completes a pair");
        let (even, odd) = (
            media.local_addr().unwrap().port(),
            control.local_addr().unwrap().port(),
        );
        assert_eq!((even % 2, odd), (0, even + 1));
        assert_ne!(even / 2, tried[0] / 2, "not the blocked candidate's pair");
    }

    #[test]
    fn rfc3550_11_a_pair_takes_its_last_try_then_gives_up_and_a_failed_bind_at_once() {
        traced();
        let (mut held, mut ports) = (Vec::new(), Vec::new());
        let err = pair_among(candidates(PAIR_TRIES, &mut held, &mut ports)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
        assert_eq!(ports.len(), PAIR_TRIES);
        // The candidates tried stay bound until the end: each try a new port.
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), PAIR_TRIES);
        // The last try may still complete a pair.
        let mut tries = Vec::new();
        let (media, _control) = pair_among(candidates(PAIR_TRIES - 1, &mut held, &mut tries))
            .expect("the last candidate's pair");
        assert_eq!(tries.len(), PAIR_TRIES);
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

    #[test]
    fn rfc3550_5_1_late_packets_go_on_and_strangers_are_refused() {
        let mut check = Check::new(ip("127.0.0.1"), Some(6970));
        let camera = from("127.0.0.1:6970");
        assert_eq!(
            check.judge(false, camera, &[0x80; 11]),
            Verdict::Refused("not an RTP packet")
        );
        let mut v1 = rtp(1, 7);
        v1[0] = 0x40;
        assert_eq!(
            check.judge(false, camera, &v1),
            Verdict::Refused("not an RTP packet")
        );
        // Padding that claims more than the packet holds: retina's own
        // check refuses it.
        let mut padded = rtp(1, 7);
        padded[0] |= 0x20;
        *padded.last_mut().unwrap() = 0xff;
        assert_eq!(
            check.judge(false, camera, &padded),
            Verdict::Refused("not an RTP packet")
        );
        assert_eq!(check.judge(false, camera, &rtp(10, 7)), Verdict::Pass);
        assert_eq!(
            check.judge(false, camera, &rtp(11, 8)),
            Verdict::Refused("from another synchronization source")
        );
        assert_eq!(
            check.judge(false, camera, &rtp(10, 7)),
            Verdict::Late,
            "a duplicate"
        );
        assert_eq!(check.judge(false, camera, &rtp(12, 7)), Verdict::Pass);
        assert_eq!(
            check.judge(false, camera, &rtp(11, 7)),
            Verdict::Late,
            "late"
        );
        assert_eq!(
            check.judge(false, camera, &rtp(500, 7)),
            Verdict::Pass,
            "a gap"
        );
        // MAX_MISORDER behind is a stray, not a reordering.
        assert_eq!(
            check.judge(false, camera, &rtp(500 - MAX_MISORDER + 1, 7)),
            Verdict::Late
        );
        assert_eq!(
            check.judge(false, camera, &rtp(500 - MAX_MISORDER, 7)),
            Verdict::Pass
        );
        // Across the wrap.
        let mut check = Check::new(ip("127.0.0.1"), Some(6970));
        assert_eq!(check.judge(false, camera, &rtp(0xffff, 1)), Verdict::Pass);
        assert_eq!(check.judge(false, camera, &rtp(0, 1)), Verdict::Pass);
        assert_eq!(check.judge(false, camera, &rtp(0xfffe, 1)), Verdict::Late);
    }

    #[test]
    fn rfc3550_a_1_a_stray_leaves_the_highest_and_two_in_a_row_restart_the_sequence() {
        let mut check = Check::new(ip("127.0.0.1"), None);
        let camera = from("127.0.0.1:6970");
        let mut judge = |seq| check.judge(false, camera, &rtp(seq, 7));
        assert_eq!(judge(1000), Verdict::Pass);
        // Far behind: a stray, and the highest stays 1000.
        assert_eq!(judge(500), Verdict::Pass);
        assert_eq!(judge(999), Verdict::Late, "still behind 1000");
        // Far ahead: a stray too.
        assert_eq!(judge(1000 + MAX_DROPOUT), Verdict::Pass);
        assert_eq!(judge(1001), Verdict::Pass, "the highest moved on from 1000");
        // A stray, then the packet that follows it: the sender restarted.
        assert_eq!(judge(100), Verdict::Pass);
        assert_eq!(judge(101), Verdict::Pass);
        assert_eq!(judge(100), Verdict::Late, "behind the restarted sequence");
        assert_eq!(
            judge(1001),
            Verdict::Pass,
            "the old sequence is a stray now"
        );
    }

    #[test]
    fn rfc3550_8_2_a_new_source_two_packets_in_a_row_ends_the_stream_one_stray_does_not() {
        let mut check = Check::new(ip("127.0.0.1"), None);
        let camera = from("127.0.0.1:6970");
        let refused = Verdict::Refused("from another synchronization source");
        assert_eq!(
            check.judge(false, camera, &rtp(10, 7)),
            Verdict::Pass,
            "locks 7"
        );
        // One stray, then the camera's own again: no switch, and the run
        // starts over.
        assert_eq!(check.judge(false, camera, &rtp(500, 8)), refused);
        assert_eq!(check.judge(false, camera, &rtp(11, 7)), Verdict::Pass);
        assert_eq!(check.judge(false, camera, &rtp(501, 8)), refused);
        // Not in a row: no switch either.
        assert_eq!(check.judge(false, camera, &rtp(503, 8)), refused);
        // Two in a row from the new source.
        assert_eq!(
            check.judge(false, camera, &rtp(504, 8)),
            Verdict::SsrcChanged { from: 7, to: 8 }
        );
    }

    #[test]
    fn rfc4961_3_the_camera_is_heard_only_from_its_media_ports() {
        let report = [0x80, 201, 0, 1, 0, 0, 0, 1];
        let mut check = Check::new(ip("192.0.2.10"), Some(6970));
        let refused = Verdict::Refused("not from the camera's media port");
        assert_eq!(
            check.judge(false, from("192.0.2.10:6970"), &rtp(1, 1)),
            Verdict::Pass
        );
        assert_eq!(
            check.judge(true, from("192.0.2.10:6971"), &report),
            Verdict::Pass
        );
        assert_eq!(
            check.judge(false, from("192.0.2.10:6971"), &rtp(2, 1)),
            refused
        );
        assert_eq!(check.judge(true, from("192.0.2.10:6970"), &report), refused);
        assert_eq!(
            check.judge(false, from("192.0.2.11:6970"), &rtp(2, 1)),
            refused
        );
        // An IPv4-mapped sender is the IPv4 one (RFC 4291 §2.5.5.2), on a
        // pair of the wildcard IPv6 address.
        assert_eq!(
            check.judge(false, from("[::ffff:192.0.2.10]:6970"), &rtp(2, 1)),
            Verdict::Pass
        );
        // No `server_port`: any port of the source's address.
        let mut check = Check::new(ip("2001:db8::10"), None);
        assert_eq!(
            check.judge(false, from("[2001:db8::10]:1"), &rtp(1, 1)),
            Verdict::Pass
        );
        assert_eq!(
            check.judge(true, from("[2001:db8::10]:2"), &report),
            Verdict::Pass
        );
        assert_eq!(
            check.judge(true, from("[2001:db8::11]:2"), &report),
            refused
        );
        assert_eq!(
            check.judge(true, from("[2001:db8::10]:2"), &report[..3]),
            Verdict::Refused("not an RTCP compound packet")
        );
    }

    #[test]
    fn rfc3550_6_1_rtcp_compound_packets_are_framed_as_retina_reads_them() {
        let rr = [0x80, 201, 0, 1, 0, 0, 0, 1];
        let sdes = [0x81, 202, 0, 1, 0, 0, 0, 1];
        assert!(rtcp_compound(&rr));
        assert!(rtcp_compound(&[&rr[..], &sdes[..]].concat()));
        // Padding on the last packet only (§6.4.1).
        let padded = [0xa0, 201, 0, 1, 0, 0, 0, 4];
        assert!(rtcp_compound(&padded));
        assert!(!rtcp_compound(&[&padded[..], &sdes[..]].concat()));
        assert!(!rtcp_compound(&[]));
        assert!(!rtcp_compound(&rr[..3]));
        assert!(!rtcp_compound(&[0x40, 201, 0, 1, 0, 0, 0, 1]));
        // A length past the datagram, and a second packet cut short.
        assert!(!rtcp_compound(&[0x80, 201, 0, 2, 0, 0, 0, 1]));
        assert!(!rtcp_compound(&[&rr[..], &sdes[..6]].concat()));
    }

    #[test]
    fn a_datagram_is_written_across_the_receive_buffers_wrap() {
        let mut buf = MarkBuf::new(16);
        put(&mut buf, &[1; 12]);
        buf.advance_end(12);
        buf.advance_unparsed(12);
        let datagram: Vec<u8> = (2..12).collect();
        put(&mut buf, &datagram);
        buf.advance_end(datagram.len());
        let written = buf.split(12, datagram.len());
        assert_eq!(written.to_vec(), datagram);
        let (first, second) = written.slices();
        assert_eq!((first.len(), second.len()), (4, 6), "wrapped");
        // Contiguous room takes it whole.
        let mut buf = MarkBuf::new(16);
        put(&mut buf, &datagram);
        buf.advance_end(datagram.len());
        assert_eq!(buf.split(0, datagram.len()).to_vec(), datagram);
    }

    #[test]
    fn a_pair_that_cannot_be_bound_fails_the_attempt_as_unreachable() {
        traced();
        // TEST-NET-1 (RFC 5737 §3): no host has it, nothing binds there.
        let err = Pair::bind_on(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).unwrap_err();
        assert!(
            matches!(&err, SourceError::Unreachable(m) if m.starts_with("rtsp udp: no RTP/RTCP port pair")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn rfc1122_3_2_1_3_a_refused_source_keeps_nothing_and_an_accepted_one_is_heard() {
        traced();
        let mut streams = Streams::new(ip("192.0.2.10"));
        let pair = Pair::bind(ip("127.0.0.1")).unwrap();
        assert_eq!(pair.port() % 2, 0);
        let err = streams
            .answered(0, pair, ip("127.0.0.1"), Some(6970))
            .unwrap_err();
        assert!(
            matches!(&err, SourceError::Protocol(m)
                if m.contains("source 127.0.0.1") && m.contains("loopback")
                    && m.contains("RFC 1122 §3.2.1.3")),
            "{err:?}"
        );
        assert!(streams.pairs.is_empty() && streams.datagram.is_empty());
        // Another host of the camera's family is taken at its word; a
        // stream set up again replaces its pair.
        for _ in 0..2 {
            let pair = Pair::bind(ip("127.0.0.1")).unwrap();
            streams.answered(1, pair, ip("192.0.2.11"), None).unwrap();
        }
        assert_eq!(streams.pairs.len(), 1);
        let (index, stream) = &streams.pairs[0];
        assert_eq!((*index, stream.check.source), (1, ip("192.0.2.11")));
        assert_eq!(streams.datagram.len(), MAX_DATAGRAM);
        assert!(format!("{streams:?}").starts_with("Streams"));
    }

    #[tokio::test]
    async fn datagrams_wait_in_the_sockets_until_the_session_plays() {
        traced();
        let mut streams = Streams::new(ip("127.0.0.1"));
        let pair = Pair::bind(ip("127.0.0.1")).unwrap();
        let port = pair.port();
        streams.answered(0, pair, ip("127.0.0.1"), None).unwrap();
        let camera = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        camera.send_to(&rtp(1, 1), ("127.0.0.1", port)).unwrap();
        let mut core = SessionCore::new(
            from("127.0.0.1:50000"),
            from("127.0.0.1:554"),
            SessionOptions::default(),
        );
        // A session not playing has no buffers to read into.
        let now = SystemClock.now();
        let polled = poll_fn(|cx| Poll::Ready(streams.poll_recv(cx, &mut core, now))).await;
        assert!(polled.is_pending());
        // Once it plays, the datagram that waited reaches it.
        let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
            m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track0\r\n";
        core.describe(url::Url::parse("rtsp://127.0.0.1:554/").unwrap())
            .unwrap();
        answer(
            &mut core,
            &format!(
                "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Base: rtsp://127.0.0.1:554/\r\n\
                 Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                sdp.len()
            ),
        );
        let transport = retina::client::SetupTransport::Udp {
            client_rtp_port: port,
            options: udp_options(),
        };
        core.setup(0, transport).unwrap();
        answer(
            &mut core,
            &format!(
                "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 1;timeout=60\r\n\
                 Transport: RTP/AVP/UDP;unicast;client_port={port}-{}\r\n\r\n",
                port + 1
            ),
        );
        core.play(crate::source::play_options()).unwrap();
        answer(
            &mut core,
            "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 1\r\n\r\n",
        );
        let polled = poll_fn(|cx| streams.poll_recv(cx, &mut core, now)).await;
        assert!(polled.is_ok());
        let item = core.poll_item(now).unwrap().unwrap();
        assert!(
            matches!(item, retina::client::PlayingItem::Rtp(ref packet) if packet.packet().meta.sequence_number == 1),
            "{item:?}"
        );
    }

    /// Hands `core` the camera's `response` to the request it wrote.
    fn answer(core: &mut SessionCore, response: &str) {
        let (first, second) = core.transmit_buf();
        let written = first.len() + second.len();
        core.advance_transmit(written);
        core.read_buf().extend(response.as_bytes());
        core.poll_event(SystemClock.now()).unwrap().unwrap();
    }
}

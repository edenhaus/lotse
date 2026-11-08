//! The I/O of retina's sans-I/O RTSP client on a connection the source
//! owns: [`Driver`] writes what retina's [`SessionCore`] has to send,
//! reads what the camera sends into its buffer, and keeps its time, on
//! the injected clock; once the session is over, [`Driver::teardown`]
//! drives retina's [`TeardownCore`], on fresh connections the source
//! dials when retina asks for one.
//!
//! The source dials the camera itself, TCP for `rtsp` and the TLS stream
//! of `lotse_tls` over it for `rtsps` (RFC 7826 §19.2), so retina sees
//! neither sockets nor TLS: it is handed the bytes and the times. The
//! requests carry the source URL itself as their Request-URI (RFC 2326
//! §6.1, RFC 7826 §19.2), `rtsps` included.
//!
//! One request at a time ([`Driver::describe`], [`Driver::setup`],
//! [`Driver::play`]) is driven to its answer; the caller bounds it with
//! its read deadline, and dropping it there leaves the core consistent:
//! bytes count as written only once the connection took them. While the
//! session plays, [`Driver::next_item`] copies each packet out of retina's
//! buffer ([`Received`]), which a [`PlayingItem`] only borrows until the
//! core is polled again, and sends the keepalives and receiver reports
//! retina schedules (RFC 2326 §10.8 and §12.37, RFC 3550 §6.4.2) when
//! they are due.
//!
//! Nothing here caps an outgoing request: retina writes the request whole,
//! and what bounds it is what goes into it, the source URL (the control
//! API's `MAX_URL_CHARS`, 4096 characters) and the `user_agent`
//! ([`crate::options::MAX_USER_AGENT_LEN`]). What the camera sends is
//! bounded by retina, at most [`crate::source::MAX_MESSAGE`] bytes of one
//! message (`SessionOptions::max_message_size`).
//!
//! A teardown runs under a [`Budget`]: the attempt on the session's own
//! connection is bounded tightly, and only when retina retries on a fresh
//! connection does the bound grow, so that a dial and a TLS handshake fit.
//! retina retries on a fresh connection only once the session's own one
//! closed or failed; one that stalls silently keeps the tight bound, and
//! the session is left to expire on the camera, by design. A
//! cancellation, before the teardown or during it, bounds what is left at
//! the tight bound from then on, fresh connections included, so the
//! source honors its cancel within the source contract's 100 ms.
//!
//! RTP over UDP plugs in beside [`Driver::next_item`]'s exchange on the
//! connection: [`Driver::setup_udp`] asks for it with a pair the source
//! bound, the driver sends what the core queues for the pairs (the hole
//! punches right after the `SETUP` answer, the receiver reports while
//! playing) and hands the core what they receive, once [`crate::udp`]'s
//! checks passed it, in the same poll as the connection's bytes. The ONVIF
//! backchannel's packets go out the same way, on the same core and
//! connection ([`Driver::queue_rtp`]).

use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::FutureExt as _;
use lotse_core::clock::Clock;
use lotse_core::ingest::IngestCounters;
use lotse_core::source::SourceError;
use lotse_core::source_url::SourceUrl;
use lotse_core::task::BoxFuture;
use retina::buf::MarkBuf;
use retina::client::{
    PlayOptions, PlayingItem, RtpPacket, SessionCore, SessionEvent, SessionOptions, SetupTransport,
    Stream, TeardownAction, TeardownCore, UdpPeer,
};
use retina::rtp::Continuity;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::error::classify;
use crate::udp::{Pair, Streams, udp_options};

/// How much free space a read from the camera asks of retina's buffer at
/// least: 16 KiB.
const READ_RESERVE: usize = 16_384;

/// The reads, at most, of what is already waiting on the connection before
/// due timers run ([`Driver::read_ready`]): a read gets the free space of
/// retina's ring up to its end only, which at its wrap may be a few bytes;
/// the second then starts at the ring's beginning, with at least
/// [`READ_RESERVE`] in one piece. Bounded, so a camera whose connection
/// never runs dry cannot hold the timers off.
const READS_BEFORE_TIMERS: usize = 2;

/// A connection to the camera, plain TCP or TLS over it.
pub(crate) trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A connection the source dialed, with the addresses of its two ends,
/// which retina names in its errors.
pub(crate) struct Connection {
    /// The stream.
    pub(crate) stream: Box<dyn Duplex>,
    /// The local end.
    pub(crate) local: SocketAddr,
    /// The camera's end.
    pub(crate) peer: SocketAddr,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Dials a fresh connection to the camera, as the session's was dialed:
/// for the retries of a `TEARDOWN` ([`TeardownAction::Connect`]).
pub(crate) type Dial<'a> =
    dyn Fn() -> BoxFuture<'static, Result<Connection, SourceError>> + Sync + 'a;

/// Why the driven session failed.
///
/// A TLS stream takes a write once rustls buffered its plaintext, so a
/// camera that stopped reading surfaces as a keepalive it never answered
/// (`Session`), seldom as `Write`.
#[derive(Debug)]
pub(crate) enum Error {
    /// retina's: a refused or unreadable answer, a read that failed or
    /// ended mid-request, a keepalive unanswered.
    Session(retina::client::Error),
    /// Writing to the camera failed.
    Write(io::Error),
    /// The camera closed the connection, and every packet before its
    /// close was handed out. A TLS camera that drops its TCP connection
    /// without `close_notify` (RFC 8446 §6.1) ends here too.
    Closed,
    /// [`Driver::next_item`] was asked before `PLAY` was answered.
    NotPlaying,
    /// The camera's answer was refused here: a UDP `source` no camera can
    /// send from ([`crate::udp`]).
    Refused(SourceError),
    /// A `SETUP` named a stream the description does not have (none before
    /// `DESCRIBE`): retina would index past its streams.
    UnknownStream(usize),
}

impl Error {
    /// The error as the source reports it for `url`: retina's classified
    /// ([`classify`]), the connection's own as `ended`.
    pub(crate) fn source_error(&self, url: &SourceUrl) -> SourceError {
        match self {
            Self::Session(err) => classify(err, url),
            Self::Write(err) => SourceError::Ended(format!("writing to the camera failed: {err}")),
            Self::Closed => SourceError::Ended("the camera closed the session".into()),
            Self::NotPlaying => SourceError::Protocol("rtsp: no packets before PLAY".into()),
            Self::Refused(err) => err.clone(),
            Self::UnknownStream(index) => SourceError::Protocol(format!(
                "rtsp: no stream {index} in the camera's description"
            )),
        }
    }

    /// The RTSP status of a refused request, if it is one.
    pub(crate) fn status_code(&self) -> Option<u16> {
        match self {
            Self::Session(err) => err.status_code(),
            Self::Write(_)
            | Self::Closed
            | Self::NotPlaying
            | Self::Refused(_)
            | Self::UnknownStream(_) => None,
        }
    }
}

/// One RTP packet as the source keeps it: the header fields it reads and
/// the payload, copied out of retina's receive buffer, which a
/// [`PlayingItem`] borrows only until the session is polled again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Received {
    /// The index of its stream among the session's.
    pub(crate) stream: usize,
    /// The RTP timestamp, as sent (RFC 3550 §5.1).
    pub(crate) ts: u32,
    /// The sequence number.
    pub(crate) seq: u16,
    /// The synchronization source.
    pub(crate) ssrc: u32,
    /// The marker bit.
    pub(crate) marker: bool,
    /// The packets the sequence numbers say were lost just before it (RFC
    /// 3550 §6.4.1); none after a sequence restart, which retina warns
    /// about and whose loss nobody can count.
    pub(crate) loss: u16,
    /// The payload.
    pub(crate) payload: Bytes,
}

impl Received {
    /// What the source keeps of `packet`.
    pub(crate) fn new(packet: &RtpPacket<'_>) -> Self {
        let meta = &packet.packet().meta;
        let loss = match meta.continuity {
            Continuity::Lost(lost) => lost.get(),
            Continuity::Contiguous | Continuity::Discontinuity => 0,
        };
        Self {
            stream: packet.stream_id(),
            ts: raw_timestamp(meta.timestamp),
            seq: meta.sequence_number,
            ssrc: meta.ssrc,
            marker: meta.mark,
            loss,
            payload: Bytes::from(packet.packet().payload().to_vec()),
        }
    }
}

/// The raw 32-bit RTP timestamp of a packet, as the header carried it.
pub(crate) fn raw_timestamp(ts: retina::Timestamp) -> u32 {
    u32::try_from(ts.timestamp().rem_euclid(1_i64 << 32)).unwrap_or(0)
}

/// What a playing session hands out, owned.
#[derive(Debug)]
pub(crate) enum Item {
    /// An RTP packet, copied.
    Rtp(Received),
    /// An RTCP compound packet (RFC 3550 §6.1).
    Rtcp(retina::rtcp::ReceivedCompoundPacket),
}

/// What the source keeps of a playing session's `item`, copied out of
/// retina's buffer; nothing for no item, or for an item kind a later
/// retina may add, which carries nothing the source reads.
pub(crate) fn copied(item: Option<PlayingItem<'_>>) -> Option<Item> {
    match item {
        Some(PlayingItem::Rtp(packet)) => Some(Item::Rtp(Received::new(&packet))),
        Some(PlayingItem::Rtcp(compound)) => Some(Item::Rtcp(compound)),
        _ => None,
    }
}

/// A retina core with bytes to write to the connection and a buffer to
/// read into: the session's, and its teardown's.
trait Exchange: Send {
    /// The bytes to write, in order; the first slice is empty when there
    /// are none.
    fn transmit_buf(&self) -> (&[u8], &[u8]);
    /// The first `n` of them were written.
    fn advance_transmit(&mut self, n: usize);
    /// Where the connection's bytes go.
    fn read_buf(&mut self) -> &mut MarkBuf;
    /// The camera closed the connection.
    fn handle_eof(&mut self);
}

impl Exchange for SessionCore {
    fn transmit_buf(&self) -> (&[u8], &[u8]) {
        Self::transmit_buf(self)
    }

    fn advance_transmit(&mut self, n: usize) {
        Self::advance_transmit(self, n);
    }

    fn read_buf(&mut self) -> &mut MarkBuf {
        Self::read_buf(self)
    }

    fn handle_eof(&mut self) {
        Self::handle_eof(self);
    }
}

impl Exchange for TeardownCore {
    fn transmit_buf(&self) -> (&[u8], &[u8]) {
        Self::transmit_buf(self)
    }

    fn advance_transmit(&mut self, n: usize) {
        Self::advance_transmit(self, n);
    }

    fn read_buf(&mut self) -> &mut MarkBuf {
        Self::read_buf(self)
    }

    fn handle_eof(&mut self) {
        Self::handle_eof(self);
    }
}

/// Which side of an exchange failed.
#[derive(Debug)]
enum Failed {
    /// Reading from the camera.
    Read(io::Error),
    /// Writing or flushing to the camera, or a write that took nothing.
    Write(io::Error),
}

impl Failed {
    /// The I/O error, whichever side it came from.
    fn into_io(self) -> io::Error {
        match self {
            Self::Read(err) | Self::Write(err) => err,
        }
    }
}

/// One exchange on `conn` for `core`: writes what the core has to send as
/// far as the connection takes it, flushes, then completes once one read
/// returned bytes, or the camera's close, which the core is told of.
async fn exchange(conn: &mut dyn Duplex, core: &mut dyn Exchange) -> Result<(), Failed> {
    poll_fn(|cx| poll_exchange(cx, conn, core)).await
}

/// [`exchange`] as a poll.
fn poll_exchange(
    cx: &mut Context<'_>,
    conn: &mut dyn Duplex,
    core: &mut dyn Exchange,
) -> Poll<Result<(), Failed>> {
    let mut conn = Pin::new(conn);
    loop {
        let (first, second) = core.transmit_buf();
        if first.is_empty() {
            break;
        }
        let bufs = [IoSlice::new(first), IoSlice::new(second)];
        match conn.as_mut().poll_write_vectored(cx, &bufs) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(Failed::Write(io::ErrorKind::WriteZero.into())));
            }
            Poll::Ready(Ok(n)) => core.advance_transmit(n),
            Poll::Ready(Err(err)) => return Poll::Ready(Err(Failed::Write(err))),
            Poll::Pending => break,
        }
    }
    // A TLS stream holds what it took until it is flushed.
    if let Poll::Ready(Err(err)) = conn.as_mut().poll_flush(cx) {
        return Poll::Ready(Err(Failed::Write(err)));
    }
    // The first slice is never empty: retina's ring returns at least the
    // reserve, the part up to its end first.
    let (spare, _) = core.read_buf().spare_capacity(READ_RESERVE);
    let mut buf = ReadBuf::new(spare);
    match conn.poll_read(cx, &mut buf) {
        Poll::Ready(Ok(())) => {
            let n = buf.filled().len();
            if n == 0 {
                core.handle_eof();
            } else {
                core.read_buf().advance_end(n);
            }
            Poll::Ready(Ok(()))
        }
        // A TLS peer that closed TCP without `close_notify` (RFC 8446
        // §6.1): the camera is gone all the same.
        Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {
            core.handle_eof();
            Poll::Ready(Ok(()))
        }
        Poll::Ready(Err(err)) => Poll::Ready(Err(Failed::Read(err))),
        Poll::Pending => Poll::Pending,
    }
}

/// The camera's media address a `SETUP` answer names for a UDP stream;
/// none for any other event.
fn udp_peer(event: &SessionEvent) -> Option<UdpPeer> {
    match event {
        SessionEvent::SetUp { udp_peer, .. } => *udp_peer,
        _ => None,
    }
}

/// The session's error for a failed exchange of `core` on the clock `time`:
/// a read as retina words it, with the connection's context.
fn failure(core: &SessionCore, time: &dyn Clock, failed: Failed) -> Error {
    match failed {
        Failed::Read(err) => Error::Session(core.read_error(err, time.now())),
        Failed::Write(err) => Error::Write(err),
    }
}

/// One round of a playing session's I/O: [`poll_exchange`] on `conn`,
/// then the datagrams of the UDP streams ([`Streams::poll_recv`]), each
/// time both, so neither waits for the other; ready once either made
/// progress or failed.
fn poll_media(
    cx: &mut Context<'_>,
    conn: &mut dyn Duplex,
    core: &mut SessionCore,
    udp: &mut Streams,
    time: &dyn Clock,
) -> Poll<Result<(), Error>> {
    let exchanged = poll_exchange(cx, conn, core);
    if let Poll::Ready(Err(failed)) = exchanged {
        return Poll::Ready(Err(failure(core, time, failed)));
    }
    let received = udp.poll_recv(cx, core, time.now());
    if let Poll::Ready(Err(err)) = received {
        return Poll::Ready(Err(err));
    }
    if exchanged.is_ready() || received.is_ready() {
        Poll::Ready(Ok(()))
    } else {
        Poll::Pending
    }
}

/// retina's [`SessionCore`] on one connection to the camera, on the
/// injected clock.
pub(crate) struct Driver {
    /// The session's protocol state.
    core: SessionCore,
    /// The connection the session runs on.
    conn: Box<dyn Duplex>,
    /// The clock every instant the core is given comes from, and its
    /// timers.
    time: Arc<dyn Clock>,
    /// The pairs of the streams set up over UDP.
    udp: Streams,
    /// The reads that come before due timers were made
    /// ([`Driver::read_ready`]): the timers run at the next call that finds
    /// nothing buffered, whether the connection has more or not. Cleared
    /// once they ran, or are no longer due.
    read_before_timers: bool,
}

impl fmt::Debug for Driver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Driver")
            .field("playing", &self.core.is_playing())
            .field("closed", &self.core.is_closed())
            .finish_non_exhaustive()
    }
}

impl Driver {
    /// A session with `options` on `conn`, newly dialed.
    pub(crate) fn new(conn: Connection, options: SessionOptions, time: Arc<dyn Clock>) -> Self {
        Self {
            core: SessionCore::new(conn.local, conn.peer, options),
            udp: Streams::new(conn.peer.ip()),
            conn: conn.stream,
            time,
            read_before_timers: false,
        }
    }

    /// Counts the datagrams refused, and the packets that came late, of the
    /// streams set up over UDP into `ingest`.
    pub(crate) fn count_udp_into(&mut self, ingest: Arc<IngestCounters>) {
        self.udp.count_into(ingest);
    }

    /// The streams the `DESCRIBE` answer described; none before it.
    pub(crate) fn streams(&self) -> &[Stream] {
        self.core.streams()
    }

    /// The raw SDP of the `DESCRIBE` answer; empty before it.
    pub(crate) fn sdp(&self) -> &[u8] {
        self.core.sdp()
    }

    /// Queues `packet` on the stream at `index`, one the session sends on
    /// (the ONVIF backchannel, ONVIF Streaming Specification §5.3), on its
    /// interleaved RTP channel (RFC 2326 §10.12); [`Driver::next_item`]
    /// writes it. Nothing bounds the queue: the caller checks
    /// [`Driver::queued_len`] first. retina's error, nothing queued, when
    /// the session does not play or the stream takes no data.
    pub(crate) fn queue_rtp(
        &mut self,
        index: usize,
        packet: &retina::rtp::OutgoingPacketRef<'_>,
    ) -> Result<(), Error> {
        self.core.queue_rtp(index, packet).map_err(Error::Session)
    }

    /// Queues the RTCP compound `packet` (RFC 3550 §6.1), a Sender Report,
    /// on the RTCP channel of the stream at `index` the session sends on,
    /// as [`Driver::queue_rtp`] does.
    pub(crate) fn queue_rtcp(&mut self, index: usize, packet: &[u8]) -> Result<(), Error> {
        self.core.queue_rtcp(index, packet).map_err(Error::Session)
    }

    /// How many bytes wait for the camera to take them: requests and
    /// queued packets alike.
    pub(crate) fn queued_len(&self) -> usize {
        self.core.queued_len()
    }

    /// `DESCRIBE` of `url`, which carries no credentials (RFC 2326 §10.2).
    pub(crate) async fn describe(&mut self, url: Url) -> Result<(), Error> {
        self.core.describe(url).map_err(Error::Session)?;
        self.request().await?;
        Ok(())
    }

    /// `SETUP` of the stream at `index` among [`Driver::streams`], TCP
    /// interleaved (RFC 2326 §10.4, §10.12).
    pub(crate) async fn setup(&mut self, index: usize) -> Result<(), Error> {
        self.described(index)?;
        self.core
            .setup(index, SetupTransport::Tcp)
            .map_err(Error::Session)?;
        self.request().await?;
        Ok(())
    }

    /// `SETUP` of the stream at `index` among [`Driver::streams`], RTP over
    /// UDP to `pair` (RFC 2326 §10.4, §12.39), without a reorder buffer
    /// ([`udp_options`]). Once answered, the source the answer names is
    /// checked before anything is sent there ([`Error::Refused`]), then the
    /// hole punches retina queued go out; the pair receives once the
    /// session plays.
    pub(crate) async fn setup_udp(&mut self, index: usize, pair: Pair) -> Result<(), Error> {
        let transport = SetupTransport::Udp {
            client_rtp_port: pair.port(),
            options: udp_options(),
        };
        self.described(index)?;
        self.core.setup(index, transport).map_err(Error::Session)?;
        let peer = udp_peer(&self.request().await?);
        self.udp
            .set_up(index, pair, peer.as_ref())
            .map_err(Error::Refused)?;
        self.send_udp();
        Ok(())
    }

    /// [`Error::UnknownStream`] unless the description has a stream at
    /// `index`: retina's `setup` indexes its streams unchecked.
    fn described(&self, index: usize) -> Result<(), Error> {
        self.streams()
            .get(index)
            .map(|_| ())
            .ok_or(Error::UnknownStream(index))
    }

    /// Sends every datagram the core queued for the pairs.
    fn send_udp(&mut self) {
        let now = self.time.now();
        while let Some(transmit) = self.core.poll_transmit_udp() {
            self.udp.send(&transmit, now);
        }
    }

    /// `PLAY` of the whole presentation (RFC 2326 §10.5) with `options`.
    pub(crate) async fn play(&mut self, options: PlayOptions) -> Result<(), Error> {
        self.core.play(options).map_err(Error::Session)?;
        self.request().await?;
        Ok(())
    }

    /// Exchanges with the camera until the request in flight is answered.
    async fn request(&mut self) -> Result<SessionEvent, Error> {
        loop {
            if let Some(event) = self.core.poll_event(self.time.now()) {
                return event.map_err(Error::Session);
            }
            if let Err(failed) = exchange(&mut *self.conn, &mut self.core).await {
                return Err(self.failure(failed));
            }
        }
    }

    /// The session's error for a failed exchange: a read as retina words
    /// it, with the connection's context.
    fn failure(&self, failed: Failed) -> Error {
        failure(&self.core, &*self.time, failed)
    }

    /// One round of the playing session's I/O ([`poll_media`]): the
    /// connection's exchange and the pairs' datagrams.
    fn media(&mut self) -> impl Future<Output = Result<(), Error>> + '_ {
        let Self {
            core,
            conn,
            time,
            udp,
            ..
        } = self;
        poll_fn(move |cx| poll_media(cx, &mut **conn, core, udp, &**time))
    }

    /// The next item of a playing session, once one arrived: every item
    /// already buffered first (a keepalive's answer among them, which the
    /// core takes in), then what already waits on the connection, at most
    /// [`READS_BEFORE_TIMERS`] reads, then the timers, so an answer that
    /// arrived by its deadline still counts and neither the connection nor
    /// the UDP pairs can hold the timers off; keepalives and receiver
    /// reports go out when retina has them due, and the camera's bytes and
    /// datagrams are read meanwhile. Each item handed out spends
    /// a unit of tokio's task budget, so a burst yields to the runtime as
    /// reads would. [`Error::Closed`] once the camera closed the
    /// connection and every item before was handed out, its datagrams
    /// still arriving or not; [`Error::NotPlaying`] before
    /// `PLAY` was answered.
    pub(crate) async fn next_item(&mut self) -> Result<Item, Error> {
        if !self.core.is_playing() {
            return Err(Error::NotPlaying);
        }
        loop {
            let now = self.time.now();
            // An item kind a later retina may add carries nothing the
            // source reads: the next one is parsed.
            let mut item = None;
            let mut polled = true;
            while item.is_none() && polled {
                let next = self
                    .core
                    .poll_item(now)
                    .transpose()
                    .map_err(Error::Session)?;
                polled = next.is_some();
                item = copied(next);
            }
            if let Some(item) = item {
                // An item already buffered needs no read, so a burst
                // that arrived at once (a keyframe of thousands of
                // packets) would be handed out without an await point
                // that yields: one unit of tokio's budget per item lets
                // the runtime's other tasks run as often as a task doing
                // real I/O does (tokio 1.54.1,
                // `tokio::task::consume_budget`), the session that
                // takes the packets from the track among them.
                tokio::task::consume_budget().await;
                return Ok(item);
            }
            if self.core.is_closed() {
                return Err(Error::Closed);
            }
            // What already arrived on the connection is taken in before
            // the timers: a keepalive's answer waiting in the socket at its
            // deadline still counts. Bounded reads only, and what they
            // parsed handed out: a camera whose connection never runs dry
            // would otherwise hold the keepalive and the receiver reports
            // off for good (retina's own driver reads until nothing is left
            // first). The UDP pairs carry no answer, so their datagrams
            // wait until the timers ran: a stream that never pauses would
            // hold them off too.
            let due = self.core.poll_timeout().unwrap_or(now) <= now;
            let ready = if due && !self.read_before_timers {
                self.read_ready()
            } else {
                None
            };
            self.read_before_timers = ready.is_some();
            let io = if let Some(exchanged) = ready {
                exchanged.map_err(|failed| self.failure(failed))
            } else {
                if due {
                    self.core.handle_timeout(now).map_err(Error::Session)?;
                    self.send_udp();
                }
                let next = self.core.poll_timeout().unwrap_or(now);
                let wait = self.time.sleep(next.saturating_duration_since(now));
                tokio::select! {
                    io = self.media() => io,
                    () = wait => Ok(()),
                }
            };
            io?;
        }
    }

    /// Reads what is already waiting on the connection, without waiting:
    /// at most [`READS_BEFORE_TIMERS`] reads, each written and flushed
    /// first, as [`exchange`] does. `None` when nothing was waiting; the
    /// first failure ends the reads.
    fn read_ready(&mut self) -> Option<Result<(), Failed>> {
        let mut read = None;
        for _ in 0..READS_BEFORE_TIMERS {
            match exchange(&mut *self.conn, &mut self.core).now_or_never() {
                None => break,
                Some(Err(failed)) => return Some(Err(failed)),
                Some(Ok(())) => read = Some(Ok(())),
            }
        }
        read
    }

    /// Ends the session on the camera as retina's teardown policy says
    /// (RFC 2326 §10.7, RFC 7826 §13.7): first on the session's own
    /// connection, then, when the policy retries, on fresh ones from
    /// `dial`, until the camera answered, retina gives up, or `budget`
    /// runs out, which leaves the session to expire on the camera (RFC
    /// 2326 §12.37). Once `cancel` fires, before the teardown or during
    /// it, at most `budget.own` is left from then on and the fresh budget
    /// no longer applies: a dial in progress may finish within it, a
    /// retry beyond it is not waited for. Nothing when no `SETUP`
    /// succeeded. retina words a write that failed during it as a read
    /// from the peer; the attempt's failure is only logged at `debug`, by
    /// retina.
    pub(crate) async fn teardown(
        self,
        dial: &Dial<'_>,
        budget: Budget,
        cancel: &CancellationToken,
    ) {
        let Self {
            core,
            conn,
            time,
            udp,
            ..
        } = self;
        // The camera sends to the pairs no more once torn down, and before
        // nothing reads them.
        drop(udp);
        let start = time.now();
        let Some(mut teardown) = core.into_teardown(start) else {
            tracing::debug!("rtsp: no session to tear down");
            return;
        };
        let mut limit = start.checked_add(budget.own).unwrap_or(start);
        let mut conn = conn;
        let mut fresh = 0_u32;
        // Whether a cancellation has bounded the teardown.
        let mut cut = false;
        // The fresh connection being dialed, kept across a cancellation.
        let mut pending: Option<BoxFuture<'static, Result<Connection, SourceError>>> = None;
        loop {
            let now = time.now();
            if !cut && cancel.is_cancelled() {
                cut = true;
                limit = limit.min(now.checked_add(budget.own).unwrap_or(now));
                tracing::debug!(
                    fresh,
                    budget_ms = budget.own.as_millis(),
                    "rtsp: cancelled; the TEARDOWN gets the cancellation's budget and no fresh one, so the source honors its cancel"
                );
            }
            if now >= limit {
                tracing::debug!(
                    fresh,
                    cancelled = cut,
                    budget_ms = limit.saturating_duration_since(start).as_millis(),
                    "rtsp: TEARDOWN still pending after its budget; the session is left to expire"
                );
                return;
            }
            match teardown.poll(now) {
                TeardownAction::Io { deadline } => {
                    let wait = pause(&*time, cancel, cut, now, deadline.min(limit));
                    let failed = tokio::select! {
                        exchanged = exchange(&mut *conn, &mut teardown) => exchanged.err().map(Failed::into_io),
                        () = wait => None,
                    };
                    if let Some(err) = failed {
                        teardown.handle_io_error(err, time.now());
                    }
                }
                TeardownAction::Connect { deadline } => {
                    if pending.is_none() {
                        conn = closed();
                        fresh = fresh.saturating_add(1);
                        if !cut {
                            limit = limit.max(start.checked_add(budget.fresh).unwrap_or(start));
                        }
                        tracing::debug!(
                            fresh,
                            deadline_ms = deadline.saturating_duration_since(now).as_millis(),
                            "rtsp: TEARDOWN on a fresh connection"
                        );
                    }
                    let dialing = pending.get_or_insert_with(dial);
                    let wait = pause(&*time, cancel, cut, now, deadline.min(limit));
                    let dialed = tokio::select! {
                        dialed = dialing => Some(dialed),
                        () = wait => None,
                    };
                    match dialed {
                        Some(Ok(dialed)) => {
                            pending = None;
                            teardown.connected(dialed.local, dialed.peer, time.now());
                            conn = dialed.stream;
                        }
                        Some(Err(err)) => {
                            pending = None;
                            tracing::debug!(fresh, error = %err, "rtsp: TEARDOWN connection failed");
                            teardown.handle_io_error(io::Error::other(err.to_string()), time.now());
                        }
                        // At its deadline the next poll fails the attempt as
                        // timed out, and a retry dials anew; cut short by a
                        // cancellation, the dial goes on within its budget.
                        None => {
                            if time.now() >= deadline {
                                pending = None;
                            }
                        }
                    }
                }
                TeardownAction::Wait { until } => {
                    conn = closed();
                    pause(&*time, cancel, cut, now, until.min(limit)).await;
                }
                // Done, or an action a later retina may add, which this
                // driver cannot follow.
                _ => {
                    tracing::debug!(fresh, "rtsp: TEARDOWN over");
                    return;
                }
            }
        }
    }
}

/// Sleeps on `time` from `now` until `until`, or until `cancel` fires
/// unless a cancellation already bounded the teardown (`cut`): the
/// teardown's waits, cut short by a cancel so that its budget shrinks at
/// once.
async fn pause(
    time: &dyn Clock,
    cancel: &CancellationToken,
    cut: bool,
    now: Instant,
    until: Instant,
) {
    tokio::select! {
        () = time.sleep(until.saturating_duration_since(now)) => {}
        () = cancel.cancelled(), if !cut => {}
    }
}

/// How long a teardown may take: `own` while it tries the session's own
/// connection, `fresh` (from its start, never less than `own`) once retina
/// retries on fresh connections, which take a dial and, for `rtsps`, a
/// TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Budget {
    /// The bound while the session's own connection is tried.
    pub(crate) own: Duration,
    /// The bound once a fresh connection is dialed.
    pub(crate) fresh: Duration,
}

/// What stands in for a connection the teardown closed (by dropping it)
/// until retina has the next one dialed: it reads as closed and takes every
/// write, and retina does no I/O on it.
fn closed() -> Box<dyn Duplex> {
    Box::new(tokio::io::empty())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use std::net::IpAddr;

    use lotse_core::clock::FakeClock;
    use lotse_core::ingest::IngestStats;
    use retina::client::{ReceiverReportPolicy, TeardownPolicy};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

    use super::*;
    use crate::source::play_options;

    const SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
        m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track0\r\n";
    const SSRC: u32 = 0x1234_5678;

    /// Every log line's fields are evaluated, as at `trace`, on this
    /// thread; the lines go nowhere.
    fn traced() -> tracing::subscriber::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(io::sink)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    /// The camera's side of a connection: requests read whole.
    struct Cam {
        io: DuplexStream,
        buf: Vec<u8>,
    }

    impl Cam {
        fn new(io: DuplexStream) -> Self {
            Self {
                io,
                buf: Vec::new(),
            }
        }

        /// The head of the next request.
        async fn request(&mut self) -> String {
            loop {
                if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head: Vec<u8> = self.buf.drain(..end + 4).collect();
                    return String::from_utf8(head).unwrap();
                }
                let mut chunk = [0_u8; 4096];
                let n = self.io.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the driver closed: {:?}", self.buf);
                self.buf.extend_from_slice(&chunk[..n]);
            }
        }

        /// The interleaved frame the driver sent right after the last
        /// request, read with it: its channel and packet.
        fn frame(&mut self) -> (u8, Vec<u8>) {
            assert_eq!(self.buf[0], b'$', "a frame next: {:?}", self.buf);
            let len = usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]]));
            let frame: Vec<u8> = self.buf.drain(..4 + len).collect();
            (frame[1], frame[4..].to_vec())
        }

        /// Answers `head` with `status`, `headers` and `body`.
        async fn answer(&mut self, head: &str, status: &str, headers: &str, body: &str) {
            let cseq = head
                .lines()
                .find_map(|line| line.strip_prefix("CSeq: "))
                .unwrap();
            let text = format!(
                "RTSP/1.0 {status}\r\nCSeq: {cseq}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
                body.len()
            );
            self.io.write_all(text.as_bytes()).await.unwrap();
        }

        /// Reads the next request, which must be `method`, and answers it
        /// `200 OK` with `headers` and `body`.
        async fn ok(&mut self, method: &str, headers: &str, body: &str) -> String {
            let head = self.request().await;
            assert!(head.starts_with(method), "{head}");
            self.answer(&head, "200 OK", headers, body).await;
            head
        }

        /// The camera's half of `DESCRIBE`, `SETUP` and `PLAY`.
        async fn serve_until_playing(&mut self) -> String {
            let describe = self
                .ok(
                    "DESCRIBE",
                    "Content-Base: rtsp://cam/stream/\r\nContent-Type: application/sdp\r\n",
                    SDP,
                )
                .await;
            self.ok(
                "SETUP",
                "Session: 12345678;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
                "",
            )
            .await;
            self.ok("PLAY", "Session: 12345678\r\n", "").await;
            describe
        }

        async fn send(&mut self, bytes: &[u8]) {
            self.io.write_all(bytes).await.unwrap();
        }
    }

    impl Item {
        fn rtp(&self) -> Option<&Received> {
            match self {
                Self::Rtp(packet) => Some(packet),
                Self::Rtcp(_) => None,
            }
        }

        fn rtcp(&self) -> Option<&retina::rtcp::ReceivedCompoundPacket> {
            match self {
                Self::Rtp(_) => None,
                Self::Rtcp(compound) => Some(compound),
            }
        }
    }

    /// An RTP packet of the camera's stream (RFC 3550 §5.1).
    fn rtp(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x80, 0x60 | if marker { 0x80 } else { 0 }];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&ts.to_be_bytes());
        packet.extend_from_slice(&SSRC.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    /// A Sender Report without report blocks (RFC 3550 §6.4.1).
    fn sender_report() -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0, 6];
        packet.extend_from_slice(&SSRC.to_be_bytes());
        packet.extend_from_slice(&0xe436_2f99_cccc_cccc_u64.to_be_bytes());
        packet.extend_from_slice(&9000_u32.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet
    }

    /// `packet` interleaved on `channel` (RFC 2326 §10.12).
    fn interleaved(channel: u8, packet: &[u8]) -> Vec<u8> {
        let mut frame = vec![b'$', channel];
        frame.extend_from_slice(&u16::try_from(packet.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(packet);
        frame
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn connection(stream: impl Duplex + 'static) -> Connection {
        Connection {
            stream: Box::new(stream),
            local: addr(50_000),
            peer: addr(554),
        }
    }

    fn options(teardown: TeardownPolicy) -> SessionOptions {
        SessionOptions::default()
            .teardown(teardown)
            .receiver_reports(ReceiverReportPolicy::Always)
    }

    /// A driver on a connection with `capacity` bytes of buffer each way,
    /// and the camera's side.
    fn rig(capacity: usize, teardown: TeardownPolicy) -> (Arc<FakeClock>, Driver, Cam) {
        let clock = Arc::new(FakeClock::from_system());
        let (ours, theirs) = tokio::io::duplex(capacity);
        let time: Arc<dyn Clock> = Arc::<FakeClock>::clone(&clock);
        let driver = Driver::new(connection(ours), options(teardown), time);
        (clock, driver, Cam::new(theirs))
    }

    fn url() -> Url {
        Url::parse("rtsps://cam.example/camkey7f3a?token=tok9d2e").unwrap()
    }

    /// `DESCRIBE`, `SETUP` and `PLAY` on `driver` against `cam`; the
    /// `DESCRIBE`'s head.
    async fn played(driver: &mut Driver, cam: &mut Cam) -> String {
        let session = async {
            driver.describe(url()).await.unwrap();
            assert_eq!(driver.streams().len(), 1);
            assert_eq!(driver.sdp(), SDP.as_bytes());
            driver.setup(0).await.unwrap();
            driver.play(play_options()).await.unwrap();
        };
        let ((), describe) = tokio::join!(session, cam.serve_until_playing());
        describe
    }

    /// The cancellation of a teardown no test cancels.
    static NEVER: std::sync::LazyLock<CancellationToken> =
        std::sync::LazyLock::new(CancellationToken::new);

    /// A budget no test's teardown reaches.
    const GENEROUS: Budget = Budget {
        own: Duration::from_secs(600),
        fresh: Duration::from_secs(600),
    };

    /// Lets every other future of the test's task run until it waits.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    /// Yields until `done`.
    async fn until(done: impl Fn() -> bool) {
        while !done() {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn rfc7826_19_2_the_request_uri_is_the_url_itself_and_writes_may_be_partial() {
        let _logs = traced();
        // 64 bytes each way: every request is written in parts.
        let (_clock, mut driver, mut cam) = rig(64, TeardownPolicy::Auto);
        let describe = played(&mut driver, &mut cam).await;
        assert!(
            describe
                .starts_with("DESCRIBE rtsps://cam.example/camkey7f3a?token=tok9d2e RTSP/1.0\r\n"),
            "{describe}"
        );
        let shown = format!("{driver:?}");
        assert!(
            shown.contains("playing: true") && !shown.contains("camkey"),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn rfc3550_5_1_packets_are_copied_out_with_their_header_fields_and_loss() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        // Two packets in one read, the second one sequence number past a
        // lost one, then a Sender Report, then a packet in two reads.
        let mut bytes = interleaved(0, &rtp(1, 90_000, false, &[0x65, 1, 2]));
        bytes.extend(interleaved(0, &rtp(3, 93_000, true, &[0x41, 3])));
        bytes.extend(interleaved(1, &sender_report()));
        cam.send(&bytes).await;
        let first = driver.next_item().await.unwrap();
        let second = driver.next_item().await.unwrap();
        let third = driver.next_item().await.unwrap();
        assert!(first.rtcp().is_none() && third.rtp().is_none());
        let (first, second) = (first.rtp().unwrap(), second.rtp().unwrap());
        // The first is its own copy, whatever retina's buffer holds now.
        assert_eq!(
            *first,
            Received {
                stream: 0,
                ts: 90_000,
                seq: 1,
                ssrc: SSRC,
                marker: false,
                loss: 0,
                payload: Bytes::from_static(&[0x65, 1, 2]),
            }
        );
        assert_eq!((second.seq, second.loss, second.marker), (3, 1, true));
        assert_eq!(third.rtcp().unwrap().stream_id(), 0);
        let split = interleaved(0, &rtp(4, 96_000, false, &[0x41, 4]));
        let (head, tail) = split.split_at(7);
        let reads = async {
            cam.send(head).await;
            tokio::task::yield_now().await;
            cam.send(tail).await;
        };
        let (item, ()) = tokio::join!(driver.next_item(), reads);
        let fourth = item.unwrap();
        assert_eq!(
            fourth.rtp().unwrap().payload,
            Bytes::from_static(&[0x41, 4])
        );
    }

    #[tokio::test]
    async fn a_burst_already_buffered_lets_the_runtimes_other_tasks_run_while_it_is_handed_out() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        // Three times tokio's budget of 128 in a few reads: the
        // connection's own budget use cannot force a yield.
        let count = 3 * 128_u16;
        let burst: Vec<u8> = (1..=count)
            .flat_map(|seq| interleaved(0, &rtp(seq, 0, false, &[0x41])))
            .collect();
        cam.send(&burst).await;
        // The test's own task and one beside it on this thread.
        let beside = Arc::new(AtomicBool::new(false));
        let ran = Arc::clone(&beside);
        let _beside = lotse_core::task::spawn_named("test.beside", async move {
            ran.store(true, Ordering::SeqCst);
        });
        let mut handed = 0_u16;
        while !beside.load(Ordering::SeqCst) {
            let item = driver.next_item().await.unwrap();
            handed += 1;
            assert_eq!(item.rtp().unwrap().seq, handed);
            assert!(handed < count, "no other task ran during the burst");
        }
        assert!(handed <= 128, "{handed} items before another task ran");
    }

    #[tokio::test]
    async fn rfc2326_10_8_keepalives_and_rfc3550_6_4_2_receiver_reports_go_out_when_due() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        let camera = async {
            // The session's timeout is 60 s: a keepalive every 30 s, due
            // at exactly 30 s, and the first report well within it.
            clock.advance(Duration::from_secs(30));
            let keepalive = cam.request().await;
            assert!(
                keepalive.starts_with("OPTIONS rtsp://cam/stream/"),
                "{keepalive}"
            );
            cam.answer(&keepalive, "200 OK", "", "").await;
            cam.send(&interleaved(0, &rtp(1, 0, true, &[0x65]))).await;
        };
        let (item, ()) = tokio::join!(driver.next_item(), camera);
        assert!(matches!(item, Ok(Item::Rtp(_))), "{item:?}");
        // The report follows the keepalive, on the stream's RTCP channel.
        let (channel, report) = cam.frame();
        assert_eq!(channel, 1);
        assert_eq!(report[1], 201, "an RR: {report:?}");
        // The next keepalive goes unanswered: the one after it ends the
        // session, as retina words a read that failed.
        let camera = async {
            clock.advance(Duration::from_secs(31));
            let keepalive = cam.request().await;
            assert_ne!(keepalive, "");
            clock.advance(Duration::from_secs(31));
        };
        let (item, ()) = tokio::join!(driver.next_item(), camera);
        let err = item.unwrap_err();
        let source = err.source_error(&SourceUrl::parse("rtsp://cam/stream").unwrap());
        assert!(
            matches!(&source, SourceError::Ended(m)
                if m.starts_with("Error reading from RTSP peer: Server failed to respond to keepalive")),
            "{source:?}"
        );
        assert_eq!(err.status_code(), None);
    }

    #[tokio::test]
    async fn rfc2326_10_8_a_keepalive_the_camera_never_reads_ends_the_session_as_ended() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        // The camera reads nothing more: the keepalive stays unwritten.
        let camera = async {
            clock.advance(Duration::from_secs(31));
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            clock.advance(Duration::from_secs(31));
        };
        let (item, ()) = tokio::join!(driver.next_item(), camera);
        let source = item
            .unwrap_err()
            .source_error(&SourceUrl::parse("rtsp://cam/").unwrap());
        assert!(
            matches!(&source, SourceError::Ended(m)
                if m.starts_with("Error writing to RTSP peer: Unable to write keepalive")),
            "{source:?}"
        );
    }

    #[tokio::test]
    async fn a_camera_that_closes_while_playing_ends_after_its_last_packet() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        cam.send(&interleaved(0, &rtp(1, 0, true, &[0x65]))).await;
        drop(cam);
        assert!(matches!(driver.next_item().await, Ok(Item::Rtp(_))));
        let err = driver.next_item().await.unwrap_err();
        assert!(matches!(err, Error::Closed), "{err:?}");
        assert_eq!(err.status_code(), None);
        assert_eq!(
            err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap()),
            SourceError::Ended("the camera closed the session".into())
        );
    }

    #[tokio::test]
    async fn rfc2326_10_2_a_camera_that_closes_before_answering_describe_ends_the_request() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = async {
            cam.request().await;
            drop(cam);
        };
        let (described, ()) = tokio::join!(driver.describe(url()), camera);
        let source = described
            .unwrap_err()
            .source_error(&SourceUrl::parse("rtsp://cam/").unwrap());
        assert_eq!(
            source,
            SourceError::Ended(
                "Error reading from RTSP peer: EOF while expecting response to DESCRIBE CSeq 1"
                    .into()
            )
        );
    }

    #[tokio::test]
    async fn rfc2326_7_1_1_a_refused_request_keeps_its_status() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = async {
            let head = cam.request().await;
            cam.answer(&head, "404 Not Found", "", "").await;
        };
        let (described, ()) = tokio::join!(driver.describe(url()), camera);
        let err = described.unwrap_err();
        assert_eq!(err.status_code(), Some(404));
        assert!(matches!(
            err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap()),
            SourceError::Protocol(m) if m.starts_with("404")
        ));
        // Without a description there is no stream to set up, and a
        // request retina refuses to start is its error.
        let refused = driver.setup(0).await.unwrap_err();
        assert!(matches!(refused, Error::UnknownStream(0)), "{refused:?}");
        let refused = driver.play(play_options()).await.unwrap_err();
        assert!(matches!(refused, Error::Session(_)), "{refused:?}");
    }

    #[tokio::test]
    async fn rfc2326_10_4_a_setup_of_a_stream_the_description_lacks_is_refused() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = cam.ok(
            "DESCRIBE",
            "Content-Base: rtsp://cam/stream/\r\nContent-Type: application/sdp\r\n",
            SDP,
        );
        let (described, _) = tokio::join!(driver.describe(url()), camera);
        described.unwrap();
        // Between DESCRIBE and PLAY retina indexes its streams unchecked:
        // one stream described, index 1 would be past them.
        let err = driver.setup(1).await.unwrap_err();
        assert!(matches!(err, Error::UnknownStream(1)), "{err:?}");
        assert_eq!(err.status_code(), None);
        assert_eq!(
            err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap()),
            SourceError::Protocol("rtsp: no stream 1 in the camera's description".into())
        );
        let pair = Pair::bind(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).unwrap();
        let err = driver.setup_udp(5, pair).await.unwrap_err();
        assert!(matches!(err, Error::UnknownStream(5)), "{err:?}");
        // The stream that is there sets up; a second time is retina's
        // refusal, the stream already set up.
        let camera = cam.ok(
            "SETUP",
            "Session: 12345678;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
            "",
        );
        let (set_up, _) = tokio::join!(driver.setup(0), camera);
        set_up.unwrap();
        let err = driver.setup(0).await.unwrap_err();
        assert!(matches!(err, Error::Session(_)), "{err:?}");
    }

    /// How a [`Faulty`] connection fails.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    enum Fault {
        /// It does not.
        #[default]
        None,
        /// Reads fail.
        Read,
        /// Writes fail.
        Write,
        /// Writes take nothing.
        WriteZero,
        /// Flushes fail.
        Flush,
        /// Reads end as a TLS stream that lost its TCP connection without
        /// `close_notify`.
        Truncated,
    }

    /// A connection that fails as its fault says, else passes through.
    struct Faulty {
        inner: DuplexStream,
        fault: Arc<Mutex<Fault>>,
    }

    impl Faulty {
        fn fault(&self) -> Fault {
            *self.fault.lock().unwrap()
        }
    }

    impl AsyncRead for Faulty {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.fault() {
                Fault::Read => return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                Fault::Truncated => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
                _ => {}
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Faulty {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.fault() {
                Fault::WriteZero => Poll::Ready(Ok(0)),
                Fault::Write => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                _ => Pin::new(&mut self.inner).poll_write(cx, buf),
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.fault() == Fault::Flush {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A driver on a [`Faulty`] connection, its faults and the camera's
    /// side.
    fn faulty(teardown: TeardownPolicy) -> (Arc<FakeClock>, Driver, Arc<Mutex<Fault>>, Cam) {
        let clock = Arc::new(FakeClock::from_system());
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let faults = Arc::new(Mutex::new(Fault::None));
        let stream = Faulty {
            inner: ours,
            fault: Arc::clone(&faults),
        };
        let time: Arc<dyn Clock> = Arc::<FakeClock>::clone(&clock);
        let driver = Driver::new(connection(stream), options(teardown), time);
        (clock, driver, faults, Cam::new(theirs))
    }

    #[tokio::test]
    async fn a_connection_that_fails_ends_the_request_with_its_side() {
        let _logs = traced();
        let url_shown = SourceUrl::parse("rtsp://cam/").unwrap();
        for (fault, expected) in [
            (Fault::WriteZero, "writing to the camera failed: write zero"),
            (Fault::Write, "writing to the camera failed: broken pipe"),
            (Fault::Flush, "writing to the camera failed: broken pipe"),
            (
                Fault::Read,
                "Error reading from RTSP peer: connection reset",
            ),
        ] {
            let (_clock, mut driver, set, _cam) = faulty(TeardownPolicy::Auto);
            *set.lock().unwrap() = fault;
            let err = driver.describe(url()).await.unwrap_err();
            let source = err.source_error(&url_shown);
            assert!(
                matches!(&source, SourceError::Ended(m) if m.starts_with(expected)),
                "{fault:?}: {source:?}"
            );
            if fault != Fault::Read {
                assert!(matches!(err, Error::Write(_)), "{err:?}");
                assert_eq!(err.status_code(), None);
            }
        }
    }

    #[tokio::test]
    async fn rfc2326_10_12_what_no_parser_reads_while_playing_ends_the_session_as_protocol() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        cam.send(b"\x00\x01 not RTSP\r\n\r\n").await;
        let err = driver.next_item().await.unwrap_err();
        let source = err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap());
        let protocol = matches!(source, SourceError::Protocol(_));
        assert!(protocol, "{err:?}");
    }

    #[tokio::test]
    async fn a_read_that_fails_while_playing_ends_the_session_as_ended() {
        let _logs = traced();
        // With the keepalive due, the read fails among those made before
        // the timers.
        for due in [false, true] {
            let (clock, mut driver, faults, mut cam) = faulty(TeardownPolicy::Auto);
            played(&mut driver, &mut cam).await;
            *faults.lock().unwrap() = Fault::Read;
            if due {
                clock.advance(Duration::from_secs(30));
            }
            let err = driver.next_item().await.unwrap_err();
            assert!(
                matches!(
                    err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap()),
                    SourceError::Ended(m) if m.starts_with("Error reading from RTSP peer: connection reset")
                ),
                "due {due}: {err:?}"
            );
        }
    }

    /// What one dial of the teardown gives.
    enum Dialed {
        Refused,
        Hangs,
        Camera(DuplexStream),
    }

    /// A dial that gives `script` in order, counting its calls.
    struct Dialer {
        script: Mutex<VecDeque<Dialed>>,
        calls: AtomicUsize,
    }

    impl Dialer {
        fn new(script: impl IntoIterator<Item = Dialed>) -> Self {
            Self {
                script: Mutex::new(script.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn dial(&self) -> BoxFuture<'static, Result<Connection, SourceError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let next = self.script.lock().unwrap().pop_front();
            match next.expect("scripted") {
                Dialed::Refused => {
                    Box::pin(async { Err(SourceError::Unreachable("refused".into())) })
                }
                Dialed::Hangs => Box::pin(std::future::pending()),
                Dialed::Camera(stream) => Box::pin(async move { Ok(connection(stream)) }),
            }
        }
    }

    /// The dial of the teardown, from `dialer`.
    fn dial_with(
        dialer: &Dialer,
    ) -> impl Fn() -> BoxFuture<'static, Result<Connection, SourceError>> + Sync + '_ {
        || dialer.dial()
    }

    #[tokio::test]
    async fn rfc2326_10_7_nothing_set_up_is_nothing_to_tear_down() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Always);
        let camera = cam.ok(
            "DESCRIBE",
            "Content-Base: rtsp://cam/stream/\r\nContent-Type: application/sdp\r\n",
            SDP,
        );
        let (described, _) = tokio::join!(driver.describe(url()), camera);
        described.unwrap();
        let dialer = Dialer::new([]);
        let dial = dial_with(&dialer);
        driver.teardown(&dial, GENEROUS, &NEVER).await;
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn rfc2326_10_7_teardown_is_answered_on_the_sessions_own_connection() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        let dialer = Dialer::new([]);
        let camera = async {
            let head = cam.ok("TEARDOWN", "", "").await;
            assert!(head.contains("Session: 12345678"), "{head}");
        };
        let dial = dial_with(&dialer);
        tokio::join!(driver.teardown(&dial, GENEROUS, &NEVER), camera);
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn rfc2326_10_7_an_unanswered_teardown_gives_up_at_its_deadline() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        let dialer = Dialer::new([]);
        let dial = dial_with(&dialer);
        let over = AtomicBool::new(false);
        let teardown = async {
            driver.teardown(&dial, GENEROUS, &NEVER).await;
            over.store(true, Ordering::SeqCst);
        };
        let camera = async {
            let head = cam.request().await;
            assert!(head.starts_with("TEARDOWN"), "{head}");
            // retina waits 5 s for the answer on the session's connection,
            // and its `Auto` policy tries no more over TCP.
            clock.advance(Duration::from_millis(4_999));
            settle().await;
            assert!(!over.load(Ordering::SeqCst), "given up before its deadline");
            clock.advance(Duration::from_millis(1));
            until(|| over.load(Ordering::SeqCst)).await;
        };
        tokio::join!(teardown, camera);
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn rfc2326_10_7_a_teardown_on_the_sessions_own_connection_stops_at_its_budget() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        let dialer = Dialer::new([]);
        let dial = dial_with(&dialer);
        let over = AtomicBool::new(false);
        let budget = Budget {
            own: Duration::from_millis(100),
            fresh: Duration::from_secs(2),
        };
        let teardown = async {
            driver.teardown(&dial, budget, &NEVER).await;
            over.store(true, Ordering::SeqCst);
        };
        let camera = async {
            cam.request().await;
            clock.advance(Duration::from_millis(99));
            settle().await;
            assert!(!over.load(Ordering::SeqCst), "stopped before its budget");
            clock.advance(Duration::from_millis(1));
            until(|| over.load(Ordering::SeqCst)).await;
        };
        tokio::join!(teardown, camera);
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn rfc2326_10_7_a_teardown_on_fresh_connections_gets_the_fresh_budget_and_no_more() {
        let _logs = traced();
        let (clock, mut driver, faults, mut cam) = faulty(TeardownPolicy::Always);
        played(&mut driver, &mut cam).await;
        *faults.lock().unwrap() = Fault::Write;
        let dialer = Dialer::new([Dialed::Hangs, Dialed::Hangs]);
        let dial = dial_with(&dialer);
        let over = AtomicBool::new(false);
        let budget = Budget {
            own: Duration::from_millis(100),
            fresh: Duration::from_secs(2),
        };
        let teardown = async {
            driver.teardown(&dial, budget, &NEVER).await;
            over.store(true, Ordering::SeqCst);
        };
        let camera = async {
            // The first fresh dial hangs past its 1 s deadline, beyond the
            // 100 ms of the session's own connection: dialed again.
            until(|| dialer.calls() == 1).await;
            clock.advance(Duration::from_secs(1));
            until(|| dialer.calls() == 2).await;
            assert!(!over.load(Ordering::SeqCst));
            // The second one is cut at the 2 s of the fresh budget.
            clock.advance(Duration::from_secs(1));
            until(|| over.load(Ordering::SeqCst)).await;
        };
        tokio::join!(teardown, camera);
        assert_eq!(dialer.calls(), 2);
    }

    /// The source contract's 100 ms to honor a cancel: a teardown that
    /// starts cancelled gets [`Budget::own`] in all, its fresh connections
    /// included, never the fresh budget.
    #[tokio::test]
    async fn rfc2326_10_7_a_cancelled_teardown_gets_its_own_budget_on_fresh_connections_too() {
        let _logs = traced();
        let (clock, mut driver, faults, mut cam) = faulty(TeardownPolicy::Always);
        played(&mut driver, &mut cam).await;
        *faults.lock().unwrap() = Fault::Write;
        let dialer = Dialer::new([Dialed::Hangs]);
        let dial = dial_with(&dialer);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let over = AtomicBool::new(false);
        let budget = Budget {
            own: Duration::from_millis(100),
            fresh: Duration::from_secs(2),
        };
        let teardown = async {
            driver.teardown(&dial, budget, &cancel).await;
            over.store(true, Ordering::SeqCst);
        };
        let camera = async {
            until(|| dialer.calls() == 1).await;
            clock.advance(Duration::from_millis(99));
            settle().await;
            assert!(!over.load(Ordering::SeqCst), "stopped before its budget");
            clock.advance(Duration::from_millis(1));
            until(|| over.load(Ordering::SeqCst)).await;
        };
        tokio::join!(teardown, camera);
        assert_eq!(dialer.calls(), 1);
    }

    /// A cancel while a retry dials a fresh connection leaves the teardown
    /// [`Budget::own`] from then on, the dial in progress kept rather than
    /// dialed again, and then the session is left to expire (RFC 2326
    /// §12.37).
    #[tokio::test]
    async fn rfc2326_10_7_a_cancel_during_a_fresh_connection_retry_stops_it_within_its_own_budget()
    {
        let _logs = traced();
        let (clock, mut driver, faults, mut cam) = faulty(TeardownPolicy::Always);
        played(&mut driver, &mut cam).await;
        *faults.lock().unwrap() = Fault::Write;
        let dialer = Dialer::new([Dialed::Hangs, Dialed::Hangs]);
        let dial = dial_with(&dialer);
        let cancel = CancellationToken::new();
        let over = AtomicBool::new(false);
        let budget = Budget {
            own: Duration::from_millis(100),
            fresh: Duration::from_secs(2),
        };
        let teardown = async {
            driver.teardown(&dial, budget, &cancel).await;
            over.store(true, Ordering::SeqCst);
        };
        let camera = async {
            // The first fresh dial hangs past its 1 s deadline: the retry
            // dials again, its budget up to 2 s.
            until(|| dialer.calls() == 1).await;
            clock.advance(Duration::from_secs(1));
            until(|| dialer.calls() == 2).await;
            cancel.cancel();
            settle().await;
            assert!(!over.load(Ordering::SeqCst), "the cancellation's budget");
            clock.advance(Duration::from_millis(99));
            settle().await;
            assert!(!over.load(Ordering::SeqCst), "stopped before its budget");
            clock.advance(Duration::from_millis(1));
            until(|| over.load(Ordering::SeqCst)).await;
        };
        tokio::join!(teardown, camera);
        assert_eq!(dialer.calls(), 2, "the dial in progress, not a new one");
    }

    #[tokio::test]
    async fn rfc2326_10_7_teardown_retries_on_fresh_connections_through_refusals_and_hangs() {
        let _logs = traced();
        let (clock, mut driver, faults, mut cam) = faulty(TeardownPolicy::Always);
        played(&mut driver, &mut cam).await;
        *faults.lock().unwrap() = Fault::Write;
        let (fresh, theirs) = tokio::io::duplex(64 * 1024);
        let dialer = Dialer::new([Dialed::Refused, Dialed::Hangs, Dialed::Camera(fresh)]);
        let mut fresh_cam = Cam::new(theirs);
        let camera = async {
            // Refused: the attempt waits out its deadline (1 s).
            until(|| dialer.calls() == 1).await;
            clock.advance(Duration::from_secs(1));
            // Hangs: given up at its deadline (2 s), and dialed again.
            until(|| dialer.calls() == 2).await;
            clock.advance(Duration::from_secs(2));
            let head = fresh_cam.ok("TEARDOWN", "", "").await;
            assert!(head.contains("Session: 12345678"), "{head}");
        };
        let dial = dial_with(&dialer);
        tokio::join!(driver.teardown(&dial, GENEROUS, &NEVER), camera);
        assert_eq!(dialer.calls(), 3);
    }

    #[tokio::test]
    async fn rfc2326_10_7_a_camera_that_closes_on_teardown_is_left_to_expire() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        let dialer = Dialer::new([]);
        let camera = async {
            let head = cam.request().await;
            assert!(head.starts_with("TEARDOWN"), "{head}");
            drop(cam);
        };
        let dial = dial_with(&dialer);
        tokio::join!(driver.teardown(&dial, GENEROUS, &NEVER), camera);
        assert_eq!(dialer.calls(), 0);
    }

    /// A camera's answer with an ONVIF backchannel: PCMU the client sends
    /// (ONVIF Streaming Specification §5.3.2).
    const BACKCHANNEL_SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
        m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track0\r\n\
        m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\na=control:back\r\n";

    #[tokio::test]
    async fn onvif_5_3_packets_queued_on_the_sending_stream_go_out_on_its_channels() {
        let _logs = traced();
        let clock = Arc::new(FakeClock::from_system());
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let time: Arc<dyn Clock> = Arc::<FakeClock>::clone(&clock);
        let options = SessionOptions::default().backchannel(true);
        let mut driver = Driver::new(connection(ours), options, time);
        let mut cam = Cam::new(theirs);
        let camera = cam.ok(
            "DESCRIBE",
            "Content-Base: rtsp://cam/stream/\r\nContent-Type: application/sdp\r\n",
            BACKCHANNEL_SDP,
        );
        let (described, describe) = tokio::join!(driver.describe(url()), camera);
        described.unwrap();
        assert!(
            describe.contains("Require: www.onvif.org/ver20/backchannel"),
            "{describe}"
        );
        let sending = driver.streams()[1].rtp_payload_type();
        let mut sender = retina::rtp::Sender::new(sending, retina::rtp::SenderOptions::default());
        let rate = std::num::NonZeroU32::new(8_000).unwrap();
        let ts = retina::Timestamp::new(0, rate, 0).unwrap();
        // Before `PLAY`, nothing is queued.
        let early = driver.queue_rtp(1, &sender.packet(ts, true, &[&[0xff; 4]]));
        assert!(matches!(early, Err(Error::Session(_))), "{early:?}");
        let early = driver.queue_rtcp(1, &[0x80, 200, 0, 0]);
        assert!(matches!(early, Err(Error::Session(_))), "{early:?}");
        assert_eq!(driver.queued_len(), 0);
        let session = async {
            driver.setup(1).await.unwrap();
            driver.play(play_options()).await.unwrap();
        };
        let camera = async {
            cam.ok(
                "SETUP",
                "Session: 12345678;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
                "",
            )
            .await;
            cam.ok("PLAY", "Session: 12345678\r\n", "").await;
        };
        tokio::join!(session, camera);
        // A packet on the stream index past the session's last is retina's
        // error, nothing queued.
        let past = driver.queue_rtp(2, &sender.packet(ts, false, &[&[0xff; 4]]));
        assert!(matches!(past, Err(Error::Session(_))), "{past:?}");
        let packet = sender.packet(ts, true, &[&[0xff; 160]]);
        driver.queue_rtp(1, &packet).unwrap();
        let report = sender.sender_report(retina::NtpTimestamp(0), ts, "cname");
        driver.queue_rtcp(1, &report).unwrap();
        assert_eq!(driver.queued_len(), 4 + 12 + 160 + 4 + report.len());
        // Polled, the session writes them; the camera reads both and closes.
        let camera = async {
            let mut frames = Vec::new();
            let mut chunk = [0_u8; 4096];
            while cam.buf.len() < 4 + 12 + 160 + 4 + report.len() {
                let n = cam.io.read(&mut chunk).await.unwrap();
                cam.buf.extend_from_slice(&chunk[..n]);
            }
            frames.push(cam.frame());
            frames.push(cam.frame());
            drop(cam);
            frames
        };
        let (item, frames) = tokio::join!(driver.next_item(), camera);
        assert!(matches!(item, Err(Error::Closed)), "{item:?}");
        assert_eq!(frames[0].0, 0, "RTP on the stream's first channel");
        assert_eq!(frames[0].1[1], 0x80, "the marker, payload type 0");
        assert_eq!(frames[1], (1, report), "the SR on its RTCP channel");
        assert_eq!(driver.queued_len(), 0);
    }

    #[tokio::test]
    async fn a_faulty_connection_shuts_down_as_its_inner_one() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut stream = Faulty {
            inner: ours,
            fault: Arc::new(Mutex::new(Fault::None)),
        };
        stream.shutdown().await.unwrap();
        assert_eq!(theirs.read(&mut [0_u8; 1]).await.unwrap(), 0);
    }

    /// retina's own driver parses what arrived before it checks its
    /// timers: a keepalive's answer in the buffer when its deadline comes
    /// is an answer.
    #[tokio::test]
    async fn rfc2326_10_8_a_keepalive_answer_buffered_at_its_deadline_counts() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        let camera = async {
            clock.advance(Duration::from_secs(30));
            let keepalive = cam.request().await;
            // The receiver report the keepalive came with.
            assert_eq!(cam.frame().0, 1);
            cam.answer(&keepalive, "200 OK", "", "").await;
            cam.send(&interleaved(0, &rtp(1, 0, true, &[0x65]))).await;
            // The answer waits unread while the next deadline passes.
            clock.advance(Duration::from_secs(30));
        };
        let (item, ()) = tokio::join!(driver.next_item(), camera);
        assert!(item.unwrap().rtp().is_some());
        // The session goes on: the next keepalive goes out.
        let camera = async {
            let keepalive = cam.request().await;
            cam.answer(&keepalive, "200 OK", "", "").await;
            cam.send(&interleaved(0, &rtp(2, 3000, true, &[0x41])))
                .await;
        };
        let (item, ()) = tokio::join!(driver.next_item(), camera);
        assert!(item.unwrap().rtp().is_some());
    }

    /// A packet waiting on the connection when the keepalive falls due is
    /// read and handed out before the keepalive goes out, which the next
    /// call sends: the state is set up before `next_item` runs, so no
    /// `select!` between the read and the timer decides it.
    #[tokio::test]
    async fn rfc2326_10_8_a_packet_waiting_at_the_keepalives_deadline_is_handed_out_first() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        cam.send(&interleaved(0, &rtp(1, 0, true, &[0x65]))).await;
        clock.advance(Duration::from_secs(30));
        let item = driver.next_item().await.unwrap();
        assert_eq!(item.rtp().unwrap().seq, 1);
        let mut byte = [0_u8; 1];
        let sent = cam.io.read(&mut byte).now_or_never();
        assert!(sent.is_none(), "nothing sent before the packet: {sent:?}");
        let camera = async {
            let keepalive = cam.request().await;
            assert!(
                keepalive.starts_with("OPTIONS rtsp://cam/stream/"),
                "{keepalive}"
            );
            cam.answer(&keepalive, "200 OK", "", "").await;
            cam.send(&interleaved(0, &rtp(2, 3000, true, &[0x41])))
                .await;
        };
        let (item, ()) = tokio::join!(driver.next_item(), camera);
        assert_eq!(item.unwrap().rtp().unwrap().seq, 2);
    }

    /// A camera whose connection never runs dry (a packet waiting at every
    /// call) still gets its keepalive and receiver report once they fall
    /// due: one read comes before the due timers, not every read.
    #[tokio::test]
    async fn rfc2326_10_8_an_always_readable_camera_still_gets_its_keepalive_when_due() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        clock.advance(Duration::from_secs(30));
        let mut seq = 0_u16;
        let mut byte = [0_u8; 1];
        let sent = loop {
            seq += 1;
            assert!(seq <= 8, "no keepalive in {} calls", seq - 1);
            cam.send(&interleaved(0, &rtp(seq, 0, true, &[0x41]))).await;
            let item = driver.next_item().await.unwrap();
            assert_eq!(item.rtp().unwrap().seq, seq);
            if let Some(read) = cam.io.read(&mut byte).now_or_never() {
                break read.unwrap();
            }
        };
        assert_eq!(sent, 1);
        assert!(seq <= 2, "the keepalive went out on call {seq}");
        cam.buf.push(byte[0]);
        let keepalive = cam.request().await;
        assert!(
            keepalive.starts_with("OPTIONS rtsp://cam/stream/"),
            "{keepalive}"
        );
        // The receiver report the keepalive came with.
        assert_eq!(cam.frame().0, 1);
    }

    /// The free space of retina's ring up to its end: what the next read
    /// from the camera can take at most.
    fn before_wrap(driver: &mut Driver) -> usize {
        driver.core.read_buf().spare_capacity(READ_RESERVE).0.len()
    }

    /// A keepalive's answer waiting at its deadline counts even when the
    /// first read before the timers is cut short at the wrap of retina's
    /// ring, which leaves the answer's rest in the socket: a second read
    /// takes it in before the timers run.
    #[tokio::test]
    async fn rfc2326_10_8_a_keepalive_answer_split_by_the_rings_wrap_still_counts() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        // The keepalive goes out at 30 s, and waits for its answer.
        let mut seq = 1_u16;
        let camera = async {
            clock.advance(Duration::from_secs(30));
            let keepalive = cam.request().await;
            assert_eq!(cam.frame().0, 1, "the receiver report");
            cam.send(&interleaved(0, &rtp(seq, 0, true, &[0x41]))).await;
            keepalive
        };
        let (item, keepalive) = tokio::join!(driver.next_item(), camera);
        assert!(item.unwrap().rtp().is_some());
        // Packets that leave 8 bytes of the ring before its end, wrapping
        // it first when less than a packet is left.
        for _ in 0..2 {
            let left = before_wrap(&mut driver);
            let len = if left < 64 { left } else { left - 8 };
            seq += 1;
            let payload = vec![0x41; len - 16];
            cam.send(&interleaved(0, &rtp(seq, 0, true, &payload)))
                .await;
            assert_eq!(driver.next_item().await.unwrap().rtp().unwrap().seq, seq);
            if before_wrap(&mut driver) == 8 {
                break;
            }
        }
        assert_eq!(before_wrap(&mut driver), 8);
        // The answer, longer than that, and a packet wait while the next
        // deadline passes.
        cam.answer(&keepalive, "200 OK", "", "").await;
        cam.send(&interleaved(0, &rtp(seq + 1, 0, true, &[0x41])))
            .await;
        clock.advance(Duration::from_secs(30));
        let item = driver.next_item().await.unwrap();
        assert_eq!(item.rtp().unwrap().seq, seq + 1);
    }

    #[tokio::test]
    async fn what_already_arrived_is_handed_out_before_an_overdue_timer_fires() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        // A packet waits unread while the keepalive's deadline passes.
        cam.send(&interleaved(0, &rtp(1, 0, true, &[0x65]))).await;
        clock.advance(Duration::from_secs(31));
        let item = driver.next_item().await.unwrap();
        assert_eq!(item.rtp().unwrap().seq, 1);
        // The keepalive goes out with the next round.
        let camera = async {
            let keepalive = cam.request().await;
            assert!(keepalive.starts_with("OPTIONS"), "{keepalive}");
            cam.answer(&keepalive, "200 OK", "", "").await;
            cam.send(&interleaved(0, &rtp(2, 3000, true, &[0x41])))
                .await;
        };
        let (item, ()) = tokio::join!(driver.next_item(), camera);
        assert_eq!(item.unwrap().rtp().unwrap().seq, 2);
    }

    #[tokio::test]
    async fn no_item_before_play() {
        let _logs = traced();
        let (_clock, mut driver, _cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let err = driver.next_item().await.unwrap_err();
        assert!(matches!(err, Error::NotPlaying), "{err:?}");
        assert_eq!(err.status_code(), None);
        let source = err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap());
        assert_eq!(
            source,
            SourceError::Protocol("rtsp: no packets before PLAY".into())
        );
    }

    /// RFC 8446 §6.1: a TLS camera that drops its TCP connection without
    /// `close_notify` has closed the session all the same.
    #[tokio::test]
    async fn rfc8446_6_1_a_read_cut_short_while_playing_is_a_close() {
        let _logs = traced();
        let (_clock, mut driver, faults, mut cam) = faulty(TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        *faults.lock().unwrap() = Fault::Truncated;
        let err = driver.next_item().await.unwrap_err();
        assert!(matches!(err, Error::Closed), "{err:?}");
    }

    #[test]
    fn raw_timestamps_are_the_low_32_bits() {
        let ts =
            retina::Timestamp::new(0x1_0000_0005, std::num::NonZeroU32::new(90_000).unwrap(), 0)
                .unwrap();
        assert_eq!(raw_timestamp(ts), 5);
        let ts = retina::Timestamp::new(0xffff_fff0, std::num::NonZeroU32::new(90_000).unwrap(), 0)
            .unwrap();
        assert_eq!(raw_timestamp(ts), 0xffff_fff0);
    }

    #[test]
    fn a_connection_shows_its_addresses_only() {
        let (ours, _theirs) = tokio::io::duplex(1);
        let shown = format!("{:?}", connection(ours));
        assert_eq!(
            shown,
            "Connection { local: 127.0.0.1:50000, peer: 127.0.0.1:554, .. }"
        );
    }

    #[test]
    fn a_failed_exchange_gives_its_io_error_whichever_side() {
        let kind = Failed::Read(io::ErrorKind::Other.into()).into_io().kind();
        assert_eq!(kind, io::ErrorKind::Other);
        let kind = Failed::Write(io::ErrorKind::BrokenPipe.into())
            .into_io()
            .kind();
        assert_eq!(kind, io::ErrorKind::BrokenPipe);
    }

    /// The SDP of a camera with video and audio.
    const SDP_AV: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
        m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track0\r\n\
        m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:track1\r\n";

    /// The camera's RTP/RTCP pair on loopback, RTP on an even port.
    struct CamUdp {
        rtp: tokio::net::UdpSocket,
        rtcp: tokio::net::UdpSocket,
        port: u16,
    }

    impl CamUdp {
        fn bind() -> Self {
            let (media, control) =
                crate::udp::bind_pair(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).unwrap();
            let port = media.local_addr().unwrap().port();
            for socket in [&media, &control] {
                socket.set_nonblocking(true).unwrap();
            }
            Self {
                rtp: tokio::net::UdpSocket::from_std(media).unwrap(),
                rtcp: tokio::net::UdpSocket::from_std(control).unwrap(),
                port,
            }
        }

        /// The next datagram on `socket` and its sender, within 5 s.
        async fn recv(socket: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
            let mut buf = vec![0_u8; 2048];
            let (n, from) = within_5s(socket.recv_from(&mut buf)).await.unwrap();
            buf.truncate(n);
            (buf, from)
        }

        /// Whether nothing arrived on `socket` yet.
        fn quiet(socket: &tokio::net::UdpSocket) -> bool {
            let mut buf = [0_u8; 64];
            matches!(socket.try_recv_from(&mut buf), Err(err) if err.kind() == io::ErrorKind::WouldBlock)
        }
    }

    /// The `client_port` a `SETUP`'s head names.
    fn client_port(head: &str) -> u16 {
        let at = head.find("client_port=").unwrap() + "client_port=".len();
        head[at..].split('-').next().unwrap().parse().unwrap()
    }

    impl Cam {
        /// The camera's half of `DESCRIBE` of `sdp`, then a `SETUP` over
        /// UDP for each of its `streams`, answered with what `transport`
        /// makes of the `client_port` it names; the client ports.
        async fn serve_udp_setups(
            &mut self,
            sdp: &str,
            streams: usize,
            transport: impl Fn(u16) -> String,
        ) -> Vec<u16> {
            self.ok(
                "DESCRIBE",
                "Content-Base: rtsp://cam/stream/\r\nContent-Type: application/sdp\r\n",
                sdp,
            )
            .await;
            let mut ports = Vec::new();
            for _ in 0..streams {
                let head = self.request().await;
                assert!(head.starts_with("SETUP"), "{head}");
                let port = client_port(&head);
                assert!(
                    head.contains(&format!(
                        "Transport: RTP/AVP/UDP;unicast;client_port={port}-{}\r\n",
                        port + 1
                    )),
                    "{head}"
                );
                let headers = format!(
                    "Session: 12345678;timeout=60\r\nTransport: {}\r\n",
                    transport(port)
                );
                self.answer(&head, "200 OK", &headers, "").await;
                ports.push(port);
            }
            ports
        }
    }

    /// The answer's `Transport` for the camera's pair at `server`, or
    /// without `server_port` for none.
    fn answered(server: Option<u16>) -> impl Fn(u16) -> String {
        move |client| {
            let server = server.map_or_else(String::new, |port| {
                format!(";server_port={port}-{}", port + 1)
            });
            format!(
                "RTP/AVP/UDP;unicast;client_port={client}-{}{server}",
                client + 1
            )
        }
    }

    /// `DESCRIBE` of [`SDP`] and its stream set up over UDP on a pair
    /// bound for it, the camera answering with `transport`; the client
    /// port.
    async fn set_up_udp(
        driver: &mut Driver,
        cam: &mut Cam,
        transport: impl Fn(u16) -> String,
    ) -> Result<u16, Error> {
        let session = async {
            driver.describe(url()).await.unwrap();
            let pair = Pair::bind(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).unwrap();
            driver.setup_udp(0, pair).await
        };
        let (set_up, ports) = tokio::join!(session, cam.serve_udp_setups(SDP, 1, transport));
        set_up.map(|()| ports[0])
    }

    /// `PLAY` on `driver` against `cam`.
    async fn play_udp(driver: &mut Driver, cam: &mut Cam) {
        let session = driver.play(play_options());
        let camera = cam.ok("PLAY", "Session: 12345678\r\n", "");
        let (played, _) = tokio::join!(session, camera);
        played.unwrap();
    }

    /// `future`'s output within 5 s of real time, or a failed test rather
    /// than a hung one.
    async fn within_5s<T>(future: impl Future<Output = T>) -> T {
        use lotse_core::clock::SystemClock;

        tokio::select! {
            out = future => out,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }

    /// `next_item`, within 5 s.
    async fn next(driver: &mut Driver) -> Result<Item, Error> {
        within_5s(driver.next_item()).await
    }

    fn to(port: u16) -> SocketAddr {
        addr(port)
    }

    #[tokio::test]
    async fn rfc2326_12_39_hole_punches_follow_the_setup_answer_and_media_and_reports_flow_over_udp()
     {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let ingest = Arc::new(IngestCounters::default());
        driver.count_udp_into(Arc::clone(&ingest));
        let camera = CamUdp::bind();
        let client = set_up_udp(&mut driver, &mut cam, answered(Some(camera.port)))
            .await
            .unwrap();
        // Before PLAY: one punch from each of the pair's ports to the
        // camera's (RFC 3550 §5.1 and §6.4.2 packets with nothing to say).
        let (punch, from) = CamUdp::recv(&camera.rtp).await;
        assert_eq!((punch.len(), punch[0], from.port()), (12, 0x80, client));
        let (punch, from) = CamUdp::recv(&camera.rtcp).await;
        assert_eq!(
            (punch, from.port()),
            (vec![0x80, 201, 0, 1, 0, 0, 0, 0], client + 1)
        );
        play_udp(&mut driver, &mut cam).await;
        camera
            .rtp
            .send_to(&rtp(1, 90_000, true, &[0x65, 1]), to(client))
            .await
            .unwrap();
        let item = next(&mut driver).await.unwrap();
        assert_eq!(item.rtp().unwrap().payload, Bytes::from_static(&[0x65, 1]));
        camera
            .rtcp
            .send_to(&sender_report(), to(client + 1))
            .await
            .unwrap();
        let item = next(&mut driver).await.unwrap();
        assert_eq!(item.rtcp().unwrap().stream_id(), 0);
        // RFC 3550 §6.4.2: the first report is due within 3.1 s of the
        // first packet; it leaves from the RTCP port for the camera's.
        clock.advance(Duration::from_secs(4));
        camera
            .rtp
            .send_to(&rtp(2, 93_000, true, &[0x41, 2]), to(client))
            .await
            .unwrap();
        assert!(next(&mut driver).await.unwrap().rtp().is_some());
        let (report, from) = CamUdp::recv(&camera.rtcp).await;
        assert_eq!((report[1], from.port()), (201, client + 1));
        assert!(report.len() > 8, "a block and an SDES: {report:?}");
        assert_eq!(ingest.snapshot(), IngestStats::default());
    }

    /// A camera whose UDP stream never pauses still gets its keepalive once
    /// it falls due: more datagrams wait than one poll takes (the socket
    /// stays readable), but the pairs carry no answer, so they wait until
    /// the timers ran.
    #[tokio::test]
    async fn rfc2326_10_8_an_always_readable_udp_stream_still_gets_its_keepalive_when_due() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = CamUdp::bind();
        let client = set_up_udp(&mut driver, &mut cam, answered(Some(camera.port)))
            .await
            .unwrap();
        play_udp(&mut driver, &mut cam).await;
        // Twice as many datagrams as a poll takes, and the next two at
        // every call: the socket is never drained.
        let reads = u16::try_from(crate::udp::MAX_READS).unwrap();
        let mut sent = 0_u16;
        for _ in 0..2 * reads {
            sent += 1;
            camera
                .rtp
                .send_to(&rtp(sent, 0, true, &[0x41]), to(client))
                .await
                .unwrap();
        }
        assert_eq!(next(&mut driver).await.unwrap().rtp().unwrap().seq, 1);
        clock.advance(Duration::from_secs(30));
        let mut byte = [0_u8; 1];
        let mut calls = 0_u16;
        let read = loop {
            calls += 1;
            assert!(calls <= 3 * reads, "no keepalive in {} calls", calls - 1);
            for _ in 0..2 {
                sent += 1;
                camera
                    .rtp
                    .send_to(&rtp(sent, 0, true, &[0x41]), to(client))
                    .await
                    .unwrap();
            }
            let item = next(&mut driver).await.unwrap();
            assert_eq!(item.rtp().unwrap().seq, calls + 1);
            if let Some(read) = cam.io.read(&mut byte).now_or_never() {
                break read.unwrap();
            }
        };
        assert_eq!(read, 1);
        // Once what one poll took is handed out.
        assert!(calls <= reads, "the keepalive went out on call {calls}");
        cam.buf.push(byte[0]);
        let keepalive = cam.request().await;
        assert!(
            keepalive.starts_with("OPTIONS rtsp://cam/stream/"),
            "{keepalive}"
        );
    }

    #[tokio::test]
    async fn rfc7362_strays_are_refused_and_counted_and_late_packets_go_on_to_be_dropped() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let ingest = Arc::new(IngestCounters::default());
        driver.count_udp_into(Arc::clone(&ingest));
        let camera = CamUdp::bind();
        let client = set_up_udp(&mut driver, &mut cam, answered(Some(camera.port)))
            .await
            .unwrap();
        play_udp(&mut driver, &mut cam).await;
        let stranger = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other_ssrc = {
            let mut packet = rtp(11, 0, false, &[0x41]);
            packet[8..12].copy_from_slice(&7_u32.to_be_bytes());
            packet
        };
        let mut not_rtp = rtp(11, 0, false, &[0x41]);
        not_rtp[0] = 0x40;
        // From another port, then what is no RTP, then the stream, two
        // duplicates (the second one's line held for the summary), another
        // source, and the stream again.
        stranger
            .send_to(&rtp(10, 0, false, &[0x41]), to(client))
            .await
            .unwrap();
        for packet in [
            not_rtp,
            rtp(10, 0, false, &[0x41, 10]),
            rtp(10, 0, false, &[0x41, 10]),
            rtp(10, 0, false, &[0x41, 10]),
            other_ssrc,
            rtp(11, 3000, true, &[0x41, 11]),
        ] {
            camera.rtp.send_to(&packet, to(client)).await.unwrap();
        }
        // RTCP that is no compound packet.
        camera
            .rtcp
            .send_to(&[0x80, 200], to(client + 1))
            .await
            .unwrap();
        let first = next(&mut driver).await.unwrap();
        let second = next(&mut driver).await.unwrap();
        assert_eq!(
            (first.rtp().unwrap().seq, second.rtp().unwrap().seq),
            (10, 11)
        );
        assert_eq!(second.rtp().unwrap().loss, 0);
        let stats = ingest.snapshot();
        assert_eq!(
            (
                stats.datagrams_rejected,
                stats.packets_out_of_order,
                stats.packets_lost
            ),
            (4, 2, 0),
            "{stats:?}"
        );
    }

    #[tokio::test]
    async fn rfc3550_8_2_a_camera_that_changes_its_synchronization_source_ends_the_attempt() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = CamUdp::bind();
        let client = set_up_udp(&mut driver, &mut cam, answered(Some(camera.port)))
            .await
            .unwrap();
        play_udp(&mut driver, &mut cam).await;
        let restarted = |seq: u16| {
            let mut packet = rtp(seq, 0, true, &[0x65]);
            packet[8..12].copy_from_slice(&0x0bad_cafe_u32.to_be_bytes());
            packet
        };
        for packet in [rtp(1, 0, true, &[0x65]), restarted(500), restarted(501)] {
            camera.rtp.send_to(&packet, to(client)).await.unwrap();
        }
        assert_eq!(next(&mut driver).await.unwrap().rtp().unwrap().seq, 1);
        let err = next(&mut driver).await.unwrap_err();
        let source = err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap());
        assert_eq!(
            source,
            SourceError::Protocol(
                "the camera changed its RTP synchronization source from 12345678 to 0badcafe (RFC 3550 §8.2): a new session".into()
            )
        );
    }

    #[tokio::test]
    async fn rfc1122_3_2_1_3_a_source_no_camera_can_send_from_ends_the_setup_before_any_punch() {
        let _logs = traced();
        let clock = Arc::new(FakeClock::from_system());
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let conn = Connection {
            stream: Box::new(ours),
            local: addr(50_000),
            peer: "192.0.2.10:554".parse().unwrap(),
        };
        let time: Arc<dyn Clock> = Arc::<FakeClock>::clone(&clock);
        let mut driver = Driver::new(conn, options(TeardownPolicy::Auto), time);
        let mut cam = Cam::new(theirs);
        let camera = CamUdp::bind();
        let server = camera.port;
        let err = set_up_udp(&mut driver, &mut cam, move |client| {
            format!(
                "RTP/AVP/UDP;unicast;client_port={client}-{};source=127.0.0.1;server_port={server}-{}",
                client + 1,
                server + 1
            )
        })
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), None);
        let source = err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap());
        assert!(
            matches!(&source, SourceError::Protocol(m) if m.contains("source 127.0.0.1") && m.contains("loopback")),
            "{source:?}"
        );
        // The punches would have gone out before `setup_udp` returned.
        assert!(CamUdp::quiet(&camera.rtp) && CamUdp::quiet(&camera.rtcp));
    }

    #[tokio::test]
    async fn rfc4961_without_server_port_nothing_is_punched_and_the_core_learns_the_ports() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = CamUdp::bind();
        let client = set_up_udp(&mut driver, &mut cam, answered(None))
            .await
            .unwrap();
        assert!(CamUdp::quiet(&camera.rtp) && CamUdp::quiet(&camera.rtcp));
        play_udp(&mut driver, &mut cam).await;
        camera
            .rtp
            .send_to(&rtp(1, 0, true, &[0x65]), to(client))
            .await
            .unwrap();
        assert!(next(&mut driver).await.unwrap().rtp().is_some());
        // The reports wait for the camera's RTCP, then go where it came
        // from.
        camera
            .rtcp
            .send_to(&sender_report(), to(client + 1))
            .await
            .unwrap();
        assert!(next(&mut driver).await.unwrap().rtcp().is_some());
        clock.advance(Duration::from_secs(4));
        camera
            .rtp
            .send_to(&rtp(2, 3000, true, &[0x41]), to(client))
            .await
            .unwrap();
        assert!(next(&mut driver).await.unwrap().rtp().is_some());
        let (report, from) = CamUdp::recv(&camera.rtcp).await;
        assert_eq!((report[1], from.port()), (201, client + 1));
        assert!(CamUdp::quiet(&camera.rtp), "no punch, ever");
    }

    #[tokio::test]
    async fn a_closed_rtcp_port_refuses_its_hole_punch_and_the_media_still_flows() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let CamUdp {
            rtp: camera,
            rtcp,
            port,
        } = CamUdp::bind();
        // Nothing listens on the camera's RTCP port: the punch there is
        // answered with ICMP port unreachable, which an unconnected socket
        // never reports.
        drop(rtcp);
        let client = set_up_udp(&mut driver, &mut cam, answered(Some(port)))
            .await
            .unwrap();
        CamUdp::recv(&camera).await;
        play_udp(&mut driver, &mut cam).await;
        for seq in 1..=3 {
            camera
                .send_to(&rtp(seq, 0, true, &[0x65]), to(client))
                .await
                .unwrap();
            assert_eq!(next(&mut driver).await.unwrap().rtp().unwrap().seq, seq);
        }
    }

    #[tokio::test]
    async fn rfc2326_1_1_a_udp_session_whose_connection_closes_is_torn_down_on_a_fresh_one() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = CamUdp::bind();
        let client = set_up_udp(&mut driver, &mut cam, answered(Some(camera.port)))
            .await
            .unwrap();
        play_udp(&mut driver, &mut cam).await;
        camera
            .rtp
            .send_to(&rtp(1, 0, true, &[0x65]), to(client))
            .await
            .unwrap();
        assert!(next(&mut driver).await.unwrap().rtp().is_some());
        // The camera closes the control connection: the session ends with
        // it, while the camera's media goes on.
        drop(cam);
        let err = next(&mut driver).await.unwrap_err();
        assert!(matches!(err, Error::Closed), "{err:?}");
        camera
            .rtp
            .send_to(&rtp(2, 3000, true, &[0x65]), to(client))
            .await
            .unwrap();
        let (fresh, theirs) = tokio::io::duplex(64 * 1024);
        let dialer = Dialer::new([Dialed::Camera(fresh)]);
        let mut fresh_cam = Cam::new(theirs);
        let camera_side = async {
            let head = fresh_cam.ok("TEARDOWN", "", "").await;
            assert!(head.contains("Session: 12345678"), "{head}");
        };
        let dial = dial_with(&dialer);
        tokio::join!(driver.teardown(&dial, GENEROUS, &NEVER), camera_side);
        assert_eq!(dialer.calls(), 1);
    }

    #[tokio::test]
    async fn one_busy_stream_does_not_starve_another() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let camera = CamUdp::bind();
        let session = async {
            driver.describe(url()).await.unwrap();
            for index in 0..2 {
                let pair = Pair::bind(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).unwrap();
                driver.setup_udp(index, pair).await.unwrap();
            }
        };
        let ((), clients) = tokio::join!(
            session,
            cam.serve_udp_setups(SDP_AV, 2, answered(Some(camera.port)))
        );
        play_udp(&mut driver, &mut cam).await;
        // A hundred video packets queue before the one audio packet.
        let flood = 100;
        for seq in 1..=flood {
            camera
                .rtp
                .send_to(&rtp(seq, 0, false, &[0x41]), to(clients[0]))
                .await
                .unwrap();
        }
        camera
            .rtp
            .send_to(&rtp(1, 0, true, &[0x7f]), to(clients[1]))
            .await
            .unwrap();
        let mut streams = Vec::new();
        while streams.len() <= usize::from(flood) {
            streams.push(next(&mut driver).await.unwrap().rtp().unwrap().stream);
        }
        let audio = streams.iter().position(|&stream| stream == 1).unwrap();
        assert!(
            audio < usize::from(flood),
            "the audio waited for the flood: {audio}"
        );
    }

    /// A socket whose receives and sends fail.
    #[derive(Debug)]
    struct Failing;

    impl crate::udp::Socket for Failing {
        fn poll_recv_from(
            &self,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<SocketAddr>> {
            Poll::Ready(Err(io::Error::other("receive failed")))
        }

        fn send_to(&self, _data: &[u8], _to: SocketAddr) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    #[test]
    fn only_an_answered_setup_names_a_udp_peer() {
        assert_eq!(udp_peer(&SessionEvent::Playing), None);
        assert_eq!(
            udp_peer(&SessionEvent::SetUp {
                stream_i: 0,
                udp_peer: None
            }),
            None
        );
    }

    #[tokio::test]
    async fn a_send_that_fails_is_dropped_and_a_receive_that_fails_ends_the_session() {
        let _logs = traced();
        let (_clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        let session = async {
            driver.describe(url()).await.unwrap();
            let pair = Pair::of(Box::new(Failing), Box::new(Failing), 50_000);
            driver.setup_udp(0, pair).await
        };
        let (set_up, _) = tokio::join!(session, cam.serve_udp_setups(SDP, 1, answered(Some(6970))));
        // The punches could not go out: logged, nothing more.
        set_up.unwrap();
        play_udp(&mut driver, &mut cam).await;
        let err = next(&mut driver).await.unwrap_err();
        let source = err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap());
        assert!(
            matches!(&source, SourceError::Ended(m) if m.starts_with("Error receiving UDP packet: receive failed")),
            "{source:?}"
        );
    }
}

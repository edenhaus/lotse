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
//! The core is built for more than this one path: RTP over UDP (the core's
//! UDP buffers and transmits, sockets the caller binds) and the ONVIF
//! backchannel (`queue_rtp`) plug in beside [`Driver::next_item`]'s one
//! exchange per round, on the same core and connection.

use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use lotse_core::clock::Clock;
use lotse_core::source::SourceError;
use lotse_core::source_url::SourceUrl;
use lotse_core::task::BoxFuture;
use retina::buf::MarkBuf;
use retina::client::{
    PlayOptions, PlayingItem, RtpPacket, SessionCore, SessionEvent, SessionOptions, SetupTransport,
    Stream, TeardownAction, TeardownCore,
};
use retina::rtp::Continuity;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;

use crate::error::classify;

/// How much free space a read from the camera asks of retina's buffer at
/// least: 16 KiB, as the relay reads.
const READ_RESERVE: usize = 16_384;

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
#[derive(Debug)]
pub(crate) enum Error {
    /// retina's: a refused or unreadable answer, a read that failed or
    /// ended mid-request, a keepalive unanswered.
    Session(retina::client::Error),
    /// Writing to the camera failed.
    Write(io::Error),
    /// The camera closed the connection, and every packet before its
    /// close was handed out.
    Closed,
}

impl Error {
    /// The error as the source reports it for `url`: retina's classified
    /// ([`classify`]), the connection's own as `ended`.
    pub(crate) fn source_error(&self, url: &SourceUrl) -> SourceError {
        match self {
            Self::Session(err) => classify(err, url),
            Self::Write(err) => SourceError::Ended(format!("writing to the camera failed: {err}")),
            Self::Closed => SourceError::Ended("the camera closed the session".into()),
        }
    }

    /// The RTSP status of a refused request, if it is one.
    pub(crate) fn status_code(&self) -> Option<u16> {
        match self {
            Self::Session(err) => err.status_code(),
            Self::Write(_) | Self::Closed => None,
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
        Poll::Ready(Err(err)) => Poll::Ready(Err(Failed::Read(err))),
        Poll::Pending => Poll::Pending,
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
            conn: conn.stream,
            time,
        }
    }

    /// The streams the `DESCRIBE` answer described; none before it.
    pub(crate) fn streams(&self) -> &[Stream] {
        self.core.streams()
    }

    /// The raw SDP of the `DESCRIBE` answer; empty before it.
    pub(crate) fn sdp(&self) -> &[u8] {
        self.core.sdp()
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
        self.core
            .setup(index, SetupTransport::Tcp)
            .map_err(Error::Session)?;
        self.request().await?;
        Ok(())
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
        match failed {
            Failed::Read(err) => Error::Session(self.core.read_error(err, self.time.now())),
            Failed::Write(err) => Error::Write(err),
        }
    }

    /// The next item of a playing session, once one arrived; keepalives
    /// and receiver reports go out when retina has them due, and the
    /// camera's bytes are read meanwhile. [`Error::Closed`] once the
    /// camera closed the connection and every item before was handed out.
    /// Only while playing: before, the session has no timers and this
    /// spins on its reads.
    pub(crate) async fn next_item(&mut self) -> Result<Item, Error> {
        loop {
            let now = self.time.now();
            let due = self.core.poll_timeout().unwrap_or(now);
            if due <= now {
                self.core.handle_timeout(now).map_err(Error::Session)?;
            }
            let item = self
                .core
                .poll_item(now)
                .transpose()
                .map_err(Error::Session)?;
            if let Some(item) = copied(item) {
                return Ok(item);
            }
            if self.core.is_closed() {
                return Err(Error::Closed);
            }
            let next = self.core.poll_timeout().unwrap_or(now);
            let wait = self.time.sleep(next.saturating_duration_since(now));
            let exchanged = tokio::select! {
                exchanged = exchange(&mut *self.conn, &mut self.core) => exchanged,
                () = wait => Ok(()),
            };
            if let Err(failed) = exchanged {
                return Err(self.failure(failed));
            }
        }
    }

    /// Ends the session on the camera as retina's teardown policy says
    /// (RFC 2326 §10.7, RFC 7826 §13.7): first on the session's own
    /// connection, then, when the policy retries, on fresh ones from
    /// `dial`, until the camera answered, retina gives up, or the caller,
    /// which bounds it, drops it. Nothing when no `SETUP` succeeded.
    pub(crate) async fn teardown(self, dial: &Dial<'_>) {
        let Self { core, conn, time } = self;
        let Some(mut teardown) = core.into_teardown(time.now()) else {
            tracing::debug!("rtsp: no session to tear down");
            return;
        };
        let mut conn = conn;
        loop {
            let now = time.now();
            match teardown.poll(now) {
                TeardownAction::Io { deadline } => {
                    let wait = time.sleep(deadline.saturating_duration_since(now));
                    let failed = tokio::select! {
                        exchanged = exchange(&mut *conn, &mut teardown) => exchanged.err().map(Failed::into_io),
                        () = wait => None,
                    };
                    if let Some(err) = failed {
                        teardown.handle_io_error(err, time.now());
                    }
                }
                TeardownAction::Connect { deadline } => {
                    conn = closed();
                    tracing::debug!("rtsp: TEARDOWN on a fresh connection");
                    let wait = time.sleep(deadline.saturating_duration_since(now));
                    let dialed = tokio::select! {
                        dialed = dial() => Some(dialed),
                        () = wait => None,
                    };
                    match dialed {
                        Some(Ok(fresh)) => {
                            teardown.connected(fresh.local, fresh.peer, time.now());
                            conn = fresh.stream;
                        }
                        Some(Err(err)) => {
                            teardown.handle_io_error(io::Error::other(err.to_string()), time.now());
                        }
                        // At its deadline: the next poll fails the attempt
                        // as timed out.
                        None => {}
                    }
                }
                TeardownAction::Wait { until } => {
                    conn = closed();
                    time.sleep(until.saturating_duration_since(now)).await;
                }
                // Done, or an action a later retina may add, which this
                // driver cannot follow.
                _ => {
                    tracing::debug!("rtsp: teardown over");
                    return;
                }
            }
        }
    }
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use lotse_core::clock::FakeClock;
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
            assert!(!keepalive.is_empty());
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
        // A request retina refuses to start is its error too.
        let refused = driver.setup(0).await.unwrap_err();
        assert!(matches!(refused, Error::Session(_)), "{refused:?}");
        let refused = driver.play(play_options()).await.unwrap_err();
        assert!(matches!(refused, Error::Session(_)), "{refused:?}");
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
            if self.fault() == Fault::Read {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
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
        let (_clock, mut driver, faults, mut cam) = faulty(TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        *faults.lock().unwrap() = Fault::Read;
        let err = driver.next_item().await.unwrap_err();
        assert!(
            matches!(
                err.source_error(&SourceUrl::parse("rtsp://cam/").unwrap()),
                SourceError::Ended(m) if m.starts_with("Error reading from RTSP peer: connection reset")
            ),
            "{err:?}"
        );
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
        driver.teardown(&dial).await;
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
        tokio::join!(driver.teardown(&dial), camera);
        assert_eq!(dialer.calls(), 0);
    }

    #[tokio::test]
    async fn rfc2326_10_7_an_unanswered_teardown_gives_up_at_its_deadline() {
        let _logs = traced();
        let (clock, mut driver, mut cam) = rig(64 * 1024, TeardownPolicy::Auto);
        played(&mut driver, &mut cam).await;
        let dialer = Dialer::new([]);
        let camera = async {
            let head = cam.request().await;
            assert!(head.starts_with("TEARDOWN"), "{head}");
            // retina waits 5 s for the answer on the session's connection,
            // and its `Auto` policy tries no more over TCP.
            clock.advance(Duration::from_secs(5));
        };
        let dial = dial_with(&dialer);
        tokio::join!(driver.teardown(&dial), camera);
        assert_eq!(dialer.calls(), 0);
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
        tokio::join!(driver.teardown(&dial), camera);
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
        tokio::join!(driver.teardown(&dial), camera);
        assert_eq!(dialer.calls(), 0);
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
        let kind = Failed::Read(io::ErrorKind::Other.into()).into_io().kind();
        assert_eq!(kind, io::ErrorKind::Other);
    }
}

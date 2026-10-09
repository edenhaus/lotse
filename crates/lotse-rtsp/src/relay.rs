//! The loopback relay every RTSP connection goes through: retina speaks
//! plain RTSP to a listener on `127.0.0.1`, and the relay carries it to the
//! camera, over TCP for `rtsp` and the TLS stream for `rtsps`.
//!
//! retina 0.4 opens its own `TcpStream` from the URL and has no way to be
//! handed a stream or to speak TLS. So the source connects to the camera
//! itself (and completes the TLS handshake for `rtsps`), then lets retina
//! connect to the relay's listener and copies bytes both ways between that
//! one connection and the camera. retina's requests go on whole; what the
//! camera sends goes on as it arrives, interleaved RTP included.
//!
//! In a sandboxed worker Landlock allows TCP `bind` and `connect` only on
//! the ports listed at startup, so the worker binds the listener before its
//! sandbox and passes it to the factory (`--loopback-relay`); without one,
//! the relay binds an ephemeral port per attempt (tests, `--sandbox off`).
//! A pre-bound listener is shared by every attempt of the worker's one
//! connection: connections left in its backlog by an earlier attempt are
//! dropped before retina connects, and each attempt accepts exactly one.
//!
//! With `transport: "udp"` the relay also carries the media's UDP side:
//! [`crate::udp`] translates the `SETUP` exchange, frames every message
//! both ways, and hands retina the camera's datagrams as interleaved
//! frames between whole messages. A UDP session outlives its control
//! connection (RFC 2326 §1.1), so once the camera's connection is gone
//! (closed, failed or refused), the relay keeps retina's side and sends
//! the session's `TEARDOWN` (§10.7, RFC 7826 §13.7) on a fresh one
//! ([`teardown`]), as retina's own teardown policy does for UDP; over
//! TCP the interleaved session ends with its connection.
//!
//! The relay also sends the camera RTCP Receiver Reports, which retina
//! does not ([`crate::rtcp`]): over TCP a [`Tap`] reads along the camera's
//! interleaved frames and the reports go on each stream's RTCP channel
//! between retina's whole requests, which the relay frames for that
//! (RFC 2326 §10.12); over UDP [`crate::udp`] keeps the statistics and
//! sends them from each stream's RTCP port.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use lotse_core::clock::Clock;
use lotse_core::source::SourceError;
use lotse_core::source_url::SourceUrl;
use lotse_core::task::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::framer::Framer;
use crate::rtcp::ReceiverReports;
use crate::tap::Tap;
use crate::udp::{self, MAX_DATAGRAM, UdpRelay};

/// How much the relay reads from the camera at once: 16 KiB.
const READ_CHUNK: usize = 16_384;

/// Connects to the camera at `addr`; a failure is `unreachable`, worded
/// as retina words its own.
pub(crate) async fn tcp(addr: SocketAddr) -> Result<TcpStream, SourceError> {
    TcpStream::connect(addr)
        .await
        .map_err(|err| SourceError::Unreachable(format!("Unable to connect to {addr}: {err}")))
}

/// The relay's listener for one attempt and its address: a clone of the
/// pre-bound one with its stale backlog dropped, or a fresh ephemeral port.
pub(crate) async fn listen(
    pre_bound: Option<&StdListener>,
) -> Result<(TcpListener, SocketAddr), SourceError> {
    let failed = |err: io::Error| SourceError::Unreachable(format!("rtsp relay: {err}"));
    let listener = bind(pre_bound).await.map_err(failed)?;
    let local = listener.local_addr().map_err(failed)?;
    Ok((listener, local))
}

/// [`listen`] before its error is typed.
async fn bind(pre_bound: Option<&StdListener>) -> io::Result<TcpListener> {
    let Some(listener) = pre_bound else {
        return TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await;
    };
    let listener = listener.try_clone()?;
    listener.set_nonblocking(true)?;
    let mut stale = 0_u32;
    while listener.accept().is_ok() {
        stale = stale.saturating_add(1);
    }
    tracing::debug!(
        stale,
        "rtsp relay: listening; connections left by earlier attempts dropped"
    );
    TcpListener::from_std(listener)
}

/// The URL retina connects to: scheme `rtsp`, which is all retina accepts,
/// and the relay's address, with the camera's path and query.
// SPEC-DEVIATION(RFC 7826 §19.2, RFC 2326 §6.1): the Request-URI the
// camera sees says `rtsp://127.0.0.1:<relay port>` instead of
// `rtsps://<host>` or `rtsp://<host>`, because retina sends the URL it
// connected to; cameras route by path. gates:
// rtsps_plays_with_a_pinned_certificate_rfc7826_19_2,
// an_sdp_retina_cannot_parse_is_refused_as_protocol_rfc8866_5
pub(crate) fn relay_url(url: &SourceUrl, local: SocketAddr) -> url::Url {
    let mut target = url.url().clone();
    // Neither can fail: `rtsps` and `rtsp` are both non-special schemes, and
    // a source URL always has a host.
    let _same_kind = target.set_scheme("rtsp");
    let _has_host = target.set_ip_host(local.ip());
    let _has_port = target.set_port(Some(local.port()));
    target
}

/// How the media of one attempt takes: interleaved on the camera's
/// connection, with the receiver reports and the time they keep, or as
/// datagrams through the UDP side, which keeps both itself.
#[derive(Debug)]
pub(crate) enum Media {
    /// TCP interleaved.
    Interleaved(ReceiverReports, Arc<dyn Clock>),
    /// RTP over UDP.
    Udp(Box<UdpRelay>),
}

/// The sleep until `due` on `clock`, none for no due time.
fn sleep_until(clock: &dyn Clock, due: Option<Instant>) -> Option<BoxFuture<'static, ()>> {
    due.map(|due| clock.sleep(due.saturating_duration_since(clock.now())))
}

/// Why the copy ended early.
#[derive(Debug)]
enum Ended {
    /// A side failed.
    Io(io::Error),
    /// The relay refused what one side sent.
    Refused(SourceError),
    /// Over UDP, the camera's connection is gone, with why: retina's side
    /// stays open for the session's `TEARDOWN`.
    CameraGone(SourceError, Box<Orphan>),
}

/// How the relay ended the attempt: why, and over UDP retina's side, kept
/// for the session's `TEARDOWN` on a fresh connection.
#[derive(Debug)]
pub(crate) struct RelayEnd {
    /// The attempt's error.
    pub(crate) error: SourceError,
    /// retina's side, when its session still needs a `TEARDOWN`.
    pub(crate) orphan: Option<Box<Orphan>>,
}

/// retina's side of a UDP relay whose camera connection is gone, and the
/// translation state, whose framer may hold part of retina's next
/// request.
#[derive(Debug)]
pub(crate) struct Orphan {
    /// What retina writes.
    from_retina: OwnedReadHalf,
    /// What retina reads.
    to_retina: OwnedWriteHalf,
    /// The translation.
    udp: UdpRelay,
}

/// Accepts retina's connection and copies between it and the camera until
/// both sides closed, or with `udp` translates between them and adds the
/// camera's datagrams. Ends when a side sends what the relay cannot frame,
/// with why, and over UDP also when the camera's
/// connection is gone, with retina's side for the `TEARDOWN`; otherwise it
/// stays pending once the copy is over, and the source, which keeps
/// polling the session, notices the closed relay as an ended connection.
pub(crate) async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
    listener: TcpListener,
    camera: S,
    media: Media,
) -> RelayEnd {
    let copied = match media {
        Media::Interleaved(reports, clock) => relay(listener, camera, reports, clock).await,
        Media::Udp(udp) => relay_udp(listener, camera, *udp).await,
    };
    let end = match copied {
        Ok((to_camera, from_camera)) => {
            tracing::debug!(to_camera, from_camera, "rtsp relay: closed");
            None
        }
        Err(Ended::Io(err)) => {
            tracing::debug!(error = %err, "rtsp relay: ended");
            None
        }
        Err(Ended::Refused(error)) => Some(RelayEnd {
            error,
            orphan: None,
        }),
        Err(Ended::CameraGone(error, orphan)) => Some(RelayEnd {
            error,
            orphan: Some(orphan),
        }),
    };
    match end {
        Some(end) => end,
        None => match std::future::pending::<Infallible>().await {},
    }
}

/// Which of the relay and the session it carries ended first.
#[derive(Debug)]
pub(crate) enum First<R, S> {
    /// The relay, with how it ended.
    Relay(R),
    /// The session, with its exit.
    Session(S),
}

/// Runs the relay's `pump` beside the `session` it carries, in the
/// session's task, until one of them ends.
///
/// The session is polled first. Both spend the task's cooperative budget,
/// and a pump that never waits spends all of it on every wake-up before
/// it yields: polled first, it would starve the session, whose reads and
/// read deadline then never complete. A pump that ends still wins over
/// what its end causes: it closes retina's connection only in the poll it
/// ends in, after the session's turn, so the session cannot have seen
/// that close yet.
pub(crate) async fn beside<R, S>(
    pump: impl Future<Output = R>,
    session: impl Future<Output = S>,
) -> First<R, S> {
    tokio::select! {
        biased;
        exit = session => First::Session(exit),
        ended = pump => First::Relay(ended),
    }
}

/// Carries the `TEARDOWN` retina sends for a UDP session whose camera
/// connection is gone to the camera on a fresh connection from `connect`,
/// and the camera's answer back (RFC 2326 §1.1: the session is not tied
/// to its connection, so the camera would otherwise send datagrams to the
/// closed ports until its session times out). retina's other requests are
/// dropped. Best effort: the source bounds it with the teardown budget,
/// and a reconnect or shutdown never waits for it longer.
pub(crate) async fn teardown<S, F>(orphan: Box<Orphan>, connect: impl FnOnce() -> F)
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = Result<S, SourceError>>,
{
    match fresh_teardown(*orphan, connect).await {
        Ok(()) => tracing::debug!("rtsp udp: TEARDOWN answered on a fresh connection"),
        Err(why) => {
            tracing::debug!(error = %why, "rtsp udp: TEARDOWN on a fresh connection failed");
        }
    }
}

/// [`teardown`] until the answer reached retina, or why not.
async fn fresh_teardown<S, F>(orphan: Orphan, connect: impl FnOnce() -> F) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = Result<S, SourceError>>,
{
    let Orphan {
        mut from_retina,
        mut to_retina,
        mut udp,
    } = orphan;
    let mut buf = vec![0_u8; READ_CHUNK];
    let request = loop {
        let n = from_retina
            .read(&mut buf)
            .await
            .map_err(|err| err.to_string())?;
        let bytes = buf.get(..n).filter(|read| !read.is_empty());
        let bytes = bytes.ok_or("retina closed without a TEARDOWN")?;
        if let Some(request) = udp.orphaned_request(bytes).map_err(|err| err.to_string())? {
            break request;
        }
    };
    let mut camera = connect().await.map_err(|err| err.to_string())?;
    tracing::debug!("rtsp udp: TEARDOWN sent on a fresh connection");
    camera
        .write_all(&request)
        .await
        .map_err(|err| err.to_string())?;
    loop {
        let n = camera.read(&mut buf).await.map_err(|err| err.to_string())?;
        let bytes = buf.get(..n).filter(|read| !read.is_empty());
        let bytes = bytes.ok_or("the camera closed without answering")?;
        if let Some(answer) = udp.fresh_answer(bytes).map_err(|err| err.to_string())? {
            return to_retina
                .write_all(&answer)
                .await
                .map_err(|err| err.to_string());
        }
    }
}

/// [`pump`] until it ends: the bytes copied each way. retina's requests
/// go on whole, with the receiver reports due between them; the camera's
/// side goes on as it arrives, read along by the tap.
async fn relay<S: AsyncRead + AsyncWrite + Unpin>(
    listener: TcpListener,
    camera: S,
    reports: ReceiverReports,
    clock: Arc<dyn Clock>,
) -> Result<(u64, u64), Ended> {
    let (plain, _) = listener.accept().await.map_err(Ended::Io)?;
    drop(listener);
    let (mut from_retina, mut to_retina) = plain.into_split();
    let (mut from_camera, mut to_camera) = tokio::io::split(camera);
    // Both directions run in this one task and never hold the lock across
    // an await: it is never contended.
    let reports = Mutex::new(reports);
    let locked = || reports.lock().unwrap_or_else(PoisonError::into_inner);
    // The camera's side moved a report earlier.
    let rescheduled = Notify::new();
    let up = async {
        let mut framer = Framer::default();
        let mut buf = vec![0_u8; READ_CHUNK];
        let mut out = Vec::new();
        let mut copied = 0_u64;
        loop {
            // A report round awaits nothing that waits: the runtime's
            // cooperative budget keeps the loop from holding its worker.
            tokio::task::coop::consume_budget().await;
            let mut due = sleep_until(&*clock, locked().due());
            out.clear();
            tokio::select! {
                biased;
                read = from_retina.read(&mut buf) => {
                    let n = read.map_err(Ended::Io)?;
                    let Some(bytes) = buf.get(..n).filter(|read| !read.is_empty()) else {
                        to_camera.shutdown().await.map_err(Ended::Io)?;
                        return Ok(copied);
                    };
                    framer.pending.extend_from_slice(bytes);
                    while let Some(framed) = framer.next().map_err(|why| {
                        Ended::Refused(SourceError::Protocol(format!("rtsp relay: retina's request is unreadable: {why}")))
                    })? {
                        out.extend_from_slice(&framed.raw);
                    }
                }
                () = rescheduled.notified() => continue,
                () = async { if let Some(due) = &mut due { due.await } }, if due.is_some() => {
                    let reports = locked().take_due(clock.now());
                    for report in reports {
                        report.interleave(&mut out);
                    }
                }
            }
            to_camera.write_all(&out).await.map_err(Ended::Io)?;
            copied = copied.saturating_add(u64::try_from(out.len()).unwrap_or(u64::MAX));
        }
    };
    let down = async {
        let mut tap = Tap::default();
        let mut buf = vec![0_u8; READ_CHUNK];
        let mut copied = 0_u64;
        loop {
            let n = from_camera.read(&mut buf).await.map_err(Ended::Io)?;
            let Some(read) = buf.get(..n).filter(|read| !read.is_empty()) else {
                to_retina.shutdown().await.map_err(Ended::Io)?;
                return Ok(copied);
            };
            if tap.feed(read, clock.now(), &mut locked()) {
                rescheduled.notify_one();
            }
            to_retina.write_all(read).await.map_err(Ended::Io)?;
            copied = copied.saturating_add(u64::try_from(read.len()).unwrap_or(u64::MAX));
        }
    };
    tokio::try_join!(up, down)
}

/// Why one step of the UDP relay stopped it.
#[derive(Debug)]
enum Stop {
    /// As in [`Ended`]: retina's side failed, or retina wrote what no
    /// RTSP parser reads.
    Ended(Ended),
    /// The camera closed after the session was over: retina sees its
    /// side end.
    Closed,
    /// The camera's connection is gone while the session is not over.
    Gone(SourceError),
}

impl From<Ended> for Stop {
    fn from(ended: Ended) -> Self {
        Self::Ended(ended)
    }
}

/// Why reading the camera ended: expected once the session is `over`
/// (retina closed, or sent its `TEARDOWN`), else the session lost it.
fn camera_ended(over: bool, failed: Option<io::Error>) -> Stop {
    match (over, failed) {
        (true, None) => Stop::Closed,
        (true, Some(err)) => Stop::Ended(Ended::Io(err)),
        (false, None) => Stop::Gone(SourceError::Ended("the camera closed the session".into())),
        (false, Some(err)) => Stop::Gone(SourceError::Ended(format!(
            "reading from the camera failed: {err}"
        ))),
    }
}

/// The UDP relay's state between steps: both connections, the
/// translation and the buffers.
struct UdpPump<S> {
    /// What retina writes.
    from_retina: OwnedReadHalf,
    /// What retina reads.
    to_retina: OwnedWriteHalf,
    /// What the camera sends.
    from_camera: tokio::io::ReadHalf<S>,
    /// What the camera reads.
    to_camera: tokio::io::WriteHalf<S>,
    /// The translation.
    udp: UdpRelay,
    /// Reads from the camera.
    camera_buf: Vec<u8>,
    /// Reads from retina.
    retina_buf: Vec<u8>,
    /// One datagram.
    datagram: Vec<u8>,
    /// What one step writes.
    out: Vec<u8>,
    /// retina has not closed its side.
    retina_open: bool,
    /// The pair the next receive starts at, so none starves.
    start: usize,
    /// Bytes sent to the camera.
    up: u64,
    /// Bytes sent to retina, datagrams included.
    down: u64,
    /// When the next receiver report is due, as `timer` sleeps for it.
    due: Option<Instant>,
    /// The sleep until `due`.
    timer: Option<BoxFuture<'static, ()>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> UdpPump<S> {
    /// One read of the camera, retina or a pair, and what it makes go on;
    /// the camera is read first.
    async fn step(&mut self) -> Result<(), Stop> {
        self.out.clear();
        let due = self.udp.report_due();
        if due != self.due {
            self.due = due;
            self.timer = sleep_until(self.udp.clock(), due);
        }
        tokio::select! {
            biased;
            read = self.from_camera.read(&mut self.camera_buf) => {
                let over = !self.retina_open || self.udp.tearing_down();
                let n = read.map_err(|err| camera_ended(over, Some(err)))?;
                let bytes = self.camera_buf.get(..n).filter(|read| !read.is_empty());
                let bytes = bytes.ok_or_else(|| camera_ended(over, None))?;
                self.udp.camera_sent(bytes, &mut self.out).map_err(Stop::Gone)?;
                self.to_retina.write_all(&self.out).await.map_err(Ended::Io)?;
                self.down = self.down.saturating_add(u64::try_from(self.out.len()).unwrap_or(u64::MAX));
            }
            read = self.from_retina.read(&mut self.retina_buf), if self.retina_open => {
                let n = read.map_err(Ended::Io)?;
                let Some(bytes) = self.retina_buf.get(..n).filter(|read| !read.is_empty()) else {
                    self.retina_open = false;
                    self.to_camera.shutdown().await.map_err(Ended::Io)?;
                    return Ok(());
                };
                self.udp.retina_wrote(bytes, &mut self.out).map_err(Ended::Refused)?;
                let written = self.to_camera.write_all(&self.out).await;
                written.map_err(|err| Stop::Gone(SourceError::Ended(format!("writing to the camera failed: {err}"))))?;
                self.up = self.up.saturating_add(u64::try_from(self.out.len()).unwrap_or(u64::MAX));
            }
            // Before the datagrams, which a busy camera never runs out of.
            () = async { if let Some(timer) = &mut self.timer { timer.await } }, if self.timer.is_some() => {
                (self.due, self.timer) = (None, None);
                self.udp.report(&mut self.out).await;
                let written = self.to_camera.write_all(&self.out).await;
                written.map_err(|err| Stop::Gone(SourceError::Ended(format!("writing to the camera failed: {err}"))))?;
                self.up = self.up.saturating_add(u64::try_from(self.out.len()).unwrap_or(u64::MAX));
            }
            received = self.udp.recv(self.start, &mut self.datagram) => {
                self.start = self.start.wrapping_add(1);
                let received = received.map_err(|err| Stop::Gone(udp::receive_failed(&err)))?;
                let payload = self.datagram.get(..received.len).unwrap_or_default();
                self.udp.datagram(received, payload, &mut self.out);
                self.to_retina.write_all(&self.out).await.map_err(Ended::Io)?;
                self.down = self.down.saturating_add(u64::try_from(self.out.len()).unwrap_or(u64::MAX));
            }
        }
        Ok(())
    }
}

/// [`pump`] over UDP until it ends. One loop serves retina, the camera
/// and the pairs, so a frame of a datagram only ever goes to retina
/// between whole messages. Once the camera's connection is gone while the
/// session is not over, retina's side and the translation are kept for
/// the `TEARDOWN` ([`teardown`]).
async fn relay_udp<S: AsyncRead + AsyncWrite + Unpin>(
    listener: TcpListener,
    camera: S,
    udp: UdpRelay,
) -> Result<(u64, u64), Ended> {
    let (plain, _) = listener.accept().await.map_err(Ended::Io)?;
    drop(listener);
    let (from_retina, to_retina) = plain.into_split();
    let (from_camera, to_camera) = tokio::io::split(camera);
    let mut pump = UdpPump {
        from_retina,
        to_retina,
        from_camera,
        to_camera,
        udp,
        camera_buf: vec![0_u8; READ_CHUNK],
        retina_buf: vec![0_u8; READ_CHUNK],
        datagram: vec![0_u8; MAX_DATAGRAM],
        out: Vec::new(),
        retina_open: true,
        start: 0,
        up: 0,
        down: 0,
        due: None,
        timer: None,
    };
    let stop = loop {
        // As in [`relay`]: a step that waits for nothing still yields to
        // the runtime once its cooperative budget is spent.
        tokio::task::coop::consume_budget().await;
        if let Err(stop) = pump.step().await {
            break stop;
        }
    };
    match stop {
        Stop::Ended(ended) => Err(ended),
        Stop::Closed => {
            pump.to_retina.shutdown().await.map_err(Ended::Io)?;
            Ok((pump.up, pump.down))
        }
        Stop::Gone(why) => {
            tracing::info!(error = %why, "rtsp udp: the camera's connection is gone; the session's TEARDOWN goes on a fresh one");
            let UdpPump {
                from_retina,
                to_retina,
                udp,
                ..
            } = pump;
            Err(Ended::CameraGone(
                why,
                Box::new(Orphan {
                    from_retina,
                    to_retina,
                    udp,
                }),
            ))
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

    use std::pin::Pin;
    use std::task::{Context, Poll};

    use lotse_core::task::spawn_named;
    use tokio::io::ReadBuf;
    use tokio::net::TcpStream;

    use super::*;

    #[test]
    fn the_relay_url_keeps_path_and_query_and_drops_the_credentials() {
        let url = SourceUrl::parse("rtsps://admin:secret@camera.local/h264?x=1").unwrap();
        let target = relay_url(&url, "127.0.0.1:41000".parse().unwrap());
        assert_eq!(target.as_str(), "rtsp://127.0.0.1:41000/h264?x=1");
    }

    #[tokio::test]
    async fn a_pre_bound_listener_drops_its_stale_backlog() {
        let pre_bound = StdListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = pre_bound.local_addr().unwrap();
        let _stale = std::net::TcpStream::connect(addr).unwrap();
        let (listener, local) = listen(Some(&pre_bound)).await.unwrap();
        assert_eq!(local, addr);
        // The stale connection is gone: the next accept is the new one.
        let fresh = TcpStream::connect(addr).await.unwrap();
        let (_accepted, peer) = listener.accept().await.unwrap();
        assert_eq!(peer, fresh.local_addr().unwrap());
        // Without one, every attempt binds its own port.
        let (_own, own) = listen(None).await.unwrap();
        assert_ne!(own, addr);
        assert!(own.ip().is_loopback());
    }

    fn reports() -> ReceiverReports {
        use crate::rtcp::{Seed, SetupRates};

        ReceiverReports::new(Arc::new(SetupRates::default()), Seed::random())
    }

    fn tcp_media() -> Media {
        use lotse_core::clock::SystemClock;

        Media::Interleaved(reports(), Arc::new(SystemClock))
    }

    /// `future`, or a failed test after 5 s rather than a hung one.
    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        use lotse_core::clock::{Clock as _, SystemClock};
        tokio::select! {
            out = future => out,
            () = SystemClock.sleep(std::time::Duration::from_secs(5)) => panic!("no progress within 5 s"),
        }
    }

    /// Lets the pump run until it is idle.
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_pump_that_never_waits_leaves_the_session_its_turn_and_one_that_ends_wins() {
        use lotse_core::clock::{Clock as _, SystemClock};

        // In a task of its own, as in the source: the spinning pump spends
        // that task's cooperative budget on every wake-up, and the
        // session's sleep still ends.
        let race = spawn_named("test.beside", async {
            let spinning = async {
                loop {
                    tokio::task::coop::consume_budget().await;
                }
            };
            let session = SystemClock.sleep(std::time::Duration::from_millis(10));
            matches!(beside(spinning, session).await, First::Session(()))
        });
        assert!(bounded(race).await.unwrap(), "the session ends first");
        let ended = beside(async { 7 }, std::future::pending::<()>()).await;
        assert!(matches!(ended, First::Relay(7)), "{ended:?}");
    }

    #[tokio::test]
    async fn the_pump_copies_both_ways_and_outlives_the_close() {
        let (listener, local) = listen(None).await.unwrap();
        let (camera, mut far) = tokio::io::duplex(1024);
        let relay = spawn_named("test.pump", pump(listener, camera, tcp_media()));
        let mut plain = TcpStream::connect(local).await.unwrap();
        let request = b"DESCRIBE rtsp://127.0.0.1/ RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        plain.write_all(request).await.unwrap();
        let mut got = vec![0_u8; request.len()];
        bounded(far.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, request);
        // The answer in two pieces, then media, all as they arrive.
        let answer =
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 10\r\n\r\nv=0\r\ns=-\r\n$\x00\x00\x01z";
        far.write_all(&answer[..20]).await.unwrap();
        far.write_all(&answer[20..]).await.unwrap();
        let mut got = vec![0_u8; answer.len()];
        bounded(plain.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, answer);
        // Both sides close; the relay stays, for the session to decide.
        drop(far);
        plain.shutdown().await.unwrap();
        let mut rest = Vec::new();
        assert_eq!(bounded(plain.read_to_end(&mut rest)).await.unwrap(), 0);
        settle().await;
        assert!(!relay.is_finished());
        relay.abort();
    }

    /// The read half of a camera connection that fails.
    struct Broken;

    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("broken")))
        }
    }

    #[tokio::test]
    async fn a_failing_camera_ends_the_copy_and_retina_sees_the_close() {
        let (listener, local) = listen(None).await.unwrap();
        let camera = tokio::io::join(Broken, tokio::io::sink());
        let relay = spawn_named("test.pump", pump(listener, camera, tcp_media()));
        let mut plain = TcpStream::connect(local).await.unwrap();
        let mut rest = Vec::new();
        // The copy fails and drops retina's side: EOF or a reset.
        let _closed = bounded(plain.read_to_end(&mut rest)).await;
        assert!(rest.is_empty());
        settle().await;
        assert!(!relay.is_finished(), "a failure is the session's to report");
        relay.abort();
    }

    #[tokio::test]
    async fn a_relay_whose_listener_fails_stays_for_the_session_to_decide() {
        let (listener, _local) = listen(None).await.unwrap();
        // A listener that never sees retina: the attempt's deadline ends it.
        let (camera, _far) = tokio::io::duplex(16);
        let relay = spawn_named("test.pump", pump(listener, camera, tcp_media()));
        settle().await;
        assert!(!relay.is_finished());
        relay.abort();
    }

    /// Reads one bodiless RTSP message from `stream`, bounded.
    async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            bounded(stream.read_exact(&mut byte)).await.unwrap();
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    #[tokio::test]
    async fn rfc2326_12_39_over_udp_the_pump_translates_setup_and_frames_datagrams_between_messages()
     {
        use lotse_core::clock::SystemClock;
        use tokio::net::UdpSocket;

        let (listener, local) = listen(None).await.unwrap();
        let (camera, mut far) = tokio::io::duplex(4096);
        let udp = UdpRelay::new(
            Ipv4Addr::LOCALHOST.into(),
            Arc::default(),
            Arc::new(SystemClock),
            reports(),
        );
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Udp(Box::new(udp))),
        );
        let mut plain = TcpStream::connect(local).await.unwrap();
        let described =
            b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: 5\r\n\r\nv=0\r\n";
        far.write_all(described).await.unwrap();
        let mut got = vec![0_u8; described.len()];
        bounded(plain.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, described);
        plain
            .write_all(b"SETUP rtsp://127.0.0.1/s/track0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n")
            .await
            .unwrap();
        let request = read_head(&mut far).await;
        let at = request.find("client_port=").unwrap() + "client_port=".len();
        let port: u16 = request[at..].split('-').next().unwrap().parse().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_port = server.local_addr().unwrap().port();
        far.write_all(format!("RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 7\r\nTransport: RTP/AVP;unicast;client_port={port}-{};server_port={server_port}-{}\r\n\r\n", port + 1, server_port + 1).as_bytes()).await.unwrap();
        let answer = read_head(&mut plain).await;
        assert!(
            answer.contains("Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"),
            "{answer}"
        );
        plain
            .write_all(b"PLAY rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 4\r\nSession: 7\r\n\r\n")
            .await
            .unwrap();
        assert!(read_head(&mut far).await.starts_with("PLAY "));
        far.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 7\r\n\r\n")
            .await
            .unwrap();
        assert!(read_head(&mut plain).await.contains("CSeq: 4"));
        // A datagram from the camera's RTP port reaches retina framed.
        let packet = [0x80, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 9, 0xaa];
        server.send_to(&packet, ("127.0.0.1", port)).await.unwrap();
        let mut frame = [0_u8; 17];
        bounded(plain.read_exact(&mut frame)).await.unwrap();
        assert_eq!(frame[..4], [b'$', 0, 0, 13]);
        assert_eq!(frame[4..], packet);
        // retina closes: the camera sees its side end; the camera closes:
        // retina's ends; the relay stays for the session to decide.
        plain.shutdown().await.unwrap();
        let mut rest = Vec::new();
        assert_eq!(bounded(far.read_to_end(&mut rest)).await.unwrap(), 0);
        drop(far);
        assert_eq!(bounded(plain.read_to_end(&mut rest)).await.unwrap(), 0);
        settle().await;
        assert!(!relay.is_finished());
        relay.abort();
    }

    #[tokio::test]
    async fn over_udp_a_camera_the_relay_refuses_ends_the_pump_with_why() {
        use lotse_core::clock::SystemClock;

        let (listener, local) = listen(None).await.unwrap();
        let (camera, mut far) = tokio::io::duplex(1024);
        let udp = UdpRelay::new(
            Ipv4Addr::LOCALHOST.into(),
            Arc::default(),
            Arc::new(SystemClock),
            reports(),
        );
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Udp(Box::new(udp))),
        );
        let _plain = TcpStream::connect(local).await.unwrap();
        far.write_all(b"\x01\x02 junk\r\n\r\n").await.unwrap();
        let refused = bounded(relay).await.unwrap();
        assert!(
            matches!(refused.error, SourceError::Protocol(ref m) if m.contains("unreadable")),
            "{refused:?}"
        );
        assert!(
            refused.orphan.is_some(),
            "retina's side kept for the TEARDOWN"
        );
    }

    fn udp_relay() -> UdpRelay {
        use lotse_core::clock::SystemClock;

        UdpRelay::new(
            Ipv4Addr::LOCALHOST.into(),
            Arc::default(),
            Arc::new(SystemClock),
            reports(),
        )
    }

    #[tokio::test]
    async fn over_udp_a_failing_or_closing_camera_ends_the_pump_with_retinas_side_kept() {
        let (listener, local) = listen(None).await.unwrap();
        let camera = tokio::io::join(Broken, tokio::io::sink());
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Udp(Box::new(udp_relay()))),
        );
        let _plain = TcpStream::connect(local).await.unwrap();
        let end = bounded(relay).await.unwrap();
        assert!(
            matches!(end.error, SourceError::Ended(ref m) if m.starts_with("reading from the camera failed: broken")),
            "{end:?}"
        );
        assert!(end.orphan.is_some());

        let (listener, local) = listen(None).await.unwrap();
        let (camera, far) = tokio::io::duplex(64);
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Udp(Box::new(udp_relay()))),
        );
        let _plain = TcpStream::connect(local).await.unwrap();
        drop(far);
        let end = bounded(relay).await.unwrap();
        assert!(
            matches!(end.error, SourceError::Ended(ref m) if m == "the camera closed the session"),
            "{end:?}"
        );
        assert!(end.orphan.is_some());
    }

    /// A camera whose reads come from `far`'s writes until `far` is gone,
    /// then fail; its writes go to `far`.
    fn failing_after(far_end: tokio::io::DuplexStream) -> impl AsyncRead + AsyncWrite + Unpin {
        let (read, write) = tokio::io::split(far_end);
        tokio::io::join(read.chain(Broken), write)
    }

    #[tokio::test]
    async fn rfc2326_10_7_over_udp_the_camera_may_close_or_fail_once_retina_sent_its_teardown() {
        for fails in [false, true] {
            let (listener, local) = listen(None).await.unwrap();
            let (ours, mut far) = tokio::io::duplex(1024);
            let relay = if fails {
                spawn_named(
                    "test.pump",
                    pump(
                        listener,
                        failing_after(ours),
                        Media::Udp(Box::new(udp_relay())),
                    ),
                )
            } else {
                spawn_named(
                    "test.pump",
                    pump(listener, ours, Media::Udp(Box::new(udp_relay()))),
                )
            };
            let mut plain = TcpStream::connect(local).await.unwrap();
            let teardown =
                b"TEARDOWN rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 5\r\nSession: 7\r\n\r\n";
            plain.write_all(teardown).await.unwrap();
            assert!(read_head(&mut far).await.starts_with("TEARDOWN "));
            far.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 5\r\n\r\n")
                .await
                .unwrap();
            drop(far);
            assert!(read_head(&mut plain).await.contains("CSeq: 5"));
            // The session is over: retina sees its side end, and the
            // session decides the exit.
            let mut rest = Vec::new();
            let _closed = bounded(plain.read_to_end(&mut rest)).await;
            settle().await;
            assert!(!relay.is_finished(), "fails: {fails}");
            relay.abort();
        }
    }

    #[tokio::test]
    async fn over_udp_a_failed_write_to_the_camera_ends_the_pump_with_retinas_side_kept() {
        // A camera that sends nothing yet and whose writes fail.
        let (reads, _quiet) = tokio::io::duplex(64);
        let (writes, gone) = tokio::io::duplex(64);
        drop(gone);
        let unwritable = tokio::io::join(reads, writes);
        let (listener, local) = listen(None).await.unwrap();
        let relay = spawn_named(
            "test.pump",
            pump(listener, unwritable, Media::Udp(Box::new(udp_relay()))),
        );
        let mut plain = TcpStream::connect(local).await.unwrap();
        plain
            .write_all(b"OPTIONS rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            .await
            .unwrap();
        let end = bounded(relay).await.unwrap();
        assert!(
            matches!(end.error, SourceError::Ended(ref m) if m.starts_with("writing to the camera failed")),
            "{end:?}"
        );
        assert!(end.orphan.is_some());
    }

    #[tokio::test]
    async fn over_udp_retina_writing_what_no_parser_reads_ends_the_pump_with_nothing_to_tear_down()
    {
        let (listener, local) = listen(None).await.unwrap();
        let (camera, _far) = tokio::io::duplex(64);
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Udp(Box::new(udp_relay()))),
        );
        let mut plain = TcpStream::connect(local).await.unwrap();
        plain.write_all(b"\x01\x02 junk\r\n\r\n").await.unwrap();
        let end = bounded(relay).await.unwrap();
        assert!(
            matches!(end.error, SourceError::Protocol(ref m) if m.contains("retina's request")),
            "{end:?}"
        );
        assert!(end.orphan.is_none());
    }

    /// The orphan of a UDP relay whose camera closed, and retina's end.
    async fn orphaned_relay() -> (Box<Orphan>, TcpStream) {
        let (listener, local) = listen(None).await.unwrap();
        let (camera, far) = tokio::io::duplex(64);
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Udp(Box::new(udp_relay()))),
        );
        let plain = TcpStream::connect(local).await.unwrap();
        drop(far);
        let end = bounded(relay).await.unwrap();
        (end.orphan.unwrap(), plain)
    }

    #[tokio::test]
    async fn rfc2326_10_7_over_udp_retinas_teardown_goes_on_a_fresh_connection_and_its_answer_back()
    {
        let (orphan, mut plain) = orphaned_relay().await;
        let (fresh, mut far) = tokio::io::duplex(1024);
        let forward = spawn_named(
            "test.teardown",
            teardown(orphan, move || async move { Ok(fresh) }),
        );
        // A keepalive has nobody to answer it; the TEARDOWN, in two
        // pieces, goes on as retina wrote it.
        let teardown_request =
            b"TEARDOWN rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 6\r\nSession: 7\r\n\r\n";
        plain
            .write_all(
                b"GET_PARAMETER rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 5\r\nSession: 7\r\n\r\n",
            )
            .await
            .unwrap();
        plain.write_all(&teardown_request[..20]).await.unwrap();
        settle().await;
        plain.write_all(&teardown_request[20..]).await.unwrap();
        let mut got = vec![0_u8; teardown_request.len()];
        bounded(far.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, teardown_request);
        // The answer, after a stray interleaved frame and in two pieces,
        // reaches retina.
        far.write_all(b"$\x00\x00\x01zRTSP/1.0 200 OK\r\n")
            .await
            .unwrap();
        settle().await;
        far.write_all(b"CSeq: 6\r\n\r\n").await.unwrap();
        assert_eq!(
            read_head(&mut plain).await,
            "RTSP/1.0 200 OK\r\nCSeq: 6\r\n\r\n"
        );
        bounded(forward).await.unwrap();
    }

    /// A camera the fresh connection cannot reach.
    async fn no_camera() -> Result<tokio::io::DuplexStream, SourceError> {
        Err(SourceError::Unreachable("no".into()))
    }

    #[tokio::test]
    async fn over_udp_a_fresh_teardown_that_cannot_go_on_gives_up_and_retina_gets_nothing() {
        // retina closes without one.
        let (orphan, plain) = orphaned_relay().await;
        drop(plain);
        let forward = spawn_named("test.teardown", teardown(orphan, no_camera));
        bounded(forward).await.unwrap();
        // The camera cannot be reached.
        let (orphan, mut plain) = orphaned_relay().await;
        let forward = spawn_named("test.teardown", teardown(orphan, no_camera));
        plain
            .write_all(b"TEARDOWN rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 6\r\n\r\n")
            .await
            .unwrap();
        bounded(forward).await.unwrap();
        // The camera closes without an answer, or answers what retina
        // would abort on, or what no parser reads: retina gets nothing.
        for answer in [
            &b""[..],
            b"RTSP/1.0 200 OK\r\nCSeq: 6\r\nSession: \r\n\r\n",
            b"\x01\x02 junk\r\n\r\n",
        ] {
            let (orphan, mut plain) = orphaned_relay().await;
            let (fresh, mut far) = tokio::io::duplex(1024);
            let forward = spawn_named(
                "test.teardown",
                teardown(orphan, move || async move { Ok(fresh) }),
            );
            plain
                .write_all(b"TEARDOWN rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 6\r\n\r\n")
                .await
                .unwrap();
            assert!(read_head(&mut far).await.starts_with("TEARDOWN "));
            far.write_all(answer).await.unwrap();
            drop(far);
            bounded(forward).await.unwrap();
            let mut rest = Vec::new();
            drop(plain.shutdown().await);
            let _closed = bounded(plain.read_to_end(&mut rest)).await;
            assert!(rest.is_empty(), "{answer:?}");
        }
        // retina writes what no parser reads.
        let (orphan, mut plain) = orphaned_relay().await;
        let forward = spawn_named("test.teardown", teardown(orphan, no_camera));
        plain.write_all(b"\x01\x02 junk\r\n\r\n").await.unwrap();
        bounded(forward).await.unwrap();
    }

    /// Reports on `clock`, the video's clock rate handed over.
    fn reports_on(clock: &Arc<lotse_core::clock::FakeClock>) -> (ReceiverReports, Arc<dyn Clock>) {
        use crate::rtcp::{Seed, SetupRates};

        let rates = Arc::new(SetupRates::default());
        rates.push(90_000);
        let time: Arc<dyn Clock> = Arc::<lotse_core::clock::FakeClock>::clone(clock);
        (ReceiverReports::new(rates, Seed::random()), time)
    }

    fn rtp_frame(seq: u16) -> Vec<u8> {
        let mut frame = vec![b'$', 0, 0, 13, 0x80, 96];
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 9, 0xaa]);
        frame
    }

    #[tokio::test]
    async fn rfc3550_6_4_2_over_tcp_reports_go_on_the_rtcp_channel_between_whole_requests() {
        use lotse_core::clock::FakeClock;

        let clock = Arc::new(FakeClock::from_system());
        let (reports, time) = reports_on(&clock);
        let (listener, local) = listen(None).await.unwrap();
        let (camera, mut far) = tokio::io::duplex(4096);
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Interleaved(reports, time)),
        );
        let mut plain = TcpStream::connect(local).await.unwrap();
        let mut stream = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 5\r\n\r\nv=0\r\nRTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\nRTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 1\r\n\r\n".to_vec();
        for seq in [1, 2, 3, 5] {
            stream.extend_from_slice(&rtp_frame(seq));
        }
        far.write_all(&stream).await.unwrap();
        let mut got = vec![0_u8; stream.len()];
        bounded(plain.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, stream, "the camera's side is forwarded unchanged");
        // Half a keepalive: the report may not go inside it.
        let keepalive =
            b"GET_PARAMETER rtsp://127.0.0.1/s/ RTSP/1.0\r\nCSeq: 5\r\nSession: 1\r\n\r\n";
        plain.write_all(&keepalive[..10]).await.unwrap();
        settle().await;
        // The first report is due within 2.5 s × 1.5 / 1.21828 of the
        // first packet.
        clock.advance(std::time::Duration::from_millis(3100));
        let mut header = [0_u8; 4];
        bounded(far.read_exact(&mut header)).await.unwrap();
        assert_eq!(header[..2], [b'$', 1], "on the RTCP channel");
        let mut report = vec![0_u8; usize::from(u16::from_be_bytes([header[2], header[3]]))];
        bounded(far.read_exact(&mut report)).await.unwrap();
        assert_eq!(report[..2], [0x81, 201]);
        // Extended highest 5, one lost (seq 4), of 2..=5 after probation.
        assert_eq!(report[16..20], 5_u32.to_be_bytes());
        assert_eq!(report[13..16], [0, 0, 1]);
        plain.write_all(&keepalive[10..]).await.unwrap();
        let mut got = vec![0_u8; keepalive.len()];
        bounded(far.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, keepalive);
        relay.abort();
    }

    #[tokio::test]
    async fn over_tcp_retina_writing_what_no_parser_reads_ends_the_pump() {
        let (listener, local) = listen(None).await.unwrap();
        let (camera, _far) = tokio::io::duplex(64);
        let relay = spawn_named("test.pump", pump(listener, camera, tcp_media()));
        let mut plain = TcpStream::connect(local).await.unwrap();
        plain.write_all(b"\x01\x02 junk\r\n\r\n").await.unwrap();
        let end = bounded(relay).await.unwrap();
        assert!(
            matches!(end.error, SourceError::Protocol(ref m) if m.contains("retina's request is unreadable")),
            "{end:?}"
        );
        assert!(end.orphan.is_none());
    }

    #[tokio::test]
    async fn rfc3550_6_4_2_over_udp_the_pump_reports_when_due() {
        use lotse_core::clock::FakeClock;
        use tokio::net::UdpSocket;

        let clock = Arc::new(FakeClock::from_system());
        let (reports, time) = reports_on(&clock);
        let udp = UdpRelay::new(Ipv4Addr::LOCALHOST.into(), Arc::default(), time, reports);
        let (listener, local) = listen(None).await.unwrap();
        let (camera, mut far) = tokio::io::duplex(4096);
        let relay = spawn_named(
            "test.pump",
            pump(listener, camera, Media::Udp(Box::new(udp))),
        );
        let mut plain = TcpStream::connect(local).await.unwrap();
        let described =
            b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: 5\r\n\r\nv=0\r\n";
        far.write_all(described).await.unwrap();
        let mut got = vec![0_u8; described.len()];
        bounded(plain.read_exact(&mut got)).await.unwrap();
        plain
            .write_all(b"SETUP rtsp://127.0.0.1/s/track0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n")
            .await
            .unwrap();
        let request = read_head(&mut far).await;
        let at = request.find("client_port=").unwrap() + "client_port=".len();
        let port: u16 = request[at..].split('-').next().unwrap().parse().unwrap();
        // No server_port: the reports follow the camera's RTCP.
        far.write_all(
            b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: 7\r\nTransport: RTP/AVP;unicast\r\n\r\n",
        )
        .await
        .unwrap();
        read_head(&mut plain).await;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        server
            .send_to(&[0x80, 200, 0, 0], ("127.0.0.1", port + 1))
            .await
            .unwrap();
        for seq in [1_u16, 2] {
            server
                .send_to(&rtp_frame(seq)[4..], ("127.0.0.1", port))
                .await
                .unwrap();
        }
        // Received before PLAY, held for retina, counted for the reports:
        // the clock moves on until the first report arrives.
        let mut buf = [0_u8; 128];
        let mut reported = None;
        for _ in 0..20 {
            clock.advance(std::time::Duration::from_millis(500));
            tokio::select! {
                got = server.recv_from(&mut buf) => {
                    reported = Some(got.unwrap().0);
                    break;
                }
                () = lotse_core::clock::SystemClock.sleep(std::time::Duration::from_millis(20)) => {}
            }
        }
        assert_eq!(reported, Some(32 + 36), "one block and the SDES");
        assert_eq!(buf[..2], [0x81, 201]);
        relay.abort();
    }

    #[tokio::test]
    async fn a_camera_that_cannot_be_reached_is_unreachable() {
        // A port nothing listens on: bound, then closed.
        let addr = StdListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap();
        let Err(SourceError::Unreachable(message)) = tcp(addr).await else {
            panic!("unreachable");
        };
        assert!(message.starts_with("Unable to connect to"), "{message}");
    }
}

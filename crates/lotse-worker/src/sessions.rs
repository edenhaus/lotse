//! The session manager of a worker: the uplink datagrams routed to the
//! session tasks by local ufrag, one task per session driving its engine,
//! and egress on the shared UDP socket, as `ChannelData` to the TURN
//! server for what leaves a relay candidate, or to the supervisor on the
//! datagram channel when the allocation is a TCP one ([`crate::relay`]).
//!
//! The worker never names a WebRTC engine: it negotiates the tracks through
//! core (leasing a shared derived track when the stream's audio needs a
//! transcode, [`crate::derived`]), opens the session through the
//! registered output factory and drives the `SessionEngine` it gets back.
//! Media egress is a non-blocking `send_to`, or `sendmsg` marking the
//! audio track's packets EF and, on a socket bound to the unspecified
//! address, naming the candidate's address as the source
//! ([`crate::sendmsg`]); a full socket buffer drops the datagram and
//! counts it. The socket is set non-blocking here, which
//! the supervisor's copy shares (one open file description, fcntl(2)
//! `O_NONBLOCK`); its receive thread waits
//! with `poll(2)` and so does not care. `MSG_DONTWAIT` per call instead
//! was tried and is wrong on macOS: there it also gives up when another
//! thread holds the socket's send lock (XNU's `sosend`, `SBLOCKWAIT`), so
//! two sessions sending at once dropped datagrams (`EAGAIN`, measured on
//! 2026-09-30).
//!
//! The socket's open file description is the supervisor's and every other
//! worker's too, so the worker moves it to the number its seccomp filter
//! names ([`crate::Settings::shared_udp_fd`]) as soon as it arrives,
//! before any camera byte is read, and closes the number it arrived at:
//! from then on the worker can send on it and nothing else.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;
use lotse_core::clock_map::ClockMapper;
use lotse_core::codec::{Codec, CodecFamily, Kind};
use lotse_core::media::MediaPacket;
use lotse_core::negotiate::NegotiationError;
use lotse_core::orientation::Orientation;
use lotse_core::output::{OutputFactory, TalkbackRequest};
use lotse_core::registry::Registries;
use lotse_core::session::{
    IceCredentials, SessionEngine, SessionEvent, SessionLimits, SessionOutput, SessionRequest,
    TalkbackClaim, TalkbackTarget, Transport, apply_audio_event, apply_track_event,
};
use lotse_core::skew::AV_SYNC_LOST;
use lotse_core::source::{BACKCHANNEL_OPEN_LIMIT, BackchannelRefused};
use lotse_core::task::{BoxFuture, spawn_named};
use lotse_core::track::{Track, TrackEvent, TrackId, TrackSubscription, Unit};
use lotse_ipc::{SessionEvent as IpcEvent, SessionSpec, datagram};
use tokio::net::UnixDatagram;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::derived::{DerivedTracks, Lease, PickedTrack};
use crate::ice_tcp::Links;
use crate::relay::{Egress, Relays};
use crate::sendmsg;
use crate::talkback::{self, Arbiter, Claim, ClaimError, Claimant, Talkback, TalkbackStats};

/// The bounded inbound queue per session:
/// uplink only, so small.
const INBOUND_CAPACITY: usize = 256;

/// How long `close_all` waits for the session tasks.
const CLOSE_BUDGET: Duration = Duration::from_secs(1);

/// A datagram for one session: off the datagram channel, or a frame off
/// one of its ICE-TCP connections.
#[derive(Debug)]
pub(crate) struct Inbound {
    /// What it arrived on.
    pub(crate) transport: Transport,
    /// The peer.
    pub(crate) source: SocketAddr,
    /// The local address it arrived on.
    pub(crate) destination: SocketAddr,
    /// The datagram.
    pub(crate) payload: Vec<u8>,
}

/// The close a session was asked for, the first one: the `closed` code
/// and message. It travels apart from [`Control`] so a full control queue
/// never drops it, and a session that waits for its tracks without a
/// deadline of its own always hears it.
type CloseRequest = Option<(&'static str, String)>;

/// What the manager tells a session task.
#[derive(Debug)]
enum Control {
    /// A trickled remote candidate; empty is end-of-candidates.
    Candidate(String),
    /// A re-offer from the browser (`webrtc/renegotiate`).
    Renegotiate(String),
    /// The stream's orientation changed.
    Orientation(Orientation),
    /// A relay candidate the supervisor allocated for this session.
    Relay {
        /// The relayed address.
        relayed: SocketAddr,
        /// The allocation's server.
        server: SocketAddr,
        /// The host address the allocation's traffic leaves from.
        local: SocketAddr,
        /// The allocation reaches its server over TCP.
        tcp: bool,
    },
    /// A channel the supervisor bound on one of the relay candidates.
    Channel {
        /// The relayed address.
        relayed: SocketAddr,
        /// The peer.
        peer: SocketAddr,
        /// The channel number.
        channel: u16,
    },
    /// An ICE-TCP connection the supervisor verified for this session.
    Tcp {
        /// The connection.
        stream: std::net::TcpStream,
        /// The browser's address.
        peer: SocketAddr,
        /// Its first frame, already read by the supervisor.
        first_frame: Vec<u8>,
    },
}

/// The routing table from local ufrag to the session's inbound queue.
type Routes = Arc<Mutex<HashMap<String, mpsc::Sender<Inbound>>>>;

/// The router's counters.
#[derive(Debug, Default)]
pub(crate) struct RouterStats {
    /// Datagrams for a ufrag no session holds.
    pub(crate) unroutable: AtomicU64,
    /// Datagrams dropped because the session's queue was full.
    pub(crate) dropped: AtomicU64,
    /// Frames that did not decode.
    pub(crate) malformed: AtomicU64,
    /// Egress datagrams the socket did not take, and relayed frames the
    /// datagram channel to the supervisor did not.
    pub(crate) send_failures: AtomicU64,
    /// Datagrams from a relay candidate to a peer without a channel yet,
    /// or too long for `ChannelData`, dropped.
    pub(crate) relay_unbound: AtomicU64,
}

/// One running session, from the manager's side.
#[derive(Debug)]
struct SessionHandle {
    /// The local ufrag, which ICE-TCP hand-offs name.
    ufrag: String,
    /// The task's control queue.
    control: mpsc::Sender<Control>,
    /// The task's close, which no full queue drops.
    close: watch::Sender<CloseRequest>,
    /// The task.
    task: JoinHandle<()>,
    /// Its talk-back counters.
    talkback: Arc<TalkbackStats>,
}

/// The manager.
#[derive(Debug)]
pub(crate) struct SessionManager {
    /// The shared UDP socket, non-blocking, for egress.
    udp: Arc<UdpSocket>,
    /// The routing table the reader fills queues from.
    routes: Routes,
    /// The datagram channel: the reader's, and the sessions' way to the
    /// supervisor's TCP allocations.
    datagrams: Arc<UnixDatagram>,
    /// The sessions by id, at most `max_sessions` of them.
    sessions: HashMap<String, SessionHandle>,
    /// The most sessions open at once; another is refused.
    max_sessions: usize,
    /// The datagram channel reader.
    reader: JoinHandle<()>,
    /// Where session events go.
    events: mpsc::Sender<(String, IpcEvent)>,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// The counters.
    stats: Arc<RouterStats>,
}

impl SessionManager {
    /// Takes the sockets the supervisor handed over and starts routing,
    /// with the shared socket moved to `shared_at` when given ([`pin`]),
    /// holding at most `max_sessions` sessions.
    pub(crate) fn new(
        udp: OwnedFd,
        shared_at: Option<RawFd>,
        datagrams: OwnedFd,
        max_sessions: usize,
        clock: Arc<dyn Clock>,
        events: mpsc::Sender<(String, IpcEvent)>,
    ) -> io::Result<Self> {
        let udp = UdpSocket::from(udp);
        // Before the move: on the pinned number the filter denies `ioctl`.
        udp.set_nonblocking(true)?;
        let udp = match shared_at {
            Some(at) => UdpSocket::from(pin(OwnedFd::from(udp), at)?),
            None => udp,
        };
        let datagrams = StdUnixDatagram::from(datagrams);
        datagrams.set_nonblocking(true)?;
        let datagrams = Arc::new(UnixDatagram::from_std(datagrams)?);
        let routes: Routes = Arc::default();
        let stats = Arc::new(RouterStats::default());
        let reader = spawn_named(
            "sessions.router",
            route_loop(
                Arc::clone(&datagrams),
                Arc::clone(&routes),
                Arc::clone(&stats),
            ),
        );
        let local = udp.local_addr().ok();
        let from_candidate = pins_source(local);
        tracing::info!(?local, from_candidate, "session manager ready");
        Ok(Self {
            udp: Arc::new(udp),
            routes,
            datagrams,
            sessions: HashMap::new(),
            max_sessions,
            reader,
            events,
            clock,
            stats,
        })
    }

    /// The counters.
    pub(crate) fn stats(&self) -> &RouterStats {
        &self.stats
    }

    /// Sessions open now. Finished ones are forgotten first: otherwise
    /// they would count until the next session opens.
    pub(crate) fn len(&mut self) -> usize {
        self.reap();
        self.sessions.len()
    }

    /// The talk-back counters of every open session an answer of which
    /// negotiated talk-back, its offer's or a re-offer's, by session id:
    /// all it counted, also after a re-offer dropped talk-back.
    pub(crate) fn talkback(&mut self) -> Vec<(String, lotse_ipc::TalkbackStats)> {
        self.reap();
        let mut report: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(id, handle)| Some((id.clone(), handle.talkback.report()?)))
            .collect();
        report.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        report
    }

    /// Reports a session that never started.
    async fn refuse(&self, session_id: String, code: &'static str, message: String) {
        tracing::warn!(session = %session_id, code, message, "session refused");
        let event = IpcEvent::Closed {
            code: code.to_owned(),
            message,
        };
        // The receiver is the serve loop; when it is gone the worker is
        // stopping and the event has nowhere to go.
        let _sent = self.events.send((session_id, event)).await;
    }

    /// Opens a session on the connection's tracks, native and derived.
    pub(crate) async fn open(
        &mut self,
        spec: SessionSpec,
        connection: ConnectionMedia,
        registries: &Registries,
        limits: SessionLimits,
    ) {
        self.reap();
        if self.sessions.contains_key(&spec.session_id) {
            self.refuse(
                spec.session_id,
                "internal_error",
                "session id already open in this worker".to_owned(),
            )
            .await;
            return;
        }
        if self.sessions.len() >= self.max_sessions {
            self.refuse(
                spec.session_id,
                "internal_error",
                format!(
                    "the worker holds its limit of {} sessions",
                    self.max_sessions
                ),
            )
            .await;
            return;
        }
        let Some(factory) = registries.outputs.get(&spec.kind) else {
            self.refuse(
                spec.session_id,
                "internal_error",
                format!("output kind {:?} is not compiled in", spec.kind),
            )
            .await;
            return;
        };
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_CAPACITY);
        let (control_tx, control) = mpsc::channel(64);
        let (close_tx, close) = watch::channel(None);
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(spec.ice_ufrag.clone(), inbound_tx.clone());
        let session_id = spec.session_id.clone();
        let ufrag = spec.ice_ufrag.clone();
        let talkback = Arc::new(TalkbackStats::default());
        let ConnectionMedia {
            tracks,
            mapper,
            backchannel,
        } = connection;
        let ctx = SessionCtx {
            spec,
            inbound: inbound_tx,
            tracks,
            mapper,
            backchannel,
            talkback: Arc::clone(&talkback),
            factory: Arc::clone(factory),
            limits,
            udp: Arc::clone(&self.udp),
            uplink: Arc::clone(&self.datagrams),
            clock: Arc::clone(&self.clock),
            events: self.events.clone(),
            routes: Arc::clone(&self.routes),
            stats: Arc::clone(&self.stats),
        };
        let span = tracing::info_span!("session", id = %session_id);
        let task = spawn_named(
            "session",
            tracing::Instrument::instrument(run_session(ctx, inbound, control, close), span),
        );
        self.sessions.insert(
            session_id,
            SessionHandle {
                ufrag,
                control: control_tx,
                close: close_tx,
                task,
                talkback,
            },
        );
    }

    /// An ICE-TCP connection for the session holding `ufrag`; without one
    /// the connection is closed.
    pub(crate) fn ice_tcp(
        &self,
        ufrag: &str,
        stream: OwnedFd,
        peer: SocketAddr,
        first_frame: Vec<u8>,
    ) {
        let Some(handle) = self.sessions.values().find(|handle| handle.ufrag == ufrag) else {
            tracing::debug!(ufrag, %peer, "ice-tcp connection for no session; closed");
            return;
        };
        let control = Control::Tcp {
            stream: std::net::TcpStream::from(stream),
            peer,
            first_frame,
        };
        if handle.control.try_send(control).is_err() {
            tracing::debug!(ufrag, %peer, "session busy or gone; ice-tcp connection closed");
        }
    }

    /// A trickled candidate for a session.
    pub(crate) fn candidate(&self, session_id: &str, candidate: String) {
        self.send(session_id, Control::Candidate(candidate));
    }

    /// Hands a re-offer to its session, which answers it with a
    /// `Renegotiated` or `RenegotiateRefused` report: `false` when there
    /// is no such session or its queue is full. The caller, the serve
    /// loop, refuses that one itself, straight to the supervisor: the
    /// loop is the one reader of the session events, so waiting for room
    /// in their queue here could wait forever.
    pub(crate) fn renegotiate(&self, session_id: &str, sdp: String) -> bool {
        self.sessions
            .get(session_id)
            .is_some_and(|handle| handle.control.try_send(Control::Renegotiate(sdp)).is_ok())
    }

    /// A relay candidate for a session.
    pub(crate) fn relay(
        &self,
        session_id: &str,
        relayed: SocketAddr,
        server: SocketAddr,
        local: SocketAddr,
        tcp: bool,
    ) {
        self.send(
            session_id,
            Control::Relay {
                relayed,
                server,
                local,
                tcp,
            },
        );
    }

    /// A channel bound on one of a session's relay candidates.
    pub(crate) fn relay_channel(
        &self,
        session_id: &str,
        relayed: SocketAddr,
        peer: SocketAddr,
        channel: u16,
    ) {
        self.send(
            session_id,
            Control::Channel {
                relayed,
                peer,
                channel,
            },
        );
    }

    /// The stream's orientation changed to the one numbered `code` (an
    /// unknown number is none, as at the open): the session answers with
    /// it, or turns the picture from its next frame once answered.
    pub(crate) fn orientation(&self, session_id: &str, code: u8) {
        let orientation = Orientation::from_code(code).unwrap_or_default();
        self.send(session_id, Control::Orientation(orientation));
    }

    /// Closes a session; a session asked already keeps its first close.
    pub(crate) fn close(&self, session_id: &str, code: &'static str, message: String) {
        let Some(handle) = self.sessions.get(session_id) else {
            tracing::debug!(session = session_id, code, "close for an unknown session");
            return;
        };
        request_close(&handle.close, code, message);
    }

    /// Hands a control message to a session; unknown or gone sessions
    /// are logged, not errors (a close may race with the session's end).
    fn send(&self, session_id: &str, control: Control) {
        let Some(handle) = self.sessions.get(session_id) else {
            tracing::debug!(
                session = session_id,
                ?control,
                "message for an unknown session"
            );
            return;
        };
        if let Err(err) = handle.control.try_send(control) {
            tracing::debug!(session = session_id, error = %err, "message dropped: session busy or gone");
        }
    }

    /// Closes every session and waits up to [`CLOSE_BUDGET`] for the tasks.
    pub(crate) async fn close_all(&mut self, code: &'static str, message: &str) {
        let sessions = std::mem::take(&mut self.sessions);
        for handle in sessions.values() {
            request_close(&handle.close, code, message.to_owned());
        }
        let budget = self.clock.sleep(CLOSE_BUDGET);
        tokio::pin!(budget);
        for (id, handle) in sessions {
            tokio::select! {
                _ = handle.task => {}
                () = &mut budget => {
                    tracing::warn!(session = %id, "session task did not stop in time");
                    break;
                }
            }
        }
    }

    /// Forgets finished sessions.
    fn reap(&mut self) {
        self.sessions.retain(|_, handle| !handle.task.is_finished());
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        self.reader.abort();
        for handle in self.sessions.values() {
            handle.task.abort();
        }
    }
}

/// Asks a session to close with `code`, unless it was asked already.
fn request_close(close: &watch::Sender<CloseRequest>, code: &'static str, message: String) {
    close.send_if_modified(|request| {
        let first = request.is_none();
        if first {
            *request = Some((code, message));
        }
        first
    });
}

/// Reads the datagram channel and queues each frame for its session,
/// until the channel fails or the supervisor closes its end.
///
/// The buffer is one byte longer than [`datagram::MAX_FRAME_LEN`]: the
/// socket cuts a longer frame to the buffer, so a read that fills it is a
/// cut frame, malformed, and one that does not is whole.
async fn route_loop(datagrams: Arc<UnixDatagram>, routes: Routes, stats: Arc<RouterStats>) {
    let mut buf = vec![0_u8; datagram::MAX_FRAME_LEN.saturating_add(1)];
    loop {
        let len = match datagrams.recv(&mut buf).await {
            // A read of zero bytes on a `SOCK_SEQPACKET` socket is the
            // peer's end closing (unix(7), recv(2)); every lotse frame
            // carries a header, so none is empty.
            Ok(0) => {
                tracing::info!(
                    reason = "zero-length read",
                    "datagram channel closed by the supervisor; routing stopped"
                );
                return;
            }
            Ok(len) if len > datagram::MAX_FRAME_LEN => {
                tracing::debug!(
                    len,
                    max = datagram::MAX_FRAME_LEN,
                    "datagram frame longer than the longest; truncated"
                );
                stats.malformed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Ok(len) => len,
            Err(err) => {
                tracing::warn!(error = %err, "datagram channel read failed; routing stopped");
                return;
            }
        };
        let frame = buf.get(..len).unwrap_or(&[]);
        let decoded = match datagram::decode(frame) {
            Ok(decoded) => decoded,
            Err(err) => {
                tracing::debug!(error = %err, len, "malformed datagram frame");
                stats.malformed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let queue = routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(decoded.ufrag)
            .cloned();
        let Some(queue) = queue else {
            stats.unroutable.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let inbound = Inbound {
            transport: Transport::Udp,
            source: decoded.source,
            destination: decoded.destination,
            payload: decoded.payload.to_vec(),
        };
        if queue.try_send(inbound).is_err() {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// What one session task runs with.
struct SessionCtx {
    /// The session to open.
    spec: SessionSpec,
    /// The session's inbound queue, which its ICE-TCP readers feed too.
    inbound: mpsc::Sender<Inbound>,
    /// The connection's tracks, native and derived.
    tracks: Arc<DerivedTracks>,
    /// The connection's clock mapper.
    mapper: Arc<ClockMapper>,
    /// The arbiter of the connection's backchannel, when its protocol has
    /// one.
    backchannel: Option<Arc<Arbiter>>,
    /// The session's talk-back counters, which the manager reports.
    talkback: Arc<TalkbackStats>,
    /// The output that opens the session.
    factory: Arc<dyn OutputFactory>,
    /// The tunables.
    limits: SessionLimits,
    /// Egress.
    udp: Arc<UdpSocket>,
    /// The datagram channel to the supervisor, for what leaves a relay
    /// candidate on a TCP allocation.
    uplink: Arc<UnixDatagram>,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// Where events go.
    events: mpsc::Sender<(String, IpcEvent)>,
    /// To unregister the ufrag at the end.
    routes: Routes,
    /// The counters.
    stats: Arc<RouterStats>,
}

impl SessionCtx {
    /// Reports an event to the supervisor.
    async fn emit(&self, event: IpcEvent) {
        let _sent = self
            .events
            .send((self.spec.session_id.clone(), event))
            .await;
    }

    /// Reports that the stream's audio is withdrawn for sync.
    async fn audio_withdrawn(&self) {
        tracing::info!(
            reason = AV_SYNC_LOST,
            "audio withdrawn from the session: audio/video sync could not be held"
        );
        self.emit(IpcEvent::Warning {
            code: AV_SYNC_LOST.to_owned(),
            message: "audio withdrawn: the camera's Sender Reports could not keep audio in sync with video".to_owned(),
        })
        .await;
    }

    /// Reports `closed` and unregisters the ufrag.
    async fn finish(&self, code: &'static str, message: String) {
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.spec.ice_ufrag);
        self.emit(IpcEvent::Closed {
            code: code.to_owned(),
            message,
        })
        .await;
    }
}

/// The `closed` code of a close request from the supervisor; codes are
/// the fixed set the control API defines.
pub(crate) fn close_code(code: &str) -> &'static str {
    match code {
        "stream_deleted" => "stream_deleted",
        "stream_changed" => "stream_changed",
        "shutting_down" => "shutting_down",
        _ => "session_closed",
    }
}

/// A core session event as the IPC carries it; `None` for the ones the
/// worker consumes itself.
fn to_ipc(event: SessionEvent) -> Option<IpcEvent> {
    match event {
        SessionEvent::Candidate { candidate, mid } => Some(IpcEvent::Candidate { candidate, mid }),
        SessionEvent::State { ice, dtls } => Some(IpcEvent::State {
            ice: ice.to_owned(),
            dtls: dtls.to_owned(),
        }),
        SessionEvent::Warning { code, message } => Some(IpcEvent::Warning {
            code: code.to_owned(),
            message,
        }),
        SessionEvent::Closed { code, message } => Some(IpcEvent::Closed {
            code: code.to_owned(),
            message,
        }),
        SessionEvent::Connected => None,
        SessionEvent::KeyframeRequest => {
            // An upstream request (ONVIF) is an M6 optimization; until
            // then the next camera keyframe repairs the picture.
            tracing::debug!("keyframe wanted upstream");
            None
        }
    }
}

/// `fd` moved to descriptor number `at`, its old number closed.
/// `F_DUPFD_CLOEXEC` takes the lowest free number at or above `at`
/// (fcntl(2)), so it never replaces a descriptor that is there, and
/// landing on any other number is an error.
fn pin(fd: OwnedFd, at: RawFd) -> io::Result<OwnedFd> {
    let pinned = rustix::io::fcntl_dupfd_cloexec(&fd, at)?;
    drop(fd);
    let landed = pinned.as_raw_fd();
    if landed != at {
        return Err(io::Error::other(format!(
            "the shared socket's descriptor {at} is taken (the next free is {landed})"
        )));
    }
    tracing::info!(fd = at, "shared udp socket pinned");
    Ok(pinned)
}

/// The address to send to from the shared socket: an IPv4 peer of a
/// dual-stack socket is addressed as IPv4-mapped (RFC 4291 §2.5.5.2),
/// which every platform accepts.
fn egress_target(local: Option<SocketAddr>, destination: SocketAddr) -> SocketAddr {
    match (local, destination) {
        (Some(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => destination,
    }
}

/// Whether a datagram leaves the shared socket, bound to `local`, from
/// the address of the candidate it is sent from: only when the socket is
/// bound to the unspecified address, where the kernel would otherwise
/// pick the source by its routes and a multi-homed host could answer a
/// check from an address the browser did not send it to
/// (RFC 8445 §7.2.5.2.1). A socket bound to one address sends from it
/// anyway, and an unknown one is left as it was.
fn pins_source(local: Option<SocketAddr>) -> bool {
    local.is_some_and(|local| local.ip().is_unspecified())
}

/// The source address a datagram the engine sends from `source` names,
/// when the socket pins sources ([`pins_source`]): `None` for the
/// unspecified address, which names none.
fn egress_source(pinned: bool, source: SocketAddr) -> Option<IpAddr> {
    let ip = source.ip();
    (pinned && !ip.is_unspecified()).then_some(ip)
}

/// Waits for the source to declare its tracks, unless the supervisor
/// closes the session first. Returns the close to report, if any. Relay
/// candidates that arrive meanwhile wait in `relays` for the engine; an
/// orientation change goes into the spec the answer reads.
///
/// No deadline of its own: the source's attempt is bounded by its own
/// deadlines and the runner's ready timeout, and the supervisor closes
/// the session with the source's error when the attempt fails.
async fn wait_ready(
    ctx: &mut SessionCtx,
    control: &mut mpsc::Receiver<Control>,
    close: &mut watch::Receiver<CloseRequest>,
    relays: &mut Vec<PendingRelay>,
) -> Option<(&'static str, String)> {
    let mut ready = ctx.tracks.tracks().ready();
    if *ready.borrow_and_update() {
        return None;
    }
    loop {
        // Whether a re-offer arrived, refused after the select: the
        // close's guard must not live across an await.
        let reoffer = tokio::select! {
            // The session holds the track set, so its sender outlives this
            // wait and `changed` never fails.
            Ok(()) = ready.changed() => {
                if *ready.borrow_and_update() {
                    return None;
                }
                false
            }
            // A manager that is gone ends the control queue too.
            Ok(request) = close.wait_for(Option::is_some) => return request.clone(),
            message = control.recv() => match message {
                Some(Control::Candidate(_)) => false,
                // The supervisor refuses one before the answer; a race
                // with the answer is refused here.
                Some(Control::Renegotiate(_)) => true,
                Some(Control::Orientation(orientation)) => {
                    ctx.spec.orientation = orientation.code();
                    false
                }
                Some(Control::Relay { relayed, server, local, tcp }) => {
                    relays.push(PendingRelay { relayed, server, local, tcp });
                    false
                }
                // No relay candidate yet, so no channel on one.
                Some(Control::Channel { relayed, peer, .. }) => {
                    tracing::debug!(%relayed, %peer, "relay channel before the answer; ignored");
                    false
                }
                // No answer yet, so no browser knows a TCP candidate.
                Some(Control::Tcp { peer, .. }) => {
                    tracing::debug!(%peer, "ice-tcp connection before the answer; closed");
                    false
                }
                None => return Some(("shutting_down", "the worker is stopping".to_owned())),
            },
        };
        if reoffer {
            tracing::debug!("re-offer before the answer; refused");
            ctx.emit(IpcEvent::RenegotiateRefused {
                code: "internal_error".to_owned(),
                message: "the session has no answer yet".to_owned(),
            })
            .await;
        }
    }
}

/// What negotiation picked for a session.
#[derive(Default)]
struct Picked {
    /// The video track, when the session plays video.
    video: Option<PickedTrack>,
    /// The audio track, when one was picked.
    audio: Option<PickedTrack>,
    /// Why no audio was picked although the stream has some.
    warning: Option<NegotiationError>,
}

/// The tracks negotiation picked for the session's offer, with audio if
/// `audio` ([`OutputFactory::session_tracks`]: an offer without video
/// wants none); a derived one comes leased, so its transcoder runs until
/// the session lets go. A required track that cannot be had is the
/// error; audio that cannot is a warning, or nothing when the stream has
/// none.
fn pick_tracks(ctx: &SessionCtx, audio: bool) -> Result<Picked, NegotiationError> {
    let requests = ctx.factory.session_tracks(&ctx.spec.offer, audio);
    let mut picked = Picked::default();
    for (request, pick) in requests.iter().zip(ctx.tracks.pick(&requests)) {
        match pick {
            Ok(track) if request.kind == Kind::Video => picked.video = Some(track),
            Ok(track) => picked.audio = Some(track),
            Err(err) if request.required => return Err(err),
            Err(err @ NegotiationError::CodecUnsupported { .. }) => picked.warning = Some(err),
            Err(NegotiationError::NoTrack { .. }) => {}
        }
    }
    Ok(picked)
}

/// The video a session plays: the track, the family it opened with, its
/// packets.
struct VideoSubscription {
    /// The track.
    track: Arc<Track>,
    /// Its codec family when the session opened; a change of it closes the
    /// session.
    family: CodecFamily,
    /// Its live packets.
    subscription: TrackSubscription,
    /// Keeps a derived video track's transcoder running; none today.
    _lease: Option<Lease>,
}

/// The next event of a session's video, with its track and the family
/// it opened with, or never without video.
async fn next_video(
    video: &mut Option<VideoSubscription>,
) -> (TrackId, CodecFamily, Option<TrackEvent>) {
    match video {
        Some(video) => (
            video.track.id(),
            video.family,
            video.subscription.next().await,
        ),
        None => std::future::pending().await,
    }
}

/// What the preamble of a session produced: the engine and the tracks it
/// serves.
struct Opened {
    /// The engine.
    engine: Box<dyn SessionEngine>,
    /// The video, when the session plays video.
    video: Option<VideoSubscription>,
    /// The audio track's live packets, until it ends.
    audio: Option<AudioSubscription>,
    /// The relay candidates and their channels.
    relays: Relays,
    /// The datagram-channel message to the supervisor being encoded,
    /// reused from frame to frame.
    uplink: Vec<u8>,
    /// The viewer's talk-back towards the connection's backchannel
    /// ([`talkback`]), when it has one; dropped with the session, which
    /// frees the channel if the session held it.
    talkback: Option<Talkback>,
    /// The stream audio's codec the engine opened with
    /// ([`SessionRequest::audio`]), which weighs the talk-back of every
    /// re-offer as it did the offer's ([`OutputFactory::talkback_request`]).
    stream_audio: Option<Arc<Codec>>,
}

/// Why an offer's talk-back was declined: the `backchannel_declined`
/// warning the session gets after the answer to that offer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decline {
    /// The session cannot receive talk-back on this stream, and why
    /// ([`TalkbackRequest::Unsupported`]).
    Unsupported(String),
    /// This session holds the backchannel.
    Busy(String),
    /// The camera's backchannel session did not open for the claim, or
    /// was lost while the session held it, and why.
    Refused(BackchannelRefused),
}

impl Decline {
    /// The warning's `reason`.
    const fn reason(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => "unsupported",
            Self::Busy(_) => "busy",
            Self::Refused(_) => "refused",
        }
    }

    /// The warning, for the supervisor.
    fn event(&self) -> IpcEvent {
        let (message, status) = match self {
            Self::Unsupported(reason) => (format!("talk-back declined: {reason}"), None),
            Self::Busy(holder) => (
                format!("talk-back declined: session {holder} holds the camera's backchannel"),
                None,
            ),
            Self::Refused(why) => (
                format!("talk-back declined: the camera's backchannel session: {why}"),
                why.status,
            ),
        };
        IpcEvent::TalkbackDeclined {
            reason: self.reason().to_owned(),
            status,
            message,
        }
    }
}

/// The arbitration of an offer's talk-back, before the engine answers
/// it: what the engine negotiates with, and what follows the answer.
#[derive(Debug)]
struct Arbitration {
    /// The backchannel the session negotiates with: the one it has open
    /// while it holds it, the one the camera offers now otherwise,
    /// whoever holds that.
    backchannel: Option<TalkbackTarget>,
    /// Whether the session holds it for this offer.
    claim: TalkbackClaim,
    /// The decline to report after the answer, if any.
    decline: Option<Decline>,
    /// The claim the offer made, its backchannel session open, for the
    /// session to adopt ([`Talkback::adopt`]); dropped unadopted, it lets
    /// go.
    granted: Option<Claim>,
    /// The offer claimed the backchannel, which the session did not hold
    /// before, as the claim itself decided ([`Claimant::claim`]): an
    /// engine that refuses the offer lets go again.
    claimed: bool,
    /// The offer drops talk-back the session held: it lets go once the
    /// engine took the offer, since the engine needs no claim to answer
    /// without talk-back.
    drops: bool,
}

impl Arbitration {
    /// The arbitration of an offer that asks for nothing, with
    /// `backchannel` offered.
    const fn new(backchannel: Option<TalkbackTarget>) -> Self {
        Self {
            backchannel,
            claim: TalkbackClaim::Granted,
            decline: None,
            granted: None,
            claimed: false,
            drops: false,
        }
    }

    /// Logs the outcome: log-only.
    fn log(&self) {
        let (claim, decline) = (self.claim, self.decline.as_ref().map(Decline::reason));
        tracing::debug!(
            ?claim,
            decline,
            claimed = self.claimed,
            drops = self.drops,
            "talk-back arbitrated for the offer"
        );
    }
}

/// An offer's arbitration: decided at once, or a claim that opens the
/// camera's backchannel session (or waits for the source's probe first),
/// which the answer waits for.
enum Arbitrating {
    /// Decided.
    Decided(Arbitration),
    /// Decided once the future resolves.
    Claiming(BoxFuture<'static, Arbitration>),
}

/// What an offer asks for on the backchannel offered now: the
/// arbitration so far, and whether a claim must still be made.
struct Assessed {
    /// The arbitration without the claim.
    arbitration: Arbitration,
    /// The offer asks for talk-back the backchannel takes, and the session
    /// does not hold it.
    claims: bool,
}

/// Arbitrates `offer`'s talk-back for the session, which sends the
/// stream's audio in `audio`, through `talkback` when its connection has
/// a backchannel: an offer that asks for talk-back the backchannel takes
/// ([`OutputFactory::talkback_request`], which weighs `audio` too)
/// claims it, first offer wins, and is declined `busy` when another
/// session holds it, `refused` when the camera's backchannel session does
/// not open for it; one that asks for talk-back the stream cannot carry
/// is declined `unsupported`; one that asks for none lets go of a
/// backchannel the session held. Decided before the engine sees the
/// offer, so the answer carries the outcome: a claim, which opens the
/// camera's backchannel session, and an offer that asks for talk-back
/// while the source probes the camera with nothing offered before, are
/// decided by the future [`Arbitrating::Claiming`] holds.
fn arbitrate(
    ctx: &SessionCtx,
    talkback: Option<&Talkback>,
    audio: Option<Arc<Codec>>,
    offer: &str,
) -> Arbitrating {
    let Some(talkback) = talkback else {
        let mut arbitration = Arbitration::new(None);
        if let TalkbackRequest::Unsupported(reason) =
            ctx.factory.talkback_request(offer, audio.as_deref(), None)
        {
            arbitration.decline = Some(Decline::Unsupported(reason));
        }
        return Arbitrating::Decided(arbitration);
    };
    let claimant = talkback.claimant();
    let factory = Arc::clone(&ctx.factory);
    // The probe's result decides an offer that asks for talk-back, unless
    // an offer from before stands.
    let probing = claimant.arbiter().awaits_probe()
        && !matches!(
            factory.talkback_request(offer, audio.as_deref(), None),
            TalkbackRequest::NotRequested
        );
    let assessed = assess(factory.as_ref(), &claimant, audio.as_deref(), offer);
    if !probing && !assessed.claims {
        return Arbitrating::Decided(assessed.arbitration);
    }
    let offer = offer.to_owned();
    Arbitrating::Claiming(Box::pin(async move {
        // One limit for the probe's wait and the claim's.
        let (assessed, limit) = if probing {
            tracing::info!("talk-back: the offer waits for the probe of the camera's backchannel");
            let left = claimant.arbiter().settled().await;
            (
                assess(factory.as_ref(), &claimant, audio.as_deref(), &offer),
                left,
            )
        } else {
            (assessed, BACKCHANNEL_OPEN_LIMIT)
        };
        if assessed.claims {
            claim(assessed.arbitration, claimant, limit).await
        } else {
            assessed.arbitration
        }
    }))
}

/// What `offer` asks of `claimant`'s backchannel ([`arbitrate`]), for a
/// session that sends the stream's audio in `audio`: the backchannel it
/// has open while it holds it, the one offered now otherwise
/// ([`Claimant::target`]).
fn assess(
    factory: &dyn OutputFactory,
    claimant: &Claimant,
    audio: Option<&Codec>,
    offer: &str,
) -> Assessed {
    let (backchannel, holds) = claimant.target();
    let request = factory.talkback_request(offer, audio, backchannel.as_ref());
    let mut arbitration = Arbitration::new(backchannel);
    let claims = match request {
        TalkbackRequest::NotRequested => {
            arbitration.drops = holds;
            false
        }
        TalkbackRequest::Unsupported(reason) => {
            arbitration.drops = holds;
            arbitration.decline = Some(Decline::Unsupported(reason));
            false
        }
        TalkbackRequest::Negotiable => !holds,
    };
    Assessed {
        arbitration,
        claims,
    }
}

/// Claims the backchannel for `arbitration`'s offer through `claimant`,
/// which opens the camera's backchannel session within `limit`: granted,
/// or declined `busy` or `refused`. The claim carries the backchannel the
/// answer is negotiated with, so it opens that one or none: a probe that
/// replaced the offer since with another codec declines it `refused`
/// ([`Claimant::claim`]).
async fn claim(mut arbitration: Arbitration, claimant: Claimant, limit: Duration) -> Arbitration {
    let negotiated = arbitration.backchannel.clone();
    match claimant.claim(negotiated, limit).await {
        Ok(granted) => {
            arbitration.claimed = granted.is_some();
            arbitration.granted = granted;
        }
        Err(ClaimError::Busy(holder)) => {
            arbitration.claim = TalkbackClaim::Busy;
            arbitration.decline = Some(Decline::Busy(holder));
        }
        Err(ClaimError::Refused(why)) => {
            arbitration.claim = TalkbackClaim::Busy;
            arbitration.decline = Some(Decline::Refused(why));
        }
    }
    arbitration
}

/// The close a session waits for: the first one asked, or the worker's
/// stop once the manager is gone.
async fn closed(close: &mut watch::Receiver<CloseRequest>) -> (&'static str, String) {
    let request = close
        .wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|request| request.clone());
    request.unwrap_or_else(|| ("shutting_down", "the worker is stopping".to_owned()))
}

/// What a session takes from the connection it opens on.
pub(crate) struct ConnectionMedia {
    /// The connection's tracks, native and derived.
    pub(crate) tracks: Arc<DerivedTracks>,
    /// The connection's clock mapper.
    pub(crate) mapper: Arc<ClockMapper>,
    /// The arbiter of the connection's backchannel, when its source
    /// protocol can carry audio back: talk-back is answered from what its
    /// slot holds, and the session's uplink goes through it.
    pub(crate) backchannel: Option<Arc<Arbiter>>,
}

/// A relay candidate handed over before the engine exists.
#[derive(Debug, Clone, Copy)]
struct PendingRelay {
    /// The relayed address.
    relayed: SocketAddr,
    /// The allocation's server.
    server: SocketAddr,
    /// The host address the allocation's traffic leaves from.
    local: SocketAddr,
    /// The allocation reaches its server over TCP.
    tcp: bool,
}

/// A session's audio: the track, the family it opened with, its packets.
struct AudioSubscription {
    /// The track, for its clock mapping.
    track: Arc<Track>,
    /// Its codec family when the session opened.
    family: CodecFamily,
    /// Its live packets.
    subscription: TrackSubscription,
    /// `Some` for a derived track: keeps its transcoder running until the
    /// audio ends with the session or the track.
    lease: Option<Lease>,
}

impl AudioSubscription {
    /// The capture time of one of its packets, for the Sender Reports that
    /// sync it with the video.
    /// A native track maps through the connection's clock mapper, like the
    /// video. A derived track's timestamps are not the camera's, so it maps
    /// through its own side branch, whose frames carry the capture time the
    /// transcoder derived from the source frame's (the mapper's, at the
    /// time); the packet's arrival if the transcoder moved on to another
    /// epoch since.
    fn capture_time(&self, mapper: &ClockMapper, packet: &MediaPacket) -> Instant {
        if self.lease.is_some() {
            self.track
                .capture_time(packet.epoch, packet.rtp.ts)
                .unwrap_or(packet.arrival)
        } else {
            mapper.map(self.track.id(), packet.rtp.ts, packet.arrival)
        }
    }
}

/// The next event of a session's audio, or never without audio.
async fn next_audio(audio: &mut Option<AudioSubscription>) -> Option<TrackEvent> {
    match audio {
        Some(audio) => audio.subscription.next().await,
        None => std::future::pending().await,
    }
}

/// The arbitration of the session's offer ([`arbitrate`]) for a session
/// that sends the stream's audio in `audio`, a claim it granted adopted
/// by `talkback`. A claim holds it until the camera's backchannel session
/// is open; a close meanwhile ends the session, and the claim with it:
/// `None`, reported already.
async fn arbitrate_offer(
    ctx: &SessionCtx,
    talkback: Option<&mut Talkback>,
    audio: Option<Arc<Codec>>,
    close: &mut watch::Receiver<CloseRequest>,
) -> Option<Arbitration> {
    let mut arbitration = match arbitrate(ctx, talkback.as_deref(), audio, &ctx.spec.offer) {
        Arbitrating::Decided(arbitration) => arbitration,
        Arbitrating::Claiming(claiming) => tokio::select! {
            arbitration = claiming => arbitration,
            (code, message) = closed(close) => {
                ctx.finish(code, message).await;
                return None;
            }
        },
    };
    arbitration.log();
    if let (Some(talkback), Some(claim)) = (talkback, arbitration.granted.take()) {
        talkback.adopt(claim);
    }
    Some(arbitration)
}

/// Waits for the tracks, negotiates, opens the engine and reports the
/// answer; `None` when the session ended before that (reported already).
async fn open_session(
    ctx: &mut SessionCtx,
    control: &mut mpsc::Receiver<Control>,
    close: &mut watch::Receiver<CloseRequest>,
) -> Option<Opened> {
    let mut relays = Vec::new();
    if let Some((code, message)) = wait_ready(ctx, control, close, &mut relays).await {
        ctx.finish(code, message).await;
        return None;
    }
    // A stream whose audio is withdrawn opens sessions without it, as
    // `audio: "off"` does: its m-line is answered inactive.
    let withdrawn = ctx.spec.audio && ctx.mapper.audio_withdrawn();
    let picked = match pick_tracks(ctx, ctx.spec.audio && !withdrawn) {
        Ok(picked) => picked,
        Err(err) => {
            ctx.finish(err.code(), err.to_string()).await;
            return None;
        }
    };
    if withdrawn {
        ctx.audio_withdrawn().await;
    }
    if let Some(warning) = picked.warning {
        ctx.emit(IpcEvent::Warning {
            code: warning.code().to_owned(),
            message: warning.to_string(),
        })
        .await;
    }
    // Subscribed before the answer so the queue starts at the live edge
    // of now; the age gate drops what grows old meanwhile.
    let video = picked.video.map(|video| VideoSubscription {
        family: video.track.codec().family(),
        subscription: video.track.subscribe(Unit::Packets),
        track: video.track,
        _lease: video.lease,
    });
    let audio = picked.audio.map(|audio| AudioSubscription {
        family: audio.track.codec().family(),
        subscription: audio.track.subscribe(Unit::Packets),
        track: audio.track,
        lease: audio.lease,
    });
    // The offer claims the backchannel before the engine answers; a
    // session that never opens lets go as it is dropped.
    let mut talkback = ctx.backchannel.as_ref().map(|arbiter| {
        Talkback::new(
            Arc::clone(arbiter),
            ctx.spec.session_id.clone(),
            Arc::clone(&ctx.talkback),
        )
    });
    let stream_audio = audio.as_ref().map(|audio| audio.track.codec());
    let arbitration = arbitrate_offer(ctx, talkback.as_mut(), stream_audio.clone(), close).await?;
    // The monotonic and the wall clock read together: the session's anchor
    // for the capture times it sends.
    let now = ctx.clock.now();
    let request = SessionRequest {
        offer: ctx.spec.offer.clone(),
        ice: IceCredentials {
            ufrag: ctx.spec.ice_ufrag.clone(),
            pass: ctx.spec.ice_pass.clone(),
        },
        candidates: ctx.spec.candidates.clone(),
        tcp_candidates: ctx.spec.tcp_candidates.clone(),
        video: video.as_ref().map(|video| video.track.codec()),
        audio: stream_audio.clone(),
        // What the source offers now, behind its protocol's gate (a new
        // session holds no backchannel session yet), and whether this
        // session holds it.
        backchannel: arbitration.backchannel,
        claim: arbitration.claim,
        orientation: Orientation::from_code(ctx.spec.orientation).unwrap_or_default(),
        limits: ctx.limits,
        wall: ctx.clock.wall_now(),
    };
    let (engine, answer) = match ctx.factory.open_session(request, now) {
        Ok(opened) => opened,
        Err(err) => {
            ctx.finish(err.code(), err.to_string()).await;
            return None;
        }
    };
    let negotiated = engine.talkback();
    if negotiated.is_some() {
        ctx.talkback.ever_negotiated.store(true, Ordering::Relaxed);
    }
    ctx.emit(IpcEvent::Answer {
        sdp: answer,
        talkback: negotiated.map(|codec| codec.name().to_owned()),
    })
    .await;
    if let Some(decline) = &arbitration.decline {
        ctx.emit(decline.event()).await;
    }
    let mut opened = Opened {
        engine,
        video,
        audio,
        relays: Relays::default(),
        uplink: Vec::new(),
        talkback,
        stream_audio,
    };
    for relay in relays {
        add_relay(ctx, &mut opened, relay).await;
    }
    Some(opened)
}

/// A re-offer whose answer waits for its claim: the camera's backchannel
/// session opening, or the source's probe.
struct PendingOffer {
    /// The re-offer.
    sdp: String,
    /// Its arbitration.
    arbitration: BoxFuture<'static, Arbitration>,
}

/// A re-offer: arbitrates its talk-back ([`arbitrate`]) and answers it
/// ([`answer`]), or, when its claim opens the camera's backchannel
/// session, holds it in `pending` until the arbitration is decided, while
/// the session plays on. A re-offer while one is held is refused.
async fn renegotiate(
    ctx: &SessionCtx,
    opened: &mut Opened,
    pending: &mut Option<PendingOffer>,
    sdp: String,
) {
    if pending.is_some() {
        tracing::info!("re-offer while another is held; refused");
        ctx.emit(IpcEvent::RenegotiateRefused {
            code: "internal_error".to_owned(),
            message: "a re-offer of the session is still being answered".to_owned(),
        })
        .await;
        return;
    }
    match arbitrate(
        ctx,
        opened.talkback.as_ref(),
        opened.stream_audio.clone(),
        &sdp,
    ) {
        Arbitrating::Decided(arbitration) => answer(ctx, opened, &sdp, arbitration).await,
        Arbitrating::Claiming(arbitration) => {
            tracing::info!("re-offer held until its talk-back claim is decided");
            *pending = Some(PendingOffer { sdp, arbitration });
        }
    }
}

/// The next held re-offer's decided arbitration, taken out of `pending`;
/// never without one.
async fn next_arbitration(pending: &mut Option<PendingOffer>) -> (String, Arbitration) {
    let Some(offer) = pending.as_mut() else {
        return std::future::pending().await;
    };
    let arbitration = offer.arbitration.as_mut().await;
    let sdp = pending.take().map(|offer| offer.sdp).unwrap_or_default();
    (sdp, arbitration)
}

/// The next loss of the session's backchannel session the arbiter
/// reports; never without talk-back.
async fn next_loss(talkback: Option<&mut Talkback>) -> Option<BackchannelRefused> {
    match talkback {
        Some(talkback) => talkback.lost().await,
        None => std::future::pending().await,
    }
}

/// Answers a re-offer once its talk-back is arbitrated: has the engine
/// answer it and reports the answer (`Renegotiated`) and the decline, if
/// any; a refused re-offer is reported (`RenegotiateRefused`) and leaves
/// the session as it was, a backchannel it claimed let go again. An
/// answer without talk-back lets go of a backchannel the session still
/// holds, declined `unsupported`: the engine may find what the output
/// judged negotiable from the offer alone
/// ([`OutputFactory::talkback_request`]) not receivable, on an m-line
/// it answered before, and a claim for no talk-back would keep every
/// other session's out.
async fn answer(ctx: &SessionCtx, opened: &mut Opened, sdp: &str, mut arbitration: Arbitration) {
    arbitration.log();
    if let (Some(talkback), Some(claim)) = (opened.talkback.as_mut(), arbitration.granted.take()) {
        talkback.adopt(claim);
    }
    let now = ctx.clock.now();
    match opened
        .engine
        .renegotiate(now, sdp, arbitration.backchannel.clone(), arbitration.claim)
    {
        Ok(answer) => {
            if arbitration.drops
                && let Some(talkback) = opened.talkback.as_mut()
            {
                talkback.let_go();
            }
            let negotiated = opened.engine.talkback();
            if negotiated.is_none()
                && let Some(talkback) = opened.talkback.as_mut()
                && talkback.holds()
            {
                talkback.let_go();
                tracing::info!(
                    "talk-back declined: the engine answered the re-offer without it; the backchannel is let go"
                );
                arbitration.decline = Some(Decline::Unsupported(
                    "the session answered without talk-back".to_owned(),
                ));
            }
            // A session that drops talk-back stays reported, with what
            // it counted so far.
            if negotiated.is_some() {
                ctx.talkback.ever_negotiated.store(true, Ordering::Relaxed);
            }
            let talkback = negotiated.map(lotse_core::uplink::UplinkCodec::name);
            tracing::info!(talkback, "re-offer answered");
            ctx.emit(IpcEvent::Renegotiated {
                sdp: answer,
                talkback: talkback.map(str::to_owned),
            })
            .await;
            if let Some(decline) = &arbitration.decline {
                ctx.emit(decline.event()).await;
            }
        }
        Err(err) => {
            if arbitration.claimed
                && let Some(talkback) = opened.talkback.as_mut()
            {
                talkback.let_go();
            }
            let code = err.code();
            tracing::info!(code, error = %err, "re-offer refused");
            ctx.emit(IpcEvent::RenegotiateRefused {
                code: code.to_owned(),
                message: err.to_string(),
            })
            .await;
        }
    }
}

/// Gives the engine a relay candidate and reports its line, or that it
/// was not taken; a second one at the same relayed address is not.
async fn add_relay(ctx: &SessionCtx, opened: &mut Opened, relay: PendingRelay) {
    let PendingRelay {
        relayed,
        server,
        local,
        tcp,
    } = relay;
    let candidate = if opened.relays.add(relayed, server, tcp) {
        opened
            .engine
            .add_relay_candidate(ctx.clock.now(), relayed, local)
    } else {
        tracing::debug!(%relayed, "relay candidate known already");
        None
    };
    tracing::debug!(%relayed, %server, tcp, taken = candidate.is_some(), "relay candidate");
    ctx.emit(IpcEvent::Relayed { relayed, candidate }).await;
}

/// Drains the engine after an input: sends, joins, reports. Returns the
/// engine's next timeout, or `None` once the session is closed.
async fn drain(
    ctx: &SessionCtx,
    opened: &mut Opened,
    local: Option<SocketAddr>,
    links: &Links,
) -> Option<Instant> {
    loop {
        match opened.engine.poll() {
            SessionOutput::Transmit {
                transport: Transport::Udp,
                source,
                destination,
                payload,
                audio,
            } => match opened.relays.egress(source, destination, &payload) {
                Egress::Direct => {
                    let from = egress_source(pins_source(local), source);
                    send_udp(ctx, local, from, destination, &payload, audio);
                }
                // `ChannelData` leaves from where the kernel routes, as
                // the supervisor's own requests on the allocation do, so
                // the server sees the allocation's 5-tuple (RFC 8656 §5).
                Egress::Relay { to, frame } => send_udp(ctx, local, None, to, frame, audio),
                Egress::Uplink {
                    relayed,
                    server,
                    frame,
                } => send_uplink(ctx, relayed, server, frame, &mut opened.uplink),
                Egress::Want { relayed, peer } => {
                    ctx.stats.relay_unbound.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%relayed, %peer, "relay channel wanted");
                    ctx.emit(IpcEvent::ChannelWanted { relayed, peer }).await;
                }
                Egress::Dropped => {
                    ctx.stats.relay_unbound.fetch_add(1, Ordering::Relaxed);
                    tracing::trace!(%source, %destination, "relayed datagram dropped: no channel");
                }
            },
            SessionOutput::Transmit {
                transport: Transport::Tcp,
                destination,
                payload,
                ..
            } => {
                if !links.send(destination, payload) {
                    ctx.stats.send_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::trace!(%destination, "ice-tcp send dropped");
                }
            }
            SessionOutput::Event(SessionEvent::Connected) => {
                if let Some(video) = &opened.video {
                    let gop = video.track.gop();
                    opened.engine.join(ctx.clock.now(), gop.as_deref());
                }
            }
            SessionOutput::Event(SessionEvent::Closed { code, message }) => {
                ctx.finish(code, message).await;
                return None;
            }
            SessionOutput::Event(event) => {
                if let Some(event) = to_ipc(event) {
                    ctx.emit(event).await;
                }
            }
            SessionOutput::Uplink(packet) => {
                ctx.talkback
                    .packets_received
                    .store(opened.engine.stats().uplink_packets, Ordering::Relaxed);
                talkback::receive(opened.talkback.as_mut(), packet);
            }
            SessionOutput::Timeout(at) => return Some(at),
        }
    }
}

/// Sends `payload` to `destination` from the shared socket, marked EF
/// when it is the audio track's and leaving from `source` when given
/// ([`sendmsg`]); a send that fails is counted, as a full buffer drops
/// the datagram, and so is one from an address the host no longer has.
fn send_udp(
    ctx: &SessionCtx,
    local: Option<SocketAddr>,
    source: Option<IpAddr>,
    destination: SocketAddr,
    payload: &[u8],
    audio: bool,
) {
    let target = egress_target(local, destination);
    if let Err(err) = sendmsg::send_to(&ctx.udp, payload, target, audio, source) {
        ctx.stats.send_failures.fetch_add(1, Ordering::Relaxed);
        tracing::trace!(error = %err, %target, ?source, "send failed");
    }
}

/// Hands `frame`, which leaves the relay candidate at `relayed` for the
/// TCP allocation on `server`, to the supervisor on the datagram channel,
/// encoded into `encoded`, which it reuses; a send that fails is counted,
/// as a full socket buffer drops.
fn send_uplink(
    ctx: &SessionCtx,
    relayed: SocketAddr,
    server: SocketAddr,
    frame: &[u8],
    encoded: &mut Vec<u8>,
) {
    datagram::encode(&ctx.spec.ice_ufrag, relayed, server, frame, encoded);
    if let Err(err) = ctx.uplink.try_send(encoded) {
        ctx.stats.send_failures.fetch_add(1, Ordering::Relaxed);
        tracing::trace!(error = %err, %server, "relayed frame not handed to the supervisor");
    }
}

/// One session, start to `closed`.
async fn run_session(
    mut ctx: SessionCtx,
    mut inbound: mpsc::Receiver<Inbound>,
    mut control: mpsc::Receiver<Control>,
    mut close: watch::Receiver<CloseRequest>,
) {
    let Some(mut opened) = open_session(&mut ctx, &mut control, &mut close).await else {
        return;
    };
    let local = ctx.udp.local_addr().ok();
    let mut links = Links::new(Arc::clone(&ctx.clock));
    let mut pending = None;
    loop {
        // Drain after every input (the engine's contract).
        let Some(at) = drain(&ctx, &mut opened, local, &links).await else {
            return;
        };
        let sleep = ctx
            .clock
            .sleep(at.saturating_duration_since(ctx.clock.now()));
        // Each input is handled at the time it arrived, not when the wait
        // began: a packet read later than a stale `now` would hand the
        // engine a capture time in its future (str0m then sends a Sender
        // Report with RTP time 0) and look younger to the age gate.
        tokio::select! {
            // `ctx` holds a sender of the queue, so it never closes.
            Some(datagram) = inbound.recv() => {
                let now = ctx.clock.now();
                opened.engine.handle_datagram(now, datagram.transport, datagram.source, datagram.destination, &datagram.payload);
            }
            // The reactions to track events are core's, shared by every
            // session output.
            (track, family, event) = next_video(&mut opened.video) => {
                let now = ctx.clock.now();
                apply_track_event(opened.engine.as_mut(), now, family, event, |packet| {
                    ctx.mapper.map(track, packet.rtp.ts, packet.arrival)
                });
            }
            event = next_audio(&mut opened.audio) => {
                let now = ctx.clock.now();
                if ctx.mapper.audio_withdrawn() {
                    // Withdrawn: nothing more is written, and a derived
                    // track's lease goes; the m-line stays as negotiated.
                    opened.audio = None;
                    ctx.audio_withdrawn().await;
                } else {
                    // `next_audio` yields only while there is audio.
                    let keep = opened.audio.as_ref().is_some_and(|audio| {
                        apply_audio_event(opened.engine.as_mut(), now, audio.family, event, |packet| {
                            audio.capture_time(&ctx.mapper, packet)
                        })
                    });
                    if !keep {
                        opened.audio = None;
                    }
                }
            }
            message = control.recv() => {
                let now = ctx.clock.now();
                match message {
                    Some(Control::Candidate(candidate)) => opened.engine.add_remote_candidate(now, &candidate),
                    Some(Control::Renegotiate(sdp)) => renegotiate(&ctx, &mut opened, &mut pending, sdp).await,
                    Some(Control::Orientation(orientation)) => opened.engine.set_orientation(orientation),
                    Some(Control::Relay { relayed, server, local, tcp }) => add_relay(&ctx, &mut opened, PendingRelay { relayed, server, local, tcp }).await,
                    Some(Control::Channel { relayed, peer, channel }) => {
                        let bound = opened.relays.bind(relayed, peer, channel);
                        tracing::debug!(%relayed, %peer, channel, bound, "relay channel");
                    }
                    Some(Control::Tcp { stream, peer, first_frame }) => {
                        match links.attach(stream, peer, ctx.inbound.clone()) {
                            Ok(Some(local)) => opened.engine.handle_datagram(now, Transport::Tcp, peer, local, &first_frame),
                            // Over the cap: closed, and logged there.
                            Ok(None) => {}
                            Err(err) => tracing::warn!(%peer, error = %err, "ice-tcp connection not usable"),
                        }
                    }
                    None => opened.engine.close(now, "shutting_down", "the worker is stopping".to_owned()),
                }
            }
            (sdp, arbitration) = next_arbitration(&mut pending) => {
                answer(&ctx, &mut opened, &sdp, arbitration).await;
            }
            Some(why) = next_loss(opened.talkback.as_mut()) => {
                ctx.emit(Decline::Refused(why).event()).await;
            }
            Ok(()) = close.changed() => {
                let request = close.borrow_and_update().clone();
                if let Some((code, message)) = request {
                    opened.engine.close(ctx.clock.now(), code, message);
                }
            }
            () = sleep => opened.engine.handle_timeout(ctx.clock.now()),
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

    use std::collections::VecDeque;
    use std::io::Read as _;
    use std::pin::{Pin, pin};
    use std::task::Poll;

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_core::codec::{Codec, Kind};
    use lotse_core::let_assert;
    use lotse_core::media::RtpHeaderFields;
    use lotse_core::output::TrackRequest;
    use lotse_core::session::{SessionOpenError, SessionStats};
    use lotse_core::source::{TrackPublisher, TrackSet};
    use lotse_core::track::{GopSnapshot, TrackId, TrackLimits};
    use tracing::Level;

    use super::*;
    use crate::talkback::TalkerFeed;
    use crate::test_logs::Logs;

    const HOUR: Duration = Duration::from_secs(3600);

    /// What the scripted engines of a test did, and what they say next.
    #[derive(Debug, Default)]
    struct Script {
        /// Every engine and output call, in order.
        calls: Mutex<Vec<String>>,
        /// What the next polls return, before the engine's timeout.
        outputs: Mutex<VecDeque<SessionOutput>>,
        /// Opening a session fails with `invalid_sdp`.
        refuse: bool,
    }

    impl Script {
        fn call(&self, call: &str) {
            self.calls.lock().unwrap().push(call.to_owned());
        }

        fn called(&self, call: &str) -> bool {
            self.calls.lock().unwrap().iter().any(|made| made == call)
        }

        fn then(&self, output: SessionOutput) {
            self.outputs.lock().unwrap().push_back(output);
        }
    }

    /// The codec an offer of the scripted output sends talk-back in to
    /// `backchannel`, as the engine picks one a route reaches: of the
    /// uplink codecs the offer names (`opus`, `pcmu`, `pcma`), in its
    /// order, PCMU when it names none, the first the backchannel takes.
    fn scripted_codec(
        offer: &str,
        backchannel: &TalkbackTarget,
    ) -> Option<lotse_core::uplink::UplinkCodec> {
        let mut named: Vec<_> = lotse_core::uplink::UplinkCodec::ALL
            .into_iter()
            .filter_map(|codec| Some((offer.find(codec.name())?, codec)))
            .collect();
        named.sort_unstable_by_key(|(at, _)| *at);
        let mut named: Vec<_> = named.into_iter().map(|(_, codec)| codec).collect();
        if named.is_empty() {
            named.push(lotse_core::uplink::UplinkCodec::Pcmu);
        }
        named
            .into_iter()
            .find(|codec| backchannel.takes.contains(codec))
    }

    /// The backchannel an engine call negotiates with, for the script:
    /// its codec and the uplink codecs that reach it.
    fn target_name(backchannel: Option<&TalkbackTarget>) -> String {
        backchannel.map_or_else(
            || "nothing".to_owned(),
            |target| {
                let takes: Vec<_> = target.takes.iter().map(|codec| codec.name()).collect();
                format!("{} taking {}", target.codec.name(), takes.join(" "))
            },
        )
    }

    /// Whether an offer of the scripted output negotiates talk-back, and
    /// in which codec: it asks (`talk` in the offer) for talk-back the
    /// camera's backchannel takes (not `unsupported`, nor `one-way` for a
    /// session with stream audio, `audio`, in a codec it takes,
    /// [`scripted_codec`]), and the session holds the backchannel; but
    /// never where the offer says `kept`, which the output still judges
    /// negotiable, as an engine whose m-line kept a codec the camera does
    /// not take.
    fn scripted_talkback(
        offer: &str,
        audio: bool,
        backchannel: Option<&TalkbackTarget>,
        claim: TalkbackClaim,
    ) -> Option<lotse_core::uplink::UplinkCodec> {
        if !offer.contains("talk")
            || offer.contains("unsupported")
            || offer.contains("kept")
            || (audio && offer.contains("one-way"))
            || claim != TalkbackClaim::Granted
        {
            return None;
        }
        scripted_codec(offer, backchannel?)
    }

    /// An engine that records its calls in its script and returns the
    /// script's outputs, then a timeout an hour after it opened or last
    /// timed out. It takes every relay candidate and video change, and
    /// closes when asked. It negotiates talk-back as [`scripted_talkback`]
    /// says, for the offer and every re-offer, and refuses a re-offer
    /// containing `refuse`.
    #[derive(Debug)]
    struct Scripted {
        script: Arc<Script>,
        idle: Instant,
        talkback: Option<lotse_core::uplink::UplinkCodec>,
        /// Whether it opened with stream audio, which weighs the talk-back
        /// of its re-offers ([`scripted_talkback`]).
        audio: bool,
    }

    impl SessionEngine for Scripted {
        fn handle_datagram(
            &mut self,
            _now: Instant,
            transport: Transport,
            source: SocketAddr,
            _destination: SocketAddr,
            bytes: &[u8],
        ) {
            let payload = String::from_utf8_lossy(bytes);
            self.script
                .call(&format!("datagram {transport:?} {source} {payload}"));
        }

        fn handle_timeout(&mut self, now: Instant) {
            self.script.call("timeout");
            self.idle = now + HOUR;
        }

        fn add_remote_candidate(&mut self, _now: Instant, candidate: &str) {
            self.script.call(&format!("candidate {candidate}"));
        }

        fn add_relay_candidate(
            &mut self,
            _now: Instant,
            relayed: SocketAddr,
            _local: SocketAddr,
        ) -> Option<String> {
            self.script.call(&format!("relay {relayed}"));
            Some(format!("candidate:relay {relayed}"))
        }

        fn join(&mut self, _now: Instant, _gop: Option<&GopSnapshot>) {
            self.script.call("join");
        }

        fn write_video(&mut self, _now: Instant, _packet: &MediaPacket, _wallclock: Instant) {
            self.script.call("video");
        }

        fn write_audio(&mut self, _now: Instant, _packet: &MediaPacket, _wallclock: Instant) {
            self.script.call("audio");
        }

        fn skip_to_keyframe(&mut self, reason: &'static str) {
            self.script.call(&format!("skip {reason}"));
        }

        fn set_orientation(&mut self, orientation: Orientation) {
            self.script
                .call(&format!("orientation {}", orientation.name()));
        }

        fn check_video_change(&self, codec: &Codec) -> Result<(), String> {
            self.script.call(&format!("video change {}", codec.name()));
            Ok(())
        }

        fn close(&mut self, _now: Instant, code: &'static str, message: String) {
            self.script.call(&format!("close {code}"));
            self.script
                .then(SessionOutput::Event(SessionEvent::Closed { code, message }));
        }

        fn poll(&mut self) -> SessionOutput {
            let next = self.script.outputs.lock().unwrap().pop_front();
            next.unwrap_or(SessionOutput::Timeout(self.idle))
        }

        fn stats(&self) -> SessionStats {
            SessionStats::default()
        }

        fn talkback(&self) -> Option<lotse_core::uplink::UplinkCodec> {
            self.talkback
        }

        fn renegotiate(
            &mut self,
            _now: Instant,
            offer: &str,
            backchannel: Option<TalkbackTarget>,
            claim: TalkbackClaim,
        ) -> Result<String, lotse_core::session::RenegotiateError> {
            self.script
                .call(&format!("renegotiate {offer} claim={claim:?}"));
            self.script.call(&format!(
                "renegotiate with {}",
                target_name(backchannel.as_ref())
            ));
            if offer.contains("refuse") {
                return Err(lotse_core::session::RenegotiateError::InvalidSdp(
                    "refused by the script".into(),
                ));
            }
            self.talkback = scripted_talkback(offer, self.audio, backchannel.as_ref(), claim);
            Ok(format!("answer to {offer}"))
        }
    }

    /// The `webrtc` output of [`Scripted`] engines: H.264 video unless the
    /// offer says `no video`, and PCMU audio when asked. An offer with
    /// `talk` asks for talk-back, which a
    /// camera's backchannel takes unless the offer says `unsupported`, or
    /// `one-way` for a session with stream audio, or names no codec it
    /// takes ([`scripted_codec`]).
    #[derive(Debug, Default)]
    struct ScriptedOutput(Arc<Script>);

    impl OutputFactory for ScriptedOutput {
        fn kind(&self) -> &'static str {
            "webrtc"
        }

        fn session_tracks(&self, offer: &str, audio: bool) -> Vec<TrackRequest> {
            let video = (!offer.contains("no video")).then(|| TrackRequest {
                kind: Kind::Video,
                accept: vec![CodecFamily::H264],
                unit: Unit::Packets,
                required: true,
            });
            let audio = audio.then(|| TrackRequest {
                kind: Kind::Audio,
                accept: vec![CodecFamily::Pcmu],
                unit: Unit::Packets,
                required: false,
            });
            video.into_iter().chain(audio).collect()
        }

        fn open_session(
            &self,
            request: SessionRequest,
            now: Instant,
        ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError> {
            self.0
                .call(&format!("open video={}", request.video.is_some()));
            self.0
                .call(&format!("open audio={}", request.audio.is_some()));
            self.0
                .call(&format!("open orientation={}", request.orientation.name()));
            self.0.call(&format!(
                "open backchannel={} claim={:?}",
                request.backchannel.is_some(),
                request.claim
            ));
            self.0.call(&format!(
                "open with {}",
                target_name(request.backchannel.as_ref())
            ));
            if self.0.refuse {
                return Err(SessionOpenError::InvalidSdp("refused by the script".into()));
            }
            let engine = Scripted {
                script: Arc::clone(&self.0),
                idle: now + HOUR,
                talkback: scripted_talkback(
                    &request.offer,
                    request.audio.is_some(),
                    request.backchannel.as_ref(),
                    request.claim,
                ),
                audio: request.audio.is_some(),
            };
            Ok((Box::new(engine), "answer".into()))
        }

        fn talkback_request(
            &self,
            offer: &str,
            audio: Option<&Codec>,
            backchannel: Option<&TalkbackTarget>,
        ) -> TalkbackRequest {
            if !offer.contains("talk") {
                TalkbackRequest::NotRequested
            } else if audio.is_some() && offer.contains("one-way") {
                TalkbackRequest::Unsupported("the script says one way".into())
            } else if offer.contains("unsupported")
                || backchannel
                    .is_none_or(|backchannel| scripted_codec(offer, backchannel).is_none())
            {
                TalkbackRequest::Unsupported("the script says no".into())
            } else {
                TalkbackRequest::Negotiable
            }
        }
    }

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }
    }

    /// A connection's tracks: H.264 video, PCMU audio with `audio`, ready
    /// with `ready`.
    fn connection(clock: &Arc<FakeClock>, audio: bool, ready: bool) -> TrackPublisher {
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        let mut publisher = set.publisher();
        publisher.declare(Kind::Video, h264(), 90_000);
        if audio {
            publisher.declare(Kind::Audio, Codec::Pcmu, 8_000);
        }
        if ready {
            publisher.ready();
        }
        publisher
    }

    /// The spec of session `id`, with audio if `audio`.
    fn spec(id: &str, audio: bool) -> SessionSpec {
        SessionSpec {
            session_id: id.into(),
            kind: "webrtc".into(),
            offer: "v=0".into(),
            ice_ufrag: format!("ufrag-{id}"),
            ice_pass: "pass".into(),
            candidates: vec![],
            tcp_candidates: vec![],
            audio,
            orientation: 1,
        }
    }

    /// A packet of a track's, arriving at `arrival`.
    fn packet(arrival: Instant) -> MediaPacket {
        MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: 0,
                ts: 0,
                marker: true,
                ssrc: 1,
            },
            frame_start: true,
            keyframe_start: true,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0x65_u8][..]),
        }
    }

    /// A loopback TCP connection: the browser's end, and the worker's as
    /// the descriptor the supervisor passes.
    fn tcp_pair() -> (std::net::TcpStream, OwnedFd, SocketAddr) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let browser = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        // A close that never comes fails the test's read instead of hanging it.
        browser
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (ours, peer) = listener.accept().unwrap();
        (browser, OwnedFd::from(ours), peer)
    }

    /// Polls `future` once, whatever woke it: a test steps a session to
    /// where its inputs so far leave it, with nothing else running.
    async fn poll_once<F: Future + Send + Unpin>(future: &mut F) -> Poll<F::Output> {
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *future).poll(cx))).await
    }

    /// Yields until `done` holds, which it must not yet: the worker's other
    /// tasks run meanwhile.
    async fn until(done: &(dyn Fn() -> bool + Sync)) {
        let mut yields = 0;
        assert!(!done(), "holds already");
        while !done() {
            assert!(yields < 10_000, "does not hold after {yields} yields");
            yields += 1;
            tokio::task::yield_now().await;
        }
    }

    /// One session's surroundings, driven by hand: its connection's tracks,
    /// its engine's script, and the queues its manager would hold.
    struct Rig {
        clock: Arc<FakeClock>,
        publisher: TrackPublisher,
        script: Arc<Script>,
        events: mpsc::Receiver<(String, IpcEvent)>,
        control: mpsc::Sender<Control>,
        close: watch::Sender<CloseRequest>,
        inbound: mpsc::Sender<Inbound>,
        /// Its talk-back counters, as the manager would report them.
        talkback: Arc<TalkbackStats>,
    }

    impl Rig {
        /// The events the session reported since the last call.
        fn events(&mut self) -> Vec<IpcEvent> {
            std::iter::from_fn(|| self.events.try_recv().ok().map(|(_, event)| event)).collect()
        }

        /// The connection's first track of `kind`.
        fn track(&self, kind: Kind) -> Arc<Track> {
            self.publisher.tracks().get(TrackId::new(kind, 0)).unwrap()
        }

        fn control(&self, control: Control) {
            self.control.try_send(control).unwrap();
        }
    }

    /// Session `s` on the connection [`connection`] makes, and its task's
    /// future, not yet polled.
    fn session(script: Script, audio: bool, ready: bool) -> (Rig, impl Future<Output = ()> + Send) {
        session_on("s", script, audio, ready, "v=0", None)
    }

    /// Session `id` offering `offer` on the connection [`connection`]
    /// makes, with the arbiter of its backchannel when it has one, and
    /// its task's future, not yet polled.
    fn session_on(
        id: &str,
        script: Script,
        audio: bool,
        ready: bool,
        offer: &str,
        backchannel: Option<Arc<Arbiter>>,
    ) -> (Rig, impl Future<Output = ()> + Send) {
        session_with(id, script, (audio, audio), ready, offer, backchannel)
    }

    /// [`session_on`], its connection with an audio track when
    /// `audio.0` and the session asking for audio when `audio.1`.
    fn session_with(
        id: &str,
        script: Script,
        audio: (bool, bool),
        ready: bool,
        offer: &str,
        backchannel: Option<Arc<Arbiter>>,
    ) -> (Rig, impl Future<Output = ()> + Send) {
        let (stream_audio, audio) = audio;
        let clock = Arc::new(FakeClock::default());
        let publisher = connection(&clock, stream_audio, ready);
        let script = Arc::new(script);
        let (events_tx, events) = mpsc::channel(64);
        let (control, control_rx) = mpsc::channel(64);
        let (close, close_rx) = watch::channel(None);
        let (inbound, inbound_rx) = mpsc::channel(INBOUND_CAPACITY);
        let (uplink, _supervisor) = UnixDatagram::pair().unwrap();
        let talkback = Arc::new(TalkbackStats::default());
        let ctx = SessionCtx {
            spec: SessionSpec {
                offer: offer.into(),
                ..spec(id, audio)
            },
            inbound: inbound.clone(),
            tracks: DerivedTracks::new(Arc::clone(publisher.tracks()), Vec::new(), clock.clone()),
            mapper: Arc::new(ClockMapper::new()),
            backchannel,
            talkback: Arc::clone(&talkback),
            factory: Arc::new(ScriptedOutput(Arc::clone(&script))),
            limits: SessionLimits::default(),
            udp: Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap()),
            uplink: Arc::new(uplink),
            clock: clock.clone(),
            events: events_tx,
            routes: Arc::default(),
            stats: Arc::default(),
        };
        let rig = Rig {
            clock,
            publisher,
            script,
            events,
            control,
            close,
            inbound,
            talkback,
        };
        (rig, run_session(ctx, inbound_rx, control_rx, close_rx))
    }

    /// The camera's backchannel for the session tests: each open answers
    /// at once with a session, or with the next refusal scripted, or once
    /// `hold` is notified when it is set. The sessions' losses are kept
    /// for the tests to report, and what each takes for them to read.
    #[derive(Debug, Default)]
    struct TestCamera {
        refusals: Mutex<VecDeque<BackchannelRefused>>,
        hold: Mutex<Option<Arc<tokio::sync::Notify>>>,
        losses: Mutex<Vec<tokio::sync::oneshot::Sender<BackchannelRefused>>>,
        closes: Mutex<Vec<tokio_util::sync::CancellationToken>>,
        /// The codec its sessions open in; PCMU unless set.
        codec: Mutex<Option<Codec>>,
        /// What each session took, in the order they opened.
        devices: Mutex<Vec<mpsc::Receiver<MediaPacket>>>,
    }

    impl lotse_core::source::BackchannelOpener for TestCamera {
        fn open(
            &self,
        ) -> BoxFuture<'static, Result<lotse_core::source::BackchannelSession, BackchannelRefused>>
        {
            let refusal = self.refusals.lock().unwrap().pop_front();
            let hold = self.hold.lock().unwrap().clone();
            let (sender, device) = mpsc::channel(8);
            let (on_loss, lost) = tokio::sync::oneshot::channel();
            let close = tokio_util::sync::CancellationToken::new();
            self.losses.lock().unwrap().push(on_loss);
            self.closes.lock().unwrap().push(close.clone());
            self.devices.lock().unwrap().push(device);
            let codec = self.codec.lock().unwrap().clone();
            let session = lotse_core::source::BackchannelSession::new(
                codec.unwrap_or(Codec::Pcmu),
                lotse_core::source::BackchannelOffer::DEFAULT_FRAME,
                sender,
                lost,
                close,
            );
            Box::pin(async move {
                if let Some(hold) = hold {
                    hold.notified().await;
                }
                refusal.map_or(Ok(session), Err)
            })
        }
    }

    /// An arbiter of a connection whose source offers a PCMU backchannel,
    /// and the feed of its talker changes.
    fn arbiter() -> (Arc<Arbiter>, TalkerFeed) {
        let (arbiter, feed, _camera, _slot) = arbiter_with();
        (arbiter, feed)
    }

    /// [`arbiter`], with the camera's backchannel and the slot.
    fn arbiter_with() -> (
        Arc<Arbiter>,
        TalkerFeed,
        Arc<TestCamera>,
        lotse_core::source::BackchannelSlot,
    ) {
        let slot = lotse_core::source::BackchannelSlot::default();
        let camera = Arc::new(TestCamera::default());
        let opener: Arc<dyn lotse_core::source::BackchannelOpener> = camera.clone();
        slot.offer(lotse_core::source::BackchannelOffer {
            codec: Codec::Pcmu,
            frame: lotse_core::source::BackchannelOffer::DEFAULT_FRAME,
            opener,
        });
        let arbiter = Arc::new(Arbiter::new(
            slot.clone(),
            None,
            Arc::new(FakeClock::default()),
        ));
        let feed = TalkerFeed::new(&arbiter);
        (arbiter, feed, camera, slot)
    }

    /// The next talker change of `feed`, which must be there already.
    async fn change(feed: &mut TalkerFeed) -> (String, &'static str) {
        let next = feed.next();
        let mut next = pin!(next);
        let_assert!(Poll::Ready(Some(changed)) = poll_once(&mut next).await);
        (changed.session, changed.reason.code())
    }

    /// A client that only talks back offers no video: its session claims
    /// the backchannel for the offer as a viewer's does, opens its engine
    /// without video, takes none of the stream's video and joins none
    /// once connected; the stream's audio it was asked for reaches it.
    #[tokio::test]
    async fn a_talk_only_session_claims_the_backchannel_and_plays_no_video() {
        let (arbiter, mut feed) = arbiter();
        let (mut rig, task) = session_on(
            "t",
            Script::default(),
            true,
            true,
            "v=0 talk, no video",
            Some(Arc::clone(&arbiter)),
        );
        let mut task = pin!(task);
        assert!(poll_once(&mut task).await.is_pending());
        assert!(rig.script.called("open video=false"));
        assert!(rig.script.called("open backchannel=true claim=Granted"));
        assert_eq!(
            rig.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("t".into(), "claimed"));

        rig.track(Kind::Video)
            .publish_packet(packet(rig.clock.now()));
        rig.track(Kind::Audio)
            .publish_packet(packet(rig.clock.now()));
        rig.script
            .then(SessionOutput::Event(SessionEvent::Connected));
        rig.control(Control::Candidate("candidate:browser".into()));
        assert!(poll_once(&mut task).await.is_pending());
        assert!(rig.script.called("audio"));
        assert!(!rig.script.called("video"));
        assert!(!rig.script.called("join"));
    }

    /// A session that asks for the stream's audio on a stream without
    /// any opens without it, and without a warning: there is no audio to
    /// miss.
    #[tokio::test]
    async fn a_session_asking_for_audio_on_a_stream_without_any_opens_without_it() {
        let (mut rig, task) =
            session_with("s", Script::default(), (false, true), true, "v=0", None);
        let mut task = pin!(task);
        assert!(poll_once(&mut task).await.is_pending());
        assert!(rig.script.called("open video=true") && rig.script.called("open audio=false"));
        assert_eq!(
            rig.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: None,
            }]
        );
    }

    /// A re-offer, as the manager hands it to the session.
    fn reoffer(sdp: &str) -> Control {
        Control::Renegotiate(sdp.into())
    }

    /// A talk-back packet the engine hands on.
    fn uplink(now: Instant) -> SessionOutput {
        uplink_in(lotse_core::uplink::UplinkCodec::Pcmu, now)
    }

    /// A talk-back packet in `codec` the engine hands on.
    fn uplink_in(codec: lotse_core::uplink::UplinkCodec, now: Instant) -> SessionOutput {
        SessionOutput::Uplink(lotse_core::uplink::UplinkPacket {
            codec,
            packet: packet(now),
            duration: Duration::ZERO,
        })
    }

    /// The offer claims the backchannel before the engine answers, and
    /// the answer says so; a second session's offer is declined `busy`
    /// after its answer, one the stream cannot serve `unsupported`; a
    /// re-offer that drops talk-back lets go, one that asks for it claims
    /// or is declined, and one the engine refuses, after claiming, lets
    /// go again; a packet of a session that does not hold the backchannel
    /// is dropped and counted.
    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "two sessions' offers and re-offers")]
    async fn an_offer_claims_the_backchannel_and_re_offers_claim_or_let_go() {
        let (arbiter, mut feed) = arbiter();
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("open backchannel=true claim=Granted"));
        assert_eq!(
            a.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        assert!(a.talkback.ever_negotiated.load(Ordering::Relaxed));

        // b asks too: declined, after its answer.
        let (mut b, task) = session_on(
            "b",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut b_task = pin!(task);
        assert!(poll_once(&mut b_task).await.is_pending());
        assert!(b.script.called("open backchannel=true claim=Busy"));
        assert_eq!(
            b.events(),
            [
                IpcEvent::Answer {
                    sdp: "answer".into(),
                    talkback: None,
                },
                IpcEvent::TalkbackDeclined {
                    reason: "busy".into(),
                    status: None,
                    message: "talk-back declined: session a holds the camera's backchannel".into(),
                },
            ]
        );
        assert!(!b.talkback.ever_negotiated.load(Ordering::Relaxed));
        // b's packets go nowhere, and are counted.
        b.script.then(uplink(b.clock.now()));
        b.control(Control::Candidate("candidate:x".into()));
        assert!(poll_once(&mut b_task).await.is_pending());
        assert_eq!(b.talkback.packets_dropped_busy.load(Ordering::Relaxed), 1);

        // Talk-back the stream cannot serve: declined `unsupported`, with
        // and without a backchannel on the connection.
        for (what, backchannel) in [
            ("v=0 talk unsupported", Some(Arc::clone(&arbiter))),
            ("v=0 talk", None),
        ] {
            let (mut c, task) = session_on("c", Script::default(), false, true, what, backchannel);
            let mut c_task = pin!(task);
            assert!(poll_once(&mut c_task).await.is_pending());
            assert_eq!(
                c.events(),
                [
                    IpcEvent::Answer {
                        sdp: "answer".into(),
                        talkback: None,
                    },
                    IpcEvent::TalkbackDeclined {
                        reason: "unsupported".into(),
                        status: None,
                        message: "talk-back declined: the script says no".into(),
                    },
                ],
                "{what}"
            );
        }
        // An offer that asks for none is answered without a word.
        let (mut d, task) = session_on(
            "d",
            Script::default(),
            false,
            true,
            "v=0",
            Some(Arc::clone(&arbiter)),
        );
        let mut d_task = pin!(task);
        assert!(poll_once(&mut d_task).await.is_pending());
        assert_eq!(d.events().len(), 1);

        // a's re-offer drops talk-back: let go, and b's re-offer claims.
        a.control(reoffer("v=0"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("renegotiate v=0 claim=Granted"));
        assert_eq!(
            a.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0".into(),
                talkback: None,
            }]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "renegotiated"));
        assert!(
            a.talkback.ever_negotiated.load(Ordering::Relaxed),
            "still reported, with what it counted"
        );
        b.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut b_task).await.is_pending());
        assert!(b.script.called("renegotiate v=0 talk claim=Granted"));
        assert_eq!(
            b.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0 talk".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("b".into(), "claimed"));
        assert!(b.talkback.ever_negotiated.load(Ordering::Relaxed));
        // a asks again while b holds it: declined, after the answer.
        a.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("renegotiate v=0 talk claim=Busy"));
        assert_eq!(
            a.events(),
            [
                IpcEvent::Renegotiated {
                    sdp: "answer to v=0 talk".into(),
                    talkback: None,
                },
                IpcEvent::TalkbackDeclined {
                    reason: "busy".into(),
                    status: None,
                    message: "talk-back declined: session b holds the camera's backchannel".into(),
                },
            ]
        );
        // A re-offer the engine refuses leaves the holder holding.
        b.control(reoffer("v=0 talk refuse"));
        assert!(poll_once(&mut b_task).await.is_pending());
        assert_eq!(
            b.events(),
            [IpcEvent::RenegotiateRefused {
                code: "invalid_sdp".into(),
                message: "invalid re-offer: refused by the script".into(),
            }]
        );
        assert!(b.talkback.ever_negotiated.load(Ordering::Relaxed));
        // b lets go; a's refused re-offer claimed first, and lets go again.
        b.control(reoffer("v=0"));
        assert!(poll_once(&mut b_task).await.is_pending());
        assert_eq!(change(&mut feed).await, ("b".into(), "renegotiated"));
        a.control(reoffer("v=0 talk refuse"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(
            a.events(),
            [IpcEvent::RenegotiateRefused {
                code: "invalid_sdp".into(),
                message: "invalid re-offer: refused by the script".into(),
            }]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        assert_eq!(change(&mut feed).await, ("a".into(), "renegotiated"));
        // A session closing lets go of what it holds.
        a.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        request_close(&a.close, "session_closed", "bye".into());
        assert!(poll_once(&mut a_task).await.is_ready());
        assert_eq!(change(&mut feed).await, ("a".into(), "session_closed"));
    }

    /// A re-offer whose talk-back the output judged negotiable, which the
    /// engine answers without (an m-line it answered before kept a codec
    /// the camera does not take), lets go of the backchannel the session
    /// claimed for it, or held from before, and is declined
    /// `unsupported` after the answer; another session claims it then.
    #[tokio::test]
    async fn a_re_offer_the_engine_answers_without_talk_back_lets_go_of_the_backchannel() {
        let declined = IpcEvent::TalkbackDeclined {
            reason: "unsupported".into(),
            status: None,
            message: "talk-back declined: the session answered without talk-back".into(),
        };
        let (arbiter, mut feed) = arbiter();
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(a.events().len(), 1, "answered");
        // Claimed for the re-offer, and let go once it is answered.
        a.control(reoffer("v=0 talk kept"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("renegotiate v=0 talk kept claim=Granted"));
        assert_eq!(
            a.events(),
            [
                IpcEvent::Renegotiated {
                    sdp: "answer to v=0 talk kept".into(),
                    talkback: None,
                },
                declined.clone(),
            ]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        assert_eq!(change(&mut feed).await, ("a".into(), "renegotiated"));
        assert!(!a.talkback.ever_negotiated.load(Ordering::Relaxed));
        // Held from before: let go all the same.
        a.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        assert_eq!(
            a.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0 talk".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        a.control(reoffer("v=0 talk kept"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("renegotiate v=0 talk kept claim=Granted"));
        assert_eq!(
            a.events(),
            [
                IpcEvent::Renegotiated {
                    sdp: "answer to v=0 talk kept".into(),
                    talkback: None,
                },
                declined,
            ]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "renegotiated"));
        // The backchannel is free for another session.
        let (b, task) = session_on(
            "b",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut b_task = pin!(task);
        assert!(poll_once(&mut b_task).await.is_pending());
        assert!(b.script.called("open backchannel=true claim=Granted"));
        assert_eq!(change(&mut feed).await, ("b".into(), "claimed"));
    }

    /// The stream audio a session sends weighs its offer's talk-back
    /// ([`OutputFactory::talkback_request`]): an offer the output cannot
    /// give talk-back beside it (`one-way`) is declined `unsupported` and
    /// claims nothing, and so is a re-offer, which the audio the session
    /// opened with still weighs; the same offer from a session without
    /// stream audio claims the backchannel.
    #[tokio::test]
    async fn the_stream_audio_weighs_the_talk_back_of_an_offer_and_its_re_offers() {
        let (arbiter, mut feed) = arbiter();
        let declined = IpcEvent::TalkbackDeclined {
            reason: "unsupported".into(),
            status: None,
            message: "talk-back declined: the script says one way".into(),
        };
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            true,
            true,
            "v=0 talk one-way",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("open audio=true"));
        assert_eq!(
            a.events(),
            [
                IpcEvent::Answer {
                    sdp: "answer".into(),
                    talkback: None,
                },
                declined.clone(),
            ]
        );
        a.control(reoffer("v=0 talk one-way"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(
            a.events(),
            [
                IpcEvent::Renegotiated {
                    sdp: "answer to v=0 talk one-way".into(),
                    talkback: None,
                },
                declined,
            ]
        );
        // Without stream audio the same offer claims, the first change
        // the feed reports: a claimed nothing.
        let (mut b, task) = session_on(
            "b",
            Script::default(),
            false,
            true,
            "v=0 talk one-way",
            Some(Arc::clone(&arbiter)),
        );
        let mut b_task = pin!(task);
        assert!(poll_once(&mut b_task).await.is_pending());
        assert_eq!(
            b.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("b".into(), "claimed"));
    }

    /// ONVIF Streaming Specification §5.3: the camera takes no data before
    /// its backchannel session's `PLAY` is answered, so the answer to the
    /// offer that claims it waits until the session is open; a close
    /// meanwhile ends the session and lets go of the claim.
    #[tokio::test]
    async fn onvif_5_3_the_answer_to_a_claiming_offer_waits_for_the_backchannel_session() {
        let (arbiter, mut feed, camera, _slot) = arbiter_with();
        let go = Arc::new(tokio::sync::Notify::new());
        *camera.hold.lock().unwrap() = Some(Arc::clone(&go));
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = Box::pin(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(
            a.events().is_empty(),
            "no answer before the session is open"
        );
        assert!(a.script.calls.lock().unwrap().is_empty(), "not opened yet");
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        go.notify_one();
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("open backchannel=true claim=Granted"));
        assert_eq!(
            a.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: Some("pcmu".into()),
            }]
        );

        // b's answer waits too, and b closes meanwhile: it lets go.
        drop(a_task);
        assert_eq!(change(&mut feed).await, ("a".into(), "session_closed"));
        let (mut b, task) = session_on(
            "b",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut b_task = pin!(task);
        assert!(poll_once(&mut b_task).await.is_pending());
        assert_eq!(change(&mut feed).await, ("b".into(), "claimed"));
        request_close(&b.close, "session_closed", "bye".into());
        assert!(poll_once(&mut b_task).await.is_ready());
        assert_eq!(b.events(), [closed("session_closed", "bye")]);
        assert_eq!(change(&mut feed).await, ("b".into(), "session_closed"));
        // c's answer waits, and its manager goes meanwhile: the worker is
        // stopping.
        let (mut c, task) = session_on(
            "c",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut c_task = pin!(task);
        assert!(poll_once(&mut c_task).await.is_pending());
        assert_eq!(change(&mut feed).await, ("c".into(), "claimed"));
        c.close = watch::channel(None).0;
        assert!(poll_once(&mut c_task).await.is_ready());
        assert_eq!(
            c.events(),
            [closed("shutting_down", "the worker is stopping")]
        );
        assert_eq!(change(&mut feed).await, ("c".into(), "session_closed"));
        assert!(
            camera
                .closes
                .lock()
                .unwrap()
                .iter()
                .all(tokio_util::sync::CancellationToken::is_cancelled),
            "every session closed"
        );
    }

    /// The camera refuses the backchannel session: the answer declines
    /// talk-back with `refused` and the camera's status, and no claim is
    /// kept; the next offer opens one.
    #[tokio::test]
    async fn rfc2326_11_3_3_a_refused_backchannel_session_declines_with_its_status() {
        let (arbiter, mut feed, camera, _slot) = arbiter_with();
        camera
            .refusals
            .lock()
            .unwrap()
            .push_back(BackchannelRefused {
                status: Some(453),
                message: "SETUP: 453 Not Enough Bandwidth".into(),
            });
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("open backchannel=true claim=Busy"));
        assert_eq!(
            a.events(),
            [
                IpcEvent::Answer {
                    sdp: "answer".into(),
                    talkback: None,
                },
                IpcEvent::TalkbackDeclined {
                    reason: "refused".into(),
                    status: Some(453),
                    message: "talk-back declined: the camera's backchannel session: SETUP: 453 Not Enough Bandwidth".into(),
                },
            ]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        assert_eq!(change(&mut feed).await, ("a".into(), "refused"));
        // The user's next press: a re-offer, which opens one.
        a.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(
            a.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0 talk".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
    }

    /// A re-offer that claims waits for the backchannel session while the
    /// session plays on; another re-offer meanwhile is refused.
    #[tokio::test]
    async fn a_held_re_offer_leaves_the_session_playing_and_refuses_another() {
        let (arbiter, mut feed, camera, _slot) = arbiter_with();
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(a.events().len(), 1, "the answer");
        let go = Arc::new(tokio::sync::Notify::new());
        *camera.hold.lock().unwrap() = Some(Arc::clone(&go));
        a.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.events().is_empty(), "held");
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        // The session plays on meanwhile.
        a.control(Control::Candidate("candidate:x".into()));
        a.control(reoffer("v=0 talk again"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("candidate candidate:x"));
        assert_eq!(
            a.events(),
            [IpcEvent::RenegotiateRefused {
                code: "internal_error".into(),
                message: "a re-offer of the session is still being answered".into(),
            }]
        );
        go.notify_one();
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("renegotiate v=0 talk claim=Granted"));
        assert_eq!(
            a.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0 talk".into(),
                talkback: Some("pcmu".into()),
            }]
        );
    }

    /// The camera's backchannel session is lost while the session talks:
    /// one `refused` warning with why, and the claim released.
    #[tokio::test]
    async fn a_lost_backchannel_session_warns_the_talker_once() {
        let (arbiter, mut feed, camera, _slot) = arbiter_with();
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(a.events().len(), 1, "the answer");
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        let on_loss = camera.losses.lock().unwrap().pop().unwrap();
        on_loss
            .send(BackchannelRefused {
                status: Some(454),
                message: "GET_PARAMETER: 454 Session Not Found".into(),
            })
            .unwrap();
        // The arbiter's watch runs on the runtime: step the session until
        // the warning is out.
        let mut events = Vec::new();
        for _ in 0..10_000 {
            assert!(poll_once(&mut a_task).await.is_pending());
            events = a.events();
            if !events.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            events,
            [IpcEvent::TalkbackDeclined {
                reason: "refused".into(),
                status: Some(454),
                message: "talk-back declined: the camera's backchannel session: GET_PARAMETER: 454 Session Not Found".into(),
            }]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "refused"));
    }

    /// While the source probes the camera with nothing offered, an offer
    /// that asks for talk-back waits for the probe; one that asks for none
    /// does not.
    #[tokio::test]
    async fn an_offer_that_asks_for_talk_back_waits_for_the_probe() {
        let (arbiter, mut feed, camera, slot) = arbiter_with();
        slot.withdraw();
        slot.probing();
        let (mut d, task) = session_on(
            "d",
            Script::default(),
            false,
            true,
            "v=0",
            Some(Arc::clone(&arbiter)),
        );
        let mut d_task = pin!(task);
        assert!(poll_once(&mut d_task).await.is_pending());
        assert_eq!(d.events().len(), 1, "answered at once");
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.events().is_empty(), "waits for the probe");
        slot.withdraw();
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(
            a.events(),
            [
                IpcEvent::Answer {
                    sdp: "answer".into(),
                    talkback: None,
                },
                IpcEvent::TalkbackDeclined {
                    reason: "unsupported".into(),
                    status: None,
                    message: "talk-back declined: the script says no".into(),
                },
            ]
        );
        let next = feed.next();
        let mut next = pin!(next);
        assert!(poll_once(&mut next).await.is_pending(), "nothing claimed");
        // The next probe finds the backchannel: a's re-offer meanwhile
        // waits for it, then claims and opens it.
        slot.probing();
        a.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.events().is_empty(), "waits for the probe");
        let opener: Arc<dyn lotse_core::source::BackchannelOpener> = camera;
        slot.offer(lotse_core::source::BackchannelOffer {
            codec: Codec::Pcmu,
            frame: lotse_core::source::BackchannelOffer::DEFAULT_FRAME,
            opener,
        });
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(
            a.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0 talk".into(),
                talkback: Some("pcmu".into()),
            }]
        );
    }

    /// A reconnect's probe that waits for its connect permit does not hold
    /// up a claim: the offer kept from before is claimed and opened at
    /// once, the probe still running.
    #[tokio::test]
    async fn an_offer_claims_the_backchannel_a_reconnect_kept_while_its_probe_runs() {
        let (logs, _guard) = Logs::capture();
        let (arbiter, mut feed, _camera, slot) = arbiter_with();
        slot.probing();
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0 talk",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(
            a.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        assert!(slot.is_probing(), "the probe still runs");
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "talk-back: the source probes the camera again; a claim takes the backchannel offered before without waiting for it"
            ),
            1
        );
    }

    /// A probe again that finds another codec than the talker's open
    /// backchannel session leaves that session open, and the talker's
    /// re-offers negotiate with it: Opus, which reaches it, though the
    /// camera now offers PCMU, which would reach nothing; a re-offer that
    /// can send it nothing is declined and lets go. Another session
    /// negotiates with what the camera offers now, and claims and opens
    /// that once the channel is free.
    #[tokio::test]
    async fn a_talkers_re_offer_negotiates_with_its_open_session_not_a_new_probes_codec() {
        let (arbiter, mut feed, camera, slot) = arbiter_with();
        let opener: Arc<dyn lotse_core::source::BackchannelOpener> = camera.clone();
        let offer = |codec: Codec| lotse_core::source::BackchannelOffer {
            codec,
            frame: lotse_core::source::BackchannelOffer::DEFAULT_FRAME,
            opener: Arc::clone(&opener),
        };
        let opus = Codec::Opus { channels: 2 };
        *camera.codec.lock().unwrap() = Some(opus.clone());
        slot.offer(offer(opus));
        let (mut a, task) = session_on(
            "a",
            Script::default(),
            false,
            true,
            "v=0 talk opus pcmu",
            Some(Arc::clone(&arbiter)),
        );
        let mut a_task = pin!(task);
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("open with opus taking opus"));
        assert_eq!(
            a.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: Some("opus".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));

        // The probe again finds PCMU; a's Opus session stays open, and its
        // re-offer that prefers PCMU negotiates Opus all the same.
        *camera.codec.lock().unwrap() = None;
        slot.offer(offer(Codec::Pcmu));
        a.control(reoffer("v=0 talk pcmu opus"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert!(a.script.called("renegotiate with opus taking opus"));
        assert_eq!(
            a.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0 talk pcmu opus".into(),
                talkback: Some("opus".into()),
            }]
        );
        // Its Opus reaches its session; the forwarder runs on the runtime.
        a.script.then(uplink_in(
            lotse_core::uplink::UplinkCodec::Opus,
            a.clock.now(),
        ));
        a.control(Control::Candidate("candidate:x".into()));
        assert!(poll_once(&mut a_task).await.is_pending());
        until(&|| a.talkback.packets_sent.load(Ordering::Relaxed) == 1).await;
        assert!(camera.devices.lock().unwrap()[0].try_recv().is_ok());
        assert_eq!(a.talkback.packets_dropped.load(Ordering::Relaxed), 0);

        // b negotiates with the offer of now, which a holds.
        let (mut b, task) = session_on(
            "b",
            Script::default(),
            false,
            true,
            "v=0 talk pcmu",
            Some(Arc::clone(&arbiter)),
        );
        let mut b_task = pin!(task);
        assert!(poll_once(&mut b_task).await.is_pending());
        assert!(b.script.called("open with pcmu taking pcmu"));
        assert!(b.script.called("open backchannel=true claim=Busy"));
        assert_eq!(b.events().len(), 2, "the answer and the decline");

        // a's re-offer that names PCMU alone cannot reach its session:
        // declined, and a lets go.
        a.control(reoffer("v=0 talk pcmu"));
        assert!(poll_once(&mut a_task).await.is_pending());
        assert_eq!(
            a.events(),
            [
                IpcEvent::Renegotiated {
                    sdp: "answer to v=0 talk pcmu".into(),
                    talkback: None,
                },
                IpcEvent::TalkbackDeclined {
                    reason: "unsupported".into(),
                    status: None,
                    message: "talk-back declined: the script says no".into(),
                },
            ]
        );
        assert_eq!(change(&mut feed).await, ("a".into(), "renegotiated"));
        // b's re-offer claims and opens the PCMU session.
        b.control(reoffer("v=0 talk pcmu"));
        assert!(poll_once(&mut b_task).await.is_pending());
        assert!(b.script.called("renegotiate with pcmu taking pcmu"));
        assert_eq!(
            b.events(),
            [IpcEvent::Renegotiated {
                sdp: "answer to v=0 talk pcmu".into(),
                talkback: Some("pcmu".into()),
            }]
        );
        assert_eq!(change(&mut feed).await, ("b".into(), "claimed"));
        assert_eq!(camera.devices.lock().unwrap().len(), 2, "b's opened");
    }

    /// A probe that replaces the offer between an offer's assessment and
    /// its claim: the claim opens the backchannel the answer is
    /// negotiated with, or none. Opus in place of the negotiated PCMU
    /// declines the offer `refused`, nothing opened and nothing claimed,
    /// so its answer goes out without talk-back rather than with PCMU an
    /// Opus session would drop; PCMU found again is opened, and the
    /// answer's PCMU reaches it.
    #[tokio::test]
    async fn a_claim_declines_a_backchannel_replaced_since_its_offer_was_assessed() {
        let (arbiter, mut feed, camera, slot) = arbiter_with();
        let opener: Arc<dyn lotse_core::source::BackchannelOpener> = camera.clone();
        let offer = |codec: Codec| lotse_core::source::BackchannelOffer {
            codec,
            frame: lotse_core::source::BackchannelOffer::DEFAULT_FRAME,
            opener: Arc::clone(&opener),
        };
        let stats = Arc::new(TalkbackStats::default());
        let mut talkback = Talkback::new(Arc::clone(&arbiter), "a".into(), Arc::clone(&stats));
        let output = ScriptedOutput::default();
        let assessed = assess(&output, &talkback.claimant(), None, "v=0 talk pcmu");
        assert!(assessed.claims);
        assert_eq!(
            target_name(assessed.arbitration.backchannel.as_ref()),
            "pcmu taking pcmu"
        );
        // The probe again finds Opus before the claim.
        let opus = Codec::Opus { channels: 2 };
        *camera.codec.lock().unwrap() = Some(opus.clone());
        slot.offer(offer(opus));
        let declined = claim(
            assessed.arbitration,
            talkback.claimant(),
            BACKCHANNEL_OPEN_LIMIT,
        )
        .await;
        assert_eq!(declined.claim, TalkbackClaim::Busy);
        assert_eq!(
            declined.decline,
            Some(Decline::Refused(BackchannelRefused {
                status: None,
                message: "the camera's backchannel changed to opus while the offer was negotiated"
                    .into(),
            }))
        );
        assert!(declined.granted.is_none() && !declined.claimed);
        assert!(camera.devices.lock().unwrap().is_empty(), "nothing opened");
        {
            let next = feed.next();
            let mut next = pin!(next);
            assert!(poll_once(&mut next).await.is_pending(), "nothing claimed");
        }

        // It finds PCMU again, after the next offer's assessment: the same
        // backchannel, opened.
        *camera.codec.lock().unwrap() = None;
        slot.offer(offer(Codec::Pcmu));
        let assessed = assess(&output, &talkback.claimant(), None, "v=0 talk pcmu");
        slot.offer(offer(Codec::Pcmu));
        let mut granted = claim(
            assessed.arbitration,
            talkback.claimant(),
            BACKCHANNEL_OPEN_LIMIT,
        )
        .await;
        assert_eq!(
            (granted.claim, granted.decline.is_none(), granted.claimed),
            (TalkbackClaim::Granted, true, true)
        );
        talkback.adopt(granted.granted.take().unwrap());
        assert_eq!(change(&mut feed).await, ("a".into(), "claimed"));
        talkback.receive(lotse_core::uplink::UplinkPacket {
            codec: lotse_core::uplink::UplinkCodec::Pcmu,
            packet: packet(SystemClock.now()),
            duration: Duration::ZERO,
        });
        until(&|| stats.packets_sent.load(Ordering::Relaxed) == 1).await;
        assert!(camera.devices.lock().unwrap()[0].try_recv().is_ok());
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 0);
    }

    /// A re-offer before the answer is refused; the manager hands one on
    /// to its session, and tells its caller of one for a session it does
    /// not hold or whose queue is full, for the caller to refuse.
    #[tokio::test]
    async fn a_re_offer_before_the_answer_or_for_no_session_is_refused() {
        let (mut rig, session) = session(Script::default(), false, false);
        let mut session = pin!(session);
        assert!(poll_once(&mut session).await.is_pending());
        rig.control(reoffer("v=0 talk"));
        assert!(poll_once(&mut session).await.is_pending());
        assert_eq!(
            rig.events(),
            [IpcEvent::RenegotiateRefused {
                code: "internal_error".into(),
                message: "the session has no answer yet".into(),
            }]
        );
        assert!(rig.script.calls.lock().unwrap().is_empty(), "never opened");

        let mut m = managed();
        assert!(!m.manager.renegotiate("ghost", "v=0".into()), "no session");
        m.open("a").await;
        assert!(m.manager.renegotiate("a", "v=0".into()), "handed on");
        // Its task has not run, so nothing reads the queue.
        while m.manager.sessions["a"]
            .control
            .try_send(Control::Candidate(String::new()))
            .is_ok()
        {}
        assert!(!m.manager.renegotiate("a", "v=0".into()), "queue full");
    }

    fn closed(code: &str, message: &str) -> IpcEvent {
        IpcEvent::Closed {
            code: code.into(),
            message: message.into(),
        }
    }

    /// A session drives its engine with every input it has: media, the
    /// supervisor's messages, datagrams and time; reports what the engine
    /// says but a keyframe request, which stays in the worker; and closes
    /// once its control queue goes, as the worker stops.
    #[tokio::test]
    #[expect(clippy::too_many_lines, reason = "one session's whole life")]
    async fn a_live_session_drives_its_engine_and_closes_when_its_control_goes() {
        let (logs, _guard) = Logs::capture();
        let (mut rig, session) = session(Script::default(), true, true);
        let mut session = pin!(session);
        assert!(poll_once(&mut session).await.is_pending());
        assert_eq!(
            rig.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: None,
            }]
        );
        assert!(rig.script.called("open video=true") && rig.script.called("open audio=true"));

        rig.track(Kind::Video)
            .publish_packet(packet(rig.clock.now()));
        rig.track(Kind::Audio)
            .publish_packet(packet(rig.clock.now()));
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("video") && rig.script.called("audio"));

        // What the engine says after the next input.
        rig.script
            .then(SessionOutput::Event(SessionEvent::Connected));
        rig.script
            .then(SessionOutput::Event(SessionEvent::KeyframeRequest));
        rig.script
            .then(SessionOutput::Event(SessionEvent::Candidate {
                candidate: "candidate:1".into(),
                mid: Some("0".into()),
            }));
        rig.script.then(SessionOutput::Event(SessionEvent::State {
            ice: "connected",
            dtls: "connected",
        }));
        rig.control(Control::Candidate("candidate:browser".into()));
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("candidate candidate:browser"));
        assert!(rig.script.called("join"));
        assert_eq!(
            rig.events(),
            [
                IpcEvent::Candidate {
                    candidate: "candidate:1".into(),
                    mid: Some("0".into())
                },
                IpcEvent::State {
                    ice: "connected".into(),
                    dtls: "connected".into()
                }
            ]
        );
        assert_eq!(logs.count(Level::DEBUG, "keyframe wanted upstream"), 1);

        let relayed: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        rig.control(Control::Orientation(Orientation::Rotate180));
        rig.control(Control::Relay {
            relayed,
            server: "203.0.113.1:3478".parse().unwrap(),
            local: "127.0.0.1:5000".parse().unwrap(),
            tcp: false,
        });
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("orientation rotate_180"));
        assert_eq!(
            rig.events(),
            [IpcEvent::Relayed {
                relayed,
                candidate: Some(format!("candidate:relay {relayed}"))
            }]
        );
        rig.control(Control::Channel {
            relayed,
            peer: "192.0.2.1:5000".parse().unwrap(),
            channel: 0x4000,
        });
        assert!(poll_once(&mut session).await.is_pending());

        // A hand-off whose descriptor the runtime cannot poll.
        let dev_null = OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
        rig.control(Control::Tcp {
            stream: std::net::TcpStream::from(dev_null),
            peer: "192.0.2.1:5000".parse().unwrap(),
            first_frame: vec![0, 1],
        });
        assert!(poll_once(&mut session).await.is_pending());
        assert_eq!(logs.count(Level::WARN, "ice-tcp connection not usable"), 1);

        rig.inbound
            .try_send(Inbound {
                transport: Transport::Udp,
                source: "192.0.2.1:5000".parse().unwrap(),
                destination: "127.0.0.1:5000".parse().unwrap(),
                payload: b"check".to_vec(),
            })
            .unwrap();
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("datagram Udp 192.0.2.1:5000 check"));

        // A new epoch, then a codec change within the family.
        rig.publisher.discontinuity();
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("skip epoch"));
        rig.track(Kind::Video).set_codec(Codec::H264 {
            profile_level_id: Some([0x42, 0xe0, 0x1f]),
            sps: None,
            pps: None,
        });
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("video change h264"));

        // The audio track ends: the session goes on with video.
        rig.track(Kind::Audio).close();
        assert!(poll_once(&mut session).await.is_pending());
        assert_eq!(
            logs.count(
                Level::INFO,
                "audio track closed; the session continues without it"
            ),
            1
        );

        rig.clock.advance(HOUR);
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("timeout"));

        rig.control = mpsc::channel(1).0;
        assert!(poll_once(&mut session).await.is_ready());
        assert!(rig.script.called("close shutting_down"));
        assert_eq!(
            rig.events(),
            [closed("shutting_down", "the worker is stopping")]
        );
    }

    /// While it waits for the tracks, a session keeps what its answer
    /// needs, closes an ICE-TCP connection no browser can use yet, waits
    /// on while the tracks are not ready, and closes when asked.
    #[tokio::test]
    async fn a_session_waiting_for_the_tracks_closes_an_ice_tcp_connection_and_closes_on_request() {
        let (mut rig, session) = session(Script::default(), false, false);
        let mut session = pin!(session);
        assert!(poll_once(&mut session).await.is_pending());
        let (mut browser, ours, peer) = tcp_pair();
        rig.control(Control::Candidate("candidate:early".into()));
        rig.control(Control::Tcp {
            stream: std::net::TcpStream::from(ours),
            peer,
            first_frame: vec![0, 1],
        });
        assert!(poll_once(&mut session).await.is_pending());
        assert_eq!(browser.read(&mut [0_u8; 1]).unwrap(), 0, "closed");
        // A connection ends before it went live: still not ready.
        rig.publisher.tracks().reset_ready();
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.events().is_empty());
        request_close(&rig.close, "session_closed", "bye".into());
        assert!(poll_once(&mut session).await.is_ready());
        assert_eq!(rig.events(), [closed("session_closed", "bye")]);
        assert!(rig.script.calls.lock().unwrap().is_empty(), "never opened");
    }

    /// What arrives while a session waits for the tracks reaches its
    /// answer: the orientation it opens with, and the relay candidates,
    /// whose channels must wait for them.
    #[tokio::test]
    async fn a_session_waiting_for_the_tracks_answers_with_what_arrived_meanwhile() {
        let (mut rig, session) = session(Script::default(), false, false);
        let mut session = pin!(session);
        assert!(poll_once(&mut session).await.is_pending());
        let relayed: SocketAddr = "203.0.113.5:40000".parse().unwrap();
        rig.control(Control::Orientation(Orientation::Rotate180));
        rig.control(Control::Relay {
            relayed,
            server: "203.0.113.1:3478".parse().unwrap(),
            local: "127.0.0.1:5000".parse().unwrap(),
            tcp: false,
        });
        rig.control(Control::Channel {
            relayed,
            peer: "192.0.2.1:5000".parse().unwrap(),
            channel: 0x4000,
        });
        assert!(poll_once(&mut session).await.is_pending());
        assert!(
            rig.script.calls.lock().unwrap().is_empty(),
            "not opened yet"
        );
        rig.publisher.ready();
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.script.called("open orientation=rotate_180"));
        assert!(rig.script.called(&format!("relay {relayed}")));
        assert_eq!(
            rig.events(),
            [
                IpcEvent::Answer {
                    sdp: "answer".into(),
                    talkback: None,
                },
                IpcEvent::Relayed {
                    relayed,
                    candidate: Some(format!("candidate:relay {relayed}"))
                }
            ]
        );
    }

    #[tokio::test]
    async fn a_session_waiting_for_the_tracks_ends_with_its_control_queue() {
        let (mut rig, session) = session(Script::default(), false, false);
        let mut session = pin!(session);
        rig.control = mpsc::channel(1).0;
        assert!(poll_once(&mut session).await.is_ready());
        assert_eq!(
            rig.events(),
            [closed("shutting_down", "the worker is stopping")]
        );
    }

    /// The supervisor closes a waiting session when its source fails; the
    /// session keeps no deadline of its own.
    #[tokio::test]
    async fn a_session_waits_for_the_tracks_however_long_the_source_takes() {
        let (mut rig, session) = session(Script::default(), false, false);
        let mut session = pin!(session);
        assert!(poll_once(&mut session).await.is_pending());
        rig.clock.advance(Duration::from_secs(3600));
        assert!(poll_once(&mut session).await.is_pending());
        assert!(rig.events().is_empty());
        rig.publisher.ready();
        assert!(poll_once(&mut session).await.is_pending());
        assert_eq!(
            rig.events(),
            [IpcEvent::Answer {
                sdp: "answer".into(),
                talkback: None,
            }]
        );
    }

    #[tokio::test]
    async fn an_offer_the_output_refuses_closes_the_session_with_its_code() {
        let script = Script {
            refuse: true,
            ..Script::default()
        };
        let (mut rig, session) = session(script, false, true);
        assert_eq!(session.await, ());
        assert!(rig.script.called("open audio=false"));
        assert_eq!(
            rig.events(),
            [closed(
                "invalid_sdp",
                "invalid offer: refused by the script"
            )]
        );
        // The parts no test session reaches.
        let engine = Scripted {
            script: Arc::default(),
            idle: rig.clock.now(),
            talkback: None,
            audio: false,
        };
        assert_eq!(engine.stats(), SessionStats::default());
        assert_eq!(engine.talkback(), None);
    }

    /// A manager on fresh sockets with the scripted output, and what a
    /// test drives it with.
    struct Managed {
        manager: SessionManager,
        /// The supervisor's end of the datagram channel.
        demux: StdUnixDatagram,
        events: mpsc::Receiver<(String, IpcEvent)>,
        clock: Arc<FakeClock>,
        registries: Registries,
        /// A connection that never goes live.
        tracks: Arc<DerivedTracks>,
    }

    fn managed() -> Managed {
        let clock = Arc::new(FakeClock::default());
        let (datagrams, demux) = StdUnixDatagram::pair().unwrap();
        let (events_tx, events) = mpsc::channel(64);
        let manager = SessionManager::new(
            OwnedFd::from(UdpSocket::bind("127.0.0.1:0").unwrap()),
            None,
            OwnedFd::from(datagrams),
            8,
            clock.clone(),
            events_tx,
        )
        .unwrap();
        let mut registries = Registries::default();
        registries
            .outputs
            .register(Arc::new(ScriptedOutput::default()))
            .unwrap();
        let publisher = connection(&clock, false, false);
        let tracks = DerivedTracks::new(Arc::clone(publisher.tracks()), Vec::new(), clock.clone());
        Managed {
            manager,
            demux,
            events,
            clock,
            registries,
            tracks,
        }
    }

    impl Managed {
        /// Opens session `id`, which waits for the tracks. Its task has not
        /// run when this returns.
        async fn open(&mut self, id: &str) {
            self.manager
                .open(
                    spec(id, false),
                    ConnectionMedia {
                        tracks: Arc::clone(&self.tracks),
                        mapper: Arc::new(ClockMapper::new()),
                        backchannel: None,
                    },
                    &self.registries,
                    SessionLimits::default(),
                )
                .await;
        }

        /// The manager's next event, or a failed test after five seconds
        /// of real time: an answer that never comes fails instead of
        /// hanging.
        async fn next(&mut self) -> (String, IpcEvent) {
            tokio::select! {
                event = self.events.recv() => event.unwrap(),
                () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no event within 5 s"),
            }
        }

        /// Sends a datagram-channel frame for `ufrag` as the supervisor's
        /// demux does.
        fn route(&self, ufrag: &str) {
            let mut frame = Vec::new();
            datagram::encode(
                ufrag,
                "192.0.2.1:5000".parse().unwrap(),
                "127.0.0.1:5000".parse().unwrap(),
                b"check",
                &mut frame,
            );
            self.demux.send(&frame).unwrap();
        }
    }

    /// The talk-back counters for the supervisor's stats: one entry per
    /// session whose answer negotiated talk-back, in the order of their
    /// ids whatever the order they opened in.
    #[tokio::test]
    async fn talk_back_counters_are_reported_per_negotiated_session_in_id_order() {
        let mut m = managed();
        for id in ["b", "a", "c"] {
            m.open(id).await;
        }
        assert!(m.manager.talkback().is_empty(), "none negotiated");
        for id in ["b", "a"] {
            let stats = &m.manager.sessions[id].talkback;
            stats.ever_negotiated.store(true, Ordering::Relaxed);
        }
        let b = &m.manager.sessions["b"].talkback;
        b.packets_received.store(2, Ordering::Relaxed);
        assert_eq!(
            m.manager.talkback(),
            [
                ("a".to_owned(), lotse_ipc::TalkbackStats::default()),
                (
                    "b".to_owned(),
                    lotse_ipc::TalkbackStats {
                        packets_received: 2,
                        ..lotse_ipc::TalkbackStats::default()
                    }
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_session_id_already_open_is_refused() {
        let mut m = managed();
        m.open("a").await;
        m.open("a").await;
        assert_eq!(
            m.next().await,
            (
                "a".into(),
                closed("internal_error", "session id already open in this worker")
            )
        );
    }

    /// The manager never waits on a session: what its full control queue
    /// cannot take is dropped, an ICE-TCP connection closed, but a close
    /// still reaches it.
    #[tokio::test]
    async fn a_session_whose_control_queue_is_full_drops_messages_and_closes_hand_offs() {
        let (logs, _guard) = Logs::capture();
        let mut m = managed();
        m.open("a").await;
        // Its task has not run, so nothing reads the queue.
        for n in 0..64 {
            m.manager.candidate("a", format!("candidate:{n}"));
        }
        let dropped = "message dropped: session busy or gone";
        assert_eq!(logs.count(Level::DEBUG, dropped), 0);
        m.manager.candidate("a", "candidate:64".into());
        assert_eq!(logs.count(Level::DEBUG, dropped), 1);
        let (mut browser, ours, peer) = tcp_pair();
        m.manager.ice_tcp("ufrag-a", ours, peer, vec![0, 1]);
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "session busy or gone; ice-tcp connection closed"
            ),
            1
        );
        assert_eq!(browser.read(&mut [0_u8; 1]).unwrap(), 0, "closed");
        // A close is never dropped, and the first one asked is the one.
        m.manager.close("a", "session_closed", "bye".into());
        m.manager.close("a", "shutting_down", "later".into());
        assert_eq!(
            m.next().await,
            ("a".to_owned(), closed("session_closed", "bye"))
        );
        m.manager.close("nobody", "session_closed", String::new());
        assert_eq!(logs.count(Level::DEBUG, "close for an unknown session"), 1);
    }

    #[tokio::test]
    async fn closing_all_sessions_waits_for_their_tasks_at_most_the_close_budget() {
        let (logs, _guard) = Logs::capture();
        let mut m = managed();
        m.open("a").await;
        let mut closing = pin!(m.manager.close_all("shutting_down", "bye"));
        // The session's task has not run, so it cannot have stopped.
        assert!(poll_once(&mut closing).await.is_pending());
        m.clock.advance(CLOSE_BUDGET);
        closing.await;
        assert_eq!(
            logs.count(Level::WARN, "session task did not stop in time"),
            1
        );
    }

    /// The router drops what no session can take: a frame for a session
    /// whose queue is full, one for no session, and one that does not
    /// decode.
    #[tokio::test]
    async fn the_router_counts_malformed_frames_and_frames_for_no_session_or_a_full_queue() {
        let mut m = managed();
        m.open("a").await;
        // The session waits for the tracks, so it reads none of its queue.
        let queue = m.manager.routes.lock().unwrap().get("ufrag-a").cloned();
        let queue = queue.unwrap();
        let datagram = || Inbound {
            transport: Transport::Udp,
            source: "192.0.2.1:5000".parse().unwrap(),
            destination: "127.0.0.1:5000".parse().unwrap(),
            payload: Vec::new(),
        };
        while queue.try_send(datagram()).is_ok() {}
        m.route("ufrag-a");
        until(&|| m.manager.stats().dropped.load(Ordering::Relaxed) == 1).await;
        m.route("ufrag-nobody");
        until(&|| m.manager.stats().unroutable.load(Ordering::Relaxed) == 1).await;
        m.demux.send(&[0xff, 0xff]).unwrap();
        until(&|| m.manager.stats().malformed.load(Ordering::Relaxed) == 1).await;
    }

    #[tokio::test]
    async fn a_datagram_channel_that_fails_to_read_stops_the_router() {
        let (logs, _guard) = Logs::capture();
        // A listening TCP socket with a connection waiting is readable, and
        // a read on it fails.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _waiting = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (events, _rx) = mpsc::channel(1);
        let mut manager = SessionManager::new(
            OwnedFd::from(UdpSocket::bind("127.0.0.1:0").unwrap()),
            None,
            OwnedFd::from(listener),
            8,
            Arc::new(FakeClock::default()),
            events,
        )
        .unwrap();
        (&mut manager.reader).await.unwrap();
        assert_eq!(
            logs.count(Level::WARN, "datagram channel read failed; routing stopped"),
            1
        );
    }

    /// On Linux the channel is a `SOCK_SEQPACKET` pair, where a read of
    /// zero bytes is the peer's end closing (unix(7), `recv(2)`); no lotse
    /// frame is empty, so the router stops instead of reading again at
    /// once, forever.
    #[tokio::test]
    async fn the_supervisor_closing_its_end_of_the_datagram_channel_stops_the_router() {
        let (logs, _guard) = Logs::capture();
        let (datagrams, demux) = datagram::datagram_pair().unwrap();
        let (events, _rx) = mpsc::channel(1);
        let mut manager = SessionManager::new(
            OwnedFd::from(UdpSocket::bind("127.0.0.1:0").unwrap()),
            None,
            datagrams,
            8,
            Arc::new(FakeClock::default()),
            events,
        )
        .unwrap();
        drop(demux);
        tokio::select! {
            joined = &mut manager.reader => joined.unwrap(),
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("the router still runs"),
        }
        assert_eq!(
            logs.count(
                Level::INFO,
                "datagram channel closed by the supervisor; routing stopped"
            ),
            1
        );
        assert_eq!(manager.stats().malformed.load(Ordering::Relaxed), 0);
    }

    /// The read buffer is one byte longer than the longest frame, so a
    /// frame longer than that, which the socket cuts to the buffer, is
    /// told apart from one of exactly the longest length: the first is
    /// malformed, the second routes.
    #[tokio::test]
    async fn a_frame_longer_than_the_longest_is_malformed_and_one_of_the_longest_routes() {
        let m = managed();
        let addr: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let ufrag = "u".repeat(datagram::MAX_UFRAG_LEN);
        let mut frame = Vec::new();
        let payload = vec![0; datagram::MAX_DATAGRAM_PAYLOAD + 1];
        datagram::encode(&ufrag, addr, addr, &payload, &mut frame);
        assert_eq!(frame.len(), datagram::MAX_FRAME_LEN + 1);
        m.demux.send(&frame).unwrap();
        until(&|| m.manager.stats().malformed.load(Ordering::Relaxed) == 1).await;
        assert_eq!(m.manager.stats().unroutable.load(Ordering::Relaxed), 0);
        datagram::encode(&ufrag, addr, addr, &payload[1..], &mut frame);
        assert_eq!(frame.len(), datagram::MAX_FRAME_LEN);
        m.demux.send(&frame).unwrap();
        until(&|| m.manager.stats().unroutable.load(Ordering::Relaxed) == 1).await;
        assert_eq!(m.manager.stats().malformed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn egress_never_blocks_and_reaches_the_peer() {
        // Non-blocking on the shared description: a full send buffer drops
        // a datagram rather than stalling the runtime thread; the
        // supervisor's receive thread polls, so the flag is harmless there.
        let supervisors = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (datagrams, _peer) = StdUnixDatagram::pair().unwrap();
        let (events, _rx) = mpsc::channel(1);
        let manager = SessionManager::new(
            OwnedFd::from(supervisors.try_clone().unwrap()),
            None,
            OwnedFd::from(datagrams),
            256,
            Arc::new(SystemClock),
            events,
        )
        .unwrap();
        let flags = rustix::fs::fcntl_getfl(&supervisors).unwrap();
        assert!(flags.contains(rustix::fs::OFlags::NONBLOCK), "{flags:?}");
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            manager
                .udp
                .send_to(b"media", peer.local_addr().unwrap())
                .unwrap(),
            5
        );
        let mut buf = [0_u8; 8];
        let (n, from) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(
            (&buf[..n], from),
            (&b"media"[..], supervisors.local_addr().unwrap())
        );
        drop(manager);
    }

    /// Regression for SBX-4: the shared socket stayed at whatever number
    /// `recvmsg` gave it, which no seccomp rule can name; the manager now
    /// sends from the number it is told, the one the filter keeps to
    /// sending.
    #[tokio::test]
    async fn the_shared_socket_moves_to_the_number_the_filter_names() {
        let supervisors = UdpSocket::bind("127.0.0.1:0").unwrap();
        // A number that is free: taken, then given back.
        let at = rustix::io::fcntl_dupfd_cloexec(&supervisors, 100)
            .unwrap()
            .as_raw_fd();
        let (datagrams, _peer) = StdUnixDatagram::pair().unwrap();
        let (events, _rx) = mpsc::channel(1);
        let manager = SessionManager::new(
            OwnedFd::from(supervisors.try_clone().unwrap()),
            Some(at),
            OwnedFd::from(datagrams),
            256,
            Arc::new(SystemClock),
            events,
        )
        .unwrap();
        assert_eq!(manager.udp.as_raw_fd(), at);
        let flags = rustix::fs::fcntl_getfl(&*manager.udp).unwrap();
        assert!(flags.contains(rustix::fs::OFlags::NONBLOCK), "{flags:?}");
        let descriptor = rustix::io::fcntl_getfd(&*manager.udp).unwrap();
        assert!(descriptor.contains(rustix::io::FdFlags::CLOEXEC));
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        manager
            .udp
            .send_to(b"media", peer.local_addr().unwrap())
            .unwrap();
        let mut buf = [0_u8; 8];
        let (n, from) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(
            (&buf[..n], from),
            (&b"media"[..], supervisors.local_addr().unwrap())
        );
    }

    /// The move never replaces a descriptor at the number: a taken one
    /// refuses the socket, and the sessions with it.
    #[tokio::test]
    async fn a_taken_number_refuses_the_shared_socket() {
        let supervisors = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (datagrams, kept) = StdUnixDatagram::pair().unwrap();
        let taken = kept.as_raw_fd();
        let (events, _rx) = mpsc::channel(1);
        let err = SessionManager::new(
            OwnedFd::from(supervisors.try_clone().unwrap()),
            Some(taken),
            OwnedFd::from(datagrams),
            256,
            Arc::new(SystemClock),
            events,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("the shared socket's descriptor {taken} is taken")),
            "{err}"
        );
        // Still the unix socket it was, not replaced by the UDP one.
        assert!(kept.local_addr().unwrap().is_unnamed());
    }

    #[test]
    fn rfc8445_7_2_5_2_1_an_unspecified_bind_sends_from_the_candidates_address() {
        let any_v4: SocketAddr = "0.0.0.0:18556".parse().unwrap();
        let any_v6: SocketAddr = "[::]:18556".parse().unwrap();
        let one: SocketAddr = "192.0.2.1:18556".parse().unwrap();
        assert!(pins_source(Some(any_v4)));
        assert!(pins_source(Some(any_v6)), "the dual-stack socket");
        assert!(
            !pins_source(Some(one)),
            "bound to one address: it is the source"
        );
        assert!(!pins_source(None), "unknown: left to the kernel");
        let host: SocketAddr = "192.0.2.7:18556".parse().unwrap();
        let host_v6: SocketAddr = "[2001:db8::7]:18556".parse().unwrap();
        assert_eq!(egress_source(true, host), Some(host.ip()));
        assert_eq!(egress_source(true, host_v6), Some(host_v6.ip()));
        assert_eq!(egress_source(false, host), None);
        assert_eq!(egress_source(true, any_v4), None, "names no address");
        assert_eq!(egress_source(true, any_v6), None, "names no address");
    }

    #[test]
    fn codes_and_egress_targets_map() {
        assert_eq!(close_code("stream_deleted"), "stream_deleted");
        assert_eq!(close_code("shutting_down"), "shutting_down");
        assert_eq!(close_code("stream_changed"), "stream_changed");
        assert_eq!(close_code("anything"), "session_closed");
        let v4: SocketAddr = "192.0.2.1:5".parse().unwrap();
        let v6: SocketAddr = "[::1]:5".parse().unwrap();
        assert_eq!(
            egress_target(Some(v6), v4),
            "[::ffff:192.0.2.1]:5".parse().unwrap()
        );
        assert_eq!(egress_target(Some(v4), v4), v4);
        assert_eq!(egress_target(None, v6), v6);
        assert!(to_ipc(SessionEvent::Connected).is_none());
        assert!(to_ipc(SessionEvent::KeyframeRequest).is_none());
        assert_eq!(
            to_ipc(SessionEvent::Candidate {
                candidate: "candidate:1".into(),
                mid: None
            }),
            Some(IpcEvent::Candidate {
                candidate: "candidate:1".into(),
                mid: None
            })
        );
        assert_eq!(
            to_ipc(SessionEvent::Closed {
                code: "session_closed",
                message: "bye".into()
            }),
            Some(closed("session_closed", "bye"))
        );
        assert!(matches!(
            to_ipc(SessionEvent::State {
                ice: "new",
                dtls: "new"
            }),
            Some(IpcEvent::State { .. })
        ));
    }
}

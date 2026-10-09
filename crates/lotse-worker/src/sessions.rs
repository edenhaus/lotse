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
use lotse_core::codec::CodecFamily;
use lotse_core::media::MediaPacket;
use lotse_core::negotiate::NegotiationError;
use lotse_core::orientation::Orientation;
use lotse_core::output::OutputFactory;
use lotse_core::registry::Registries;
use lotse_core::session::{
    IceCredentials, SessionEngine, SessionEvent, SessionLimits, SessionOutput, SessionRequest,
    Transport, apply_audio_event, apply_track_event,
};
use lotse_core::skew::AV_SYNC_LOST;
use lotse_core::task::spawn_named;
use lotse_core::track::{Track, TrackEvent, TrackSubscription, Unit};
use lotse_ipc::{SessionEvent as IpcEvent, SessionSpec, datagram};
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::derived::{DerivedTracks, Lease, PickedTrack};
use crate::ice_tcp::Links;
use crate::relay::{Egress, Relays};
use crate::sendmsg;

/// The bounded inbound queue per session:
/// uplink only, so small.
const INBOUND_CAPACITY: usize = 256;

/// How long a session waits for the source to declare its tracks.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

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

/// What the manager tells a session task.
#[derive(Debug)]
enum Control {
    /// A trickled remote candidate; empty is end-of-candidates.
    Candidate(String),
    /// The stream's orientation changed.
    Orientation(Orientation),
    /// Close with this code.
    Close {
        /// The `closed` code.
        code: &'static str,
        /// The message.
        message: String,
    },
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
    /// The task.
    task: JoinHandle<()>,
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
        tracks: Arc<DerivedTracks>,
        mapper: Arc<ClockMapper>,
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
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(spec.ice_ufrag.clone(), inbound_tx.clone());
        let session_id = spec.session_id.clone();
        let ufrag = spec.ice_ufrag.clone();
        let ctx = SessionCtx {
            spec,
            inbound: inbound_tx,
            tracks,
            mapper,
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
            tracing::Instrument::instrument(run_session(ctx, inbound, control), span),
        );
        self.sessions.insert(
            session_id,
            SessionHandle {
                ufrag,
                control: control_tx,
                task,
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

    /// Closes a session.
    pub(crate) fn close(&self, session_id: &str, code: &'static str, message: String) {
        self.send(session_id, Control::Close { code, message });
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
            let _sent = handle.control.try_send(Control::Close {
                code,
                message: message.to_owned(),
            });
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

/// Reads the datagram channel and queues each frame for its session.
async fn route_loop(datagrams: Arc<UnixDatagram>, routes: Routes, stats: Arc<RouterStats>) {
    let mut buf =
        vec![0_u8; datagram::MAX_DATAGRAM_PAYLOAD.saturating_add(datagram::HEADER_LEN + 256)];
    loop {
        let len = match datagrams.recv(&mut buf).await {
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
        SessionEvent::Connected | SessionEvent::KeyframeRequest => None,
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
async fn wait_ready(
    ctx: &mut SessionCtx,
    control: &mut mpsc::Receiver<Control>,
    relays: &mut Vec<PendingRelay>,
) -> Option<(&'static str, String)> {
    let mut ready = ctx.tracks.tracks().ready();
    if *ready.borrow_and_update() {
        return None;
    }
    let timeout = ctx.clock.sleep(READY_TIMEOUT);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            changed = ready.changed() => {
                if changed.is_err() {
                    return Some(("internal_error", "the track set is gone".to_owned()));
                }
                if *ready.borrow_and_update() {
                    return None;
                }
            }
            message = control.recv() => match message {
                Some(Control::Close { code, message }) => return Some((code, message)),
                Some(Control::Candidate(_)) => {}
                Some(Control::Orientation(orientation)) => ctx.spec.orientation = orientation.code(),
                Some(Control::Relay { relayed, server, local, tcp }) => relays.push(PendingRelay { relayed, server, local, tcp }),
                // No relay candidate yet, so no channel on one.
                Some(Control::Channel { relayed, peer, .. }) => {
                    tracing::debug!(%relayed, %peer, "relay channel before the answer; ignored");
                }
                // No answer yet, so no browser knows a TCP candidate.
                Some(Control::Tcp { peer, .. }) => {
                    tracing::debug!(%peer, "ice-tcp connection before the answer; closed");
                }
                None => return Some(("shutting_down", "the worker is stopping".to_owned())),
            },
            () = &mut timeout => {
                return Some(("source_not_live", format!("the source declared no tracks within {} s", READY_TIMEOUT.as_secs())));
            }
        }
    }
}

/// What negotiation picked for a session.
struct Picked {
    /// The video track.
    video: PickedTrack,
    /// The audio track, when one was picked.
    audio: Option<PickedTrack>,
    /// Why no audio was picked although the stream has some.
    warning: Option<NegotiationError>,
}

/// The tracks negotiation picked, with audio if `audio`; a derived one
/// comes leased, so its transcoder runs until the session lets go.
fn pick_tracks(ctx: &SessionCtx, audio: bool) -> Result<Picked, NegotiationError> {
    let requests = ctx.factory.session_tracks(audio);
    let mut picks = ctx.tracks.pick(&requests).into_iter();
    let video = match picks.next() {
        Some(Ok(video)) => video,
        Some(Err(err)) => return Err(err),
        None => {
            return Err(NegotiationError::NoTrack {
                kind: lotse_core::codec::Kind::Video,
            });
        }
    };
    let (audio, warning) = match picks.next() {
        Some(Ok(audio)) => (Some(audio), None),
        Some(Err(err @ NegotiationError::CodecUnsupported { .. })) => (None, Some(err)),
        _ => (None, None),
    };
    Ok(Picked {
        video,
        audio,
        warning,
    })
}

/// What the preamble of a session produced: the engine and the video
/// track it serves.
struct Opened {
    /// The engine.
    engine: Box<dyn SessionEngine>,
    /// The video track.
    video: Arc<Track>,
    /// Its codec family when the session opened; a change of it closes the
    /// session.
    family: CodecFamily,
    /// Its live packets.
    subscription: TrackSubscription,
    /// The audio track's live packets, until it ends.
    audio: Option<AudioSubscription>,
    /// Keeps a derived video track's transcoder running; none today.
    _video_lease: Option<Lease>,
    /// The relay candidates and their channels.
    relays: Relays,
    /// The datagram-channel message to the supervisor being encoded,
    /// reused from frame to frame.
    uplink: Vec<u8>,
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

/// Waits for the tracks, negotiates, opens the engine and reports the
/// answer; `None` when the session ended before that (reported already).
async fn open_session(
    ctx: &mut SessionCtx,
    control: &mut mpsc::Receiver<Control>,
) -> Option<Opened> {
    let mut relays = Vec::new();
    if let Some((code, message)) = wait_ready(ctx, control, &mut relays).await {
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
    let video = picked.video.track;
    let subscription = video.subscribe(Unit::Packets);
    let audio = picked.audio.map(|audio| AudioSubscription {
        family: audio.track.codec().family(),
        subscription: audio.track.subscribe(Unit::Packets),
        track: audio.track,
        lease: audio.lease,
    });
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
        video: video.codec(),
        audio: audio.as_ref().map(|audio| audio.track.codec()),
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
    ctx.emit(IpcEvent::Answer { sdp: answer }).await;
    let mut opened = Opened {
        engine,
        family: video.codec().family(),
        video,
        subscription,
        audio,
        _video_lease: picked.video.lease,
        relays: Relays::default(),
        uplink: Vec::new(),
    };
    for relay in relays {
        add_relay(ctx, &mut opened, relay).await;
    }
    Some(opened)
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
                let gop = opened.video.gop();
                opened.engine.join(ctx.clock.now(), gop.as_deref());
            }
            SessionOutput::Event(SessionEvent::KeyframeRequest) => {
                // An upstream request (ONVIF) is an M6 optimization;
                // until then the next camera keyframe repairs the picture.
                tracing::debug!("keyframe wanted upstream");
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
) {
    let Some(mut opened) = open_session(&mut ctx, &mut control).await else {
        return;
    };
    let local = ctx.udp.local_addr().ok();
    let mut links = Links::new(Arc::clone(&ctx.clock));
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
            datagram = inbound.recv() => {
                let now = ctx.clock.now();
                match datagram {
                    Some(datagram) => opened.engine.handle_datagram(now, datagram.transport, datagram.source, datagram.destination, &datagram.payload),
                    None => opened.engine.close(now, "internal_error", "the router is gone".to_owned()),
                }
            }
            // The reactions to track events are core's, shared by every
            // session output.
            event = opened.subscription.next() => {
                let now = ctx.clock.now();
                let track = opened.video.id();
                apply_track_event(opened.engine.as_mut(), now, opened.family, event, |packet| {
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
                } else if let Some(audio) = opened.audio.as_ref() {
                    let keep = apply_audio_event(opened.engine.as_mut(), now, audio.family, event, |packet| {
                        audio.capture_time(&ctx.mapper, packet)
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
                    Some(Control::Orientation(orientation)) => opened.engine.set_orientation(orientation),
                    Some(Control::Close { code, message }) => opened.engine.close(now, code, message),
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
            () = sleep => opened.engine.handle_timeout(ctx.clock.now()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

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
            Arc::new(lotse_core::clock::SystemClock),
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
            Arc::new(lotse_core::clock::SystemClock),
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
            Arc::new(lotse_core::clock::SystemClock),
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
        assert!(matches!(
            to_ipc(SessionEvent::State {
                ice: "new",
                dtls: "new"
            }),
            Some(IpcEvent::State { .. })
        ));
    }
}

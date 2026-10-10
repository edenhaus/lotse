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
use lotse_core::source::BackchannelSlot;
use lotse_core::task::spawn_named;
use lotse_core::track::{Track, TrackEvent, TrackSubscription, Unit};
use lotse_core::uplink::UplinkTrack;
use lotse_ipc::{SessionEvent as IpcEvent, SessionSpec, datagram};
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::derived::{DerivedTracks, Lease, PickedTrack};
use crate::ice_tcp::Links;
use crate::relay::{Egress, Relays};
use crate::sendmsg;
use crate::talkback;

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
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(spec.ice_ufrag.clone(), inbound_tx.clone());
        let session_id = spec.session_id.clone();
        let ufrag = spec.ice_ufrag.clone();
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
    /// The connection's backchannel slot, when its protocol has one.
    backchannel: Option<BackchannelSlot>,
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
            // The session holds the track set, so its sender outlives this
            // wait and `changed` never fails.
            Ok(()) = ready.changed() => {
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
    /// The track the viewer's talk-back goes out on, from its first
    /// packet ([`talkback`]); closed with the session.
    talkback: Option<UplinkTrack>,
}

/// What a session takes from the connection it opens on.
pub(crate) struct ConnectionMedia {
    /// The connection's tracks, native and derived.
    pub(crate) tracks: Arc<DerivedTracks>,
    /// The connection's clock mapper.
    pub(crate) mapper: Arc<ClockMapper>,
    /// The connection's backchannel slot, when its source protocol can
    /// carry audio back; talk-back is answered from what it holds.
    pub(crate) backchannel: Option<BackchannelSlot>,
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
        // What the source offers now, behind its protocol's gate; never
        // who talks.
        backchannel: ctx
            .backchannel
            .as_ref()
            .and_then(BackchannelSlot::current)
            .map(|handle| handle.codec),
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
        talkback: None,
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
            SessionOutput::Event(SessionEvent::Closed { code, message }) => {
                ctx.finish(code, message).await;
                return None;
            }
            SessionOutput::Event(event) => {
                if let Some(event) = to_ipc(event) {
                    ctx.emit(event).await;
                }
            }
            SessionOutput::Uplink(packet) => talkback::receive(&mut opened.talkback, packet),
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
            // `ctx` holds a sender of the queue, so it never closes.
            Some(datagram) = inbound.recv() => {
                let now = ctx.clock.now();
                opened.engine.handle_datagram(now, datagram.transport, datagram.source, datagram.destination, &datagram.payload);
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
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::collections::VecDeque;
    use std::io::Read as _;
    use std::pin::{Pin, pin};
    use std::task::Poll;

    use lotse_core::clock::FakeClock;
    use lotse_core::codec::{Codec, Kind};
    use lotse_core::media::RtpHeaderFields;
    use lotse_core::output::{OutputShape, TrackRequest};
    use lotse_core::session::{SessionOpenError, SessionStats};
    use lotse_core::source::{TrackPublisher, TrackSet};
    use lotse_core::track::{GopSnapshot, TrackId, TrackLimits};
    use tracing::Level;

    use super::*;
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

    /// An engine that records its calls in its script and returns the
    /// script's outputs, then a timeout an hour after it opened or last
    /// timed out. It takes every relay candidate and video change, and
    /// closes when asked.
    #[derive(Debug)]
    struct Scripted {
        script: Arc<Script>,
        idle: Instant,
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
    }

    /// The `webrtc` output of [`Scripted`] engines: H.264 video, and PCMU
    /// audio when asked.
    #[derive(Debug, Default)]
    struct ScriptedOutput(Arc<Script>);

    impl OutputFactory for ScriptedOutput {
        fn kind(&self) -> &'static str {
            "webrtc"
        }

        fn shape(&self) -> OutputShape {
            OutputShape::Session
        }

        fn session_tracks(&self, audio: bool) -> Vec<TrackRequest> {
            let video = TrackRequest {
                kind: Kind::Video,
                accept: vec![CodecFamily::H264],
                unit: Unit::Packets,
                required: true,
            };
            let audio = audio.then(|| TrackRequest {
                kind: Kind::Audio,
                accept: vec![CodecFamily::Pcmu],
                unit: Unit::Packets,
                required: false,
            });
            std::iter::once(video).chain(audio).collect()
        }

        fn open_session(
            &self,
            request: SessionRequest,
            now: Instant,
        ) -> Result<(Box<dyn SessionEngine>, String), SessionOpenError> {
            self.0
                .call(&format!("open audio={}", request.audio.is_some()));
            self.0
                .call(&format!("open orientation={}", request.orientation.name()));
            if self.0.refuse {
                return Err(SessionOpenError::InvalidSdp("refused by the script".into()));
            }
            let engine = Scripted {
                script: Arc::clone(&self.0),
                idle: now + HOUR,
            };
            Ok((Box::new(engine), "answer".into()))
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
        inbound: mpsc::Sender<Inbound>,
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
        let clock = Arc::new(FakeClock::default());
        let publisher = connection(&clock, audio, ready);
        let script = Arc::new(script);
        let (events_tx, events) = mpsc::channel(64);
        let (control, control_rx) = mpsc::channel(64);
        let (inbound, inbound_rx) = mpsc::channel(INBOUND_CAPACITY);
        let (uplink, _supervisor) = UnixDatagram::pair().unwrap();
        let ctx = SessionCtx {
            spec: spec("s", audio),
            inbound: inbound.clone(),
            tracks: DerivedTracks::new(Arc::clone(publisher.tracks()), Vec::new(), clock.clone()),
            mapper: Arc::new(ClockMapper::new()),
            backchannel: None,
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
            inbound,
        };
        (rig, run_session(ctx, inbound_rx, control_rx))
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
                sdp: "answer".into()
            }]
        );
        assert!(rig.script.called("open audio=true"));

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
                "audio track closed; the session continues with video"
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
        rig.control(Control::Close {
            code: "session_closed",
            message: "bye".into(),
        });
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
                    sdp: "answer".into()
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

    #[tokio::test]
    async fn a_source_that_declares_no_tracks_within_the_ready_timeout_closes_the_session() {
        let (mut rig, session) = session(Script::default(), false, false);
        let mut session = pin!(session);
        assert!(poll_once(&mut session).await.is_pending());
        rig.clock
            .advance(READY_TIMEOUT.checked_sub(Duration::from_millis(1)).unwrap());
        assert!(poll_once(&mut session).await.is_pending());
        rig.clock.advance(Duration::from_millis(1));
        assert!(poll_once(&mut session).await.is_ready());
        assert_eq!(
            rig.events(),
            [closed(
                "source_not_live",
                "the source declared no tracks within 10 s"
            )]
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
        let output = ScriptedOutput::default();
        assert_eq!(output.shape(), OutputShape::Session);
        let engine = Scripted {
            script: Arc::default(),
            idle: rig.clock.now(),
        };
        assert_eq!(engine.stats(), SessionStats::default());
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

    #[tokio::test]
    async fn a_session_id_already_open_is_refused() {
        let mut m = managed();
        m.open("a").await;
        m.open("a").await;
        assert_eq!(
            m.events.recv().await.unwrap(),
            (
                "a".into(),
                closed("internal_error", "session id already open in this worker")
            )
        );
    }

    /// The manager never waits on a session: what its full control queue
    /// cannot take is dropped, an ICE-TCP connection closed.
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

//! The ingest contract: what a protocol crate implements to be a source,
//! and what core hands it for one connection.
//!
//! A source runs one connection (or one publisher, for push sources) until
//! it ends and reports how. Core owns retries, backoff, stall detection,
//! hot swap and clock mapping, so those never depend on the protocol. Track
//! identity across reconnects is core's job: a reconnecting source declares
//! its tracks again and gets the same [`Track`] objects back.

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;

use crate::clock::Clock;
use crate::clock_map::ClockMapper;
use crate::codec::{Codec, Kind};
use crate::ingest::{IngestCounters, IngestStats};
use crate::media::MediaPacket;
use crate::negotiate::TrackInfo;
use crate::runner::ProbeGate;
use crate::source_url::SourceUrl;
use crate::task::{BoxFuture, spawn_named};
use crate::track::{Feeds, Track, TrackId, TrackLimits};

/// How a source protocol obtains media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// The daemon connects to the source (RTSP, RTMP `play`, HTTP).
    Pull,
    /// A publisher connects to the daemon (RTMP `publish`, WHIP). Behaves as
    /// `preload: true`, since a publisher cannot be asked to start.
    Push,
    /// Control logic that yields a spec for another scheme (ONVIF).
    Resolver,
}

/// What a source protocol can do, declared by its factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceCapabilities {
    /// Pull, push or resolver.
    pub direction: Direction,
    /// The protocol can carry audio back to the device.
    pub backchannel: bool,
    /// The protocol or device can be asked for a keyframe.
    pub keyframe_request: bool,
    /// The protocol can hand out a camera-native snapshot URI.
    pub snapshot_uri: bool,
}

/// Why a factory refused a URL and its options. The API reports it as
/// `invalid_request` with the message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceConfigError {
    /// The options do not match the scheme's typed options (unknown field,
    /// bad value, wrong type).
    #[error("invalid options for scheme {scheme}: {message}")]
    InvalidOptions {
        /// The scheme whose options were checked.
        scheme: &'static str,
        /// What was wrong, for humans.
        message: String,
    },
    /// The URL is syntactically fine but not usable by this protocol.
    #[error("invalid url for scheme {scheme}: {message}")]
    InvalidUrl {
        /// The scheme that refused it.
        scheme: &'static str,
        /// What was wrong, for humans.
        message: String,
    },
}

/// One source protocol, registered at startup behind its Cargo feature.
pub trait SourceFactory: fmt::Debug + Send + Sync {
    /// The URL schemes this protocol serves (`rtsp`, `rtsps`; `http`,
    /// `https`; later `rtmp`, `onvif`, ...), lowercase. `info.schemes` is the union over the registry.
    fn schemes(&self) -> &'static [&'static str];

    /// What the protocol can do.
    fn capabilities(&self) -> SourceCapabilities;

    /// The port a URL of `scheme` means when it names none (`554` for
    /// `rtsp`, `322` for `rtsps`), which the supervisor applies when it
    /// resolves the host; `None` for protocols without one.
    fn default_port(&self, _scheme: &str) -> Option<u16> {
        None
    }

    /// Whether a connection of `scheme` needs a loopback TCP listener that
    /// the worker binds before its sandbox and may connect to afterwards:
    /// for a protocol client that only speaks plain TCP behind a local
    /// relay (`rtsp` and `rtsps` through retina and its guard). The
    /// supervisor asks the worker for one; Landlock could not allow the
    /// port once the sandbox is on.
    fn loopback_relay(&self, _scheme: &str) -> bool {
        false
    }

    /// Checks `url` and the untyped `options` against the scheme's typed
    /// options (unknown fields rejected) and builds the source. Pure: no
    /// I/O, so it can run inside `stream/put`.
    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError>;
}

/// A source as the API reports it: protocol, redacted URL, redacted options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDescriptor {
    /// The protocol name, which is also the scheme family (`rtsp`).
    pub protocol: &'static str,
    /// The URL; its `Display` is redacted.
    pub url: SourceUrl,
    /// The options with secrets redacted.
    pub options: serde_json::Value,
}

/// How a keyframe request went. Sources that cannot force a keyframe
/// answer `Unsupported`, and the next camera keyframe repairs the picture.
pub enum KeyframeRequest {
    /// The protocol or device has no way to force a keyframe.
    Unsupported,
    /// The request is on its way; the future resolves when the device
    /// acknowledged it (or refused it).
    Sent(BoxFuture<'static, Result<(), SourceError>>),
}

impl fmt::Debug for KeyframeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "KeyframeRequest::Unsupported",
            Self::Sent(_) => "KeyframeRequest::Sent(..)",
        })
    }
}

/// One validated source. `run` is called once per connection attempt.
pub trait Source: fmt::Debug + Send + Sync {
    /// Protocol, URL and options with every secret redacted.
    fn describe(&self) -> SourceDescriptor;

    /// The options that identify the connection, the options half of the
    /// supervisor's connection key: every receive-relevant option with its
    /// default applied, in one canonical form, so two option objects that
    /// mean the same camera session compare equal however they were
    /// spelled. Options that never change what is received (RTSP
    /// `backchannel`) are left out, so they never open a second camera
    /// session. Not redacted: a differing secret must split the connection,
    /// so the value never reaches a log line or the API.
    fn connection_options(&self) -> serde_json::Value;

    /// Whether the source asks the device for its backchannel, two-way
    /// audio's path to the camera's speaker (RTSP `backchannel`, ONVIF
    /// Streaming Specification §5.3.1, which the RTSP source probes on a
    /// connection of its own): only when its stream opted in, as the
    /// client knows which cameras talk back. Left out of
    /// [`Self::connection_options`], so streams sharing a connection may
    /// differ here: the supervisor has the connection ask iff one of its
    /// sources does. `false` for a protocol without a backchannel.
    fn wants_backchannel(&self) -> bool {
        false
    }

    /// Runs one connection (or one publisher session) until it ends. Must
    /// honor `ctx.cancel` within 100 ms, send the protocol's teardown, and
    /// return a typed exit. Boxed so `dyn Source` stays object-safe.
    fn run(&self, ctx: SourceCtx) -> BoxFuture<'static, SourceExit>;

    /// Asks the device for a keyframe, if the protocol can.
    fn request_keyframe(&self) -> KeyframeRequest {
        KeyframeRequest::Unsupported
    }
}

/// How a connection ended.
#[derive(Debug)]
pub enum SourceExit {
    /// A resolver found the spec to run instead (ONVIF → `rtsp://`).
    Resolved(SourceSpec),
    /// The connection is over, for this reason.
    Ended(SourceError),
}

/// A URL and its options, as `stream/put` carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpec {
    /// The source URL.
    pub url: SourceUrl,
    /// The per-scheme options, untyped until a factory validates them.
    pub options: serde_json::Value,
}

/// Why a connection ended. The API code is the variant's `code()`; the
/// message carries protocol detail (RTSP status and method, TCP error).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// Connecting failed.
    #[error("source unreachable: {0}")]
    Unreachable(String),
    /// The device rejected the credentials.
    #[error("source authentication failed: {0}")]
    AuthFailed(String),
    /// The read deadline or the stall watchdog hit.
    #[error("source timed out: {0}")]
    Timeout(String),
    /// The device violated the protocol or sent something unparseable.
    #[error("source protocol error: {0}")]
    Protocol(String),
    /// The device or publisher closed the stream, or the run was cancelled.
    #[error("source ended: {0}")]
    Ended(String),
}

impl SourceError {
    /// The stable API code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "source_unreachable",
            Self::AuthFailed(_) => "source_auth_failed",
            Self::Timeout(_) => "source_timeout",
            Self::Protocol(_) => "source_protocol_error",
            Self::Ended(_) => "source_ended",
        }
    }

    /// The same error with its message scrubbed of `url`'s secrets
    /// ([`RedactedUrl::scrub`](crate::secret::RedactedUrl::scrub)): for a
    /// message that carries a third-party library's text, which may echo
    /// a URL built from the source URL.
    #[must_use]
    pub fn scrubbed(self, url: &SourceUrl) -> Self {
        let shown = url.redacted();
        match self {
            Self::Unreachable(message) => Self::Unreachable(shown.scrub(&message)),
            Self::AuthFailed(message) => Self::AuthFailed(shown.scrub(&message)),
            Self::Timeout(message) => Self::Timeout(shown.scrub(&message)),
            Self::Protocol(message) => Self::Protocol(shown.scrub(&message)),
            Self::Ended(message) => Self::Ended(shown.scrub(&message)),
        }
    }
}

/// The addresses a source connects to. Resolved by the supervisor: workers
/// have no DNS. The host name stays for the protocol URL and TLS SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeer {
    /// The host as written in the URL, for the protocol's own URL and SNI.
    pub host: String,
    /// The addresses to try, in order, with the port already applied.
    pub addrs: Vec<SocketAddr>,
}

/// A sync hint a protocol provides for the clock mapper. No hints is valid;
/// core then maps by arrival time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncHint {
    /// An RTCP Sender Report (RFC 3550 §6.4.1): the NTP timestamp and the
    /// RTP timestamp of the same instant.
    RtcpSenderReport {
        /// The 64-bit NTP timestamp.
        ntp: u64,
        /// The RTP timestamp in the track's clock.
        rtp_ts: u32,
    },
    /// An MPEG-TS program clock reference, in 27 MHz ticks.
    Pcr {
        /// The PCR value.
        pcr: u64,
    },
}

/// One sync hint with the track it belongs to and when it arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReport {
    /// The track the hint is about.
    pub track: TrackId,
    /// The track's declared clock rate, in which the hint's RTP timestamp
    /// counts; the mapper's fallback slope and its sanity bound.
    pub clock_rate: u32,
    /// The hint.
    pub hint: SyncHint,
    /// When it was read.
    pub arrival: Instant,
}

/// Hints in flight from the source to the clock mapper before the
/// oldest is dropped; hints are rare (an SR every few seconds).
const CLOCK_REPORT_CAPACITY: usize = 32;

/// The source's handle to the connection's clock mapper: hints go in,
/// capture times come out, so the mapping stays in core.
#[derive(Debug, Clone)]
pub struct ClockInput {
    /// Reports go here; the clock mapper drains them.
    tx: mpsc::Sender<ClockReport>,
    /// The mapper, for the capture time of a frame.
    mapper: Arc<ClockMapper>,
}

impl ClockInput {
    /// A handle onto `mapper` and the receiving end its owner drains.
    pub fn channel(mapper: Arc<ClockMapper>) -> (Self, mpsc::Receiver<ClockReport>) {
        let (tx, rx) = mpsc::channel(CLOCK_REPORT_CAPACITY);
        (Self { tx, mapper }, rx)
    }

    /// The capture time of the item with `rtp_ts` that arrived at
    /// `arrival`, on the connection's shared clock.
    pub fn map(&self, track: TrackId, rtp_ts: u32, arrival: Instant) -> Instant {
        self.mapper.map(track, rtp_ts, arrival)
    }

    /// The connection's RTP timeline restarted (a timestamp discontinuity):
    /// the mapper forgets its fits.
    pub fn reset(&self) {
        self.mapper.reset();
    }

    /// Reports a hint. Never waits: when the mapper is behind, the hint is
    /// dropped and `false` returned, since the next one supersedes it.
    pub fn report(&self, report: ClockReport) -> bool {
        self.tx.try_send(report).is_ok()
    }
}

/// The longest a claim of the device's backchannel waits for its session
/// to open, the answer to the claiming offer held meanwhile: under the
/// 10 s the control API gives a re-offer's answer, so a camera that never
/// answers is declined in that answer, not timed out as a failed
/// re-offer. A source bounds its handshake by the lesser of this and its
/// own connect timeout; the worker bounds the wait by this.
pub const BACKCHANNEL_OPEN_LIMIT: Duration = Duration::from_secs(8);

/// Why the device's backchannel session could not be opened, or ended
/// while a talker held it: the device's status when it answered with one
/// (RTSP's on `DESCRIBE`, `SETUP` or `PLAY`), else `None` (a connection
/// that failed or closed, a timeout), and what happened, for humans.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct BackchannelRefused {
    /// The device's status code, when it refused with one.
    pub status: Option<u16>,
    /// What happened.
    pub message: String,
}

/// Opens the device's backchannel in a session of its own (RTSP: ONVIF
/// Streaming Specification §5.3), for the talker that claimed it.
/// Offered by a source whose probe found a backchannel
/// ([`BackchannelOffer`]); one opener serves every claim of the offer.
pub trait BackchannelOpener: fmt::Debug + Send + Sync {
    /// Opens the session: resolves once the device takes packets (RTSP:
    /// `PLAY` answered), or with why not. Dropping the future before it
    /// resolves abandons the handshake and closes what it opened.
    fn open(&self) -> BoxFuture<'static, Result<BackchannelSession, BackchannelRefused>>;
}

/// A device's backchannel as a source's probe found it: the codec the
/// device takes, the audio one packet carries, and the way to open it. No
/// session is open while it is offered; a claim opens one
/// ([`BackchannelOpener::open`]).
#[derive(Debug, Clone)]
pub struct BackchannelOffer {
    /// The codec the device accepts.
    pub codec: Codec,
    /// The audio one packet carries, as the device asks for it (RTSP: the
    /// backchannel media's `a=ptime`, RFC 8866 §6.4), else
    /// [`BackchannelOffer::DEFAULT_FRAME`]. The talk-back transcoder
    /// frames G.711 to it; a forwarded packet keeps the sender's.
    pub frame: Duration,
    /// Opens the device's backchannel session.
    pub opener: Arc<dyn BackchannelOpener>,
}

impl BackchannelOffer {
    /// 20 ms, RFC 3551 §4.5's default packetization interval: the frame
    /// of a device that names none.
    pub const DEFAULT_FRAME: Duration = Duration::from_millis(20);
}

/// One open session of the device's backchannel, held by its talker:
/// packets sent here reach the device in its codec and frame. Dropping it
/// closes the session (RTSP: `TEARDOWN`, then the connection closes).
#[derive(Debug)]
pub struct BackchannelSession {
    /// The codec the device takes on this session.
    pub codec: Codec,
    /// The audio one packet carries.
    pub frame: Duration,
    /// Where uplink packets go. Never waited on: a full queue drops.
    pub sender: mpsc::Sender<MediaPacket>,
    /// Resolves with why, should the session end on the device's side (a
    /// lost connection, a refused keepalive) while it is held; never
    /// once the holder dropped it.
    pub lost: oneshot::Receiver<BackchannelRefused>,
    /// Ends the session when dropped.
    _close: DropGuard,
}

impl BackchannelSession {
    /// A session in `codec` and `frame` fed through `sender`, which
    /// reports its loss on `lost` and ends once `close` is cancelled: when
    /// the session is dropped.
    pub fn new(
        codec: Codec,
        frame: Duration,
        sender: mpsc::Sender<MediaPacket>,
        lost: oneshot::Receiver<BackchannelRefused>,
        close: CancellationToken,
    ) -> Self {
        Self {
            codec,
            frame,
            sender,
            lost,
            _close: close.drop_guard(),
        }
    }
}

/// The tasks of the backchannel sessions opened from a worker's offers,
/// tracked so that the worker's shutdown waits for each to close its
/// session on the device (RTSP: its `TEARDOWN`, RFC 2326 §10.7, RFC 7826
/// §13.4) instead of its runtime dropping them halfway. Clones track
/// together; a default one tracks on its own, for a slot outside a
/// worker. A source spawns its session's task here
/// ([`BackchannelTasks::spawn`]), the claim's drop closes the session, and
/// the task ends once the device's side is closed.
#[derive(Debug, Clone, Default)]
pub struct BackchannelTasks(TaskTracker);

impl BackchannelTasks {
    /// Spawns `future`, one backchannel session's task, under `name`,
    /// tracked until it ends.
    pub fn spawn<F>(&self, name: &'static str, future: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        spawn_named(name, self.0.track_future(future))
    }

    /// How many of the tracked tasks still run.
    pub fn running(&self) -> usize {
        self.0.len()
    }

    /// Resolves once every tracked task ended, a task spawned meanwhile
    /// included. The caller bounds the wait.
    pub async fn ended(&self) {
        self.0.close();
        self.0.wait().await;
    }
}

/// What a slot holds: the backchannel the last probe found, and whether a
/// probe runs now.
#[derive(Debug, Clone, Default)]
struct Probed {
    /// The backchannel found, until a probe finds none.
    offer: Option<BackchannelOffer>,
    /// A probe runs: with nothing offered before it, a claim waits for
    /// its result ([`BackchannelSlot::awaits_probe`]).
    probing: bool,
}

/// The slot a source fills when its probe found the device's backchannel,
/// and where the probe waits for a connect permit. Shared with the
/// connection, which arbitrates the talker and opens the backchannel for
/// it. An offer stands until a probe finds none: a reconnect of the
/// source keeps it, and the next probe replaces it.
#[derive(Debug, Clone, Default)]
pub struct BackchannelSlot {
    /// What the probes found.
    probed: Arc<watch::Sender<Probed>>,
    /// Where a probe waits for a connect permit; [`ProbeGate::default`]
    /// lets every probe through, for a source outside a worker.
    probes: ProbeGate,
    /// Where the tasks of the sessions opened from its offers are
    /// tracked: the worker's, or one of its own.
    tasks: BackchannelTasks,
}

impl BackchannelSlot {
    /// A slot whose probes wait at `probes` for their connect permit.
    pub fn gated(probes: ProbeGate) -> Self {
        Self {
            probed: Arc::default(),
            probes,
            tasks: BackchannelTasks::default(),
        }
    }

    /// This slot, the tasks of the sessions opened from its offers
    /// tracked in `tasks`: the worker's, which its shutdown waits for.
    #[must_use]
    pub fn tracked(self, tasks: BackchannelTasks) -> Self {
        Self { tasks, ..self }
    }

    /// Where the source's probe waits for its connect permit.
    pub const fn probes(&self) -> &ProbeGate {
        &self.probes
    }

    /// Where the opener of an offer spawns its sessions' tasks.
    pub const fn tasks(&self) -> &BackchannelTasks {
        &self.tasks
    }

    /// A probe started: claims wait for its result unless an offer
    /// stands ([`BackchannelSlot::awaits_probe`]).
    pub fn probing(&self) {
        self.probed.send_modify(|probed| probed.probing = true);
    }

    /// The probe found `offer`: offered (or replaced).
    pub fn offer(&self, offer: BackchannelOffer) {
        self.probed.send_modify(|probed| {
            probed.offer = Some(offer);
            probed.probing = false;
        });
    }

    /// The probe found none, or failed: withdrawn.
    pub fn withdraw(&self) {
        self.probed.send_modify(|probed| {
            probed.offer = None;
            probed.probing = false;
        });
    }

    /// The probe ended without a result (the source's attempt ended
    /// first): what was offered before stands.
    pub fn abandon_probe(&self) {
        self.probed.send_modify(|probed| probed.probing = false);
    }

    /// The offered backchannel, if any.
    pub fn current(&self) -> Option<BackchannelOffer> {
        self.probed.borrow().offer.clone()
    }

    /// Whether a probe runs now.
    pub fn is_probing(&self) -> bool {
        self.probed.borrow().probing
    }

    /// Whether a claim waits for the probe ([`BackchannelSlot::settled`]):
    /// one runs, and nothing was offered before it. An offer a reconnect
    /// kept is claimed at once while the new attempt's probe runs, which
    /// may wait for its connect permit a long time
    /// (`sources.connect_concurrency`): the claim's open asks the device
    /// again anyway.
    pub fn awaits_probe(&self) -> bool {
        let probed = self.probed.borrow();
        probed.probing && probed.offer.is_none()
    }

    /// The offered backchannel once no probe runs: at once without one,
    /// else when it found one, none, or ended without a result.
    pub async fn settled(&self) -> Option<BackchannelOffer> {
        let mut probed = self.probed.subscribe();
        // The slot holds the sender, so the wait never fails.
        let settled = probed.wait_for(|probed| !probed.probing).await;
        settled.ok().and_then(|probed| probed.offer.clone())
    }
}

/// The native tracks of one source connection. Declared by the source,
/// stable across reconnects, read by every sink of the connection. Derived
/// tracks (a transcoder's output) are kept by their owner beside the set,
/// not in it: the runner watches every track here for stalls and starts
/// their epochs together, and a derived track's are its transcoder's.
#[derive(Debug)]
pub struct TrackSet {
    /// The bounds every track enforces.
    limits: TrackLimits,
    /// The instant tracks time their activity from.
    origin: Instant,
    /// The tracks, in declaration order. Control-plane lock only.
    tracks: RwLock<Vec<Arc<Track>>>,
    /// `true` once the source has declared every track of a connection.
    ready: watch::Sender<bool>,
    /// What the connection lost or refused before its tracks.
    ingest: Arc<IngestCounters>,
    /// Which source feeds the live tracks, shared with the staging sets.
    feeds: Arc<Feeds>,
    /// The source this set is written by: 0 for the live set, else the
    /// standby's tag.
    tag: u8,
    /// The live set a staging set forwards into.
    live: Option<Arc<Self>>,
}

impl TrackSet {
    /// An empty set whose tracks will enforce `limits` and time their
    /// activity from `origin` (the clock's reading at creation).
    pub fn new(limits: TrackLimits, origin: Instant) -> Arc<Self> {
        let (ready, _rx) = watch::channel(false);
        Arc::new_cyclic(|weak| Self {
            limits,
            origin,
            tracks: RwLock::new(Vec::new()),
            ready,
            ingest: Arc::default(),
            feeds: Arc::new(Feeds::new(weak.clone())),
            tag: 0,
            live: None,
        })
    }

    /// A set for a standby source of `live`'s connection: its tracks
    /// forward into their live counterparts once it is armed and switched
    /// to ([`Feeds`]); until then its writes are dropped. It counts into
    /// the connection's ingest counters, and its own readiness is the
    /// standby's.
    pub fn staging(live: &Arc<Self>) -> Arc<Self> {
        let (ready, _rx) = watch::channel(false);
        Arc::new(Self {
            limits: live.limits,
            origin: live.origin,
            tracks: RwLock::new(Vec::new()),
            ready,
            ingest: Arc::clone(&live.ingest),
            feeds: Arc::clone(&live.feeds),
            tag: live.feeds.next_tag(),
            live: Some(Arc::clone(live)),
        })
    }

    /// Which source feeds the connection's tracks.
    pub fn feeds(&self) -> &Arc<Feeds> {
        &self.feeds
    }

    /// Whether this set's source is the active feed.
    pub fn is_active(&self) -> bool {
        self.feeds.active() == self.tag
    }

    /// Arms this staging set: the connection switches to it at its video's
    /// first keyframe. The live set itself cannot be armed.
    pub fn arm_switch(&self) {
        if self.live.is_some() {
            self.feeds.arm(self.tag, &self.tracks());
        }
    }

    /// Takes this staging set out of the switch, if it was armed.
    pub fn disarm(&self) {
        self.feeds.disarm(self.tag);
    }

    /// Sets this set's readiness directly.
    pub(crate) fn mark_ready(&self, ready: bool) {
        self.ready.send_replace(ready);
    }

    /// Sets the readiness as this set's source reports it: a staging set's
    /// own, mirrored onto the live set while it is the active feed; the
    /// live set's own only while its source is.
    fn set_ready(&self, ready: bool) {
        match &self.live {
            Some(live) => {
                self.mark_ready(ready);
                if self.is_active() {
                    live.mark_ready(ready);
                }
            }
            None => {
                if self.is_active() {
                    self.mark_ready(ready);
                }
            }
        }
    }

    /// The bounds every track of the set enforces, for a source that sizes
    /// its own buffers by them before it declares a track (a
    /// demultiplexer's largest frame).
    pub const fn limits(&self) -> TrackLimits {
        self.limits
    }

    /// What the connection lost or refused before its tracks, over every
    /// attempt so far.
    pub fn ingest(&self) -> IngestStats {
        self.ingest.snapshot()
    }

    /// Every track, in declaration order.
    pub fn tracks(&self) -> Vec<Arc<Track>> {
        self.tracks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The track with `id`, if declared.
    pub fn get(&self, id: TrackId) -> Option<Arc<Track>> {
        self.tracks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|track| track.id() == id)
            .cloned()
    }

    /// The native tracks as negotiation sees them.
    pub fn infos(&self) -> Vec<TrackInfo> {
        self.tracks()
            .iter()
            .map(|track| TrackInfo {
                id: track.id(),
                codec: track.codec(),
                derived_from: None,
            })
            .collect()
    }

    /// Whether the current connection has declared every track. Changes
    /// are observed through the receiver.
    pub fn ready(&self) -> watch::Receiver<bool> {
        self.ready.subscribe()
    }

    /// Marks the set not ready, when a connection ends.
    pub fn reset_ready(&self) {
        self.set_ready(false);
    }

    /// Starts a new epoch on every track together: epochs are per source,
    /// not per track.
    pub fn start_epoch(&self) {
        for track in self.tracks() {
            track.start_epoch();
        }
    }

    /// Tells every track's subscribers the source is gone or back.
    pub fn set_source_lost(&self, lost: bool) {
        for track in self.tracks() {
            track.set_source_lost(lost);
        }
    }

    /// A publisher for one connection attempt.
    pub fn publisher(self: &Arc<Self>) -> TrackPublisher {
        TrackPublisher {
            set: Arc::clone(self),
            declared: Vec::new(),
        }
    }

    /// Returns the existing track `id` with its codec updated, or declares
    /// a new one: a staging set's forwards into the live track of that id,
    /// if there is one.
    pub(crate) fn declare(&self, id: TrackId, codec: Codec, clock_rate: u32) -> Arc<Track> {
        if let Some(existing) = self.get(id) {
            if existing.clock_rate() != clock_rate {
                tracing::warn!(
                    track = %id,
                    was = existing.clock_rate(),
                    now = clock_rate,
                    "track clock rate changed on reconnect; keeping the original"
                );
            }
            existing.set_codec(codec);
            return existing;
        }
        tracing::info!(track = %id, codec = codec.name(), clock_rate, tag = self.tag, "track declared");
        let forward_to = self.live.as_ref().and_then(|live| live.get(id));
        let track = Arc::new(Track::with_feeds(
            id,
            codec,
            clock_rate,
            self.limits,
            self.origin,
            Arc::clone(&self.feeds),
            self.tag,
            forward_to,
        ));
        self.tracks
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&track));
        track
    }
}

/// What a source uses to declare tracks and signal readiness and
/// discontinuities for one connection attempt. Media goes straight to the
/// [`Track`]s it returns.
#[derive(Debug)]
pub struct TrackPublisher {
    /// The connection's tracks.
    set: Arc<TrackSet>,
    /// The ids this attempt has declared, to number the next one.
    declared: Vec<TrackId>,
}

impl TrackPublisher {
    /// Declares the next track of `kind`: the first video declared is `v0`,
    /// the first audio `a0`. On a reconnect the existing track comes back,
    /// with `TrackChanged` if the codec differs. Must be called before the
    /// first packet of that track.
    pub fn declare(&mut self, kind: Kind, codec: Codec, clock_rate: u32) -> Arc<Track> {
        let index = self.declared.iter().filter(|id| id.kind() == kind).count();
        let id = TrackId::new(kind, u8::try_from(index).unwrap_or(u8::MAX));
        self.declared.push(id);
        self.set.declare(id, codec, clock_rate)
    }

    /// Every track is declared; the connection is live.
    pub fn ready(&self) {
        self.set.set_ready(true);
    }

    /// The source saw a timestamp reset or a sequence-header change: a new
    /// epoch for all tracks together.
    pub fn discontinuity(&self) {
        self.set.start_epoch();
    }

    /// The connection's tracks.
    pub const fn tracks(&self) -> &Arc<TrackSet> {
        &self.set
    }

    /// The connection's ingest counters, for the source's tasks to count
    /// losses and refusals in.
    pub fn ingest(&self) -> Arc<IngestCounters> {
        Arc::clone(&self.set.ingest)
    }
}

/// What core hands a source for one connection.
#[derive(Debug)]
pub struct SourceCtx {
    /// Where to connect (pull) or which publisher to expect (push).
    pub peer: ResolvedPeer,
    /// Declares tracks and signals readiness and discontinuities.
    pub tracks: TrackPublisher,
    /// Reports sync hints and maps arrivals to capture times.
    pub clock: ClockInput,
    /// The time source, for deadlines and arrival stamps.
    pub time: Arc<dyn Clock>,
    /// Where the source offers the device's backchannel its probe found,
    /// if the protocol has one, and where the probe waits for its connect
    /// permit.
    pub backchannel: BackchannelSlot,
    /// Cancelled when core wants the connection to end; honor within 100 ms.
    pub cancel: CancellationToken,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::clock::SystemClock;
    use crate::codec::CodecFamily;
    use crate::media::{MediaFrame, MediaTime, RtpHeaderFields};
    use crate::test_logs::Logs;
    use crate::track::{TrackEvent, Unit};

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }
    }

    fn h265() -> Codec {
        Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        }
    }

    fn packet(seq: u16, keyframe_start: bool) -> MediaPacket {
        MediaPacket {
            arrival: SystemClock.now(),
            rtp: RtpHeaderFields {
                pt: 96,
                seq,
                ts: u32::from(seq) * 3000,
                marker: false,
                ssrc: 1,
            },
            frame_start: keyframe_start,
            keyframe_start,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0_u8; 10][..]),
        }
    }

    fn frame(keyframe: bool) -> MediaFrame {
        let now = SystemClock.now();
        MediaFrame {
            ts: MediaTime::ZERO,
            wallclock: now,
            arrival: now,
            keyframe,
            discontinuity: false,
            epoch: 0,
            payload: bytes::Bytes::from(vec![0; 10]),
        }
    }

    async fn next_packet(sub: &mut crate::track::TrackSubscription) -> (u16, u32) {
        crate::let_assert!(Some(TrackEvent::Packet(packet)) = sub.next().await);
        (packet.rtp.seq, packet.epoch)
    }

    /// The standby with tag 1 and its two tracks was armed and switched
    /// to, each logged once.
    fn assert_armed_and_switched_once(logs: &Logs) {
        for message in [
            "standby source armed; switching at its next keyframe",
            "source switched: the standby feeds the tracks",
        ] {
            let lines = logs.lines(tracing::Level::INFO, message);
            assert_eq!(lines.len(), 1, "{message}");
            assert_eq!(lines[0].fields, " tag=1 tracks=2", "{message}");
        }
    }

    #[tokio::test]
    async fn a_standby_source_switches_in_at_its_first_keyframe_and_the_old_one_is_dropped() {
        let (logs, _guard) = Logs::capture();
        let live = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let mut old = live.publisher();
        let v0 = old.declare(Kind::Video, h264(), 90_000);
        let a0 = old.declare(Kind::Audio, Codec::Pcmu, 8_000);
        old.ready();
        let mut video = v0.subscribe(Unit::Packets);
        let mut audio = a0.subscribe(Unit::Packets);
        let mut switched = live.feeds().switched();
        assert_eq!(*switched.borrow_and_update(), 0);

        // The standby declares into a staging set: other track objects,
        // whose writes go nowhere until the set is armed and switched to,
        // but which still time its stall watchdog.
        let staging = TrackSet::staging(&live);
        assert!(!staging.is_active() && live.is_active());
        let mut standby = staging.publisher();
        let sv0 = standby.declare(Kind::Video, h265(), 90_000);
        let sa0 = standby.declare(Kind::Audio, Codec::Pcma, 8_000);
        assert!(!Arc::ptr_eq(&sv0, &v0));
        sv0.publish_packet(packet(1, true));
        assert_eq!(v0.stats().packets, 0);
        assert!(sv0.last_activity().is_some());
        // Its readiness is its own; the live set's stays the old source's.
        standby.ready();
        assert!(*staging.ready().borrow() && *live.ready().borrow());
        staging.reset_ready();
        assert!(!*staging.ready().borrow() && *live.ready().borrow());
        standby.ready();
        // Armed: audio and delta frames before its first keyframe are
        // dropped.
        staging.arm_switch();
        sa0.publish_packet(packet(1, false));
        sv0.publish_packet(packet(2, false));
        assert_eq!((v0.stats().packets, a0.stats().packets), (0, 0));
        // The keyframe switches: a new epoch on every live track, the
        // standby's codecs on them, then the keyframe itself.
        sv0.publish_packet(packet(3, true));
        assert_eq!(*switched.borrow_and_update(), 1);
        assert_armed_and_switched_once(&logs);
        assert!(staging.is_active() && !live.is_active());
        assert_eq!(live.feeds().active(), 1);
        assert_eq!(
            video.next().await,
            Some(TrackEvent::EpochStart { epoch: 1 })
        );
        assert_eq!(
            video.next().await,
            Some(TrackEvent::TrackChanged(Arc::new(h265())))
        );
        assert_eq!(next_packet(&mut video).await, (3, 1));
        assert_eq!(
            audio.next().await,
            Some(TrackEvent::EpochStart { epoch: 1 })
        );
        assert_eq!(
            audio.next().await,
            Some(TrackEvent::TrackChanged(Arc::new(Codec::Pcma)))
        );
        assert_eq!(v0.codec().family(), CodecFamily::H265);
        // The old source's writes are dropped now; the standby's reach the
        // live tracks and count there.
        v0.publish_packet(packet(9, false));
        assert_eq!(v0.stats().packets, 1);
        sa0.publish_packet(packet(2, false));
        assert_eq!((a0.stats().packets, sa0.stats().packets), (1, 0));
        assert_eq!(next_packet(&mut audio).await, (2, 1));
        // Epochs, source loss and codec changes of the standby reach the
        // live tracks; the old source's no longer do.
        live.start_epoch();
        old.discontinuity();
        assert_eq!(v0.epoch(), 1);
        staging.start_epoch();
        assert_eq!((v0.epoch(), a0.epoch(), sv0.epoch()), (2, 2, 0));
        assert_eq!(sv0.start_epoch(), 3);
        live.set_source_lost(true);
        staging.set_source_lost(true);
        v0.set_codec(h264());
        assert_eq!(v0.codec().family(), CodecFamily::H265);
        sv0.set_codec(Codec::Mjpeg);
        assert_eq!(v0.codec().family(), CodecFamily::Mjpeg);
        assert_eq!(
            video.next().await,
            Some(TrackEvent::EpochStart { epoch: 2 })
        );
        assert_eq!(
            video.next().await,
            Some(TrackEvent::EpochStart { epoch: 3 })
        );
        assert_eq!(video.next().await, Some(TrackEvent::SourceLost));
        assert_eq!(
            video.next().await,
            Some(TrackEvent::TrackChanged(Arc::new(Codec::Mjpeg)))
        );
        // The standby's connection drops reset the live set's readiness;
        // the old source's no longer touch it.
        staging.reset_ready();
        assert!(!*live.ready().borrow());
        standby.ready();
        assert!(*live.ready().borrow());
        live.reset_ready();
        assert!(*live.ready().borrow(), "the old source's reset is ignored");
        // The side branch forwards too, and so does the browser-limit count.
        assert!(sv0.publish_frame(frame(true)));
        assert!(v0.gop().is_some() && sv0.gop().is_none());
        assert!(
            !v0.publish_frame(frame(true)),
            "the old source's frame is dropped"
        );
        assert_eq!(v0.stats().frames, 1);
        sv0.count_frame_over_browser_limit();
        v0.count_frame_over_browser_limit();
        assert_eq!(v0.stats().frames_over_browser_limit, 1);
        // The ingest counters are the connection's.
        standby.ingest().count_lost(1);
        assert_eq!(live.ingest().packets_lost, 1);
    }

    #[tokio::test]
    async fn a_standby_without_video_switches_at_its_first_item_and_declares_what_the_live_set_lacks()
     {
        let live = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let v0 = live.publisher().declare(Kind::Video, h264(), 90_000);
        let staging = TrackSet::staging(&live);
        let mut standby = staging.publisher();
        let sa0 = standby.declare(Kind::Audio, Codec::Pcmu, 8_000);
        standby.ready();
        staging.arm_switch();
        sa0.publish_packet(packet(1, false));
        assert!(staging.is_active());
        let a0 = live
            .get(TrackId::new(Kind::Audio, 0))
            .expect("declared at the switch");
        assert_eq!(
            (a0.stats().packets, a0.codec().family()),
            (1, CodecFamily::Pcmu)
        );
        assert_eq!((v0.epoch(), live.tracks().len()), (1, 2));
        sa0.publish_packet(packet(2, false));
        assert_eq!(a0.stats().packets, 2);
        // A second standby forwards into the live tracks as well, the
        // ones the first standby brought included; the first's writes are
        // dropped.
        let second = TrackSet::staging(&live);
        let mut publisher = second.publisher();
        let tv0 = publisher.declare(Kind::Video, h265(), 90_000);
        let ta0 = publisher.declare(Kind::Audio, Codec::Pcma, 8_000);
        assert!(!tv0.publish_frame(frame(true)));
        second.arm_switch();
        assert!(
            tv0.publish_frame(frame(true)),
            "a frames-only video source switches at its first keyframe"
        );
        assert_eq!(live.feeds().active(), 2);
        ta0.publish_packet(packet(3, false));
        sa0.publish_packet(packet(4, false));
        assert_eq!((a0.stats().packets, v0.stats().frames), (3, 1));
        assert_eq!(a0.codec().family(), CodecFamily::Pcma);
    }

    #[tokio::test]
    async fn a_disarmed_standby_does_not_switch_and_the_live_set_cannot_be_armed() {
        let live = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let v0 = live.publisher().declare(Kind::Video, h264(), 90_000);
        let staging = TrackSet::staging(&live);
        let sv0 = staging.publisher().declare(Kind::Video, h265(), 90_000);
        // A codec the standby reports before the switch is kept for it.
        sv0.set_codec(Codec::Mjpeg);
        assert_eq!(sv0.codec().family(), CodecFamily::Mjpeg);
        staging.arm_switch();
        staging.disarm();
        sv0.publish_packet(packet(1, true));
        assert!(live.is_active());
        assert_eq!(v0.stats().packets, 0);
        // Disarming another tag leaves the armed one.
        staging.arm_switch();
        TrackSet::staging(&live).disarm();
        live.arm_switch();
        live.disarm();
        sv0.publish_packet(packet(2, true));
        assert!(staging.is_active());
        assert_eq!(v0.codec().family(), CodecFamily::Mjpeg);
        assert_eq!(v0.stats().packets, 1);
    }

    #[tokio::test]
    async fn tracks_keep_their_identity_across_reconnects() {
        let (logs, _guard) = Logs::capture();
        let set = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let mut ready = set.ready();
        assert!(!*ready.borrow_and_update());

        let mut first = set.publisher();
        let v0 = first.declare(Kind::Video, h264(), 90_000);
        let a0 = first.declare(Kind::Audio, Codec::Pcmu, 8_000);
        let a1 = first.declare(Kind::Audio, Codec::Opus { channels: 1 }, 48_000);
        assert_eq!(v0.id().to_string(), "v0");
        assert_eq!(a0.id().to_string(), "a0");
        assert_eq!(a1.id().to_string(), "a1");
        first.ready();
        assert!(ready.changed().await.is_ok());
        assert!(*ready.borrow_and_update());
        assert_eq!(set.tracks().len(), 3);
        assert_eq!(set.infos().len(), 3);
        assert!(set.get(TrackId::new(Kind::Audio, 2)).is_none());

        let mut sub = v0.subscribe(Unit::Packets);
        set.reset_ready();
        assert!(!*set.ready().borrow());

        let mut second = set.publisher();
        let again = second.declare(Kind::Video, Codec::Mjpeg, 90_000);
        assert!(Arc::ptr_eq(&v0, &again), "same track object");
        assert_eq!(again.codec().family(), CodecFamily::Mjpeg);
        assert_eq!(
            sub.next().await,
            Some(TrackEvent::TrackChanged(Arc::new(Codec::Mjpeg)))
        );
        let audio_again = second.declare(Kind::Audio, Codec::Pcmu, 16_000);
        assert!(Arc::ptr_eq(&a0, &audio_again));
        assert_eq!(audio_again.clock_rate(), 8_000, "clock rate is kept");
        let changed = logs.lines(
            tracing::Level::WARN,
            "track clock rate changed on reconnect; keeping the original",
        );
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].fields, " track=a0 was=8000 now=16000");
        assert_eq!(set.tracks().len(), 3);
        assert!(Arc::ptr_eq(second.tracks(), &set));
    }

    #[test]
    fn a_standby_whose_live_set_is_gone_still_switches_its_tag() {
        let live = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let feeds = Arc::clone(live.feeds());
        let staging = TrackSet::staging(&live);
        let sv0 = staging.publisher().declare(Kind::Video, h265(), 90_000);
        staging.arm_switch();
        // The connection is torn down while the standby's source still
        // holds its track: the switch has no live set to declare into.
        drop((staging, live));
        sv0.publish_packet(packet(1, true));
        assert_eq!(feeds.active(), 1);
        assert_eq!(sv0.stats().packets, 1, "no live track to forward to");
    }

    #[tokio::test]
    async fn discontinuity_and_source_loss_reach_every_track() {
        let set = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let mut publisher = set.publisher();
        let v0 = publisher.declare(Kind::Video, h264(), 90_000);
        let a0 = publisher.declare(Kind::Audio, Codec::Pcma, 8_000);
        let mut video = v0.subscribe(Unit::Packets);
        let mut audio = a0.subscribe(Unit::Packets);

        publisher.discontinuity();
        set.set_source_lost(true);
        for sub in [&mut video, &mut audio] {
            assert_eq!(sub.next().await, Some(TrackEvent::EpochStart { epoch: 1 }));
            assert_eq!(sub.next().await, Some(TrackEvent::SourceLost));
        }
        assert_eq!(v0.epoch(), 1);
        assert_eq!(a0.epoch(), 1);
    }

    #[test]
    fn the_set_hands_out_the_limits_its_tracks_enforce() {
        let limits = TrackLimits {
            max_frame_bytes: 7,
            ..TrackLimits::default()
        };
        let set = TrackSet::new(limits, SystemClock.now());
        assert_eq!(set.limits(), limits);
        assert_eq!(
            set.publisher()
                .declare(Kind::Video, h264(), 90_000)
                .limits(),
            set.limits()
        );
    }

    #[test]
    fn every_attempt_counts_into_the_connections_ingest_stats() {
        let set = TrackSet::new(TrackLimits::default(), SystemClock.now());
        set.publisher().ingest().count_lost(2);
        set.publisher().ingest().count_rejected();
        let stats = set.ingest();
        assert_eq!((stats.packets_lost, stats.datagrams_rejected), (2, 1));
    }

    #[test]
    fn clock_input_reset_forgets_the_mappers_fits() {
        let mapper = Arc::new(ClockMapper::new());
        let (input, _rx) = ClockInput::channel(Arc::clone(&mapper));
        let v0 = TrackId::new(Kind::Video, 0);
        mapper.ingest(ClockReport {
            track: v0,
            clock_rate: 90_000,
            hint: SyncHint::RtcpSenderReport {
                ntp: 1 << 32,
                rtp_ts: 0,
            },
            arrival: SystemClock.now(),
        });
        assert_eq!(mapper.mode(v0), crate::clock_map::SyncMode::SenderReports);
        input.reset();
        assert_eq!(mapper.mode(v0), crate::clock_map::SyncMode::Arrival);
    }

    #[test]
    fn clock_input_drops_hints_when_the_mapper_is_behind() {
        let (input, mut rx) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let now = SystemClock.now();
        assert_eq!(input.map(TrackId::new(Kind::Video, 0), 5, now), now);
        let report = ClockReport {
            track: TrackId::new(Kind::Video, 0),
            clock_rate: 90_000,
            hint: SyncHint::RtcpSenderReport { ntp: 1, rtp_ts: 2 },
            arrival: SystemClock.now(),
        };
        for _ in 0..CLOCK_REPORT_CAPACITY {
            assert!(input.report(report));
        }
        assert!(!input.report(report), "full: dropped, never blocks");
        assert_eq!(rx.try_recv().unwrap(), report);
        assert!(input.report(ClockReport {
            hint: SyncHint::Pcr { pcr: 3 },
            ..report
        }));
    }

    /// An opener whose session never opens.
    #[derive(Debug)]
    struct Pending;

    impl BackchannelOpener for Pending {
        fn open(&self) -> BoxFuture<'static, Result<BackchannelSession, BackchannelRefused>> {
            Box::pin(std::future::pending())
        }
    }

    fn pcmu() -> BackchannelOffer {
        BackchannelOffer {
            codec: Codec::Pcmu,
            frame: BackchannelOffer::DEFAULT_FRAME,
            opener: Arc::new(Pending),
        }
    }

    #[tokio::test]
    async fn backchannel_slot_is_probed_offered_read_and_withdrawn() {
        let slot = BackchannelSlot::default();
        assert!(slot.current().is_none());
        assert!(
            bounded(slot.settled()).await.is_none(),
            "no probe: settled at once"
        );
        slot.offer(pcmu());
        assert_eq!(slot.current().unwrap().codec, Codec::Pcmu);
        assert_eq!(BackchannelOffer::DEFAULT_FRAME, Duration::from_millis(20));
        // A probe keeps what was offered readable, and a claim takes it
        // without waiting for the probe's result.
        assert!(!slot.is_probing());
        slot.probing();
        assert!(slot.is_probing());
        assert!(!slot.awaits_probe(), "an offer stands");
        assert_eq!(slot.current().unwrap().codec, Codec::Pcmu);
        let waiting = slot.clone();
        let settled = spawn_named("test.settled", async move { waiting.settled().await });
        tokio::task::yield_now().await;
        assert!(!settled.is_finished(), "waits for the probe");
        slot.withdraw();
        assert!(
            bounded(settled).await.unwrap().is_none(),
            "the probe found none"
        );
        assert!(slot.current().is_none());
        // With nothing offered, a claim waits for the probe.
        assert!(!slot.awaits_probe(), "no probe");
        slot.probing();
        assert!(slot.awaits_probe());
        // A probe abandoned leaves the offer as it was.
        slot.offer(pcmu());
        slot.probing();
        slot.abandon_probe();
        assert_eq!(bounded(slot.settled()).await.unwrap().codec, Codec::Pcmu);
        let mut never = slot.current().unwrap().opener.open();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(never.as_mut().poll(&mut cx).is_pending(), "a test opener");
    }

    /// `future`'s output, or a failed test after five seconds.
    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::select! {
            output = future => output,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
        }
    }

    #[tokio::test]
    async fn a_slot_s_probes_wait_at_its_gate() {
        let (gate, mut asks) = ProbeGate::closed();
        let slot = BackchannelSlot::gated(gate);
        let probes = slot.probes().clone();
        let permit = spawn_named("test.permit", async move { probes.permit().await });
        assert_eq!(
            bounded(asks.recv()).await,
            Some(crate::runner::ProbeAsk::Connecting(1))
        );
        assert!(slot.probes().grant(1));
        drop(bounded(permit).await.unwrap());
        assert_eq!(
            bounded(asks.recv()).await,
            Some(crate::runner::ProbeAsk::Ended(1))
        );
        // The default slot's probes never wait.
        drop(bounded(BackchannelSlot::default().probes().permit()).await);
    }

    /// A slot's tasks are the ones it was given: a task spawned there
    /// counts until it ends, and the wait for them resolves only then, a
    /// task spawned during the wait included.
    #[tokio::test]
    async fn a_slot_tracks_its_sessions_tasks_where_it_was_told() {
        let tasks = BackchannelTasks::default();
        let slot = BackchannelSlot::default().tracked(tasks.clone());
        assert_eq!(BackchannelSlot::default().tasks().running(), 0);
        let (end, ended) = oneshot::channel::<()>();
        let task = slot.tasks().spawn("test.session", async move {
            let _ended = ended.await;
        });
        assert_eq!(tasks.running(), 1, "tracked by the tasks it was given");
        let waiting = tasks.clone();
        let wait = spawn_named("test.wait", async move { waiting.ended().await });
        let (more, later) = oneshot::channel::<()>();
        let _late = slot.tasks().spawn("test.late", async move {
            let _later = later.await;
        });
        drop(end);
        bounded(task).await.unwrap();
        tokio::task::yield_now().await;
        assert!(!wait.is_finished(), "a task spawned during the wait counts");
        assert_eq!(tasks.running(), 1);
        drop(more);
        bounded(wait).await.unwrap();
        assert_eq!(tasks.running(), 0);
    }

    #[tokio::test]
    async fn dropping_a_backchannel_session_closes_it() {
        let close = CancellationToken::new();
        let (sender, _uplink) = mpsc::channel(1);
        let (on_loss, lost) = oneshot::channel();
        let session = BackchannelSession::new(
            Codec::Pcma,
            Duration::from_millis(40),
            sender,
            lost,
            close.clone(),
        );
        assert_eq!(
            (session.codec.clone(), session.frame),
            (Codec::Pcma, Duration::from_millis(40))
        );
        assert!(!close.is_cancelled());
        let refused = BackchannelRefused {
            status: Some(453),
            message: "453 Not Enough Bandwidth".into(),
        };
        assert_eq!(refused.to_string(), "453 Not Enough Bandwidth");
        on_loss.send(refused.clone()).unwrap();
        let mut session = session;
        assert_eq!((&mut session.lost).await.unwrap(), refused);
        drop(session);
        assert!(close.is_cancelled(), "closed with the session");
    }

    #[test]
    fn a_scrubbed_source_error_keeps_its_kind_and_loses_the_urls_secrets() {
        let url = SourceUrl::parse("rtsp://u:p@cam/KEY/live?token=TOK").unwrap();
        let text = || "join rtsp://127.0.0.1:9/KEY/live?token=TOK to /KEY/live".to_owned();
        let shown = "join rtsp://127.0.0.1:9/****?**** to /****";
        for (err, scrubbed) in [
            (
                SourceError::Unreachable(text()),
                SourceError::Unreachable(shown.into()),
            ),
            (
                SourceError::AuthFailed(text()),
                SourceError::AuthFailed(shown.into()),
            ),
            (
                SourceError::Timeout(text()),
                SourceError::Timeout(shown.into()),
            ),
            (
                SourceError::Protocol(text()),
                SourceError::Protocol(shown.into()),
            ),
            (SourceError::Ended(text()), SourceError::Ended(shown.into())),
        ] {
            assert_eq!(err.scrubbed(&url), scrubbed);
        }
    }

    #[test]
    fn source_errors_carry_the_api_codes() {
        let cases = [
            (SourceError::Unreachable("x".into()), "source_unreachable"),
            (SourceError::AuthFailed("x".into()), "source_auth_failed"),
            (SourceError::Timeout("x".into()), "source_timeout"),
            (SourceError::Protocol("x".into()), "source_protocol_error"),
            (SourceError::Ended("x".into()), "source_ended"),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code);
            assert!(err.to_string().ends_with(": x"), "{err}");
        }
        assert_eq!(
            SourceConfigError::InvalidOptions {
                scheme: "rtsp",
                message: "unknown field `foo`".into()
            }
            .to_string(),
            "invalid options for scheme rtsp: unknown field `foo`"
        );
        assert_eq!(
            SourceConfigError::InvalidUrl {
                scheme: "rtsp",
                message: "no path".into()
            }
            .to_string(),
            "invalid url for scheme rtsp: no path"
        );
    }

    #[test]
    fn keyframe_request_debug_names_the_variant() {
        assert_eq!(
            format!("{:?}", KeyframeRequest::Unsupported),
            "KeyframeRequest::Unsupported"
        );
        let sent = KeyframeRequest::Sent(Box::pin(std::future::ready(Ok(()))));
        assert_eq!(format!("{sent:?}"), "KeyframeRequest::Sent(..)");
    }
}

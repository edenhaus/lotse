//! [`Track`]: one media track of a source connection, with its packet
//! broadcast (cut-through), its side-branch frame broadcast, the GOP cache
//! and counters.
//!
//! Invariants: the producer never blocks and never waits for a subscriber;
//! a slow subscriber sees `Lagged` and skips, the channel never grows past
//! its capacity; the GOP cache is an immutable snapshot swapped on every
//! frame, so readers take no lock; consecutive snapshots share their frames
//! as one chain, so a frame costs the producer the same at any GOP length;
//! the cache is bounded in payload bytes and in frames; a keyframe always
//! fits the cache because `max_frame_bytes` never exceeds `gop_cache_bytes`
//! and a keyframe alone is never over the frame bound.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::sync::{broadcast, watch};

use crate::clock_map::ticks_between;
use crate::codec::{Codec, Kind};
use crate::lateness::LatenessMeter;
use crate::media::{MediaFrame, MediaPacket, MediaTime};
use crate::throttle::Throttle;

/// The id of a track within its stream: a kind letter and an index (`v0`,
/// `a0`, `a1` for a derived track), as the API reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrackId {
    /// The track's kind.
    kind: Kind,
    /// The index among the stream's tracks of that kind.
    index: u8,
}

impl TrackId {
    /// The `index`th track of `kind`.
    pub const fn new(kind: Kind, index: u8) -> Self {
        Self { kind, index }
    }

    /// The track's kind.
    pub const fn kind(self) -> Kind {
        self.kind
    }

    /// The index among the stream's tracks of that kind.
    pub const fn index(self) -> u8 {
        self.index
    }
}

impl fmt::Display for TrackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.kind.letter(), self.index)
    }
}

/// Default of `limits.max_frame_bytes`: 4 MiB.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Default of `limits.gop_cache_bytes`: 4 MiB, equal to the frame limit so
/// every legal keyframe fits.
pub const DEFAULT_GOP_CACHE_BYTES: usize = 4 * 1024 * 1024;

/// Default of `limits.gop_cache_frames`: 1024 frames, keyframe included,
/// which holds a 17 s GOP at 60 fps. The byte cap alone does not bound a
/// GOP of tiny access units (an AUD or SEI per packet), whose per-frame
/// overhead it does not count.
pub const DEFAULT_GOP_CACHE_FRAMES: usize = 1024;

/// Default packet broadcast capacity: ~500 ms at 4000 packets/s, which is
/// a 40 Mbit/s stream in 1200-byte packets. The capacity is only the safety
/// bound; consumers bound their queues by age.
pub const DEFAULT_PACKET_CAPACITY: usize = 2048;

/// Default frame broadcast capacity: a few GOPs of frames for the side
/// branch, whose consumers keep their own bounded queues.
pub const DEFAULT_FRAME_CAPACITY: usize = 64;

/// Capacity of the control-event broadcast. Control events are rare (an
/// epoch per reconnect, a codec change, a source loss), so a subscriber
/// that lags here is broken and is told so.
const CONTROL_CAPACITY: usize = 16;

/// The bounds a track enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackLimits {
    /// Frames larger than this are dropped from the side branch and counted.
    pub max_frame_bytes: usize,
    /// The GOP cache keeps only the keyframe once a GOP exceeds this many
    /// payload bytes.
    pub gop_cache_bytes: usize,
    /// The GOP cache keeps only the keyframe once a GOP has more frames
    /// than this, keyframe included; a keyframe alone is always kept.
    pub gop_cache_frames: usize,
    /// Capacity of the packet broadcast, in packets. Zero is treated as one.
    pub packet_capacity: usize,
    /// Capacity of the frame broadcast, in frames. Zero is treated as one.
    pub frame_capacity: usize,
}

impl Default for TrackLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            gop_cache_bytes: DEFAULT_GOP_CACHE_BYTES,
            gop_cache_frames: DEFAULT_GOP_CACHE_FRAMES,
            packet_capacity: DEFAULT_PACKET_CAPACITY,
            frame_capacity: DEFAULT_FRAME_CAPACITY,
        }
    }
}

/// The last keyframe and the frames since it, in decode order. Immutable:
/// the track publishes a new snapshot on every frame, sharing the frames of
/// the one before, so publishing costs one link whatever the GOP length.
pub struct GopSnapshot {
    /// The keyframe that starts the GOP.
    keyframe: Arc<MediaFrame>,
    /// The newest frame after the keyframe, linked back to the one before
    /// it down to the first after the keyframe; `None` when only the
    /// keyframe is held (a fresh GOP, or a truncated one).
    newest: Option<Arc<GopLink>>,
    /// Frames held, keyframe included: one plus the links in `newest`.
    frames: usize,
    /// Payload bytes held, keyframe included.
    bytes: usize,
    /// The GOP outgrew `gop_cache_bytes` or `gop_cache_frames`, so only the
    /// keyframe is kept until the next keyframe.
    truncated: bool,
}

/// One frame after a GOP's keyframe, linked to the frame before it. Every
/// snapshot of the GOP shares the links before its newest, so appending a
/// frame allocates one link and copies nothing.
struct GopLink {
    /// The frame.
    frame: Arc<MediaFrame>,
    /// The frame before it; `None` for the first after the keyframe.
    previous: Option<Arc<Self>>,
}

impl Drop for GopLink {
    /// Unlinks the chain in a loop: the derived drop would recurse once
    /// per link and could overflow the stack on a long GOP. Stops at the
    /// first link another snapshot still holds.
    fn drop(&mut self) {
        let mut previous = self.previous.take();
        while let Some(link) = previous {
            previous = Arc::into_inner(link).and_then(|mut owned| owned.previous.take());
        }
    }
}

impl GopSnapshot {
    /// The keyframe that starts the GOP.
    pub fn keyframe(&self) -> &Arc<MediaFrame> {
        &self.keyframe
    }

    /// The keyframe and the frames after it, in decode order: a decodable
    /// start for a joiner. Walks the chain once, so it costs O(frames).
    pub fn frames(&self) -> impl Iterator<Item = &Arc<MediaFrame>> {
        let mut following = Vec::new();
        let mut link = self.newest.as_deref();
        while let Some(current) = link {
            following.push(&current.frame);
            link = current.previous.as_deref();
        }
        std::iter::once(&self.keyframe).chain(following.into_iter().rev())
    }

    /// Frames held, keyframe included.
    pub const fn frame_count(&self) -> usize {
        self.frames
    }

    /// Payload bytes held, keyframe included.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether the GOP outgrew the cache and only the keyframe is kept.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// How old the keyframe is at `now`, by its capture time, but at
    /// least as old as its arrival makes it: a capture time a camera's
    /// Sender Report put ahead of the arrival is not believed. Decides
    /// between a catch-up burst and a still on join.
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.keyframe.wallclock.min(self.keyframe.arrival))
    }
}

impl fmt::Debug for GopSnapshot {
    /// A summary: the frames themselves would be the whole GOP.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GopSnapshot")
            .field("keyframe_ts", &self.keyframe.ts)
            .field("frames", &self.frames)
            .field("bytes", &self.bytes)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// A snapshot of a track's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackStats {
    /// Packets published on the live path.
    pub packets: u64,
    /// Payload bytes of those packets.
    pub packet_bytes: u64,
    /// Frames accepted on the side branch.
    pub frames: u64,
    /// Payload bytes of those frames.
    pub frame_bytes: u64,
    /// Keyframes among the accepted frames.
    pub keyframes: u64,
    /// Frames dropped because they exceeded `max_frame_bytes`.
    pub frames_dropped_oversize: u64,
    /// Frames the live path carried in more RTP packets than some
    /// libwebrtc receivers assemble, as the source reported them
    /// ([`Track::count_frame_over_browser_limit`]).
    pub frames_over_browser_limit: u64,
}

/// The live counters behind [`TrackStats`].
#[derive(Debug, Default)]
struct Counters {
    /// See [`TrackStats::packets`].
    packets: AtomicU64,
    /// See [`TrackStats::packet_bytes`].
    packet_bytes: AtomicU64,
    /// See [`TrackStats::frames`].
    frames: AtomicU64,
    /// See [`TrackStats::frame_bytes`].
    frame_bytes: AtomicU64,
    /// See [`TrackStats::keyframes`].
    keyframes: AtomicU64,
    /// See [`TrackStats::frames_dropped_oversize`].
    frames_dropped_oversize: AtomicU64,
    /// See [`TrackStats::frames_over_browser_limit`].
    frames_over_browser_limit: AtomicU64,
}

impl Counters {
    /// Adds `bytes` (saturated to `u64`) to `counter`.
    fn add_bytes(counter: &AtomicU64, bytes: usize) {
        counter.fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Reads every counter.
    fn snapshot(&self) -> TrackStats {
        TrackStats {
            packets: self.packets.load(Ordering::Relaxed),
            packet_bytes: self.packet_bytes.load(Ordering::Relaxed),
            frames: self.frames.load(Ordering::Relaxed),
            frame_bytes: self.frame_bytes.load(Ordering::Relaxed),
            keyframes: self.keyframes.load(Ordering::Relaxed),
            frames_dropped_oversize: self.frames_dropped_oversize.load(Ordering::Relaxed),
            frames_over_browser_limit: self.frames_over_browser_limit.load(Ordering::Relaxed),
        }
    }
}

/// What a track tells its subscribers besides media. Delivered on a channel
/// of its own; media items carry their epoch, so a subscriber never needs
/// the two channels ordered against each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackControlEvent {
    /// A new epoch began: a timestamp discontinuity or a reconnect. Live
    /// sinks compute a new timestamp offset at the first item of the epoch.
    EpochStart {
        /// The epoch number that media items now carry.
        epoch: u32,
    },
    /// The codec descriptor changed on a reconnect. A session closes with
    /// `stream_changed` only if the family changed.
    TrackChanged(Arc<Codec>),
    /// The source connection is gone; the track stays and will resume.
    SourceLost,
    /// The source connection is back.
    SourceRestored,
    /// The track is being torn down (stream deleted, worker stopping).
    /// Subscriptions end at once; items still queued are discarded.
    Closed,
}

/// The unit a subscriber wants: live packets or side-branch frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unit {
    /// RTP packets as read, for live sinks (WebRTC).
    Packets,
    /// Whole frames from the side branch, for frame sinks (snapshot,
    /// transcoders, later muxers).
    Frames,
}

/// What a subscription yields; each sink decides what it means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackEvent {
    /// A live packet (`Unit::Packets` subscriptions).
    Packet(Arc<MediaPacket>),
    /// A side-branch frame (`Unit::Frames` subscriptions).
    Frame(Arc<MediaFrame>),
    /// The subscriber missed items: `BestEffort` lag, later `Reliable`
    /// overflow. Always explicit, never silent. A live sink skips to the
    /// next keyframe; a recorder records a gap.
    Gap {
        /// How many items were missed.
        skipped: u64,
    },
    /// See [`TrackControlEvent::EpochStart`].
    EpochStart {
        /// The epoch number that media items now carry.
        epoch: u32,
    },
    /// See [`TrackControlEvent::TrackChanged`].
    TrackChanged(Arc<Codec>),
    /// See [`TrackControlEvent::SourceLost`].
    SourceLost,
    /// See [`TrackControlEvent::SourceRestored`].
    SourceRestored,
}

impl TrackEvent {
    /// The event a control event becomes for a sink; `None` for `Closed`,
    /// which ends the subscription instead.
    fn from_control(event: TrackControlEvent) -> Option<Self> {
        match event {
            TrackControlEvent::EpochStart { epoch } => Some(Self::EpochStart { epoch }),
            TrackControlEvent::TrackChanged(codec) => Some(Self::TrackChanged(codec)),
            TrackControlEvent::SourceLost => Some(Self::SourceLost),
            TrackControlEvent::SourceRestored => Some(Self::SourceRestored),
            TrackControlEvent::Closed => None,
        }
    }
}

/// The media half of a [`TrackSubscription`].
#[derive(Debug)]
enum MediaSubscription {
    /// Live packets.
    Packets(PacketSubscription),
    /// Side-branch frames.
    Frames(FrameSubscription),
}

impl MediaSubscription {
    /// Waits for the next media item as a [`TrackEvent`].
    async fn recv(&mut self) -> Result<TrackEvent, SubscriptionError> {
        match self {
            Self::Packets(sub) => sub.recv().await.map(TrackEvent::Packet),
            Self::Frames(sub) => sub.recv().await.map(TrackEvent::Frame),
        }
    }
}

/// A sink's view of one track: media items of the chosen [`Unit`] merged
/// with the track's control events, lag turned into explicit gaps.
#[derive(Debug)]
pub struct TrackSubscription {
    /// The track subscribed to.
    track: Arc<Track>,
    /// The media items.
    media: MediaSubscription,
    /// The control events.
    control: broadcast::Receiver<TrackControlEvent>,
    /// Rate-limits the line of a lag on the control events, which a
    /// camera changing its codec on every frame causes on every
    /// [`CONTROL_CAPACITY`]th.
    lags: Throttle,
}

impl TrackSubscription {
    /// The track subscribed to.
    pub const fn track(&self) -> &Arc<Track> {
        &self.track
    }

    /// The next event, or `None` once the track is closed. Control events
    /// take precedence over queued media so a sink learns about an epoch
    /// or a codec change before it writes the items that follow.
    pub async fn next(&mut self) -> Option<TrackEvent> {
        if self.track.is_closed() {
            return None;
        }
        loop {
            tokio::select! {
                biased;
                control = self.control.recv() => match control {
                    Ok(event) => return TrackEvent::from_control(event),
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        if let Some(count) = self.lags.hit(self.track.activity_clock()) {
                            tracing::warn!(track = %self.track.id, skipped, count, "subscriber missed control events");
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                },
                media = self.media.recv() => match media {
                    Ok(event) => return Some(event),
                    Err(SubscriptionError::Lagged(skipped)) => return Some(TrackEvent::Gap { skipped }),
                    Err(SubscriptionError::Closed) => return None,
                },
            }
        }
    }
}

/// Why a subscription yielded no item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SubscriptionError {
    /// The subscriber fell behind and this many items were discarded; the
    /// next receive continues at the oldest item still held. A live sink
    /// skips to the next keyframe.
    #[error("subscriber lagged: {0} items skipped")]
    Lagged(u64),
    /// The track is gone.
    #[error("track closed")]
    Closed,
}

impl From<broadcast::error::RecvError> for SubscriptionError {
    fn from(err: broadcast::error::RecvError) -> Self {
        match err {
            broadcast::error::RecvError::Lagged(n) => Self::Lagged(n),
            broadcast::error::RecvError::Closed => Self::Closed,
        }
    }
}

/// A subscription to a track's live packets, starting at the live edge.
#[derive(Debug)]
pub struct PacketSubscription(broadcast::Receiver<Arc<MediaPacket>>);

/// A subscription to a track's side-branch frames, starting at the live edge.
#[derive(Debug)]
pub struct FrameSubscription(broadcast::Receiver<Arc<MediaFrame>>);

/// Implements the receive side of a broadcast subscription.
macro_rules! subscription {
    ($name:ident, $item:ty) => {
        impl $name {
            /// Waits for the next item.
            pub async fn recv(&mut self) -> Result<$item, SubscriptionError> {
                self.0.recv().await.map_err(SubscriptionError::from)
            }

            /// The next item if one is queued, `Ok(None)` if the queue is empty.
            pub fn try_recv(&mut self) -> Result<Option<$item>, SubscriptionError> {
                match self.0.try_recv() {
                    Ok(item) => Ok(Some(item)),
                    Err(broadcast::error::TryRecvError::Empty) => Ok(None),
                    Err(broadcast::error::TryRecvError::Lagged(n)) => {
                        Err(SubscriptionError::Lagged(n))
                    }
                    Err(broadcast::error::TryRecvError::Closed) => Err(SubscriptionError::Closed),
                }
            }

            /// Items queued for this subscriber.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Whether nothing is queued for this subscriber.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
    };
}

subscription!(PacketSubscription, Arc<MediaPacket>);
subscription!(FrameSubscription, Arc<MediaFrame>);

/// Which source feeds a connection's tracks: the one its live
/// [`TrackSet`](crate::source::TrackSet) was made for (tag 0) or a standby
/// declared through a staging set ([`TrackSet::staging`](crate::source::TrackSet::staging)),
/// whose tracks forward into their live counterparts. Shared by the live
/// set, its staging sets and all their tracks.
///
/// A `stream/put` that changes a stream's source connects the new source
/// as a standby while the old one keeps streaming (make before break).
/// Once the standby is live the worker arms it; its writes are dropped
/// until its video's first keyframe (or its first item, without video),
/// which switches: every live track starts a new epoch and takes the
/// standby's codec, the live set is ready, and from then on the standby's
/// writes reach the live tracks while the old source's are dropped.
/// Sessions see a hot swap, as on a reconnect.
#[derive(Debug)]
pub struct Feeds {
    /// The tag whose writes reach the live tracks.
    active: AtomicU8,
    /// The tag that switches at its first keyframe; 0 when none (the live
    /// set's own source is never a standby).
    armed: AtomicU8,
    /// The armed staging set has a video track, so only a keyframe
    /// switches.
    armed_has_video: AtomicBool,
    /// The next staging set's tag.
    next_tag: AtomicU8,
    /// The armed staging set's tracks, for the switch.
    armed_tracks: Mutex<Vec<Weak<Track>>>,
    /// The live set, for the switch.
    live: Weak<crate::source::TrackSet>,
    /// The tag last switched to, for whoever runs the sources.
    switched: watch::Sender<u8>,
}

impl Feeds {
    /// The feeds of `live`, which its own source feeds.
    pub(crate) fn new(live: Weak<crate::source::TrackSet>) -> Self {
        let (switched, _rx) = watch::channel(0);
        Self {
            active: AtomicU8::new(0),
            armed: AtomicU8::new(0),
            armed_has_video: AtomicBool::new(false),
            next_tag: AtomicU8::new(1),
            armed_tracks: Mutex::new(Vec::new()),
            live,
            switched,
        }
    }

    /// The tag whose writes reach the live tracks.
    pub fn active(&self) -> u8 {
        self.active.load(Ordering::Acquire)
    }

    /// The tag last switched to, 0 before any switch; changes are observed
    /// through the receiver.
    pub fn switched(&self) -> watch::Receiver<u8> {
        self.switched.subscribe()
    }

    /// A fresh staging tag.
    pub(crate) fn next_tag(&self) -> u8 {
        self.next_tag.fetch_add(1, Ordering::Relaxed)
    }

    /// Arms the staging set with `tag` and `tracks`: it switches at its
    /// first keyframe. Replaces a standby armed before.
    pub(crate) fn arm(&self, tag: u8, tracks: &[Arc<Track>]) {
        *self
            .armed_tracks
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = tracks.iter().map(Arc::downgrade).collect();
        self.armed_has_video.store(
            tracks.iter().any(|track| track.kind() == Kind::Video),
            Ordering::Release,
        );
        self.armed.store(tag, Ordering::Release);
        tracing::info!(
            tag,
            tracks = tracks.len(),
            "standby source armed; switching at its next keyframe"
        );
    }

    /// Takes the standby with `tag` out of the switch, if it is the one
    /// armed.
    pub(crate) fn disarm(&self, tag: u8) {
        if tag != 0
            && self
                .armed
                .compare_exchange(tag, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.armed_tracks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
            tracing::info!(tag, "standby source disarmed");
        }
    }

    /// Whether a write from the source tagged `tag` reaches the live
    /// tracks: yes while it is active; a write from the armed standby
    /// switches to it first when it is the one the switch waits for
    /// (`keyframe` of a video track, or any write when the standby has no
    /// video), else it is dropped.
    fn admits(&self, tag: u8, kind: Kind, keyframe: bool) -> bool {
        if self.active() == tag {
            return true;
        }
        // Tag 0 is the live set's own source, never a standby.
        if tag == 0 || self.armed.load(Ordering::Acquire) != tag {
            return false;
        }
        let video_only = self.armed_has_video.load(Ordering::Acquire);
        if video_only && !(kind == Kind::Video && keyframe) {
            return false;
        }
        self.switch(tag);
        true
    }

    /// Switches to the armed standby `tag`: a new epoch on every live
    /// track, the standby's codecs on their counterparts, live tracks
    /// declared for standby tracks without one, the live set ready.
    fn switch(&self, tag: u8) {
        let staging: Vec<Arc<Track>> = std::mem::take(
            &mut *self
                .armed_tracks
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
        let live = self.live.upgrade();
        if let Some(live) = &live {
            for track in live.tracks() {
                track.start_epoch_inner();
            }
        }
        for track in &staging {
            let codec = (*track.codec()).clone();
            match track.forward_to.load_full() {
                Some(target) => target.set_codec_inner(codec),
                None => {
                    if let Some(live) = &live {
                        let declared = live.declare(track.id(), codec, track.clock_rate());
                        track.forward_to.store(Some(declared));
                    }
                }
            }
        }
        if let Some(live) = &live {
            live.mark_ready(true);
        }
        self.armed.store(0, Ordering::Release);
        self.armed_has_video.store(false, Ordering::Release);
        self.active.store(tag, Ordering::Release);
        tracing::info!(
            tag,
            tracks = staging.len(),
            "source switched: the standby feeds the tracks"
        );
        self.switched.send_replace(tag);
    }
}

/// One media track: codec descriptor, packet broadcast, frame broadcast,
/// GOP cache and counters. Written by the source task, read by every sink
/// of the connection. A staging track ([`TrackSet::staging`](crate::source::TrackSet::staging))
/// forwards its writes into its live counterpart once its source is the
/// active feed ([`Feeds`]).
pub struct Track {
    /// The track's id within its stream.
    id: TrackId,
    /// Ticks per second of `MediaTime` and of the RTP timestamps.
    clock_rate: u32,
    /// The codec descriptor; swapped when a reconnect changes it.
    codec: ArcSwap<Codec>,
    /// The live path: every packet, as read.
    packets: broadcast::Sender<Arc<MediaPacket>>,
    /// The side branch: every accepted frame.
    frames: broadcast::Sender<Arc<MediaFrame>>,
    /// The GOP cache; `None` until the first keyframe. Video only.
    gop: ArcSwapOption<GopSnapshot>,
    /// The last side-branch frame accepted, the anchor of
    /// [`Track::capture_time`].
    last_frame: ArcSwapOption<MediaFrame>,
    /// Control events: epochs, codec changes, source loss.
    control: broadcast::Sender<TrackControlEvent>,
    /// The current epoch, stamped on every item.
    epoch: AtomicU32,
    /// The next frame is the first of a new epoch and gets `discontinuity`.
    epoch_frame_pending: AtomicBool,
    /// Measures each frame's ingest lateness; only the source's task
    /// publishes, so the lock is never contended.
    lateness: Mutex<LatenessMeter>,
    /// Rate-limits the log line of a GOP outgrowing the cache, which a
    /// camera with long GOPs hits on every GOP; only the source's task
    /// publishes, so the lock is never contended.
    gop_truncations: Mutex<Throttle>,
    /// Rate-limits the line of a codec change, which a camera alternating
    /// two parameter sets makes on every frame; taken only by whoever sets
    /// the codec, the source's task.
    codec_changes: Mutex<Throttle>,
    /// Set by [`Track::close`]; subscriptions end and nothing is published.
    closed: AtomicBool,
    /// The instant `last_activity` counts from.
    origin: Instant,
    /// Nanoseconds since `origin` of the last item published, plus one;
    /// zero means none yet. The stall watchdog reads it.
    last_activity: AtomicU64,
    /// The bounds enforced.
    limits: TrackLimits,
    /// The counters.
    counters: Counters,
    /// Which source feeds the connection's tracks.
    feeds: Arc<Feeds>,
    /// The source this track is written by: 0 for a live set's track, the
    /// staging set's tag for a standby's.
    tag: u8,
    /// The live counterpart a staging track forwards into, once its source
    /// is active; set at the switch for a track the live set lacked.
    forward_to: ArcSwapOption<Self>,
}

impl Track {
    /// A track carrying `codec` at `clock_rate` ticks per second. `origin`
    /// is any instant not after the first item; activity is timed from it.
    pub fn new(
        id: TrackId,
        codec: Codec,
        clock_rate: u32,
        limits: TrackLimits,
        origin: Instant,
    ) -> Self {
        Self::with_feeds(
            id,
            codec,
            clock_rate,
            limits,
            origin,
            Arc::new(Feeds::new(Weak::new())),
            0,
            None,
        )
    }

    /// [`Self::new`] as the source tagged `tag` of `feeds` writes it,
    /// forwarding into `forward_to` while that source is active.
    #[expect(
        clippy::too_many_arguments,
        reason = "a constructor wiring the track into its set's feeds; called from the set alone"
    )]
    pub(crate) fn with_feeds(
        id: TrackId,
        codec: Codec,
        clock_rate: u32,
        limits: TrackLimits,
        origin: Instant,
        feeds: Arc<Feeds>,
        tag: u8,
        forward_to: Option<Arc<Self>>,
    ) -> Self {
        let (packets, _no_receivers_yet) = broadcast::channel(limits.packet_capacity.max(1));
        let (frames, _no_receivers_yet) = broadcast::channel(limits.frame_capacity.max(1));
        let (control, _no_receivers_yet) = broadcast::channel(CONTROL_CAPACITY);
        Self {
            id,
            clock_rate,
            codec: ArcSwap::from_pointee(codec),
            packets,
            frames,
            gop: ArcSwapOption::empty(),
            last_frame: ArcSwapOption::empty(),
            control,
            epoch: AtomicU32::new(0),
            epoch_frame_pending: AtomicBool::new(false),
            lateness: Mutex::new(LatenessMeter::new(clock_rate)),
            gop_truncations: Mutex::new(Throttle::default()),
            codec_changes: Mutex::new(Throttle::default()),
            closed: AtomicBool::new(false),
            origin,
            last_activity: AtomicU64::new(0),
            limits,
            counters: Counters::default(),
            feeds,
            tag,
            forward_to: ArcSwapOption::new(forward_to),
        }
    }

    /// Whether this track's own source is the active feed.
    fn fed(&self) -> bool {
        self.feeds.active() == self.tag
    }

    /// The live counterpart a staging track's write lands on, if any.
    fn forwarded(&self) -> Option<Arc<Self>> {
        self.forward_to.load_full()
    }

    /// When the last item was published, if any. Packets and frames alike
    /// are timed by their `arrival` on the injected clock, never by a
    /// frame's `wallclock`: the camera's Sender Reports move that, and a
    /// capture time hours ahead would hold off the stall watchdog.
    pub fn last_activity(&self) -> Option<Instant> {
        let stored = self.last_activity.load(Ordering::Relaxed);
        let nanos = stored.checked_sub(1)?;
        self.origin.checked_add(Duration::from_nanos(nanos))
    }

    /// The track's latest instant on the injected clock, which times its
    /// rate-limited lines: the last item's arrival, `origin` before any.
    fn activity_clock(&self) -> Instant {
        self.last_activity().unwrap_or(self.origin)
    }

    /// Records activity at `at`.
    fn touch(&self, at: Instant) {
        let nanos = at.saturating_duration_since(self.origin).as_nanos();
        let stored = u64::try_from(nanos).unwrap_or(u64::MAX).saturating_add(1);
        self.last_activity.fetch_max(stored, Ordering::Relaxed);
    }

    /// The track's id within its stream.
    pub const fn id(&self) -> TrackId {
        self.id
    }

    /// The track's kind.
    pub const fn kind(&self) -> Kind {
        self.id.kind()
    }

    /// Ticks per second of `MediaTime` and of the RTP timestamps.
    pub const fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// The bounds enforced.
    pub const fn limits(&self) -> TrackLimits {
        self.limits
    }

    /// The current codec descriptor.
    pub fn codec(&self) -> Arc<Codec> {
        self.codec.load_full()
    }

    /// Replaces the codec descriptor, for a reconnect or a stream that
    /// changed it, and tells subscribers. A descriptor equal to the current
    /// one is a no-op. The line is rate-limited, timed by the track's
    /// activity: a camera can change its parameter sets on every frame.
    pub fn set_codec(&self, codec: Codec) {
        if self.fed() {
            match self.forwarded() {
                Some(target) => target.set_codec_inner(codec),
                None => self.set_codec_inner(codec),
            }
        } else if self.tag != 0 {
            // A standby's codec, kept for the switch.
            self.set_codec_inner(codec);
        }
    }

    /// [`Self::set_codec`] on this track itself, whoever feeds it.
    fn set_codec_inner(&self, codec: Codec) {
        if *self.codec.load().as_ref() == codec {
            return;
        }
        let codec = Arc::new(codec);
        let due = self
            .codec_changes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hit(self.activity_clock());
        if let Some(count) = due {
            tracing::info!(track = %self.id, codec = codec.name(), count, "track codec changed");
        }
        self.codec.store(Arc::clone(&codec));
        self.publish_control(TrackControlEvent::TrackChanged(codec));
    }

    /// The current epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Starts a new epoch (a timestamp discontinuity or a reconnect): items
    /// published from now on carry the new number, the next frame gets
    /// `discontinuity`, lateness is measured afresh, and subscribers get
    /// `EpochStart`.
    pub fn start_epoch(&self) -> u32 {
        if !self.fed() {
            return self.epoch();
        }
        match self.forwarded() {
            Some(target) => target.start_epoch_inner(),
            None => self.start_epoch_inner(),
        }
    }

    /// [`Self::start_epoch`] on this track itself, whoever feeds it.
    fn start_epoch_inner(&self) -> u32 {
        let epoch = self.epoch.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        self.epoch_frame_pending.store(true, Ordering::Relaxed);
        self.lateness
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reset();
        tracing::debug!(track = %self.id, epoch, "epoch started");
        self.publish_control(TrackControlEvent::EpochStart { epoch });
        epoch
    }

    /// Tells subscribers the source connection is gone or back.
    pub fn set_source_lost(&self, lost: bool) {
        if !self.fed() {
            return;
        }
        match self.forwarded() {
            Some(target) => target.set_source_lost_inner(lost),
            None => self.set_source_lost_inner(lost),
        }
    }

    /// [`Self::set_source_lost`] on this track itself, whoever feeds it.
    fn set_source_lost_inner(&self, lost: bool) {
        self.publish_control(if lost {
            TrackControlEvent::SourceLost
        } else {
            TrackControlEvent::SourceRestored
        });
    }

    /// Tears the track down: every subscription ends, and nothing published
    /// afterwards reaches anyone. Idempotent. Subscribers hold the track,
    /// so this, not dropping it, is how a track ends.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        tracing::debug!(track = %self.id, "track closed");
        let _delivered_to = self.control.send(TrackControlEvent::Closed);
    }

    /// Whether [`Track::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Sends a control event; no subscriber is not an error. Nothing after
    /// `close`.
    fn publish_control(&self, event: TrackControlEvent) {
        if self.is_closed() {
            return;
        }
        let _delivered_to = self.control.send(event);
    }

    /// The counters now.
    pub fn stats(&self) -> TrackStats {
        self.counters.snapshot()
    }

    /// The GOP cache, once a keyframe has been seen.
    pub fn gop(&self) -> Option<Arc<GopSnapshot>> {
        self.gop.load_full()
    }

    /// The capture time of the RTP timestamp `rtp_ts` of `epoch`,
    /// extrapolated from the last side-branch frame at the track's clock
    /// rate (timestamps wrap, RFC 3550 §5.1); `None` before the first
    /// frame or when that frame belongs to another epoch.
    ///
    /// This is how a derived track's packets are mapped: its transcoder
    /// stamps each frame with the capture time its timestamp claims,
    /// derived from the source frame's, and publishes the frame before its
    /// packets. The connection's `ClockMapper` knows only the native
    /// tracks' clocks.
    pub fn capture_time(&self, epoch: u32, rtp_ts: u32) -> Option<Instant> {
        let anchor = self.last_frame.load_full()?;
        if anchor.epoch != epoch {
            return None;
        }
        let anchor_ts = u32::try_from(anchor.ts.ticks().rem_euclid(1_i64 << 32)).ok()?;
        let ticks = ticks_between(anchor_ts, rtp_ts);
        let span =
            MediaTime::from_ticks(i64::from(ticks.unsigned_abs())).to_duration(self.clock_rate)?;
        if ticks.is_negative() {
            anchor.wallclock.checked_sub(span)
        } else {
            anchor.wallclock.checked_add(span)
        }
    }

    /// A live-packet subscription starting at the live edge.
    pub fn subscribe_packets(&self) -> PacketSubscription {
        PacketSubscription(self.packets.subscribe())
    }

    /// A frame subscription starting at the live edge.
    pub fn subscribe_frames(&self) -> FrameSubscription {
        FrameSubscription(self.frames.subscribe())
    }

    /// A sink's subscription: media of `unit` merged with control events.
    pub fn subscribe(self: &Arc<Self>, unit: Unit) -> TrackSubscription {
        let media = match unit {
            Unit::Packets => MediaSubscription::Packets(self.subscribe_packets()),
            Unit::Frames => MediaSubscription::Frames(self.subscribe_frames()),
        };
        TrackSubscription {
            track: Arc::clone(self),
            media,
            control: self.control.subscribe(),
            lags: Throttle::default(),
        }
    }

    /// Live subscribers now.
    pub fn packet_subscribers(&self) -> usize {
        self.packets.receiver_count()
    }

    /// Counts a frame the source's live path carried in more RTP packets
    /// than some libwebrtc receivers assemble; every session sends it
    /// whole all the same.
    pub fn count_frame_over_browser_limit(&self) {
        if !self.fed() {
            return;
        }
        match self.forwarded() {
            Some(target) => target.count_frame_over_browser_limit_inner(),
            None => self.count_frame_over_browser_limit_inner(),
        }
    }

    /// [`Self::count_frame_over_browser_limit`] on this track itself.
    fn count_frame_over_browser_limit_inner(&self) {
        self.counters
            .frames_over_browser_limit
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Publishes a packet on the live path, stamped with the current epoch
    /// and its frame's ingest lateness. Never blocks; a subscriber that
    /// cannot keep up lags and skips.
    pub fn publish_packet(&self, packet: MediaPacket) {
        // Before the switch too: the standby's stall watchdog reads this
        // track, and a camera's keyframes can be further apart than its
        // stall timeout.
        self.touch(packet.arrival);
        if !self
            .feeds
            .admits(self.tag, self.kind(), packet.keyframe_start)
        {
            return;
        }
        match self.forwarded() {
            Some(target) => target.publish_packet_inner(packet),
            None => self.publish_packet_inner(packet),
        }
    }

    /// [`Self::publish_packet`] on this track itself, whoever feeds it.
    fn publish_packet_inner(&self, mut packet: MediaPacket) {
        if self.is_closed() {
            return;
        }
        packet.epoch = self.epoch();
        packet.lateness = self
            .lateness
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .packet(packet.arrival, packet.rtp.ts, packet.frame_start);
        self.touch(packet.arrival);
        self.counters.packets.fetch_add(1, Ordering::Relaxed);
        Counters::add_bytes(&self.counters.packet_bytes, packet.payload.len());
        // A send fails only when nobody is subscribed, which is not an error
        // for a producer that never waits for its consumers.
        let _delivered_to = self.packets.send(Arc::new(packet));
    }

    /// Publishes a frame on the side branch, stamped with the current epoch
    /// (and `discontinuity` if it is the epoch's first): updates the GOP
    /// cache (video) and broadcasts it. Returns `false` for a frame larger
    /// than `max_frame_bytes`, which is dropped and counted.
    pub fn publish_frame(&self, frame: MediaFrame) -> bool {
        self.touch(frame.arrival);
        if !self.feeds.admits(self.tag, self.kind(), frame.keyframe) {
            return false;
        }
        match self.forwarded() {
            Some(target) => target.publish_frame_inner(frame),
            None => self.publish_frame_inner(frame),
        }
    }

    /// [`Self::publish_frame`] on this track itself, whoever feeds it.
    fn publish_frame_inner(&self, mut frame: MediaFrame) -> bool {
        if self.is_closed() {
            return false;
        }
        frame.epoch = self.epoch();
        if self.epoch_frame_pending.swap(false, Ordering::Relaxed) {
            frame.discontinuity = true;
        }
        let bytes = frame.payload.len();
        if bytes > self.limits.max_frame_bytes {
            self.counters
                .frames_dropped_oversize
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                track = %self.id,
                bytes,
                limit = self.limits.max_frame_bytes,
                "frame dropped: larger than max_frame_bytes"
            );
            return false;
        }
        self.touch(frame.arrival);
        self.counters.frames.fetch_add(1, Ordering::Relaxed);
        Counters::add_bytes(&self.counters.frame_bytes, bytes);
        if frame.keyframe {
            self.counters.keyframes.fetch_add(1, Ordering::Relaxed);
        }
        let frame = Arc::new(frame);
        if self.kind() == Kind::Video {
            self.update_gop(&frame);
        }
        self.last_frame.store(Some(Arc::clone(&frame)));
        // As above: no subscriber is not an error.
        let _delivered_to = self.frames.send(frame);
        true
    }

    /// Publishes the next GOP snapshot for `frame`: a keyframe starts a
    /// new GOP; any other frame is linked onto the current one in O(1),
    /// or truncates it to its keyframe once it would exceed
    /// `gop_cache_bytes` or `gop_cache_frames`.
    fn update_gop(&self, frame: &Arc<MediaFrame>) {
        let bytes = frame.payload.len();
        if frame.keyframe {
            self.gop.store(Some(Arc::new(GopSnapshot {
                keyframe: Arc::clone(frame),
                newest: None,
                frames: 1,
                bytes,
                truncated: false,
            })));
            return;
        }
        // Before the first keyframe there is nothing a joiner could decode from.
        let Some(current) = self.gop.load_full() else {
            return;
        };
        if current.truncated {
            return;
        }
        let total = current.bytes.saturating_add(bytes);
        let count = current.frames.saturating_add(1);
        let exceeded = if total > self.limits.gop_cache_bytes {
            Some("gop_cache_bytes")
        } else if count > self.limits.gop_cache_frames {
            Some("gop_cache_frames")
        } else {
            None
        };
        let next = if let Some(limit) = exceeded {
            let due = self
                .gop_truncations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .hit(frame.wallclock);
            if let Some(truncations) = due {
                tracing::debug!(
                    track = %self.id,
                    limit,
                    gop_bytes = total,
                    gop_frames = count,
                    bytes_limit = self.limits.gop_cache_bytes,
                    frames_limit = self.limits.gop_cache_frames,
                    truncations,
                    "gop cache: GOP exceeds the cache, keeping only the keyframe"
                );
            }
            GopSnapshot {
                keyframe: Arc::clone(&current.keyframe),
                newest: None,
                frames: 1,
                bytes: current.keyframe.payload.len(),
                truncated: true,
            }
        } else {
            GopSnapshot {
                keyframe: Arc::clone(&current.keyframe),
                newest: Some(Arc::new(GopLink {
                    frame: Arc::clone(frame),
                    previous: current.newest.clone(),
                })),
                frames: count,
                bytes: total,
                truncated: false,
            }
        };
        self.gop.store(Some(Arc::new(next)));
    }
}

impl fmt::Debug for Track {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Track")
            .field("id", &self.id)
            .field("clock_rate", &self.clock_rate)
            .field("codec", &self.codec.load())
            .field("packet_subscribers", &self.packets.receiver_count())
            .field("frame_subscribers", &self.frames.receiver_count())
            .field("gop", &self.gop.load().as_ref().map(|gop| gop.bytes))
            .field("epoch", &self.epoch())
            .field("closed", &self.is_closed())
            .field("limits", &self.limits)
            .field("stats", &self.counters.snapshot())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use bytes::Bytes;

    use super::*;
    use crate::clock::{Clock as _, SystemClock};
    use crate::media::{MediaTime, RtpHeaderFields};
    use crate::test_logs::Logs;

    fn video_track(limits: TrackLimits) -> Track {
        Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            limits,
            SystemClock.now(),
        )
    }

    fn packet(seq: u16) -> MediaPacket {
        MediaPacket {
            arrival: SystemClock.now(),
            rtp: RtpHeaderFields {
                pt: 96,
                seq,
                ts: u32::from(seq) * 3000,
                marker: false,
                ssrc: 1,
            },
            frame_start: false,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0_u8; 10][..]),
        }
    }

    fn frame(keyframe: bool, bytes: usize) -> MediaFrame {
        let now = SystemClock.now();
        MediaFrame {
            ts: MediaTime::ZERO,
            wallclock: now,
            arrival: now,
            keyframe,
            discontinuity: false,
            epoch: 0,
            payload: Bytes::from(vec![0; bytes]),
        }
    }

    #[test]
    fn track_ids_display_as_letter_and_index() {
        let id = TrackId::new(Kind::Audio, 1);
        assert_eq!(id.to_string(), "a1");
        assert_eq!(id.kind(), Kind::Audio);
        assert_eq!(id.index(), 1);
        assert_eq!(TrackId::new(Kind::Video, 0).to_string(), "v0");
    }

    #[tokio::test]
    async fn packets_fan_out_by_reference_to_every_subscriber() {
        let track = video_track(TrackLimits::default());
        let mut a = track.subscribe_packets();
        let mut b = track.subscribe_packets();
        assert_eq!(track.packet_subscribers(), 2);

        track.publish_packet(packet(1));
        let from_a = a.recv().await.unwrap();
        let from_b = b.recv().await.unwrap();
        assert!(Arc::ptr_eq(&from_a, &from_b));
        assert_eq!(from_a.rtp.seq, 1);
        assert!(a.is_empty());
        assert_eq!(b.len(), 0);

        let stats = track.stats();
        assert_eq!(stats.packets, 1);
        assert_eq!(stats.packet_bytes, 10);
    }

    #[tokio::test]
    async fn subscriptions_start_at_the_live_edge() {
        let track = video_track(TrackLimits::default());
        track.publish_packet(packet(1));
        let mut sub = track.subscribe_packets();
        track.publish_packet(packet(2));
        assert_eq!(sub.recv().await.unwrap().rtp.seq, 2);
        assert_eq!(sub.try_recv().unwrap(), None);
    }

    #[tokio::test]
    async fn a_slow_subscriber_lags_and_the_producer_never_waits() {
        let limits = TrackLimits {
            packet_capacity: 2,
            ..TrackLimits::default()
        };
        let track = video_track(limits);
        let mut sub = track.subscribe_packets();
        for seq in 1..=5 {
            track.publish_packet(packet(seq));
        }
        assert_eq!(sub.recv().await, Err(SubscriptionError::Lagged(3)));
        assert_eq!(sub.recv().await.unwrap().rtp.seq, 4);
        assert_eq!(sub.try_recv().unwrap().unwrap().rtp.seq, 5);
        assert_eq!(track.stats().packets, 5);
    }

    #[tokio::test]
    async fn try_recv_reports_lag_and_closure() {
        let limits = TrackLimits {
            packet_capacity: 0, // treated as 1
            ..TrackLimits::default()
        };
        let track = video_track(limits);
        let mut sub = track.subscribe_packets();
        track.publish_packet(packet(1));
        track.publish_packet(packet(2));
        assert_eq!(sub.try_recv(), Err(SubscriptionError::Lagged(1)));
        assert_eq!(sub.try_recv().unwrap().unwrap().rtp.seq, 2);
        drop(track);
        assert_eq!(sub.try_recv(), Err(SubscriptionError::Closed));
        assert_eq!(sub.recv().await, Err(SubscriptionError::Closed));
    }

    #[test]
    fn subscription_errors_convert_from_the_channel_errors() {
        assert_eq!(
            SubscriptionError::from(broadcast::error::RecvError::Lagged(4)),
            SubscriptionError::Lagged(4)
        );
        assert_eq!(
            SubscriptionError::from(broadcast::error::RecvError::Closed),
            SubscriptionError::Closed
        );
        assert_eq!(
            SubscriptionError::Lagged(4).to_string(),
            "subscriber lagged: 4 items skipped"
        );
        assert_eq!(SubscriptionError::Closed.to_string(), "track closed");
    }

    #[test]
    fn gop_age_counts_from_the_capture_time_but_never_from_after_the_arrival() {
        let track = video_track(TrackLimits::default());
        let now = SystemClock.now() + Duration::from_secs(60);
        assert!(track.publish_frame(MediaFrame {
            wallclock: now.checked_sub(Duration::from_secs(12)).unwrap(),
            arrival: now.checked_sub(Duration::from_secs(10)).unwrap(),
            ..frame(true, 1)
        }));
        assert_eq!(
            track.gop().unwrap().age(now),
            Duration::from_secs(12),
            "captured before it arrived: by its capture time"
        );
        // Security review WRK-1: a Sender Report maps it hours ahead.
        assert!(track.publish_frame(MediaFrame {
            wallclock: now + Duration::from_hours(6),
            arrival: now.checked_sub(Duration::from_secs(10)).unwrap(),
            ..frame(true, 1)
        }));
        assert_eq!(track.gop().unwrap().age(now), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn frames_reach_the_side_branch_and_the_gop_cache() {
        let track = video_track(TrackLimits::default());
        let mut frames = track.subscribe_frames();
        assert!(track.gop().is_none());

        assert!(track.publish_frame(frame(false, 100)), "accepted");
        assert!(track.gop().is_none(), "no keyframe yet: nothing to join to");

        assert!(track.publish_frame(frame(true, 1000)));
        assert!(track.publish_frame(frame(false, 100)));
        assert!(track.publish_frame(frame(false, 200)));
        let gop = track.gop().unwrap();
        assert!(gop.keyframe().keyframe);
        assert_eq!(gop.frame_count(), 3);
        assert_eq!(
            gop.frames().map(|f| f.payload.len()).collect::<Vec<_>>(),
            [1000, 100, 200],
            "a joiner gets the keyframe first, then the rest in decode order"
        );
        assert_eq!(gop.bytes(), 1300);
        assert!(!gop.truncated());
        assert!(gop.age(SystemClock.now()) < Duration::from_secs(5));

        assert!(track.publish_frame(frame(true, 500)));
        let gop = track.gop().unwrap();
        assert_eq!(gop.frame_count(), 1);
        assert_eq!(gop.frames().count(), 1);
        assert_eq!(gop.bytes(), 500);

        for _ in 0..5 {
            assert!(frames.recv().await.is_ok());
        }
        assert!(frames.is_empty());
        let stats = track.stats();
        assert_eq!(stats.frames, 5);
        assert_eq!(stats.frame_bytes, 1900);
        assert_eq!(stats.keyframes, 2);
    }

    #[test]
    fn gop_cache_keeps_only_the_keyframe_once_the_gop_outgrows_the_cap() {
        let limits = TrackLimits {
            gop_cache_bytes: 1000,
            max_frame_bytes: 1000,
            ..TrackLimits::default()
        };
        let track = video_track(limits);
        assert!(track.publish_frame(frame(true, 600)));
        assert!(track.publish_frame(frame(false, 300)));
        assert_eq!(track.gop().unwrap().bytes(), 900);
        assert!(track.publish_frame(frame(false, 100)));
        let gop = track.gop().unwrap();
        assert_eq!(gop.bytes(), 1000, "exactly the cap still fits");
        assert!(!gop.truncated());
        assert_eq!(gop.frame_count(), 3);

        assert!(
            track.publish_frame(frame(false, 300)),
            "accepted on the side branch"
        );
        let gop = track.gop().unwrap();
        assert!(gop.truncated());
        assert_eq!(gop.frame_count(), 1);
        assert_eq!(gop.frames().count(), 1);
        assert_eq!(gop.bytes(), 600);

        assert!(track.publish_frame(frame(false, 10)));
        assert!(
            track.gop().unwrap().truncated(),
            "stays truncated until the next keyframe"
        );

        assert!(
            track.publish_frame(frame(true, 1000)),
            "a keyframe of exactly the cap fits"
        );
        let gop = track.gop().unwrap();
        assert!(!gop.truncated());
        assert_eq!(gop.bytes(), 1000);
    }

    #[test]
    fn gop_cache_keeps_only_the_keyframe_once_the_gop_has_more_frames_than_the_cap() {
        let limits = TrackLimits {
            gop_cache_frames: 4,
            ..TrackLimits::default()
        };
        let track = video_track(limits);
        assert!(track.publish_frame(frame(true, 50)));
        for _ in 0..3 {
            assert!(track.publish_frame(frame(false, 2)));
        }
        let gop = track.gop().unwrap();
        assert_eq!(gop.frame_count(), 4, "exactly the cap still fits");
        assert_eq!(gop.frames().count(), 4);
        assert_eq!(gop.bytes(), 56);
        assert!(!gop.truncated());

        assert!(
            track.publish_frame(frame(false, 2)),
            "accepted on the side branch"
        );
        let gop = track.gop().unwrap();
        assert!(gop.truncated());
        assert_eq!(gop.frame_count(), 1);
        assert_eq!(gop.bytes(), 50);
        assert!(gop.frames().all(|f| f.keyframe), "a still for joiners");

        assert!(track.publish_frame(frame(false, 2)));
        assert!(
            track.gop().unwrap().truncated(),
            "stays truncated until the next keyframe"
        );
        assert!(track.publish_frame(frame(true, 60)));
        assert!(track.publish_frame(frame(false, 2)));
        let gop = track.gop().unwrap();
        assert!(!gop.truncated());
        assert_eq!(gop.frame_count(), 2);
    }

    #[test]
    fn a_frame_count_cap_of_zero_still_keeps_the_keyframe() {
        let limits = TrackLimits {
            gop_cache_frames: 0,
            ..TrackLimits::default()
        };
        let track = video_track(limits);
        assert!(track.publish_frame(frame(true, 50)));
        let gop = track.gop().unwrap();
        assert!(!gop.truncated());
        assert_eq!(gop.frame_count(), 1);
        assert!(track.publish_frame(frame(false, 2)));
        assert!(track.gop().unwrap().truncated());
    }

    #[test]
    fn many_tiny_frames_without_a_keyframe_stay_bounded_by_count() {
        // WRK-2: a camera sending a tiny access unit (an AUD or SEI) per
        // packet never reaches the byte cap; the frame cap bounds it.
        let track = video_track(TrackLimits::default());
        assert!(track.publish_frame(frame(true, 1000)));
        let tiny = 10 * DEFAULT_GOP_CACHE_FRAMES;
        for _ in 0..tiny {
            assert!(track.publish_frame(frame(false, 2)));
            let gop = track.gop().unwrap();
            assert!(gop.frame_count() <= DEFAULT_GOP_CACHE_FRAMES);
            assert!(gop.bytes() <= DEFAULT_GOP_CACHE_BYTES);
        }
        let gop = track.gop().unwrap();
        assert!(gop.truncated());
        assert_eq!(gop.frame_count(), 1);
        assert_eq!(gop.bytes(), 1000);
        assert!(gop.keyframe().keyframe);
    }

    #[test]
    fn a_frame_links_onto_the_previous_snapshot_without_copying_it() {
        let track = video_track(TrackLimits::default());
        assert!(track.publish_frame(frame(true, 10)));
        assert!(track.publish_frame(frame(false, 1)));
        let before = track.gop().unwrap();
        assert!(track.publish_frame(frame(false, 2)));
        let after = track.gop().unwrap();
        let newest = after.newest.as_ref().unwrap();
        assert_eq!(newest.frame.payload.len(), 2);
        assert!(
            Arc::ptr_eq(
                newest.previous.as_ref().unwrap(),
                before.newest.as_ref().unwrap()
            ),
            "the earlier frames are shared, not rebuilt"
        );
        assert!(Arc::ptr_eq(after.keyframe(), before.keyframe()));
        assert_eq!(
            before.frames().map(|f| f.payload.len()).collect::<Vec<_>>(),
            [10, 1],
            "an older snapshot is unchanged"
        );
        assert_eq!(
            after.frames().map(|f| f.payload.len()).collect::<Vec<_>>(),
            [10, 1, 2]
        );
    }

    #[test]
    fn dropping_a_long_gop_does_not_recurse_per_frame() {
        // The derived drop of a million links overflows a test thread's
        // stack; the unlinking loop does not.
        let shared = Arc::new(frame(false, 0));
        let mut newest = None;
        for _ in 0..1_000_000 {
            newest = Some(Arc::new(GopLink {
                frame: Arc::clone(&shared),
                previous: newest,
            }));
        }
        let held = newest.as_ref().and_then(|link| link.previous.clone());
        drop(newest);
        assert!(held.is_some(), "a link another snapshot holds survives");
        drop(held);
        assert_eq!(Arc::strong_count(&shared), 1, "every link was freed");
    }

    #[test]
    fn gop_snapshot_debug_is_a_summary() {
        let track = video_track(TrackLimits::default());
        assert!(track.publish_frame(frame(true, 7)));
        assert!(track.publish_frame(frame(false, 3)));
        let text = format!("{:?}", track.gop().unwrap());
        assert!(text.starts_with("GopSnapshot {"), "{text}");
        assert!(text.contains("frames: 2"), "{text}");
        assert!(text.contains("bytes: 10"), "{text}");
        assert!(text.contains("truncated: false"), "{text}");
    }

    #[tokio::test]
    async fn oversize_frames_are_dropped_and_counted() {
        let limits = TrackLimits {
            max_frame_bytes: 100,
            ..TrackLimits::default()
        };
        let track = video_track(limits);
        let mut frames = track.subscribe_frames();
        assert!(!track.publish_frame(frame(true, 101)));
        assert!(track.gop().is_none());
        assert!(frames.is_empty());
        let stats = track.stats();
        assert_eq!(stats.frames_dropped_oversize, 1);
        assert_eq!(stats.frames, 0);
        assert!(track.publish_frame(frame(true, 100)));
        assert!(frames.recv().await.is_ok());
        // Frames over the browser limit are the source's to report.
        assert_eq!(track.stats().frames_over_browser_limit, 0);
        track.count_frame_over_browser_limit();
        assert_eq!(track.stats().frames_over_browser_limit, 1);
    }

    #[test]
    fn audio_tracks_have_no_gop_cache() {
        let track = Track::new(
            TrackId::new(Kind::Audio, 0),
            Codec::Pcmu,
            8_000,
            TrackLimits::default(),
            SystemClock.now(),
        );
        assert!(track.publish_frame(frame(true, 160)));
        assert!(track.gop().is_none());
        assert_eq!(track.kind(), Kind::Audio);
        assert_eq!(track.clock_rate(), 8_000);
        assert_eq!(track.stats().keyframes, 1);
    }

    #[test]
    fn capture_times_extrapolate_from_the_last_frame_across_the_rfc3550_5_1_wrap() {
        let track = Track::new(
            TrackId::new(Kind::Audio, 1),
            Codec::Opus { channels: 1 },
            48_000,
            TrackLimits::default(),
            SystemClock.now(),
        );
        assert_eq!(track.capture_time(0, 0), None, "no frame yet");
        let at = SystemClock.now() + Duration::from_secs(10);
        // Unwrapped, the frame is at -480: 32-bit timestamp 2³² − 480.
        assert!(track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(-480),
            wallclock: at,
            ..frame(true, 3)
        }));
        assert_eq!(track.capture_time(0, u32::MAX - 479), Some(at));
        assert_eq!(
            track.capture_time(0, 480),
            Some(at + Duration::from_millis(20)),
            "ahead over the wrap"
        );
        assert_eq!(
            track.capture_time(0, u32::MAX - 959),
            Some(at.checked_sub(Duration::from_millis(10)).unwrap()),
            "behind"
        );
        assert_eq!(track.capture_time(1, 480), None, "another epoch");
        track.start_epoch();
        assert!(track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(96_000),
            wallclock: at,
            ..frame(true, 3)
        }));
        assert_eq!(
            track.capture_time(1, 48_000),
            Some(at.checked_sub(Duration::from_secs(1)).unwrap())
        );
        assert_eq!(track.capture_time(0, 48_000), None, "the old epoch");
    }

    #[tokio::test]
    async fn codec_change_is_published_once_and_only_when_different() {
        let track = Arc::new(video_track(TrackLimits::default()));
        let mut sub = track.subscribe(Unit::Packets);
        assert_eq!(track.codec().family(), CodecFamily::H264);
        track.set_codec(Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        });
        let h265 = Codec::H265 {
            vps: None,
            sps: None,
            pps: None,
        };
        track.set_codec(h265.clone());
        assert_eq!(track.codec().family(), CodecFamily::H265);
        assert_eq!(
            sub.next().await,
            Some(TrackEvent::TrackChanged(Arc::new(h265)))
        );
        assert_eq!(track.id(), TrackId::new(Kind::Video, 0));
        assert_eq!(track.limits(), TrackLimits::default());
        assert_eq!(sub.track().id(), track.id());
    }

    /// A video track whose activity is timed from `origin`.
    fn video_track_at(origin: Instant) -> Arc<Track> {
        Arc::new(Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            90_000,
            TrackLimits::default(),
            origin,
        ))
    }

    /// An H.264 descriptor whose SPS is the one byte `sps`.
    fn h264_with_sps(sps: u8) -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: Some(Bytes::from(vec![0x67, sps])),
            pps: None,
        }
    }

    #[tokio::test]
    async fn a_codec_changed_on_every_frame_is_logged_once_per_interval_and_always_published() {
        let (logs, _guard) = Logs::capture();
        let at = SystemClock.now();
        let track = video_track_at(at);
        let mut sub = track.subscribe(Unit::Packets);
        for n in 0..10_u8 {
            track.set_codec(h264_with_sps(n % 2));
        }
        let lines = logs.lines(tracing::Level::INFO, "track codec changed");
        assert_eq!(lines.len(), 1, "timed from the origin before any item");
        assert!(lines[0].fields.ends_with(" count=1"), "{lines:?}");
        track.publish_packet(MediaPacket {
            arrival: at + Duration::from_secs(9),
            ..packet(1)
        });
        track.set_codec(h264_with_sps(0));
        assert_eq!(logs.count(tracing::Level::INFO, "track codec changed"), 1);
        track.publish_packet(MediaPacket {
            arrival: at + crate::throttle::SUMMARY_INTERVAL,
            ..packet(2)
        });
        track.set_codec(h264_with_sps(1));
        let lines = logs.lines(tracing::Level::INFO, "track codec changed");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].fields.ends_with(" count=11"), "{lines:?}");
        assert_eq!(*track.codec(), h264_with_sps(1));
        // Every change reached the subscriber.
        let mut changes = 0;
        while let Some(TrackEvent::TrackChanged(_)) = queued(&mut sub) {
            changes += 1;
        }
        assert_eq!(changes, 12);
    }

    #[tokio::test]
    async fn a_subscriber_s_control_lags_are_warned_once_per_interval() {
        let (logs, _guard) = Logs::capture();
        let at = SystemClock.now();
        let track = video_track_at(at);
        let mut sub = track.subscribe(Unit::Packets);
        let lag = |sub: &mut TrackSubscription| {
            for _ in 0..=CONTROL_CAPACITY {
                track.start_epoch();
            }
            assert!(matches!(queued(sub), Some(TrackEvent::EpochStart { .. })));
        };
        lag(&mut sub);
        lag(&mut sub);
        let warned =
            |logs: &Logs| logs.lines(tracing::Level::WARN, "subscriber missed control events");
        let lines = warned(&logs);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].fields.ends_with(" count=1"), "{lines:?}");
        track.publish_packet(MediaPacket {
            arrival: at + crate::throttle::SUMMARY_INTERVAL,
            ..packet(1)
        });
        lag(&mut sub);
        let lines = warned(&logs);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].fields.ends_with(" count=2"), "{lines:?}");
    }

    /// `sub`'s next event, which must be queued already: polled once, so
    /// a missing event fails the test instead of hanging it.
    fn queued(sub: &mut TrackSubscription) -> Option<TrackEvent> {
        let mut next = std::pin::pin!(sub.next());
        let polled = next
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        let std::task::Poll::Ready(event) = polled else {
            panic!("no event queued");
        };
        event
    }

    #[tokio::test]
    async fn epochs_stamp_items_and_reach_subscribers_first() {
        let track = Arc::new(video_track(TrackLimits::default()));
        let mut packets = track.subscribe(Unit::Packets);
        let mut frames = track.subscribe(Unit::Frames);
        assert_eq!(track.epoch(), 0);

        track.publish_packet(packet(1));
        assert_eq!(track.start_epoch(), 1);
        track.publish_packet(packet(2));
        assert!(track.publish_frame(frame(true, 10)));
        assert!(track.publish_frame(frame(false, 10)));

        // Everything is queued already: polled once each, so a frame the
        // track failed to publish fails here rather than hanging.
        // The control event is delivered before the packet queued earlier.
        assert_eq!(
            queued(&mut packets),
            Some(TrackEvent::EpochStart { epoch: 1 })
        );
        let Some(TrackEvent::Packet(first)) = queued(&mut packets) else {
            panic!("packet expected");
        };
        assert_eq!((first.rtp.seq, first.epoch), (1, 0));
        let Some(TrackEvent::Packet(second)) = queued(&mut packets) else {
            panic!("packet expected");
        };
        assert_eq!((second.rtp.seq, second.epoch), (2, 1));

        assert_eq!(
            queued(&mut frames),
            Some(TrackEvent::EpochStart { epoch: 1 })
        );
        let Some(TrackEvent::Frame(keyframe)) = queued(&mut frames) else {
            panic!("frame expected");
        };
        assert!(keyframe.discontinuity && keyframe.epoch == 1);
        let Some(TrackEvent::Frame(next)) = queued(&mut frames) else {
            panic!("frame expected");
        };
        assert!(!next.discontinuity, "only the first frame of an epoch");
    }

    #[test]
    fn packets_carry_their_frames_lateness_measured_per_epoch() {
        let track = video_track(TrackLimits::default());
        let mut packets = track.subscribe_packets();
        let t0 = SystemClock.now();
        let at = |arrival: Instant, ts: u32, frame_start: bool| MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                ts,
                ..packet(0).rtp
            },
            frame_start,
            // A source's value is overwritten.
            lateness: Duration::from_secs(9),
            ..packet(0)
        };
        let ms = Duration::from_millis;
        track.publish_packet(at(t0, 0, true));
        // 33 ms of video read 400 ms later: an ingest stall.
        track.publish_packet(at(t0 + ms(400), 33 * 90, true));
        track.publish_packet(at(t0 + ms(450), 33 * 90, false));
        // A reconnect: new timestamps, measured afresh.
        let _epoch = track.start_epoch();
        track.publish_packet(at(t0 + ms(500), 7_777_777, true));
        let lateness: Vec<_> = std::iter::from_fn(|| packets.try_recv().unwrap())
            .map(|p| p.lateness)
            .collect();
        assert_eq!(lateness, [ms(0), ms(367), ms(367), ms(0)]);
    }

    #[tokio::test]
    async fn source_loss_and_lag_are_explicit_events() {
        let limits = TrackLimits {
            packet_capacity: 1,
            ..TrackLimits::default()
        };
        let track = Arc::new(video_track(limits));
        let mut sub = track.subscribe(Unit::Packets);
        track.set_source_lost(true);
        track.set_source_lost(false);
        track.publish_packet(packet(1));
        track.publish_packet(packet(2));
        assert_eq!(sub.next().await, Some(TrackEvent::SourceLost));
        assert_eq!(sub.next().await, Some(TrackEvent::SourceRestored));
        assert_eq!(sub.next().await, Some(TrackEvent::Gap { skipped: 1 }));
        assert!(matches!(sub.next().await, Some(TrackEvent::Packet(p)) if p.rtp.seq == 2));
        track.close();
        track.close();
        assert!(track.is_closed());
        assert_eq!(sub.next().await, None);
        assert_eq!(sub.next().await, None, "stays closed");
        track.publish_packet(packet(3));
        assert!(!track.publish_frame(frame(true, 1)));
        track.set_source_lost(true);
        assert_eq!(track.stats().packets, 2, "nothing counted after close");
        let mut late = track.subscribe(Unit::Frames);
        assert_eq!(
            late.next().await,
            None,
            "a subscription after close ends at once"
        );
    }

    #[tokio::test]
    async fn a_subscriber_that_misses_control_events_is_warned_and_continues() {
        let track = Arc::new(video_track(TrackLimits::default()));
        let mut sub = track.subscribe(Unit::Frames);
        for _ in 0..(CONTROL_CAPACITY + 3) {
            track.start_epoch();
        }
        // The first three epochs were lost; the rest arrive in order.
        assert_eq!(sub.next().await, Some(TrackEvent::EpochStart { epoch: 4 }));
        let mut remaining = 0;
        while let Some(TrackEvent::EpochStart { .. }) = sub.next().await {
            remaining += 1;
            if remaining == CONTROL_CAPACITY - 1 {
                break;
            }
        }
        assert_eq!(remaining, CONTROL_CAPACITY - 1);
        assert!(sub.track().gop().is_none());
    }

    #[test]
    fn last_activity_follows_the_newest_item() {
        let origin = SystemClock.now();
        let track = Track::new(
            TrackId::new(Kind::Video, 0),
            Codec::Mjpeg,
            90_000,
            TrackLimits::default(),
            origin,
        );
        assert_eq!(track.last_activity(), None);
        let mut p = packet(1);
        p.arrival = origin + Duration::from_millis(40);
        track.publish_packet(p);
        assert_eq!(
            track.last_activity(),
            Some(origin + Duration::from_millis(40))
        );
        let mut f = frame(true, 1);
        f.arrival = origin + Duration::from_millis(30);
        assert!(track.publish_frame(f));
        assert_eq!(
            track.last_activity(),
            Some(origin + Duration::from_millis(40)),
            "an older item never moves it back"
        );
        let mut f = frame(false, 1);
        f.arrival = origin + Duration::from_millis(50);
        f.wallclock = origin + Duration::from_hours(6);
        assert!(track.publish_frame(f));
        assert_eq!(
            track.last_activity(),
            Some(origin + Duration::from_millis(50)),
            "a frame counts by its arrival, not a capture time hours ahead (WRK-1)"
        );
        let mut early = packet(2);
        early.arrival = origin.checked_sub(Duration::from_secs(1)).unwrap();
        track.publish_packet(early);
        assert_eq!(
            track.last_activity(),
            Some(origin + Duration::from_millis(50)),
            "before the origin counts as the origin"
        );
    }

    #[test]
    fn closed_is_not_a_sink_event() {
        assert_eq!(TrackEvent::from_control(TrackControlEvent::Closed), None);
        assert_eq!(
            TrackEvent::from_control(TrackControlEvent::SourceRestored),
            Some(TrackEvent::SourceRestored)
        );
    }

    #[test]
    fn control_events_convert_to_track_events() {
        let codec = Arc::new(Codec::Pcmu);
        assert_eq!(
            TrackEvent::from_control(TrackControlEvent::TrackChanged(Arc::clone(&codec))),
            Some(TrackEvent::TrackChanged(codec))
        );
        assert_eq!(
            TrackEvent::from_control(TrackControlEvent::EpochStart { epoch: 3 }),
            Some(TrackEvent::EpochStart { epoch: 3 })
        );
        assert_eq!(
            TrackEvent::from_control(TrackControlEvent::SourceLost),
            Some(TrackEvent::SourceLost)
        );
    }

    #[test]
    fn debug_summarizes_the_track() {
        let track = video_track(TrackLimits::default());
        assert!(track.publish_frame(frame(true, 7)));
        let text = format!("{track:?}");
        assert!(
            text.contains("id: TrackId { kind: Video, index: 0 }"),
            "{text}"
        );
        assert!(text.contains("gop: Some(7)"), "{text}");
        assert!(text.contains("packet_subscribers: 0"), "{text}");
    }

    #[test]
    fn stats_default_to_zero_and_add_bytes_accumulates() {
        assert_eq!(TrackStats::default().packets, 0);
        let counter = AtomicU64::new(7);
        Counters::add_bytes(&counter, 5);
        Counters::add_bytes(&counter, usize::MAX);
        assert_eq!(
            counter.load(Ordering::Relaxed),
            12_u64.wrapping_add(u64::try_from(usize::MAX).unwrap_or(u64::MAX))
        );
    }

    use crate::codec::CodecFamily;
}

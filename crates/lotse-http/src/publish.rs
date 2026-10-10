//! Publishes a demultiplexed program on the connection's tracks, as the
//! RTSP source publishes a camera's packets: the tracks declared from the
//! program's [`Layout`], each video unit through lotse-codec's
//! `FramedNormalizer` into live packets ([`Track::publish_packet`]) and a
//! side-branch frame ([`Track::publish_frame`]), the codec updated when a
//! unit brings a new sequence parameter set, AAC frames on the side branch.
//!
//! Units are paced by [`Pacer`] on the program's decoding time; a unit's
//! arrival is the instant it is released, and its capture time is the
//! connection's clock mapping of that arrival: MPEG-TS gives no sync hint
//! here (the program clock reference is not read), the pacer is what puts
//! the tracks on one base.
//!
//! The first video and the first audio track of the program are carried,
//! as the RTSP source carries the first of each in the SDP. A codec
//! lotse cannot carry is declared [`Codec::Unsupported`], so negotiation
//! can say why, and its units are dropped.
//!
//! A new timeline (an epoch) restarts everything that holds timestamp
//! state: one discontinuity for every track together, the clock mapping
//! forgotten, the pacer re-anchored at the next unit, the normalizers and
//! the timestamp guards fresh. It comes from the caller (an HLS
//! discontinuity, RFC 8216 §4.3.2.3), from the pacer (a unit due too far
//! ahead) or, as a backstop, from a track's [`TimestampGuard`]: a
//! presentation time that leaves its timeline against the release
//! instants, which the pacer alone would release at once and keep doing so.
//!
//! RTP fields of the live path: the timestamp is the unit's presentation
//! time on the track's clock, wrapped to 32 bits (RFC 3550 §5.1); the
//! sequence numbers count each track's packets, and the payload type and
//! SSRC are fixed, since every session writes its own.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_codec::h264::{
    self, DEFAULT_MAX_PAYLOAD, FrameOverLimit, LIBWEBRTC_MAX_FRAME_PACKETS, NormalizedPacket,
};
use lotse_codec::h265;
use lotse_core::discontinuity::TimestampGuard;
use lotse_core::ingest::IngestCounters;
use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields};
use lotse_core::source::{ClockInput, SourceError, TrackPublisher, TrackSet};
use lotse_core::throttle::Throttle;
use lotse_core::track::Track;
use lotse_core::{Codec, Kind};

use crate::media::{Layout, LayoutTrack, Unit};
use crate::pace::{Pace, Pacer};

/// The payload type on the live path's packets: the first dynamic one
/// (RFC 3551 §6), for the logs; sessions write their negotiated one.
const PAYLOAD_TYPE: u8 = 96;

/// The SSRC on the live path's packets ("HTTP"); sessions write their own.
const SSRC: u32 = 0x4854_5450;

/// A track's identity in a layout: what it was declared with. Two
/// layouts with the same carried tracks need no new declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Declared {
    /// Video or audio.
    kind: Kind,
    /// The codec as the layout names it.
    codec: Codec,
    /// The clock of its timestamps.
    clock_rate: u32,
}

impl Declared {
    /// The declaration of `track`.
    fn of(track: &LayoutTrack) -> Self {
        Self {
            kind: track.kind,
            codec: track.codec.clone(),
            clock_rate: track.clock_rate,
        }
    }
}

/// The program's carried tracks changed: they need a new declaration,
/// which a new connection attempt makes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the program's tracks changed from {was} to {now}")]
pub struct LayoutChanged {
    /// The carried tracks before, described.
    was: String,
    /// The carried tracks now, described.
    now: String,
}

/// Describes carried tracks for a log line or an error.
fn describe(declared: &[Declared]) -> String {
    let mut out = String::new();
    for (i, track) in declared.iter().enumerate() {
        let separator = if i == 0 { "" } else { ", " };
        let _infallible = write!(
            out,
            "{separator}{} {} at {} Hz",
            track.kind,
            track.codec.name(),
            track.clock_rate
        );
    }
    if out.is_empty() {
        out.push_str("nothing");
    }
    out
}

/// The tracks of `layout` that are carried, with their index in it: the
/// first video and the first audio, in the order of their kinds, which is
/// the order of their track ids whatever the program map's.
fn choose(layout: &Layout) -> Vec<(usize, &LayoutTrack)> {
    let mut chosen: Vec<(usize, &LayoutTrack)> = Vec::new();
    for (index, track) in layout.tracks.iter().enumerate() {
        if chosen.iter().all(|(_, other)| other.kind != track.kind) {
            chosen.push((index, track));
        }
    }
    chosen.sort_by_key(|(_, track)| track.kind);
    chosen
}

/// The carried track of each of `layout`'s tracks, by index.
fn routes(layout: &Layout, chosen: &[(usize, &LayoutTrack)]) -> Vec<Option<usize>> {
    let mut routes = vec![None; layout.tracks.len()];
    for (carried, (index, _)) in chosen.iter().enumerate() {
        if let Some(route) = routes.get_mut(*index) {
            *route = Some(carried);
        }
    }
    routes
}

/// The 32-bit RTP timestamp of a presentation time (RFC 3550 §5.1: it
/// wraps).
fn rtp_ts(ts: i64) -> u32 {
    let [a, b, c, d, ..] = ts.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

/// Both normalization layers of a video track.
#[derive(Debug)]
enum Video {
    /// H.264.
    H264(h264::FramedNormalizer),
    /// H.265.
    H265(h265::FramedNormalizer),
}

/// One access unit out of the side branch's layer.
#[derive(Debug)]
struct Frame {
    /// An IDR or IRAP picture, or a recovery point.
    keyframe: bool,
    /// Annex B, parameter sets in-band before a keyframe.
    payload: Bytes,
    /// The codec the track has from this unit on, when it brought a new
    /// sequence parameter set.
    codec: Option<Codec>,
}

impl Video {
    /// Fresh layers for `codec` with units up to `max_frame_bytes`,
    /// seeded with the parameter sets the codec carries: none from
    /// MPEG-TS, which carries them in band; those of the `avcC` or
    /// `hvcC` from fragmented MP4 (ISO/IEC 14496-15 §5.3.3, §8.3.3).
    /// `None` for codecs without a normalizer.
    fn new(codec: &Codec, max_frame_bytes: usize) -> Option<Self> {
        match codec {
            Codec::H264 { sps, pps, .. } => Some(Self::H264(h264::FramedNormalizer::new(
                DEFAULT_MAX_PAYLOAD,
                max_frame_bytes,
                h264::ParameterSets {
                    sps: sps.clone(),
                    pps: pps.clone(),
                },
            ))),
            Codec::H265 { vps, sps, pps } => Some(Self::H265(h265::FramedNormalizer::new(
                DEFAULT_MAX_PAYLOAD,
                max_frame_bytes,
                h265::ParameterSets {
                    vps: vps.clone(),
                    sps: sps.clone(),
                    pps: pps.clone(),
                },
            ))),
            _ => None,
        }
    }

    /// Normalizes one Annex B access unit with RTP timestamp `ts`: its
    /// live packets are appended to `packets`; its side-branch unit, if
    /// any, is returned, with the access unit that went out in too many
    /// packets.
    fn push(
        &mut self,
        ts: u32,
        access_unit: &[u8],
        packets: &mut Vec<NormalizedPacket>,
    ) -> (Vec<Frame>, Option<FrameOverLimit>) {
        match self {
            Self::H264(normalizer) => {
                let mut units = Vec::new();
                normalizer.push(ts, access_unit, packets, &mut units);
                let frames = units
                    .into_iter()
                    .map(|unit| {
                        let codec = unit.sps.map(|info| {
                            let sets = normalizer.frame_layer().parameter_sets();
                            Codec::H264 {
                                profile_level_id: Some(info.profile_level_id),
                                sps: sets.sps.clone(),
                                pps: sets.pps.clone(),
                            }
                        });
                        Frame {
                            keyframe: unit.keyframe,
                            payload: unit.payload,
                            codec,
                        }
                    })
                    .collect();
                (frames, normalizer.take_frame_over_limit())
            }
            Self::H265(normalizer) => {
                let mut units = Vec::new();
                normalizer.push(ts, access_unit, packets, &mut units);
                let frames = units
                    .into_iter()
                    .map(|unit| {
                        let codec = unit.sps.map(|_| {
                            let sets = normalizer.frame_layer().parameter_sets();
                            Codec::H265 {
                                vps: sets.vps.clone(),
                                sps: sets.sps.clone(),
                                pps: sets.pps.clone(),
                            }
                        });
                        Frame {
                            keyframe: unit.keyframe,
                            payload: unit.payload,
                            codec,
                        }
                    })
                    .collect();
                (frames, normalizer.take_frame_over_limit())
            }
        }
    }
}

/// A carried track.
#[derive(Debug)]
struct Carried {
    /// Its track.
    track: Arc<Track>,
    /// Its codec as declared, for fresh normalizers.
    codec: Codec,
    /// The normalization layers, for H.264 and H.265.
    video: Option<Video>,
    /// AAC: each unit is a frame of the side branch.
    audio_frames: bool,
    /// Watches its timestamps against the release instants.
    guard: TimestampGuard,
    /// The sequence number of its next live packet.
    seq: u16,
    /// The rate limit of the `frame_over_browser_limit` warning.
    over_limit: Throttle,
}

impl Carried {
    /// The state for `declared`, on `track`.
    fn new(track: Arc<Track>, declared: &Declared) -> Self {
        Self {
            video: Video::new(&declared.codec, track.limits().max_frame_bytes),
            audio_frames: matches!(declared.codec, Codec::AacLc { .. }),
            codec: declared.codec.clone(),
            guard: TimestampGuard::new(declared.clock_rate),
            seq: 0,
            over_limit: Throttle::default(),
            track,
        }
    }
}

impl Carried {
    /// Publishes `unit`, released at `arrival`, with its capture time
    /// from `clock`; `packets` is the reused buffer of live packets.
    fn publish(
        &mut self,
        clock: &ClockInput,
        packets: &mut Vec<NormalizedPacket>,
        unit: Unit,
        arrival: Instant,
    ) {
        let ts = rtp_ts(unit.ts);
        let id = self.track.id();
        let frame = |keyframe, payload| MediaFrame {
            ts: MediaTime::from_ticks(unit.ts),
            wallclock: clock.map(id, ts, arrival),
            arrival,
            keyframe,
            discontinuity: false,
            epoch: 0,
            payload,
        };
        let Some(video) = self.video.as_mut() else {
            if self.audio_frames {
                self.track.publish_frame(frame(true, unit.payload));
            }
            return;
        };
        packets.clear();
        let (frames, over_limit) = video.push(ts, &unit.payload, packets);
        frame_over_limit(&self.track, &mut self.over_limit, arrival, over_limit);
        for out in packets.drain(..) {
            self.track.publish_packet(MediaPacket {
                arrival,
                rtp: RtpHeaderFields {
                    pt: PAYLOAD_TYPE,
                    seq: self.seq,
                    ts,
                    marker: out.marker,
                    ssrc: SSRC,
                },
                frame_start: out.frame_start,
                keyframe_start: out.keyframe_start,
                epoch: 0,
                lateness: Duration::ZERO,
                payload: Arc::from(out.payload.as_ref()),
            });
            self.seq = self.seq.wrapping_add(1);
        }
        for Frame {
            keyframe,
            payload,
            codec,
        } in frames
        {
            if let Some(codec) = codec {
                self.track.set_codec(codec);
            }
            self.track.publish_frame(frame(keyframe, payload));
        }
    }
}

/// Publishes one program on the tracks of one connection attempt.
#[derive(Debug)]
pub struct Publisher {
    /// The connection's tracks, for an epoch on all of them.
    set: Arc<TrackSet>,
    /// The connection's ingest counters.
    ingest: Arc<IngestCounters>,
    /// The connection's clock mapper.
    clock: ClockInput,
    /// Paces the units on the program's decoding time.
    pacer: Pacer,
    /// What the carried tracks were declared with, in order.
    declared: Vec<Declared>,
    /// The carried track of each track of the current layout.
    routes: Vec<Option<usize>>,
    /// The carried tracks.
    carried: Vec<Carried>,
    /// The live packets of the unit at hand, reused.
    packets: Vec<NormalizedPacket>,
    /// The rate limit of the lost-packets line.
    loss_log: Throttle,
}

impl Publisher {
    /// Declares the first video and the first audio track of `layout` on
    /// `tracks` and marks them ready; `clock` maps their arrivals, and the
    /// pacer waits at most `max_lead` for a unit (see [`Pacer::new`]).
    ///
    /// # Errors
    ///
    /// [`SourceError::Protocol`] for a program without a video or audio
    /// track.
    pub fn new(
        tracks: &mut TrackPublisher,
        clock: ClockInput,
        layout: &Layout,
        max_lead: Duration,
    ) -> Result<Self, SourceError> {
        let chosen = choose(layout);
        if chosen.is_empty() {
            return Err(SourceError::Protocol(
                "the program has no video or audio stream".into(),
            ));
        }
        let mut declared = Vec::new();
        let mut carried = Vec::new();
        for (_, track) in &chosen {
            let this = Declared::of(track);
            tracing::info!(
                program = layout.program_number,
                id = track.id,
                stream_type = track.stream_type,
                kind = %this.kind,
                codec = this.codec.name(),
                clock_rate = this.clock_rate,
                "http: declaring a track of the program"
            );
            let track = tracks.declare(this.kind, this.codec.clone(), this.clock_rate);
            carried.push(Carried::new(track, &this));
            declared.push(this);
        }
        tracks.ready();
        Ok(Self {
            set: Arc::clone(tracks.tracks()),
            ingest: tracks.ingest(),
            clock,
            pacer: Pacer::new(max_lead),
            routes: routes(layout, &chosen),
            declared,
            carried,
            packets: Vec::new(),
            loss_log: Throttle::default(),
        })
    }

    /// Takes the program's next layout: units from now on index it. The
    /// same carried tracks continue.
    ///
    /// # Errors
    ///
    /// [`LayoutChanged`] when the carried tracks differ: the caller ends
    /// the attempt, so the next one declares them anew.
    pub fn relayout(&mut self, layout: &Layout) -> Result<(), LayoutChanged> {
        let chosen = choose(layout);
        let now: Vec<Declared> = chosen
            .iter()
            .map(|(_, track)| Declared::of(track))
            .collect();
        if now != self.declared {
            return Err(LayoutChanged {
                was: describe(&self.declared),
                now: describe(&now),
            });
        }
        tracing::debug!(
            program = layout.program_number,
            tracks = layout.tracks.len(),
            "http: the program's layout repeated with the same tracks"
        );
        self.routes = routes(layout, &chosen);
        Ok(())
    }

    /// The carried track `unit` belongs to, if any.
    fn route(&self, unit: &Unit) -> Option<usize> {
        self.routes.get(unit.track).copied().flatten()
    }

    /// When to publish `unit`, offered at `now`: `None` for now, else the
    /// instant to offer it again at. A unit due further ahead than the
    /// pacer waits starts a new epoch, anchored at it.
    pub fn due(&mut self, unit: &Unit, now: Instant) -> Option<Instant> {
        self.route(unit)?;
        match self.pacer.pace(unit.decode_time, now) {
            Pace::Now => None,
            Pace::At(at) => Some(at),
            Pace::Jump { ahead } => {
                tracing::info!(
                    ahead_ms = ahead.as_millis(),
                    decode_time = unit.decode_time,
                    "http: the program's timestamps jumped ahead; new epoch"
                );
                self.new_timeline(None);
                let _anchored = self.pacer.pace(unit.decode_time, now);
                None
            }
        }
    }

    /// Starts a new epoch for `reason`: an HLS discontinuity (RFC 8216
    /// §4.3.2.3), or a new start of the stream.
    pub fn new_epoch(&mut self, reason: &'static str) {
        tracing::info!(reason, "http: new timeline; new epoch");
        self.new_timeline(None);
    }

    /// One new epoch for every track; the guard of `except`, whose
    /// timestamp started it, keeps that timestamp as its base.
    fn new_timeline(&mut self, except: Option<usize>) {
        for (index, entry) in self.carried.iter_mut().enumerate() {
            if except != Some(index) {
                entry.guard.rebase();
            }
            entry.video = Video::new(&entry.codec, entry.track.limits().max_frame_bytes);
        }
        self.set.start_epoch();
        self.clock.reset();
        self.pacer.reset();
    }

    /// Publishes `unit`, released at `arrival`: video through the
    /// normalizers onto the live path and the side branch, AAC onto the
    /// side branch. A unit of a track not carried, or of one whose codec
    /// lotse cannot carry, is dropped.
    pub fn publish(&mut self, unit: Unit, arrival: Instant) {
        let Some(index) = self.route(&unit) else {
            return;
        };
        let ts = rtp_ts(unit.ts);
        if let Some(entry) = self.carried.get_mut(index)
            && let Some(moved_ms) = entry.guard.observe(ts, arrival)
        {
            let track = entry.track.id();
            tracing::info!(%track, moved_ms, "http: timestamps jumped; new epoch");
            self.new_timeline(Some(index));
        }
        if let Some(entry) = self.carried.get_mut(index) {
            entry.publish(&self.clock, &mut self.packets, unit, arrival);
        }
    }

    /// Counts `lost` transport packets: the continuity errors the
    /// demultiplexer found (ISO/IEC 13818-1 §2.4.3.3), each at least one
    /// packet lost; one line per summary interval.
    pub fn count_lost(&mut self, lost: u64, now: Instant) {
        if lost == 0 {
            return;
        }
        self.ingest.count_lost(lost);
        if let Some(count) = self.loss_log.hit(now) {
            tracing::debug!(lost, count, "http: MPEG-TS continuity errors; packets lost");
        }
    }
}

/// A unit the live path carried in more packets than some libwebrtc
/// receivers assemble ([`LIBWEBRTC_MAX_FRAME_PACKETS`]): counted on the
/// track, and warned about at most once per summary interval. Every
/// session sends it whole all the same.
fn frame_over_limit(
    track: &Track,
    throttle: &mut Throttle,
    arrival: Instant,
    frame: Option<FrameOverLimit>,
) {
    let Some(frame) = frame else { return };
    track.count_frame_over_browser_limit();
    if let Some(count) = throttle.hit(arrival) {
        tracing::warn!(
            track = %track.id(),
            code = "frame_over_browser_limit",
            codec = track.codec().name(),
            bytes = frame.bytes,
            packets = frame.packets,
            limit = LIBWEBRTC_MAX_FRAME_PACKETS,
            keyframe = frame.keyframe,
            count,
            advice = "choose a lower bitrate of the stream",
            "http: frame over the packet limit of some libwebrtc receivers (by version); sent whole, those viewers may freeze until a keyframe that fits"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::clock::{Clock as _, SystemClock};
    use lotse_core::clock_map::{ClockMapper, SyncMode};
    use lotse_core::source::{ClockReport, SyncHint};
    use lotse_core::track::{FrameSubscription, PacketSubscription, TrackLimits};

    use std::io;
    use std::sync::Mutex;

    use super::*;
    use crate::fmp4::Reader;
    use crate::fmp4::test_data::{H264_AAC_0, H264_AAC_1, H264_AAC_INIT, H265_0, H265_INIT};
    use crate::media::Event;
    use crate::ts::Demuxer;
    use crate::ts::test_data::{AUDIO_PID, H264_AAC, H264_AAC16K, H265_V1, VIDEO_PID};
    use lotse_codec::h264::annex_b_units;

    const LEAD: Duration = Duration::from_secs(30);

    /// A log writer that keeps every line.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        /// The lines logged so far that contain `needle`.
        fn lines(&self, needle: &str) -> Vec<String> {
            io::Write::flush(&mut self.clone()).unwrap();
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .filter(|line| line.contains(needle))
                .map(str::to_owned)
                .collect()
        }

        /// Starts capturing this thread's log lines, `debug` and up.
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            let writer = self.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::DEBUG)
                .finish();
            tracing::subscriber::set_default(subscriber)
        }
    }

    struct Fixture {
        t0: Instant,
        set: Arc<TrackSet>,
        mapper: Arc<ClockMapper>,
        publisher: Publisher,
    }

    fn start(layout: &Layout, max_lead: Duration) -> Fixture {
        let t0 = SystemClock.now();
        let set = TrackSet::new(TrackLimits::default(), t0);
        let mapper = Arc::new(ClockMapper::new());
        let (clock, _reports) = ClockInput::channel(Arc::clone(&mapper));
        let mut tracks = set.publisher();
        let publisher = Publisher::new(&mut tracks, clock, layout, max_lead).unwrap();
        Fixture {
            t0,
            set,
            mapper,
            publisher,
        }
    }

    fn demux(data: &[u8]) -> (Layout, Vec<Unit>) {
        let mut demuxer = Demuxer::new(TrackLimits::default().max_frame_bytes);
        let mut events = Vec::new();
        demuxer.push(data, &mut events);
        demuxer.flush(&mut events);
        let mut layout = None;
        let mut units = Vec::new();
        for event in events {
            match event {
                Event::Layout(next) => {
                    layout.get_or_insert(next);
                }
                Event::Unit(unit) => units.push(unit),
            }
        }
        (layout.unwrap(), units)
    }

    /// Offers each unit until it is due, moving the time to when it is,
    /// and publishes it: the release instants.
    fn play(publisher: &mut Publisher, units: Vec<Unit>, mut now: Instant) -> Vec<Instant> {
        let mut released = Vec::new();
        for unit in units {
            while let Some(at) = publisher.due(&unit, now) {
                assert!(at > now, "due ahead");
                now = at;
            }
            released.push(now);
            publisher.publish(unit, now);
        }
        released
    }

    fn frames(sub: &mut FrameSubscription) -> Vec<Arc<MediaFrame>> {
        std::iter::from_fn(|| sub.try_recv().unwrap()).collect()
    }

    fn packets(sub: &mut PacketSubscription) -> Vec<Arc<MediaPacket>> {
        std::iter::from_fn(|| sub.try_recv().unwrap()).collect()
    }

    fn ticks_to(ticks: i64) -> Duration {
        Duration::from_nanos(u64::try_from(ticks.max(0) * 1_000_000_000 / 90_000).unwrap())
    }

    fn track(kind: Kind, codec: Codec, clock_rate: u32, id: u32) -> LayoutTrack {
        LayoutTrack {
            id,
            stream_type: 0,
            kind,
            codec,
            clock_rate,
        }
    }

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }
    }

    fn layout(tracks: Vec<LayoutTrack>) -> Layout {
        Layout {
            program_number: 1,
            tracks,
        }
    }

    fn video_unit(track: usize, decode_time: i64, ts: i64, payload: &[u8]) -> Unit {
        Unit {
            track,
            decode_time,
            ts,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    /// A unit's track, decoding time and presentation time, and when it
    /// was released.
    type Released = (usize, i64, i64, Instant);

    fn assert_declared_h264_and_aac(set: &TrackSet) {
        let tracks = set.tracks();
        assert_eq!(tracks.len(), 2);
        let (video, audio) = (&tracks[0], &tracks[1]);
        assert_eq!((video.kind(), video.clock_rate()), (Kind::Video, 90_000));
        assert_eq!((audio.kind(), audio.clock_rate()), (Kind::Audio, 48_000));
        assert!(matches!(
            *audio.codec(),
            Codec::AacLc {
                sample_rate: 48_000,
                channels: 1,
                ..
            }
        ));
        assert!(*set.ready().borrow());
    }

    /// Each unit at its decoding time after the first, or at once when the
    /// time has passed it (the mux order is not the decode order).
    fn assert_released_at_decoding_time(t0: Instant, released: &[Released]) {
        let first = released[0].1;
        let mut clock = t0;
        for (_, decode_time, _, at) in released {
            clock = clock.max(t0 + ticks_to(decode_time - first));
            assert_eq!(*at, clock);
        }
        let (_, last, _, at) = released.last().unwrap();
        assert_eq!(*at - t0, ticks_to(last - first));
    }

    fn assert_h264_codec(codec: &Codec) {
        let baseline = matches!(
            codec,
            Codec::H264 {
                profile_level_id: Some([0x42, ..]),
                sps: Some(_),
                pps: Some(_),
            }
        );
        assert!(baseline, "baseline with its sets: {codec:?}");
    }

    fn assert_video_frames(out: &[Arc<MediaFrame>], video: &[&Released]) {
        assert_eq!(out.len(), 10);
        assert!(out[0].keyframe);
        assert_eq!(out.iter().filter(|f| f.keyframe).count(), 1, "-g 10");
        for (frame, (_, _, ts, at)) in out.iter().zip(video) {
            assert_eq!(frame.ts.ticks(), *ts);
            assert_eq!(frame.arrival, *at);
            assert_eq!(frame.wallclock, *at, "no sync hint: by arrival");
            assert_eq!(frame.epoch, 0);
        }
    }

    fn assert_video_packets(out: &[Arc<MediaPacket>], video: &[&Released]) {
        assert!(out[0].frame_start);
        // The joining point is the parameter sets before the IDR, once.
        assert_eq!(out.iter().filter(|p| p.keyframe_start).count(), 1);
        assert_eq!(out.iter().filter(|p| p.rtp.marker).count(), 10);
        for (i, packet) in out.iter().enumerate() {
            assert_eq!(usize::from(packet.rtp.seq), i);
            assert_eq!((packet.rtp.pt, packet.rtp.ssrc), (PAYLOAD_TYPE, SSRC));
        }
        let starts: Vec<_> = out.iter().filter(|p| p.frame_start).collect();
        assert_eq!(starts.len(), 10);
        for (packet, (_, _, ts, at)) in starts.iter().zip(video) {
            assert_eq!(i64::from(packet.rtp.ts), *ts);
            assert_eq!(packet.arrival, *at);
        }
    }

    fn assert_audio_frames(out: &[Arc<MediaFrame>]) {
        assert_eq!(out.len(), 48);
        assert!(out.iter().all(|f| f.keyframe && f.wallclock == f.arrival));
        for pair in out.windows(2) {
            assert_eq!(
                pair[1].ts.ticks() - pair[0].ts.ticks(),
                1024,
                "ISO/IEC 14496-3 §4.4.1"
            );
            assert!(pair[1].arrival >= pair[0].arrival);
        }
    }

    #[test]
    fn iso13818_1_h264_and_aac_are_published_at_their_decoding_time_on_one_base() {
        let logs = Captured::default();
        let _logs = logs.install();
        let (layout, units) = demux(H264_AAC);
        let mut f = start(&layout, LEAD);
        assert_declared_h264_and_aac(&f.set);
        let declared = logs.lines("http: declaring a track of the program");
        assert_eq!(declared.len(), 2);
        assert!(
            declared[0].contains("id=256") && declared[0].contains("codec=\"h264\""),
            "{declared:?}"
        );
        let tracks = f.set.tracks();
        let mut video_frames = tracks[0].subscribe_frames();
        let mut video_packets = tracks[0].subscribe_packets();
        let mut audio_frames = tracks[1].subscribe_frames();

        let ids: Vec<_> = units
            .iter()
            .map(|u| (u.track, u.decode_time, u.ts))
            .collect();
        let released: Vec<Released> = ids
            .into_iter()
            .zip(play(&mut f.publisher, units, f.t0))
            .map(|((track, decode_time, ts), at)| (track, decode_time, ts, at))
            .collect();
        assert_released_at_decoding_time(f.t0, &released);
        // The codec took the in-band parameter sets of the first unit.
        assert_h264_codec(&tracks[0].codec());
        let video: Vec<_> = released.iter().filter(|u| u.0 == 0).collect();
        assert_video_frames(&frames(&mut video_frames), &video);
        assert_video_packets(&packets(&mut video_packets), &video);
        assert_audio_frames(&frames(&mut audio_frames));
        assert_eq!(tracks[0].epoch(), 0, "no epoch on a steady program");
        assert!(logs.lines("new epoch").is_empty());
    }

    #[test]
    fn iso13818_1_h265_takes_its_parameter_sets_in_band() {
        let (layout, units) = demux(H265_V1);
        let mut f = start(&layout, LEAD);
        let video = &f.set.tracks()[0];
        let mut sub = video.subscribe_frames();
        play(&mut f.publisher, units, f.t0);
        assert!(matches!(
            &*video.codec(),
            Codec::H265 {
                vps: Some(_),
                sps: Some(_),
                pps: Some(_)
            }
        ));
        let out = frames(&mut sub);
        assert_eq!(out.len(), 10);
        assert!(out[0].keyframe);
    }

    fn read_fmp4(init: &[u8], segment: &[u8]) -> (Layout, Vec<Unit>) {
        let mut reader = Reader::new(init, TrackLimits::default().max_frame_bytes).unwrap();
        let mut units = Vec::new();
        reader.read_segment(segment, &mut units).unwrap();
        (reader.layout().clone(), units)
    }

    #[test]
    fn iso14496_15_5_3_3_the_avcc_parameter_sets_seed_the_normalizers() {
        let (layout, units) = read_fmp4(H264_AAC_INIT, H264_AAC_0);
        let mut f = start(&layout, LEAD);
        assert_declared_h264_and_aac(&f.set);
        let tracks = f.set.tracks();
        // Declared with the avcC's sets, as an SDP's.
        let declared = Codec::clone(&tracks[0].codec());
        assert_h264_codec(&declared);
        let mut video_frames = tracks[0].subscribe_frames();
        let mut video_packets = tracks[0].subscribe_packets();
        let mut audio_frames = tracks[1].subscribe_frames();
        play(&mut f.publisher, units, f.t0);
        // The samples carry no SPS or PPS: both layers put the seeded
        // ones before the IDR.
        let out = frames(&mut video_frames);
        assert_eq!(out.len(), 10);
        assert!(out[0].keyframe);
        let types: Vec<u8> = annex_b_units(&out[0].payload)
            .iter()
            .map(|nal| nal[0] & 0x1f)
            .collect();
        assert_eq!(types, [6, 7, 8, 5]);
        let live = packets(&mut video_packets);
        let head: Vec<(bool, bool, u8)> = live
            .iter()
            .take(3)
            .map(|p| (p.frame_start, p.keyframe_start, p.payload[0] & 0x1f))
            .collect();
        // The SEI, the sets in a STAP-A at the joining point (RFC 6184
        // §5.7.1), the IDR in FU-A fragments (§5.8).
        assert_eq!(
            head,
            [(true, false, 6), (false, true, 24), (false, false, 28)]
        );
        assert_eq!(*tracks[0].codec(), declared, "no update without news");
        assert_audio_frames(&frames(&mut audio_frames));
        // A new epoch seeds the fresh normalizers again.
        f.publisher.new_epoch("test");
        let (_, units) = read_fmp4(H264_AAC_INIT, H264_AAC_1);
        play(&mut f.publisher, units, f.t0 + Duration::from_secs(1));
        let out = frames(&mut video_frames);
        assert_eq!(out.len(), 10);
        let types: Vec<u8> = annex_b_units(&out[0].payload)
            .iter()
            .map(|nal| nal[0] & 0x1f)
            .collect();
        assert_eq!(types, [7, 8, 5]);
    }

    #[test]
    fn iso14496_15_8_3_3_the_hvcc_parameter_sets_seed_the_normalizers() {
        let (layout, units) = read_fmp4(H265_INIT, H265_0);
        let mut f = start(&layout, LEAD);
        let video = &f.set.tracks()[0];
        let declared = Codec::clone(&video.codec());
        assert!(matches!(
            declared,
            Codec::H265 {
                vps: Some(_),
                sps: Some(_),
                pps: Some(_)
            }
        ));
        let mut sub = video.subscribe_frames();
        play(&mut f.publisher, units, f.t0);
        let out = frames(&mut sub);
        assert_eq!(out.len(), 10);
        assert!(out[0].keyframe);
        let types: Vec<u8> = annex_b_units(&out[0].payload)
            .iter()
            .map(|nal| nal[0] >> 1)
            .collect();
        assert_eq!(&types[..3], [32, 33, 34]);
        assert_eq!(*video.codec(), declared);
    }

    #[test]
    fn a_late_segment_is_published_at_once() {
        let (layout, units) = demux(H264_AAC);
        let mut f = start(&layout, LEAD);
        let late = f.t0 + Duration::from_secs(5);
        assert_eq!(f.publisher.due(&units[0], f.t0), None);
        for unit in &units[1..] {
            assert_eq!(f.publisher.due(unit, late), None);
        }
    }

    #[test]
    fn a_new_epoch_restarts_the_tracks_the_clock_the_pacer_and_the_normalizers() {
        let logs = Captured::default();
        let _logs = logs.install();
        let (layout, units) = demux(H264_AAC);
        let mut f = start(&layout, LEAD);
        let video = Arc::clone(&f.set.tracks()[0]);
        let audio = Arc::clone(&f.set.tracks()[1]);
        let idr = units.iter().find(|u| u.track == 0).unwrap().clone();
        let sound = units.iter().find(|u| u.track == 1).unwrap().clone();
        f.publisher.publish(idr.clone(), f.t0);
        f.publisher.publish(sound.clone(), f.t0);
        let parsed = video.codec();
        assert!(f.publisher.due(&idr, f.t0).is_none(), "the anchor");
        f.mapper.ingest(ClockReport {
            track: video.id(),
            clock_rate: 90_000,
            hint: SyncHint::RtcpSenderReport {
                ntp: 1 << 32,
                rtp_ts: 0,
            },
            arrival: f.t0,
        });
        assert_eq!(f.mapper.mode(video.id()), SyncMode::SenderReports);

        // Without an epoch the same SPS is no news: a codec set aside
        // stays.
        video.set_codec(h264());
        f.publisher.publish(idr.clone(), f.t0);
        assert_eq!(*video.codec(), h264());

        f.publisher.new_epoch("discontinuity");
        assert_eq!((video.epoch(), audio.epoch()), (1, 1), "one epoch for all");
        let lines = logs.lines("http: new timeline; new epoch");
        assert!(lines[0].contains("reason=\"discontinuity\""), "{lines:?}");
        assert_eq!(
            f.mapper.mode(video.id()),
            SyncMode::Arrival,
            "mapping forgotten"
        );
        // A fresh normalizer reads the SPS anew.
        f.publisher.publish(idr.clone(), f.t0);
        assert_eq!(video.codec(), parsed);
        // The guards start over: an hour back is the new base.
        let back = Unit {
            ts: sound.ts - 48_000 * 3_600,
            ..sound
        };
        f.publisher.publish(back, f.t0);
        assert_eq!(video.epoch(), 1);
        // The pacer anchors at the next unit, wherever it lies.
        let later = f.t0 + Duration::from_secs(60);
        let earlier = Unit {
            decode_time: idr.decode_time - 90_000 * 3_600,
            ..idr.clone()
        };
        assert_eq!(f.publisher.due(&earlier, later), None);
        let next = Unit {
            decode_time: earlier.decode_time + 9_000,
            ..idr
        };
        assert_eq!(
            f.publisher.due(&next, later),
            Some(later + Duration::from_millis(100))
        );
    }

    #[test]
    fn rfc3550_5_1_a_timestamp_off_its_timeline_starts_an_epoch_as_a_backstop() {
        let logs = Captured::default();
        let _logs = logs.install();
        let (layout, units) = demux(H264_AAC);
        let mut f = start(&layout, LEAD);
        let video = Arc::clone(&f.set.tracks()[0]);
        let idr = units.iter().find(|u| u.track == 0).unwrap().clone();
        let sound = units.iter().find(|u| u.track == 1).unwrap().clone();
        f.publisher.publish(idr.clone(), f.t0);
        f.publisher.publish(sound.clone(), f.t0);
        let at = |ms| f.t0 + Duration::from_millis(ms);
        // Ten seconds back at once: a new epoch.
        let back = |unit: &Unit, by: i64| Unit {
            ts: unit.ts - by,
            ..unit.clone()
        };
        f.publisher.publish(back(&idr, 900_000), at(40));
        assert_eq!(video.epoch(), 1);
        let lines = logs.lines("http: timestamps jumped; new epoch");
        assert!(
            lines[0].contains("track=v0") && lines[0].contains("moved_ms=-10000"),
            "{lines:?}"
        );
        // The jumped track keeps its new base: another jump from it is
        // one more epoch.
        f.publisher.publish(back(&idr, 1_800_000), at(80));
        assert_eq!(video.epoch(), 2);
        // The other track starts over at its next timestamp.
        f.publisher.publish(back(&sound, 48_000 * 3_600), at(120));
        assert_eq!(video.epoch(), 2);
        // The wrapped 32-bit timestamp continues the timeline.
        let wrapped = Unit {
            ts: back(&idr, 1_800_000).ts + (1_i64 << 32) + 3_000,
            ..idr
        };
        f.publisher.publish(wrapped, at(153));
        assert_eq!(video.epoch(), 2);
    }

    #[test]
    fn a_unit_due_beyond_the_lead_starts_an_epoch_anchored_at_it() {
        let logs = Captured::default();
        let _logs = logs.install();
        let (layout, units) = demux(H264_AAC);
        let mut f = start(&layout, Duration::from_secs(1));
        let video = Arc::clone(&f.set.tracks()[0]);
        let unit = units[0].clone();
        assert_eq!(f.publisher.due(&unit, f.t0), None);
        let ahead = Unit {
            decode_time: unit.decode_time + 90_000 * 10,
            ..unit.clone()
        };
        assert_eq!(f.publisher.due(&ahead, f.t0), None);
        assert_eq!(video.epoch(), 1);
        let lines = logs.lines("http: the program's timestamps jumped ahead; new epoch");
        assert!(lines[0].contains("ahead_ms=10000"), "{lines:?}");
        let next = Unit {
            decode_time: ahead.decode_time + 9_000,
            ..unit
        };
        assert_eq!(
            f.publisher.due(&next, f.t0),
            Some(f.t0 + Duration::from_millis(100))
        );
    }

    #[test]
    fn the_same_tracks_in_a_new_layout_continue_and_other_tracks_end_the_attempt() {
        let logs = Captured::default();
        let _logs = logs.install();
        let (first, _) = demux(H264_AAC);
        let mut f = start(&first, LEAD);
        let video = Arc::clone(&f.set.tracks()[0]);
        let audio = Arc::clone(&f.set.tracks()[1]);
        assert_eq!(f.publisher.relayout(&first), Ok(()));
        let lines = logs.lines("http: the program's layout repeated with the same tracks");
        assert!(lines[0].contains("tracks=2"), "{lines:?}");

        // Reordered, with a second audio track: the same carried tracks,
        // routed by the new indices; the extra track is not carried.
        let mut reordered = first.clone();
        reordered.tracks.reverse();
        reordered.tracks.push(track(
            Kind::Audio,
            Codec::Unsupported {
                kind: Kind::Audio,
                name: "mp2".into(),
            },
            90_000,
            0x102,
        ));
        assert_eq!(f.publisher.relayout(&reordered), Ok(()));
        let mut audio_frames = audio.subscribe_frames();
        let mut video_frames = video.subscribe_frames();
        let (_, units) = demux(H264_AAC);
        let sound = units.iter().find(|u| u.track == 1).unwrap();
        f.publisher.publish(
            Unit {
                track: 0,
                ..sound.clone()
            },
            f.t0,
        );
        f.publisher.publish(
            Unit {
                track: 2,
                ..sound.clone()
            },
            f.t0,
        );
        assert_eq!(
            f.publisher.due(
                &Unit {
                    track: 2,
                    ..sound.clone()
                },
                f.t0
            ),
            None
        );
        assert_eq!(frames(&mut audio_frames).len(), 1);
        assert!(frames(&mut video_frames).is_empty());
        assert_eq!(
            f.publisher.due(
                &Unit {
                    track: 7,
                    ..sound.clone()
                },
                f.t0
            ),
            None,
            "no such track"
        );

        // Another AAC configuration: other tracks.
        let (other, _) = demux(H264_AAC16K);
        let err = f.publisher.relayout(&other).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the program's tracks changed from video h264 at 90000 Hz, audio aac_lc at 48000 Hz \
             to video h264 at 90000 Hz, audio aac_lc at 16000 Hz"
        );
        let err = f.publisher.relayout(&layout(vec![])).unwrap_err();
        assert!(err.to_string().ends_with("to nothing"), "{err}");
        assert_eq!(first.tracks[0].id, u32::from(VIDEO_PID));
        assert_eq!(first.tracks[1].id, u32::from(AUDIO_PID));
    }

    #[test]
    fn a_program_without_tracks_is_refused() {
        let set = TrackSet::new(TrackLimits::default(), SystemClock.now());
        let (clock, _reports) = ClockInput::channel(Arc::new(ClockMapper::new()));
        let err = Publisher::new(&mut set.publisher(), clock, &layout(vec![]), LEAD).unwrap_err();
        assert!(matches!(err, SourceError::Protocol(_)), "{err:?}");
        assert!(set.tracks().is_empty());
        assert!(!*set.ready().borrow());
    }

    #[test]
    fn units_of_a_codec_lotse_cannot_carry_are_dropped() {
        let unsupported = |kind| Codec::Unsupported {
            kind,
            name: "mpeg2".into(),
        };
        let mut f = start(
            &layout(vec![
                track(Kind::Video, unsupported(Kind::Video), 90_000, 0x100),
                track(Kind::Audio, unsupported(Kind::Audio), 90_000, 0x101),
            ]),
            LEAD,
        );
        let tracks = f.set.tracks();
        assert_eq!(*tracks[0].codec(), unsupported(Kind::Video));
        let mut subs: Vec<_> = tracks.iter().map(|t| t.subscribe_frames()).collect();
        let mut packet_subs: Vec<_> = tracks.iter().map(|t| t.subscribe_packets()).collect();
        for index in 0..2 {
            f.publisher
                .publish(video_unit(index, 0, 0, &[0, 0, 0, 1, 0x65, 1]), f.t0);
        }
        assert!(subs.iter_mut().all(|s| frames(s).is_empty()));
        assert!(packet_subs.iter_mut().all(|s| packets(s).is_empty()));
    }

    #[test]
    fn rfc3550_5_1_the_rtp_timestamp_is_the_presentation_time_wrapped() {
        assert_eq!(rtp_ts(5), 5);
        assert_eq!(rtp_ts((1 << 32) + 5), 5);
        assert_eq!(rtp_ts(-1), u32::MAX);
        assert_eq!(rtp_ts(0x1_2345_6789), 0x2345_6789);
    }

    #[test]
    fn continuity_errors_count_as_lost_packets() {
        let logs = Captured::default();
        let _logs = logs.install();
        let (layout, _) = demux(H264_AAC);
        let mut f = start(&layout, LEAD);
        f.publisher.count_lost(0, f.t0);
        assert_eq!(f.set.ingest().packets_lost, 0);
        f.publisher.count_lost(3, f.t0);
        f.publisher.count_lost(2, f.t0);
        assert_eq!(f.set.ingest().packets_lost, 5);
        // One line per summary interval.
        let lines = logs.lines("http: MPEG-TS continuity errors; packets lost");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("lost=3"), "{lines:?}");
    }

    #[test]
    fn a_unit_over_the_browser_packet_limit_is_counted_and_sent_whole() {
        let logs = Captured::default();
        let _logs = logs.install();
        let mut f = start(
            &layout(vec![track(Kind::Video, h264(), 90_000, 0x100)]),
            LEAD,
        );
        let video = Arc::clone(&f.set.tracks()[0]);
        let mut idr = vec![0, 0, 0, 1, 0x65];
        idr.resize(
            5 + DEFAULT_MAX_PAYLOAD * (LIBWEBRTC_MAX_FRAME_PACKETS + 1),
            0xab,
        );
        f.publisher.publish(video_unit(0, 0, 0, &idr), f.t0);
        assert_eq!(video.stats().frames_over_browser_limit, 1);
        let sent = usize::try_from(video.stats().packets).unwrap();
        assert!(sent > LIBWEBRTC_MAX_FRAME_PACKETS, "{sent}");
        f.publisher.publish(video_unit(0, 3_000, 3_000, &idr), f.t0);
        assert_eq!(video.stats().frames_over_browser_limit, 2);
        let lines = logs.lines("http: frame over the packet limit");
        assert_eq!(lines.len(), 1, "rate-limited");
        assert!(
            lines[0].contains("WARN")
                && lines[0].contains("codec=\"h264\"")
                && lines[0].contains("code=\"frame_over_browser_limit\""),
            "{lines:?}"
        );
    }
}

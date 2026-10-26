//! The movie fragments of a clip and the decode timeline of each track.
//!
//! Implements ISO/IEC 14496-12: a fragment is one `moof` (§8.8.4) with its
//! `mfhd` (§8.8.5, the sequence number from 1) and one `traf` (§8.8.6)
//! per track with samples in it, followed by one `mdat` (§8.1.1) with the
//! samples in `traf` order. Each `traf` has a `tfhd` with
//! `default-base-is-moof` (§8.8.7), so its run's data offset counts from
//! the first byte of the `moof`; a `tfdt` (§8.8.12) with the decode time
//! of its first sample; and one `trun` (§8.8.8) with each sample's
//! duration and size, video's sample flags (§8.8.3.1:
//! `sample_is_non_sync_sample` and `sample_depends_on`) and, for
//! reordered video, signed composition offsets (version 1, §8.8.8.1).
//! mp4-atom encodes the boxes; the `mdat` header goes through its
//! `Header` and the samples follow as the frames' own bytes, so nothing
//! is copied. A video sample is the access unit's NAL units, each behind
//! its 4-byte length instead of its start code (ISO/IEC 14496-15 §5.3.2,
//! §8.3.2). H.264 samples keep the parameter sets the camera sent in-band,
//! as ffmpeg 9.0.2 keeps them in `avc1` (observed 2026-10-23). H.265
//! samples leave out the VPS, SPS and PPS that equal the `hvc1` sample
//! entry's, whose arrays say they are complete (§8.4.1.1.2: none in the
//! samples), as ffmpeg 9.0.2 leaves them out of `hvc1` (observed
//! 2026-10-23).
//!
//! SPEC-DEVIATION: from the first H.265 sample with a parameter set the
//! sample entry lacks on, every sample keeps all its parameter sets, the
//! entry's included. Only a pre-roll GOP from before a change of the sets
//! within the codec family has such a set (the ring keeps those GOPs, the
//! clip's sample entry has the newest sets), and without it that GOP
//! would not decode. Its set takes the place of the entry's with the same
//! ID in the decoder (ITU-T H.265 §7.4.2.4.2), and a new fragment does not
//! bring the entry's back, so the GOPs after it need their own in-band
//! sets (every keyframe carries them, [`MediaFrame::payload`]) to decode
//! with the current ones, and keep them wherever a player starts or seeks.
//!
//! The timeline: a track's timescale is its clock rate, so the camera's
//! timestamps are the file's. Each epoch of a track is presented from its
//! first frame's capture time after the clip's origin (the capture time
//! of the clip's first frame, or the earlier one the clip task set with
//! [`ClipMuxer::set_origin`](lotse_core::clip::ClipMuxer::set_origin)),
//! in ticks, and no earlier than where the
//! track's presentation so far ends; inside the epoch a sample's
//! presentation time is that anchor plus its timestamp's distance from
//! the epoch's first. A reconnect is so a hole of the real time between
//! the epochs, in a new fragment. Its decode times start at the anchor
//! too, unless the track's last sample is decoded until later (reordered
//! video is decoded ahead of its presentation): then from where that
//! sample's decode ends, and every sample of the epoch in order carries
//! the difference, the epoch's lead, as a negative composition offset
//! (§8.8.8.1), so decode times never go back and the video stays at its
//! capture times, in sync with the audio. Where the track's presentation
//! so far ends is where its last epoch's last sample ends, or one nominal
//! frame duration after the latest presentation time of the samples
//! before it, if later: reordered video's last sample in decode order is
//! not its last in presentation order, and the durations, steps of the
//! decode times, are not how long the samples before it are shown. The
//! nominal frame duration is the smallest distance between two of the
//! epoch's timestamps, wherever they are in decode order: a GOP a
//! reconnect cut short, its later pictures lost, keeps it as long as two
//! of the pictures it kept are a frame apart (`B1` and `I0` of
//! `I0 P3 B1`), and short of that it is the shortest the timestamps show,
//! which cannot tell a lost picture from a longer frame (`I0 P4 B2` of a
//! pyramid is `I0 P2 B1` at half the rate). Durations are the distances
//! to the next sample's decode time; the last one of an epoch, which has
//! no next, takes its frame's own length where the codec states one (an
//! AAC-LC frame's 1024 samples, ISO/IEC 14496-3 §4.4.1; an Opus packet's
//! frames, RFC 6716 §3.1), else the one before it (video), cut short so
//! its presentation ends where the next epoch begins when that is sooner
//! and no sooner than the track's presentation so far ends, and an epoch
//! captured before the track's presentation ends starts where it ends.
//!
//! Video whose timestamps go back in decode order is reordered
//! (B-frames): from the first such frame on, the epoch's decode times
//! step by the smallest distance seen between two consecutive timestamps,
//! and each sample's composition offset is its presentation time minus
//! its decode time, negative for the frames presented before the ones
//! decoded earlier. Audio is never reordered: audio whose timestamp does
//! not advance starts a new epoch.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut as _, Bytes, BytesMut};
use lotse_codec::aac::FRAME_SAMPLES as AAC_FRAME_SAMPLES;
use lotse_codec::h264::annex_b_units;
use lotse_codec::h265::nal;
use lotse_codec::opus::packet_samples;
use lotse_core::clip::{ClipError, ClipTrack};
use lotse_core::{Codec, Kind, MediaFrame};
use mp4_atom::{
    Atom as _, Encode as _, Header, Mdat, Mfhd, Moof, Tfdt, Tfhd, Traf, Trun, TrunEntry,
};

use crate::encode_failed;
use crate::init::{NON_SYNC_SAMPLE, OPUS_RATE, SYNC_SAMPLE};

/// Nanoseconds in a second, for the conversion of capture times to ticks.
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// The frame rate a video track's only sample is timed at: nothing else
/// says how long it lasts.
const FALLBACK_FRAME_RATE: u32 = 30;

/// How many of an epoch's highest timestamps it keeps to find a new
/// timestamp's neighbours ([`Epoch::space`]): one more than the pictures a
/// stream may decode before a picture and present after it, so the
/// neighbours of every new one are among them. That is at most 16 in H.264
/// (ITU-T H.264 §E.2.1: `num_reorder_frames` at most
/// `max_dec_frame_buffering`; §A.3.1: that at most `MaxDpbFrames`, at most
/// 16) and at most 15 in H.265 (ITU-T H.265 §7.4.3.2.1:
/// `sps_max_num_reorder_pics` at most `sps_max_dec_pic_buffering_minus1`;
/// §A.4.2: that below `MaxDpbSize`, at most 16).
const NEIGHBOURHOOD: usize = 17;

/// `elapsed` in ticks of `rate`, rounded down.
pub(crate) fn ticks(elapsed: Duration, rate: u32) -> u64 {
    let ticks = elapsed
        .as_nanos()
        .saturating_mul(u128::from(rate))
        .checked_div(NANOS_PER_SECOND)
        .unwrap_or_default();
    u64::try_from(ticks).unwrap_or(u64::MAX)
}

/// `ticks` at `rate` as a duration: zero for a negative count or a rate
/// of zero, the longest for one past `Duration`'s nanoseconds.
pub(crate) fn duration_of(ticks: i128, rate: u32) -> Duration {
    let nanos = u128::try_from(ticks)
        .unwrap_or_default()
        .saturating_mul(NANOS_PER_SECOND)
        .checked_div(u128::from(rate))
        .unwrap_or_default();
    u64::try_from(nanos).map_or(Duration::MAX, Duration::from_nanos)
}

/// A conversion that does not fit its field: the clip cannot go on.
fn out_of_range(what: &str, value: i128) -> ClipError {
    ClipError::Failed(format!("{what} of {value} ticks out of range"))
}

/// How a track's last sample learns its length when no sample follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameLength {
    /// Video: from the samples before it.
    Video,
    /// AAC-LC: 1024 samples at its sampling rate.
    Aac {
        /// The sampling rate in Hz.
        sample_rate: u32,
    },
    /// Opus: the packet's own duration at 48 kHz (RFC 6716 §3.1).
    Opus,
}

/// One epoch of a track: where its timeline is anchored, and how it runs.
#[derive(Debug)]
struct Epoch {
    /// The frames' epoch number.
    number: u32,
    /// The epoch's first timestamp.
    first_ts: i128,
    /// The presentation time of its first sample.
    anchor: i128,
    /// How far its decode times run ahead of its presentation times until
    /// it is reordered: where the track's decode so far ends past the
    /// anchor, else 0 (see the module).
    lead: i128,
    /// The latest timestamp, in decode order.
    last_ts: i128,
    /// The latest decode time.
    last_dts: i128,
    /// The smallest distance between two consecutive timestamps seen: the
    /// step of reordered video's decode times.
    step: Option<i128>,
    /// The smallest distance between two of its timestamps seen, consecutive
    /// or not: its nominal frame duration (see [`Epoch::shown`]).
    spacing: Option<i128>,
    /// Its [`NEIGHBOURHOOD`] highest timestamps, among which a new one's
    /// neighbours are: never more, so an epoch holds the same whatever it
    /// lasts.
    highest: BTreeSet<i128>,
    /// Whether a timestamp went back: the epoch's decode times step by
    /// `step` from then on.
    reordered: bool,
    /// The latest presentation time of its frames before the latest one
    /// (see [`Epoch::shown`]); `None` before the second.
    top: Option<i128>,
}

impl Epoch {
    /// An epoch whose first frame has `ts`, is presented at `anchor` and
    /// is decoded `lead` (at least 0) later.
    fn new(number: u32, ts: i128, anchor: i128, lead: i128) -> Self {
        Self {
            number,
            first_ts: ts,
            anchor,
            lead,
            last_ts: ts,
            last_dts: anchor.saturating_add(lead),
            step: None,
            spacing: None,
            highest: BTreeSet::from([ts]),
            reordered: false,
            top: None,
        }
    }

    /// The presentation time of its frame with timestamp `ts`: the anchor
    /// plus the timestamp's distance from the first.
    const fn pts(&self, ts: i128) -> i128 {
        self.anchor.saturating_add(ts.saturating_sub(self.first_ts))
    }

    /// Where the presentation of its frames before the latest one ends:
    /// one nominal frame duration, the spacing, after the latest of their
    /// presentation times (a tick after it while all its timestamps are
    /// equal), `None` before the second frame. Not where their durations
    /// end, which are steps of the decode times: `P3` of `I0 P3 B1 B2` at
    /// 25 fps is decoded at 120 ms and `B1`, a step of the 2 frames between
    /// them, at 200 ms, while the four pictures are shown until 160 ms.
    /// Each of those frames but the one presented latest is shown until a
    /// later one begins, so before this. Of pictures a frame apart, the
    /// spacing is a frame or more, and a frame once two of them a frame
    /// apart arrived, whichever were lost (`I0 P3 B1`, missing `B2`, has
    /// `B1` a frame after `I0`): the next epoch is never presented over the
    /// latest, and no later than it ends unless the timestamps cannot tell
    /// (see the module). The spacing is never longer than the step of the
    /// decode times, as two consecutive timestamps are two of the epoch's.
    /// In order, the latest frame is presented at least a spacing after the
    /// ones before it, so its own end decides. Asked when the epoch ends:
    /// the spacing only shrinks.
    fn shown(&self) -> Option<i128> {
        self.top
            .map(|top| top.saturating_add(self.spacing.unwrap_or(1)))
    }

    /// Takes in its next frame's timestamp `ts`: narrows the spacing to the
    /// distance from `ts` to its neighbours among the highest timestamps,
    /// and keeps it if it is one of them. Every timestamp above `ts` is of
    /// a picture decoded before it and presented after it, at most
    /// [`NEIGHBOURHOOD`] less one, so both neighbours are kept, and the
    /// spacing is the smallest distance between any two timestamps of the
    /// epoch: two closest ones are neighbours, and the later decoded finds
    /// the other. A stream reordered deeper, which neither codec allows,
    /// may find a longer one.
    fn space(&mut self, ts: i128) {
        let below = self.highest.range(..ts).next_back();
        let above = self.highest.range(ts..).next();
        let nearest = below
            .into_iter()
            .chain(above)
            .map(|neighbour| neighbour.saturating_sub(ts).saturating_abs())
            .filter(|distance| *distance != 0)
            .min();
        self.spacing = self.spacing.into_iter().chain(nearest).min();
        self.highest.insert(ts);
        if self.highest.len() > NEIGHBOURHOOD {
            self.highest.pop_first();
        }
    }

    /// The composition offset of a sample before the epoch is reordered:
    /// minus its lead, none without one.
    fn offset(&self) -> Option<i128> {
        (self.lead != 0).then(|| self.lead.saturating_neg())
    }

    /// The decode time and, once reordered, the composition offset of the
    /// next frame of the epoch, `ts`.
    fn next(&mut self, ts: i128, video: bool) -> (i128, Option<i128>) {
        let before = self.pts(self.last_ts);
        self.top = Some(self.top.map_or(before, |top| top.max(before)));
        let delta = ts.saturating_sub(self.last_ts);
        if delta != 0 {
            let distance = delta.saturating_abs();
            self.step = Some(self.step.map_or(distance, |step| step.min(distance)));
        }
        self.space(ts);
        self.reordered |= video && delta <= 0;
        self.last_ts = ts;
        let pts = self.pts(ts);
        let (dts, cts) = if self.reordered {
            let dts = self.last_dts.saturating_add(self.step.unwrap_or(1));
            (dts, Some(pts.saturating_sub(dts)))
        } else {
            (pts.saturating_add(self.lead), self.offset())
        };
        self.last_dts = dts;
        (dts, cts)
    }
}

/// A frame whose decode time is known and whose duration is not yet.
#[derive(Debug)]
struct Held {
    /// The frame.
    frame: Arc<MediaFrame>,
    /// Its decode time.
    dts: u64,
    /// Its composition offset, when its epoch is reordered.
    cts: Option<i32>,
}

impl Held {
    /// Its presentation time: its decode time plus its composition offset.
    fn pts(&self) -> i128 {
        i128::from(self.dts).saturating_add(self.cts.map_or(0, i128::from))
    }
}

/// A sample ready for a fragment.
#[derive(Debug)]
pub(crate) struct Sample {
    /// Its bytes in the `mdat`, in order: slices of the frame's payload
    /// and, for video, the length before each NAL unit.
    pieces: Vec<Bytes>,
    /// The sum of the pieces' lengths.
    size: u32,
    /// Its decode time.
    dts: u64,
    /// Its duration.
    duration: u32,
    /// Its sample flags: video only.
    flags: Option<u32>,
    /// Its composition offset, when its epoch is reordered.
    cts: Option<i32>,
}

/// The samples of one track for one fragment.
#[derive(Debug)]
pub(crate) struct Run {
    /// The track's ID.
    track_id: u32,
    /// Its samples in decode order.
    samples: Vec<Sample>,
}

/// One track of a clip: its timeline, the sample whose duration waits
/// for the next frame, and the samples ready for the next fragment.
#[derive(Debug)]
pub(crate) struct TrackWriter {
    /// The track's ID.
    track_id: u32,
    /// Whether it is the video track.
    video: bool,
    /// Its timescale.
    clock_rate: u32,
    /// How its last sample learns its length.
    length: FrameLength,
    /// The parameter sets the sample entry carries that the samples leave
    /// out: H.265's, until a sample brings one the entry lacks, and none
    /// from then on (see the module).
    out_of_band: Vec<Bytes>,
    /// The current epoch; `None` before the first frame.
    epoch: Option<Epoch>,
    /// Where the latest finished sample's decode ends; the next epoch is
    /// decoded no earlier.
    end: i128,
    /// Where the presentation of the earlier epochs ends, each settled as
    /// it ends ([`Self::close_before`]); with the current epoch's,
    /// [`Self::presented`]. The next epoch is presented no earlier.
    shown: i128,
    /// The latest frame, waiting for its duration.
    held: Option<Held>,
    /// The latest finished sample's duration.
    last_duration: Option<u32>,
    /// The presentation time of the latest frame taken, in ticks.
    latest: i128,
    /// The finished samples of the next fragment.
    ready: Vec<Sample>,
    /// What they hold (see [`Self::finish`]).
    ready_bytes: u64,
}

impl TrackWriter {
    /// The writer of track `track_id`, the clip's `track`.
    pub(crate) fn new(track_id: u32, kind: Kind, track: &ClipTrack) -> Self {
        let length = match track.codec {
            Codec::AacLc { sample_rate, .. } => FrameLength::Aac { sample_rate },
            Codec::Opus { .. } => FrameLength::Opus,
            _ => FrameLength::Video,
        };
        let out_of_band = match &track.codec {
            Codec::H265 { vps, sps, pps } => {
                [vps, sps, pps].into_iter().flatten().cloned().collect()
            }
            _ => Vec::new(),
        };
        Self {
            track_id,
            video: kind == Kind::Video,
            clock_rate: track.clock_rate,
            length,
            out_of_band,
            epoch: None,
            end: 0,
            shown: 0,
            held: None,
            last_duration: None,
            latest: 0,
            ready: Vec::new(),
            ready_bytes: 0,
        }
    }

    /// Times `frame` on a clip whose origin is `origin`, and finishes the
    /// sample before it. Returns whether `frame` re-anchored the track's
    /// timeline (a new epoch after another), which the fragment must
    /// begin with.
    pub(crate) fn push(
        &mut self,
        frame: Arc<MediaFrame>,
        origin: Instant,
    ) -> Result<bool, ClipError> {
        let ts = i128::from(frame.ts.ticks());
        let video = self.video;
        let (dts, cts, anchored) = match self.epoch.as_mut() {
            Some(epoch) if epoch.number == frame.epoch && (video || ts > epoch.last_ts) => {
                let (dts, cts) = epoch.next(ts, video);
                (dts, cts, false)
            }
            previous => {
                let anchored = previous.is_some();
                let since = frame.wallclock.saturating_duration_since(origin);
                let at = i128::from(ticks(since, self.clock_rate));
                self.close_before(Some(at));
                let anchor = at.max(self.shown);
                let lead = self.end.saturating_sub(anchor).max(0);
                let epoch = Epoch::new(frame.epoch, ts, anchor, lead);
                let offset = epoch.offset();
                self.epoch = Some(epoch);
                (anchor.saturating_add(lead), offset, anchored)
            }
        };
        let dts = u64::try_from(dts).map_err(|_| out_of_range("a decode time", dts))?;
        let cts = cts
            .map(|cts| i32::try_from(cts).map_err(|_| out_of_range("a composition offset", cts)))
            .transpose()?;
        if let Some(held) = self.held.take() {
            let duration = i128::from(dts).saturating_sub(i128::from(held.dts));
            let duration =
                u32::try_from(duration).map_err(|_| out_of_range("a sample duration", duration))?;
            self.finish(&held, duration);
        }
        let held = Held { frame, dts, cts };
        self.latest = held.pts();
        self.held = Some(held);
        Ok(anchored)
    }

    /// Where the presentation of the samples finished so far ends: where
    /// the earlier epochs' ends ([`Self::shown`]) or where the current
    /// one's before its held sample ends ([`Epoch::shown`]), whichever is
    /// later.
    fn presented(&self) -> i128 {
        self.epoch
            .as_ref()
            .and_then(Epoch::shown)
            .map_or(self.shown, |shown| self.shown.max(shown))
    }

    /// The presentation time of the latest frame taken, from the clip's
    /// media time 0; zero before the first.
    pub(crate) fn media_time(&self) -> Duration {
        duration_of(self.latest, self.clock_rate)
    }

    /// The decode time of the latest frame taken, from the clip's media
    /// time 0; zero before the first. It never goes back (see the
    /// module), and inside an epoch it follows the frames' timestamps,
    /// not their capture times.
    pub(crate) fn decode_time(&self) -> Duration {
        let dts = self.held.as_ref().map_or(0, |held| held.dts);
        duration_of(i128::from(dts), self.clock_rate)
    }

    /// Finishes the held sample, if any, with its frame's own length
    /// where the codec states one (audio: a frame's length is known
    /// before the next frame comes, and a packet longer than the one
    /// before it, an Opus packet of 40 ms after one of 20 ms, would
    /// otherwise end early), else the duration of the one before it
    /// (video), else a frame at [`FALLBACK_FRAME_RATE`].
    pub(crate) fn close(&mut self) {
        self.close_before(None);
    }

    /// [`close`](Self::close), with the sample cut short so its
    /// presentation ends at `next`, where the next epoch begins, when that
    /// is after its presentation began and before its duration ends: a
    /// reconnect quicker than a frame. The next epoch so begins at its
    /// capture time, and the track keeps its capture times (and its sync
    /// with the other track). The cut counts from the sample's presentation
    /// time, not its decode time, which an epoch's lead or reordering puts
    /// elsewhere (see the module), and never ends it before the track's
    /// presentation so far ends: reordered video's last sample in decode
    /// order may be presented before the others end, and cutting it would
    /// not bring the next epoch sooner. The cut is the hole's, not the
    /// frame's: the duration the next epoch's last sample inherits is the
    /// uncut one. The epoch so ends: where its presentation ends, the
    /// sample's end or the ones' before it ([`Epoch::shown`]), goes into
    /// [`Self::shown`].
    fn close_before(&mut self, next: Option<i128>) {
        let Some(held) = self.held.take() else {
            return;
        };
        let duration = self
            .frame_length(&held.frame)
            .or(self.last_duration)
            .unwrap_or(self.clock_rate / FALLBACK_FRAME_RATE);
        let shown = self.presented();
        let cut = next
            .map(|next| next.max(shown).saturating_sub(held.pts()))
            .and_then(|cut| u32::try_from(cut).ok())
            .filter(|cut| (1..duration).contains(cut));
        let length = cut.unwrap_or(duration);
        self.finish(&held, length);
        self.shown = shown.max(held.pts().saturating_add(i128::from(length)));
        self.last_duration = Some(duration);
    }

    /// The length of an audio frame in ticks; `None` for video, and for a
    /// packet that is not Opus.
    fn frame_length(&self, frame: &MediaFrame) -> Option<u32> {
        let (samples, rate) = match self.length {
            FrameLength::Video => return None,
            FrameLength::Aac { sample_rate } => (AAC_FRAME_SAMPLES, sample_rate),
            FrameLength::Opus => (packet_samples(&frame.payload).ok()?, OPUS_RATE),
        };
        let ticks = u64::from(samples)
            .saturating_mul(u64::from(self.clock_rate))
            .checked_div(u64::from(rate))?;
        u32::try_from(ticks).ok()
    }

    /// Whether `unit` is an H.265 parameter set the sample entry lacks
    /// while the samples still leave the entry's out (see the module).
    fn foreign_set(&self, unit: &[u8]) -> bool {
        !self.out_of_band.is_empty()
            && nal::unit_type(unit).is_some_and(nal::is_parameter_set)
            && !self.out_of_band.iter().any(|set| set.as_ref() == unit)
    }

    /// Makes `held` a sample of `duration` ready for the next fragment,
    /// and counts what it holds until the fragment goes out: its frame's
    /// payload, which its slices keep whole, its units' 4-byte lengths, and
    /// the descriptors of its pieces and its own. A frame of many tiny NAL
    /// units holds far more in descriptors than in media data: an access
    /// unit of one-byte units behind four-byte start codes, 64 bytes of
    /// descriptors per 5 bytes of media.
    fn finish(&mut self, held: &Held, duration: u32) {
        let payload = &held.frame.payload;
        let (pieces, lengths) = if self.video {
            let mut units = annex_b_units(payload);
            if units.iter().any(|unit| self.foreign_set(unit)) {
                // SPEC-DEVIATION (see the module): this sample's sets and
                // every later one's stay in band.
                self.out_of_band.clear();
            }
            units.retain(|unit| !self.out_of_band.iter().any(|set| set.as_ref() == *unit));
            let lengths_bytes = units.len().saturating_mul(4);
            let mut lengths = BytesMut::with_capacity(lengths_bytes);
            let mut pieces = Vec::with_capacity(units.len().saturating_mul(2));
            for unit in units {
                // A unit is shorter than its frame, which a sample bounds.
                lengths.put_u32(u32::try_from(unit.len()).unwrap_or(u32::MAX));
                pieces.push(lengths.split().freeze());
                pieces.push(payload.slice_ref(unit));
            }
            (pieces, lengths_bytes)
        } else {
            (vec![payload.clone()], 0)
        };
        let holds = payload
            .len()
            .saturating_add(lengths)
            .saturating_add(pieces.len().saturating_mul(size_of::<Bytes>()))
            .saturating_add(size_of::<Sample>());
        let size = pieces
            .iter()
            .map(Bytes::len)
            .fold(0_usize, usize::saturating_add);
        // At most a frame's bytes and a length per unit, which the muxer
        // keeps far below 4 GiB.
        let size = u32::try_from(size).unwrap_or(u32::MAX);
        let flags = self.video.then_some(if held.frame.keyframe {
            SYNC_SAMPLE
        } else {
            NON_SYNC_SAMPLE
        });
        self.ready.push(Sample {
            pieces,
            size,
            dts: held.dts,
            duration,
            flags,
            cts: held.cts,
        });
        self.ready_bytes = self
            .ready_bytes
            .saturating_add(u64::try_from(holds).unwrap_or(u64::MAX));
        self.last_duration = Some(duration);
        self.end = i128::from(held.dts).saturating_add(i128::from(duration));
    }

    /// What the samples ready for the next fragment hold: their frames'
    /// payloads, their lengths and their descriptors (see
    /// [`Self::finish`]).
    pub(crate) const fn ready_bytes(&self) -> u64 {
        self.ready_bytes
    }

    /// Takes the samples ready for the next fragment.
    pub(crate) fn take_ready(&mut self) -> Run {
        self.ready_bytes = 0;
        Run {
            track_id: self.track_id,
            samples: std::mem::take(&mut self.ready),
        }
    }
}

/// The track fragment of `run` with its run's data `offset` from the
/// first byte of the `moof`.
fn traf(run: &Run, offset: i32) -> Traf {
    let entries = run
        .samples
        .iter()
        .map(|sample| TrunEntry {
            duration: Some(sample.duration),
            size: Some(sample.size),
            flags: sample.flags,
            cts: sample.cts,
        })
        .collect();
    Traf {
        tfhd: Tfhd {
            track_id: run.track_id,
            default_base_is_moof: true,
            ..Tfhd::default()
        },
        tfdt: run.samples.first().map(|first| Tfdt {
            base_media_decode_time: first.dts,
        }),
        trun: vec![Trun {
            data_offset: Some(offset),
            entries,
        }],
        ..Traf::default()
    }
}

/// The movie fragment `sequence` of `runs` (those without samples left
/// out), and its media data: the `moof` and the `mdat` header in the
/// first piece, then the samples' bytes. Empty when no run has samples.
pub(crate) fn fragment(sequence: u32, runs: &[Run]) -> Result<Vec<Bytes>, ClipError> {
    let runs: Vec<&Run> = runs.iter().filter(|run| !run.samples.is_empty()).collect();
    if runs.is_empty() {
        return Ok(Vec::new());
    }
    let run_bytes: Vec<usize> = runs
        .iter()
        .map(|run| {
            run.samples
                .iter()
                .flat_map(|sample| &sample.pieces)
                .map(Bytes::len)
                .fold(0_usize, usize::saturating_add)
        })
        .collect();
    let media = run_bytes
        .iter()
        .copied()
        .fold(0_usize, usize::saturating_add);
    let mut mdat = Vec::new();
    Header {
        kind: Mdat::KIND,
        size: Some(media),
    }
    .encode(&mut mdat)
    .map_err(encode_failed)?;
    let mut moof = Moof {
        mfhd: Mfhd {
            sequence_number: sequence,
        },
        traf: runs.iter().map(|run| traf(run, 0)).collect(),
    };
    // The offsets do not change the size of the `moof`: measure it with
    // zeros, then write it with the real ones.
    let mut head = Vec::new();
    moof.encode(&mut head).map_err(encode_failed)?;
    let mut offset = head.len().saturating_add(mdat.len());
    for (traf, bytes) in moof.traf.iter_mut().zip(&run_bytes) {
        for trun in &mut traf.trun {
            // A fragment's media data stays far below 2 GiB (see the muxer).
            trun.data_offset = Some(i32::try_from(offset).unwrap_or(i32::MAX));
        }
        offset = offset.saturating_add(*bytes);
    }
    head.clear();
    moof.encode(&mut head).map_err(encode_failed)?;
    head.extend_from_slice(&mdat);
    let mut out = vec![Bytes::from(head)];
    for run in runs {
        for sample in &run.samples {
            out.extend(sample.pieces.iter().cloned());
        }
    }
    Ok(out)
}

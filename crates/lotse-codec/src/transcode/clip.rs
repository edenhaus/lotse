//! The event clips' audio transcoder: a G.711 (PCMU, PCMA) or G.722
//! track's frames in, Opus packets at 48 kHz out, for a clip container
//! that has no form for those codecs (ISO/IEC 14496-14 registers none) and
//! carries Opus ("Encapsulation of Opus in ISO Base Media File Format").
//!
//! One [`ToOpus`] per clip, which the clip's task calls on each audio
//! frame as its queue releases them, in capture order: the camera's frames
//! stay as they arrived in the pre-roll ring, and only a clip transcodes
//! them, the pre-roll's in a burst at its start. Synchronous and unpaced:
//! a clip writes as fast as its reader takes the bytes.
//!
//! The chain is the decoder ([`Law::decode`], G.711 §2 and §3;
//! [`g722::Decoder`], G.722 §4) → PCM at the codec's sampling rate, cut
//! into 20 ms chunks → [`Resampler`] to 48 kHz → a PCM FIFO →
//! [`Encoder`], 20 ms per packet (RFC 7587 §4.2: one frame per packet).
//! The resampler's first chunk of a timeline comes out a few samples short
//! of 20 ms (rubato 5: 948 of 960 from 8 kHz), so a timeline's first 20 ms
//! frame makes no packet and each one after it makes one.
//!
//! Timestamps compensate the chain's delay, as the AAC-LC chain's do, so a
//! decoded Opus sample carries the timestamp of the camera's sample it
//! came from. On the first frame of a timeline (timestamp `ts` at the
//! track's clock rate `r`), the anchor is `ts · 48000 / r` less the codec's
//! own delay (G.722's QMFs, [`g722::CODEC_DELAY`]; none for G.711), the
//! resampler's filter delay and the Opus look-ahead, and the `k`th packet
//! from there gets `anchor + 960·k` (RFC 7587 §4.1: a 48 kHz clock). The
//! container writes `PreSkip` 0, so the look-ahead is in the timestamps.
//! A packet's capture time is that of the frame its output epoch is placed
//! at (the timeline's first, or the first of an input epoch it goes on
//! through), moved by the distance of their timestamps: the container
//! places an epoch at its first packet's capture time, and without Sender
//! Reports a frame's capture time is its arrival, so a frame that comes
//! late moves no packet.
//!
//! The timeline follows the sample count. A frame whose timestamp is
//! within [`JITTER_TOLERANCE`] of where the count puts it continues the
//! timeline, as a camera's stamps wobble. A hole up to [`MAX_SILENCE`]
//! ahead (frames lost) is filled with silence, so the track stays one run
//! of packets and what follows sits where its timestamps say. A longer
//! hole or a step back re-anchors on the frame: the PCM not yet encoded
//! (less than a chunk and a packet) is dropped, the resampler forgets its
//! history, and the packets start a new output epoch, which the container
//! places by its capture time. A new input epoch or a `discontinuity`
//! whose timestamp continues the sample count, within the tolerance and
//! modulo 2^32 (RFC 3550 §5.1), is the same audio going on (the RTSP
//! source starts every track's epoch together when one track's timestamps
//! jump, and unwraps them afresh), so the timeline goes on, moved by that
//! multiple of 2^32, the G.722 decoder's state and all; its packets start
//! a new output epoch all the same, placed at that frame's capture time,
//! since the source forgets its clock mapping with the epoch and the
//! container places the video's new epoch at the new capture times. One
//! anywhere else re-anchors and also resets the G.722 decoder (the
//! camera's encoder may have started over). The Opus encoder is never
//! reset: its look-ahead splices the old timeline's last 2.5 ms in before
//! the new anchor, where they belong. A clip's end leaves the PCM not yet
//! encoded out, less than 20 ms plus the chain's delay.
//!
//! Implements RFC 7587 (Opus RTP: 48 kHz clock §4.1, one frame per packet
//! §4.2) over RFC 6716 frames, from ITU-T G.711 (RFC 3551 §4.5.14) and
//! ITU-T G.722 (RFC 3551 §4.5.2: 16 kHz samples on an 8000 Hz clock).

use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::clip::{ClipError, ClipTrack};
use lotse_core::codec::{Codec, CodecFamily};
use lotse_core::media::{MediaFrame, MediaTime};
use lotse_core::throttle::Throttle;

use super::{shift, to_48k};
use crate::g711::{self, Law};
use crate::g722;
use crate::opus::{Encoder, FRAME_SAMPLES as OPUS_FRAME, OpusError, SAMPLE_RATE};
use crate::resample::{ResampleError, Resampler};

/// How far a frame's timestamp may sit from where the sample count puts
/// it, either way, and still continue the timeline: 10 ms, half the 20 ms
/// a camera's G.711 or G.722 packet usually holds. Less is how a camera
/// stamps; the samples are contiguous all the same.
pub const JITTER_TOLERANCE: Duration = Duration::from_millis(10);

/// The longest hole ahead filled with silence: frames lost inside an
/// epoch. A longer one re-anchors, a hole of the real time in the file.
pub const MAX_SILENCE: Duration = Duration::from_secs(1);

/// Chunks the resampler takes per second: 20 ms each.
const CHUNKS_PER_SECOND: u32 = 50;

/// Milliseconds in a second, for the tolerance and silence bounds.
const MILLIS_PER_SECOND: u128 = 1_000;

/// [`OPUS_FRAME`] in 48 kHz ticks, 960: how far each packet's timestamp
/// moves (RFC 7587 §4.1).
#[expect(
    clippy::cast_possible_wrap,
    reason = "960 fits; `i64::try_from` is not const"
)]
const PACKET_TICKS: i64 = OPUS_FRAME as i64;

/// Full scale of 16-bit PCM, which the encoder takes as `[-1.0, 1.0]`.
const FULL_SCALE: f32 = 32_768.0;

/// The 48 kHz rate of the Opus track the chain feeds (RFC 7587 §4.1).
pub const OUTPUT_RATE: u32 = SAMPLE_RATE;

/// Whether [`ToOpus`] transcodes `codec`: G.711 (PCMU, PCMA) and G.722.
pub const fn transcodes(codec: &Codec) -> bool {
    matches!(codec, Codec::Pcmu | Codec::Pcma | Codec::G722)
}

/// `ticks` as a distance of 32-bit RTP timestamps (RFC 3550 §5.1): of
/// `ticks + k·2^32`, the one within ±2^31 of zero.
fn wrapped(ticks: i64) -> i64 {
    let low = u32::try_from(ticks & 0xFFFF_FFFF).unwrap_or_default();
    i64::from(i32::from_ne_bytes(low.to_ne_bytes()))
}

/// Why the chain could not be built or a frame not transcoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToOpusError {
    /// A codec other than G.711 and G.722.
    #[error("no clip transcode from {0}")]
    Unsupported(CodecFamily),
    /// A track without a clock rate.
    #[error("a track at 0 Hz")]
    ClockRate,
    /// The resampler refused its parameters or a chunk.
    #[error(transparent)]
    Resample(ResampleError),
    /// libopus refused its parameters or a frame.
    #[error(transparent)]
    Encode(OpusError),
}

impl From<ToOpusError> for ClipError {
    /// A transcode that failed fails the clip as its container would.
    fn from(err: ToOpusError) -> Self {
        Self::Failed(format!("audio transcode: {err}"))
    }
}

/// The decoder of the chain's input.
#[derive(Debug)]
enum Source {
    /// G.711: one code per sample, no state.
    G711(Law),
    /// G.722: the ADPCM and QMF state, boxed (G.711's is a byte).
    G722(Box<g722::Decoder>),
}

/// Where the current timeline stands.
#[derive(Debug, Clone, Copy, Default)]
struct Timeline {
    /// The input epoch it belongs to.
    input_epoch: u32,
    /// The input timestamp the sample count starts from.
    origin: i64,
    /// Input samples since `origin`, decoded and filled.
    samples: i64,
    /// The 48 kHz timestamp of the next packet.
    next_packet: i64,
    /// Added to a frame's timestamp to put it on this timeline: a multiple
    /// of 2^32 once an input epoch the audio went on through had its
    /// timestamps unwrapped afresh ([`ToOpus::cross`]); 0 otherwise.
    rebase: i64,
    /// The 48 kHz timestamp and the capture time of the frame the output
    /// epoch is placed at: the timeline's first, or the first of an input
    /// epoch the timeline went on through ([`ToOpus::cross`]); set with
    /// every output epoch. A packet's capture time is that one moved by the
    /// distance of their timestamps ([`ToOpus::captured`]). `None` before
    /// the first frame.
    placed: Option<(i64, Instant)>,
}

/// One clip's G.711 or G.722 → Opus chain.
#[derive(Debug)]
pub struct ToOpus {
    /// The input's decoder.
    source: Source,
    /// The input track's clock rate.
    clock_rate: u32,
    /// The input codec's sampling rate.
    sample_rate: u32,
    /// Input samples per resampler call: 20 ms.
    chunk: usize,
    /// To 48 kHz, one chunk per call.
    resampler: Resampler,
    /// The Opus encoder, 20 ms per call; never reset.
    encoder: Encoder,
    /// The input codec's own delay, in 48 kHz ticks.
    codec_delay: i64,
    /// [`JITTER_TOLERANCE`] in input ticks.
    tolerance: i64,
    /// [`MAX_SILENCE`] in input ticks.
    max_silence: i64,
    /// One frame's decoded samples.
    decoded: Vec<i16>,
    /// Input PCM not yet resampled: less than a chunk between frames.
    pcm: Vec<f32>,
    /// 48 kHz PCM not yet encoded: less than a packet between frames.
    fifo: Vec<f32>,
    /// The timeline, once [`Self::anchored`].
    timeline: Timeline,
    /// Whether a frame anchored the timeline.
    anchored: bool,
    /// The output epoch the packets carry: one more at every re-anchor and
    /// at every input epoch the timeline goes on through ([`Self::cross`]).
    epoch: u32,
    /// The next packet starts a new output epoch.
    fresh_epoch: bool,
    /// Rate-limits the lines of holes and re-anchors.
    moves: Throttle,
    /// Whether the last frame pushed went on the timeline before it
    /// ([`Self::continued`]); a re-anchor clears it.
    continued: bool,
}

impl ToOpus {
    /// The chain for a track of `codec` at `clock_rate`: G.711 or G.722.
    pub fn new(codec: &Codec, clock_rate: u32) -> Result<Self, ToOpusError> {
        let (source, sample_rate, codec_delay) = match codec {
            Codec::Pcmu => (Source::G711(Law::Mu), g711::SAMPLE_RATE, 0),
            Codec::Pcma => (Source::G711(Law::A), g711::SAMPLE_RATE, 0),
            Codec::G722 => (
                Source::G722(Box::default()),
                g722::SAMPLE_RATE,
                g722::CODEC_DELAY,
            ),
            other => return Err(ToOpusError::Unsupported(other.family())),
        };
        if clock_rate == 0 {
            return Err(ToOpusError::ClockRate);
        }
        let chunk =
            usize::try_from(sample_rate.checked_div(CHUNKS_PER_SECOND).unwrap_or(0)).unwrap_or(0);
        let resampler = Resampler::new(sample_rate, 1, chunk).map_err(ToOpusError::Resample)?;
        let encoder = Encoder::new(1).map_err(ToOpusError::Encode)?;
        let ticks = |span: Duration| {
            let ticks = span
                .as_millis()
                .saturating_mul(u128::from(clock_rate))
                .checked_div(MILLIS_PER_SECOND)
                .unwrap_or_default();
            i64::try_from(ticks).unwrap_or(i64::MAX)
        };
        Ok(Self {
            source,
            clock_rate,
            sample_rate,
            chunk,
            resampler,
            encoder,
            codec_delay: to_48k(i64::from(codec_delay), sample_rate),
            tolerance: ticks(JITTER_TOLERANCE),
            max_silence: ticks(MAX_SILENCE),
            decoded: Vec::new(),
            pcm: Vec::new(),
            fifo: Vec::new(),
            timeline: Timeline::default(),
            anchored: false,
            epoch: 0,
            fresh_epoch: false,
            moves: Throttle::default(),
            continued: false,
        })
    }

    /// The track the packets make: mono Opus at 48 kHz.
    pub const fn output() -> ClipTrack {
        ClipTrack {
            codec: Codec::Opus { channels: 1 },
            clock_rate: OUTPUT_RATE,
        }
    }

    /// How far the packets' timestamps and capture times are moved back
    /// from the samples they came from: the codec's own delay, the
    /// resampler's filter delay and the Opus look-ahead.
    pub fn delay(&self) -> Duration {
        MediaTime::from_ticks(self.compensation())
            .to_duration(OUTPUT_RATE)
            .unwrap_or_default()
    }

    /// [`Self::delay`] in 48 kHz ticks.
    fn compensation(&self) -> i64 {
        self.codec_delay
            .saturating_add(i64::from(self.resampler.delay()))
            .saturating_add(i64::from(self.encoder.lookahead()))
    }

    /// Whether the last frame pushed went on the timeline of the frames
    /// before it, the decoder and the sample count with it: within the
    /// tolerance, after a hole filled with silence, or across an input
    /// epoch it continues (whose packets start a new output epoch all the
    /// same). Not the first frame, nor one that re-anchored.
    pub const fn continued(&self) -> bool {
        self.continued
    }

    /// `frame`'s timestamp on the timeline ([`Timeline::rebase`]).
    fn ts(&self, frame: &MediaFrame) -> i64 {
        frame.ts.ticks().saturating_add(self.timeline.rebase)
    }

    /// The input timestamp where the timeline's sample count is, rounded
    /// down.
    fn position(&self) -> i64 {
        let ticks = i128::from(self.timeline.samples)
            .saturating_mul(i128::from(self.clock_rate))
            .checked_div(i128::from(self.sample_rate))
            .unwrap_or_default();
        self.timeline
            .origin
            .saturating_add(i64::try_from(ticks).unwrap_or(i64::MAX))
    }

    /// The capture time of the packet at `ts`: the placed frame's
    /// ([`Timeline::placed`]) moved by the distance of their timestamps,
    /// whichever frame completes the packet; `frame`'s before any frame
    /// placed one, which never comes ([`Self::push`] anchors first).
    fn captured(&self, ts: i64, frame: &MediaFrame) -> Instant {
        self.timeline
            .placed
            .map_or(frame.wallclock, |(placed, at)| {
                shift(at, ts.saturating_sub(placed))
            })
    }

    /// Starts a new output epoch at the next packet, which the container
    /// places at its capture time.
    fn new_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.fresh_epoch = true;
    }

    /// One input frame: the Opus packets it completes, in order, each a
    /// frame of the output track at 48 kHz.
    pub fn push(&mut self, frame: &MediaFrame) -> Result<Vec<Arc<MediaFrame>>, ToOpusError> {
        // A re-anchor, the first frame's included, clears it ([`Self::anchor`]).
        self.continued = true;
        if !self.anchored {
            self.anchor(frame, 0, false);
        } else if self.timeline.input_epoch != frame.epoch || frame.discontinuity {
            self.cross(frame);
        } else {
            let offset = self.ts(frame).saturating_sub(self.position());
            if offset.saturating_abs() > self.tolerance {
                if offset > 0 && offset <= self.max_silence {
                    self.fill(offset, frame);
                } else {
                    self.anchor(frame, offset, false);
                }
            }
        }
        self.decode(&frame.payload);
        let mut packets = Vec::new();
        let mut start = 0_usize;
        while let Some(chunk) = self.pcm.get(start..start.saturating_add(self.chunk)) {
            let resampled = self
                .resampler
                .process(chunk)
                .map_err(ToOpusError::Resample)?;
            self.fifo.extend_from_slice(resampled);
            start = start.saturating_add(self.chunk);
        }
        self.pcm.drain(..start);
        let mut start = 0_usize;
        while let Some(pcm) = self.fifo.get(start..start.saturating_add(OPUS_FRAME)) {
            let payload = self.encoder.encode(pcm).map_err(ToOpusError::Encode)?;
            let ts = self.timeline.next_packet;
            self.timeline.next_packet = ts.saturating_add(PACKET_TICKS);
            let wallclock = self.captured(ts, frame);
            packets.push(Arc::new(MediaFrame {
                ts: MediaTime::from_ticks(ts),
                wallclock,
                arrival: frame.arrival,
                keyframe: true,
                discontinuity: std::mem::take(&mut self.fresh_epoch),
                epoch: self.epoch,
                payload,
            }));
            start = start.saturating_add(OPUS_FRAME);
        }
        self.fifo.drain(..start);
        Ok(packets)
    }

    /// Decodes `payload` onto the input PCM and counts its samples.
    fn decode(&mut self, payload: &[u8]) {
        self.decoded.clear();
        match &mut self.source {
            Source::G711(law) => self
                .decoded
                .extend(payload.iter().map(|code| law.decode(*code))),
            Source::G722(decoder) => decoder.decode(payload, &mut self.decoded),
        }
        self.pcm.extend(
            self.decoded
                .iter()
                .map(|sample| f32::from(*sample) / FULL_SCALE),
        );
        self.count(self.decoded.len());
    }

    /// Adds `samples` input samples to the timeline's count.
    fn count(&mut self, samples: usize) {
        self.timeline.samples = self
            .timeline
            .samples
            .saturating_add(i64::try_from(samples).unwrap_or(i64::MAX));
    }

    /// Fills a hole of `ticks` input ticks before `frame` with silence.
    fn fill(&mut self, ticks: i64, frame: &MediaFrame) {
        let samples = i128::from(ticks)
            .saturating_mul(i128::from(self.sample_rate))
            .checked_div(i128::from(self.clock_rate))
            .unwrap_or_default();
        let samples = usize::try_from(samples).unwrap_or(0);
        if let Some(count) = self.moves.hit(frame.arrival) {
            tracing::debug!(
                hole_ticks = ticks,
                samples,
                count,
                "clip audio: frames lost; the hole is filled with silence"
            );
        }
        self.pcm.resize(self.pcm.len().saturating_add(samples), 0.0);
        self.count(samples);
    }

    /// A new input epoch or a discontinuity at `frame`. A timestamp that
    /// continues the sample count within the tolerance, read modulo 2^32
    /// ([`wrapped`]), is the same audio going on: the RTSP source starts
    /// every track's epoch together when one track's timestamps jump, and
    /// unwraps every track's timestamps afresh with it. The timeline then
    /// takes the epoch, its timestamps moved by that multiple of 2^32, and
    /// keeps the decoder's state, the resampler's and the PCM, so the
    /// packets' timestamps go on in one run. They start a new output epoch
    /// all the same, placed at `frame`'s capture time: the source forgets
    /// its clock mapping with the epoch (Sender Reports until then,
    /// arrivals after), so the capture times can step there, and the
    /// container places the video's new epoch at the new ones. Any other
    /// timestamp may be the camera's encoder starting over: a re-anchor
    /// that resets the decoder.
    fn cross(&mut self, frame: &MediaFrame) {
        let offset = self.ts(frame).saturating_sub(self.position());
        let near = wrapped(offset);
        if near.saturating_abs() > self.tolerance {
            self.anchor(frame, 0, true);
            return;
        }
        if let Some(count) = self.moves.hit(frame.arrival) {
            tracing::debug!(
                input_epoch = frame.epoch,
                offset_ticks = near,
                count,
                "clip audio: a new input epoch continues the sample count; the decoder goes on in a new output epoch"
            );
        }
        self.timeline.input_epoch = frame.epoch;
        self.timeline.rebase = self
            .timeline
            .rebase
            .saturating_add(near.saturating_sub(offset));
        self.new_epoch();
        // The sample count, where the frame's audio goes in the run, not
        // its timestamp, which may be off it by up to the tolerance: the
        // packets follow the count, so a jittered stamp would place the new
        // epoch that far off and overlap or leave a hole after the last.
        self.timeline.placed = Some((to_48k(self.position(), self.clock_rate), frame.wallclock));
    }

    /// Starts a timeline at `frame`, placed at its capture time, `offset`
    /// ticks off the old one's sample count (0 for a new input epoch or a
    /// first frame); a new output epoch unless it is the first. `restart` (a new input epoch or
    /// a discontinuity off the sample count, [`Self::cross`]) resets the
    /// decoder.
    fn anchor(&mut self, frame: &MediaFrame, offset: i64, restart: bool) {
        if self.anchored {
            let reason = if restart {
                "restart"
            } else if offset > 0 {
                "hole"
            } else {
                "backwards"
            };
            if let Some(count) = self.moves.hit(frame.arrival) {
                tracing::debug!(
                    reason,
                    offset_ticks = offset,
                    count,
                    "clip audio: timeline re-anchored; a new output epoch"
                );
            }
            self.new_epoch();
        }
        if restart && let Source::G722(decoder) = &mut self.source {
            decoder.reset();
        }
        self.pcm.clear();
        self.fifo.clear();
        self.resampler.reset();
        let ts = frame.ts.ticks();
        let at = to_48k(ts, self.clock_rate);
        self.anchored = true;
        self.continued = false;
        self.timeline = Timeline {
            input_epoch: frame.epoch,
            origin: ts,
            samples: 0,
            next_packet: at.saturating_sub(self.compensation()),
            rebase: 0,
            placed: Some((at, frame.wallclock)),
        };
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "test code; signal math in floats"
    )]

    use std::time::Instant;

    use lotse_core::clock::{Clock as _, FakeClock};
    use tracing::Level;

    use super::super::tests::Logs;
    use super::*;
    use crate::g722::test_data::encode;
    use crate::opus::{self, Decoder};

    /// Input ticks in one 20 ms frame at the 8000 Hz clock of G.711 and
    /// G.722 (RFC 3551 §4.5.2, §4.5.14).
    const FRAME_TICKS: i64 = 160;

    /// Where every test's timeline starts: far from 0, so nothing leans on
    /// a zero origin.
    const TS0: i64 = 1_234_560;

    const CODECS: [Codec; 3] = [Codec::Pcmu, Codec::Pcma, Codec::G722];

    fn t0() -> Instant {
        FakeClock::default().now()
    }

    /// `ms` of silence, then `ms_tone` of a 1 kHz sine at half scale, at
    /// `rate`.
    fn onset(rate: u32, ms_silence: u32, ms_tone: u32) -> Vec<i16> {
        let silence = (rate / 1_000 * ms_silence) as usize;
        let tone = (rate / 1_000 * ms_tone) as usize;
        std::iter::repeat_n(0, silence)
            .chain((0..tone).map(|index| {
                let phase = std::f64::consts::TAU * 1_000.0 * index as f64 / f64::from(rate);
                (16_384.0 * phase.sin()) as i16
            }))
            .collect()
    }

    /// `pcm` at the codec's sampling rate, encoded in 20 ms payloads.
    fn payloads(codec: &Codec, pcm: &[i16]) -> Vec<Vec<u8>> {
        let rate = codec.sample_rate().unwrap();
        let per_frame = (rate / CHUNKS_PER_SECOND) as usize;
        pcm.chunks(per_frame)
            .map(|chunk| match Law::of(codec) {
                Some(law) => chunk.iter().map(|sample| law.encode(*sample)).collect(),
                None => encode(chunk),
            })
            .collect()
    }

    fn frame(ts: i64, epoch: u32, wallclock: Instant, payload: Vec<u8>) -> MediaFrame {
        MediaFrame {
            ts: MediaTime::from_ticks(ts),
            wallclock,
            arrival: wallclock,
            keyframe: true,
            discontinuity: false,
            epoch,
            payload: payload.into(),
        }
    }

    /// The input frames of `pcm`: 20 ms each from [`TS0`], captured 20 ms
    /// apart from `t0`.
    fn frames(codec: &Codec, pcm: &[i16], t0: Instant) -> Vec<MediaFrame> {
        payloads(codec, pcm)
            .into_iter()
            .enumerate()
            .map(|(index, payload)| {
                let index = index as u32;
                frame(
                    TS0 + i64::from(index) * FRAME_TICKS,
                    0,
                    t0 + Duration::from_millis(u64::from(index) * 20),
                    payload,
                )
            })
            .collect()
    }

    fn run(chain: &mut ToOpus, frames: &[MediaFrame]) -> Vec<Arc<MediaFrame>> {
        frames
            .iter()
            .flat_map(|frame| chain.push(frame).unwrap())
            .collect()
    }

    /// The packets' timestamps, epochs and discontinuity flags.
    fn timeline(packets: &[Arc<MediaFrame>]) -> Vec<(i64, u32, bool)> {
        packets
            .iter()
            .map(|packet| (packet.ts.ticks(), packet.epoch, packet.discontinuity))
            .collect()
    }

    /// The anchor of a timeline whose first frame is at `ts`.
    fn anchor(chain: &ToOpus, ts: i64) -> i64 {
        ts * 6 - chain.compensation()
    }

    #[test]
    fn only_g711_and_g722_are_transcoded() {
        for codec in CODECS {
            assert!(transcodes(&codec));
            assert!(ToOpus::new(&codec, 8_000).is_ok());
        }
        let aac = Codec::AacLc {
            sample_rate: 16_000,
            channels: 1,
            config: bytes::Bytes::from_static(&[0x14, 0x08]),
        };
        assert!(!transcodes(&aac));
        assert!(!transcodes(&Codec::Opus { channels: 1 }));
        assert_eq!(
            ToOpus::new(&aac, 16_000).unwrap_err(),
            ToOpusError::Unsupported(CodecFamily::AacLc)
        );
        assert_eq!(
            ToOpus::new(&Codec::Pcmu, 0).unwrap_err(),
            ToOpusError::ClockRate
        );
        assert_eq!(ToOpusError::ClockRate.to_string(), "a track at 0 Hz");
        assert_eq!(
            ToOpusError::Unsupported(CodecFamily::AacLc).to_string(),
            "no clip transcode from aac_lc"
        );
        assert_eq!(
            ClipError::from(ToOpusError::ClockRate),
            ClipError::Failed("audio transcode: a track at 0 Hz".into())
        );
        assert_eq!(
            ToOpus::output(),
            ClipTrack {
                codec: Codec::Opus { channels: 1 },
                clock_rate: 48_000,
            }
        );
    }

    /// The delay the timestamps take back: the resampler's filter and the
    /// Opus look-ahead (120 ticks, 2.5 ms), and G.722's QMFs (22 samples at
    /// 16 kHz, 66 ticks).
    #[test]
    fn rfc7587_4_1_the_delay_is_the_codec_s_the_resampler_s_and_the_look_ahead() {
        let lookahead = i64::from(Encoder::new(1).unwrap().lookahead());
        assert_eq!(lookahead, 120);
        let filter = |rate: u32| {
            i64::from(
                Resampler::new(rate, 1, (rate / 50) as usize)
                    .unwrap()
                    .delay(),
            )
        };
        for (codec, ticks) in [
            (Codec::Pcmu, filter(8_000) + lookahead),
            (Codec::Pcma, filter(8_000) + lookahead),
            (Codec::G722, filter(16_000) + lookahead + 66),
        ] {
            let chain = ToOpus::new(&codec, 8_000).unwrap();
            assert_eq!(chain.compensation(), ticks, "{codec:?}");
            assert_eq!(
                chain.delay(),
                Duration::from_nanos(ticks as u64 * 1_000_000_000 / 48_000)
            );
        }
    }

    /// One second in 20 ms frames comes out as 20 ms packets, one per
    /// frame, 960 ticks apart from the compensated anchor, each a valid
    /// Opus packet of 960 samples; the first is captured `delay` before
    /// the first frame. The resampler's first chunk comes out a few
    /// samples short of 20 ms (rubato 5: 948 of 960 from 8 kHz, 954 from
    /// 16 kHz), so the last packet waits for the next frame: 49.
    #[test]
    fn rfc7587_4_2_one_packet_per_20_ms_from_the_compensated_anchor() {
        for codec in CODECS {
            let t0 = t0();
            let mut chain = ToOpus::new(&codec, 8_000).unwrap();
            let rate = codec.sample_rate().unwrap();
            let input = frames(&codec, &onset(rate, 0, 1_000), t0);
            assert_eq!(input.len(), 50);
            let packets = run(&mut chain, &input);
            assert_eq!(packets.len(), 49, "{codec:?}");
            let first = anchor(&chain, TS0);
            let expected: Vec<(i64, u32, bool)> =
                (0..49).map(|k| (first + 960 * k, 0, false)).collect();
            assert_eq!(timeline(&packets), expected, "{codec:?}");
            for packet in &packets {
                assert_eq!(opus::packet_samples(&packet.payload), Ok(960));
                assert!(packet.keyframe);
            }
            assert_eq!(
                packets[0].wallclock,
                t0.checked_sub(chain.delay()).unwrap(),
                "{codec:?}"
            );
            assert_eq!(
                packets[0].arrival,
                t0 + Duration::from_millis(20),
                "the second frame completes it"
            );
        }
    }

    /// The decoded Opus carries each sample at the timestamp of the
    /// camera's sample it came from: a tone that starts 200 ms in starts
    /// 9600 ticks after the first frame's timestamp, within half a
    /// millisecond (measured: 4 to 11 ticks late, the threshold's own lag),
    /// for every codec; and as many samples come out as went in, but for
    /// the last packet the resampler's short start holds back.
    #[test]
    fn rfc7587_4_1_a_tone_onset_keeps_its_timestamp_and_the_sample_count_its_length() {
        for codec in CODECS {
            let mut chain = ToOpus::new(&codec, 8_000).unwrap();
            let rate = codec.sample_rate().unwrap();
            let input = frames(&codec, &onset(rate, 200, 600), t0());
            let packets = run(&mut chain, &input);
            let mut decoder = Decoder::new(48_000).unwrap();
            let mut pcm = Vec::new();
            for packet in &packets {
                pcm.extend_from_slice(decoder.decode(&packet.payload).unwrap());
            }
            assert_eq!(pcm.len(), 48 * 780, "{codec:?}: 800 ms in, 780 ms out");
            let start = pcm
                .iter()
                .position(|sample| sample.unsigned_abs() > 8_192)
                .unwrap() as i64;
            let off = packets[0].ts.ticks() + start - (TS0 * 6 + 200 * 48);
            assert!(off.abs() <= 24, "{codec:?}: the onset {off} ticks off");
        }
    }

    /// Timestamps a few milliseconds off the sample count are how a camera
    /// stamps: the packets stay one run.
    #[test]
    fn a_camera_s_jitter_within_10_ms_keeps_the_timeline() {
        let (logs, _guard) = Logs::capture();
        let t0 = t0();
        let mut chain = ToOpus::new(&Codec::Pcmu, 8_000).unwrap();
        let mut input = frames(&Codec::Pcmu, &onset(8_000, 0, 200), t0);
        for (index, frame) in input.iter_mut().enumerate() {
            let jitter = [0, 79, -80, 40, -3][index % 5];
            frame.ts = MediaTime::from_ticks(frame.ts.ticks() + jitter);
        }
        let packets = run(&mut chain, &input);
        let first = anchor(&chain, TS0);
        let expected: Vec<(i64, u32, bool)> = (0..9).map(|k| (first + 960 * k, 0, false)).collect();
        assert_eq!(timeline(&packets), expected);
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "clip audio: frames lost; the hole is filled with silence"
            ),
            0
        );
    }

    /// Lost frames inside an epoch, up to a second, become silence: the
    /// packets go on in one run, as many as the time the frames spanned,
    /// and the samples after the hole keep their timestamps.
    #[test]
    fn a_hole_up_to_a_second_is_filled_with_silence() {
        let (logs, _guard) = Logs::capture();
        for codec in CODECS {
            let t0 = t0();
            let mut chain = ToOpus::new(&codec, 8_000).unwrap();
            let rate = codec.sample_rate().unwrap();
            let mut input = frames(&codec, &onset(rate, 0, 2_000), t0);
            // Frames 10 and 11 (40 ms), then 30 to 79 (one second) are lost.
            input.drain(30..80);
            input.drain(10..12);
            let packets = run(&mut chain, &input);
            let first = anchor(&chain, TS0);
            let expected: Vec<(i64, u32, bool)> =
                (0..99).map(|k| (first + 960 * k, 0, false)).collect();
            assert_eq!(timeline(&packets), expected, "{codec:?}");
        }
        let lines = logs.fields(
            Level::DEBUG,
            "clip audio: frames lost; the hole is filled with silence",
        );
        assert!(
            lines
                .first()
                .unwrap()
                .contains(&"hole_ticks=320".to_owned()),
            "{lines:?}"
        );
    }

    /// A hole longer than a second, a step back past the tolerance, and a
    /// new input epoch or a discontinuity off the sample count (even by
    /// less than a second, which inside one epoch would be silence) each
    /// re-anchor on the frame: the next packet starts a new output epoch at
    /// the frame's timestamp less the delay, and the chain logs why, once
    /// in 10 s at most.
    #[test]
    fn a_long_hole_a_step_back_and_a_restart_re_anchor_in_a_new_epoch() {
        let (logs, _guard) = Logs::capture();
        for codec in CODECS {
            let t0 = t0();
            let mut chain = ToOpus::new(&codec, 8_000).unwrap();
            let rate = codec.sample_rate().unwrap();
            let pcm = onset(rate, 0, 200);
            let ten = frames(&codec, &pcm, t0);
            let mut packets = run(&mut chain, &ten);
            // Each move arrives 11 s after the one before, so each is logged,
            // but the discontinuity, which comes with the restart's frames.
            let shifted = |by: i64, epoch: u32, later: u64| -> Vec<MediaFrame> {
                ten.iter()
                    .map(|frame| MediaFrame {
                        ts: MediaTime::from_ticks(frame.ts.ticks() + by),
                        arrival: frame.arrival + Duration::from_secs(11 * later),
                        epoch,
                        ..frame.clone()
                    })
                    .collect()
            };
            // 1.0125 s after the last frame's end: no silence that long.
            let hole = 1_600 + 8_100;
            packets.extend(run(&mut chain, &shifted(hole, 0, 1)));
            // Back to the first frame's timestamp, past the tolerance.
            packets.extend(run(&mut chain, &shifted(0, 0, 2)));
            // The camera restarted: a new epoch 100 ms off the count (inside
            // one epoch, silence).
            packets.extend(run(&mut chain, &shifted(2_400, 1, 3)));
            // A discontinuity in the same epoch, off the count again.
            let mut again = shifted(4_800, 1, 3);
            again[0].discontinuity = true;
            packets.extend(run(&mut chain, &again));
            let mut expected = Vec::new();
            for (epoch, ts) in [
                (0, TS0),
                (1, TS0 + hole),
                (2, TS0),
                (3, TS0 + 2_400),
                (4, TS0 + 4_800),
            ] {
                let first = anchor(&chain, ts);
                expected.extend((0..9).map(|k| (first + 960 * k, epoch, k == 0 && epoch > 0)));
            }
            assert_eq!(timeline(&packets), expected, "{codec:?}");
        }
        let reasons: Vec<String> = logs
            .fields(
                Level::DEBUG,
                "clip audio: timeline re-anchored; a new output epoch",
            )
            .into_iter()
            .take(3)
            .map(|fields| fields[0].clone())
            .collect();
        assert_eq!(
            reasons,
            [
                "reason=\"hole\"",
                "reason=\"backwards\"",
                "reason=\"restart\"",
            ]
        );
    }

    /// A new input epoch with a discontinuity whose timestamp continues the
    /// sample count, within the tolerance, is the same audio going on: the
    /// RTSP source starts every track's epoch when another track's
    /// timestamps jump, and unwraps the timestamps afresh, k·2^32 lower
    /// after a wrap (RFC 3550 §5.1). The G.722 decoder keeps its state and
    /// the packets their timestamps and payloads, as without the epoch;
    /// they start a new output epoch at the first packet the epoch's frame
    /// completes ([`ToOpus::cross`]). Regression: the epoch reset the
    /// decoder and dropped the PCM not yet encoded, in audio that went on.
    #[test]
    fn a_new_epoch_that_continues_the_sample_count_keeps_the_decoder_and_the_run() {
        let (logs, _guard) = Logs::capture();
        let mut input = frames(&Codec::G722, &onset(16_000, 0, 1_000), t0());
        // Stamped 80 ticks (10 ms, the tolerance) late, as a camera's stamps wobble.
        input[25].ts = MediaTime::from_ticks(input[25].ts.ticks() + 80);
        let whole = run(&mut ToOpus::new(&Codec::G722, 8_000).unwrap(), &input);
        assert_eq!(whole.len(), 49);
        let audio = |packets: &[Arc<MediaFrame>]| -> Vec<(i64, bytes::Bytes)> {
            packets
                .iter()
                .map(|packet| (packet.ts.ticks(), packet.payload.clone()))
                .collect()
        };
        for wrap in [0, 1_i64 << 32] {
            let mut split = input.clone();
            for frame in &mut split[25..] {
                frame.epoch = 1;
                frame.ts = MediaTime::from_ticks(frame.ts.ticks() - wrap);
            }
            split[25].discontinuity = true;
            let packets = run(&mut ToOpus::new(&Codec::G722, 8_000).unwrap(), &split);
            assert_eq!(audio(&packets), audio(&whole), "wrap {wrap}");
            // Placed by the sample count, not by frame 25's late stamp: the
            // capture times go on as in the unsplit run.
            let captured = |packets: &[Arc<MediaFrame>]| -> Vec<Instant> {
                packets.iter().map(|packet| packet.wallclock).collect()
            };
            assert_eq!(captured(&packets), captured(&whole), "wrap {wrap}");
            // Frame 25 completes packet 24: the new output epoch starts there.
            let epochs: Vec<(u32, bool)> = packets
                .iter()
                .map(|packet| (packet.epoch, packet.discontinuity))
                .collect();
            let expected: Vec<(u32, bool)> =
                (0..49).map(|k| (u32::from(k >= 24), k == 24)).collect();
            assert_eq!(epochs, expected, "wrap {wrap}");
        }
        assert_eq!(
            logs.count(
                Level::DEBUG,
                "clip audio: a new input epoch continues the sample count; the decoder goes on in a new output epoch"
            ),
            2
        );
    }

    /// The capture times can step at a new input epoch while the audio's
    /// timestamps go on: the RTSP source forgets its clock mapping with the
    /// epoch (Sender Reports until then, arrivals after), and the container
    /// places the video's new epoch at its new capture times. The packets,
    /// from the first one the epoch's first frame completes, start a new
    /// output epoch placed at that frame's capture time, a second later
    /// here, while their timestamps go on. Regression: they went on in the
    /// output epoch the container had placed at the old capture times, and
    /// the audio played a second before its video.
    #[test]
    fn a_new_epoch_that_moves_the_capture_times_starts_an_output_epoch_placed_at_them() {
        for codec in CODECS {
            let t0 = t0();
            let rate = codec.sample_rate().unwrap();
            let mut input = frames(&codec, &onset(rate, 0, 400), t0);
            for frame in &mut input[10..] {
                frame.epoch = 1;
                frame.wallclock += Duration::from_secs(1);
                frame.arrival = frame.wallclock;
            }
            input[10].discontinuity = true;
            let mut chain = ToOpus::new(&codec, 8_000).unwrap();
            let packets = run(&mut chain, &input);
            let first = anchor(&chain, TS0);
            let expected: Vec<(i64, u32, bool)> = (0..19)
                .map(|k| (first + 960 * k, u32::from(k >= 9), k == 9))
                .collect();
            assert_eq!(timeline(&packets), expected, "{codec:?}");
            for (k, packet) in packets.iter().enumerate() {
                let stepped = if k >= 9 {
                    Duration::from_secs(1)
                } else {
                    Duration::ZERO
                };
                let at = t0 + stepped + Duration::from_millis(20 * k as u64);
                assert_eq!(
                    packet.wallclock,
                    at.checked_sub(chain.delay()).unwrap(),
                    "{codec:?}: packet {k}"
                );
            }
        }
    }

    /// A packet's capture time counts from the frame its output epoch is
    /// placed at, by the distance of their timestamps, not from the frame
    /// that completes it: without Sender Reports a frame's capture time is
    /// its arrival, and a frame that comes late moves no packet. Contiguous
    /// frames, all but an epoch's first up to 250 ms late, give the packets
    /// the epoch's first frame's capture time less the delay, 20 ms apart,
    /// also after a re-anchor. Regression: the first packet took the
    /// completing frame's capture time, 93.5 ms for PCMU when the second
    /// frame, stamped 20 ms, came at 120 ms, instead of -6.5 ms, and the
    /// container placed the whole epoch there, 100 ms after its video.
    #[test]
    fn a_packet_s_capture_time_counts_from_its_epoch_s_first_frame_not_a_late_one() {
        let late = [0, 100, 37, 250, 3, 0, 80, 12, 0, 40];
        for codec in CODECS {
            let t0 = t0();
            let rate = codec.sample_rate().unwrap();
            let ten = frames(&codec, &onset(rate, 0, 200), t0);
            // The same ten 1.0125 s after the first ten end (a re-anchor), 2 s later.
            let hole = 1_600 + 8_100;
            let again = ten.iter().map(|frame| MediaFrame {
                ts: MediaTime::from_ticks(frame.ts.ticks() + hole),
                wallclock: frame.wallclock + Duration::from_secs(2),
                ..frame.clone()
            });
            let input: Vec<MediaFrame> = ten
                .iter()
                .cloned()
                .chain(again)
                .zip(late.iter().cycle())
                .map(|(frame, ms)| {
                    let wallclock = frame.wallclock + Duration::from_millis(*ms);
                    MediaFrame {
                        wallclock,
                        arrival: wallclock,
                        ..frame
                    }
                })
                .collect();
            let mut chain = ToOpus::new(&codec, 8_000).unwrap();
            let packets = run(&mut chain, &input);
            assert_eq!(packets.len(), 18, "{codec:?}");
            for (k, packet) in packets.iter().enumerate() {
                let (epoch, since) = if k < 9 {
                    (0, Duration::from_millis(20 * k as u64))
                } else {
                    (
                        1,
                        Duration::from_secs(2) + Duration::from_millis(20 * (k as u64 - 9)),
                    )
                };
                assert_eq!(packet.epoch, epoch, "{codec:?}: packet {k}");
                assert_eq!(
                    packet.wallclock,
                    (t0 + since).checked_sub(chain.delay()).unwrap(),
                    "{codec:?}: packet {k}"
                );
            }
        }
    }

    /// A timestamp distance reads modulo 2^32, the nearest way: what a
    /// source's unwrapping started afresh moves by.
    #[test]
    fn rfc3550_5_1_a_timestamp_distance_reads_modulo_2_32() {
        for (ticks, near) in [
            (80, 80),
            (-80, -80),
            (80 - (1_i64 << 32), 80),
            ((1_i64 << 32) - 80, -80),
            (3 << 32, 0),
            (1 << 31, -(1 << 31)),
            ((1 << 31) - 1, (1 << 31) - 1),
        ] {
            assert_eq!(wrapped(ticks), near, "{ticks}");
        }
    }

    /// `continued` tells a frame on the run before it (within the
    /// tolerance, after a hole filled with silence, across an epoch it
    /// continues) from the first and from one that re-anchors (an epoch off
    /// the count, a step back, a hole over a second).
    #[test]
    fn continued_is_a_frame_on_the_run_before_it_not_one_that_re_anchors() {
        let mut chain = ToOpus::new(&Codec::Pcmu, 8_000).unwrap();
        let input = frames(&Codec::Pcmu, &onset(8_000, 0, 200), t0());
        let mut push = |frame: &MediaFrame, epoch: u32| {
            chain
                .push(&MediaFrame {
                    epoch,
                    ..frame.clone()
                })
                .unwrap();
            chain.continued()
        };
        assert!(!push(&input[0], 0), "the first anchors");
        assert!(push(&input[1], 0), "the next");
        assert!(push(&input[3], 0), "after a hole filled with silence");
        assert!(push(&input[4], 1), "across an epoch it continues");
        assert!(!push(&input[6], 2), "a new epoch 20 ms off restarts");
        assert!(!push(&input[0], 2), "a step back");
        let mut far = input[1].clone();
        far.ts = MediaTime::from_ticks(far.ts.ticks() + 8_160);
        assert!(!push(&far, 2), "a hole over a second");
    }

    /// A frame without samples moves nothing and makes no packet.
    #[test]
    fn an_empty_frame_makes_no_packet() {
        let mut chain = ToOpus::new(&Codec::G722, 8_000).unwrap();
        assert!(
            chain
                .push(&frame(TS0, 0, t0(), Vec::new()))
                .unwrap()
                .is_empty()
        );
        let input = frames(&Codec::G722, &onset(16_000, 0, 40), t0());
        let packets = run(&mut chain, &input);
        assert_eq!(timeline(&packets), [(anchor(&chain, TS0), 0, false)]);
    }
}

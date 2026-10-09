//! The AAC-LC → Opus transcoder: a source track's AAC frames in, a derived
//! Opus track at 48 kHz out, one task per derived track.
//!
//! The chain is [`AacDecoder`] → [`Resampler`] (one decoded frame per call)
//! → a PCM FIFO at 48 kHz → [`Encoder`] (20 ms frames) → a pacer. One AAC
//! frame completes several Opus packets at once; the pacer releases them
//! one Opus frame apart, at the media rate, instead of in a clump the
//! browser would read as jitter (`pace`). Each packet is published on the
//! output track when released, as a side-branch frame carrying its
//! capture time and then live, so the derived track looks like any other
//! and a session maps its packets through the frames
//! (`Track::capture_time`).
//!
//! Timestamps compensate the chain's own delay, so a decoded Opus sample
//! carries the capture time of the AAC sample it came from. On the first
//! frame of a timeline (timestamp `ts` at the AAC rate `r`), the anchor is
//! `(ts − DECODER_DELAY) · 48000 / r` (the decoder's PCM describes the
//! frame before), and the `k`th 20 ms packet from there gets
//! `anchor + 960·k − resampler delay − Opus look-ahead`, wrapped to 32 bits
//! (RFC 7587 §4.1, RFC 3550 §5.1). The stream follows the sample count:
//! one frame's timestamp says little, so the camera's timeline counts as
//! moved only when the median offset of the last 16 frames from the sample
//! count moves more than half a frame (a lost frame moves it a whole one),
//! and the new timeline starts where that median puts it. A new input
//! epoch, a `discontinuity`, such a move, a frame that fails to decode, or
//! a lag on the side branch resets the decoder, the resampler and the FIFO
//! and re-anchors on the next frame. The output
//! track starts a new epoch when the input's did, or when the new anchor
//! would overlap packets already sent; a forward gap keeps the epoch, so
//! the output timeline stays the camera's. The pacer keeps its queue
//! across a re-anchor, and the epoch starts when the new timeline's first
//! packet is released, after the old timeline's last.
//!
//! Implements RFC 7587 (Opus RTP: 48 kHz clock §4.1, one frame per
//! packet §4.2) over RFC 6716 frames, from RFC 3640 AAC-LC frames
//! (ISO/IEC 14496-3 §4, 1024 samples per frame).

mod pace;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;
use lotse_core::codec::{Codec, CodecFamily};
use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields};
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use lotse_core::track::{FrameSubscription, SubscriptionError, Track};
use lotse_core::transcode::{TrackHandle, TranscodeError, Transcoder};
use tokio_util::sync::CancellationToken;

use crate::aac::{AacDecoder, DECODER_DELAY, DecodeError, FRAME_SAMPLES as AAC_FRAME};
use crate::opus::{Encoder, FRAME_SAMPLES as OPUS_FRAME, OpusError, SAMPLE_RATE};
use crate::resample::{RATES, ResampleError, Resampler};

use self::pace::Pacer;

/// The payload type on the derived track's packets. Sessions write their
/// negotiated one; this is the common dynamic Opus type for logs.
const PAYLOAD_TYPE: u8 = 111;

/// The SSRC on the derived track's packets; sessions write their own.
const SSRC: u32 = 0x4f50_5553;

/// [`OPUS_FRAME`] in 48 kHz ticks, 960: how far each packet's timestamp
/// moves (RFC 7587 §4.1: the timestamp counts samples at 48 kHz).
#[expect(
    clippy::cast_possible_wrap,
    reason = "960 fits; `i64::try_from` is not const"
)]
const PACKET_TICKS: i64 = OPUS_FRAME as i64;

/// [`AAC_FRAME`] in source ticks: the timestamp step between two AAC-LC
/// frames of one stream (RFC 3640 §3.2.1, one tick per sample).
const FRAME_TICKS: i64 = 1024;

/// How far the camera's timeline may move against the sample count before
/// the transcoder re-anchors: half a frame. A lost frame moves it a whole
/// frame; anything less is how the camera stamps, and the samples are
/// contiguous all the same, so the output follows the sample count.
const JITTER_TOLERANCE: i64 = FRAME_TICKS / 2;

/// How many frames the camera's timeline is judged over: their median
/// offset from the sample count, not any one frame's, says whether it
/// moved. Single frames say little: cameras that stamp audio from their
/// wall clock are a few samples off per frame, and one stamps on a 60 ms
/// grid, steps of 0, 960 or 1920 samples between 1024-sample frames
/// (2026-10-01; a reset per odd step lost 1.35 % of the audio). Sixteen
/// frames span such a grid's whole cycle, so the median holds still, and a
/// real loss moves it within nine: about 0.6 s at 16 kHz, 0.2 s at 48 kHz.
const TIMELINE_WINDOW: usize = 16;

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// The AAC-LC → Opus transcoder, registered by the binary. Stateless
/// itself: every [`Transcoder::spawn`] builds its own chain.
#[derive(Debug)]
pub struct AacToOpus {
    /// Reads each input frame's arrival at the transcoder and paces the
    /// packets; a packet's release becomes its `arrival`.
    clock: Arc<dyn Clock>,
}

impl AacToOpus {
    /// A transcoder reading time from `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }

    /// The delay the chain adds at an AAC rate of `sample_rate` Hz, as
    /// `tracks[].audio_delay_ms` reports it: the longest a packet leaves
    /// after the capture time its timestamp claims, for frames that arrive
    /// on time. It is one AAC frame of overlap ([`DECODER_DELAY`]), the
    /// resampler's filter delay, the Opus look-ahead and one Opus frame
    /// of waiting in the FIFO. The AAC frame's own length is the camera's:
    /// cut-through audio waits for it just the same. Pacing adds nothing:
    /// a clump's later packets leave later by as much as their media is
    /// later, so each waits as long as its first.
    pub fn delay(sample_rate: u32) -> Result<Duration, TranscodeError> {
        let resampler = Resampler::new(sample_rate, 1, chunk())
            .map_err(|err| TranscodeError::Failed(err.to_string()))?;
        let encoder = Encoder::new(1).map_err(|err| TranscodeError::Failed(err.to_string()))?;
        Ok(chain_delay(
            sample_rate,
            resampler.delay(),
            encoder.lookahead(),
        ))
    }
}

impl Transcoder for AacToOpus {
    /// Opus with the same channel count from mono or stereo AAC-LC at a
    /// rate the resampler takes ([`RATES`]).
    fn derive(&self, from: &Codec, to: CodecFamily) -> Option<Codec> {
        match (from, to) {
            (
                Codec::AacLc {
                    channels,
                    sample_rate,
                    ..
                },
                CodecFamily::Opus,
            ) if matches!(channels, 1 | 2) && RATES.contains(sample_rate) => Some(Codec::Opus {
                channels: *channels,
            }),
            _ => None,
        }
    }

    /// Builds the chain for `from`'s configuration and starts its task,
    /// which runs until the handle is dropped or the input track is gone.
    /// Must be called inside a Tokio runtime. The owner closes `output`.
    fn spawn(
        &self,
        input: FrameSubscription,
        from: &Codec,
        output: Arc<Track>,
    ) -> Result<TrackHandle, TranscodeError> {
        let (Codec::AacLc { config, .. }, Some(to)) = (from, self.derive(from, CodecFamily::Opus))
        else {
            return Err(TranscodeError::Unsupported {
                from: from.family(),
                to: output.codec().family(),
            });
        };
        if *output.codec() != to || output.clock_rate() != SAMPLE_RATE {
            return Err(TranscodeError::Failed(format!(
                "output track is {} at {} Hz, not {} at {SAMPLE_RATE} Hz",
                output.codec().name(),
                output.clock_rate(),
                to.name(),
            )));
        }
        let chain = Chain::new(config, Arc::clone(&output), Arc::clone(&self.clock))
            .map_err(|err| TranscodeError::Failed(err.to_string()))?;
        tracing::info!(
            track = %output.id(),
            sample_rate = chain.rate,
            channels = chain.channels,
            delay_ms = chain.delay().as_millis(),
            "transcoder started: aac_lc to opus"
        );
        let stop = CancellationToken::new();
        let delay = chain.delay();
        let _task = spawn_named("transcode.aac_opus", run(chain, input, stop.clone()));
        Ok(TrackHandle {
            track: output,
            delay,
            stop,
        })
    }
}

/// The resampler's chunk: one decoded AAC frame per call.
fn chunk() -> usize {
    usize::try_from(AAC_FRAME).unwrap_or(usize::MAX)
}

/// The delay [`AacToOpus::delay`] reports, from its parts: the decoder's
/// overlap at `sample_rate`, and the resampler delay, look-ahead and one
/// Opus frame at 48 kHz.
fn chain_delay(sample_rate: u32, resampler_delay: u32, lookahead: u32) -> Duration {
    let overlap = u64::from(DECODER_DELAY)
        .saturating_mul(NANOS_PER_SEC)
        .checked_div(u64::from(sample_rate))
        .unwrap_or(u64::MAX);
    let at_48k = u64::from(resampler_delay)
        .saturating_add(u64::from(lookahead))
        .saturating_add(u64::try_from(OPUS_FRAME).unwrap_or(u64::MAX))
        .saturating_mul(NANOS_PER_SEC)
        .checked_div(u64::from(SAMPLE_RATE))
        .unwrap_or(u64::MAX);
    Duration::from_nanos(overlap.saturating_add(at_48k))
}

/// `ticks` at `rate` Hz in 48 kHz ticks, rounded down.
fn to_48k(ticks: i64, rate: u32) -> i64 {
    let scaled = i128::from(ticks)
        .saturating_mul(i128::from(SAMPLE_RATE))
        .checked_div_euclid(i128::from(rate))
        .unwrap_or_default();
    i64::try_from(scaled.clamp(i128::from(i64::MIN), i128::from(i64::MAX))).unwrap_or_default()
}

/// A 48 kHz timestamp as the 32-bit RTP timestamp it wraps to
/// (RFC 3550 §5.1).
fn rtp_ts(ticks: i64) -> u32 {
    u32::try_from(ticks.rem_euclid(1_i64 << 32)).unwrap_or(0)
}

/// `at` moved by `ticks` of the 48 kHz clock, either way; `at` itself if
/// that leaves the range of [`Instant`].
fn shift(at: Instant, ticks: i64) -> Instant {
    let span = MediaTime::from_ticks(ticks.saturating_abs())
        .to_duration(SAMPLE_RATE)
        .unwrap_or_default();
    if ticks.is_negative() {
        at.checked_sub(span)
    } else {
        at.checked_add(span)
    }
    .unwrap_or(at)
}

/// Why a frame did not make it through the chain. Every one is handled
/// like a lost frame.
#[derive(Debug, thiserror::Error)]
enum ChainError {
    /// The AAC frame did not decode.
    #[error(transparent)]
    Decode(DecodeError),
    /// The resampler refused the PCM.
    #[error(transparent)]
    Resample(ResampleError),
    /// libopus refused a frame.
    #[error(transparent)]
    Encode(OpusError),
}

/// An Opus packet waiting in the pacer, with what publishing it needs.
#[derive(Debug)]
struct Pending {
    /// The 48 kHz timestamp, unwrapped.
    ts: i64,
    /// The Opus packet.
    payload: bytes::Bytes,
    /// The capture time of its first sample.
    wallclock: Instant,
    /// The output epoch to start before it, and why: set on the first
    /// packet of a timeline that needs one, so the old timeline's packets
    /// still queued leave in the old epoch.
    epoch: Option<&'static str>,
}

/// Where the current timeline stands.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    /// The input timestamp the timeline's sample count starts from.
    origin: i64,
    /// Input samples decoded since `origin`: `origin + samples` is where
    /// the next frame sits on the timeline, whatever its timestamp says.
    samples: i64,
    /// The 48 kHz timestamp of the next packet.
    next_packet: i64,
}

impl Anchor {
    /// The input timestamp of the next frame by sample count.
    const fn position(&self) -> i64 {
        self.origin.saturating_add(self.samples)
    }
}

/// The median of `values`, the upper one of an even count; `None` when
/// empty.
fn median(values: &VecDeque<i64>) -> Option<i64> {
    let mut sorted: Vec<i64> = values.iter().copied().collect();
    sorted.sort_unstable();
    sorted.get(sorted.len() / 2).copied()
}

/// One running chain: decoder, resampler, FIFO, encoder and the timeline.
#[derive(Debug)]
struct Chain {
    /// The AAC-LC decoder.
    decoder: AacDecoder,
    /// To 48 kHz, one decoded frame per call.
    resampler: Resampler,
    /// The Opus encoder, 20 ms per call. Not reset on a new timeline: its
    /// look-ahead holds the old timeline's last 2.5 ms, which the first new
    /// packet splices in before the new anchor, where it belongs.
    encoder: Encoder,
    /// The derived track.
    output: Arc<Track>,
    /// Reads each frame's arrival and each packet's release; sleeps until
    /// the next release.
    clock: Arc<dyn Clock>,
    /// The AAC sampling rate, which is the input's clock rate.
    rate: u32,
    /// 1 or 2.
    channels: u8,
    /// Resampled, interleaved PCM not yet encoded: less than one Opus
    /// frame between input frames.
    fifo: Vec<f32>,
    /// The timeline; `None` until the first frame after a reset.
    anchor: Option<Anchor>,
    /// The last [`TIMELINE_WINDOW`] frames' timestamps less their
    /// position by sample count, oldest first.
    offsets: VecDeque<i64>,
    /// The median offset when the window first filled: where the camera's
    /// stamps sit on this timeline. Kept across a re-anchor over a gap,
    /// which moves the timeline, not the camera's habit.
    baseline: Option<i64>,
    /// The input timestamp the next anchor starts from instead of its
    /// frame's: set by a re-anchor over a gap to the frame's position plus
    /// the gap, so one odd stamp does not misplace the new timeline.
    restart: Option<i64>,
    /// The input epoch of the last frame.
    epoch: Option<u32>,
    /// The input's epoch changed: the next anchor starts an output epoch.
    new_epoch: bool,
    /// An anchor that needs an output epoch has not completed a packet
    /// yet; the next packet carries the epoch start and this reason.
    pending_epoch: Option<&'static str>,
    /// Releases the packets at the media rate.
    pacer: Pacer<Pending>,
    /// The 48 kHz timestamp just after the last packet sent, which a new
    /// anchor in the same epoch must not go below.
    published_end: Option<i64>,
    /// The next packet's sequence number.
    seq: u16,
    /// Frames that failed in the chain.
    failures: Throttle,
    /// Lost input frames.
    gaps: Throttle,
    /// Lags on the side branch.
    lags: Throttle,
    /// The largest timestamp jitter reported so far, in input samples.
    jitter_reported: i64,
}

impl Chain {
    /// A chain for the `AudioSpecificConfig` `config`, feeding `output`.
    fn new(config: &[u8], output: Arc<Track>, clock: Arc<dyn Clock>) -> Result<Self, ChainError> {
        let decoder = AacDecoder::new(config).map_err(ChainError::Decode)?;
        let (rate, channels) = (decoder.sample_rate(), decoder.channels());
        let resampler = Resampler::new(rate, channels, chunk()).map_err(ChainError::Resample)?;
        let encoder = Encoder::new(channels).map_err(ChainError::Encode)?;
        let pacer = Pacer::new(output.id());
        Ok(Self {
            decoder,
            resampler,
            encoder,
            output,
            clock,
            rate,
            channels,
            fifo: Vec::new(),
            anchor: None,
            offsets: VecDeque::with_capacity(TIMELINE_WINDOW),
            baseline: None,
            restart: None,
            epoch: None,
            new_epoch: false,
            pending_epoch: None,
            pacer,
            published_end: None,
            seq: 0,
            failures: Throttle::default(),
            gaps: Throttle::default(),
            lags: Throttle::default(),
            jitter_reported: 0,
        })
    }

    /// What [`AacToOpus::delay`] reports for this chain.
    fn delay(&self) -> Duration {
        chain_delay(self.rate, self.resampler.delay(), self.encoder.lookahead())
    }

    /// Samples at 48 kHz a packet's timestamp is moved back by: the
    /// resampler's filter delay and the Opus look-ahead.
    fn compensation(&self) -> i64 {
        i64::from(self.resampler.delay()).saturating_add(i64::from(self.encoder.lookahead()))
    }

    /// Forgets the timeline: the decoder's overlap, the resampler's
    /// history, the FIFO and what the camera's stamps were judged by. The
    /// next frame anchors a new one. The pacer keeps its queue, the old
    /// timeline's tail, and its pace.
    fn reset(&mut self) {
        self.decoder.reset();
        self.resampler.reset();
        self.fifo.clear();
        self.anchor = None;
        self.offsets.clear();
        self.baseline = None;
        self.restart = None;
    }

    /// One input frame: a new epoch, a discontinuity or a gap resets
    /// first; a frame the chain refuses resets after.
    fn frame(&mut self, frame: &MediaFrame) {
        let now = self.clock.now();
        let ts = frame.ts.ticks();
        if self.epoch != Some(frame.epoch) || frame.discontinuity {
            if self.epoch.is_some() {
                tracing::debug!(
                    track = %self.output.id(),
                    input_epoch = frame.epoch,
                    ts,
                    "transcoder: new input timeline; re-anchoring"
                );
                self.new_epoch = true;
            }
            self.epoch = Some(frame.epoch);
            self.reset();
        } else if let Some(anchor) = self.anchor
            && let Some(shift) = self.moved(&anchor, ts)
        {
            if let Some(count) = self.gaps.hit(now) {
                tracing::debug!(
                    track = %self.output.id(),
                    shift_samples = shift,
                    ts,
                    count,
                    "transcoder: camera audio timeline moved; re-anchoring"
                );
            }
            let baseline = self.baseline;
            self.reset();
            self.baseline = baseline;
            self.restart = Some(anchor.position().saturating_add(shift));
        }
        if let Err(err) = self.process(frame, now) {
            if let Some(count) = self.failures.hit(now) {
                tracing::warn!(
                    track = %self.output.id(),
                    error = %err,
                    ts,
                    count,
                    "transcoder: frame dropped; re-anchoring at the next"
                );
            }
            self.reset();
        }
    }

    /// How far the camera's timeline moved against the sample count, when
    /// a frame at `ts` shows it moved more than [`JITTER_TOLERANCE`]: the
    /// median offset of the last [`TIMELINE_WINDOW`] frames, from the
    /// [`Chain::baseline`] the first full window set. Nothing is judged
    /// before the window fills. A first window whose median is more than a
    /// whole frame off is a move, not a habit: the anchor frame stands
    /// apart from the frames after it, as when a jump follows it. The
    /// offset from the baseline is logged whenever it exceeds what was
    /// reported before, so a camera's habit shows once, not per frame.
    fn moved(&mut self, anchor: &Anchor, ts: i64) -> Option<i64> {
        let offset = ts.saturating_sub(anchor.position());
        if self.offsets.len() >= TIMELINE_WINDOW {
            self.offsets.pop_front();
        }
        self.offsets.push_back(offset);
        if self.offsets.len() < TIMELINE_WINDOW {
            return None;
        }
        let median = median(&self.offsets)?;
        let baseline = match self.baseline {
            Some(baseline) => baseline,
            None if median.saturating_abs() > FRAME_TICKS => return Some(median),
            None => *self.baseline.insert(median),
        };
        let shift = median.saturating_sub(baseline);
        if shift.saturating_abs() > JITTER_TOLERANCE {
            return Some(shift);
        }
        let jitter = offset.saturating_sub(baseline).saturating_abs();
        if jitter > self.jitter_reported {
            self.jitter_reported = jitter;
            tracing::info!(
                track = %self.output.id(),
                jitter_samples = jitter,
                "transcoder: camera audio timestamps jitter; following the sample count"
            );
        }
        None
    }

    /// The side branch skipped `skipped` frames: handled like a gap.
    fn lagged(&mut self, skipped: u64) {
        if let Some(count) = self.lags.hit(self.clock.now()) {
            tracing::warn!(
                track = %self.output.id(),
                skipped,
                count,
                "transcoder lagged behind the source; re-anchoring"
            );
        }
        self.reset();
    }

    /// Anchors a timeline on a frame at `ts`, marking its first packet to
    /// start an output epoch when the input's changed or the new
    /// timestamps would overlap the packets already sent.
    fn anchor_at(&mut self, ts: i64) -> Anchor {
        let next_packet = to_48k(ts.saturating_sub(i64::from(DECODER_DELAY)), self.rate)
            .saturating_sub(self.compensation());
        let overlaps = self.published_end.is_some_and(|end| next_packet < end);
        if self.new_epoch || overlaps {
            self.pending_epoch = Some(if self.new_epoch {
                "input_epoch"
            } else {
                "overlap"
            });
            self.new_epoch = false;
        }
        Anchor {
            origin: ts,
            samples: 0,
            next_packet,
        }
    }

    /// Decodes, resamples and encodes one frame, queueing every Opus
    /// frame it completes in the pacer, ready at `now`.
    fn process(&mut self, frame: &MediaFrame, now: Instant) -> Result<(), ChainError> {
        let ts = frame.ts.ticks();
        let mut anchor = if let Some(anchor) = self.anchor {
            anchor
        } else {
            let start = self.restart.take().unwrap_or(ts);
            self.anchor_at(start)
        };
        let pcm = self
            .decoder
            .decode(&frame.payload)
            .map_err(ChainError::Decode)?;
        let resampled = self.resampler.process(pcm).map_err(ChainError::Resample)?;
        self.fifo.extend_from_slice(resampled);
        let frame_ts = to_48k(ts, self.rate);
        let frame_len = OPUS_FRAME.saturating_mul(usize::from(self.channels));
        let mut start = 0_usize;
        while let Some(pcm) = self.fifo.get(start..start.saturating_add(frame_len)) {
            let payload = self.encoder.encode(pcm).map_err(ChainError::Encode)?;
            let pending = Pending {
                ts: anchor.next_packet,
                payload,
                wallclock: shift(frame.wallclock, anchor.next_packet.saturating_sub(frame_ts)),
                epoch: self.pending_epoch.take(),
            };
            self.pacer.push(now, pending);
            anchor.next_packet = anchor.next_packet.saturating_add(PACKET_TICKS);
            self.published_end = Some(anchor.next_packet);
            start = start.saturating_add(frame_len);
        }
        self.fifo.drain(..start);
        anchor.samples = anchor.samples.saturating_add(FRAME_TICKS);
        self.anchor = Some(anchor);
        Ok(())
    }

    /// Publishes every packet the pacer holds, now: the input closed.
    fn flush(&mut self) {
        let now = self.clock.now();
        for pending in self.pacer.drain() {
            self.publish(pending, now);
        }
    }

    /// Publishes one Opus packet released at `now`, on the side branch and
    /// then live: a session that reads the packet finds the frame's
    /// capture time already there (`Track::capture_time`). Starts the
    /// output epoch first when the packet carries one.
    ///
    /// `arrival` is the release, so the sessions' age gate measures from
    /// when the packet left the pacer, not from when it was encoded.
    /// Every packet is a `frame_start`: paced, they leave one Opus frame
    /// apart as their timestamps say, so the output track's lateness meter
    /// measures each one. (Before pacing, a clump sharing one arrival was
    /// measured once per AAC frame, or it would have read up to an AAC
    /// frame late.)
    fn publish(&mut self, pending: Pending, now: Instant) {
        let Pending {
            ts,
            payload,
            wallclock,
            epoch,
        } = pending;
        if let Some(reason) = epoch {
            let epoch = self.output.start_epoch();
            tracing::debug!(
                track = %self.output.id(),
                epoch,
                reason,
                "transcoder: output epoch started"
            );
        }
        tracing::trace!(track = %self.output.id(), ts, len = payload.len(), "transcoder: packet");
        let packet_payload: Arc<[u8]> = Arc::from(payload.as_ref());
        self.output.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(ts),
            wallclock,
            arrival: now,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload,
        });
        self.output.publish_packet(MediaPacket {
            arrival: now,
            rtp: RtpHeaderFields {
                pt: PAYLOAD_TYPE,
                seq: self.seq,
                ts: rtp_ts(ts),
                marker: false,
                ssrc: SSRC,
            },
            frame_start: true,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: packet_payload,
        });
        self.seq = self.seq.wrapping_add(1);
    }
}

/// The transcoder task: frames in and paced packets out until `stop` is
/// cancelled, which drops what the pacer holds, or the input track is
/// gone, which publishes it at once. `Track::close` alone does not end a
/// frame subscription, so the owner cancels.
///
/// Each turn publishes what the pacer has due, then waits for a frame, the
/// stop token or the next release. Both steps are written out here: a
/// mutant that skips the release or always wakes at once makes the task
/// spin without yielding, which a test can only see as a hang.
async fn run(mut chain: Chain, mut input: FrameSubscription, stop: CancellationToken) {
    let reason = loop {
        let now = chain.clock.now();
        while let Some(pending) = chain.pacer.pop(now) {
            chain.publish(pending, now);
        }
        let next = chain
            .pacer
            .next_due()
            .map(|due| chain.clock.sleep(due.saturating_duration_since(now)));
        let release = async {
            match next {
                Some(sleep) => sleep.await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            () = stop.cancelled() => break "cancelled",
            received = input.recv() => match received {
                Ok(frame) => chain.frame(&frame),
                Err(SubscriptionError::Lagged(skipped)) => chain.lagged(skipped),
                Err(SubscriptionError::Closed) => {
                    chain.flush();
                    break "input_closed";
                }
            },
            () = release => {}
        }
    };
    tracing::info!(track = %chain.output.id(), reason, "transcoder stopped");
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "test code; signal math in floats"
    )]

    use std::sync::Mutex;

    use ::opus as libopus;
    use bytes::Bytes;
    use lotse_core::clock::FakeClock;
    use lotse_core::codec::Kind;
    use lotse_core::track::{PacketSubscription, TrackId, TrackLimits};
    use tracing::field::{Field, Visit};
    use tracing::subscriber::DefaultGuard;
    use tracing::{Event, Level, Metadata, Subscriber, span};

    use super::*;
    use crate::aac::test_data::{
        CONFIG_16K_MONO, CONFIG_48K_MONO, SINE_16K_MONO, SINE_48K_MONO, frames,
    };

    /// The events logged on this thread while captured: level and message.
    /// Also makes every field expression of the module's log lines run.
    #[derive(Debug, Clone, Default)]
    pub(super) struct Logs(Arc<Mutex<Vec<(Level, Message)>>>);

    impl Logs {
        pub(super) fn capture() -> (Self, DefaultGuard) {
            let logs = Self::default();
            let guard = tracing::subscriber::set_default(logs.clone());
            (logs, guard)
        }

        /// How many events at `level` carried `message`.
        pub(super) fn count(&self, level: Level, message: &str) -> usize {
            self.fields(level, message).len()
        }

        /// The other fields of each event at `level` with `message`.
        pub(super) fn fields(&self, level: Level, message: &str) -> Vec<Vec<String>> {
            let events = self.0.lock().unwrap();
            events
                .iter()
                .filter(|(l, m)| *l == level && m.message == message)
                .map(|(_, m)| m.fields.clone())
                .collect()
        }
    }

    /// An event's message and its other fields as `name=value`.
    #[derive(Debug, Default)]
    struct Message {
        message: String,
        fields: Vec<String>,
    }

    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            // Formatting every field runs the `%` values' `Display`.
            let text = format!("{value:?}");
            if field.name() == "message" {
                self.message = text;
            } else {
                self.fields.push(format!("{}={text}", field.name()));
            }
        }
    }

    impl Subscriber for Logs {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut message = Message::default();
            event.record(&mut message);
            self.0
                .lock()
                .unwrap()
                .push((*event.metadata().level(), message));
        }

        fn enter(&self, _: &span::Id) {}

        fn exit(&self, _: &span::Id) {}
    }

    /// A recorded fixture: its config, its ADTS stream and its rate.
    struct Fixture {
        config: &'static [u8],
        adts: &'static [u8],
        rate: u32,
    }

    const F16: Fixture = Fixture {
        config: &CONFIG_16K_MONO,
        adts: SINE_16K_MONO,
        rate: 16_000,
    };

    const F48: Fixture = Fixture {
        config: &CONFIG_48K_MONO,
        adts: SINE_48K_MONO,
        rate: 48_000,
    };

    /// 48 kHz stereo AAC-LC.
    const CONFIG_48K_STEREO: [u8; 2] = [0x11, 0x90];

    /// A raw AAC frame of one `ID_END`: a frame of silence.
    const SILENT_FRAME: [u8; 1] = [0xe0];

    /// A frame the decoder refuses (a coupling channel element).
    const BROKEN_FRAME: [u8; 3] = [0x40, 0x00, 0x00];

    /// The Opus look-ahead in `RESTRICTED_LOWDELAY` (2.5 ms).
    const LOOKAHEAD: i64 = 120;

    /// The resampler delay at `rate`, in 48 kHz samples.
    fn resampler_delay(rate: u32) -> i64 {
        i64::from(Resampler::new(rate, 1, 1024).unwrap().delay())
    }

    /// The 48 kHz timestamp of the first packet anchored on a frame at
    /// `ts`: the rule this module implements, written out.
    fn anchored(ts: i64, rate: u32) -> i64 {
        (ts - 1024) * 48_000 / i64::from(rate) - resampler_delay(rate) - LOOKAHEAD
    }

    fn aac(config: &[u8], rate: u32, channels: u8) -> Codec {
        Codec::AacLc {
            sample_rate: rate,
            channels,
            config: Bytes::copy_from_slice(config),
        }
    }

    fn opus_track(channels: u8, rate: u32) -> Arc<Track> {
        Arc::new(Track::new(
            TrackId::new(Kind::Audio, 1),
            Codec::Opus { channels },
            rate,
            TrackLimits::default(),
            FakeClock::from_system().now(),
        ))
    }

    /// A running transcoder between two real tracks, on a fake clock.
    struct Rig {
        clock: Arc<FakeClock>,
        /// The instant input timestamp 0 is captured at.
        origin: Instant,
        input: Option<Arc<Track>>,
        output: Arc<Track>,
        packets: PacketSubscription,
        frames: FrameSubscription,
        handle: Option<TrackHandle>,
        rate: u32,
    }

    impl Rig {
        fn start(config: &[u8], rate: u32, channels: u8, limits: TrackLimits) -> Self {
            let clock = Arc::new(FakeClock::from_system());
            let codec = aac(config, rate, channels);
            let input = Arc::new(Track::new(
                TrackId::new(Kind::Audio, 0),
                codec.clone(),
                rate,
                limits,
                clock.now(),
            ));
            let output = opus_track(channels, 48_000);
            let packets = output.subscribe_packets();
            let frames = output.subscribe_frames();
            let handle = AacToOpus::new(clock.clone())
                .spawn(input.subscribe_frames(), &codec, Arc::clone(&output))
                .unwrap();
            Self {
                origin: clock.now(),
                clock,
                input: Some(input),
                output,
                packets,
                frames,
                handle: Some(handle),
                rate,
            }
        }

        fn of(fixture: &Fixture) -> Self {
            Self::start(fixture.config, fixture.rate, 1, TrackLimits::default())
        }

        fn input(&self) -> &Arc<Track> {
            self.input.as_ref().unwrap()
        }

        /// The capture time of the 48 kHz timestamp `ts48`.
        fn at48(&self, ts48: i64) -> Instant {
            let nanos = i128::from(ts48) * 62_500 / 3;
            let span = Duration::from_nanos(u64::try_from(nanos.abs()).unwrap());
            if nanos < 0 {
                self.origin.checked_sub(span).unwrap()
            } else {
                self.origin + span
            }
        }

        /// The capture time of input timestamp `ts`: sent and read the
        /// moment it comes due, as a camera without Sender Reports maps.
        fn wallclock(&self, ts: i64) -> Instant {
            self.at48(to_48k(ts, self.rate))
        }

        /// Publishes one frame at `ts` without letting the task run.
        fn publish(&self, ts: i64, payload: &[u8]) {
            self.publish_flagged(ts, payload, false);
        }

        fn publish_flagged(&self, ts: i64, payload: &[u8], discontinuity: bool) {
            self.input().publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(ts),
                wallclock: self.wallclock(ts),
                arrival: self.wallclock(ts),
                keyframe: true,
                discontinuity,
                epoch: 0,
                payload: Bytes::copy_from_slice(payload),
            });
        }

        /// Publishes `frames` one AAC frame apart from `ts0`.
        fn publish_all(&self, ts0: i64, frames: &[&[u8]]) {
            for (i, frame) in frames.iter().enumerate() {
                self.publish(ts0 + 1024 * i as i64, frame);
            }
        }

        /// Runs the clock to `until` in steps of [`STEP`], letting the task
        /// release what comes due at each, and returns what it released.
        async fn run_until(&mut self, until: Instant) -> Vec<Released> {
            let mut out = Vec::new();
            loop {
                settle().await;
                for packet in self.drain() {
                    let frame = self.frames.try_recv().unwrap().expect("its frame first");
                    let mapped = self.output.capture_time(packet.epoch, packet.rtp.ts);
                    out.push((packet, frame, mapped));
                }
                let left = until.saturating_duration_since(self.clock.now());
                if left.is_zero() {
                    return out;
                }
                self.clock.advance(left.min(STEP));
            }
        }

        /// Runs the clock to the capture time of `ts`, then publishes the
        /// frame and lets the task handle it: a frame arriving in real
        /// time. Returns what was released on the way.
        async fn live(&mut self, ts: i64, payload: &[u8]) -> Vec<Released> {
            let mut out = self.run_until(self.wallclock(ts)).await;
            self.publish(ts, payload);
            out.extend(self.run_until(self.clock.now()).await);
            out
        }

        /// Everything published on the output so far.
        fn drain(&mut self) -> Vec<Arc<MediaPacket>> {
            let mut out = Vec::new();
            while let Some(packet) = self.packets.try_recv().unwrap() {
                out.push(packet);
            }
            out
        }

        /// Closes the input, waits for the task to stop, and returns what
        /// it published.
        async fn finish(&mut self) -> Vec<Arc<MediaPacket>> {
            self.input = None;
            stopped(&self.output, 2).await;
            self.drain()
        }
    }

    /// A released packet, the side-branch frame published with it (read
    /// in the same step), and the capture time the output track mapped
    /// its timestamp to then.
    type Released = (Arc<MediaPacket>, Arc<MediaFrame>, Option<Instant>);

    /// How far [`Rig::run_until`] moves the clock at a time.
    const STEP: Duration = Duration::from_micros(250);

    /// Lets the transcoder task catch up on the current-thread runtime.
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// Waits until only `holders` references to `output` remain: the task
    /// has dropped its own.
    async fn stopped(output: &Arc<Track>, holders: usize) {
        let mut tries = 0;
        while Arc::strong_count(output) != holders {
            assert!(tries < 10_000, "transcoder did not stop");
            tries += 1;
            tokio::task::yield_now().await;
        }
    }

    /// Feeds a whole fixture from `ts0` and returns the packets.
    async fn transcode(fixture: &Fixture, ts0: i64) -> Vec<Arc<MediaPacket>> {
        let mut rig = Rig::of(fixture);
        rig.publish_all(ts0, &frames(fixture.adts));
        rig.finish().await
    }

    /// Decodes contiguous packets with libopus into one mono stream.
    fn decode(packets: &[Arc<MediaPacket>]) -> Vec<f32> {
        let mut decoder = libopus::Decoder::new(48_000, libopus::Channels::Mono).unwrap();
        let mut pcm = vec![0.0_f32; packets.len() * OPUS_FRAME];
        for (packet, out) in packets.iter().zip(pcm.chunks_mut(OPUS_FRAME)) {
            assert_eq!(
                decoder.decode_float(&packet.payload, out, false).unwrap(),
                OPUS_FRAME
            );
        }
        pcm
    }

    /// The first sample index whose magnitude exceeds `level`.
    fn onset(pcm: &[f32], level: f32) -> usize {
        pcm.iter().position(|s| s.abs() > level).unwrap()
    }

    /// Estimates the frequency of `pcm` at `rate` from its zero crossings.
    fn frequency(pcm: &[f32], rate: u32) -> f64 {
        let crossings = pcm.windows(2).filter(|w| w[0] <= 0.0 && w[1] > 0.0).count();
        crossings as f64 * f64::from(rate) / pcm.len() as f64
    }

    /// The unwrapped distance of a packet's timestamp from `base`'s.
    fn ts_delta(packet: &MediaPacket, base: u32) -> i64 {
        i64::from(packet.rtp.ts.wrapping_sub(base) as i32)
    }

    #[tokio::test]
    async fn rfc7587_4_1_a_1_khz_aac_tone_comes_out_as_a_1_khz_tone_at_48_khz() {
        for fixture in [&F16, &F48] {
            let pcm = decode(&transcode(fixture, 0).await);
            let start = onset(&pcm, 0.1) + 4_800;
            let steady = &pcm[start..start + 24_000];
            let f = frequency(steady, 48_000);
            assert!((f - 1000.0).abs() < 10.0, "{} Hz: {f:.1} Hz", fixture.rate);
            let peak = steady.iter().fold(0.0_f32, |m, s| m.max(s.abs()));
            assert!(
                (0.4..0.6).contains(&peak),
                "{} Hz: peak {peak}",
                fixture.rate
            );
        }
    }

    #[tokio::test]
    async fn rfc7587_4_1_4_2_one_20_ms_frame_per_packet_960_ticks_apart() {
        assert_eq!(PACKET_TICKS, 960);
        for fixture in [&F16, &F48] {
            let input = frames(fixture.adts);
            let packets = transcode(fixture, 3_000).await;
            // Every sample the decoder produced, less the FIFO's remainder.
            let samples = input.len() * 1024 * 48_000 / fixture.rate as usize;
            assert!(
                packets.len().abs_diff(samples / 960) <= 1,
                "{}: {} packets",
                fixture.rate,
                packets.len()
            );
            for (i, pair) in packets.windows(2).enumerate() {
                assert_eq!(pair[1].rtp.ts.wrapping_sub(pair[0].rtp.ts), 960, "{i}");
                assert_eq!(pair[1].rtp.seq, pair[0].rtp.seq.wrapping_add(1));
            }
            for packet in &packets {
                assert_eq!((packet.rtp.pt, packet.rtp.ssrc), (PAYLOAD_TYPE, SSRC));
                assert!(!packet.rtp.marker && !packet.keyframe_start);
                assert_eq!(packet.epoch, 0);
                // RFC 6716 §3.1 Table 2: config 31, CELT-only fullband 20 ms.
                assert_eq!(packet.payload[0] >> 3, 31);
            }
            assert_eq!(packets[0].rtp.seq, 0);
            // Paced one Opus frame apart, every packet is measured.
            assert!(packets.iter().all(|p| p.frame_start), "{}", fixture.rate);
        }
    }

    #[tokio::test]
    async fn the_first_packet_is_anchored_one_decoder_frame_early_less_the_chain_delay() {
        for (fixture, ts0) in [(&F16, 3_000), (&F48, 3_000), (&F16, 0), (&F48, 70_000)] {
            let packets = transcode(fixture, ts0).await;
            assert_eq!(
                packets[0].rtp.ts,
                rtp_ts(anchored(ts0, fixture.rate)),
                "{} Hz from {ts0}",
                fixture.rate
            );
        }
        // Spelled out once: at 16 kHz, (3000 − 1024) × 3 − 96 − 120.
        assert_eq!(anchored(3_000, 16_000), 5_712);
        assert_eq!(resampler_delay(16_000), 96);
        assert_eq!(resampler_delay(48_000), 0);
    }

    #[tokio::test]
    async fn the_decoded_tone_starts_at_the_capture_time_of_the_aac_tone() {
        // afconvert primes with 2112 samples, of which the decoder's overlap
        // is 1024: the tone starts about 1088 samples after the first
        // frame's timestamp on the source's timeline. Measured here, not
        // assumed; the output lands within 2 samples of it (2026-10-01:
        // 0 at 48 kHz, −2 at 16 kHz), so a quarter millisecond is the bound.
        for fixture in [&F16, &F48] {
            let ts0 = 12_345;
            let mut decoder = AacDecoder::new(fixture.config).unwrap();
            let mut source = Vec::new();
            for frame in frames(fixture.adts) {
                source.extend_from_slice(decoder.decode(frame).unwrap());
            }
            let source_onset = ts0 - 1024 + onset(&source, 0.1) as i64;
            let packets = transcode(fixture, ts0).await;
            let opus_onset = onset(&decode(&packets), 0.1) as i64;
            let first = anchored(ts0, fixture.rate);
            assert_eq!(packets[0].rtp.ts, rtp_ts(first));
            let expected = to_48k(source_onset, fixture.rate);
            let error = first + opus_onset - expected;
            assert!(
                error.abs() <= 12,
                "{} Hz: tone at {} on the source timeline, {} in the output: {error} samples",
                fixture.rate,
                expected,
                first + opus_onset
            );
        }
    }

    #[tokio::test]
    async fn rfc3550_5_1_timestamps_wrap_at_32_bits() {
        let ts0 = (1_i64 << 32) - 5_000;
        let packets = transcode(&F48, ts0).await;
        assert_eq!(packets[0].rtp.ts, rtp_ts(ts0 - 1024 - LOOKAHEAD));
        assert!(
            packets
                .windows(2)
                .any(|pair| pair[1].rtp.ts < pair[0].rtp.ts)
        );
        assert!(
            packets
                .windows(2)
                .all(|pair| pair[1].rtp.ts.wrapping_sub(pair[0].rtp.ts) == 960)
        );
    }

    #[tokio::test]
    async fn a_new_input_epoch_re_anchors_in_a_new_output_epoch() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        let input = frames(SINE_16K_MONO);
        rig.publish_all(100_000, &input[..4]);
        // Four packets leave; the rest of the old timeline is still queued
        // when the new one starts.
        let released = rig
            .run_until(rig.clock.now() + Duration::from_millis(60))
            .await;
        assert_eq!(released.len(), 4);
        rig.input().start_epoch();
        rig.publish_all(2_048, &input[8..12]);
        let rest = rig.finish().await;
        let mut side: Vec<Arc<MediaFrame>> =
            released.iter().map(|(_, f, _)| Arc::clone(f)).collect();
        while let Some(frame) = rig.frames.try_recv().unwrap() {
            side.push(frame);
        }
        let packets: Vec<_> = released
            .into_iter()
            .map(|(p, _, _)| p)
            .chain(rest)
            .collect();
        // The old timeline's packets all leave in the old epoch, first.
        let old = packets.iter().take_while(|p| p.epoch == 0).count();
        assert_eq!(old, 4 * 1024 * 3 / 960);
        assert!(packets[old..].iter().all(|p| p.epoch == 1));
        assert_eq!(packets[old].rtp.ts, rtp_ts(anchored(2_048, 16_000)));
        assert_eq!(rig.output.epoch(), 1);
        // The side branch marks the new epoch's first frame, and only it.
        assert_eq!(side.len(), packets.len());
        let flagged: Vec<usize> = (0..side.len()).filter(|i| side[*i].discontinuity).collect();
        assert_eq!(flagged, vec![old]);
        assert_eq!(side[old].epoch, 1);
        let started = "transcoder: output epoch started";
        assert_eq!(logs.count(Level::DEBUG, started), 1);
        let timeline = "transcoder: new input timeline; re-anchoring";
        assert_eq!(logs.count(Level::DEBUG, timeline), 1);
        assert_eq!(
            logs.fields(Level::INFO, "transcoder started: aac_lc to opus"),
            vec![vec![
                "track=a1".to_owned(),
                "sample_rate=16000".to_owned(),
                "channels=1".to_owned(),
                "delay_ms=88".to_owned(),
            ]]
        );
        assert_eq!(logs.count(Level::INFO, "transcoder stopped"), 1);
        assert_eq!(
            logs.count(Level::TRACE, "transcoder: packet"),
            packets.len()
        );
    }

    #[tokio::test]
    async fn a_discontinuity_in_the_same_epoch_re_anchors_in_a_new_output_epoch() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F48);
        let input = frames(SINE_48K_MONO);
        rig.publish_all(0, &input[..4]);
        // Timestamps continue; only the flag says the timeline restarted.
        rig.publish_flagged(4 * 1024, input[4], true);
        let packets = rig.finish().await;
        let first = packets.iter().position(|p| p.epoch == 1).unwrap();
        assert_eq!(packets[first].rtp.ts, rtp_ts(anchored(4 * 1024, 48_000)));
        assert!(packets[first].frame_start);
        let timeline = "transcoder: new input timeline; re-anchoring";
        assert_eq!(logs.count(Level::DEBUG, timeline), 1);
    }

    /// The log line of a re-anchor over a moved timeline.
    const MOVED: &str = "transcoder: camera audio timeline moved; re-anchoring";

    /// Publishes a silent frame at each of `stamps`, letting the task take
    /// each before the next: a long stream without a lag.
    async fn publish_silent(rig: &Rig, stamps: impl IntoIterator<Item = i64>) {
        for ts in stamps {
            rig.publish(ts, &SILENT_FRAME);
            settle().await;
        }
    }

    /// The indexes of the packets that do not follow their predecessor by
    /// one Opus frame: where the output timeline jumped.
    fn jumps(packets: &[Arc<MediaPacket>]) -> Vec<usize> {
        packets
            .windows(2)
            .enumerate()
            .filter(|(_, pair)| pair[1].rtp.ts.wrapping_sub(pair[0].rtp.ts) != 960)
            .map(|(i, _)| i + 1)
            .collect()
    }

    #[tokio::test]
    async fn a_lost_frame_re_anchors_on_the_same_timeline_once_the_window_agrees() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        // Frame 24 is lost. The (upper) median of the last 16 offsets moves
        // on the eighth frame after it, frame 32, which re-anchors where the loss
        // puts it: its own timestamp here.
        publish_silent(&rig, (0..60).filter(|i| *i != 24).map(|i| i * 1024)).await;
        let packets = rig.finish().await;
        assert!(packets.iter().all(|p| p.epoch == 0));
        let jumps = jumps(&packets);
        assert_eq!(jumps.len(), 1);
        let resumed = &packets[jumps[0]];
        assert_eq!(resumed.rtp.ts, rtp_ts(anchored(32 * 1024, 16_000)));
        assert!(ts_delta(resumed, packets[jumps[0] - 1].rtp.ts) > 960);
        assert_eq!(logs.count(Level::DEBUG, MOVED), 1);
        assert!(logs.fields(Level::DEBUG, MOVED)[0].contains(&"shift_samples=1024".to_owned()));
        assert_eq!(
            logs.count(Level::DEBUG, "transcoder: output epoch started"),
            0
        );
    }

    #[tokio::test]
    async fn jittering_camera_timestamps_continue_the_stream_by_sample_count() {
        let input = frames(SINE_16K_MONO);
        let mut exact = Rig::of(&F16);
        exact.publish_all(0, &input);
        let expected = exact.finish().await;

        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        // A wall-clock-stamping camera: a few samples either way per frame.
        for (i, frame) in input.iter().enumerate() {
            let jitter = [0, 3, -2, 5, -4, 1][i % 6];
            rig.publish(1024 * i as i64 + jitter, frame);
        }
        let packets = rig.finish().await;
        // The same samples, so the same packets: nothing reset.
        let strip = |p: &[Arc<MediaPacket>]| -> Vec<(u32, Vec<u8>)> {
            p.iter().map(|p| (p.rtp.ts, p.payload.to_vec())).collect()
        };
        assert_eq!(strip(&packets), strip(&expected));
        assert_eq!(logs.count(Level::DEBUG, MOVED), 0);
        let jitter = "transcoder: camera audio timestamps jitter; following the sample count";
        // Reported against the window's median as it grows, not per frame:
        // the window fills at frame 16 with a median 1 sample late, and
        // frame 16 is 4 early, the largest offset from it.
        assert_eq!(
            logs.fields(Level::INFO, jitter),
            vec![vec!["track=a1".to_owned(), "jitter_samples=5".to_owned()]]
        );
    }

    /// The timestamps of `count` frames from a camera that stamps audio on
    /// a coarse grid: each frame's capture time, delayed by up to ±32 ms,
    /// rounded down to 960 samples (60 ms at 16 kHz). Steps between frames
    /// are then 0, 960 or 1920 samples, rarely 2880, though every frame
    /// holds 1024; over time they still advance at the sampling rate.
    /// Seen on a real camera on 2026-10-01 (16 kHz AAC over RTSP/TCP, so
    /// nothing was lost): steps 64 samples short, jumps of +896 and steps
    /// of 0, which the per-frame rule took for 2.6 lost frames a second.
    fn grid_stamped(count: usize) -> Vec<i64> {
        let mut seed: u32 = 0x2545_f491;
        (0..count)
            .map(|i| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let delay = if i == 0 {
                    0
                } else {
                    i64::from(seed >> 22) - 512
                };
                (1024 * i as i64 + delay).div_euclid(960) * 960
            })
            .collect()
    }

    #[tokio::test]
    async fn a_camera_stamping_on_a_coarse_grid_continues_by_sample_count() {
        // Ten seconds at 16 kHz.
        let count = 160;
        let stamps = grid_stamped(count);
        let steps: Vec<i64> = stamps.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(steps.contains(&0) && steps.contains(&960) && steps.contains(&1920));
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        for ts in stamps {
            rig.publish(ts, &SILENT_FRAME);
            settle().await;
        }
        let packets = rig.finish().await;
        // Every decoded sample comes out, contiguous, in one epoch.
        let sent = packets.len();
        assert!(sent.abs_diff(count * 1024 * 3 / 960) <= 1, "{sent} packets");
        assert!(packets.iter().all(|p| p.epoch == 0));
        assert!(
            packets
                .windows(2)
                .all(|pair| pair[1].rtp.ts.wrapping_sub(pair[0].rtp.ts) == 960)
        );
        assert_eq!(logs.count(Level::DEBUG, MOVED), 0);
    }

    #[tokio::test]
    async fn odd_single_stamps_continue_and_a_move_over_half_a_frame_re_anchors() {
        // One frame far off now and then, even two in a row: the median
        // does not move, so nothing resets.
        let (logs, guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        let odd = [(20, 513), (26, -513), (32, 896), (38, -1024), (39, -1024)];
        let stamps = (0..60).map(|i| {
            let by = odd.iter().find(|(at, _)| *at == i).map_or(0, |(_, by)| *by);
            i * 1024 + by
        });
        publish_silent(&rig, stamps).await;
        assert!(jumps(&rig.finish().await).is_empty());
        assert_eq!(logs.count(Level::DEBUG, MOVED), 0);
        drop(guard);

        // A timeline that stays moved from frame 24 on: half a frame either
        // way is still the camera's habit, more re-anchors.
        for (by, resets) in [(512, 0), (-512, 0), (513, 1), (-513, 1)] {
            let (logs, _guard) = Logs::capture();
            let mut rig = Rig::of(&F16);
            publish_silent(
                &rig,
                (0..48).map(|i| i * 1024 + if i >= 24 { by } else { 0 }),
            )
            .await;
            let _ = rig.finish().await;
            assert_eq!(logs.count(Level::DEBUG, MOVED), resets, "moved by {by}");
        }
    }

    #[tokio::test]
    async fn a_timeline_moved_back_re_anchors_in_a_new_epoch_where_the_window_puts_it() {
        let started = "transcoder: output epoch started";
        // Within half a frame back, the stream continues, contiguous.
        let (logs, guard) = Logs::capture();
        let mut rig = Rig::of(&F48);
        publish_silent(
            &rig,
            (0..48).map(|i| i * 1024 - if i >= 24 { 500 } else { 0 }),
        )
        .await;
        let packets = rig.finish().await;
        assert!(packets.iter().all(|p| p.epoch == 0));
        assert!(jumps(&packets).is_empty());
        assert_eq!(logs.count(Level::DEBUG, started), 0);
        drop(guard);

        // Two frames back from frame 24 on: the upper median sees a move
        // back on its ninth frame, 32, which re-anchors at its position
        // less the move, 30 frames in. That overlaps what was sent, so it
        // starts an epoch.
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F48);
        publish_silent(
            &rig,
            (0..48).map(|i| i * 1024 - if i >= 24 { 2048 } else { 0 }),
        )
        .await;
        let packets = rig.finish().await;
        let first = packets.iter().position(|p| p.epoch == 1).unwrap();
        assert!(packets[..first].iter().all(|p| p.epoch == 0));
        assert!(packets[first..].iter().all(|p| p.epoch == 1));
        assert_eq!(packets[first].rtp.ts, rtp_ts(anchored(30 * 1024, 48_000)));
        assert_eq!(
            logs.fields(Level::DEBUG, started),
            vec![vec![
                "track=a1".to_owned(),
                "epoch=1".to_owned(),
                "reason=\"overlap\"".to_owned(),
            ]]
        );
    }

    #[tokio::test]
    async fn a_move_before_the_first_window_fills_re_anchors_where_the_window_puts_it() {
        // Twelve frames are skipped after frame 3: the first full window's
        // median is twelve frames off, which is a move, not a habit. Frame
        // 16 fills the window (frames 1 to 3 and 16 to 28) and re-anchors
        // on its own timestamp.
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        publish_silent(&rig, (0..4).chain(16..40).map(|i| i * 1024)).await;
        let packets = rig.finish().await;
        let jumped = jumps(&packets);
        assert_eq!(jumped.len(), 1);
        assert_eq!(
            packets[jumped[0]].rtp.ts,
            rtp_ts(anchored(28 * 1024, 16_000))
        );
        assert!(logs.fields(Level::DEBUG, MOVED)[0].contains(&"shift_samples=12288".to_owned()));
        // Within a whole frame, the first window sets the baseline instead.
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        publish_silent(
            &rig,
            (0..40).map(|i| i * 1024 + if i > 0 { 1024 } else { 0 }),
        )
        .await;
        assert!(jumps(&rig.finish().await).is_empty());
        assert_eq!(logs.count(Level::DEBUG, MOVED), 0);
    }

    #[tokio::test]
    async fn a_frame_that_fails_to_decode_is_handled_as_a_lost_frame() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        let input = frames(SINE_16K_MONO);
        rig.publish_all(0, &input[..8]);
        let before: Vec<_> = rig
            .run_until(rig.clock.now() + Duration::from_secs(1))
            .await
            .into_iter()
            .map(|(packet, _, _)| packet)
            .collect();
        assert_eq!(before.len(), 8 * 1024 * 3 / 960);
        rig.publish(8 * 1024, &BROKEN_FRAME);
        let later = rig.clock.now() + Duration::from_millis(100);
        assert!(rig.run_until(later).await.is_empty());
        rig.publish(9 * 1024, input[9]);
        // A second failure inside the summary interval is counted quietly.
        rig.publish(10 * 1024, &BROKEN_FRAME);
        rig.publish_all(11 * 1024, &input[11..]);
        let after = rig.finish().await;
        assert!(before.iter().chain(&after).all(|p| p.epoch == 0));
        assert_eq!(after[0].rtp.ts, rtp_ts(anchored(9 * 1024, 16_000)));
        let resumed = after
            .iter()
            .rposition(|p| p.frame_start && p.rtp.ts == rtp_ts(anchored(11 * 1024, 16_000)));
        assert!(resumed.is_some());
        let dropped = "transcoder: frame dropped; re-anchoring at the next";
        assert_eq!(logs.count(Level::WARN, dropped), 1);
        let lost = "transcoder: camera audio timeline moved; re-anchoring";
        assert_eq!(logs.count(Level::DEBUG, lost), 0);
    }

    #[tokio::test]
    async fn a_lag_on_the_side_branch_re_anchors_at_the_oldest_frame_held() {
        let limits = TrackLimits {
            frame_capacity: 4,
            ..TrackLimits::default()
        };
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::start(&CONFIG_16K_MONO, 16_000, 1, limits);
        let input = frames(SINE_16K_MONO);
        // Twelve frames before the task runs: it misses the first eight.
        rig.publish_all(0, &input[..12]);
        let packets = rig.finish().await;
        assert_eq!(packets[0].rtp.ts, rtp_ts(anchored(8 * 1024, 16_000)));
        assert!(packets.iter().all(|p| p.epoch == 0));
        let lagged = "transcoder lagged behind the source; re-anchoring";
        assert_eq!(logs.count(Level::WARN, lagged), 1);
    }

    #[tokio::test]
    async fn repeated_moves_and_lags_are_logged_once_per_interval() {
        let (logs, _guard) = Logs::capture();
        let limits = TrackLimits {
            frame_capacity: 4,
            ..TrackLimits::default()
        };
        let mut rig = Rig::start(&CONFIG_48K_MONO, 48_000, 1, limits);
        for round in 0..2 {
            // Eight frames at once: the task misses four each time.
            for i in 0..8 {
                rig.publish(1024 * (round * 20 + i), &SILENT_FRAME);
            }
            settle().await;
        }
        // The second lag anchored on frame 24, and frame 40 follows 27:
        // frame 52 fills the window and re-anchors on itself. Frames 75 and
        // 95 are lost: frames 83 and 103 re-anchor over them.
        publish_silent(
            &rig,
            (40..120).filter(|i| *i != 75 && *i != 95).map(|i| i * 1024),
        )
        .await;
        let packets = rig.finish().await;
        assert!(packets.iter().all(|p| p.epoch == 0));
        let lagged = "transcoder lagged behind the source; re-anchoring";
        assert_eq!(logs.count(Level::WARN, lagged), 1);
        assert_eq!(logs.count(Level::DEBUG, MOVED), 1);
        // Each re-anchor shows in the timestamps all the same.
        let jumped: Vec<u32> = jumps(&packets).iter().map(|i| packets[*i].rtp.ts).collect();
        let at = |frame: i64| rtp_ts(anchored(frame * 1024, 48_000));
        assert!(jumped.ends_with(&[at(52), at(83), at(103)]), "{jumped:?}");
    }

    #[test]
    fn logs_capture_takes_every_kind_of_call() {
        let (logs, _guard) = Logs::capture();
        let span = tracing::info_span!("span", field = tracing::field::Empty);
        span.record("field", 1);
        span.follows_from(span::Id::from_u64(2));
        span.in_scope(|| tracing::info!(n = 1, "inside"));
        assert_eq!(logs.count(Level::INFO, "inside"), 1);
    }

    #[tokio::test]
    async fn dropping_the_handle_stops_the_task() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::of(&F16);
        rig.publish_all(0, &frames(SINE_16K_MONO)[..2]);
        settle().await;
        // Of the frames' 6 packets one left at once; the pacer holds 5.
        assert_eq!(rig.drain().len(), 1);
        let stop = rig.handle.as_ref().unwrap().stop.clone();
        rig.handle = None;
        assert!(stop.is_cancelled());
        stopped(&rig.output, 1).await;
        assert_eq!(
            logs.fields(Level::INFO, "transcoder stopped"),
            vec![vec![
                "track=a1".to_owned(),
                "reason=\"cancelled\"".to_owned()
            ]]
        );
        // What the pacer held is dropped, and nothing more is transcoded.
        rig.publish(2048, frames(SINE_16K_MONO)[2]);
        rig.clock.advance(Duration::from_secs(1));
        settle().await;
        assert!(rig.drain().is_empty());
    }

    #[tokio::test]
    async fn paced_packets_leave_one_opus_frame_apart_after_their_frame_within_the_delay() {
        for fixture in [&F16, &F48] {
            let mut rig = Rig::of(fixture);
            let delay = AacToOpus::delay(fixture.rate).unwrap();
            assert_eq!(
                rig.handle.as_ref().unwrap().delay,
                delay,
                "the handle reports it"
            );
            let input = frames(fixture.adts);
            let mut released = Vec::new();
            // The recording three times over on one timeline, in real
            // time, from 0: the first packets' timestamps are before it
            // and wrap (RFC 3550 §5.1).
            for (i, frame) in input.iter().cycle().take(3 * input.len()).enumerate() {
                let ts = 1024 * i as i64;
                released.extend(rig.live(ts, frame).await);
            }
            let end = rig.clock.now() + Duration::from_secs(1);
            released.extend(rig.run_until(end).await);
            let samples = 3 * input.len() * 1024 * 48_000 / fixture.rate as usize;
            assert_eq!(released.len(), samples / 960, "{}", fixture.rate);
            let mut delays = Vec::new();
            let mut gaps = Vec::new();
            let mut worst_lateness = Duration::ZERO;
            for (i, (packet, frame, mapped)) in released.iter().enumerate() {
                // The side-branch frame came first, with the capture time
                // a session maps the packet to.
                assert_eq!(rtp_ts(frame.ts.ticks()), packet.rtp.ts);
                assert_eq!(&frame.payload[..], &packet.payload[..]);
                assert!(frame.keyframe);
                let expected = rig.at48(frame.ts.ticks());
                let off = frame.wallclock.max(expected) - frame.wallclock.min(expected);
                assert!(off < Duration::from_micros(1), "{off:?}");
                let mapped = mapped.unwrap();
                let off = mapped.max(expected) - mapped.min(expected);
                assert!(off < Duration::from_micros(1), "{off:?}");
                assert!(packet.frame_start);
                worst_lateness = worst_lateness.max(packet.lateness);
                delays.push(packet.arrival - expected);
                if let Some((previous, _, _)) = i.checked_sub(1).map(|j| &released[j]) {
                    assert_eq!(packet.rtp.ts.wrapping_sub(previous.rtp.ts), 960);
                    assert_eq!(packet.rtp.seq, previous.rtp.seq.wrapping_add(1));
                    gaps.push(packet.arrival - previous.arrival);
                }
            }
            // Measured 2026-10-01: the worst is the reported delay at
            // 16 kHz (88.5 ms) and 1.2 ms under it at 48 kHz, as before
            // pacing: a clump's later packets wait as long as their media
            // is later than its first's.
            let worst = *delays.iter().max().unwrap();
            assert!(
                worst <= delay && worst + Duration::from_millis(10) > delay,
                "{} Hz: worst {worst:?}, reported {delay:?}",
                fixture.rate
            );
            // Never two at once. Within the first frames the pace settles
            // on the frame whose packets are ready latest; from then on
            // every packet leaves one Opus frame after the previous, with
            // the same delay (to the step the clock moves by).
            assert!(
                gaps.iter()
                    .all(|gap| *gap + STEP > crate::opus::FRAME_DURATION)
            );
            let settled = 50;
            assert!(
                gaps[settled..]
                    .iter()
                    .all(|gap| gap.abs_diff(crate::opus::FRAME_DURATION) < STEP),
                "{} Hz: {gaps:?}",
                fixture.rate
            );
            assert!(
                delays[settled..].iter().all(|d| worst.abs_diff(*d) < STEP),
                "{} Hz: {delays:?}",
                fixture.rate
            );
            // The derived track's lateness meter sees the smooth pace: only
            // the settling, one Opus frame at most.
            assert!(
                worst_lateness <= crate::opus::FRAME_DURATION,
                "{} Hz: {worst_lateness:?}",
                fixture.rate
            );
        }
    }

    #[tokio::test]
    async fn stereo_packets_carry_both_channels() {
        let mut rig = Rig::start(&CONFIG_48K_STEREO, 48_000, 2, TrackLimits::default());
        let silence = vec![&SILENT_FRAME[..]; 15];
        rig.publish_all(0, &silence);
        let packets = rig.finish().await;
        // 15 frames of 1024 are exactly 16 packets of 960.
        assert_eq!(packets.len(), 16);
        // RFC 6716 §3.1: the s bit says stereo.
        assert!(packets.iter().all(|p| p.payload[0] & 0x04 == 0x04));
    }

    #[test]
    fn derives_opus_from_mono_and_stereo_aac_lc_only() {
        let transcoder = AacToOpus::new(Arc::new(FakeClock::from_system()));
        for channels in [1, 2] {
            assert_eq!(
                transcoder.derive(&aac(&[], 16_000, channels), CodecFamily::Opus),
                Some(Codec::Opus { channels })
            );
        }
        for channels in [0, 3] {
            assert_eq!(
                transcoder.derive(&aac(&[], 16_000, channels), CodecFamily::Opus),
                None
            );
        }
        assert_eq!(
            transcoder.derive(&aac(&[], 16_000, 1), CodecFamily::Pcmu),
            None
        );
        for rate in [7_350, 96_000] {
            assert!(
                transcoder
                    .derive(&aac(&[], rate, 1), CodecFamily::Opus)
                    .is_some()
            );
        }
        for rate in [7_349, 96_001] {
            assert_eq!(
                transcoder.derive(&aac(&[], rate, 1), CodecFamily::Opus),
                None
            );
        }
        assert_eq!(transcoder.derive(&Codec::Pcmu, CodecFamily::Opus), None);
        assert_eq!(
            transcoder.derive(&Codec::Opus { channels: 1 }, CodecFamily::Opus),
            None
        );
    }

    #[test]
    fn spawn_refuses_what_it_cannot_build() {
        let transcoder = AacToOpus::new(Arc::new(FakeClock::from_system()));
        let input = Track::new(
            TrackId::new(Kind::Audio, 0),
            Codec::Pcmu,
            8_000,
            TrackLimits::default(),
            FakeClock::from_system().now(),
        );
        let spawn = |from: &Codec, output: Arc<Track>| {
            transcoder
                .spawn(input.subscribe_frames(), from, output)
                .unwrap_err()
        };
        assert_eq!(
            spawn(&Codec::Pcmu, opus_track(1, 48_000)),
            TranscodeError::Unsupported {
                from: CodecFamily::Pcmu,
                to: CodecFamily::Opus
            }
        );
        assert_eq!(
            spawn(&aac(&CONFIG_16K_MONO, 16_000, 3), opus_track(1, 48_000)),
            TranscodeError::Unsupported {
                from: CodecFamily::AacLc,
                to: CodecFamily::Opus
            }
        );
        let mono = aac(&CONFIG_16K_MONO, 16_000, 1);
        assert_eq!(
            spawn(&mono, opus_track(2, 48_000)),
            TranscodeError::Failed("output track is opus at 48000 Hz, not opus at 48000 Hz".into())
        );
        assert_eq!(
            spawn(&mono, opus_track(1, 90_000)),
            TranscodeError::Failed("output track is opus at 90000 Hz, not opus at 48000 Hz".into())
        );
        // HE-AAC declared as AAC-LC: the decoder refuses the config.
        assert_eq!(
            spawn(&aac(&[0x2b, 0x08], 24_000, 1), opus_track(1, 48_000)),
            TranscodeError::Failed("HE-AAC (audio object type 5) is not supported".into())
        );
    }

    #[test]
    fn the_added_delay_meets_the_per_rate_budgets() {
        // The budgets: < 50 ms at 48 and 44.1 kHz, < 95 ms at 16 kHz,
        // < 160 ms at 8 kHz; each 10 ms more than with 10 ms Opus frames,
        // the FIFO waiting for a 20 ms frame (2026-10-01).
        let us = |rate| AacToOpus::delay(rate).unwrap().as_micros();
        assert_eq!(us(48_000), 43_833);
        assert_eq!(us(44_100), 46_428);
        assert_eq!(us(16_000), 88_500);
        assert_eq!(us(8_000), 154_500);
        // The other AAC rates, and the one rate over its class's budget.
        assert_eq!(us(32_000), 55_500);
        assert_eq!(us(24_000), 66_499);
        assert_eq!(us(22_050), 70_377);
        assert_eq!(us(11_025), 118_275);
        assert_eq!(us(7_350), 166_153);
        assert!(AacToOpus::delay(0).is_err());
    }

    #[test]
    fn delay_parts_add_up() {
        // One AAC frame at 16 kHz is 64 ms; 96 + 120 + 960 samples at
        // 48 kHz are 24.5 ms.
        assert_eq!(chain_delay(16_000, 96, 120), Duration::from_micros(88_500));
        assert_eq!(chain_delay(48_000, 0, 0), Duration::from_nanos(41_333_333));
        assert_eq!(chain_delay(0, 0, 0), Duration::from_nanos(u64::MAX));
    }

    #[test]
    fn rates_convert_to_48_khz_rounding_down() {
        assert_eq!(to_48k(1_000, 16_000), 3_000);
        assert_eq!(to_48k(-1, 16_000), -3);
        assert_eq!(to_48k(1, 44_100), 1);
        assert_eq!(to_48k(-1, 44_100), -2);
        assert_eq!(to_48k(44_100, 44_100), 48_000);
        assert_eq!(to_48k(7, 48_000), 7);
        assert_eq!(to_48k(i64::MAX, 8_000), i64::MAX);
        assert_eq!(to_48k(i64::MIN, 8_000), i64::MIN);
        assert_eq!(to_48k(5, 0), 0);
    }

    #[test]
    fn rfc3550_5_1_rtp_timestamps_are_the_low_32_bits() {
        assert_eq!(rtp_ts(5), 5);
        assert_eq!(rtp_ts(-1), u32::MAX);
        assert_eq!(rtp_ts(1_i64 << 32), 0);
        assert_eq!(rtp_ts((1_i64 << 32) + 7), 7);
    }

    #[test]
    fn shift_moves_either_way_at_48_khz() {
        let at = FakeClock::from_system().now() + Duration::from_secs(10);
        assert_eq!(shift(at, 480), at + Duration::from_millis(10));
        assert_eq!(
            shift(at, -480),
            at.checked_sub(Duration::from_millis(10)).unwrap()
        );
        assert_eq!(shift(at, 0), at);
    }

    #[test]
    fn chain_errors_say_which_stage_refused() {
        assert_eq!(
            ChainError::Decode(DecodeError::Decoder("x".into())).to_string(),
            "AAC decoder: x"
        );
        assert_eq!(
            ChainError::Resample(ResampleError::Library("y".into())).to_string(),
            "resampler: y"
        );
        assert_eq!(
            ChainError::Encode(OpusError::Channels(3)).to_string(),
            "3 channels, the encoder takes 1 or 2"
        );
    }
}

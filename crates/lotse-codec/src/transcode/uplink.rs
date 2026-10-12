//! The talk-back transcoder: a session's uplink audio in, G.711 frames of
//! the camera's frame size out, each sent as soon as it is complete.
//!
//! It is the reverse instance of the [`Transcoder`] contract, not a second
//! abstraction: the input is a frame subscription of the uplink track (one
//! RTP payload per frame, as the session received it), the output a track
//! of the camera's G.711 law at 8 kHz, whose packets the backchannel
//! sends.
//!
//! The chain is [`Decoder`] (Opus at 8 kHz: libopus band-limits, so no
//! resampler follows) → [`Law::encode`] in the camera's law, or for G.711
//! input [`Law::transcode`] to the camera's law (G.711's conversion
//! tables, code by code, when the browser sends the other law) → the frame
//! being filled (one byte per sample) → the camera's frames. When the
//! browser already sends the camera's law the codes pass through
//! untouched; only the framing and the RTP header change. Nothing
//! waits but a frame for its last sample: no playout buffer, no pacing, no
//! timer. The frames follow the input's timing, so the camera never gets
//! audio earlier than it arrived, nor more of it. The camera absorbs the
//! network's jitter itself: a Reolink `TrackMix WiFi` (firmware
//! `v3.0.0.3748_2408281837`), observed 2026-10-11, buffers about 1.1 s of
//! backchannel audio whatever the packet size (10, 20 and 40 ms tried),
//! and a one-frame playout lead in front of it changed nothing measurable.
//!
//! - **Framing.** Each packet is decoded as it arrives into the frame
//!   being filled, and every frame it completes leaves at once, with the
//!   packet that carried its last sample. Between packets the chain holds
//!   less than one frame: nothing queues, so there is no backlog to bound.
//! - **Gaps.** A gap in the input timestamps up to [`MAX_GAP`] (a lost
//!   packet, one that does not decode, a lag on the side branch) is not
//!   filled: concealment sent when the next packet reveals the gap would
//!   reach the camera as extra audio in a burst, and a camera that plays
//!   everything it receives keeps that delay for the rest of the session.
//!   The output timestamps advance by the gap instead, at the end of the
//!   frame being filled when the gap falls inside one. Opus input runs
//!   libopus's loss concealment over the gap and discards it, so the next
//!   packet decodes from the state libopus expects after a loss.
//! - **Late packets.** A packet behind the input already taken (late,
//!   reordered, duplicated) is dropped: its place on the timeline has
//!   passed.
//! - **Talk spurts.** A gap over [`MAX_GAP`] in the input timestamps, or a
//!   sender silent for longer than that, starts a new spurt: marker set,
//!   timestamp advanced by the time that passed. The partial frame the last
//!   spurt left is dropped, less than one frame of its tail: telling a
//!   tail from a slow packet takes a timer, and sending it with the next
//!   spurt would put it ahead of that spurt's audio, late and in a burst.
//!   Stopping the task drops it too.
//!
//! Implements ITU-T G.711 (its laws, and Tables 3 and 4 between them) at
//! the RTP clock of RFC 3551 §4.5.14 (8 kHz, static payload types of
//! Table 4), with the marker on the first packet of
//! a talkspurt (RFC 3551 §4.1) and timestamps that advance with the
//! sampling clock across silence and loss (RFC 3550 §5.1); Opus input at
//! the 48 kHz clock of RFC 7587 §4.1, its losses run through the decoder's
//! concealment per RFC 6716 §4.4.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_core::clock::Clock;
use lotse_core::codec::{Codec, CodecFamily};
use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields};
use lotse_core::task::spawn_named;
use lotse_core::throttle::Throttle;
use lotse_core::track::{FrameSubscription, SubscriptionError, Track};
use lotse_core::transcode::{TrackHandle, TranscodeError, Transcoder, UplinkFactory};
use tokio_util::sync::CancellationToken;

use super::{failed, rtp_ts};
use crate::g711::{Law, SAMPLE_RATE};
use crate::opus::{Decoder, OpusError};

/// The SSRC on the output's packets; the backchannel writes its own.
const SSRC: u32 = 0x4737_3131;

/// Input ticks per 8 kHz sample for Opus: its RTP clock is 48 kHz
/// (RFC 7587 §4.1).
const OPUS_TICKS_PER_SAMPLE: i64 = 6;

/// Opus concealment comes in whole 2.5 ms steps (RFC 6716 §4.4): 20
/// samples at 8 kHz.
const CONCEAL_STEP: usize = 20;

/// The longest gap a talk spurt bridges: 100 ms. A lost packet or a short
/// network stall keeps the spurt, its timestamps advanced by the gap; a
/// longer gap in the input timestamps, or a sender silent for longer (a
/// muted or replaced track), starts a new spurt with the marker set.
pub const MAX_GAP: Duration = Duration::from_millis(100);

/// [`MAX_GAP`] in 8 kHz samples.
const MAX_GAP_SAMPLES: i64 = 800;

/// The input packet [`ToG711::delay`] assumes: RFC 3551 §4.5's default
/// packetization interval of 20 ms, which a browser's talk-back keeps
/// without an `a=ptime`.
const INPUT_PACKET: Duration = Duration::from_millis(20);

/// The G.711 samples one output frame carries: the camera's frame
/// duration at 8 kHz, one byte per sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSize(u16);

impl FrameSize {
    /// 20 ms, 160 samples: RFC 3551 §4.5's default packetization interval
    /// and what most cameras accept.
    pub const DEFAULT: Self = Self(160);

    /// The smallest frame: 10 ms.
    pub const MIN: u16 = 80;

    /// The largest frame: 120 ms, Opus's longest packet (RFC 6716
    /// §3.2.5), and well inside one packet at 1 byte per sample.
    pub const MAX: u16 = 960;

    /// A frame of `samples` at 8 kHz, between [`FrameSize::MIN`] and
    /// [`FrameSize::MAX`].
    pub const fn new(samples: u16) -> Option<Self> {
        if samples >= Self::MIN && samples <= Self::MAX {
            Some(Self(samples))
        } else {
            None
        }
    }

    /// The frame closest to `duration` that the chain frames: its whole
    /// 8 kHz samples (125 µs each), clamped to [`FrameSize::MIN`] and
    /// [`FrameSize::MAX`].
    pub fn clamped(duration: Duration) -> Self {
        let samples = duration
            .as_micros()
            .checked_div(125)
            .unwrap_or_default()
            .clamp(u128::from(Self::MIN), u128::from(Self::MAX));
        Self(u16::try_from(samples).unwrap_or(Self::MAX))
    }

    /// The samples per frame.
    pub const fn samples(self) -> u16 {
        self.0
    }

    /// The frame's duration: 125 µs per sample.
    pub fn duration(self) -> Duration {
        Duration::from_micros(u64::from(self.0).saturating_mul(125))
    }
}

/// The talk-back transcoder: Opus or G.711 uplink audio to G.711 frames of
/// one frame size. Stateless itself: every [`Transcoder::spawn`] builds
/// its own chain.
#[derive(Debug)]
pub struct ToG711 {
    /// Stamps each frame's release and rate-limits the log lines.
    clock: Arc<dyn Clock>,
    /// The camera's frame size.
    frame: FrameSize,
}

impl ToG711 {
    /// A transcoder producing frames of `frame`, reading time from `clock`.
    pub fn new(clock: Arc<dyn Clock>, frame: FrameSize) -> Self {
        Self { clock, frame }
    }

    /// The delay the chain adds for frames of `frame`, as its handle
    /// reports it: the longest a frame leaves after the capture time its
    /// timestamp claims, for input that arrives on time in packets of
    /// 20 ms, RFC 3551 §4.5's default packetization interval, which a
    /// browser's talk-back keeps without an `a=ptime`. A frame leaves with the packet that carries its
    /// last sample, so its first sample waits for the rest of the frame:
    /// `frame` less one packet, nothing when a packet fills a frame or
    /// more. Packets of another duration wait less than one frame. Nothing
    /// else waits: there is no playout buffer, and decoding at 8 kHz adds
    /// no filter delay.
    pub fn delay(frame: FrameSize) -> Duration {
        frame.duration().saturating_sub(INPUT_PACKET)
    }
}

/// The talk-back transcoder of every frame size, as the binary registers
/// it for the worker ([`Registries::uplink`](lotse_core::registry::Registries::uplink)):
/// a [`ToG711`] per backchannel, framed as its device asks.
#[derive(Debug)]
pub struct ToG711Factory {
    /// The clock every transcoder it builds reads.
    clock: Arc<dyn Clock>,
}

impl ToG711Factory {
    /// A factory whose transcoders read time from `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }
}

impl UplinkFactory for ToG711Factory {
    /// A [`ToG711`] of [`FrameSize::clamped`] `frame`: a device asking for
    /// less than 10 ms or more than 120 ms gets the nearest the chain
    /// frames, and the transcoder's start log names the frame it got.
    fn transcoder(&self, frame: Duration) -> Arc<dyn Transcoder> {
        Arc::new(ToG711::new(
            Arc::clone(&self.clock),
            FrameSize::clamped(frame),
        ))
    }
}

impl Transcoder for ToG711 {
    /// PCMU or PCMA from mono or stereo Opus, or from either G.711 law
    /// (passthrough for the same law).
    fn derive(&self, from: &Codec, to: CodecFamily) -> Option<Codec> {
        let law = match to {
            CodecFamily::Pcmu => Law::Mu,
            CodecFamily::Pcma => Law::A,
            _ => return None,
        };
        match from {
            Codec::Opus { channels: 1 | 2 } | Codec::Pcmu | Codec::Pcma => Some(law.codec()),
            _ => None,
        }
    }

    /// Builds the chain for `from` and starts its task, which runs until
    /// the handle is dropped or the input track is gone. Must be called
    /// inside a Tokio runtime. The owner closes `output`.
    fn spawn(
        &self,
        input: FrameSubscription,
        from: &Codec,
        output: Arc<Track>,
    ) -> Result<TrackHandle, TranscodeError> {
        let to = output.codec();
        let (Some(_), Some(law)) = (self.derive(from, to.family()), Law::of(&to)) else {
            return Err(TranscodeError::Unsupported {
                from: from.family(),
                to: to.family(),
            });
        };
        if output.clock_rate() != SAMPLE_RATE {
            return Err(TranscodeError::Failed(format!(
                "output track is at {} Hz, not {SAMPLE_RATE} Hz",
                output.clock_rate()
            )));
        }
        let source = match Law::of(from) {
            Some(from) => Input::G711(from),
            None => Input::Opus(Decoder::new(SAMPLE_RATE).map_err(failed)?),
        };
        let chain = Chain::new(source, law, self.frame, output, Arc::clone(&self.clock));
        let delay = Self::delay(self.frame);
        tracing::info!(
            track = %chain.output.id(),
            from = from.name(),
            to = to.name(),
            frame_ms = self.frame.duration().as_millis(),
            delay_ms = delay.as_millis(),
            "transcoder started: uplink to g711"
        );
        let stop = CancellationToken::new();
        let track = Arc::clone(&chain.output);
        let _task = spawn_named("transcode.uplink_g711", run(chain, input, stop.clone()));
        Ok(TrackHandle { track, delay, stop })
    }
}

/// What the uplink carries.
#[derive(Debug)]
enum Input {
    /// Opus, decoded at 8 kHz.
    Opus(Decoder),
    /// G.711 of this law.
    G711(Law),
}

impl Input {
    /// Input timestamp ticks per 8 kHz sample.
    const fn ticks_per_sample(&self) -> i64 {
        match self {
            Self::Opus(_) => OPUS_TICKS_PER_SAMPLE,
            Self::G711(_) => 1,
        }
    }
}

/// The duration of `samples` at 8 kHz, 125 µs each; none for a negative
/// count.
fn span(samples: i64) -> Duration {
    Duration::from_micros(u64::try_from(samples).unwrap_or(0).saturating_mul(125))
}

/// The whole 8 kHz samples in `duration`.
fn samples_in(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros() / 125).unwrap_or(i64::MAX)
}

/// The talk spurt being sent: where its next frame sits on the output
/// timeline.
#[derive(Debug, Clone, Copy)]
struct Spurt {
    /// The 8 kHz timestamp of the next frame's first sample, unwrapped.
    ts: i64,
    /// The capture time of the next frame's first sample.
    wallclock: Instant,
    /// Samples the input skipped inside the frame being filled: the frame
    /// after it starts that much later.
    skipped: i64,
    /// When the audio taken so far ends: the last packet's capture time
    /// plus its duration. A packet captured more than [`MAX_GAP`] later
    /// finds the sender stopped.
    end: Instant,
    /// The next frame is the spurt's first.
    first: bool,
}

/// One running chain: the input decoder, the frame being filled and the
/// spurt's place on the output timeline.
#[derive(Debug)]
struct Chain {
    /// The uplink's codec and its decoder.
    input: Input,
    /// The camera's law.
    law: Law,
    /// The camera's frame size.
    frame: FrameSize,
    /// The G.711 track the frames go to.
    output: Arc<Track>,
    /// Stamps each frame's release and rate-limits the log lines.
    clock: Arc<dyn Clock>,
    /// The frame being filled, encoded, oldest first: fewer samples than a
    /// frame once a packet's frames have left.
    fifo: VecDeque<u8>,
    /// The input timestamp the next packet should carry; `None` until a
    /// packet sets it, so the first packet of a timeline is taken as is.
    expected: Option<i64>,
    /// The input epoch of the last packet.
    epoch: Option<u32>,
    /// The talk spurt being sent; `None` before the first packet.
    spurt: Option<Spurt>,
    /// The next packet's sequence number.
    seq: u16,
    /// Packets dropped behind the input already taken.
    late: Throttle,
    /// Gaps in the input bridged.
    gaps: Throttle,
    /// Packets that failed to decode.
    failures: Throttle,
    /// Lags on the input subscription.
    lags: Throttle,
}

impl Chain {
    /// A chain decoding `input` into frames of `frame` in `law` on
    /// `output`.
    fn new(
        input: Input,
        law: Law,
        frame: FrameSize,
        output: Arc<Track>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            input,
            law,
            frame,
            output,
            clock,
            fifo: VecDeque::new(),
            expected: None,
            epoch: None,
            spurt: None,
            seq: 0,
            late: Throttle::default(),
            gaps: Throttle::default(),
            failures: Throttle::default(),
            lags: Throttle::default(),
        }
    }

    /// One uplink packet: dropped when it is behind the input already
    /// taken; otherwise it starts a spurt, a new one after a long gap or
    /// silence, or bridges a short gap before it, and its audio goes into
    /// the frame being filled, sending every frame that completes.
    fn packet(&mut self, frame: &MediaFrame) {
        let now = self.clock.now();
        let ts = frame.ts.ticks();
        if self.epoch != Some(frame.epoch) || frame.discontinuity {
            if self.epoch.is_some() {
                tracing::debug!(
                    track = %self.output.id(),
                    input_epoch = frame.epoch,
                    ts,
                    "uplink: new input timeline; resyncing"
                );
            }
            self.epoch = Some(frame.epoch);
            self.expected = None;
        }
        let ahead = self
            .expected
            .map_or(0, |expected| ts.saturating_sub(expected));
        if ahead < 0 {
            if let Some(count) = self.late.hit(now) {
                tracing::debug!(
                    track = %self.output.id(),
                    late_ticks = ahead.saturating_neg(),
                    ts,
                    count,
                    "uplink: late packet dropped; its place has passed"
                );
            }
            return;
        }
        let gap = ahead
            .checked_div(self.input.ticks_per_sample())
            .unwrap_or(0);
        let mut spurt = match self.spurt {
            None => self.start(frame.wallclock, 0, "first_packet"),
            Some(spurt) if gap > MAX_GAP_SAMPLES => {
                self.restart(&spurt, frame.wallclock, "input_gap")
            }
            Some(spurt) if frame.wallclock.saturating_duration_since(spurt.end) > MAX_GAP => {
                self.restart(&spurt, frame.wallclock, "sender_stopped")
            }
            Some(spurt) if gap > 0 => self.bridge(spurt, gap, now),
            Some(spurt) => spurt,
        };
        // The packet's place is taken even if it does not decode: its
        // span is the next packet's gap, bridged once.
        self.expected = Some(ts);
        match self.decode(&frame.payload) {
            Ok(samples) => {
                let samples = i64::try_from(samples).unwrap_or(i64::MAX);
                self.expected =
                    Some(ts.saturating_add(samples.saturating_mul(self.input.ticks_per_sample())));
                spurt.end = frame
                    .wallclock
                    .checked_add(span(samples))
                    .unwrap_or(frame.wallclock);
                spurt = self.flush(spurt, now);
            }
            Err(err) => {
                if let Some(count) = self.failures.hit(now) {
                    tracing::warn!(
                        track = %self.output.id(),
                        error = %err,
                        ts,
                        count,
                        "uplink: packet dropped; it does not decode"
                    );
                }
            }
        }
        self.spurt = Some(spurt);
    }

    /// A talk spurt at timestamp `ts` on a packet captured at `wallclock`:
    /// its first frame carries the marker.
    fn start(&self, wallclock: Instant, ts: i64, reason: &'static str) -> Spurt {
        tracing::debug!(track = %self.output.id(), ts, reason, "uplink: talk spurt started");
        Spurt {
            ts,
            wallclock,
            skipped: 0,
            end: wallclock,
            first: true,
        }
    }

    /// Ends `spurt` for `reason`; the next, on a packet captured at
    /// `wallclock`. The partial frame is dropped; the new spurt's
    /// timestamp continues from where the old one's audio ended, advanced
    /// by the time that passed since (RFC 3550 §5.1).
    fn restart(&mut self, spurt: &Spurt, wallclock: Instant, reason: &'static str) -> Spurt {
        let dropped = self.fifo.len();
        let end = spurt
            .ts
            .saturating_add(i64::try_from(dropped).unwrap_or(i64::MAX))
            .saturating_add(spurt.skipped);
        let silence = wallclock.saturating_duration_since(spurt.end);
        tracing::debug!(
            track = %self.output.id(),
            ts = end,
            dropped_samples = dropped,
            silence_ms = silence.as_millis(),
            reason,
            "uplink: talk spurt ended"
        );
        self.fifo.clear();
        self.start(wallclock, end.saturating_add(samples_in(silence)), reason)
    }

    /// Bridges a gap of `gap` samples, up to [`MAX_GAP`], in `spurt`
    /// before the packet being taken: nothing is sent for it, and the
    /// output timeline moves on by it, at once when no frame is being
    /// filled, else after that frame, which the gap falls inside. Opus
    /// runs its loss concealment over the gap and discards the samples, so
    /// the next packet decodes as libopus expects after a loss (RFC 6716
    /// §4.4).
    fn bridge(&mut self, mut spurt: Spurt, gap: i64, now: Instant) -> Spurt {
        if let Input::Opus(decoder) = &mut self.input {
            let steps = usize::try_from(gap).unwrap_or(0).div_ceil(CONCEAL_STEP);
            let concealed = decoder
                .conceal(steps.saturating_mul(CONCEAL_STEP))
                .map_or(0, <[i16]>::len);
            tracing::trace!(track = %self.output.id(), concealed, "uplink: loss run through the decoder");
        }
        if self.fifo.is_empty() {
            spurt.ts = spurt.ts.saturating_add(gap);
            spurt.wallclock = spurt
                .wallclock
                .checked_add(span(gap))
                .unwrap_or(spurt.wallclock);
        } else {
            spurt.skipped = spurt.skipped.saturating_add(gap);
        }
        if let Some(count) = self.gaps.hit(now) {
            tracing::debug!(
                track = %self.output.id(),
                gap_samples = gap,
                count,
                "uplink: input gap bridged; timestamps advanced by it"
            );
        }
        spurt
    }

    /// Decodes one payload into the frame being filled; the samples it
    /// carried.
    fn decode(&mut self, payload: &[u8]) -> Result<usize, OpusError> {
        let law = self.law;
        match &mut self.input {
            Input::Opus(decoder) => {
                let pcm = decoder.decode(payload)?;
                self.fifo.extend(pcm.iter().map(|s| law.encode(*s)));
                Ok(pcm.len())
            }
            Input::G711(from) => {
                let from = *from;
                self.fifo
                    .extend(payload.iter().map(|c| law.transcode(from, *c)));
                Ok(payload.len())
            }
        }
    }

    /// Sends every frame of `spurt` the last packet completed, released
    /// at `now`; the spurt moved on past them.
    fn flush(&mut self, mut spurt: Spurt, now: Instant) -> Spurt {
        let need = usize::from(self.frame.samples());
        let complete = self.fifo.len().checked_div(need).unwrap_or(0);
        for _ in 0..complete {
            let payload: Bytes = self.fifo.drain(..need.min(self.fifo.len())).collect();
            self.publish(&spurt, payload, now);
            let step = i64::from(self.frame.samples()).saturating_add(spurt.skipped);
            spurt.ts = spurt.ts.saturating_add(step);
            spurt.wallclock = spurt
                .wallclock
                .checked_add(span(step))
                .unwrap_or(spurt.wallclock);
            spurt.skipped = 0;
            spurt.first = false;
        }
        spurt
    }

    /// The input subscription skipped `skipped` packets: their audio is
    /// lost, and the next packet bridges it as a gap.
    fn lagged(&mut self, skipped: u64) {
        if let Some(count) = self.lags.hit(self.clock.now()) {
            tracing::warn!(
                track = %self.output.id(),
                skipped,
                count,
                "transcoder lagged behind the uplink; its packets are lost"
            );
        }
    }

    /// Publishes one frame released at `now`, on the side branch and then
    /// live, with the law's static payload type and the marker on a
    /// spurt's first packet (RFC 3551 §4.1).
    fn publish(&mut self, spurt: &Spurt, payload: Bytes, now: Instant) {
        tracing::trace!(track = %self.output.id(), ts = spurt.ts, "uplink: frame");
        let packet_payload: Arc<[u8]> = Arc::from(payload.as_ref());
        self.output.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(spurt.ts),
            wallclock: spurt.wallclock,
            arrival: now,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload,
        });
        self.output.publish_packet(MediaPacket {
            arrival: now,
            rtp: RtpHeaderFields {
                pt: self.law.payload_type(),
                seq: self.seq,
                ts: rtp_ts(spurt.ts),
                marker: spurt.first,
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

/// The transcoder task: packets in, the frames they complete out, until
/// `stop` is cancelled or the input track is gone; the partial frame is
/// dropped with the talker.
async fn run(mut chain: Chain, mut input: FrameSubscription, stop: CancellationToken) {
    let reason = loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => break "cancelled",
            received = input.recv() => match received {
                Ok(frame) => chain.packet(&frame),
                Err(SubscriptionError::Lagged(skipped)) => chain.lagged(skipped),
                Err(SubscriptionError::Closed) => break "input_closed",
            },
        }
    };
    tracing::info!(
        track = %chain.output.id(),
        reason,
        dropped_samples = chain.fifo.len(),
        "transcoder stopped"
    );
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

    use lotse_core::clock::FakeClock;
    use lotse_core::codec::Kind;
    use lotse_core::track::{PacketSubscription, TrackId, TrackLimits};
    use tracing::Level;

    use super::super::tests::Logs;
    use super::*;
    use crate::opus::{Encoder, FRAME_SAMPLES as OPUS_FRAME};

    const STARTED: &str = "uplink: talk spurt started";
    const ENDED: &str = "uplink: talk spurt ended";
    const LATE: &str = "uplink: late packet dropped; its place has passed";
    const BRIDGED: &str = "uplink: input gap bridged; timestamps advanced by it";

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn track(codec: Codec, rate: u32, index: u8, limits: TrackLimits, at: Instant) -> Arc<Track> {
        Arc::new(Track::new(
            TrackId::new(Kind::Audio, index),
            codec,
            rate,
            limits,
            at,
        ))
    }

    /// A running transcoder between an uplink track and a G.711 track, on
    /// a fake clock that starts at `start`.
    struct Rig {
        clock: Arc<FakeClock>,
        start: Instant,
        input: Option<Arc<Track>>,
        output: Arc<Track>,
        packets: PacketSubscription,
        frames: FrameSubscription,
        /// The capture time of every frame released, after the start.
        wallclocks: Vec<Duration>,
        handle: Option<TrackHandle>,
    }

    impl Rig {
        fn start(from: &Codec, law: Law, frame: FrameSize) -> Self {
            Self::with_limits(from, law, frame, TrackLimits::default())
        }

        fn with_limits(from: &Codec, law: Law, frame: FrameSize, limits: TrackLimits) -> Self {
            let clock = Arc::new(FakeClock::from_system());
            let start = clock.now();
            let rate = if Law::of(from).is_some() {
                8_000
            } else {
                48_000
            };
            let input = track(from.clone(), rate, 0, limits, start);
            let output = track(law.codec(), 8_000, 1, TrackLimits::default(), start);
            let packets = output.subscribe_packets();
            let frames = output.subscribe_frames();
            let handle = ToG711::new(clock.clone(), frame)
                .spawn(input.subscribe_frames(), from, Arc::clone(&output))
                .unwrap();
            Self {
                clock,
                start,
                input: Some(input),
                output,
                packets,
                frames,
                wallclocks: Vec::new(),
                handle: Some(handle),
            }
        }

        fn opus() -> Self {
            Self::start(&Codec::Opus { channels: 1 }, Law::Mu, FrameSize::DEFAULT)
        }

        fn pcmu(frame: FrameSize) -> Self {
            Self::start(&Codec::Pcmu, Law::Mu, frame)
        }

        fn input(&self) -> &Arc<Track> {
            self.input.as_ref().unwrap()
        }

        /// Publishes one packet at input timestamp `ts`, arriving and
        /// captured now, without letting the task run.
        fn publish(&self, ts: i64, payload: &[u8]) {
            self.input().publish_frame(MediaFrame {
                ts: MediaTime::from_ticks(ts),
                wallclock: self.clock.now(),
                arrival: self.clock.now(),
                keyframe: true,
                discontinuity: false,
                epoch: 0,
                payload: Bytes::copy_from_slice(payload),
            });
        }

        /// Runs the clock to `at` after the start in 1 ms steps, letting
        /// the task take what was published at each, and returns what it
        /// released.
        async fn run_to(&mut self, at: Duration) -> Vec<Arc<MediaPacket>> {
            let mut out = Vec::new();
            loop {
                settle().await;
                while let Some(packet) = self.packets.try_recv().unwrap() {
                    let frame = self.frames.try_recv().unwrap().expect("its frame first");
                    assert_eq!(rtp_ts(frame.ts.ticks()), packet.rtp.ts);
                    assert_eq!(&frame.payload[..], &packet.payload[..]);
                    self.wallclocks
                        .push(frame.wallclock.saturating_duration_since(self.start));
                    out.push(packet);
                }
                let left = (self.start + at).saturating_duration_since(self.clock.now());
                if left.is_zero() {
                    return out;
                }
                self.clock.advance(left.min(ms(1)));
            }
        }

        /// Publishes `payloads` in real time, one every 20 ms from the
        /// start, `ticks` apart from 0, skipping the indices in `lost`;
        /// then runs to `until`. Returns what was released.
        async fn feed(
            &mut self,
            payloads: &[Bytes],
            ticks: i64,
            lost: &[usize],
            until: Duration,
        ) -> Vec<Arc<MediaPacket>> {
            let mut out = Vec::new();
            for (k, payload) in payloads.iter().enumerate() {
                out.extend(self.run_to(ms(20 * k as u64)).await);
                if !lost.contains(&k) {
                    self.publish(ticks * k as i64, payload);
                }
            }
            out.extend(self.run_to(until).await);
            out
        }
    }

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

    /// `count` 20 ms Opus packets of a 1 kHz sine at half scale.
    fn opus_tone(count: usize) -> Vec<Bytes> {
        let mut encoder = Encoder::new(1).unwrap();
        (0..count)
            .map(|k| {
                let pcm: Vec<f32> = (0..OPUS_FRAME)
                    .map(|n| {
                        let t = (k * OPUS_FRAME + n) as f32 / 48_000.0;
                        (std::f32::consts::TAU * 1_000.0 * t).sin() * 0.5
                    })
                    .collect();
                encoder.encode(&pcm).unwrap()
            })
            .collect()
    }

    /// libopus's 8 kHz decode of `packets`, μ-law encoded, with the loss
    /// of the packets in `lost` run through its concealment or not.
    fn reference(packets: &[Bytes], lost: &[usize], conceal: bool) -> Vec<u8> {
        let mut decoder = Decoder::new(8_000).unwrap();
        let mut out = Vec::new();
        for (k, packet) in packets.iter().enumerate() {
            if lost.contains(&k) {
                if conceal {
                    decoder.conceal(160).unwrap();
                }
                continue;
            }
            out.extend(
                decoder
                    .decode(packet)
                    .unwrap()
                    .iter()
                    .map(|s| Law::Mu.encode(*s)),
            );
        }
        out
    }

    /// `count` 20 ms G.711 packets of distinct codes: packet `k` holds
    /// `k`, `k + 1`, ... so every sample is traceable.
    fn codes(count: usize) -> Vec<Bytes> {
        (0..count)
            .map(|k| (0..160).map(|n| ((k * 7 + n) % 251) as u8).collect())
            .collect()
    }

    /// The payloads of `packets`, one stream.
    fn sent(packets: &[Arc<MediaPacket>]) -> Vec<u8> {
        packets.iter().flat_map(|p| p.payload.to_vec()).collect()
    }

    /// The payloads of `packets`, one stream.
    fn fed(packets: &[Bytes]) -> Vec<u8> {
        packets.iter().flat_map(|p| p.to_vec()).collect()
    }

    /// Decodes `packets` of `law` into one stream.
    fn pcm(law: Law, packets: &[Arc<MediaPacket>]) -> Vec<i16> {
        packets
            .iter()
            .flat_map(|p| p.payload.iter().map(|c| law.decode(*c)).collect::<Vec<_>>())
            .collect()
    }

    fn rms(pcm: &[i16]) -> f64 {
        let sum: f64 = pcm.iter().map(|s| f64::from(*s).powi(2)).sum();
        (sum / pcm.len() as f64).sqrt() / 32_768.0
    }

    fn arrivals(rig: &Rig, packets: &[Arc<MediaPacket>]) -> Vec<Duration> {
        packets
            .iter()
            .map(|p| p.arrival.saturating_duration_since(rig.start))
            .collect()
    }

    fn timestamps(packets: &[Arc<MediaPacket>]) -> Vec<u32> {
        packets.iter().map(|p| p.rtp.ts).collect()
    }

    fn markers(packets: &[Arc<MediaPacket>]) -> Vec<bool> {
        packets.iter().map(|p| p.rtp.marker).collect()
    }

    #[test]
    fn rfc3551_4_5_a_frame_is_10_to_120_ms_20_by_default() {
        assert_eq!(FrameSize::DEFAULT.samples(), 160);
        assert_eq!(FrameSize::DEFAULT.duration(), ms(20));
        assert_eq!(FrameSize::new(80).unwrap().duration(), ms(10));
        assert_eq!(FrameSize::new(960).unwrap().duration(), ms(120));
        assert_eq!(FrameSize::new(79), None);
        assert_eq!(FrameSize::new(961), None);
        // A device's frame duration, in whole samples, clamped.
        assert_eq!(FrameSize::clamped(ms(20)), FrameSize::DEFAULT);
        assert_eq!(FrameSize::clamped(ms(10)).samples(), 80);
        assert_eq!(FrameSize::clamped(ms(120)).samples(), 960);
        assert_eq!(
            FrameSize::clamped(Duration::from_micros(30_100)).samples(),
            240
        );
        assert_eq!(FrameSize::clamped(ms(5)).samples(), FrameSize::MIN);
        assert_eq!(FrameSize::clamped(Duration::ZERO).samples(), FrameSize::MIN);
        assert_eq!(FrameSize::clamped(ms(121)).samples(), FrameSize::MAX);
        assert_eq!(FrameSize::clamped(Duration::MAX).samples(), FrameSize::MAX);
        assert_eq!(MAX_GAP.as_millis() * 8, MAX_GAP_SAMPLES as u128);
        assert_eq!((span(8), span(-1), samples_in(ms(1))), (ms(1), ms(0), 8));
    }

    #[test]
    fn rfc3551_4_5_the_delay_is_the_wait_for_the_rest_of_a_frame_of_20_ms_packets() {
        assert_eq!(INPUT_PACKET, ms(20));
        // A 20 ms packet fills a 20 ms frame, or two 10 ms ones: no wait.
        assert_eq!(ToG711::delay(FrameSize::DEFAULT), Duration::ZERO);
        assert_eq!(ToG711::delay(FrameSize::new(80).unwrap()), Duration::ZERO);
        // A 40 ms frame waits for its second packet.
        assert_eq!(ToG711::delay(FrameSize::new(320).unwrap()), ms(20));
        assert_eq!(ToG711::delay(FrameSize::new(960).unwrap()), ms(100));
    }

    #[test]
    fn derives_g711_from_opus_and_g711_only() {
        let transcoder = ToG711::new(Arc::new(FakeClock::from_system()), FrameSize::DEFAULT);
        for from in [
            Codec::Opus { channels: 1 },
            Codec::Opus { channels: 2 },
            Codec::Pcmu,
            Codec::Pcma,
        ] {
            assert_eq!(
                transcoder.derive(&from, CodecFamily::Pcmu),
                Some(Codec::Pcmu)
            );
            assert_eq!(
                transcoder.derive(&from, CodecFamily::Pcma),
                Some(Codec::Pcma)
            );
            assert_eq!(transcoder.derive(&from, CodecFamily::Opus), None);
        }
        for from in [Codec::Opus { channels: 3 }, Codec::G722] {
            assert_eq!(transcoder.derive(&from, CodecFamily::Pcmu), None);
        }
    }

    #[tokio::test]
    async fn the_factory_frames_as_the_device_asks() {
        let clock = Arc::new(FakeClock::from_system());
        let factory = ToG711Factory::new(clock.clone());
        let input = track(Codec::Pcmu, 8_000, 0, TrackLimits::default(), clock.now());
        for (asked, delay) in [
            (ms(40), ms(20)),
            (ms(20), Duration::ZERO),
            (ms(200), ms(100)),
        ] {
            let transcoder = factory.transcoder(asked);
            assert_eq!(
                transcoder.derive(&Codec::Opus { channels: 1 }, CodecFamily::Pcma),
                Some(Codec::Pcma)
            );
            let output = track(Codec::Pcmu, 8_000, 1, TrackLimits::default(), clock.now());
            let handle = transcoder
                .spawn(input.subscribe_frames(), &Codec::Pcmu, output)
                .unwrap();
            assert_eq!(handle.delay, delay, "the rest of a frame of {asked:?}");
        }
    }

    #[tokio::test]
    async fn spawn_refuses_what_it_cannot_produce() {
        let clock = Arc::new(FakeClock::from_system());
        let transcoder = ToG711::new(clock.clone(), FrameSize::DEFAULT);
        let input = track(Codec::G722, 8_000, 0, TrackLimits::default(), clock.now());
        let spawn = |from: &Codec, output: Arc<Track>| {
            transcoder
                .spawn(input.subscribe_frames(), from, output)
                .unwrap_err()
        };
        let pcmu = || track(Codec::Pcmu, 8_000, 1, TrackLimits::default(), clock.now());
        assert_eq!(
            spawn(&Codec::G722, pcmu()),
            TranscodeError::Unsupported {
                from: CodecFamily::G722,
                to: CodecFamily::Pcmu
            }
        );
        let opus_out = track(
            Codec::Opus { channels: 1 },
            48_000,
            1,
            TrackLimits::default(),
            clock.now(),
        );
        assert_eq!(
            spawn(&Codec::Pcmu, opus_out),
            TranscodeError::Unsupported {
                from: CodecFamily::Pcmu,
                to: CodecFamily::Opus
            }
        );
        let wrong_rate = track(Codec::Pcma, 16_000, 1, TrackLimits::default(), clock.now());
        assert_eq!(
            spawn(&Codec::Opus { channels: 1 }, wrong_rate),
            TranscodeError::Failed("output track is at 16000 Hz, not 8000 Hz".into())
        );
    }

    #[tokio::test]
    async fn rfc3551_4_5_14_an_opus_tone_comes_out_as_a_pcmu_tone() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::opus();
        assert_eq!(rig.handle.as_ref().unwrap().delay, Duration::ZERO);
        let input = opus_tone(50);
        let out = rig.feed(&input, 960, &[], ms(1_400)).await;
        assert_eq!(
            logs.count(Level::INFO, "transcoder started: uplink to g711"),
            1
        );
        // Exactly libopus's 8 kHz decode of each packet, μ-law encoded:
        // nothing dropped, nothing added, not even after the talker
        // stopped (RFC 7587 §4.1: 960 ticks of the 48 kHz clock are 160
        // samples).
        assert_eq!(out.len(), 50);
        assert_eq!(sent(&out), reference(&input, &[], false));
        let decoded = pcm(Law::Mu, &out);
        let steady = &decoded[1_600..];
        let crossings = steady.windows(2).filter(|w| w[0] <= 0 && w[1] > 0).count();
        let freq = crossings as f64 * 8_000.0 / steady.len() as f64;
        assert!((freq - 1_000.0).abs() < 10.0, "{freq:.1} Hz");
        assert!((rms(steady) - 0.354).abs() < 0.05, "{}", rms(steady));
        assert_eq!(logs.count(Level::DEBUG, STARTED), 1);
        assert_eq!(logs.count(Level::DEBUG, ENDED), 0);
        assert_eq!(logs.count(Level::DEBUG, BRIDGED), 0);
    }

    #[tokio::test]
    async fn rfc3551_4_1_each_frame_leaves_with_its_packet_on_continuous_timestamps_with_one_marker()
     {
        let mut rig = Rig::opus();
        let out = rig.feed(&opus_tone(10), 960, &[], ms(400)).await;
        assert_eq!(out.len(), 10);
        // No playout buffer: each frame leaves as its packet arrives.
        let times = arrivals(&rig, &out);
        for (k, at) in times.iter().enumerate() {
            assert_eq!(*at, ms(20 * k as u64), "{k}");
        }
        for (k, packet) in out.iter().enumerate() {
            assert_eq!(packet.payload.len(), 160);
            assert_eq!(packet.rtp.ts, 160 * k as u32, "RFC 3550 §5.1");
            assert_eq!(packet.rtp.seq, k as u16);
            assert_eq!(packet.rtp.pt, 0, "RFC 3551 Table 4");
            assert_eq!(packet.rtp.ssrc, SSRC);
            assert_eq!(
                packet.rtp.marker,
                k == 0,
                "RFC 3551 §4.1: first of the spurt"
            );
            assert!(packet.frame_start && !packet.keyframe_start);
        }
    }

    #[tokio::test]
    async fn frames_carry_the_capture_time_of_their_first_sample() {
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let mut frames = rig.output.subscribe_frames();
        rig.feed(&codes(3), 160, &[], ms(100)).await;
        for k in 0..3_u64 {
            let frame = frames.try_recv().unwrap().unwrap();
            assert_eq!(frame.wallclock, rig.start + ms(20 * k));
            assert_eq!(frame.ts.ticks(), 160 * k as i64);
            assert!(frame.keyframe && !frame.discontinuity);
        }
    }

    #[tokio::test]
    async fn a_40_ms_camera_frame_leaves_with_its_second_packet() {
        let mut rig = Rig::pcmu(FrameSize::new(320).unwrap());
        let input = codes(10);
        let out = rig.feed(&input, 160, &[], ms(600)).await;
        // Packet 2 i + 1 completes frame i at 40 i + 20 ms; packet 2 i
        // waited for it.
        let times = arrivals(&rig, &out);
        assert_eq!(times, (0..5).map(|i| ms(40 * i + 20)).collect::<Vec<_>>());
        assert_eq!(
            rig.wallclocks,
            (0..5).map(|i| ms(40 * i)).collect::<Vec<_>>()
        );
        assert!(out.iter().all(|p| p.payload.len() == 320));
        assert_eq!(timestamps(&out), [0, 320, 640, 960, 1_280]);
        // Passthrough: the codes reach the camera untouched, two packets
        // to a frame.
        assert_eq!(sent(&out), fed(&input));
    }

    #[tokio::test]
    async fn a_10_ms_camera_frame_splits_each_packet() {
        let mut rig = Rig::pcmu(FrameSize::new(80).unwrap());
        let input = codes(3);
        let out = rig.feed(&input, 160, &[], ms(100)).await;
        assert_eq!(out.len(), 6);
        assert!(out.iter().all(|p| p.payload.len() == 80));
        // Both halves leave as the packet arrives, 80 samples and 10 ms
        // of capture time apart.
        assert_eq!(
            arrivals(&rig, &out),
            [ms(0), ms(0), ms(20), ms(20), ms(40), ms(40)]
        );
        assert_eq!(timestamps(&out), [0, 80, 160, 240, 320, 400]);
        assert_eq!(
            rig.wallclocks,
            [ms(0), ms(10), ms(20), ms(30), ms(40), ms(50)]
        );
        assert_eq!(markers(&out), [true, false, false, false, false, false]);
        assert_eq!(sent(&out), fed(&input));
    }

    #[tokio::test]
    async fn a_frame_leaves_with_the_packet_that_completes_it() {
        // 30 ms frames from 20 ms packets.
        let mut rig = Rig::pcmu(FrameSize::new(240).unwrap());
        let input = codes(4);
        let out = rig.feed(&input, 160, &[], ms(200)).await;
        assert_eq!(arrivals(&rig, &out), [ms(20), ms(40)]);
        assert_eq!(timestamps(&out), [0, 240]);
        assert_eq!(rig.wallclocks, [ms(0), ms(30)]);
        assert_eq!(sent(&out), fed(&input[..3]));
    }

    /// Every 8-bit code five times over, in 20 ms packets: 8 packets of
    /// 160 samples, code `n % 256` at sample `n`.
    fn every_code() -> Vec<Bytes> {
        let codes: Vec<u8> = (0..=u8::MAX).cycle().take(8 * 160).collect();
        codes.chunks(160).map(Bytes::copy_from_slice).collect()
    }

    #[tokio::test]
    async fn g711_table_3_converts_pcmu_from_the_browser_for_a_pcma_camera() {
        let mut rig = Rig::start(&Codec::Pcmu, Law::A, FrameSize::DEFAULT);
        let input = every_code();
        let out = rig.feed(&input, 160, &[], ms(200)).await;
        assert_eq!(out.len(), 8, "a frame per packet, each as it arrives");
        assert!(out.iter().all(|p| p.rtp.pt == 8), "RFC 3551 Table 4");
        let (fed, sent) = (fed(&input), sent(&out));
        let expected: Vec<u8> = fed.iter().map(|c| Law::A.transcode(Law::Mu, *c)).collect();
        assert_eq!(sent, expected, "sample for sample");
        // Full scale (codes 0x00 and 0x80) and the two zeros (0x7f and
        // 0xff), at their places in the first packet; 0x20 is where Table 3
        // and the path through linear part.
        for (code, a) in [
            (0x00, 0x2a),
            (0x80, 0xaa),
            (0x7f, 0x55),
            (0xff, 0xd5),
            (0x20, 0x0a),
        ] {
            assert_eq!(sent[code], a, "μ {code:#04x}");
        }
    }

    #[tokio::test]
    async fn g711_table_4_converts_pcma_from_the_browser_for_a_pcmu_camera() {
        let mut rig = Rig::start(&Codec::Pcma, Law::Mu, FrameSize::DEFAULT);
        let input = every_code();
        let out = rig.feed(&input, 160, &[], ms(200)).await;
        assert_eq!(out.len(), 8, "a frame per packet, each as it arrives");
        assert!(out.iter().all(|p| p.rtp.pt == 0), "RFC 3551 Table 4");
        let (fed, sent) = (fed(&input), sent(&out));
        let expected: Vec<u8> = fed.iter().map(|c| Law::Mu.transcode(Law::A, *c)).collect();
        assert_eq!(sent, expected, "sample for sample");
        // Full scale (0x2a and 0xaa) and the quietest steps (0x55 and 0xd5,
        // which Table 4 takes to μ-law's second step, not to zero).
        for (code, mu) in [(0x2a, 0x00), (0xaa, 0x80), (0x55, 0x7e), (0xd5, 0xfe)] {
            assert_eq!(sent[code], mu, "A {code:#04x}");
        }
    }

    #[tokio::test]
    async fn rfc6716_4_4_a_lost_opus_packet_runs_through_the_decoder_and_is_not_sent() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::opus();
        let input = opus_tone(30);
        let out = rig.feed(&input, 960, &[15], ms(800)).await;
        assert_eq!(out.len(), 29, "nothing for the lost packet");
        // The decoder concealed the loss and the next packet decoded from
        // there; the concealed audio itself was not sent.
        let bridged = reference(&input, &[15], true);
        assert_eq!(sent(&out), bridged);
        assert_ne!(bridged, reference(&input, &[15], false));
        // RFC 3550 §5.1: the timestamps run on over the loss.
        assert_eq!(out[15].rtp.ts, 16 * 160);
        assert_eq!(out[15].rtp.seq, 15);
        assert!(!out[15].rtp.marker, "the spurt goes on");
        assert_eq!(arrivals(&rig, &out[15..16]), [ms(320)]);
        assert_eq!(logs.count(Level::DEBUG, BRIDGED), 1);
        assert_eq!(logs.count(Level::DEBUG, STARTED), 1);
    }

    #[tokio::test]
    async fn rfc3550_5_1_a_lost_g711_packet_advances_the_timestamps_without_audio() {
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(6);
        let out = rig.feed(&input, 160, &[3], ms(200)).await;
        assert_eq!(out.len(), 5);
        assert_eq!(&out[3].payload[..], &input[4][..]);
        assert_eq!(timestamps(&out), [0, 160, 320, 640, 800]);
        assert_eq!(rig.wallclocks[3], ms(80));
        assert_eq!(out[3].rtp.seq, 3);
        assert_eq!(markers(&out), [true, false, false, false, false]);
    }

    #[tokio::test]
    async fn a_gap_inside_a_frame_moves_the_next_frames_timestamp() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::new(320).unwrap());
        let input = codes(6);
        let out = rig.feed(&input, 160, &[1], ms(200)).await;
        // Packet 1 is lost with packet 0 in the frame: the frame closes
        // with packet 2 and the gap moves to its end.
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0].payload[..160], &input[0][..]);
        assert_eq!(&out[0].payload[160..], &input[2][..]);
        assert_eq!(&out[1].payload[..], &fed(&input[3..5])[..]);
        assert_eq!(timestamps(&out), [0, 480]);
        assert_eq!(rig.wallclocks, [ms(0), ms(60)]);
        assert_eq!(arrivals(&rig, &out), [ms(40), ms(80)]);
        assert_eq!(markers(&out), [true, false]);
        assert_eq!(logs.count(Level::DEBUG, BRIDGED), 1);
    }

    #[tokio::test]
    async fn a_late_or_duplicate_packet_is_dropped() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(6);
        let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
        // Packet 4 overtakes packet 3, which arrives at 65 ms, behind the
        // audio already taken: dropped. A duplicate is late too; the
        // second drop is counted, not logged.
        rig.publish(4 * 160, &input[4]);
        out.extend(rig.run_to(ms(65)).await);
        rig.publish(3 * 160, &input[3]);
        rig.publish(4 * 160, &input[4]);
        out.extend(rig.run_to(ms(80)).await);
        rig.publish(5 * 160, &input[5]);
        out.extend(rig.run_to(ms(200)).await);
        assert_eq!(out.len(), 5);
        assert_eq!(&out[3].payload[..], &input[4][..]);
        assert_eq!(&out[4].payload[..], &input[5][..]);
        assert_eq!(timestamps(&out), [0, 160, 320, 640, 800]);
        assert_eq!(logs.count(Level::DEBUG, LATE), 1);
    }

    #[tokio::test]
    async fn rfc3551_4_1_a_gap_over_100_ms_starts_a_new_spurt_with_the_marker() {
        for (gap, new_spurt) in [(800, false), (808, true)] {
            let (logs, _guard) = Logs::capture();
            let mut rig = Rig::pcmu(FrameSize::DEFAULT);
            let input = codes(4);
            let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
            rig.publish(3 * 160 + gap, &input[3]);
            out.extend(rig.run_to(ms(80)).await);
            assert_eq!(&out[3].payload[..], &input[3][..]);
            assert_eq!(out[3].rtp.marker, new_spurt, "{gap}");
            // A bridged gap moves the timestamps on; a new spurt continues
            // them by the time that passed, none here.
            let ts = if new_spurt { 480 } else { 480 + 800 };
            assert_eq!(out[3].rtp.ts, ts, "{gap}");
            assert_eq!(logs.count(Level::DEBUG, BRIDGED), usize::from(!new_spurt));
            if new_spurt {
                let ended = logs.fields(Level::DEBUG, ENDED);
                assert_eq!(ended.len(), 1);
                assert!(ended[0].contains(&"reason=\"input_gap\"".to_owned()));
            }
        }
    }

    #[tokio::test]
    async fn rfc3550_5_1_a_sender_back_after_100_ms_starts_a_new_spurt_on_the_clock() {
        for (pause, new_spurt) in [(100, false), (101, true), (800, true)] {
            let (logs, _guard) = Logs::capture();
            let mut rig = Rig::pcmu(FrameSize::DEFAULT);
            let input = codes(11);
            // Ten packets, their audio ending at 200 ms; the next one on
            // the sender's timeline, `pause` ms later.
            let mut out = rig.feed(&input[..10], 160, &[], ms(200 + pause)).await;
            assert_eq!(out.len(), 10);
            rig.publish(1_600, &input[10]);
            out.extend(rig.run_to(ms(200 + pause + 1)).await);
            let next = &out[10];
            assert_eq!(next.rtp.marker, new_spurt, "{pause} ms, RFC 3551 §4.1");
            let ts = if new_spurt {
                1_600 + 8 * pause as u32
            } else {
                1_600
            };
            assert_eq!(next.rtp.ts, ts, "{pause} ms");
            assert_eq!(next.rtp.seq, 10);
            assert_eq!(&next.payload[..], &input[10][..]);
            assert_eq!(
                logs.count(Level::DEBUG, STARTED),
                1 + usize::from(new_spurt)
            );
            let ended = logs.fields(Level::DEBUG, ENDED);
            assert_eq!(ended.len(), usize::from(new_spurt));
            if new_spurt {
                assert!(ended[0].contains(&"reason=\"sender_stopped\"".to_owned()));
                assert!(ended[0].contains(&format!("silence_ms={pause}")));
            }
        }
    }

    #[tokio::test]
    async fn a_new_spurt_drops_the_partial_frame() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::new(320).unwrap());
        let input = codes(5);
        let mut out = rig.feed(&input[..3], 160, &[], ms(500)).await;
        assert_eq!(out.len(), 1, "packet 2 waits for the rest of its frame");
        // The sender comes back at 500 ms: packet 2's half frame is
        // dropped, the new spurt's first frame is packets 3 and 4.
        rig.publish(3 * 160, &input[3]);
        out.extend(rig.run_to(ms(520)).await);
        rig.publish(4 * 160, &input[4]);
        out.extend(rig.run_to(ms(600)).await);
        assert_eq!(out.len(), 2);
        assert_eq!(&out[1].payload[..], &fed(&input[3..5])[..]);
        assert!(out[1].rtp.marker);
        // Packet 2's audio ended at 480 ticks, 60 ms; 440 ms passed.
        assert_eq!(out[1].rtp.ts, 480 + 440 * 8);
        let ended = logs.fields(Level::DEBUG, ENDED);
        assert_eq!(ended.len(), 1);
        assert!(ended[0].contains(&"dropped_samples=160".to_owned()));
        assert!(ended[0].contains(&"ts=480".to_owned()));
    }

    #[tokio::test]
    async fn a_new_spurt_starts_where_the_skipped_audio_ended() {
        // 60 ms frames: packet 0, packet 1 lost, packet 2 leave a frame of
        // 40 ms of audio spanning 60 ms when a jump in the input timeline
        // ends the spurt. The next one continues at 480, not at 320.
        let mut rig = Rig::pcmu(FrameSize::new(480).unwrap());
        let input = codes(3);
        let mut out = rig.feed(&input, 160, &[1], ms(60)).await;
        assert!(out.is_empty());
        for k in 0..3_u64 {
            rig.publish(100_000 + 160 * k as i64, &input[0]);
            out.extend(rig.run_to(ms(80 + 20 * k)).await);
        }
        assert_eq!(timestamps(&out), [480]);
        assert_eq!(markers(&out), [true]);
    }

    #[tokio::test]
    async fn a_new_input_epoch_resyncs() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(6);
        let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
        // A new timeline that starts behind the old one is not late, and
        // its audio continues the spurt.
        rig.input().start_epoch();
        rig.publish(0, &input[3]);
        out.extend(rig.run_to(ms(200)).await);
        assert_eq!(&out[3].payload[..], &input[3][..]);
        assert_eq!(timestamps(&out), [0, 160, 320, 480]);
        assert!(!out[3].rtp.marker);
        assert_eq!(
            logs.count(Level::DEBUG, "uplink: new input timeline; resyncing"),
            1
        );
    }

    #[tokio::test]
    async fn a_packet_that_does_not_decode_is_bridged() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::opus();
        let mut input = opus_tone(10);
        input[5] = Bytes::from_static(&[0xfb]);
        input[6] = Bytes::new();
        let out = rig.feed(&input, 960, &[], ms(400)).await;
        assert_eq!(out.len(), 8);
        assert_eq!(out[5].rtp.ts, 7 * 160);
        assert!(!out[5].rtp.marker);
        assert_eq!(
            logs.count(Level::WARN, "uplink: packet dropped; it does not decode"),
            1
        );
        assert_eq!(logs.count(Level::DEBUG, BRIDGED), 1);
        assert_eq!(logs.count(Level::DEBUG, LATE), 0);
    }

    #[tokio::test]
    async fn a_lagging_subscription_loses_the_skipped_packets() {
        let (logs, _guard) = Logs::capture();
        let limits = TrackLimits {
            frame_capacity: 2,
            ..TrackLimits::default()
        };
        let mut rig = Rig::with_limits(&Codec::Pcmu, Law::Mu, FrameSize::DEFAULT, limits);
        let input = codes(5);
        for (k, payload) in input.iter().enumerate() {
            rig.publish(160 * k as i64, payload);
        }
        let mut out = rig.run_to(ms(40)).await;
        // The first three were skipped; the spurt starts on the fourth.
        assert_eq!(&out[0].payload[..], &input[3][..]);
        assert_eq!(&out[1].payload[..], &input[4][..]);
        // A second lag is counted, not logged; the skipped audio is a
        // gap the timestamps run over.
        for (k, payload) in input.iter().enumerate() {
            rig.publish(160 * (k as i64 + 5), payload);
        }
        out.extend(rig.run_to(ms(60)).await);
        assert_eq!(&out[2].payload[..], &input[3][..]);
        assert_eq!(timestamps(&out), [0, 160, 800, 960]);
        assert_eq!(
            logs.count(
                Level::WARN,
                "transcoder lagged behind the uplink; its packets are lost"
            ),
            1
        );
    }

    #[tokio::test]
    async fn dropping_the_handle_or_the_input_stops_the_task() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::new(320).unwrap());
        rig.publish(0, &codes(1)[0]);
        settle().await;
        rig.handle = None;
        stopped(&rig.output, 1).await;
        // Holding the input, the task stopped on the token alone.
        assert!(rig.input.is_some());
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        rig.input = None;
        stopped(&rig.output, 2).await;
        let reasons = logs.fields(Level::INFO, "transcoder stopped");
        assert_eq!(reasons.len(), 2);
        // The half frame the talker left is dropped with it.
        for (fields, reason, dropped) in [
            (&reasons[0], "cancelled", 160),
            (&reasons[1], "input_closed", 0),
        ] {
            assert!(
                fields.contains(&format!("reason=\"{reason}\"")),
                "{fields:?}"
            );
            assert!(
                fields.contains(&format!("dropped_samples={dropped}")),
                "{fields:?}"
            );
        }
    }
}

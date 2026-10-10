//! The talk-back transcoder: a session's uplink audio in, G.711 frames of
//! the camera's frame size out, paced at the media rate behind a one-frame
//! playout buffer.
//!
//! It is the reverse instance of the [`Transcoder`] contract, not a second
//! abstraction: the input is a frame subscription of the uplink track (one
//! RTP payload per frame, as the session received it), the output a track
//! of the camera's G.711 law at 8 kHz, whose packets the backchannel
//! sends.
//!
//! The chain is [`Decoder`] (Opus at 8 kHz: libopus band-limits, so no
//! resampler follows) or a G.711 decode → [`Law::encode`] in the camera's
//! law → a FIFO of codes (one byte per sample) → one frame per frame
//! duration. When the browser already sends the camera's law the codes
//! pass through untouched; only the framing and pacing change. Packets are
//! decoded as they arrive, nothing waits for a full frame but the frame
//! itself, and:
//!
//! - **Playout.** A talk spurt's first frame leaves one frame duration
//!   after its first packet arrived (the playout buffer, which absorbs that
//!   much network jitter), every later one a frame duration after the one
//!   before, with timestamps a frame's samples apart: several cameras
//!   (Reolink, Dahua) crackle or mute on irregular pacing.
//! - **Loss.** A frame that comes due without enough audio is completed by
//!   concealment (Opus PLC, silence for G.711 input) instead of waited for;
//!   a packet arriving after its audio was concealed is dropped. A gap in
//!   the input timestamps is concealed when the next packet arrives.
//! - **Talk spurts.** After [`MAX_CONCEALMENT`] concealed in a row the
//!   spurt ends and nothing is sent until the next packet, which starts a
//!   new spurt: marker set, timestamp advanced by the time that passed.
//! - **Backlog.** More than a frame of audio still queued after a frame
//!   left means the input runs ahead (a fast sender clock, or a spurt
//!   anchored on a late packet): the oldest audio is dropped down to half a
//!   frame, so a sample waits at most two frame durations.
//!
//! Implements ITU-T G.711 at the RTP clock of RFC 3551 §4.5.14 (8 kHz,
//! static payload types of Table 4), with the marker on the first packet of
//! a talkspurt (RFC 3551 §4.1) and timestamps that advance with the
//! sampling clock across silence (RFC 3550 §5.1); Opus input at the 48 kHz
//! clock of RFC 7587 §4.1, concealed per RFC 6716 §4.4.

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
use lotse_core::transcode::{TrackHandle, TranscodeError, Transcoder};
use tokio_util::sync::CancellationToken;

use super::rtp_ts;
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

/// The most audio concealed in a row before a talk spurt ends: 100 ms. A
/// short network stall is bridged without a new spurt; a sender that
/// stopped (a muted or replaced track) is not imitated for longer, and its
/// next packet starts a new spurt with the marker set.
pub const MAX_CONCEALMENT: Duration = Duration::from_millis(100);

/// [`MAX_CONCEALMENT`] in 8 kHz samples.
const MAX_CONCEALMENT_SAMPLES: usize = 800;

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

    /// The largest frame: 120 ms, the most one Opus concealment call
    /// produces (RFC 6716 §3.2.5), and well inside one packet at 1 byte
    /// per sample.
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
    /// Times the playout and each packet's release.
    clock: Arc<dyn Clock>,
    /// The camera's frame size.
    frame: FrameSize,
}

impl ToG711 {
    /// A transcoder producing frames of `frame`, reading time from `clock`.
    pub fn new(clock: Arc<dyn Clock>, frame: FrameSize) -> Self {
        Self { clock, frame }
    }

    /// The delay the chain adds for frames of `frame`: the playout buffer,
    /// one frame. A packet's first sample leaves that long after the
    /// packet arrived; decoding at 8 kHz adds no filter delay.
    pub fn delay(frame: FrameSize) -> Duration {
        frame.duration()
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
            None => Input::Opus(
                Decoder::new(SAMPLE_RATE).map_err(|err| TranscodeError::Failed(err.to_string()))?,
            ),
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

/// The talk spurt being played out.
#[derive(Debug, Clone, Copy)]
struct Spurt {
    /// When the next frame is due.
    due: Instant,
    /// The next frame's 8 kHz timestamp, unwrapped.
    ts: i64,
    /// The capture time of the next frame's first sample.
    wallclock: Instant,
    /// Samples concealed in a row, up to the last frame sent.
    concealed: usize,
    /// The next frame is the spurt's first.
    first: bool,
}

/// One running chain: the input decoder, the FIFO and the playout.
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
    /// Times the playout and each packet's release.
    clock: Arc<dyn Clock>,
    /// Encoded samples not yet sent, oldest first.
    fifo: VecDeque<u8>,
    /// The input timestamp the next packet should carry; `None` until a
    /// packet sets it, so the first packet after a reset is taken as is.
    expected: Option<i64>,
    /// The input epoch of the last packet.
    epoch: Option<u32>,
    /// The talk spurt being played out; `None` between spurts.
    spurt: Option<Spurt>,
    /// Where the last spurt left off: when its next frame would have been
    /// due, and that frame's timestamp. The next spurt's timestamps
    /// continue from there by the time that passed.
    resume: Option<(Instant, i64)>,
    /// The next packet's sequence number.
    seq: u16,
    /// Packets that arrived after their audio was concealed.
    late: Throttle,
    /// Input timeline jumps.
    jumps: Throttle,
    /// Packets that failed to decode.
    failures: Throttle,
    /// Backlogs dropped.
    backlogs: Throttle,
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
            resume: None,
            seq: 0,
            late: Throttle::default(),
            jumps: Throttle::default(),
            failures: Throttle::default(),
            backlogs: Throttle::default(),
            lags: Throttle::default(),
        }
    }

    /// Samples per frame.
    fn frame_samples(&self) -> usize {
        usize::from(self.frame.samples())
    }

    /// One uplink packet: starts a spurt if none runs, conceals a gap
    /// before it, drops it when its audio was already concealed, and
    /// queues its audio.
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
        if self.spurt.is_none() {
            self.start(now, frame.wallclock);
        }
        if let Some(expected) = self.expected
            && !self.fill_gap(now, ts, expected)
        {
            return;
        }
        match self.decode(&frame.payload) {
            Ok(samples) => {
                let ticks = i64::try_from(samples)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(self.input.ticks_per_sample());
                self.expected = Some(ts.saturating_add(ticks));
            }
            Err(err) => {
                if let Some(count) = self.failures.hit(now) {
                    tracing::warn!(
                        track = %self.output.id(),
                        error = %err,
                        ts,
                        count,
                        "uplink: packet dropped; its audio is concealed"
                    );
                }
            }
        }
    }

    /// Handles a packet at `ts` against the `expected` timestamp: `false`
    /// when it is late and dropped. A gap up to [`MAX_CONCEALMENT`] is
    /// concealed; a longer one is a jump in the sender's timeline, taken
    /// as is.
    fn fill_gap(&mut self, now: Instant, ts: i64, expected: i64) -> bool {
        let ahead = ts.saturating_sub(expected);
        if ahead < 0 {
            if let Some(count) = self.late.hit(now) {
                tracing::debug!(
                    track = %self.output.id(),
                    late_ticks = ahead.saturating_neg(),
                    ts,
                    count,
                    "uplink: late packet dropped; its audio was concealed"
                );
            }
            return false;
        }
        let gap = usize::try_from(
            ahead
                .checked_div(self.input.ticks_per_sample())
                .unwrap_or(0),
        )
        .unwrap_or(usize::MAX);
        if gap > MAX_CONCEALMENT_SAMPLES {
            if let Some(count) = self.jumps.hit(now) {
                tracing::debug!(
                    track = %self.output.id(),
                    gap_samples = gap,
                    ts,
                    count,
                    "uplink: input timeline jumped; resyncing"
                );
            }
        } else {
            // A packet on time conceals nothing.
            self.conceal(gap);
        }
        true
    }

    /// Starts a talk spurt on a packet that arrived at `now`, captured at
    /// `wallclock`: its first frame is due one frame later, its timestamp
    /// continues the last spurt's by the time that passed.
    fn start(&mut self, now: Instant, wallclock: Instant) {
        let due = now.checked_add(self.frame.duration()).unwrap_or(now);
        let ts = self.resume.map_or(0, |(at, ts)| {
            let silence = due.saturating_duration_since(at).as_micros() / 125;
            ts.saturating_add(i64::try_from(silence).unwrap_or(i64::MAX))
        });
        tracing::debug!(track = %self.output.id(), ts, "uplink: talk spurt started");
        self.fifo.clear();
        self.expected = None;
        self.spurt = Some(Spurt {
            due,
            ts,
            wallclock,
            concealed: 0,
            first: true,
        });
    }

    /// Decodes one payload into the FIFO; the samples it carried.
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

    /// Conceals at least `samples` into the FIFO and moves the expected
    /// input timestamp past them; the samples added. Opus conceals in
    /// whole 2.5 ms steps; should libopus refuse, silence fills in.
    fn conceal(&mut self, samples: usize) -> usize {
        let silence = self.law.silence();
        let law = self.law;
        let (span, pcm) = match &mut self.input {
            Input::Opus(decoder) => {
                let span = samples.div_ceil(CONCEAL_STEP).saturating_mul(CONCEAL_STEP);
                (span, decoder.conceal(span).unwrap_or_default())
            }
            Input::G711(_) => (samples, &[][..]),
        };
        self.fifo.extend(
            pcm.iter()
                .map(|s| law.encode(*s))
                .chain(std::iter::repeat(silence))
                .take(span),
        );
        let ticks = i64::try_from(span)
            .unwrap_or(i64::MAX)
            .saturating_mul(self.input.ticks_per_sample());
        self.expected = self.expected.map(|ts| ts.saturating_add(ticks));
        span
    }

    /// Sends every frame due at `now`, concealing what is missing, and
    /// ends the spurt once concealment runs past [`MAX_CONCEALMENT`].
    /// Returns when the next frame is due, `None` between spurts: the task
    /// sleeps until then, so a release that sent nothing cannot make it
    /// spin.
    fn release(&mut self, now: Instant) -> Option<Instant> {
        let need = self.frame_samples();
        while let Some(mut spurt) = self.spurt.filter(|spurt| spurt.due <= now) {
            let deficit = need.saturating_sub(self.fifo.len());
            if deficit == 0 {
                spurt.concealed = 0;
            } else if spurt.concealed.saturating_add(deficit) > MAX_CONCEALMENT_SAMPLES {
                self.end(&spurt);
                return None;
            } else {
                spurt.concealed = spurt.concealed.saturating_add(self.conceal(deficit));
            }
            let payload: Bytes = self.fifo.drain(..need.min(self.fifo.len())).collect();
            self.publish(&spurt, payload, now);
            self.trim(now);
            spurt.due = spurt
                .due
                .checked_add(self.frame.duration())
                .unwrap_or(spurt.due);
            spurt.wallclock = spurt
                .wallclock
                .checked_add(self.frame.duration())
                .unwrap_or(spurt.wallclock);
            spurt.ts = spurt.ts.saturating_add(i64::from(self.frame.samples()));
            spurt.first = false;
            self.spurt = Some(spurt);
        }
        self.spurt.map(|spurt| spurt.due)
    }

    /// Ends `spurt`: the sender stopped. The rest of the FIFO is dropped
    /// and the next packet starts a new spurt.
    fn end(&mut self, spurt: &Spurt) {
        tracing::debug!(
            track = %self.output.id(),
            ts = spurt.ts,
            concealed_ms = spurt.concealed / 8,
            reason = "input_stopped",
            "uplink: talk spurt ended"
        );
        self.resume = Some((spurt.due, spurt.ts));
        self.spurt = None;
        self.fifo.clear();
        self.expected = None;
    }

    /// Drops the oldest audio down to half a frame when more than a frame
    /// stays queued after a frame left.
    fn trim(&mut self, now: Instant) {
        let need = self.frame_samples();
        if self.fifo.len() <= need {
            return;
        }
        let dropped = self.fifo.len().saturating_sub(need / 2);
        self.fifo.drain(..dropped);
        if let Some(count) = self.backlogs.hit(now) {
            tracing::debug!(
                track = %self.output.id(),
                dropped_samples = dropped,
                count,
                "uplink: input ahead of playout; oldest audio dropped"
            );
        }
    }

    /// The input subscription skipped `skipped` packets: their audio is
    /// concealed as it comes due, and the next packet is taken as is.
    fn lagged(&mut self, skipped: u64) {
        if let Some(count) = self.lags.hit(self.clock.now()) {
            tracing::warn!(
                track = %self.output.id(),
                skipped,
                count,
                "transcoder lagged behind the uplink; resyncing"
            );
        }
        self.expected = None;
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

/// The transcoder task: packets in and paced frames out until `stop` is
/// cancelled or the input track is gone; what is queued then is dropped
/// with the talker.
///
/// Each turn sends what is due, then waits for a packet, the stop token or
/// the next frame's release.
async fn run(mut chain: Chain, mut input: FrameSubscription, stop: CancellationToken) {
    let reason = loop {
        let now = chain.clock.now();
        let next = chain
            .release(now)
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
                Ok(frame) => chain.packet(&frame),
                Err(SubscriptionError::Lagged(skipped)) => chain.lagged(skipped),
                Err(SubscriptionError::Closed) => break "input_closed",
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

    use lotse_core::clock::FakeClock;
    use lotse_core::codec::Kind;
    use lotse_core::track::{PacketSubscription, TrackId, TrackLimits};
    use tracing::Level;

    use super::super::tests::Logs;
    use super::*;
    use crate::opus::{Encoder, FRAME_SAMPLES as OPUS_FRAME};

    const STARTED: &str = "uplink: talk spurt started";
    const ENDED: &str = "uplink: talk spurt ended";
    const LATE: &str = "uplink: late packet dropped; its audio was concealed";

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
        /// the task release what comes due at each, and returns what it
        /// released.
        async fn run_to(&mut self, at: Duration) -> Vec<Arc<MediaPacket>> {
            let mut out = Vec::new();
            loop {
                settle().await;
                while let Some(packet) = self.packets.try_recv().unwrap() {
                    let frame = self.frames.try_recv().unwrap().expect("its frame first");
                    assert_eq!(rtp_ts(frame.ts.ticks()), packet.rtp.ts);
                    assert_eq!(&frame.payload[..], &packet.payload[..]);
                    out.push(packet);
                }
                let left = (self.start + at).saturating_duration_since(self.clock.now());
                if left.is_zero() {
                    return out;
                }
                self.clock.advance(left.min(ms(1)));
            }
        }

        /// Publishes `payloads` in real time, one every 20 ms from `from`
        /// after the start, `ticks` apart from `ts0`, skipping the indices
        /// in `lost`; then runs to `until`. Returns what was released.
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

    /// `count` 20 ms G.711 packets of distinct codes: packet `k` holds
    /// `k`, `k + 1`, ... so every sample is traceable.
    fn codes(count: usize) -> Vec<Bytes> {
        (0..count)
            .map(|k| (0..160).map(|n| ((k * 7 + n) % 251) as u8).collect())
            .collect()
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

    #[test]
    fn rfc3551_4_5_a_frame_is_10_to_120_ms_20_by_default() {
        assert_eq!(FrameSize::DEFAULT.samples(), 160);
        assert_eq!(FrameSize::DEFAULT.duration(), ms(20));
        assert_eq!(FrameSize::new(80).unwrap().duration(), ms(10));
        assert_eq!(FrameSize::new(960).unwrap().duration(), ms(120));
        assert_eq!(FrameSize::new(79), None);
        assert_eq!(FrameSize::new(961), None);
        assert_eq!(ToG711::delay(FrameSize::new(320).unwrap()), ms(40));
        assert_eq!(
            MAX_CONCEALMENT.as_millis() * 8,
            MAX_CONCEALMENT_SAMPLES as u128
        );
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
        assert_eq!(rig.handle.as_ref().unwrap().delay, ms(20));
        let input = opus_tone(50);
        let out = rig.feed(&input, 960, &[], ms(1_400)).await;
        assert_eq!(
            logs.count(Level::INFO, "transcoder started: uplink to g711"),
            1
        );
        // Exactly libopus's 8 kHz decode of each packet, μ-law encoded:
        // nothing concealed, nothing dropped (RFC 7587 §4.1: 960 ticks of
        // the 48 kHz clock are 160 samples).
        let mut reference = Decoder::new(8_000).unwrap();
        let expected: Vec<u8> = input
            .iter()
            .flat_map(|p| {
                reference
                    .decode(p)
                    .unwrap()
                    .iter()
                    .map(|s| Law::Mu.encode(*s))
                    .collect::<Vec<_>>()
            })
            .collect();
        let sent: Vec<u8> = out[..50].iter().flat_map(|p| p.payload.to_vec()).collect();
        assert_eq!(sent, expected);
        // 50 packets of audio, then 100 ms of concealment ends the spurt.
        assert_eq!(out.len(), 55);
        let decoded = pcm(Law::Mu, &out[..50]);
        let steady = &decoded[1_600..];
        let crossings = steady.windows(2).filter(|w| w[0] <= 0 && w[1] > 0).count();
        let freq = crossings as f64 * 8_000.0 / steady.len() as f64;
        assert!((freq - 1_000.0).abs() < 10.0, "{freq:.1} Hz");
        assert!((rms(steady) - 0.354).abs() < 0.05, "{}", rms(steady));
        assert_eq!(logs.count(Level::DEBUG, ENDED), 1);
    }

    #[tokio::test]
    async fn rfc3551_4_1_paced_frames_with_continuous_timestamps_and_one_marker() {
        let mut rig = Rig::opus();
        let out = rig.feed(&opus_tone(10), 960, &[], ms(400)).await;
        assert_eq!(out.len(), 15);
        // The one-frame playout buffer: the first frame leaves 20 ms after
        // the first packet arrived, every later one 20 ms after the last.
        let times = arrivals(&rig, &out);
        for (k, at) in times.iter().enumerate() {
            assert_eq!(*at, ms(20 + 20 * k as u64), "{k}");
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
    async fn a_40_ms_camera_frame_takes_two_packets() {
        let mut rig = Rig::pcmu(FrameSize::new(320).unwrap());
        let input = codes(10);
        let out = rig.feed(&input, 160, &[], ms(600)).await;
        let times = arrivals(&rig, &out);
        assert_eq!(times[0], ms(40));
        assert!(
            times
                .windows(2)
                .all(|w| w[1].checked_sub(w[0]) == Some(ms(40))),
            "{times:?}"
        );
        assert!(out.iter().all(|p| p.payload.len() == 320));
        assert!(out.windows(2).all(|w| w[1].rtp.ts - w[0].rtp.ts == 320));
        // Passthrough: the codes reach the camera untouched, two packets
        // to a frame.
        let sent: Vec<u8> = out[..5].iter().flat_map(|p| p.payload.to_vec()).collect();
        let fed: Vec<u8> = input.iter().flat_map(|p| p.to_vec()).collect();
        assert_eq!(sent, fed);
    }

    #[tokio::test]
    async fn pcmu_is_converted_for_a_pcma_camera() {
        let mut rig = Rig::start(&Codec::Pcmu, Law::A, FrameSize::DEFAULT);
        let input = codes(3);
        let out = rig.feed(&input, 160, &[], ms(100)).await;
        for (packet, fed) in out.iter().zip(&input) {
            assert_eq!(packet.rtp.pt, 8, "RFC 3551 Table 4");
            let expected: Vec<u8> = fed.iter().map(|c| Law::A.transcode(Law::Mu, *c)).collect();
            assert_eq!(&packet.payload[..], &expected[..]);
        }
    }

    #[tokio::test]
    async fn rfc6716_4_4_a_lost_packet_is_concealed_in_place() {
        let mut rig = Rig::opus();
        let out = rig.feed(&opus_tone(30), 960, &[15], ms(800)).await;
        assert_eq!(out.len(), 35, "the same frames as without the loss");
        assert!(out.windows(2).all(|w| w[1].rtp.ts - w[0].rtp.ts == 160));
        // PLC continues the tone through the lost 20 ms.
        let concealed = pcm(Law::Mu, &out[15..16]);
        assert!(rms(&concealed) > 0.1, "{}", rms(&concealed));
    }

    #[tokio::test]
    async fn lost_g711_is_silence() {
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(6);
        let out = rig.feed(&input, 160, &[3], ms(200)).await;
        assert!(out[3].payload.iter().all(|c| *c == 0xff));
        assert_eq!(&out[4].payload[..], &input[4][..]);
    }

    #[tokio::test]
    async fn jitter_within_the_playout_buffer_changes_nothing() {
        let input = opus_tone(10);
        let mut steady = Rig::opus();
        let reference = steady.feed(&input, 960, &[], ms(300)).await;
        let mut rig = Rig::opus();
        let mut out = rig.feed(&input[..4], 960, &[], ms(80 + 15)).await;
        rig.publish(4 * 960, &input[4]);
        for (k, packet) in input.iter().enumerate().skip(5) {
            out.extend(rig.run_to(ms(20 * k as u64)).await);
            rig.publish(k as i64 * 960, packet);
        }
        out.extend(rig.run_to(ms(300)).await);
        let payloads =
            |p: &[Arc<MediaPacket>]| p.iter().map(|p| p.payload.clone()).collect::<Vec<_>>();
        assert_eq!(payloads(&out), payloads(&reference));
    }

    #[tokio::test]
    async fn a_packet_after_its_audio_was_concealed_is_dropped() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(8);
        let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
        // Packet 3 is due by 80 ms, when its frame leaves, and arrives at
        // 85, after packet 4 came on time: its audio was concealed, so it
        // is dropped.
        out.extend(rig.run_to(ms(80)).await);
        rig.publish(4 * 160, &input[4]);
        out.extend(rig.run_to(ms(85)).await);
        rig.publish(3 * 160, &input[3]);
        // A duplicate is late too; the second drop is counted, not logged.
        rig.publish(3 * 160, &input[3]);
        out.extend(rig.run_to(ms(200)).await);
        assert!(out[3].payload.iter().all(|c| *c == 0xff));
        assert_eq!(&out[4].payload[..], &input[4][..]);
        assert_eq!(logs.count(Level::DEBUG, LATE), 1);
        assert!(out.windows(2).all(|w| w[1].rtp.ts - w[0].rtp.ts == 160));
    }

    #[tokio::test]
    async fn a_gap_in_the_timestamps_is_concealed_when_the_next_packet_arrives() {
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(8);
        let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
        // Packet 3 never comes; packet 4 arrives in packet 3's slot.
        rig.publish(4 * 160, &input[4]);
        out.extend(rig.run_to(ms(200)).await);
        assert!(out[3].payload.iter().all(|c| *c == 0xff));
        assert_eq!(&out[4].payload[..], &input[4][..]);
    }

    #[tokio::test]
    async fn rfc3550_5_1_a_new_spurt_continues_the_clock_with_the_marker() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(11);
        let mut out = rig.feed(&input[..10], 160, &[], ms(1_000)).await;
        // 10 frames, 100 ms of concealment, then silence until a packet.
        assert_eq!(out.len(), 15);
        assert!(
            out[10..]
                .iter()
                .all(|p| p.payload.iter().all(|c| *c == 0xff))
        );
        assert_eq!(logs.count(Level::DEBUG, ENDED), 1);
        rig.publish(123_456, &input[10]);
        out.extend(rig.run_to(ms(1_100)).await);
        let next = &out[15];
        assert_eq!(arrivals(&rig, &out[15..16]), [ms(1_020)]);
        assert!(next.rtp.marker, "RFC 3551 §4.1");
        // Due at 1020 ms, 1000 ms after the first frame: 8000 ticks on.
        assert_eq!(next.rtp.ts, 8_000);
        assert_eq!(next.rtp.seq, 15);
        assert_eq!(&next.payload[..], &input[10][..]);
        assert_eq!(logs.count(Level::DEBUG, STARTED), 2);
    }

    #[tokio::test]
    async fn a_jump_in_the_input_timeline_is_taken_as_is() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(6);
        let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
        rig.publish(3 * 160 + 100_000, &input[3]);
        out.extend(rig.run_to(ms(80)).await);
        rig.publish(4 * 160 + 200_000, &input[4]);
        out.extend(rig.run_to(ms(200)).await);
        assert_eq!(&out[3].payload[..], &input[3][..]);
        assert_eq!(&out[4].payload[..], &input[4][..]);
        assert_eq!(
            logs.count(Level::DEBUG, "uplink: input timeline jumped; resyncing"),
            1
        );
    }

    #[tokio::test]
    async fn a_gap_of_100_ms_is_concealed_a_longer_one_is_a_jump() {
        for (gap, concealed) in [(800, true), (808, false)] {
            let mut rig = Rig::pcmu(FrameSize::DEFAULT);
            let input = codes(4);
            let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
            rig.publish(3 * 160 + gap, &input[3]);
            out.extend(rig.run_to(ms(80)).await);
            let silent = out[3].payload.iter().all(|c| *c == 0xff);
            assert_eq!(silent, concealed, "{gap}");
        }
    }

    #[tokio::test]
    async fn a_new_input_epoch_resyncs() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(6);
        let mut out = rig.feed(&input[..3], 160, &[], ms(60)).await;
        // A new timeline that starts behind the old one is not late.
        rig.input().start_epoch();
        rig.publish(0, &input[3]);
        out.extend(rig.run_to(ms(200)).await);
        assert_eq!(&out[3].payload[..], &input[3][..]);
        assert_eq!(
            logs.count(Level::DEBUG, "uplink: new input timeline; resyncing"),
            1
        );
    }

    #[tokio::test]
    async fn a_backlog_is_dropped_to_half_a_frame() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
        let input = codes(3);
        // Three packets at once: two frames more than the playout holds.
        for (k, payload) in input.iter().enumerate() {
            rig.publish(160 * k as i64, payload);
        }
        let out = rig.run_to(ms(40)).await;
        assert_eq!(&out[0].payload[..], &input[0][..]);
        // The oldest 240 samples went; the newest 80 lead the next frame.
        assert_eq!(&out[1].payload[..80], &input[2][80..]);
        // Another burst drops again, counted rather than logged.
        for (k, payload) in input.iter().enumerate() {
            rig.publish(160 * (k as i64 + 3), payload);
        }
        rig.run_to(ms(60)).await;
        let dropped = logs.fields(
            Level::DEBUG,
            "uplink: input ahead of playout; oldest audio dropped",
        );
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0][1], "dropped_samples=240");
    }

    #[tokio::test]
    async fn a_packet_that_does_not_decode_is_concealed() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::opus();
        let mut input = opus_tone(10);
        input[5] = Bytes::from_static(&[0xfb]);
        input[6] = Bytes::new();
        let out = rig.feed(&input, 960, &[], ms(400)).await;
        assert_eq!(out.len(), 15);
        assert!(out.windows(2).all(|w| w[1].rtp.ts - w[0].rtp.ts == 160));
        assert_eq!(
            logs.count(
                Level::WARN,
                "uplink: packet dropped; its audio is concealed"
            ),
            1
        );
        assert_eq!(logs.count(Level::DEBUG, LATE), 0);
    }

    #[tokio::test]
    async fn a_lagging_subscription_resyncs() {
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
        let out = rig.run_to(ms(40)).await;
        // The first three were skipped; the spurt starts on the fourth.
        assert_eq!(&out[0].payload[..], &input[3][..]);
        assert_eq!(&out[1].payload[..], &input[4][..]);
        // A second lag is counted, not logged.
        for (k, payload) in input.iter().enumerate() {
            rig.publish(160 * (k as i64 + 5), payload);
        }
        rig.run_to(ms(60)).await;
        assert_eq!(
            logs.count(
                Level::WARN,
                "transcoder lagged behind the uplink; resyncing"
            ),
            1
        );
    }

    #[tokio::test]
    async fn dropping_the_handle_or_the_input_stops_the_task() {
        let (logs, _guard) = Logs::capture();
        let mut rig = Rig::pcmu(FrameSize::DEFAULT);
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
        assert!(
            reasons[0].contains(&"reason=\"cancelled\"".to_owned()),
            "{reasons:?}"
        );
        assert!(
            reasons[1].contains(&"reason=\"input_closed\"".to_owned()),
            "{reasons:?}"
        );
    }
}

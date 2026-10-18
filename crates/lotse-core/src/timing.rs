//! A track's timing habits as its live path shows them, for `stream/get`:
//! how far apart its keyframes are, whether its frames come out of
//! presentation order (B-frames), whether its source ends a video frame
//! with the RTP marker bit, and how late its latest frame arrived.
//!
//! Every value is observed, never declared: each is `None` until the
//! packets have shown it. A new epoch (a reconnect, a timestamp reset, a
//! switch of source) starts every observation over, since the camera and
//! its habits may be other ones.
//!
//! Implements RFC 3550 §5.1 (the timestamp and the marker bit), RFC 6184
//! §5.1 and RFC 7798 §4.1 (the marker bit ends an access unit), and
//! ISO/IEC 14496-10 §C.4 / ITU-T H.265 §C.5 (frames with reordering leave
//! the decoder in another order than they enter it, so their timestamps
//! step back in decode order).

use std::time::Duration;

use crate::media::{MediaPacket, MediaTime, TimestampUnwrapper};

/// What a track's live path has shown of its timing, in the current
/// epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrackTiming {
    /// The media time between the latest two keyframes of a video track;
    /// `None` until two were seen, and on audio.
    pub keyframe_interval: Option<Duration>,
    /// Whether a video track's frames are reordered: `Some(true)` once a
    /// frame's timestamp stepped back behind an earlier one's (decode order
    /// is not presentation order), `Some(false)` once a whole keyframe
    /// interval passed without that. `None` before, and on audio.
    pub b_frames: Option<bool>,
    /// Whether a video track's source ends each frame with the marker bit:
    /// `Some(false)` once a frame ended without it, `Some(true)` while
    /// every frame did. Only a frame whose last packet arrived counts, so a
    /// lost packet never decides it. `None` until a frame ended, and on
    /// audio, whose marker bit means something else (RFC 3551 §4.1).
    pub marker_bit: Option<bool>,
    /// The ingest lateness of the latest frame ([`crate::lateness`]): how
    /// much later than the track's best of the last 5 to 10 s it arrived.
    /// `None` until a frame arrived.
    pub packet_latency: Option<Duration>,
}

/// One track's timing meter. Fed every live packet in order by the track;
/// reset when the track starts an epoch.
#[derive(Debug, Clone)]
pub(crate) struct TimingMeter {
    /// The track's declared ticks per second.
    clock_rate: u32,
    /// Unwraps the frames' RTP timestamps.
    unwrapper: TimestampUnwrapper,
    /// The latest packet's sequence number and marker bit.
    last: Option<(u16, bool)>,
    /// The highest unwrapped frame timestamp.
    max_ts: Option<i64>,
    /// The unwrapped timestamp of the latest keyframe.
    keyframe_ts: Option<i64>,
    /// What was seen.
    timing: TrackTiming,
}

impl TimingMeter {
    /// A meter for a track at `clock_rate` ticks per second.
    pub(crate) const fn new(clock_rate: u32) -> Self {
        Self {
            clock_rate,
            unwrapper: TimestampUnwrapper::new(),
            last: None,
            max_ts: None,
            keyframe_ts: None,
            timing: TrackTiming {
                keyframe_interval: None,
                b_frames: None,
                marker_bit: None,
                packet_latency: None,
            },
        }
    }

    /// Forgets everything, for a new epoch.
    pub(crate) fn reset(&mut self) {
        *self = Self::new(self.clock_rate);
    }

    /// What was seen so far.
    pub(crate) const fn timing(&self) -> TrackTiming {
        self.timing
    }

    /// Observes `packet`, stamped with its frame's lateness, of a video
    /// track if `video`.
    pub(crate) fn packet(&mut self, packet: &MediaPacket, video: bool) {
        if packet.frame_start {
            self.timing.packet_latency = Some(packet.lateness);
        }
        if !video {
            return;
        }
        if packet.frame_start {
            // The packet before this one ended the previous frame, if it
            // is the one right before it: a lost packet decides nothing.
            if let Some((seq, marker)) = self.last
                && seq.wrapping_add(1) == packet.rtp.seq
            {
                let every = self.timing.marker_bit.unwrap_or(true);
                self.timing.marker_bit = Some(every && marker);
            }
            self.frame(packet.rtp.ts, packet.keyframe_start);
        }
        self.last = Some((packet.rtp.seq, packet.rtp.marker));
    }

    /// Observes the start of a video frame at `rtp_ts`, a keyframe if
    /// `keyframe`.
    fn frame(&mut self, rtp_ts: u32, keyframe: bool) {
        let ts = self.unwrapper.unwrap(rtp_ts);
        if self.max_ts.is_some_and(|max| ts < max) {
            self.timing.b_frames = Some(true);
        }
        self.max_ts = Some(self.max_ts.map_or(ts, |max| max.max(ts)));
        if !keyframe {
            return;
        }
        if let Some(previous) = self.keyframe_ts
            && ts > previous
        {
            self.timing.keyframe_interval =
                MediaTime::from_ticks(ts.saturating_sub(previous)).to_duration(self.clock_rate);
            // A whole interval went by: had its frames been reordered, a
            // timestamp would have stepped back.
            self.timing.b_frames = Some(self.timing.b_frames.unwrap_or(false));
        }
        self.keyframe_ts = Some(ts);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::Arc;

    use super::*;
    use crate::clock::{Clock as _, SystemClock};
    use crate::media::RtpHeaderFields;

    /// A packet `seq` at `ts`, starting a frame if `start`, a keyframe if
    /// `keyframe`, with `marker`.
    fn packet(seq: u16, ts: u32, start: bool, keyframe: bool, marker: bool) -> MediaPacket {
        MediaPacket {
            arrival: SystemClock.now(),
            rtp: RtpHeaderFields {
                pt: 96,
                seq,
                ts,
                marker,
                ssrc: 1,
            },
            frame_start: start,
            keyframe_start: keyframe,
            epoch: 0,
            lateness: Duration::from_micros(u64::from(seq)),
            payload: Arc::from(&[0_u8; 4][..]),
        }
    }

    /// Feeds one-packet frames at `timestamps` to a 90 kHz video meter,
    /// sequence numbers from 0, every frame ending with the marker bit; a
    /// keyframe where the timestamp is in `keyframes`.
    fn frames(timestamps: &[u32], keyframes: &[u32]) -> TimingMeter {
        let mut meter = TimingMeter::new(90_000);
        for (seq, &ts) in (0_u16..).zip(timestamps) {
            meter.packet(&packet(seq, ts, true, keyframes.contains(&ts), true), true);
        }
        meter
    }

    #[test]
    fn nothing_is_known_before_the_first_packet() {
        assert_eq!(TimingMeter::new(90_000).timing(), TrackTiming::default());
    }

    #[test]
    fn rfc3550_5_1_the_keyframe_interval_is_the_media_time_between_the_latest_two() {
        let mut meter = frames(&[0, 3000, 6000], &[0]);
        assert_eq!(meter.timing().keyframe_interval, None, "one keyframe");
        // 2 s at 90 kHz, then 1 s: the latest interval counts.
        for (seq, ts) in [(3, 180_000), (4, 183_000), (5, 270_000)] {
            meter.packet(&packet(seq, ts, true, ts != 183_000, true), true);
        }
        assert_eq!(
            meter.timing().keyframe_interval,
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn rfc3550_5_1_a_keyframe_interval_spans_a_timestamp_wrap() {
        let start = u32::MAX - 44_999;
        let next = start.wrapping_add(90_000);
        assert!(next < start, "the timestamp wraps");
        let meter = frames(&[start, next], &[start, next]);
        assert_eq!(
            meter.timing().keyframe_interval,
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn a_keyframe_not_after_the_previous_one_is_no_interval() {
        // The same timestamp again, then an earlier one: neither is an
        // interval, and a later keyframe counts from the latest.
        let mut meter = TimingMeter::new(90_000);
        for (seq, ts) in [(0, 9000), (1, 9000), (2, 6000)] {
            meter.packet(&packet(seq, ts, true, true, true), true);
            assert_eq!(meter.timing().keyframe_interval, None, "at {ts}");
        }
        meter.packet(&packet(3, 15_000, true, true, true), true);
        assert_eq!(
            meter.timing().keyframe_interval,
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn a_zero_clock_rate_measures_no_interval() {
        let mut meter = TimingMeter::new(0);
        meter.packet(&packet(0, 0, true, true, true), true);
        meter.packet(&packet(1, 90_000, true, true, true), true);
        assert_eq!(meter.timing().keyframe_interval, None);
        assert_eq!(meter.timing().b_frames, Some(false));
    }

    #[test]
    fn iso_14496_10_c_4_frames_in_presentation_order_have_no_b_frames_after_an_interval() {
        let meter = frames(&[0, 3000, 6000], &[0]);
        assert_eq!(meter.timing().b_frames, None, "no whole interval yet");
        let meter = frames(&[0, 3000, 6000, 9000], &[0, 9000]);
        assert_eq!(meter.timing().b_frames, Some(false));
    }

    #[test]
    fn iso_14496_10_c_4_a_timestamp_stepping_back_is_a_b_frame() {
        // I0 P3 B1 B2 in decode order: the B-frames step back behind P.
        let meter = frames(&[0, 9000, 3000, 6000], &[0]);
        assert_eq!(meter.timing().b_frames, Some(true));
        // It stays so through the next keyframe.
        let meter = frames(&[0, 9000, 3000, 6000, 18_000], &[0, 18_000]);
        assert_eq!(meter.timing().b_frames, Some(true));
        // A timestamp equal to the highest is no step back.
        let meter = frames(&[0, 3000, 3000], &[0]);
        assert_eq!(meter.timing().b_frames, None);
    }

    #[test]
    fn rfc6184_5_1_a_source_ending_every_frame_with_the_marker_bit() {
        let mut meter = TimingMeter::new(90_000);
        assert_eq!(meter.timing().marker_bit, None);
        // A frame of two packets, the last one marked.
        meter.packet(&packet(0, 0, true, true, false), true);
        meter.packet(&packet(1, 0, false, false, true), true);
        assert_eq!(meter.timing().marker_bit, None, "no frame ended yet");
        meter.packet(&packet(2, 3000, true, false, true), true);
        assert_eq!(meter.timing().marker_bit, Some(true));
        meter.packet(&packet(3, 6000, true, false, true), true);
        assert_eq!(meter.timing().marker_bit, Some(true));
    }

    #[test]
    fn rfc6184_5_1_one_frame_ending_without_the_marker_bit_decides_it() {
        let mut meter = TimingMeter::new(90_000);
        meter.packet(&packet(0, 0, true, true, false), true);
        meter.packet(&packet(1, 3000, true, false, true), true);
        assert_eq!(meter.timing().marker_bit, Some(false));
        // Marked frames after it do not undo it.
        meter.packet(&packet(2, 6000, true, false, true), true);
        assert_eq!(meter.timing().marker_bit, Some(false));
    }

    #[test]
    fn rfc3550_5_1_a_frame_whose_last_packet_was_lost_decides_nothing() {
        let mut meter = TimingMeter::new(90_000);
        meter.packet(&packet(0, 0, true, true, false), true);
        // Sequence number 1, the marked end of frame 0, was lost.
        meter.packet(&packet(2, 3000, true, false, true), true);
        assert_eq!(meter.timing().marker_bit, None);
        // Across the sequence number wrap, the next one is the right one.
        let mut meter = TimingMeter::new(90_000);
        meter.packet(&packet(u16::MAX, 0, true, true, true), true);
        meter.packet(&packet(0, 3000, true, false, true), true);
        assert_eq!(meter.timing().marker_bit, Some(true));
    }

    #[test]
    fn rfc3551_4_1_an_audio_track_reports_only_its_latency() {
        let mut meter = TimingMeter::new(8000);
        meter.packet(&packet(7, 0, true, true, true), false);
        meter.packet(&packet(8, 160, true, true, false), false);
        meter.packet(&packet(9, 0, true, true, true), false);
        assert_eq!(
            meter.timing(),
            TrackTiming {
                packet_latency: Some(Duration::from_micros(9)),
                ..TrackTiming::default()
            }
        );
    }

    #[test]
    fn the_latency_is_the_latest_frames_and_its_later_packets_leave_it() {
        let mut meter = TimingMeter::new(90_000);
        meter.packet(&packet(4, 0, true, true, false), true);
        assert_eq!(
            meter.timing().packet_latency,
            Some(Duration::from_micros(4))
        );
        meter.packet(&packet(5, 0, false, false, true), true);
        assert_eq!(
            meter.timing().packet_latency,
            Some(Duration::from_micros(4))
        );
    }

    #[test]
    fn a_reset_forgets_everything_but_the_clock_rate() {
        let mut meter = frames(&[0, 9000, 3000, 90_000], &[0, 90_000]);
        assert_ne!(meter.timing(), TrackTiming::default());
        meter.reset();
        assert_eq!(meter.timing(), TrackTiming::default());
        // The keyframe before the reset is not the start of an interval,
        // and the clock rate is still 90 kHz.
        meter.packet(&packet(9, 900_000, true, true, true), true);
        assert_eq!(meter.timing().keyframe_interval, None);
        meter.packet(&packet(10, 990_000, true, true, true), true);
        assert_eq!(
            meter.timing().keyframe_interval,
            Some(Duration::from_secs(1))
        );
        assert_eq!(meter.timing().b_frames, Some(false));
    }
}

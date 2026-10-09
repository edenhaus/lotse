//! The two media units: the [`MediaPacket`] that is cut through to viewers
//! and the [`MediaFrame`] of the side branch, plus [`MediaTime`] and the
//! counters that unwrap RTP's wrapping fields.
//!
//! Implements RFC 3550 §5.1: the RTP header fields a packet keeps, and the
//! interpretation of a 32-bit timestamp or 16-bit sequence number as the
//! nearest value to the previous one when it wraps.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

/// Presentation time of a frame in ticks of its track's clock rate,
/// unwrapped to 64 bits so it never wraps within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MediaTime(i64);

impl MediaTime {
    /// Time zero of the track's clock.
    pub const ZERO: Self = Self(0);

    /// Wraps a tick count.
    pub const fn from_ticks(ticks: i64) -> Self {
        Self(ticks)
    }

    /// The tick count.
    pub const fn ticks(self) -> i64 {
        self.0
    }

    /// `self + ticks`, or `None` on overflow.
    pub const fn checked_add_ticks(self, ticks: i64) -> Option<Self> {
        match self.0.checked_add(ticks) {
            Some(sum) => Some(Self(sum)),
            None => None,
        }
    }

    /// `self - other` in ticks, or `None` on overflow.
    pub const fn checked_sub(self, other: Self) -> Option<i64> {
        self.0.checked_sub(other.0)
    }

    /// Converts a non-negative time to a [`Duration`] at `clock_rate` ticks
    /// per second. `None` for negative times and a zero clock rate.
    pub fn to_duration(self, clock_rate: u32) -> Option<Duration> {
        let ticks = u64::try_from(self.0).ok()?;
        let clock_rate = u64::from(clock_rate);
        if clock_rate == 0 {
            return None;
        }
        let seconds = ticks.checked_div(clock_rate)?;
        let rest = ticks.checked_rem(clock_rate)?;
        // rest < clock_rate ≤ u32::MAX, so rest × 10⁹ fits in a u64.
        let nanos = rest.checked_mul(1_000_000_000)?.checked_div(clock_rate)?;
        Some(Duration::new(seconds, u32::try_from(nanos).ok()?))
    }
}

impl fmt::Display for MediaTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unwraps 32-bit RTP timestamps (RFC 3550 §5.1) into a monotonic 64-bit
/// count: each value is read as the one nearest to its predecessor, so a
/// wrap in either direction becomes a small step.
#[derive(Debug, Clone, Default)]
pub struct TimestampUnwrapper {
    /// The last raw timestamp seen.
    last: Option<u32>,
    /// The unwrapped value of `last`.
    extended: i64,
}

impl TimestampUnwrapper {
    /// An unwrapper that has seen nothing; the first timestamp maps to itself.
    pub const fn new() -> Self {
        Self {
            last: None,
            extended: 0,
        }
    }

    /// Unwraps `ts`.
    pub fn unwrap(&mut self, ts: u32) -> i64 {
        let extended = match self.last {
            None => i64::from(ts),
            Some(last) => {
                // The forward distance modulo 2³², reinterpreted as signed: the
                // nearest interpretation, ±2³¹ around the previous value.
                let delta = i32::from_ne_bytes(ts.wrapping_sub(last).to_ne_bytes());
                self.extended.saturating_add(i64::from(delta))
            }
        };
        self.last = Some(ts);
        self.extended = extended;
        extended
    }

    /// The last unwrapped value, if any.
    pub const fn last(&self) -> Option<i64> {
        match self.last {
            Some(_) => Some(self.extended),
            None => None,
        }
    }
}

/// Unwraps 16-bit RTP sequence numbers (RFC 3550 §5.1) the same way
/// [`TimestampUnwrapper`] unwraps timestamps.
#[derive(Debug, Clone, Default)]
pub struct SequenceUnwrapper {
    /// The last raw sequence number seen.
    last: Option<u16>,
    /// The unwrapped value of `last`.
    extended: i64,
}

impl SequenceUnwrapper {
    /// An unwrapper that has seen nothing; the first number maps to itself.
    pub const fn new() -> Self {
        Self {
            last: None,
            extended: 0,
        }
    }

    /// Unwraps `seq`.
    pub fn unwrap(&mut self, seq: u16) -> i64 {
        let extended = match self.last {
            None => i64::from(seq),
            Some(last) => {
                let delta = i16::from_ne_bytes(seq.wrapping_sub(last).to_ne_bytes());
                self.extended.saturating_add(i64::from(delta))
            }
        };
        self.last = Some(seq);
        self.extended = extended;
        extended
    }

    /// The last unwrapped value, if any.
    pub const fn last(&self) -> Option<i64> {
        match self.last {
            Some(_) => Some(self.extended),
            None => None,
        }
    }
}

/// The RTP header fields (RFC 3550 §5.1) a packet keeps from the source.
/// Viewers get their own SSRC, sequence numbers and a timestamp offset; the
/// camera's values stay here for the side branch and the clock mapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RtpHeaderFields {
    /// Payload type.
    pub pt: u8,
    /// Sequence number, as sent.
    pub seq: u16,
    /// Timestamp in the source's RTP clock, as sent.
    pub ts: u32,
    /// Marker bit; for video the last packet of an access unit (RFC 6184 §5.1).
    pub marker: bool,
    /// Synchronization source, as sent.
    pub ssrc: u32,
}

/// The live unit: one RTP packet, forwarded to viewers the moment it is
/// read. The payload is copied once at ingest into a shared slice every
/// viewer hands to its engine without another copy.
#[derive(Clone, PartialEq, Eq)]
pub struct MediaPacket {
    /// When the packet was read; every age bound is measured from here.
    pub arrival: Instant,
    /// The header fields as the source sent them.
    pub rtp: RtpHeaderFields,
    /// The first packet of a frame.
    pub frame_start: bool,
    /// The first packet of an IDR or IRAP access unit.
    pub keyframe_start: bool,
    /// The track's epoch this packet belongs to; stamped by the track. A
    /// change means a timestamp discontinuity or a reconnect, and a new
    /// per-session timestamp offset.
    pub epoch: u32,
    /// How late the packet's frame arrived against the track's recent
    /// best; stamped by the track. Live sessions skip what an ingest stall
    /// delivered too late ([`crate::lateness`]).
    pub lateness: Duration,
    /// The RTP payload, without the header.
    pub payload: Arc<[u8]>,
}

impl fmt::Debug for MediaPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaPacket")
            .field("arrival", &self.arrival)
            .field("rtp", &self.rtp)
            .field("frame_start", &self.frame_start)
            .field("keyframe_start", &self.keyframe_start)
            .field("epoch", &self.epoch)
            .field("lateness", &self.lateness)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// The side-branch unit: one access unit or one audio frame, in decode
/// order, for the consumers that need whole frames (GOP cache,
/// transcoders, snapshots, later muxers).
#[derive(Clone, PartialEq, Eq)]
pub struct MediaFrame {
    /// Presentation time in the track's clock.
    pub ts: MediaTime,
    /// Capture time on the source's shared clock, from the clock mapper.
    pub wallclock: Instant,
    /// When the source read the frame (a transcoder: produced it), on the
    /// injected clock. Activity, and so the stall watchdog, counts from
    /// it, never from `wallclock`, which the camera's own Sender Reports
    /// can move hours ahead.
    pub arrival: Instant,
    /// An IDR or IRAP access unit (video), or any frame (audio).
    pub keyframe: bool,
    /// The first frame of a new epoch: a timestamp reset or a reconnect.
    /// Set by the source or by the track when it starts an epoch.
    pub discontinuity: bool,
    /// The track's epoch this frame belongs to; stamped by the track.
    pub epoch: u32,
    /// The frame. H.264 and H.265: Annex B with 4-byte start codes and the
    /// parameter sets in-band before every keyframe.
    pub payload: Bytes,
}

impl fmt::Debug for MediaFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaFrame")
            .field("ts", &self.ts)
            .field("wallclock", &self.wallclock)
            .field("arrival", &self.arrival)
            .field("keyframe", &self.keyframe)
            .field("discontinuity", &self.discontinuity)
            .field("epoch", &self.epoch)
            .field("payload_len", &self.payload.len())
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

    use super::*;
    use crate::clock::{Clock as _, SystemClock};

    #[test]
    fn media_time_arithmetic_is_checked() {
        let t = MediaTime::from_ticks(90_000);
        assert_eq!(t.ticks(), 90_000);
        assert_eq!(
            t.checked_add_ticks(10).unwrap(),
            MediaTime::from_ticks(90_010)
        );
        assert_eq!(MediaTime::from_ticks(i64::MAX).checked_add_ticks(1), None);
        assert_eq!(t.checked_sub(MediaTime::ZERO), Some(90_000));
        assert_eq!(MediaTime::from_ticks(i64::MIN).checked_sub(t), None);
        assert_eq!(t.to_string(), "90000");
        assert_eq!(MediaTime::default(), MediaTime::ZERO);
    }

    #[test]
    fn media_time_converts_to_duration_at_the_clock_rate() {
        assert_eq!(
            MediaTime::from_ticks(135_000).to_duration(90_000),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            MediaTime::from_ticks(480).to_duration(48_000),
            Some(Duration::from_millis(10))
        );
        assert_eq!(MediaTime::from_ticks(-1).to_duration(90_000), None);
        assert_eq!(MediaTime::from_ticks(1).to_duration(0), None);
        assert_eq!(
            MediaTime::from_ticks(i64::MAX).to_duration(1),
            Some(Duration::from_secs(u64::try_from(i64::MAX).unwrap()))
        );
    }

    #[test]
    fn timestamps_unwrap_across_the_32_bit_boundary_rfc3550_5_1() {
        let mut u = TimestampUnwrapper::new();
        assert_eq!(u.last(), None);
        assert_eq!(u.unwrap(u32::MAX - 3000), i64::from(u32::MAX) - 3000);
        assert_eq!(u.unwrap(600), i64::from(u32::MAX) + 601);
        assert_eq!(u.last(), Some(i64::from(u32::MAX) + 601));
        // A step backwards (reordered frame) stays a small negative step.
        assert_eq!(u.unwrap(u32::MAX - 100), i64::from(u32::MAX) - 100);
        // A step of exactly 2³¹ is read as forward.
        let mut u = TimestampUnwrapper::default();
        u.unwrap(0);
        assert_eq!(u.unwrap(1 << 31), -(1_i64 << 31));
    }

    #[test]
    fn sequence_numbers_unwrap_across_the_16_bit_boundary_rfc3550_5_1() {
        let mut u = SequenceUnwrapper::new();
        assert_eq!(u.last(), None);
        assert_eq!(u.unwrap(65_534), 65_534);
        assert_eq!(u.unwrap(65_535), 65_535);
        assert_eq!(u.unwrap(0), 65_536);
        assert_eq!(u.unwrap(1), 65_537);
        assert_eq!(u.unwrap(65_535), 65_535);
        assert_eq!(u.last(), Some(65_535));
        assert_eq!(SequenceUnwrapper::default().unwrap(7), 7);
    }

    #[test]
    fn unwrappers_saturate_instead_of_overflowing() {
        let mut u = TimestampUnwrapper {
            last: Some(0),
            extended: i64::MAX,
        };
        assert_eq!(u.unwrap(1), i64::MAX);
        let mut u = SequenceUnwrapper {
            last: Some(1),
            extended: i64::MIN,
        };
        assert_eq!(u.unwrap(0), i64::MIN);
    }

    #[test]
    fn debug_prints_the_payload_length_not_the_bytes() {
        let now = SystemClock.now();
        let packet = MediaPacket {
            arrival: now,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: 1,
                ts: 2,
                marker: true,
                ssrc: 3,
            },
            frame_start: true,
            keyframe_start: false,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&b"\x01\x02\x03"[..]),
        };
        let text = format!("{packet:?}");
        assert!(text.contains("payload_len: 3"), "{text}");
        assert!(!text.contains("\\x01"), "{text}");

        let frame = MediaFrame {
            ts: MediaTime::ZERO,
            wallclock: now,
            arrival: now,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: Bytes::from_static(b"\x00\x00\x00\x01\x65"),
        };
        let text = format!("{frame:?}");
        assert!(text.contains("payload_len: 5"), "{text}");
        assert!(text.contains("keyframe: true"), "{text}");
        assert!(text.contains("arrival: "), "{text}");
        assert_eq!(frame.clone().payload, frame.payload);
        assert_eq!(packet.clone().rtp, packet.rtp);
    }
}

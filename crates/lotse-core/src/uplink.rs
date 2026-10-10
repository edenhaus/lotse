//! A session's uplink: the talk-back audio a viewer sends, as the session
//! hands it to the worker and as the worker publishes it for the reverse
//! chain.
//!
//! A session output depacketizes what the viewer sends on its talk-back
//! m-line into [`UplinkPacket`]s. The worker publishes a session's packets
//! on an [`UplinkTrack`], one per session and codec, which carries them
//! both ways a consumer needs: the live path (every packet, as received)
//! for a backchannel that takes the codec as it is (Opus to an Opus
//! camera), and the side branch (one RTP payload per frame, timestamps
//! unwrapped) for the [`Transcoder`](crate::transcode::Transcoder) that
//! turns it into the camera's G.711 (`ToG711`). Which one feeds the
//! connection's backchannel, and for which session, is the talker
//! arbitration's to decide, not this module's.
//!
//! Standards: RFC 3550 §5.1 (timestamps wrap; a new SSRC is a new
//! timeline), RFC 7587 §4.1 (Opus at 48 kHz), RFC 3551 §4.5.14 (G.711 at
//! 8 kHz).

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;

use crate::codec::{Codec, CodecFamily, Kind};
use crate::media::{MediaFrame, MediaPacket, MediaTime, TimestampUnwrapper};
use crate::track::{Track, TrackId, TrackLimits};

/// A codec talk-back arrives in: the ones a reverse chain takes (Opus, or
/// G.711 in either law), so every uplink has a way to a camera.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UplinkCodec {
    /// Opus (RFC 7587).
    Opus,
    /// G.711 µ-law (RFC 3551 §4.5.14).
    Pcmu,
    /// G.711 A-law (RFC 3551 §4.5.14).
    Pcma,
}

impl UplinkCodec {
    /// The uplink codec of `family`, if talk-back can arrive in it.
    pub const fn of(family: CodecFamily) -> Option<Self> {
        match family {
            CodecFamily::Opus => Some(Self::Opus),
            CodecFamily::Pcmu => Some(Self::Pcmu),
            CodecFamily::Pcma => Some(Self::Pcma),
            _ => None,
        }
    }

    /// The codec family.
    pub const fn family(self) -> CodecFamily {
        match self {
            Self::Opus => CodecFamily::Opus,
            Self::Pcmu => CodecFamily::Pcmu,
            Self::Pcma => CodecFamily::Pcma,
        }
    }

    /// The codec descriptor an uplink track carries. Opus is mono: an
    /// answer that does not ask for stereo leaves the browser sending mono
    /// (RFC 7587 §6.1, `stereo` defaults to 0), and a stereo packet still
    /// decodes, mixed down.
    pub const fn codec(self) -> Codec {
        match self {
            Self::Opus => Codec::Opus { channels: 1 },
            Self::Pcmu => Codec::Pcmu,
            Self::Pcma => Codec::Pcma,
        }
    }

    /// The RTP clock rate: 48 kHz for Opus (RFC 7587 §4.1), 8 kHz for
    /// G.711 (RFC 3551 §4.5.14).
    pub const fn clock_rate(self) -> u32 {
        match self {
            Self::Opus => 48_000,
            Self::Pcmu | Self::Pcma => 8_000,
        }
    }

    /// The API name, the family's.
    pub const fn name(self) -> &'static str {
        self.family().name()
    }
}

/// One talk-back packet a viewer sent, depacketized: one RTP payload, one
/// packet of `codec`, with the header fields as the viewer sent them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UplinkPacket {
    /// The codec its payload type names.
    pub codec: UplinkCodec,
    /// The packet: `arrival` is when the session received it,
    /// `frame_start` is set (an audio packet is a frame), the epoch is
    /// the uplink track's to stamp.
    pub packet: MediaPacket,
}

/// The id every uplink track carries: an audio id no stream's track has
/// (the stream's tracks count up from `a0`), so a log line never takes it
/// for one of the camera's.
pub const UPLINK_TRACK: TrackId = TrackId::new(Kind::Audio, u8::MAX);

/// The bounds of an uplink track: a little over a second of 20 ms packets
/// on either branch for a consumer to fall behind by before it lags, a
/// frame no larger than an Opus packet can be (RFC 6716 §3.4: 120 ms of
/// 1275-byte frames at most, well under this) or a G.711 one of a second.
const UPLINK_LIMITS: TrackLimits = TrackLimits {
    max_frame_bytes: 16 * 1024,
    gop_cache_bytes: 0,
    gop_cache_frames: 0,
    packet_capacity: 64,
    frame_capacity: 64,
};

/// The track one session's talk-back goes out on, in one codec, while the
/// session sends in it. Every packet is published on the side branch first
/// (one frame per packet, at its timestamp unwrapped, captured at its
/// arrival: an uplink has no Sender Report mapping) and then on the live
/// path, as the transcoder contract has a source track do. A new SSRC
/// starts a new epoch, since its timestamps are another timeline
/// (RFC 3550 §5.1). Dropping it closes the track: a sink's
/// [`TrackSubscription`](crate::track::TrackSubscription) ends, and a raw
/// packet or frame subscription gets nothing more, so whoever reads it
/// learns that the session stopped sending in this codec.
pub struct UplinkTrack {
    /// The track.
    track: Arc<Track>,
    /// The codec it carries.
    codec: UplinkCodec,
    /// Unwraps the timestamps of the current SSRC.
    unwrapper: TimestampUnwrapper,
    /// The SSRC of the last packet, `None` before the first.
    ssrc: Option<u32>,
}

impl fmt::Debug for UplinkTrack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UplinkTrack")
            .field("codec", &self.codec)
            .field("ssrc", &self.ssrc)
            .field("epoch", &self.track.epoch())
            .finish_non_exhaustive()
    }
}

impl UplinkTrack {
    /// An empty uplink track of `codec`, timing its activity from
    /// `origin` (not after its first packet's arrival).
    pub fn new(codec: UplinkCodec, origin: Instant) -> Self {
        Self {
            track: Arc::new(Track::new(
                UPLINK_TRACK,
                codec.codec(),
                codec.clock_rate(),
                UPLINK_LIMITS,
                origin,
            )),
            codec,
            unwrapper: TimestampUnwrapper::new(),
            ssrc: None,
        }
    }

    /// The track, to subscribe to.
    pub const fn track(&self) -> &Arc<Track> {
        &self.track
    }

    /// The codec it carries.
    pub const fn codec(&self) -> UplinkCodec {
        self.codec
    }

    /// Publishes `packet`: as a frame on the side branch, then on the live
    /// path. A packet of another SSRC than the last starts a new epoch
    /// first.
    pub fn publish(&mut self, packet: MediaPacket) {
        let ssrc = packet.rtp.ssrc;
        if self.ssrc.is_some_and(|last| last != ssrc) {
            let epoch = self.track.start_epoch();
            tracing::debug!(ssrc, epoch, "uplink SSRC changed; new epoch");
            self.unwrapper = TimestampUnwrapper::new();
        }
        self.ssrc = Some(ssrc);
        let ts = self.unwrapper.unwrap(packet.rtp.ts);
        let _accepted = self.track.publish_frame(MediaFrame {
            ts: MediaTime::from_ticks(ts),
            wallclock: packet.arrival,
            arrival: packet.arrival,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: Bytes::from_owner(Arc::clone(&packet.payload)),
        });
        self.track.publish_packet(packet);
    }
}

impl Drop for UplinkTrack {
    fn drop(&mut self) {
        self.track.close();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::time::Duration;

    use super::*;
    use crate::clock::{Clock as _, SystemClock};
    use crate::media::RtpHeaderFields;
    use crate::track::Unit;

    fn packet(ssrc: u32, ts: u32, arrival: Instant, payload: &[u8]) -> MediaPacket {
        MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                pt: 111,
                seq: 1,
                ts,
                marker: false,
                ssrc,
            },
            frame_start: true,
            keyframe_start: false,
            epoch: 7,
            lateness: Duration::ZERO,
            payload: Arc::from(payload),
        }
    }

    #[test]
    fn uplink_codecs_are_the_ones_a_reverse_chain_takes() {
        for (family, codec, descriptor, rate, name) in [
            (
                CodecFamily::Opus,
                UplinkCodec::Opus,
                Codec::Opus { channels: 1 },
                48_000,
                "opus",
            ),
            (
                CodecFamily::Pcmu,
                UplinkCodec::Pcmu,
                Codec::Pcmu,
                8_000,
                "pcmu",
            ),
            (
                CodecFamily::Pcma,
                UplinkCodec::Pcma,
                Codec::Pcma,
                8_000,
                "pcma",
            ),
        ] {
            assert_eq!(UplinkCodec::of(family), Some(codec));
            assert_eq!(codec.family(), family);
            assert_eq!(codec.codec(), descriptor);
            assert_eq!(codec.clock_rate(), rate);
            assert_eq!(
                descriptor.rtp_clock_rate(),
                Some(rate),
                "RFC 7587, RFC 3551"
            );
            assert_eq!(codec.name(), name);
        }
        for family in [CodecFamily::G722, CodecFamily::AacLc, CodecFamily::H264] {
            assert_eq!(UplinkCodec::of(family), None, "{family:?}");
        }
    }

    #[test]
    fn rfc3550_5_1_packets_go_out_as_frames_then_packets_with_unwrapped_timestamps() {
        let start = SystemClock.now();
        let mut uplink = UplinkTrack::new(UplinkCodec::Opus, start);
        assert_eq!(uplink.codec(), UplinkCodec::Opus);
        let track = Arc::clone(uplink.track());
        assert_eq!(track.id(), UPLINK_TRACK);
        assert_eq!(track.id().to_string(), "a255");
        assert_eq!(track.clock_rate(), 48_000);
        assert_eq!(*track.codec(), Codec::Opus { channels: 1 });
        let mut frames = track.subscribe_frames();
        let mut packets = track.subscribe_packets();
        // Across the 32-bit wrap: the side branch counts on.
        let later = start + Duration::from_millis(20);
        uplink.publish(packet(9, u32::MAX - 479, start, &[0xfc, 1]));
        uplink.publish(packet(9, 480, later, &[0xfc, 2]));
        let first = frames.try_recv().unwrap().unwrap();
        let second = frames.try_recv().unwrap().unwrap();
        assert_eq!(first.ts.ticks(), i64::from(u32::MAX - 479));
        assert_eq!(second.ts.ticks(), i64::from(u32::MAX) + 481);
        assert_eq!((first.wallclock, second.wallclock), (start, later));
        assert!(first.keyframe && second.keyframe);
        assert_eq!(&second.payload[..], &[0xfc, 2]);
        assert_eq!((first.epoch, second.epoch), (0, 0), "stamped by the track");
        let sent = packets.try_recv().unwrap().unwrap();
        assert_eq!(sent.rtp.ts, u32::MAX - 479, "the live path as received");
        assert_eq!(sent.epoch, 0);
        assert_eq!(&sent.payload[..], &[0xfc, 1]);
        assert_eq!(packets.try_recv().unwrap().unwrap().rtp.ts, 480);
        assert_eq!(track.stats().packets, 2);
        assert_eq!(track.stats().frames, 2);
        assert_eq!(track.last_activity(), Some(later));
        assert!(format!("{uplink:?}").contains("ssrc: Some(9)"));
    }

    #[test]
    fn rfc3550_5_1_a_new_ssrc_is_a_new_epoch_and_timeline() {
        let start = SystemClock.now();
        let mut uplink = UplinkTrack::new(UplinkCodec::Pcmu, start);
        let track = Arc::clone(uplink.track());
        assert_eq!(track.clock_rate(), 8_000);
        let mut frames = track.subscribe_frames();
        uplink.publish(packet(1, 4_000_000_000, start, &[0xff; 160]));
        uplink.publish(packet(1, 4_000_000_160, start, &[0xff; 160]));
        // The same SSRC again: no epoch.
        assert_eq!(track.epoch(), 0);
        // Another SSRC: a new epoch, and its timestamps unwrap afresh
        // instead of as a jump back from the old ones.
        uplink.publish(packet(2, 160, start, &[0xff; 160]));
        assert_eq!(track.epoch(), 1);
        let frames: Vec<_> = std::iter::from_fn(|| frames.try_recv().unwrap()).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[2].ts.ticks(), 160);
        assert_eq!(frames[2].epoch, 1);
        assert!(frames[2].discontinuity);
        assert!(!frames[1].discontinuity);
    }

    #[test]
    fn rfc6716_3_4_a_second_of_g711_or_the_longest_opus_packet_is_a_frame() {
        let start = SystemClock.now();
        let mut uplink = UplinkTrack::new(UplinkCodec::Pcma, start);
        let track = Arc::clone(uplink.track());
        uplink.publish(packet(1, 0, start, &[0xd5; 8_000]));
        // Six 20 ms frames of 1275 bytes with their code 3 header.
        uplink.publish(packet(1, 8_000, start, &[0; 2 + 6 * 1_275]));
        assert_eq!(track.stats().frames, 2);
        assert_eq!(track.stats().frames_dropped_oversize, 0);
        uplink.publish(packet(1, 16_000, start, &vec![0; 16 * 1_024 + 1]));
        assert_eq!(track.stats().frames_dropped_oversize, 1);
    }

    #[tokio::test]
    async fn dropping_the_uplink_ends_its_subscriptions() {
        let uplink = UplinkTrack::new(UplinkCodec::Pcma, SystemClock.now());
        let track = Arc::clone(uplink.track());
        let mut sink = track.subscribe(Unit::Frames);
        assert!(!track.is_closed());
        drop(uplink);
        assert!(track.is_closed());
        assert!(sink.next().await.is_none());
    }
}

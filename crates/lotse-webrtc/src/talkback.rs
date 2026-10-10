//! The talk-back depacketizer: what a viewer sends on the talk-back m-line
//! in, [`UplinkPacket`]s out.
//!
//! It takes the packet by its payload type, not by the codec the answer
//! named first: the browser sends the first codec of the answer's list
//! (RFC 3264 §6.1), but the talk-back m-line lists the stream audio's too
//! (str0m's one codec list), and a browser may switch to any listed codec
//! without renegotiating (RFC 3264 §5.1). A payload type of no talk-back
//! codec (G.722, video, an unknown one) is refused, and so is a payload
//! that is not one packet of its codec: an Opus packet that breaks RFC
//! 6716 §3.4, an empty G.711 one (RFC 3551 §4.5.14: one octet per sample).
//! The packet is not decoded here; the reverse chain decodes it in the
//! camera's sandboxed worker.
//!
//! The payload bytes come from an untrusted peer: the `talkback_depacketize`
//! fuzz target holds this module to never panicking on any payload.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_codec::opus::{self, PacketError};
use lotse_core::codec::CodecFamily;
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::uplink::{UplinkCodec, UplinkPacket};

/// Why a packet on the talk-back m-line is not passed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Its payload type names no talk-back codec.
    PayloadType(u8),
    /// A G.711 packet without a sample.
    Empty,
    /// No Opus packet (RFC 6716 §3.4).
    Opus(PacketError),
}

impl Refused {
    /// The reason, for a log line's field.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::PayloadType(_) => "payload type of no talk-back codec",
            Self::Empty => "empty G.711 payload",
            Self::Opus(_) => "not an Opus packet",
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadType(pt) => write!(f, "payload type {pt} names no talk-back codec"),
            Self::Empty => f.write_str("a G.711 payload without a sample (RFC 3551 §4.5.14)"),
            Self::Opus(err) => write!(f, "{err}"),
        }
    }
}

/// The depacketizer of one session's talk-back m-line: the payload types
/// it takes and the codec each names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Depacketizer {
    /// Payload type and codec, of the talk-back codecs only.
    payload_types: Vec<(u8, UplinkCodec)>,
}

impl Depacketizer {
    /// A depacketizer taking the payload types of `negotiated` that name a
    /// talk-back codec (Opus, PCMU, PCMA); the others are refused. The
    /// first entry of a payload type counts (RFC 9143 §9.1.1: one codec
    /// per payload type in a BUNDLE group, checked before the engine sees
    /// the offer).
    pub fn new(negotiated: impl IntoIterator<Item = (u8, CodecFamily)>) -> Self {
        let mut payload_types: Vec<(u8, UplinkCodec)> = Vec::new();
        for (pt, family) in negotiated {
            if let Some(codec) = UplinkCodec::of(family)
                && !payload_types.iter().any(|(known, _)| *known == pt)
            {
                payload_types.push((pt, codec));
            }
        }
        Self { payload_types }
    }

    /// The talk-back codec payload type `pt` names, if any.
    pub fn codec(&self, pt: u8) -> Option<UplinkCodec> {
        self.payload_types
            .iter()
            .find_map(|(known, codec)| (*known == pt).then_some(*codec))
    }

    /// The talk-back packet of one RTP packet the viewer sent on the
    /// talk-back m-line, with header fields `rtp` and `payload` (without
    /// header or padding), received at `arrival`; or why it is refused.
    pub fn depacketize(
        &self,
        rtp: RtpHeaderFields,
        payload: Arc<[u8]>,
        arrival: Instant,
    ) -> Result<UplinkPacket, Refused> {
        let codec = self.codec(rtp.pt).ok_or(Refused::PayloadType(rtp.pt))?;
        match codec {
            UplinkCodec::Opus => {
                opus::packet_samples(&payload).map_err(Refused::Opus)?;
            }
            UplinkCodec::Pcmu | UplinkCodec::Pcma => {
                if payload.is_empty() {
                    return Err(Refused::Empty);
                }
            }
        }
        Ok(UplinkPacket {
            codec,
            packet: MediaPacket {
                arrival,
                rtp,
                frame_start: true,
                keyframe_start: false,
                epoch: 0,
                lateness: Duration::ZERO,
                payload,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use lotse_core::clock::{Clock as _, SystemClock};

    use super::*;

    fn rtp(pt: u8) -> RtpHeaderFields {
        RtpHeaderFields {
            pt,
            seq: 7,
            ts: 960,
            marker: true,
            ssrc: 0x1234,
        }
    }

    fn browser() -> Depacketizer {
        // What str0m negotiates from a browser's audio m-line, with video
        // in the same BUNDLE group; 0 named twice keeps the first.
        Depacketizer::new([
            (111, CodecFamily::Opus),
            (9, CodecFamily::G722),
            (0, CodecFamily::Pcmu),
            (8, CodecFamily::Pcma),
            (96, CodecFamily::H264),
            (0, CodecFamily::Pcma),
        ])
    }

    #[test]
    fn rfc3264_6_1_packets_are_taken_by_payload_type_in_any_talk_back_codec() {
        let depacketizer = browser();
        let now = SystemClock.now();
        for (pt, codec, payload) in [
            (111, UplinkCodec::Opus, &[0xfc_u8, 0xff, 0xfe][..]),
            (0, UplinkCodec::Pcmu, &[0xff; 160][..]),
            (8, UplinkCodec::Pcma, &[0xd5; 160][..]),
        ] {
            let packet = depacketizer
                .depacketize(rtp(pt), Arc::from(payload), now)
                .unwrap();
            assert_eq!(packet.codec, codec, "{pt}");
            assert_eq!(packet.packet.rtp, rtp(pt), "the header as sent");
            assert_eq!(&packet.packet.payload[..], payload, "no copy, no change");
            assert_eq!(packet.packet.arrival, now);
            assert!(packet.packet.frame_start && !packet.packet.keyframe_start);
            assert_eq!(packet.packet.epoch, 0);
            assert_eq!(packet.packet.lateness, Duration::ZERO);
        }
        assert_eq!(depacketizer.codec(0), Some(UplinkCodec::Pcmu));
    }

    #[test]
    fn a_payload_type_of_no_talk_back_codec_is_refused() {
        let depacketizer = browser();
        let now = SystemClock.now();
        for pt in [9, 96, 100] {
            assert_eq!(
                depacketizer.depacketize(rtp(pt), Arc::from(&[1_u8][..]), now),
                Err(Refused::PayloadType(pt))
            );
        }
        let refused = Refused::PayloadType(9);
        assert_eq!(refused.reason(), "payload type of no talk-back codec");
        assert_eq!(
            refused.to_string(),
            "payload type 9 names no talk-back codec"
        );
        assert_eq!(
            Depacketizer::new([]).depacketize(rtp(0), Arc::from(&[1_u8][..]), now),
            Err(Refused::PayloadType(0))
        );
    }

    #[test]
    fn rfc6716_3_4_and_rfc3551_4_5_14_payloads_that_are_no_packet_are_refused() {
        let depacketizer = browser();
        let now = SystemClock.now();
        assert_eq!(
            depacketizer.depacketize(rtp(111), Arc::from(&[][..]), now),
            Err(Refused::Opus(PacketError::Empty))
        );
        // A code 1 packet of an odd length (R3).
        assert_eq!(
            depacketizer.depacketize(rtp(111), Arc::from(&[0xf9_u8, 1][..]), now),
            Err(Refused::Opus(PacketError::OddLength))
        );
        for pt in [0, 8] {
            assert_eq!(
                depacketizer.depacketize(rtp(pt), Arc::from(&[][..]), now),
                Err(Refused::Empty)
            );
        }
        assert_eq!(Refused::Empty.reason(), "empty G.711 payload");
        assert_eq!(
            Refused::Empty.to_string(),
            "a G.711 payload without a sample (RFC 3551 §4.5.14)"
        );
        let opus = Refused::Opus(PacketError::Empty);
        assert_eq!(opus.reason(), "not an Opus packet");
        assert_eq!(opus.to_string(), "an empty packet (RFC 6716 §3.4 R1)");
    }
}

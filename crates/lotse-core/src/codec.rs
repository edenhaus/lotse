//! What the daemon can carry: media kinds and codec descriptors.
//!
//! A [`Codec`] says what a track carries, not what the daemon can decode.
//! Parameters a source does not know yet (an SPS missing from the SDP) stay
//! `None` until the first keyframe fills them in. The names are the ones the
//! API reports (`codecs` in `info`, `tracks[].codec` in `stream/get`).
//! Clock rates cite RFC 3551 §6 for the static payload types.

use std::fmt;

use bytes::Bytes;

/// Whether a track carries pictures or sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// Pictures.
    Video,
    /// Sound.
    Audio,
}

impl Kind {
    /// The API name: `video` or `audio`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Video => "video",
            Self::Audio => "audio",
        }
    }

    /// The letter that starts a track id of this kind: `v` or `a`.
    pub const fn letter(self) -> char {
        match self {
            Self::Video => 'v',
            Self::Audio => 'a',
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The codec of a track with the parameters a consumer needs to negotiate
/// or decode it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Codec {
    /// H.264 (ISO/IEC 14496-10) in RTP form (RFC 6184).
    H264 {
        /// RFC 6184 §8.1 `profile-level-id`, parsed from the SPS once known.
        profile_level_id: Option<[u8; 3]>,
        /// The most recent sequence parameter set, without a start code.
        sps: Option<Bytes>,
        /// The most recent picture parameter set, without a start code.
        pps: Option<Bytes>,
    },
    /// H.265 (ITU-T H.265) in RTP form (RFC 7798).
    H265 {
        /// The most recent video parameter set, without a start code.
        vps: Option<Bytes>,
        /// The most recent sequence parameter set, without a start code.
        sps: Option<Bytes>,
        /// The most recent picture parameter set, without a start code.
        pps: Option<Bytes>,
    },
    /// Opus (RFC 6716) in RTP form (RFC 7587): 48 kHz clock, one frame per packet.
    Opus {
        /// Channel count, 1 or 2.
        channels: u8,
    },
    /// ITU-T G.711 μ-law, 8 kHz mono (RFC 3551 §4.5.14).
    Pcmu,
    /// ITU-T G.711 A-law, 8 kHz mono (RFC 3551 §4.5.14).
    Pcma,
    /// ITU-T G.722, sampled at 16 kHz but with an RTP clock of 8000 (RFC 3551 §4.5.2).
    G722,
    /// AAC-LC (ISO/IEC 14496-3) in RTP form (RFC 3640). Reaches browsers only
    /// through the Opus transcoder.
    AacLc {
        /// The sampling rate in Hz, which is also the RTP clock rate.
        sample_rate: u32,
        /// Channel count.
        channels: u8,
        /// The `AudioSpecificConfig` (ISO/IEC 14496-3 §1.6) the decoder needs.
        config: Bytes,
    },
    /// Motion JPEG (RFC 2435). Reported, never negotiated for WebRTC.
    Mjpeg,
    /// A codec the daemon cannot carry (`aac_he`, `l16`, ...). Reported so
    /// negotiation can say why, never negotiated.
    Unsupported {
        /// Whether the source calls it video or audio.
        kind: Kind,
        /// The name as the source announced it, lowercased.
        name: String,
    },
}

/// The codec family, without parameters. A WebRTC session survives any
/// parameter change inside a family and closes with `stream_changed` when
/// the family changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecFamily {
    /// See [`Codec::H264`].
    H264,
    /// See [`Codec::H265`].
    H265,
    /// See [`Codec::Opus`].
    Opus,
    /// See [`Codec::Pcmu`].
    Pcmu,
    /// See [`Codec::Pcma`].
    Pcma,
    /// See [`Codec::G722`].
    G722,
    /// See [`Codec::AacLc`].
    AacLc,
    /// See [`Codec::Mjpeg`].
    Mjpeg,
    /// See [`Codec::Unsupported`].
    Unsupported,
}

impl CodecFamily {
    /// The API name (`h264`, `aac_lc`, ...).
    pub const fn name(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::H265 => "h265",
            Self::Opus => "opus",
            Self::Pcmu => "pcmu",
            Self::Pcma => "pcma",
            Self::G722 => "g722",
            Self::AacLc => "aac_lc",
            Self::Mjpeg => "mjpeg",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for CodecFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Codec {
    /// Whether this is a video or an audio codec.
    pub const fn kind(&self) -> Kind {
        match self {
            Self::H264 { .. } | Self::H265 { .. } | Self::Mjpeg => Kind::Video,
            Self::Opus { .. } | Self::Pcmu | Self::Pcma | Self::G722 | Self::AacLc { .. } => {
                Kind::Audio
            }
            Self::Unsupported { kind, .. } => *kind,
        }
    }

    /// The family, without parameters.
    pub const fn family(&self) -> CodecFamily {
        match self {
            Self::H264 { .. } => CodecFamily::H264,
            Self::H265 { .. } => CodecFamily::H265,
            Self::Opus { .. } => CodecFamily::Opus,
            Self::Pcmu => CodecFamily::Pcmu,
            Self::Pcma => CodecFamily::Pcma,
            Self::G722 => CodecFamily::G722,
            Self::AacLc { .. } => CodecFamily::AacLc,
            Self::Mjpeg => CodecFamily::Mjpeg,
            Self::Unsupported { .. } => CodecFamily::Unsupported,
        }
    }

    /// The API name: the family's name, or the announced name of an
    /// unsupported codec.
    pub fn name(&self) -> &str {
        match self {
            Self::Unsupported { name, .. } => name,
            _ => self.family().name(),
        }
    }

    /// Whether the daemon can carry this codec at all.
    pub const fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    /// The RTP clock rate this codec is carried with, when it has a defined one.
    ///
    /// Video is 90 kHz (RFC 6184 §8.2.1, RFC 7798 §7.1, RFC 2435 §3), Opus is
    /// 48 kHz (RFC 7587 §4.1), G.711 and G.722 are 8000 (RFC 3551 §4.5.2 and
    /// §4.5.14), AAC uses its sampling rate (RFC 3640 §3.3.1).
    pub const fn rtp_clock_rate(&self) -> Option<u32> {
        match self {
            Self::H264 { .. } | Self::H265 { .. } | Self::Mjpeg => Some(90_000),
            Self::Opus { .. } => Some(48_000),
            Self::Pcmu | Self::Pcma | Self::G722 => Some(8_000),
            Self::AacLc { sample_rate, .. } => Some(*sample_rate),
            Self::Unsupported { .. } => None,
        }
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

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: Some([0x64, 0x00, 0x28]),
            sps: None,
            pps: None,
        }
    }

    #[test]
    fn kinds_and_families_follow_the_codec_matrix() {
        let cases: [(Codec, Kind, CodecFamily, &str, Option<u32>); 9] = [
            (h264(), Kind::Video, CodecFamily::H264, "h264", Some(90_000)),
            (
                Codec::H265 {
                    vps: None,
                    sps: None,
                    pps: None,
                },
                Kind::Video,
                CodecFamily::H265,
                "h265",
                Some(90_000),
            ),
            (
                Codec::Opus { channels: 2 },
                Kind::Audio,
                CodecFamily::Opus,
                "opus",
                Some(48_000),
            ),
            (
                Codec::Pcmu,
                Kind::Audio,
                CodecFamily::Pcmu,
                "pcmu",
                Some(8_000),
            ),
            (
                Codec::Pcma,
                Kind::Audio,
                CodecFamily::Pcma,
                "pcma",
                Some(8_000),
            ),
            (
                Codec::G722,
                Kind::Audio,
                CodecFamily::G722,
                "g722",
                Some(8_000),
            ),
            (
                Codec::AacLc {
                    sample_rate: 16_000,
                    channels: 1,
                    config: Bytes::from_static(&[0x14, 0x08]),
                },
                Kind::Audio,
                CodecFamily::AacLc,
                "aac_lc",
                Some(16_000),
            ),
            (
                Codec::Mjpeg,
                Kind::Video,
                CodecFamily::Mjpeg,
                "mjpeg",
                Some(90_000),
            ),
            (
                Codec::Unsupported {
                    kind: Kind::Audio,
                    name: "aac_he".into(),
                },
                Kind::Audio,
                CodecFamily::Unsupported,
                "aac_he",
                None,
            ),
        ];
        for (codec, kind, family, name, clock_rate) in cases {
            assert_eq!(codec.kind(), kind, "{codec:?}");
            assert_eq!(codec.family(), family, "{codec:?}");
            assert_eq!(codec.name(), name, "{codec:?}");
            assert_eq!(codec.rtp_clock_rate(), clock_rate, "{codec:?}");
            assert_eq!(codec.is_supported(), family != CodecFamily::Unsupported);
        }
    }

    #[test]
    fn g722_rtp_clock_is_8000_rfc3551_4_5_2() {
        assert_eq!(Codec::G722.rtp_clock_rate(), Some(8_000));
    }

    #[test]
    fn names_display() {
        assert_eq!(Kind::Video.to_string(), "video");
        assert_eq!(Kind::Audio.letter(), 'a');
        assert_eq!(CodecFamily::AacLc.to_string(), "aac_lc");
        assert_eq!(CodecFamily::Unsupported.name(), "unsupported");
    }

    #[test]
    fn parameters_do_not_change_the_family() {
        let other = Codec::H264 {
            profile_level_id: Some([0x42, 0xe0, 0x1f]),
            sps: Some(Bytes::from_static(&[0x67])),
            pps: None,
        };
        assert_ne!(h264(), other);
        assert_eq!(h264().family(), other.family());
    }
}

//! H.264 video negotiation: the engine's entries, the offered payload
//! types and the one the session sends under (RFC 6184 §8.1
//! `profile-level-id` and `packetization-mode`, §8.2.2 offer/answer).

use std::collections::VecDeque;

use lotse_core::codec::Codec;
use lotse_core::session::{SessionEvent, SessionOpenError, SessionOutput};
use str0m::Rtc;
use str0m::format::{Codec as EngineCodec, CodecConfig};
use str0m::media::Pt;

use super::offered_video;

/// The `profile_idc` of a `profile-level-id`.
fn profile_idc(profile_level_id: u32) -> u8 {
    u8::try_from((profile_level_id >> 16) & 0xff).unwrap_or(0)
}

/// The constraint flags (`profile-iop`, RFC 6184 §8.1) of a
/// `profile-level-id`: `0x0c` makes High Constrained High, `0xe0` or
/// `0x40` Baseline Constrained Baseline.
fn profile_iop(profile_level_id: u32) -> u8 {
    u8::try_from((profile_level_id >> 8) & 0xff).unwrap_or(0)
}

/// Constrained High, level 3.1 (ISO/IEC 14496-10 A.2.11): the profile
/// Safari offers for High, which str0m's default list does not match.
const CONSTRAINED_HIGH: u32 = 0x64_0c_1f;

/// The local payload type of [`CONSTRAINED_HIGH`]; the answer uses the
/// offer's number, so any free one does.
const CONSTRAINED_HIGH_PT: u8 = 112;

/// Its RTX payload type.
const CONSTRAINED_HIGH_RTX_PT: u8 = 113;

/// One H.264 payload type of the offer's video m-line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfferedH264 {
    /// The payload type number.
    pub(crate) pt: u8,
    /// `packetization-mode`, 0 when absent (RFC 6184 §8.1).
    pub(crate) packetization_mode: u8,
    /// `profile-level-id`, Baseline 1.0 when absent (RFC 6184 §8.1).
    pub(crate) profile_level_id: u32,
}

/// The H.264 payload types the first video m-line offers, from its
/// `rtpmap` and `fmtp` lines (RFC 8866 §6.6, RFC 6184 §8.1).
pub(crate) fn offered(sdp: &str) -> Vec<OfferedH264> {
    offered_video(sdp)
        .into_iter()
        .filter(|entry| entry.is("H264/90000"))
        .map(|entry| {
            let mut offered = OfferedH264 {
                pt: entry.pt,
                packetization_mode: 0,
                profile_level_id: 0x42_00_0a,
            };
            for (key, value) in entry.params {
                match key {
                    "packetization-mode" => {
                        offered.packetization_mode = value.parse().unwrap_or(0);
                    }
                    "profile-level-id" => {
                        offered.profile_level_id =
                            u32::from_str_radix(value, 16).unwrap_or(offered.profile_level_id);
                    }
                    _ => {}
                }
            }
            offered
        })
        .collect()
}

/// The `profile-level-id` the stream's codec reports, as str0m's u32.
fn stream_profile_level_id(codec: &Codec) -> Option<u32> {
    match codec {
        Codec::H264 {
            profile_level_id: Some([p, c, l]),
            ..
        } => Some((u32::from(*p) << 16) | (u32::from(*c) << 8) | u32::from(*l)),
        _ => None,
    }
}

/// How the session means to send an H.264 stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Plan {
    /// RFC 6184 §8.1 `profile-level-id` of the stream as a number, when
    /// known.
    pub(crate) profile_level_id: Option<u32>,
}

impl Plan {
    /// The plan for an H.264 stream's codec.
    pub(crate) fn for_codec(codec: &Codec) -> Self {
        Self {
            profile_level_id: stream_profile_level_id(codec),
        }
    }

    /// The payload type the answer sends the video under, with the
    /// `h264_profile_mismatch` warning when it applies, or
    /// `video_codec_unsupported` when the offer has none to send under.
    pub(crate) fn negotiate(
        self,
        rtc: &Rtc,
        offer: &str,
        pending: &mut VecDeque<SessionOutput>,
    ) -> Result<Pt, SessionOpenError> {
        let (pt, mismatch) = choose_pt(rtc, offer, self.profile_level_id).ok_or_else(|| {
            SessionOpenError::VideoCodecUnsupported(
                "no offered h264 payload type with packetization-mode=1".to_owned(),
            )
        })?;
        if mismatch {
            pending.push_back(SessionOutput::Event(SessionEvent::Warning {
                code: "h264_profile_mismatch",
                message: format!(
                    "stream profile-level-id {:06x} exceeds every offered profile; sent under payload type {} (SPEC-DEVIATION, RFC 6184 §8.2.2)",
                    self.profile_level_id.unwrap_or(0),
                    *pt
                ),
            }));
        }
        Ok(pt)
    }
}

/// The engine's H.264 entries.
pub(crate) fn configure(codecs: &mut CodecConfig) {
    // str0m's H.264 list: Baseline, Constrained Baseline, Main and High,
    // packetization modes 0 and 1; it matches an offered payload type by
    // profile and scores the level distance, so a stream's exact level
    // needs no entry of its own (and a second entry of a profile str0m
    // already lists makes it lock one offered payload type twice).
    codecs.enable_h264(true);
    // Constrained High, which str0m's list lacks and Safari offers instead
    // of plain High (observed 2026-09-30): without it a High camera went
    // out under Safari's Constrained Baseline payload type.
    codecs.add_h264(
        CONSTRAINED_HIGH_PT.into(),
        Some(CONSTRAINED_HIGH_RTX_PT.into()),
        true,
        CONSTRAINED_HIGH,
    );
}

/// The offered H.264 payload type to send under: `packetization-mode=1`,
/// the stream's `profile-level-id` profile and constraints first, then its
/// profile under other constraints (High as Constrained High, RFC 6184
/// §8.1 `profile-iop`), then a higher profile, then the highest offered,
/// among those the engine matched. Returns the payload type and whether
/// the stream's profile exceeds it.
fn choose_pt(rtc: &Rtc, offer: &str, stream_plid: Option<u32>) -> Option<(Pt, bool)> {
    let matched = |pt: u8| {
        rtc.codec_config()
            .params()
            .iter()
            .any(|params| *params.pt() == pt && params.spec().codec == EngineCodec::H264)
    };
    let mut ranked: Vec<(u8, u8, u8)> = offered(offer)
        .into_iter()
        .filter(|entry| entry.packetization_mode == 1 && matched(entry.pt))
        .map(|entry| {
            let idc = profile_idc(entry.profile_level_id);
            let score = match stream_plid {
                Some(stream)
                    if idc == profile_idc(stream)
                        && profile_iop(entry.profile_level_id) == profile_iop(stream) =>
                {
                    4
                }
                Some(stream) if idc == profile_idc(stream) => 3,
                Some(stream) if idc > profile_idc(stream) => 2,
                Some(_) => 1,
                None => 2,
            };
            (score, idc, entry.pt)
        })
        .collect();
    ranked.sort_unstable_by(|a, b| b.cmp(a));
    ranked
        .first()
        .map(|&(score, _, pt)| (Pt::from(pt), score == 1))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use lotse_core::session::SessionRequest;
    use str0m::change::SdpOffer;

    use super::*;
    use crate::install_crypto_provider;

    #[test]
    fn rfc6184_8_1_the_payload_type_follows_profile_then_constraints_then_a_higher_profile() {
        use lotse_core::clock::{Clock as _, SystemClock};
        use std::fmt::Write as _;

        use lotse_core::session::{IceCredentials, SessionLimits};

        let now = SystemClock.now();
        install_crypto_provider();
        let viewer = lotse_testing::Viewer::new("192.0.2.20:40000".parse().unwrap(), now).unwrap();
        // High, Constrained High, Main and Constrained Baseline, the
        // constrained forms at the lower payload types so a tie by number
        // never hides the ranking.
        let mut codecs = String::new();
        for (pt, plid) in [
            (102, "640c1f"),
            (104, "64001f"),
            (106, "42e01f"),
            (108, "4d001f"),
        ] {
            write!(codecs, "a=rtpmap:{pt} H264/90000\na=fmtp:{pt} level-asymmetry-allowed=1;packetization-mode=1;profile-level-id={plid}\n").unwrap();
        }
        // High in packetization mode 0 at the highest number, which the
        // engine matches too: never sent under (RFC 6184 §6.2, single NAL
        // units only).
        codecs.push_str("a=rtpmap:110 H264/90000\na=fmtp:110 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=64001f\n");
        // High 10, the highest profile, which the engine does not match:
        // never sent under either.
        codecs.push_str("a=rtpmap:114 H264/90000\na=fmtp:114 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=6e001f\n");
        let offer = lotse_testing::viewer::with_video_codecs(viewer.offer(), &codecs);
        let request = SessionRequest {
            offer: offer.clone(),
            ice: IceCredentials {
                ufrag: "ufrag".into(),
                pass: "passwordpasswordpassword".into(),
            },
            candidates: vec![],
            tcp_candidates: vec![],
            video: std::sync::Arc::new(Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            }),
            audio: None,
            backchannel: None,
            orientation: lotse_core::Orientation::default(),
            limits: SessionLimits::default(),
            wall: std::time::SystemTime::UNIX_EPOCH,
        };
        let video = super::super::VideoPlan::for_codec(&request.video).unwrap();
        let mut rtc =
            crate::session::build_config(&request, &video, &crate::audio::EVERY_CODEC).build(now);
        rtc.sdp_api()
            .accept_offer(SdpOffer::from_sdp_string(&offer).unwrap())
            .unwrap();
        let pick =
            |plid: Option<u32>| choose_pt(&rtc, &offer, plid).map(|(pt, mismatch)| (*pt, mismatch));
        // The same profile with the same constraints.
        assert_eq!(pick(Some(0x64_00_33)), Some((104, false)), "High");
        assert_eq!(
            pick(Some(0x64_0c_28)),
            Some((102, false)),
            "Constrained High"
        );
        assert_eq!(pick(Some(0x4d_00_29)), Some((108, false)), "Main");
        // The same profile under other constraints beats a higher one.
        assert_eq!(
            pick(Some(0x4d_40_29)),
            Some((108, false)),
            "Main, constrained"
        );
        // A higher profile when the stream's is not offered: Extended (88)
        // under High.
        assert_eq!(pick(Some(0x58_00_29)), Some((104, false)), "Extended");
        // Only lower profiles: the highest, flagged.
        assert_eq!(pick(Some(0x6e_00_33)), Some((104, true)), "High 10");
        // Unknown: the highest, not flagged.
        assert_eq!(pick(None), Some((104, false)));
        assert_eq!(profile_iop(0x64_0c_1f), 0x0c);
        assert_eq!(profile_idc(0x64_0c_1f), 0x64);
    }

    #[test]
    fn profile_helpers_read_the_stream_codec() {
        assert_eq!(profile_idc(0x64_00_28), 100);
        let codec = Codec::H264 {
            profile_level_id: Some([0x42, 0xc0, 0x28]),
            sps: None,
            pps: None,
        };
        assert_eq!(stream_profile_level_id(&codec), Some(0x42_c0_28));
        assert_eq!(stream_profile_level_id(&Codec::Pcmu), None);
        let sdp = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 97 98\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=64001f\r\na=rtpmap:97 h264/90000\r\na=rtpmap:98 VP8/90000\r\na=fmtp:99 packetization-mode=1\r\nm=video 9 UDP/TLS/RTP/SAVPF 100\r\na=rtpmap:100 H264/90000\r\n";
        assert_eq!(
            offered(sdp),
            [
                OfferedH264 {
                    pt: 96,
                    packetization_mode: 1,
                    profile_level_id: 0x64_00_1f
                },
                OfferedH264 {
                    pt: 97,
                    packetization_mode: 0,
                    profile_level_id: 0x42_00_0a
                },
            ]
        );
    }
}

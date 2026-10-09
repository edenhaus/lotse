//! Video negotiation, one module per codec: what the session lists to the
//! engine for the stream's video, which offered payload type it sends
//! under, and whether a later codec change still fits that type.
//!
//! The session only dispatches: [`VideoPlan::for_codec`] reads the stream,
//! [`VideoPlan::configure`] lists the engine's entries,
//! [`VideoPlan::negotiate`] picks the payload type once the engine took the
//! offer, and the [`NegotiatedVideo`] it returns packetizes the join and
//! judges codec changes. A new codec is a module, a variant of each enum
//! and their match arms. Standards: RFC 8866 §6.6 and §6.15 (`rtpmap` and
//! `fmtp`, read once by [`offered_video`]), RFC 6184 §8.1 and §8.2.2
//! ([`h264`]), RFC 7798 §7.1 and §7.2.2 with ITU-T H.265 §7.4.4 and A.4.1
//! ([`h265`]).

pub(crate) mod h264;
pub(crate) mod h265;

use std::collections::VecDeque;

use lotse_core::codec::Codec;
use lotse_core::session::{SessionOpenError, SessionOutput};
use str0m::Rtc;
use str0m::format::CodecConfig;
use str0m::media::Pt;

use crate::sdp::{Sdp, Section};
use crate::writer::Packetizer;

/// One payload type of the offer's first video m-line: its `rtpmap`
/// encoding and the `key=value` parameters of its `fmtp`, in their order
/// (RFC 8866 §6.6, §6.15). Each codec module reads its own parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OfferedPt<'a> {
    /// The payload type number.
    pub(crate) pt: u8,
    /// The `rtpmap` encoding, `name/clock` as written.
    pub(crate) encoding: &'a str,
    /// The `fmtp` parameters, trimmed keys, values as written; a
    /// parameter without `=` is left out.
    pub(crate) params: Vec<(&'a str, &'a str)>,
}

impl OfferedPt<'_> {
    /// Whether the encoding is `encoding` (`name/clock`), compared
    /// case-insensitively (RFC 4855 §3).
    pub(crate) fn is(&self, encoding: &str) -> bool {
        self.encoding.eq_ignore_ascii_case(encoding)
    }
}

/// The payload types the first video m-line offers, in the order of their
/// `rtpmap` lines, each with the parameters of the `fmtp` lines that
/// follow it for its number; an `fmtp` before or without its `rtpmap` is
/// ignored.
pub(crate) fn offered_video(sdp: &str) -> Vec<OfferedPt<'_>> {
    let sdp = Sdp::parse(sdp);
    let mut offered: Vec<OfferedPt<'_>> = Vec::new();
    for &line in sdp.first("video").map_or(&[][..], Section::lines) {
        if let Some(rest) = line.strip_prefix("a=rtpmap:")
            && let Some((pt, encoding)) = rest.split_once(' ')
            && let Ok(pt) = pt.parse()
        {
            offered.push(OfferedPt {
                pt,
                encoding,
                params: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("a=fmtp:")
            && let Some((pt, params)) = rest.split_once(' ')
            && let Ok(pt) = pt.parse::<u8>()
            && let Some(entry) = offered.iter_mut().find(|entry| entry.pt == pt)
        {
            entry.params.extend(
                params
                    .split(';')
                    .filter_map(|param| param.trim().split_once('=')),
            );
        }
    }
    offered
}

/// How the session means to send the stream's video, before the engine
/// saw the offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VideoPlan {
    /// H.264.
    H264(h264::Plan),
    /// H.265, under the profiles and tier the stream fits.
    H265(h265::Plan),
}

impl VideoPlan {
    /// The plan for the stream's video codec, or why it cannot be sent.
    pub(crate) fn for_codec(codec: &Codec) -> Result<Self, SessionOpenError> {
        match codec {
            Codec::H264 { .. } => Ok(Self::H264(h264::Plan::for_codec(codec))),
            Codec::H265 { sps, .. } => Ok(Self::H265(h265::Plan::for_sps(sps.as_deref()))),
            other => Err(SessionOpenError::VideoCodecUnsupported(format!(
                "stream video is {}; only h264 and h265 are negotiated",
                other.name()
            ))),
        }
    }

    /// Lists the engine's video entries for this plan; `offer` is the
    /// browser's, which H.265 reads to pick each entry's tier.
    pub(crate) fn configure(&self, codecs: &mut CodecConfig, offer: &str) {
        match self {
            Self::H264(_) => h264::configure(codecs),
            Self::H265(plan) => plan.configure(codecs, offer),
        }
    }

    /// The offered payload type the session sends under, once the engine
    /// accepted `offer`, or `video_codec_unsupported` when there is none;
    /// a warning the choice calls for goes to `pending`.
    pub(crate) fn negotiate(
        &self,
        rtc: &Rtc,
        offer: &str,
        pending: &mut VecDeque<SessionOutput>,
    ) -> Result<NegotiatedVideo, SessionOpenError> {
        match self {
            Self::H264(plan) => Ok(NegotiatedVideo::H264 {
                pt: plan.negotiate(rtc, offer, pending)?,
            }),
            Self::H265(plan) => Ok(NegotiatedVideo::H265 {
                chosen: plan.negotiate(rtc, offer)?,
            }),
        }
    }
}

/// The video the answer negotiated: the payload type the session sends
/// under, with what of the offer binds the stream's later changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NegotiatedVideo {
    /// H.264 under `pt`, whatever the stream's profile (RFC 6184 §8.2.2
    /// deviation).
    H264 {
        /// The payload type.
        pt: Pt,
    },
    /// H.265 under the offered payload type `chosen`, whose profile and
    /// tier a new SPS must still fit.
    H265 {
        /// The offered payload type, with its `profile-id` and `tier-flag`.
        chosen: h265::OfferedH265,
    },
}

impl NegotiatedVideo {
    /// The payload type the session sends under.
    pub(crate) fn pt(self) -> Pt {
        match self {
            Self::H264 { pt } => pt,
            Self::H265 { chosen } => Pt::from(chosen.pt),
        }
    }

    /// The codec's name, as the API spells it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::H264 { .. } => "h264",
            Self::H265 { .. } => "h265",
        }
    }

    /// The packetizer of the join's frames: RFC 6184's for H.264, RFC
    /// 7798's for H.265.
    pub(crate) fn packetizer(self) -> Packetizer {
        match self {
            Self::H264 { .. } => lotse_codec::h264::packetize,
            Self::H265 { .. } => lotse_codec::h265::packetize,
        }
    }

    /// Whether the video can go on under the negotiated payload type now
    /// that the track's codec changed to `codec` within its family: the
    /// rule that chose the type, applied to the new codec. H.264 goes on
    /// whatever the change, as it is answered whatever its profile; H.265
    /// only while its new SPS fits ([`h265::check_change`]).
    pub(crate) fn check_change(self, codec: &Codec) -> Result<(), String> {
        match self {
            Self::H264 { .. } => Ok(()),
            Self::H265 { chosen } => h265::check_change(chosen, codec),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    #[test]
    fn the_video_plan_follows_the_stream_codec_and_packetizes_for_it() {
        use lotse_codec::h265::test_data;

        let sps = test_data::sps_of(2, 640, 480);
        let h265 = |sps: Option<Vec<u8>>| Codec::H265 {
            vps: None,
            sps: sps.map(Into::into),
            pps: None,
        };
        assert_eq!(
            VideoPlan::for_codec(&h265(Some(sps))).unwrap(),
            VideoPlan::H265(h265::Plan {
                profiles: vec![2],
                high_tier: false,
                level_id: Some(test_data::LEVEL_IDC),
            })
        );
        // The SPS's general_tier_flag (ITU-T H.265 §7.4.4).
        let high = test_data::sps_of_tier(1, true, 640, 480);
        assert_eq!(
            VideoPlan::for_codec(&h265(Some(high))).unwrap(),
            VideoPlan::H265(h265::Plan {
                profiles: vec![1, 2],
                high_tier: true,
                level_id: Some(test_data::LEVEL_IDC),
            })
        );
        // An SPS that does not parse: what cameras send, the Main tier.
        let plan = VideoPlan::for_codec(&h265(Some(vec![0x40, 0x01]))).unwrap();
        assert_eq!(
            plan,
            VideoPlan::H265(h265::Plan {
                profiles: vec![1, 2],
                high_tier: false,
                level_id: None,
            })
        );
        let mjpeg = VideoPlan::for_codec(&Codec::Mjpeg);
        assert!(
            matches!(&mjpeg, Err(SessionOpenError::VideoCodecUnsupported(message)) if message == "stream video is mjpeg; only h264 and h265 are negotiated"),
            "{mjpeg:?}"
        );
        // A unit over the payload size: RFC 7798 fragmentation units for
        // H.265 (§4.4.3), RFC 6184 FU-A for H.264 (§5.8).
        let mut idr = vec![0, 0, 0, 1, 0x26, 0x01];
        idr.resize(3_000, 0xab);
        let h265 = NegotiatedVideo::H265 {
            chosen: h265::OfferedH265 {
                pt: 49,
                profile_id: 1,
                tier_flag: 0,
                level_id: 93,
            },
        };
        assert_eq!(h265.pt(), Pt::from(49));
        let payloads = (h265.packetizer())(&idr, 1_200);
        assert!(payloads.len() > 2);
        assert_eq!(lotse_codec::h265::nal::nal_type(payloads[0][0]), 49);
        let h264 = VideoPlan::for_codec(&Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        })
        .unwrap();
        assert_eq!(
            h264,
            VideoPlan::H264(h264::Plan {
                profile_level_id: None
            })
        );
        let h264 = NegotiatedVideo::H264 { pt: Pt::from(96) };
        assert_eq!(h264.pt(), Pt::from(96));
        let payloads = (h264.packetizer())(&idr, 1_200);
        assert_eq!(payloads[0][0] & 0x1f, 28);
        assert_eq!((h264.name(), h265.name()), ("h264", "h265"));
    }
}

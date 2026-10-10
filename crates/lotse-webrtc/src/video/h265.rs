//! H.265 video negotiation: the profiles and tier a stream may go under,
//! the engine's entries, the offered payload types, the one the session
//! sends under and whether a new SPS still fits it (RFC 7798 §7.1
//! `profile-id`, `tier-flag` and `level-id`, §7.2.2 offer/answer; ITU-T
//! H.265 §7.4.4 profile compatibility and A.4.1 tiers).

use lotse_codec::h265::SpsInfo;
use lotse_core::codec::Codec;
use lotse_core::session::SessionOpenError;
use str0m::Rtc;
use str0m::format::{Codec as EngineCodec, CodecConfig, PayloadParams};

use super::offered_video;

/// The `level-id` of every local H.265 entry: level 6.0 (ITU-T H.265
/// A.4.1, `level-id` 180), str0m's own; str0m answers the lower of it and
/// the offered level.
pub(crate) const LEVEL_ID: u8 = 180;

/// The local payload types of the H.265 entries, one pair (the type and
/// its RTX) per profile the stream may be sent under, each in one tier;
/// the answer uses the offer's numbers, so any free ones do.
pub(crate) const PTS: [(u8, u8); 3] = [(114, 115), (116, 117), (118, 119)];

/// The highest `profile-id` str0m 0.24 knows (Annex A: SCC extensions'
/// high throughput 4:4:4, 11); an entry of another would claim Main.
const MAX_PROFILE: u8 = 11;

/// How the session means to send an H.265 stream: under one of these
/// profiles (`profile-id`, RFC 7798 §7.1), the preferred first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The profiles, at most [`PTS`] of them.
    pub(crate) profiles: Vec<u8>,
    /// `general_tier_flag` of the stream's SPS: the High tier, which
    /// only a High tier payload type takes (ITU-T H.265 A.4.1). An
    /// unknown SPS counts as the Main tier, what cameras send.
    pub(crate) high_tier: bool,
    /// `general_level_idc` of the stream's SPS, when known.
    pub(crate) level_id: Option<u8>,
}

impl Plan {
    /// The plan for a stream with this SPS, if any; one that does not
    /// parse counts as unknown.
    pub(crate) fn for_sps(sps: Option<&[u8]>) -> Self {
        let info = sps.and_then(|sps| lotse_codec::h265::parse_sps(sps).ok());
        Self {
            profiles: profiles(info.as_ref()),
            high_tier: info.is_some_and(|info| info.high_tier),
            level_id: info.map(|info| info.level_idc),
        }
    }

    /// The engine's H.265 entries: one per profile, in the tier
    /// [`entry_tier`] picks from `offer`.
    pub(crate) fn configure(&self, codecs: &mut CodecConfig, offer: &str) {
        // str0m matches an offered payload type only with the same profile
        // and tier, and answers the lower of the two levels (RFC 7798
        // §7.2.2).
        let offered = offered(offer);
        for (&profile, &(pt, rtx)) in self.profiles.iter().zip(&PTS) {
            let tier = entry_tier(self.high_tier, profile, &offered);
            codecs.add_h265(pt.into(), Some(rtx.into()), profile, tier, LEVEL_ID);
        }
    }

    /// The offered payload type the session sends under, or
    /// `video_codec_unsupported` when the offer has none in a profile and
    /// tier the stream fits.
    pub(crate) fn negotiate(
        &self,
        rtc: &Rtc,
        offer: &str,
    ) -> Result<OfferedH265, SessionOpenError> {
        let chosen = choose_pt(rtc, offer, &self.profiles, self.high_tier).ok_or_else(|| {
            SessionOpenError::VideoCodecUnsupported(format!(
                "no offered h265 payload type with profile-id in {:?}{}",
                self.profiles,
                if self.high_tier {
                    " and tier-flag=1"
                } else {
                    ""
                }
            ))
        })?;
        let offered_level = chosen.level_id;
        tracing::debug!(
            pt = chosen.pt,
            profile_id = chosen.profile_id,
            tier_flag = chosen.tier_flag,
            high_tier = self.high_tier,
            "h265 payload type chosen"
        );
        if let Some(level_id) = level_above(self.level_id, offered_level) {
            // SPEC-DEVIATION(RFC 7798 §7.2.2): the stream's level is
            // above the one the answer signals; sent anyway, as H.264
            // streams are sent regardless of their level; gate:
            // rfc7798_7_2_2_a_level_above_the_offer_is_sent_anyway.
            tracing::info!(
                pt = chosen.pt,
                level_id,
                offered_level,
                "h265 stream level above the offered level-id; sent anyway"
            );
        }
        Ok(chosen)
    }
}

/// The H.265 profiles a stream may be sent under, its own first: the
/// profile of its SPS, then Main and Main 10 where its compatibility
/// flags say it conforms to them (ITU-T H.265 §7.4.4; a Main stream
/// normally flags Main 10 too, A.3.2). Without a known SPS, Main, then
/// Main 10: what cameras send. Profiles str0m does not know are left out.
fn profiles(info: Option<&SpsInfo>) -> Vec<u8> {
    let Some(info) = info else {
        return vec![1, 2];
    };
    let mut profiles = vec![info.profile_idc];
    profiles.extend(
        [1, 2]
            .into_iter()
            .filter(|&p| p != info.profile_idc && info.conforms_to(p)),
    );
    profiles.retain(|&p| (1..=MAX_PROFILE).contains(&p));
    profiles
}

/// One H.265 payload type of the offer's video m-line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfferedH265 {
    /// The payload type number.
    pub(crate) pt: u8,
    /// `profile-id`, Main (1) when absent (RFC 7798 §7.1).
    pub(crate) profile_id: u8,
    /// `tier-flag`, the Main tier (0) when absent (RFC 7798 §7.1).
    pub(crate) tier_flag: u8,
    /// `level-id`, 93 (level 3.1) when absent (RFC 7798 §7.1).
    pub(crate) level_id: u8,
}

/// The H.265 payload types the first video m-line offers, from its
/// `rtpmap` and `fmtp` lines (RFC 8866 §6.6, RFC 7798 §7.1). A value that
/// is no number keeps the default.
pub(crate) fn offered(sdp: &str) -> Vec<OfferedH265> {
    offered_video(sdp)
        .into_iter()
        .filter(|entry| entry.is("H265/90000"))
        .map(|entry| {
            let mut offered = OfferedH265 {
                pt: entry.pt,
                profile_id: 1,
                tier_flag: 0,
                level_id: 93,
            };
            for (key, value) in entry.params {
                match key {
                    "profile-id" => {
                        offered.profile_id = value.parse().unwrap_or(offered.profile_id);
                    }
                    "tier-flag" => {
                        offered.tier_flag = value.parse().unwrap_or(offered.tier_flag);
                    }
                    "level-id" => {
                        offered.level_id = value.parse().unwrap_or(offered.level_id);
                    }
                    _ => {}
                }
            }
            offered
        })
        .collect()
}

/// The `tier-flag` of the session's one entry for `profile`: the High
/// tier (1) for a High tier stream, which only a High tier decoder takes,
/// and for a Main tier stream when the offer lists `profile` in no Main
/// tier payload type, since a High tier decoder decodes Main tier streams
/// too (ITU-T H.265 A.4.1: the Main tier is the lower one; RFC 7798 §7.1
/// calls the Main tier stream consistent with the High tier type). The
/// Main tier (0) otherwise.
///
/// One entry per profile, never two in different tiers: str0m 0.24 matches
/// an offered type that lacks one of `profile-id`, `tier-flag` and
/// `level-id` by profile alone, and two entries of its profile would both
/// lock it, which panics (an open str0m issue).
fn entry_tier(high_tier: bool, profile: u8, offered: &[OfferedH265]) -> u8 {
    let main_offered = offered
        .iter()
        .any(|entry| entry.profile_id == profile && entry.tier_flag == 0);
    u8::from(high_tier || !main_offered)
}

/// The `profile-id` and `tier-flag` the answer states for an H.265 payload
/// type the engine matched: those of the `fmtp` str0m writes for it, or
/// where it writes none, the RFC 7798 §7.1 defaults (Main, Main tier).
fn answered(params: &PayloadParams) -> (u8, u8) {
    let format = &params.spec().format;
    match format.h265_profile_tier_level {
        Some(ptl) => (ptl.profile_id(), ptl.tier_flag()),
        None => (
            format
                .profile_id
                .and_then(|profile| u8::try_from(profile).ok())
                .unwrap_or(1),
            0,
        ),
    }
}

/// The offered H.265 payload type to send under: among those the engine
/// matched, the one whose `profile-id` comes first in `profiles`, then the
/// first offered. RFC 7798 §7.2.2 has the answer keep the offered profile and tier, which
/// the engine only matches when the profile is one of `profiles`. A High
/// tier stream goes only under a High tier type (ITU-T H.265 A.4.1). A
/// type whose answer would not keep the offered profile and tier is passed
/// over: str0m 0.24 reads an `fmtp` with `tier-flag` or `level-id` but not
/// all three it knows as none, matches it as Main and answers it without
/// one (an open str0m issue). Returns the offered type.
fn choose_pt(rtc: &Rtc, offer: &str, profiles: &[u8], high_tier: bool) -> Option<OfferedH265> {
    let params = rtc.codec_config().params();
    offered(offer)
        .into_iter()
        .filter_map(|entry| {
            let matched = params.iter().find(|params| {
                *params.pt() == entry.pt && params.spec().codec == EngineCodec::H265
            })?;
            if answered(matched) != (entry.profile_id, entry.tier_flag)
                || (high_tier && entry.tier_flag == 0)
            {
                return None;
            }
            let rank = profiles.iter().position(|&p| p == entry.profile_id)?;
            Some((rank, entry))
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, entry)| entry)
}

/// Whether an H.265 stream of `info` may go on under the negotiated
/// payload type `pt`: the rule that chose `pt` in the answer, applied to a
/// new SPS. The stream conforms to its profile (ITU-T H.265 §7.4.4) and,
/// in the High tier, needs a High tier type (A.4.1); `Err` says why not.
fn fits(info: &SpsInfo, pt: OfferedH265) -> Result<(), String> {
    if info.conforms_to(pt.profile_id) && (!info.high_tier || pt.tier_flag == 1) {
        return Ok(());
    }
    Err(format!(
        "h265 is now profile-id {} in the {} tier, outside payload type {} (profile-id {}, tier-flag {})",
        info.profile_idc,
        if info.high_tier { "high" } else { "main" },
        pt.pt,
        pt.profile_id,
        pt.tier_flag
    ))
}

/// Whether the stream may go on under the negotiated `pt` now that its
/// codec is `codec` ([`fits`]); a codec without an SPS, or one that does
/// not parse, cannot be judged and goes on.
pub(crate) fn check_change(pt: OfferedH265, codec: &Codec) -> Result<(), String> {
    let Codec::H265 { sps: Some(sps), .. } = codec else {
        return Ok(());
    };
    lotse_codec::h265::parse_sps(sps).map_or(Ok(()), |info| fits(&info, pt))
}

/// The stream's `level-id` when it is above `offered`, the level the
/// answer signals (RFC 7798 §7.2.2 has the sender stay within it).
fn level_above(level_id: Option<u8>, offered: u8) -> Option<u8> {
    level_id.filter(|&level| level > offered)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use lotse_core::session::SessionRequest;
    use str0m::change::SdpOffer;

    use super::*;
    use str0m::IceCreds;

    use crate::install_crypto_provider;

    /// An H.265 stream of profile `profile_idc` with `compatibility`
    /// flags, at level 4.0.
    fn h265_info(profile_idc: u8, compatibility: u32) -> SpsInfo {
        SpsInfo {
            profile_space: 0,
            high_tier: false,
            profile_idc,
            compatibility,
            level_idc: 120,
            width: 640,
            height: 480,
        }
    }

    #[test]
    fn rfc7798_7_1_offered_h265_payload_types_read_profile_tier_and_level_with_defaults() {
        let sdp = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 H265/90000\r\nm=video 9 UDP/TLS/RTP/SAVPF 49 51 53 55\r\na=rtpmap:49 H265/90000\r\na=fmtp:49 level-id=180;profile-id=1;tier-flag=1;tx-mode=SRST\r\na=rtpmap:51 h265/90000\r\na=fmtp:51 profile-id=2\r\na=rtpmap:53 H265/90000\r\na=fmtp:53 profile-id=x; level-id=999; tier-flag=high\r\na=rtpmap:55 H264/90000\r\na=fmtp:55 profile-id=2\r\na=fmtp:57 profile-id=2\r\nm=video 9 UDP/TLS/RTP/SAVPF 59\r\na=rtpmap:59 H265/90000\r\n";
        assert_eq!(
            offered(sdp),
            [
                OfferedH265 {
                    pt: 49,
                    profile_id: 1,
                    tier_flag: 1,
                    level_id: 180
                },
                // The Main tier and level 3.1 when absent (RFC 7798 §7.1).
                OfferedH265 {
                    pt: 51,
                    profile_id: 2,
                    tier_flag: 0,
                    level_id: 93
                },
                // What is no number keeps the default.
                OfferedH265 {
                    pt: 53,
                    profile_id: 1,
                    tier_flag: 0,
                    level_id: 93
                },
            ]
        );
        assert!(offered("v=0\r\n").is_empty());
    }

    #[test]
    fn h265_profiles_put_the_stream_first_then_main_and_main_10_it_conforms_to() {
        // Unknown: Main, then Main 10.
        assert_eq!(profiles(None), [1, 2]);
        // Main conforms to Main 10 (A.3.2) when its flag says so.
        assert_eq!(profiles(Some(&h265_info(1, 0x6000_0000))), [1, 2]);
        assert_eq!(profiles(Some(&h265_info(1, 0x4000_0000))), [1]);
        // Main 10 is no Main stream.
        assert_eq!(profiles(Some(&h265_info(2, 0x2000_0000))), [2]);
        // Range extensions flagged as Main: its own first.
        assert_eq!(profiles(Some(&h265_info(4, 0x4800_0000))), [4, 1]);
        // A profile str0m does not know is left out.
        assert_eq!(profiles(Some(&h265_info(11, 0x0010_0000))), [11]);
        assert_eq!(profiles(Some(&h265_info(12, 0x4008_0000))), [1]);
        assert!(profiles(Some(&h265_info(0, 0))).is_empty());
    }

    #[test]
    fn rfc7798_7_2_2_a_stream_level_counts_only_above_the_offer() {
        assert_eq!(level_above(Some(153), 93), Some(153));
        assert_eq!(level_above(Some(93), 93), None);
        assert_eq!(level_above(Some(90), 93), None);
        assert_eq!(level_above(None, 93), None);
    }

    #[test]
    fn itu_t_h265_a_4_1_an_entry_is_high_tier_for_a_high_stream_or_where_no_main_tier_is_offered() {
        let offered = |profile_id, tier_flag| OfferedH265 {
            pt: 49,
            profile_id,
            tier_flag,
            level_id: 153,
        };
        let main = [offered(1, 0), offered(2, 1), offered(4, 1)];
        // A Main tier stream: the Main tier where it is offered.
        assert_eq!(entry_tier(false, 1, &main), 0);
        // Only in the High tier: a High tier decoder decodes it too.
        assert_eq!(entry_tier(false, 2, &main), 1);
        assert_eq!(entry_tier(false, 4, &main), 1);
        // Not offered at all: nothing matches either entry.
        assert_eq!(entry_tier(false, 3, &main), 1);
        // A High tier stream needs a High tier decoder.
        assert_eq!(entry_tier(true, 1, &main), 1);
        assert_eq!(entry_tier(true, 2, &main), 1);
    }

    #[test]
    fn rfc7798_7_2_2_the_payload_type_follows_the_stream_profiles_and_tier_among_those_matched() {
        use lotse_core::clock::{Clock as _, SystemClock};
        use lotse_core::session::{IceCredentials, SessionLimits};

        let now = SystemClock.now();
        install_crypto_provider();
        let viewer = lotse_testing::Viewer::new("192.0.2.20:40000".parse().unwrap(), now).unwrap();
        // Main at the higher number, so the order of the offer never
        // decides; range extensions and Main also in the High tier, and
        // Main 10 in the High tier without a level-id, which str0m matches
        // by profile alone.
        let codecs = "a=rtpmap:49 H265/90000\na=fmtp:49 level-id=93;profile-id=2;tier-flag=0\na=rtpmap:51 H265/90000\na=fmtp:51 level-id=120;profile-id=1;tier-flag=0\na=rtpmap:53 H265/90000\na=fmtp:53 level-id=153;profile-id=4;tier-flag=1\na=rtpmap:55 H265/90000\na=fmtp:55 level-id=153;profile-id=1;tier-flag=1\na=rtpmap:57 H265/90000\na=fmtp:57 profile-id=2;tier-flag=1\n";
        let pick = |codecs: &str, profiles: &[u8], high_tier: bool| {
            let offer = lotse_testing::viewer::with_video_codecs(viewer.offer(), codecs);
            let request = SessionRequest {
                offer: offer.clone(),
                ice: IceCredentials {
                    ufrag: "ufrag".into(),
                    pass: "passwordpasswordpassword".into(),
                },
                candidates: vec![],
                tcp_candidates: vec![],
                video: std::sync::Arc::new(Codec::Mjpeg),
                audio: None,
                backchannel: None,
                orientation: lotse_core::Orientation::default(),
                limits: SessionLimits::default(),
                wall: std::time::SystemTime::UNIX_EPOCH,
            };
            let video = super::super::VideoPlan::H265(Plan {
                profiles: profiles.to_vec(),
                high_tier,
                level_id: None,
            });
            let mut rtc =
                crate::session::build_config(&request, &video, &crate::audio::EVERY_CODEC)
                    .build(now);
            rtc.sdp_api()
                .accept_offer(SdpOffer::from_sdp_string(&offer).unwrap())
                .unwrap();
            choose_pt(&rtc, &offer, profiles, high_tier)
                .map(|entry| (entry.pt, entry.tier_flag, entry.level_id))
        };
        assert_eq!(
            pick(codecs, &[1, 2], false),
            Some((51, 0, 120)),
            "Main first"
        );
        assert_eq!(
            pick(codecs, &[2, 1], false),
            Some((49, 0, 93)),
            "Main 10 first"
        );
        assert_eq!(pick(codecs, &[2], false), Some((49, 0, 93)));
        // Range extensions are offered only in the High tier, which takes
        // a Main tier stream (A.4.1).
        assert_eq!(pick(codecs, &[4], false), Some((53, 1, 153)));
        assert_eq!(pick(codecs, &[], false), None);
        // A High tier stream only under a High tier type.
        assert_eq!(pick(codecs, &[1, 2], true), Some((55, 1, 153)));
        // Main 10's High tier type would be answered without its tier-flag,
        // so it is passed over.
        assert_eq!(pick(codecs, &[2], true), None);
        // A type without fmtp is the Main tier (RFC 7798 §7.1), what Safari
        // offers: a Main tier stream only.
        let bare = "a=rtpmap:49 H265/90000\n";
        assert_eq!(pick(bare, &[1, 2], false), Some((49, 0, 93)));
        assert_eq!(pick(bare, &[1, 2], true), None);
    }

    #[test]
    fn rfc7798_7_2_2_str0m_0_24_matches_a_partial_fmtp_across_tiers_and_drops_its_tier() {
        use lotse_core::clock::{Clock as _, SystemClock};

        // The engine with two Main entries, Main and High tier, against an
        // offered Main 10 High tier type without a level-id: str0m reads
        // its fmtp as none, so the Main profile, and both entries lock it,
        // the "Pt locked multiple times" assert. The High tier entry alone
        // answers it without an fmtp line: Main, Main tier (RFC 7798
        // §7.1), not the offered profile and tier. When an str0m upgrade
        // fixes it, this test is to be inverted.
        let now = SystemClock.now();
        install_crypto_provider();
        let viewer = lotse_testing::Viewer::new("192.0.2.20:40000".parse().unwrap(), now).unwrap();
        let offer = lotse_testing::viewer::with_video_codecs(
            viewer.offer(),
            "a=rtpmap:49 H265/90000\na=fmtp:49 profile-id=2;tier-flag=1\n",
        );
        let config = |tiers: &[u8]| {
            let mut config = crate::session_config(IceCreds {
                ufrag: "ufrag".into(),
                pass: "passwordpasswordpassword".into(),
            })
            .clear_codecs();
            for (&tier, &(pt, rtx)) in tiers.iter().zip(&PTS) {
                config
                    .codec_config()
                    .add_h265(pt.into(), Some(rtx.into()), 1, tier, LEVEL_ID);
            }
            config
        };
        let panicked = std::panic::catch_unwind(|| {
            let mut rtc = config(&[0, 1]).build(now);
            let _answer = rtc
                .sdp_api()
                .accept_offer(SdpOffer::from_sdp_string(&offer).unwrap());
        })
        .unwrap_err();
        let message = panicked.downcast_ref::<String>().unwrap();
        assert_eq!(message, "Pt locked multiple times: 49");
        let mut rtc = config(&[1]).build(now);
        let answer = rtc
            .sdp_api()
            .accept_offer(SdpOffer::from_sdp_string(&offer).unwrap())
            .unwrap()
            .to_sdp_string();
        assert!(answer.contains("a=rtpmap:49 H265/90000"), "{answer}");
        assert!(!answer.contains("a=fmtp:49"), "{answer}");
    }
}

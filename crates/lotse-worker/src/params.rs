//! A track's codec parameters as the worker reports them for `stream/get`:
//! what its codec descriptor carries, and the picture size its sequence
//! parameter set says, read once per report through `lotse-codec`'s
//! parsers (the sources parse the same sets, so a set that reaches a
//! descriptor parsed once already).
//!
//! Implements RFC 6184 §8.1 (`profile-level-id`), ISO/IEC 14496-10
//! §7.4.2.1.1 and ITU-T H.265 §7.4.3.2.1 (the cropped picture size).

use lotse_codec::{h264, h265};
use lotse_core::codec::Codec;
use lotse_ipc::TrackParams;

/// What `codec` says about its track. The picture size is `None` while
/// the codec carries no SPS, or one that does not parse.
pub(crate) fn track_params(codec: &Codec) -> TrackParams {
    let (profile_level_id, picture) = match codec {
        Codec::H264 {
            profile_level_id,
            sps,
            ..
        } => (
            *profile_level_id,
            sps.as_deref()
                .and_then(|sps| h264::parse_sps(sps).ok())
                .map(|info| (info.width, info.height)),
        ),
        Codec::H265 { sps, .. } => (
            None,
            sps.as_deref()
                .and_then(|sps| h265::parse_sps(sps).ok())
                .map(|info| (info.width, info.height)),
        ),
        _ => (None, None),
    };
    TrackParams {
        profile_level_id,
        picture,
        sample_rate: codec.sample_rate(),
        channels: codec.channels(),
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

    #[test]
    fn rfc6184_8_1_an_h264_track_reports_its_profile_level_id_and_its_sps_picture() {
        let sps = h264::test_data::sps(1280, 720);
        let codec = Codec::H264 {
            profile_level_id: Some([0x42, 0xc0, 0x28]),
            sps: Some(sps.into()),
            pps: None,
        };
        assert_eq!(
            track_params(&codec),
            TrackParams {
                profile_level_id: Some([0x42, 0xc0, 0x28]),
                picture: Some((1280, 720)),
                sample_rate: None,
                channels: None,
            }
        );
    }

    #[test]
    fn h265_7_4_3_2_1_an_h265_track_reports_its_sps_picture_and_no_profile_level_id() {
        let codec = Codec::H265 {
            vps: None,
            sps: Some(h265::test_data::sps(1920, 1080).into()),
            pps: None,
        };
        assert_eq!(
            track_params(&codec),
            TrackParams {
                picture: Some((1920, 1080)),
                ..TrackParams::default()
            }
        );
    }

    #[test]
    fn a_video_track_without_a_readable_sps_has_no_picture_yet() {
        let unknown = [
            Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            },
            // A PPS where the SPS should be: not a sequence parameter set.
            Codec::H264 {
                profile_level_id: None,
                sps: Some(h264::test_data::pps().into()),
                pps: None,
            },
            Codec::H265 {
                vps: None,
                sps: None,
                pps: None,
            },
            Codec::H265 {
                vps: None,
                sps: Some(h265::test_data::pps().into()),
                pps: None,
            },
            Codec::Mjpeg,
        ];
        for codec in unknown {
            assert_eq!(track_params(&codec), TrackParams::default(), "{codec:?}");
        }
    }

    #[test]
    fn iso_14496_3_an_audio_track_reports_its_sample_rate_and_channels() {
        let aac = Codec::AacLc {
            sample_rate: 16_000,
            channels: 1,
            config: vec![0x14, 0x08].into(),
        };
        assert_eq!(
            track_params(&aac),
            TrackParams {
                sample_rate: Some(16_000),
                channels: Some(1),
                ..TrackParams::default()
            }
        );
        assert_eq!(
            track_params(&Codec::Opus { channels: 2 }),
            TrackParams {
                sample_rate: Some(48_000),
                channels: Some(2),
                ..TrackParams::default()
            }
        );
    }
}

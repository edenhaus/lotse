//! Track negotiation: a pure function from what a sink wants, what the
//! stream has and which transcoders exist to a plan per request.
//!
//! Rules: a native track of any acceptable family wins, in the sink's
//! preference order; an existing derived track counts as native; only then
//! is a transcoder consulted, again in preference order. A request that
//! cannot be met yields a typed error whose code the API reports:
//! `no_video_track` and `video_codec_unsupported` close the session,
//! `audio_codec_unsupported` is a warning and audio is omitted.

use std::sync::Arc;

use crate::codec::{Codec, CodecFamily, Kind};
use crate::output::TrackRequest;
use crate::track::TrackId;
use crate::transcode::Transcoder;

/// A track as negotiation sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackInfo {
    /// The track's id.
    pub id: TrackId,
    /// Its codec.
    pub codec: Arc<Codec>,
    /// The native track it was derived from, for derived tracks.
    pub derived_from: Option<TrackId>,
}

/// Why a request cannot be met.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NegotiationError {
    /// The stream has no track of that kind.
    #[error("stream has no {kind} track")]
    NoTrack {
        /// The kind requested.
        kind: Kind,
    },
    /// No acceptable family matches the native codec, and no transcoder
    /// bridges the gap.
    #[error("sink accepts {accepted:?}; stream {kind} is {native}")]
    CodecUnsupported {
        /// The kind requested.
        kind: Kind,
        /// What the sink accepts.
        accepted: Vec<CodecFamily>,
        /// The stream's native family of that kind.
        native: CodecFamily,
    },
}

impl NegotiationError {
    /// The stable API code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoTrack { kind: Kind::Video } => "no_video_track",
            Self::CodecUnsupported {
                kind: Kind::Video, ..
            } => "video_codec_unsupported",
            Self::NoTrack { kind: Kind::Audio }
            | Self::CodecUnsupported {
                kind: Kind::Audio, ..
            } => "audio_codec_unsupported",
        }
    }
}

/// What to do for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackPlan {
    /// Subscribe to this native (or already derived) track.
    Native {
        /// The track.
        track: TrackId,
    },
    /// Start (or share) a transcoder from `from` producing `to`.
    Derived {
        /// The native track to transcode.
        from: TrackId,
        /// The derived codec.
        to: Codec,
        /// Which transcoder, as an index into the list given.
        transcoder: usize,
    },
    /// The request cannot be met.
    Unavailable(NegotiationError),
}

/// Plans one request per entry of `requests`, in order.
pub fn negotiate(
    requests: &[TrackRequest],
    tracks: &[TrackInfo],
    transcoders: &[Arc<dyn Transcoder>],
) -> Vec<TrackPlan> {
    requests
        .iter()
        .map(|request| plan(request, tracks, transcoders))
        .collect()
}

/// Plans one request.
fn plan(
    request: &TrackRequest,
    tracks: &[TrackInfo],
    transcoders: &[Arc<dyn Transcoder>],
) -> TrackPlan {
    let of_kind: Vec<&TrackInfo> = tracks
        .iter()
        .filter(|track| track.codec.kind() == request.kind)
        .collect();
    let Some(native) = of_kind.iter().find(|track| track.derived_from.is_none()) else {
        return TrackPlan::Unavailable(NegotiationError::NoTrack { kind: request.kind });
    };

    // Native first (a real native track before a derived one), in the sink's
    // preference order.
    for family in &request.accept {
        if let Some(track) = of_kind
            .iter()
            .filter(|track| track.codec.family() == *family)
            .min_by_key(|track| track.derived_from.is_some())
        {
            return TrackPlan::Native { track: track.id };
        }
    }

    for family in &request.accept {
        for (index, transcoder) in transcoders.iter().enumerate() {
            if let Some(to) = transcoder.derive(&native.codec, *family) {
                return TrackPlan::Derived {
                    from: native.id,
                    to,
                    transcoder: index,
                };
            }
        }
    }

    TrackPlan::Unavailable(NegotiationError::CodecUnsupported {
        kind: request.kind,
        accepted: request.accept.clone(),
        native: native.codec.family(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use bytes::Bytes;

    use super::*;
    use crate::test_util::FakeTranscoder;
    use crate::track::Unit;

    fn info(id: TrackId, codec: Codec, derived_from: Option<TrackId>) -> TrackInfo {
        TrackInfo {
            id,
            codec: Arc::new(codec),
            derived_from,
        }
    }

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }
    }

    fn aac() -> Codec {
        Codec::AacLc {
            sample_rate: 16_000,
            channels: 1,
            config: Bytes::from_static(&[0x14, 0x08]),
        }
    }

    fn request(kind: Kind, accept: &[CodecFamily], required: bool) -> TrackRequest {
        TrackRequest {
            kind,
            accept: accept.to_vec(),
            unit: Unit::Packets,
            required,
        }
    }

    const V0: TrackId = TrackId::new(Kind::Video, 0);
    const A0: TrackId = TrackId::new(Kind::Audio, 0);
    const A1: TrackId = TrackId::new(Kind::Audio, 1);

    #[test]
    fn native_match_wins_in_the_sinks_order() {
        let tracks = [info(V0, h264(), None), info(A0, Codec::Pcmu, None)];
        let requests = [
            request(Kind::Video, &[CodecFamily::H265, CodecFamily::H264], true),
            request(
                Kind::Audio,
                &[CodecFamily::Opus, CodecFamily::Pcmu, CodecFamily::Pcma],
                false,
            ),
        ];
        let transcoders: Vec<Arc<dyn Transcoder>> = vec![Arc::new(FakeTranscoder::g711_to_opus())];
        assert_eq!(
            negotiate(&requests, &tracks, &transcoders),
            vec![
                TrackPlan::Native { track: V0 },
                TrackPlan::Native { track: A0 },
            ],
            "native PCMU beats a transcode to the preferred Opus"
        );
    }

    #[test]
    fn a_transcoder_bridges_aac_to_opus() {
        let tracks = [info(V0, h264(), None), info(A0, aac(), None)];
        let requests = [request(
            Kind::Audio,
            &[CodecFamily::Pcma, CodecFamily::Opus],
            false,
        )];
        let transcoders: Vec<Arc<dyn Transcoder>> = vec![
            Arc::new(FakeTranscoder::g711_to_opus()),
            Arc::new(FakeTranscoder::aac_to_opus()),
        ];
        assert_eq!(
            negotiate(&requests, &tracks, &transcoders),
            vec![TrackPlan::Derived {
                from: A0,
                to: Codec::Opus { channels: 1 },
                transcoder: 1,
            }]
        );
    }

    #[test]
    fn an_existing_derived_track_is_shared_not_re_derived() {
        let tracks = [
            info(V0, h264(), None),
            info(A0, aac(), None),
            info(A1, Codec::Opus { channels: 1 }, Some(A0)),
        ];
        let requests = [request(Kind::Audio, &[CodecFamily::Opus], false)];
        let transcoders: Vec<Arc<dyn Transcoder>> = vec![Arc::new(FakeTranscoder::aac_to_opus())];
        assert_eq!(
            negotiate(&requests, &tracks, &transcoders),
            vec![TrackPlan::Native { track: A1 }]
        );
    }

    #[test]
    fn a_native_track_is_preferred_over_a_derived_one_of_the_same_family() {
        let tracks = [
            info(A1, Codec::Opus { channels: 1 }, Some(A0)),
            info(A0, Codec::Opus { channels: 2 }, None),
        ];
        let requests = [request(Kind::Audio, &[CodecFamily::Opus], false)];
        assert_eq!(
            negotiate(&requests, &tracks, &[]),
            vec![TrackPlan::Native { track: A0 }]
        );
    }

    #[test]
    fn unmet_requests_carry_the_api_codes() {
        let tracks = [
            info(
                V0,
                Codec::H265 {
                    vps: None,
                    sps: None,
                    pps: None,
                },
                None,
            ),
            info(
                A0,
                Codec::Unsupported {
                    kind: Kind::Audio,
                    name: "aac_he".into(),
                },
                None,
            ),
        ];
        let requests = [
            request(Kind::Video, &[CodecFamily::H264], true),
            request(Kind::Audio, &[CodecFamily::Opus], false),
        ];
        let plans = negotiate(&requests, &tracks, &[]);
        crate::let_assert!([video, audio] = plans.as_slice());
        crate::let_assert!(TrackPlan::Unavailable(video) = video);
        assert_eq!(video.code(), "video_codec_unsupported");
        assert_eq!(
            video.to_string(),
            "sink accepts [H264]; stream video is h265"
        );
        crate::let_assert!(TrackPlan::Unavailable(audio) = audio);
        assert_eq!(audio.code(), "audio_codec_unsupported");

        let plans = negotiate(&requests, &[], &[]);
        assert_eq!(
            plans,
            vec![
                TrackPlan::Unavailable(NegotiationError::NoTrack { kind: Kind::Video }),
                TrackPlan::Unavailable(NegotiationError::NoTrack { kind: Kind::Audio }),
            ]
        );
        crate::let_assert!(TrackPlan::Unavailable(video) = &plans[0]);
        assert_eq!(video.code(), "no_video_track");
        assert_eq!(video.to_string(), "stream has no video track");
        crate::let_assert!(TrackPlan::Unavailable(audio) = &plans[1]);
        assert_eq!(audio.code(), "audio_codec_unsupported");
    }

    #[test]
    fn plans_follow_request_order_and_an_empty_request_list_is_empty() {
        assert!(negotiate(&[], &[info(V0, h264(), None)], &[]).is_empty());
        let requests = [
            request(Kind::Audio, &[CodecFamily::Pcmu], false),
            request(Kind::Video, &[CodecFamily::H264], true),
        ];
        let tracks = [info(V0, h264(), None), info(A0, Codec::Pcmu, None)];
        assert_eq!(
            negotiate(&requests, &tracks, &[]),
            vec![
                TrackPlan::Native { track: A0 },
                TrackPlan::Native { track: V0 }
            ]
        );
    }
}

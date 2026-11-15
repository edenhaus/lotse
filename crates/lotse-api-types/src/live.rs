//! Live outputs as the API sees them: `live/create`'s result, the events of
//! its subscription, and where a live output's bytes are fetched.
//!
//! A live output is a stream's video and, when it fits the container, its
//! audio as live fragmented MP4 (ISO/IEC 14496-12 §8.8): an init segment,
//! then one movie fragment per video frame, from the stream's cached
//! keyframe on, for a player that appends them to Media Source Extensions
//! as they come. Its bytes are one HTTP response body, `GET
//! /v0/live/{live_id}` ([`live_path`]) on the same socket, in the chunked
//! transfer coding (RFC 9112 §7.1), which runs as long as the output does
//! and ends with its last chunk when the output ends; the subscription's
//! `closed` says why. Its MIME type comes with the result, `codecs`
//! included (RFC 6381), so a client asks its player whether it plays it
//! before it fetches a byte.

use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::version::LIVE_PATH;

/// The path of live output `live_id`'s bytes, `/v0/live/{live_id}`: the `url`
/// of `live/create`'s result. The id is a ULID, which needs no
/// percent-encoding (RFC 3986 §2.3).
pub fn live_path(live_id: &str) -> String {
    format!("{LIVE_PATH}/{live_id}")
}

/// `live/create`'s result: the live output, its MIME type, and where its
/// bytes are fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LiveCreateResult {
    /// The live output: a ULID.
    pub live_id: String,
    /// The MIME type of its bytes with the RFC 6381 `codecs` parameter of
    /// what the container writes, `video/mp4; codecs="avc1.640028,mp4a.40.2"`:
    /// the video's entry, then the audio's when the output has audio. What
    /// `MediaSource.isTypeSupported` takes.
    pub mime: String,
    /// The path to `GET` its bytes from on the socket this command came
    /// over: `/v0/live/{live_id}`. One request takes them; a live output
    /// not fetched within `limits.live_fetch_timeout_ms` ends `not_fetched`.
    pub url: String,
}

/// An event of `live/create`: warnings, then `closed` always last.
/// Each variant's schema title names the Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveEvent {
    /// Non-fatal: the output goes on.
    #[cfg_attr(feature = "schema", schemars(title = "LiveEventWarning"))]
    Warning {
        /// The stable code.
        code: LiveWarningCode,
        /// For humans.
        message: String,
    },
    /// The last event; the subscription ends with it, and the body ends,
    /// with its last chunk, once the bytes before it are read.
    #[cfg_attr(feature = "schema", schemars(title = "LiveEventClosed"))]
    Closed {
        /// The live output.
        live_id: String,
        /// Why.
        reason: LiveCloseReason,
        /// The bytes its worker wrote for the body; 0 when it ended without
        /// its worker's last word (`worker_crashed`, `shutting_down`).
        bytes: u64,
        /// The frames left out because the body was read slower than the
        /// camera sends: each time the output fell behind, every frame up
        /// to the next keyframe.
        dropped_frames: u64,
        /// How often it fell behind and dropped to the next keyframe.
        drops: u32,
    },
}

/// The code of a live output's `warning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum LiveWarningCode {
    /// The stream's audio does not fit the live container (G.711, G.722,
    /// anything but AAC-LC and Opus) and is not transcoded: the output has
    /// no audio, its `mime` names none, and the message names the codec.
    AudioOmitted,
}

impl LiveWarningCode {
    /// The code as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AudioOmitted => "audio_omitted",
        }
    }

    /// The code for its API name, as a worker reports it.
    pub fn parse(code: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(code.to_owned())).ok()
    }
}

impl fmt::Display for LiveWarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a live output ended: the `reason` of `closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum LiveCloseReason {
    /// `live/close`.
    Closed,
    /// The body's connection closed, or stopped taking bytes.
    ClientGone,
    /// The control connection that created it closed, or unsubscribed.
    SessionClosed,
    /// Nobody fetched the body within `limits.live_fetch_timeout_ms`.
    NotFetched,
    /// The stream was deleted, or its video track closed.
    StreamDeleted,
    /// The stream moved to another source connection, or the codec of what
    /// follows is not known.
    StreamChanged,
    /// A codec changed past what the init segment describes (another
    /// codec, profile, level or picture size): a new output needs a new
    /// init segment, so the client creates one.
    CodecChanged,
    /// The stream has no video track.
    NoVideoTrack,
    /// No keyframe came within `limits.live_start_timeout_ms` of the fetch.
    SourceNotLive,
    /// The stream's worker process exited.
    WorkerCrashed,
    /// The daemon is stopping.
    ShuttingDown,
    /// The container failed, or the worker broke the contract.
    InternalError,
}

impl LiveCloseReason {
    /// The reason as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::ClientGone => "client_gone",
            Self::SessionClosed => "session_closed",
            Self::NotFetched => "not_fetched",
            Self::StreamDeleted => "stream_deleted",
            Self::StreamChanged => "stream_changed",
            Self::CodecChanged => "codec_changed",
            Self::NoVideoTrack => "no_video_track",
            Self::SourceNotLive => "source_not_live",
            Self::WorkerCrashed => "worker_crashed",
            Self::ShuttingDown => "shutting_down",
            Self::InternalError => "internal_error",
        }
    }

    /// The reason for its API name, as a worker reports it.
    pub fn parse(reason: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(reason.to_owned())).ok()
    }
}

impl fmt::Display for LiveCloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use serde_json::json;

    use super::*;

    #[test]
    fn rfc3986_2_3_a_live_output_s_path_carries_its_id_unencoded() {
        assert_eq!(live_path("01JL"), "/v0/live/01JL");
        let result = LiveCreateResult {
            live_id: "01JL".into(),
            mime: "video/mp4; codecs=\"avc1.42c028\"".into(),
            url: live_path("01JL"),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(
            json,
            json!({ "live_id": "01JL", "mime": "video/mp4; codecs=\"avc1.42c028\"", "url": "/v0/live/01JL" })
        );
        assert_eq!(
            serde_json::from_value::<LiveCreateResult>(json).unwrap(),
            result
        );
    }

    #[test]
    fn events_serialize_with_their_type_and_codes() {
        let warning = LiveEvent::Warning {
            code: LiveWarningCode::AudioOmitted,
            message: "pcmu".into(),
        };
        assert_eq!(
            serde_json::to_value(&warning).unwrap(),
            json!({ "type": "warning", "code": "audio_omitted", "message": "pcmu" })
        );
        let closed = LiveEvent::Closed {
            live_id: "01JL".into(),
            reason: LiveCloseReason::CodecChanged,
            bytes: 10,
            dropped_frames: 3,
            drops: 1,
        };
        assert_eq!(
            serde_json::to_value(&closed).unwrap(),
            json!({ "type": "closed", "live_id": "01JL", "reason": "codec_changed",
                    "bytes": 10, "dropped_frames": 3, "drops": 1 })
        );
    }

    #[test]
    fn codes_and_reasons_spell_as_the_api_does_and_parse_back() {
        assert_eq!(LiveWarningCode::AudioOmitted.to_string(), "audio_omitted");
        assert_eq!(
            LiveWarningCode::parse("audio_omitted"),
            Some(LiveWarningCode::AudioOmitted)
        );
        assert_eq!(LiveWarningCode::parse("made_up"), None);
        for reason in [
            LiveCloseReason::Closed,
            LiveCloseReason::ClientGone,
            LiveCloseReason::SessionClosed,
            LiveCloseReason::NotFetched,
            LiveCloseReason::StreamDeleted,
            LiveCloseReason::StreamChanged,
            LiveCloseReason::CodecChanged,
            LiveCloseReason::NoVideoTrack,
            LiveCloseReason::SourceNotLive,
            LiveCloseReason::WorkerCrashed,
            LiveCloseReason::ShuttingDown,
            LiveCloseReason::InternalError,
        ] {
            let json = serde_json::to_value(reason).unwrap();
            assert_eq!(json, serde_json::Value::String(reason.as_str().to_owned()));
            assert_eq!(LiveCloseReason::parse(reason.as_str()), Some(reason));
            assert_eq!(reason.to_string(), reason.as_str());
        }
        assert_eq!(LiveCloseReason::parse("stopped"), None);
    }
}

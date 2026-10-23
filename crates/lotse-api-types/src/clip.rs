//! Event clips as the API sees them: `clip/start`'s result, the events of
//! its subscription, and where a clip's bytes are fetched.
//!
//! A clip is one fragmented MP4 file (ISO/IEC 14496-12 §8.8) of a stream's
//! video and, when it fits the container, its audio. It starts up to
//! `before_ms` before the command, from the stream's pre-roll window, at a
//! keyframe, and runs `after_ms` after it or until `clip/stop`. Its bytes
//! are one HTTP response body, `GET /v0/clips/{clip_id}` ([`clip_path`]) on
//! the same socket, in the chunked transfer coding (RFC 9112 §7.1): the body
//! ends with its last chunk when the file is whole, and without it when the
//! clip was cut (RFC 9112 §8). The events say how the clip went; its gaps
//! are holes on the file's timeline, not marked inside the file.

use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::version::CLIPS_PATH;

/// The path of clip `clip_id`'s bytes, `/v0/clips/{clip_id}`: the `url` of
/// `clip/start`'s result. The id matches `^[A-Za-z0-9._-]{1,128}$`, so it
/// needs no percent-encoding (RFC 3986 §2.3).
pub fn clip_path(clip_id: &str) -> String {
    format!("{CLIPS_PATH}/{clip_id}")
}

/// `clip/start`'s result: the clip, and where its bytes are fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ClipStartResult {
    /// The clip: the client's id, or a generated ULID.
    pub clip_id: String,
    /// The path to `GET` its bytes from on the socket this command came
    /// over: `/v0/clips/{clip_id}`. One request takes them; a clip not
    /// fetched in time stops with `not_fetched`.
    pub url: String,
}

/// A clip's video, as `started` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ClipVideo {
    /// The codec name (`h264`, `h265`).
    pub codec: String,
    /// The picture's width in pixels, cropping applied (ISO/IEC 14496-10
    /// §7.4.2.1.1, ITU-T H.265 §7.4.3.2.1); absent when the sequence
    /// parameter set does not give it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// The picture's height in pixels, present with `width`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

/// A clip's audio, as `started` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ClipAudio {
    /// The codec name in the clip (`aac_lc`, `opus`): G.711 and G.722
    /// audio is transcoded to `opus`.
    pub codec: String,
}

/// An event of `clip/start`, in the order they come: `started` unless
/// the clip ends first, then warnings and gaps, and `stopped` always last.
/// Each variant's schema title names the Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClipEvent {
    /// The clip's file is under way: its first bytes are on their way to
    /// the body.
    #[cfg_attr(feature = "schema", schemars(title = "ClipEventStarted"))]
    Started {
        /// The clip.
        clip_id: String,
        /// When it started, RFC 3339 UTC: the daemon's time of the start,
        /// which `before_ms` counts back from.
        at: String,
        /// How far before `at` the clip begins, in milliseconds: the age
        /// of the keyframe it starts at, which is what the pre-roll window
        /// held, not what was asked; 0 without a window.
        before_ms: u32,
        /// Its video.
        video: ClipVideo,
        /// Its audio; null for a clip without audio (`audio: false`, a
        /// stream without audio, or `audio_omitted`).
        #[serde(default)]
        audio: Option<ClipAudio>,
    },
    /// Non-fatal: the clip goes on.
    #[cfg_attr(feature = "schema", schemars(title = "ClipEventWarning"))]
    Warning {
        /// The stable code.
        code: ClipWarningCode,
        /// For humans.
        message: String,
    },
    /// The clip has a hole: no media between `from_ms` and `to_ms`, so
    /// the file's timeline has a hole of that length.
    #[cfg_attr(feature = "schema", schemars(title = "ClipEventGap"))]
    Gap {
        /// Why.
        reason: ClipGapReason,
        /// Where the hole begins, in milliseconds of the clip's media time
        /// (from its first frame), as the file counts it.
        from_ms: u32,
        /// Where it ends, likewise.
        to_ms: u32,
    },
    /// The last event; the subscription ends with it, and the body ends
    /// once the bytes before it are read.
    #[cfg_attr(feature = "schema", schemars(title = "ClipEventStopped"))]
    Stopped {
        /// Why.
        reason: ClipStopReason,
        /// The bytes of the file written to the body; 0 when the clip
        /// ended without its worker's last word (`worker_crashed`,
        /// `stream_deleted`, `stream_changed` by a move to another
        /// connection, `shutting_down`, `internal_error` for a malformed
        /// report), whose body is then cut.
        bytes: u64,
        /// The media time the file covers, in milliseconds; 0 for the
        /// same ends.
        duration_ms: u32,
        /// The gaps the clip had, every one counted even where not each
        /// was reported as an event.
        gaps: u32,
    },
}

/// The code of a clip's `warning`: every code a clip may warn with, and
/// nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClipWarningCode {
    /// The stream's audio neither fits the clip's container nor can be
    /// transcoded into it; the clip has no audio, and the message names
    /// the codec.
    AudioOmitted,
}

impl ClipWarningCode {
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

impl fmt::Display for ClipWarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a clip has a hole: the `reason` of `gap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClipGapReason {
    /// The camera's connection dropped and came back, during the clip or
    /// inside its pre-roll: the hole is the real time between.
    Reconnect,
    /// Video frames are missing inside one connection: two consecutive
    /// ones arrived more than twice the frame interval apart (the camera
    /// or the network dropped them).
    FramesDropped,
    /// The clip's queue ran full, since its body is read slower than the
    /// camera sends, and frames were dropped up to the next keyframe; or a
    /// pre-roll GOP larger than the window's byte cap was cut short.
    Overflow,
    /// The clip fell behind the stream's frames and missed some; it goes
    /// on from the next keyframe.
    Lagged,
}

impl ClipGapReason {
    /// The reason as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reconnect => "reconnect",
            Self::FramesDropped => "frames_dropped",
            Self::Overflow => "overflow",
            Self::Lagged => "lagged",
        }
    }

    /// The reason for its API name, as a worker reports it.
    pub fn parse(reason: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(reason.to_owned())).ok()
    }
}

impl fmt::Display for ClipGapReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a clip ended: the `reason` of `stopped`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClipStopReason {
    /// `after_ms` reached.
    Completed,
    /// `clip/stop` or `unsubscribe`.
    Stopped,
    /// `limits.clip_max_ms` reached: an open-ended clip's end.
    MaxDuration,
    /// The stream was deleted.
    StreamDeleted,
    /// The stream's codec, its parameter sets or picture size changed, or
    /// its source was switched: a file has one sample entry per track, so
    /// the client starts another clip.
    StreamChanged,
    /// The stream had no video track when its source came up.
    NoVideoTrack,
    /// The connection's worker process died; the body ends without its
    /// last chunk.
    WorkerCrashed,
    /// The source sent no keyframe to start at in time.
    SourceNotLive,
    /// The body's reader went away before the clip ended.
    ClientGone,
    /// Nobody fetched the clip's bytes in time.
    NotFetched,
    /// The control connection that started the clip closed.
    SessionClosed,
    /// The daemon is shutting down; the last fragment is written if the
    /// body takes it in time.
    ShuttingDown,
    /// An invariant failed, or a worker reported a reason the API does not
    /// know; a bug, always logged with context.
    InternalError,
}

impl ClipStopReason {
    /// The reason as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Stopped => "stopped",
            Self::MaxDuration => "max_duration",
            Self::StreamDeleted => "stream_deleted",
            Self::StreamChanged => "stream_changed",
            Self::NoVideoTrack => "no_video_track",
            Self::WorkerCrashed => "worker_crashed",
            Self::SourceNotLive => "source_not_live",
            Self::ClientGone => "client_gone",
            Self::NotFetched => "not_fetched",
            Self::SessionClosed => "session_closed",
            Self::ShuttingDown => "shutting_down",
            Self::InternalError => "internal_error",
        }
    }

    /// The reason for its API name, as a worker reports it.
    pub fn parse(reason: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(reason.to_owned())).ok()
    }
}

impl fmt::Display for ClipStopReason {
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
    fn rfc3986_2_3_a_clips_path_carries_its_id_unencoded() {
        assert_eq!(clip_path("01JB.x_y-z"), "/v0/clips/01JB.x_y-z");
        let result = ClipStartResult {
            clip_id: "c1".into(),
            url: clip_path("c1"),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json, json!({ "clip_id": "c1", "url": "/v0/clips/c1" }));
        assert_eq!(
            serde_json::from_value::<ClipStartResult>(json).unwrap(),
            result
        );
    }

    #[test]
    fn events_serialize_like_the_contract_examples() {
        for (event, expected) in [
            (
                ClipEvent::Started {
                    clip_id: "01JB".into(),
                    at: "2026-10-22T10:00:00.000Z".into(),
                    before_ms: 9800,
                    video: ClipVideo {
                        codec: "h264".into(),
                        width: Some(1920),
                        height: Some(1080),
                    },
                    audio: Some(ClipAudio {
                        codec: "aac_lc".into(),
                    }),
                },
                json!({ "type": "started", "clip_id": "01JB", "at": "2026-10-22T10:00:00.000Z",
                        "before_ms": 9800,
                        "video": { "codec": "h264", "width": 1920, "height": 1080 },
                        "audio": { "codec": "aac_lc" } }),
            ),
            // Without audio it says so, and an unknown picture is left out.
            (
                ClipEvent::Started {
                    clip_id: "c".into(),
                    at: "2026-10-22T10:00:00.000Z".into(),
                    before_ms: 0,
                    video: ClipVideo {
                        codec: "h265".into(),
                        width: None,
                        height: None,
                    },
                    audio: None,
                },
                json!({ "type": "started", "clip_id": "c", "at": "2026-10-22T10:00:00.000Z",
                        "before_ms": 0, "video": { "codec": "h265" }, "audio": null }),
            ),
            (
                ClipEvent::Warning {
                    code: ClipWarningCode::AudioOmitted,
                    message: "pcmu does not fit the clip's container; the clip has no audio".into(),
                },
                json!({ "type": "warning", "code": "audio_omitted",
                        "message": "pcmu does not fit the clip's container; the clip has no audio" }),
            ),
            (
                ClipEvent::Gap {
                    reason: ClipGapReason::Reconnect,
                    from_ms: 12_040,
                    to_ms: 15_310,
                },
                json!({ "type": "gap", "reason": "reconnect", "from_ms": 12_040, "to_ms": 15_310 }),
            ),
            (
                ClipEvent::Stopped {
                    reason: ClipStopReason::Completed,
                    bytes: 24_117_248,
                    duration_ms: 29_800,
                    gaps: 1,
                },
                json!({ "type": "stopped", "reason": "completed", "bytes": 24_117_248,
                        "duration_ms": 29_800, "gaps": 1 }),
            ),
        ] {
            assert_eq!(serde_json::to_value(&event).unwrap(), expected);
            assert_eq!(
                serde_json::from_value::<ClipEvent>(expected).unwrap(),
                event
            );
        }
        // A daemon that leaves `audio` out means none.
        let started: ClipEvent = serde_json::from_value(json!({
            "type": "started", "clip_id": "c", "at": "t", "before_ms": 0,
            "video": { "codec": "h264" }
        }))
        .unwrap();
        assert!(matches!(started, ClipEvent::Started { audio: None, .. }));
    }

    #[test]
    fn every_clip_name_serializes_as_itself_and_parses_back() {
        let code = ClipWarningCode::AudioOmitted;
        assert_eq!(serde_json::to_value(code).unwrap(), "audio_omitted");
        assert_eq!(ClipWarningCode::parse("audio_omitted"), Some(code));
        assert_eq!(code.to_string(), "audio_omitted");
        for reason in [
            ClipGapReason::Reconnect,
            ClipGapReason::FramesDropped,
            ClipGapReason::Overflow,
            ClipGapReason::Lagged,
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), reason.as_str());
            assert_eq!(ClipGapReason::parse(reason.as_str()), Some(reason));
            assert_eq!(reason.to_string(), reason.as_str());
        }
        // The worker's reasons and the supervisor's own.
        let names = [
            "completed",
            "stopped",
            "max_duration",
            "stream_deleted",
            "stream_changed",
            "no_video_track",
            "worker_crashed",
            "source_not_live",
            "client_gone",
            "not_fetched",
            "session_closed",
            "shutting_down",
            "internal_error",
        ];
        for name in names {
            let reason = ClipStopReason::parse(name).unwrap();
            assert_eq!(reason.as_str(), name);
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
            assert_eq!(reason.to_string(), name);
        }
        // A name of another kind, or none at all, is not one.
        assert_eq!(ClipWarningCode::parse("turn_unsupported"), None);
        assert_eq!(ClipGapReason::parse("completed"), None);
        assert_eq!(ClipStopReason::parse("peer_closed"), None);
        assert_eq!(ClipStopReason::parse("overflow"), None);
    }
}

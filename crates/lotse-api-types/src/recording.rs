//! Event recordings as the API sees them: `recording/create`'s result, the events of
//! its subscription, and where a recording's bytes are fetched.
//!
//! A recording is one fragmented MP4 file (ISO/IEC 14496-12 §8.8) of a stream's
//! video and, when it fits the container, its audio. It starts up to
//! `prerecord_ms` before the command, from the stream's pre-record window, at a
//! keyframe, and runs `duration_ms` after it: a fixed length, never stopped
//! early by the client. Its bytes
//! are one HTTP response body, `GET /v0/recording/{recording_id}` ([`recording_path`]) on
//! the same socket, in the chunked transfer coding (RFC 9112 §7.1): the body
//! ends with its last chunk when the file is whole, and without it when the
//! recording was cut (RFC 9112 §8). The events say how the recording went; its gaps
//! are holes on the file's timeline, not marked inside the file.

use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::version::RECORDING_PATH;

/// The path of recording `recording_id`'s bytes, `/v0/recording/{recording_id}`: the `url` of
/// `recording/create`'s result. The id matches `^[A-Za-z0-9._-]{1,128}$`, so it
/// needs no percent-encoding (RFC 3986 §2.3), and is never `.` or `..`, so
/// resolving the path keeps it whole (RFC 3986 §5.2.4).
pub fn recording_path(recording_id: &str) -> String {
    format!("{RECORDING_PATH}/{recording_id}")
}

/// `recording/create`'s result: the recording, and where its bytes are fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RecordingCreateResult {
    /// The recording: the client's id, or a generated ULID.
    pub recording_id: String,
    /// The path to `GET` its bytes from on the socket this command came
    /// over: `/v0/recording/{recording_id}`. One request takes them; a recording not
    /// fetched in time stops with `not_fetched`.
    pub url: String,
}

/// A recording's video, as `started` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RecordingVideo {
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

/// A recording's audio, as `started` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RecordingAudio {
    /// The codec name in the recording (`aac_lc`, `opus`): G.711 and G.722
    /// audio is transcoded to `opus`.
    pub codec: String,
}

/// An event of `recording/create`, in the order they come: `started` unless
/// the recording ends first, then warnings and gaps, and `closed` always last.
/// Each variant's schema title names the Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecordingEvent {
    /// The recording's file is under way: its first bytes are on their way to
    /// the body.
    #[cfg_attr(feature = "schema", schemars(title = "RecordingEventStarted"))]
    Started {
        /// The recording.
        recording_id: String,
        /// When it started, RFC 3339 UTC: the daemon's time of the start,
        /// which `prerecord_ms` counts back from.
        at: String,
        /// How far before `at` the recording begins, in milliseconds: the age
        /// of the keyframe it starts at, which is what the pre-record window
        /// held, not what was asked; 0 without a window.
        prerecord_ms: u32,
        /// Its video.
        video: RecordingVideo,
        /// Its audio; null for a recording without audio (`audio: false`, a
        /// stream without audio, or `audio_omitted`).
        #[serde(default)]
        audio: Option<RecordingAudio>,
    },
    /// Non-fatal: the recording goes on.
    #[cfg_attr(feature = "schema", schemars(title = "RecordingEventWarning"))]
    Warning {
        /// The stable code.
        code: RecordingWarningCode,
        /// For humans.
        message: String,
    },
    /// The recording has a hole: no media between `from_ms` and `to_ms`, so
    /// the file's timeline has a hole of that length.
    #[cfg_attr(feature = "schema", schemars(title = "RecordingEventGap"))]
    Gap {
        /// Why.
        reason: RecordingGapReason,
        /// Where the hole begins, in milliseconds of the recording's media time
        /// (from its first frame), as the file counts it.
        from_ms: u32,
        /// Where it ends, likewise.
        to_ms: u32,
    },
    /// The last event; the subscription ends with it, and the body ends
    /// once the bytes before it are read.
    #[cfg_attr(feature = "schema", schemars(title = "RecordingEventClosed"))]
    Closed {
        /// Why.
        reason: RecordingCloseReason,
        /// The file's length, as its worker made it: the bytes written for
        /// the body, and a last tail the body did not take in time, which it
        /// then ends without, cut; 0 when the recording ended without its worker's
        /// last word (`worker_crashed`, `stream_deleted`, `stream_changed` by
        /// a move to another connection, `shutting_down`, `internal_error`
        /// for a malformed report), whose body is then cut.
        bytes: u64,
        /// The media time the file covers, in milliseconds; 0 for the
        /// same ends.
        duration_ms: u32,
        /// The gaps the recording had, every one counted even where not each
        /// was reported as an event.
        gaps: u32,
    },
}

/// The code of a recording's `warning`: every code a recording may warn with, and
/// nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecordingWarningCode {
    /// The stream's audio neither fits the recording's container nor can be
    /// transcoded into it; the recording has no audio, and the message names
    /// the codec.
    AudioOmitted,
}

impl RecordingWarningCode {
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

impl fmt::Display for RecordingWarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a recording has a hole: the `reason` of `gap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecordingGapReason {
    /// The camera's connection dropped and came back, during the recording or
    /// inside its pre-record: the hole is the real time between.
    Reconnect,
    /// Video frames are missing inside one connection: two consecutive
    /// ones arrived more than twice the frame interval apart (the camera
    /// or the network dropped them).
    FramesDropped,
    /// The recording's queue ran full, since its body is read slower than the
    /// camera sends, and frames were dropped up to the next keyframe; or a
    /// pre-record GOP larger than the window's byte cap was cut short.
    Overflow,
    /// The recording fell behind the stream's frames and missed some; it goes
    /// on from the next keyframe.
    Lagged,
}

impl RecordingGapReason {
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

impl fmt::Display for RecordingGapReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a recording ended: the `reason` of `closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecordingCloseReason {
    /// `duration_ms` reached.
    Completed,
    /// The stream was deleted.
    StreamDeleted,
    /// The stream's codec, its parameter sets or picture size changed, or
    /// its source was switched: a file has one sample entry per track, so
    /// the client starts another recording.
    StreamChanged,
    /// The stream had no video track when its source came up.
    NoVideoTrack,
    /// The connection's worker process died; the body ends without its
    /// last chunk.
    WorkerCrashed,
    /// The source sent no keyframe to start at in time.
    SourceNotLive,
    /// The body's reader went away before the recording ended.
    ClientGone,
    /// Nobody fetched the recording's bytes in time.
    NotFetched,
    /// `unsubscribe`, or the control connection that started the recording
    /// closed.
    SessionClosed,
    /// The daemon is shutting down; the last fragment is written if the
    /// body takes it in time.
    ShuttingDown,
    /// An invariant failed, or a worker reported a reason the API does not
    /// know; a bug, always logged with context.
    InternalError,
}

impl RecordingCloseReason {
    /// The reason as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
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

impl fmt::Display for RecordingCloseReason {
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
    fn rfc3986_2_3_a_recordings_path_carries_its_id_unencoded() {
        assert_eq!(recording_path("01JB.x_y-z"), "/v0/recording/01JB.x_y-z");
        let result = RecordingCreateResult {
            recording_id: "c1".into(),
            url: recording_path("c1"),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(
            json,
            json!({ "recording_id": "c1", "url": "/v0/recording/c1" })
        );
        assert_eq!(
            serde_json::from_value::<RecordingCreateResult>(json).unwrap(),
            result
        );
    }

    #[test]
    fn events_serialize_like_the_contract_examples() {
        for (event, expected) in [
            (
                RecordingEvent::Started {
                    recording_id: "01JB".into(),
                    at: "2026-10-22T10:00:00.000Z".into(),
                    prerecord_ms: 9800,
                    video: RecordingVideo {
                        codec: "h264".into(),
                        width: Some(1920),
                        height: Some(1080),
                    },
                    audio: Some(RecordingAudio {
                        codec: "aac_lc".into(),
                    }),
                },
                json!({ "type": "started", "recording_id": "01JB", "at": "2026-10-22T10:00:00.000Z",
                        "prerecord_ms": 9800,
                        "video": { "codec": "h264", "width": 1920, "height": 1080 },
                        "audio": { "codec": "aac_lc" } }),
            ),
            // Without audio it says so, and an unknown picture is left out.
            (
                RecordingEvent::Started {
                    recording_id: "c".into(),
                    at: "2026-10-22T10:00:00.000Z".into(),
                    prerecord_ms: 0,
                    video: RecordingVideo {
                        codec: "h265".into(),
                        width: None,
                        height: None,
                    },
                    audio: None,
                },
                json!({ "type": "started", "recording_id": "c", "at": "2026-10-22T10:00:00.000Z",
                        "prerecord_ms": 0, "video": { "codec": "h265" }, "audio": null }),
            ),
            (
                RecordingEvent::Warning {
                    code: RecordingWarningCode::AudioOmitted,
                    message:
                        "pcmu does not fit the recording's container; the recording has no audio"
                            .into(),
                },
                json!({ "type": "warning", "code": "audio_omitted",
                        "message": "pcmu does not fit the recording's container; the recording has no audio" }),
            ),
            (
                RecordingEvent::Gap {
                    reason: RecordingGapReason::Reconnect,
                    from_ms: 12_040,
                    to_ms: 15_310,
                },
                json!({ "type": "gap", "reason": "reconnect", "from_ms": 12_040, "to_ms": 15_310 }),
            ),
            (
                RecordingEvent::Closed {
                    reason: RecordingCloseReason::Completed,
                    bytes: 24_117_248,
                    duration_ms: 29_800,
                    gaps: 1,
                },
                json!({ "type": "closed", "reason": "completed", "bytes": 24_117_248,
                        "duration_ms": 29_800, "gaps": 1 }),
            ),
        ] {
            assert_eq!(serde_json::to_value(&event).unwrap(), expected);
            assert_eq!(
                serde_json::from_value::<RecordingEvent>(expected).unwrap(),
                event
            );
        }
        // A daemon that leaves `audio` out means none.
        let started: RecordingEvent = serde_json::from_value(json!({
            "type": "started", "recording_id": "c", "at": "t", "prerecord_ms": 0,
            "video": { "codec": "h264" }
        }))
        .unwrap();
        assert!(matches!(
            started,
            RecordingEvent::Started { audio: None, .. }
        ));
    }

    #[test]
    fn every_recording_name_serializes_as_itself_and_parses_back() {
        let code = RecordingWarningCode::AudioOmitted;
        assert_eq!(serde_json::to_value(code).unwrap(), "audio_omitted");
        assert_eq!(RecordingWarningCode::parse("audio_omitted"), Some(code));
        assert_eq!(code.to_string(), "audio_omitted");
        for reason in [
            RecordingGapReason::Reconnect,
            RecordingGapReason::FramesDropped,
            RecordingGapReason::Overflow,
            RecordingGapReason::Lagged,
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), reason.as_str());
            assert_eq!(RecordingGapReason::parse(reason.as_str()), Some(reason));
            assert_eq!(reason.to_string(), reason.as_str());
        }
        // The worker's reasons and the supervisor's own.
        let names = [
            "completed",
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
            let reason = RecordingCloseReason::parse(name).unwrap();
            assert_eq!(reason.as_str(), name);
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
            assert_eq!(reason.to_string(), name);
        }
        // A name of another kind, or none at all, is not one.
        assert_eq!(RecordingWarningCode::parse("turn_unsupported"), None);
        assert_eq!(RecordingGapReason::parse("completed"), None);
        assert_eq!(RecordingCloseReason::parse("peer_closed"), None);
        assert_eq!(RecordingCloseReason::parse("overflow"), None);
        // A recording is never stopped early by its client, nor open-ended.
        assert_eq!(RecordingCloseReason::parse("stopped"), None);
        assert_eq!(RecordingCloseReason::parse("max_duration"), None);
    }
}

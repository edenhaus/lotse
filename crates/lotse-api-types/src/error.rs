//! The error model: stable codes, a human message, and details.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Every stable error code. `code` is the contract; `message` may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed JSON, an unknown field, a bad value.
    InvalidRequest,
    /// `type` is not a command.
    UnknownCommand,
    /// `id` is not greater than the previous one on this connection.
    IdReuse,
    /// The stream id fails the pattern.
    InvalidStreamId,
    /// No such stream.
    StreamNotFound,
    /// No such session, or its grace expired; for `webrtc/candidate`, also
    /// a session this connection does not own.
    SessionNotFound,
    /// The session id is already open.
    SessionIdInUse,
    /// `unsubscribe` of an unknown subscription.
    SubscriptionNotFound,
    /// Streams, sessions, sessions per stream or connections.
    LimitReached,
    /// The source URL scheme is not in `info.schemes`.
    SchemeUnsupported,
    /// The source URL, credentials aside, is already another stream's;
    /// `details.stream_id` names it.
    SourceInUse,
    /// The command arrived during graceful shutdown.
    ShuttingDown,
    /// An invariant failed; a bug, always logged with context.
    InternalError,
    /// Connecting to the source failed.
    SourceUnreachable,
    /// The source rejected the credentials.
    SourceAuthFailed,
    /// The read deadline or stall watchdog hit.
    SourceTimeout,
    /// The source violated its protocol.
    SourceProtocolError,
    /// The source or publisher closed the stream.
    SourceEnded,
    /// The connection's worker process died.
    WorkerCrashed,
    /// Audio omitted from a session; video continues.
    AudioCodecUnsupported,
    /// A `turns:` entry was ignored.
    TurnUnsupported,
    /// The browser did not offer the stream's H.264 profile.
    H264ProfileMismatch,
    /// A video frame needed more RTP packets than some libwebrtc receivers
    /// assemble; it was sent whole.
    FrameOverBrowserLimit,
    /// Another session holds the backchannel.
    BackchannelBusy,
    /// Audio withdrawn because sync could not be held.
    AvSyncLost,
    /// The browser closed the peer connection.
    PeerClosed,
    /// `unsubscribe`, `session/close`, or the grace expired.
    SessionClosed,
    /// The stream was deleted.
    StreamDeleted,
    /// The codec family changed on reconnect.
    StreamChanged,
    /// ICE failed or stayed disconnected.
    IceFailed,
    /// The offer could not be parsed.
    InvalidSdp,
    /// The stream has no video track.
    NoVideoTrack,
    /// No video codec both sides can use.
    VideoCodecUnsupported,
    /// No keyframe within the snapshot timeout.
    SnapshotTimeout,
    /// The snapshot decode queue is full.
    SnapshotBusy,
}

impl ErrorCode {
    /// The code as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnknownCommand => "unknown_command",
            Self::IdReuse => "id_reuse",
            Self::InvalidStreamId => "invalid_stream_id",
            Self::StreamNotFound => "stream_not_found",
            Self::SessionNotFound => "session_not_found",
            Self::SessionIdInUse => "session_id_in_use",
            Self::SubscriptionNotFound => "subscription_not_found",
            Self::LimitReached => "limit_reached",
            Self::SchemeUnsupported => "scheme_unsupported",
            Self::SourceInUse => "source_in_use",
            Self::ShuttingDown => "shutting_down",
            Self::InternalError => "internal_error",
            Self::SourceUnreachable => "source_unreachable",
            Self::SourceAuthFailed => "source_auth_failed",
            Self::SourceTimeout => "source_timeout",
            Self::SourceProtocolError => "source_protocol_error",
            Self::SourceEnded => "source_ended",
            Self::WorkerCrashed => "worker_crashed",
            Self::AudioCodecUnsupported => "audio_codec_unsupported",
            Self::TurnUnsupported => "turn_unsupported",
            Self::H264ProfileMismatch => "h264_profile_mismatch",
            Self::FrameOverBrowserLimit => "frame_over_browser_limit",
            Self::BackchannelBusy => "backchannel_busy",
            Self::AvSyncLost => "av_sync_lost",
            Self::PeerClosed => "peer_closed",
            Self::SessionClosed => "session_closed",
            Self::StreamDeleted => "stream_deleted",
            Self::StreamChanged => "stream_changed",
            Self::IceFailed => "ice_failed",
            Self::InvalidSdp => "invalid_sdp",
            Self::NoVideoTrack => "no_video_track",
            Self::VideoCodecUnsupported => "video_codec_unsupported",
            Self::SnapshotTimeout => "snapshot_timeout",
            Self::SnapshotBusy => "snapshot_busy",
        }
    }

    /// The code for a string, as domain errors report them.
    pub fn parse(code: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(code.to_owned())).ok()
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error as the API carries it, in results, `closed` events and
/// `last_error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApiError {
    /// The stable code.
    pub code: ErrorCode,
    /// For humans; may change.
    pub message: String,
    /// Structured detail, per code.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub details: serde_json::Map<String, serde_json::Value>,
}

impl ApiError {
    /// An error without details.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: serde_json::Map::new(),
        }
    }

    /// Adds one detail.
    #[must_use]
    pub fn with_detail(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.details.insert(key.to_owned(), value.into());
        self
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn codes_serialize_as_their_snake_case_names_and_parse_back() {
        let all = [
            ErrorCode::InvalidRequest,
            ErrorCode::UnknownCommand,
            ErrorCode::IdReuse,
            ErrorCode::InvalidStreamId,
            ErrorCode::StreamNotFound,
            ErrorCode::SessionNotFound,
            ErrorCode::SessionIdInUse,
            ErrorCode::SubscriptionNotFound,
            ErrorCode::LimitReached,
            ErrorCode::SchemeUnsupported,
            ErrorCode::SourceInUse,
            ErrorCode::ShuttingDown,
            ErrorCode::InternalError,
            ErrorCode::SourceUnreachable,
            ErrorCode::SourceAuthFailed,
            ErrorCode::SourceTimeout,
            ErrorCode::SourceProtocolError,
            ErrorCode::SourceEnded,
            ErrorCode::WorkerCrashed,
            ErrorCode::AudioCodecUnsupported,
            ErrorCode::TurnUnsupported,
            ErrorCode::H264ProfileMismatch,
            ErrorCode::BackchannelBusy,
            ErrorCode::AvSyncLost,
            ErrorCode::PeerClosed,
            ErrorCode::SessionClosed,
            ErrorCode::StreamDeleted,
            ErrorCode::StreamChanged,
            ErrorCode::IceFailed,
            ErrorCode::InvalidSdp,
            ErrorCode::NoVideoTrack,
            ErrorCode::VideoCodecUnsupported,
            ErrorCode::SnapshotTimeout,
            ErrorCode::SnapshotBusy,
            ErrorCode::FrameOverBrowserLimit,
        ];
        for code in all {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(json, serde_json::Value::String(code.as_str().to_owned()));
            assert_eq!(ErrorCode::parse(code.as_str()), Some(code));
            assert_eq!(code.to_string(), code.as_str());
        }
        assert_eq!(ErrorCode::parse("made_up"), None);
        assert_eq!(
            ErrorCode::H264ProfileMismatch.as_str(),
            "h264_profile_mismatch"
        );
    }

    #[test]
    fn errors_serialize_like_the_contract_example() {
        let error = ApiError::new(
            ErrorCode::SchemeUnsupported,
            "scheme 'http' is not supported",
        );
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::json!({ "code": "scheme_unsupported", "message": "scheme 'http' is not supported" })
        );
        let detailed = error.clone().with_detail("protocol", "rtsp");
        assert_eq!(
            serde_json::to_value(&detailed).unwrap()["details"],
            serde_json::json!({ "protocol": "rtsp" })
        );
        assert_eq!(
            error.to_string(),
            "scheme_unsupported: scheme 'http' is not supported"
        );
        let parsed: ApiError =
            serde_json::from_str("{\"code\":\"source_timeout\",\"message\":\"m\"}").unwrap();
        assert_eq!(parsed, ApiError::new(ErrorCode::SourceTimeout, "m"));
    }
}

//! The error model of results and `last_error`: stable codes, a human
//! message, and details. A session's `warning` and `closed` events carry
//! codes of their own ([`WarningCode`](crate::session::WarningCode),
//! [`CloseCode`](crate::session::CloseCode)).

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Every stable error code of a result or a `last_error`. `code` is the
/// contract; `message` may change.
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
    /// No such session, or its grace expired; for `webrtc/candidate` and
    /// `webrtc/renegotiate`, also a session this connection does not own.
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
    /// The command is not allowed on this connection (`pairing/create`
    /// over the TLS listener, `clients/remove` of another client over it),
    /// or not for this target (`clients/remove` of a fixed pin).
    NotPermitted,
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
    /// `backchannel/release` on a stream whose source protocol cannot
    /// carry audio back.
    BackchannelUnsupported,
    /// The offer could not be parsed, or a re-offer changes the video
    /// m-line a session keeps.
    InvalidSdp,
    /// The stream has no video track, or the offer no video m-line.
    NoVideoTrack,
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
            Self::NotPermitted => "not_permitted",
            Self::InternalError => "internal_error",
            Self::SourceUnreachable => "source_unreachable",
            Self::SourceAuthFailed => "source_auth_failed",
            Self::SourceTimeout => "source_timeout",
            Self::SourceProtocolError => "source_protocol_error",
            Self::SourceEnded => "source_ended",
            Self::WorkerCrashed => "worker_crashed",

            Self::BackchannelUnsupported => "backchannel_unsupported",
            Self::InvalidSdp => "invalid_sdp",
            Self::NoVideoTrack => "no_video_track",
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

/// An error as the API carries it, in results and `last_error`.
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
            ErrorCode::BackchannelUnsupported,
            ErrorCode::InvalidSdp,
            ErrorCode::NoVideoTrack,
            ErrorCode::NotPermitted,
        ];
        for code in all {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(json, serde_json::Value::String(code.as_str().to_owned()));
            assert_eq!(ErrorCode::parse(code.as_str()), Some(code));
            assert_eq!(code.to_string(), code.as_str());
        }
        assert_eq!(ErrorCode::parse("made_up"), None);
        // A session event's code is not a result's.
        assert_eq!(ErrorCode::parse("peer_closed"), None);
        assert_eq!(ErrorCode::parse("h264_profile_mismatch"), None);
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

//! LL-HLS sessions as the API sees them: `hls/create`'s result, the events
//! of its subscription, and where a session's playlist is fetched.
//!
//! An LL-HLS session plays a stream's live output as a Media Playlist of
//! fragmented MP4 Media Segments and Partial Segments
//! (draft-pantos-hls-rfc8216bis-22 §3.1.2, §3.2, §4), served on the same
//! socket as the control API, `GET /v0/hls/{hls_id}/index.m3u8`
//! ([`hls_playlist_path`]), with Blocking Playlist Reload (§6.2.5.2). The
//! playlist names its init segment and segments relative to itself (§4.1),
//! `GET /v0/hls/{hls_id}/{name}`. Its MIME type comes with the result,
//! `codecs` included (RFC 6381), what a Multivariant Playlist's `CODECS`
//! attribute carries (§4.4.6.2), so a client asks its player whether it
//! plays it before it fetches a byte. The subscription's `closed` says why a
//! session ended; its routes then answer 404.

use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::live::LiveWarningCode;
use crate::version::HLS_PATH;

/// The name of a session's Media Playlist: the last segment of its path.
pub const PLAYLIST_NAME: &str = "index.m3u8";

/// The path of session `hls_id`'s Media Playlist,
/// `/v0/hls/{hls_id}/index.m3u8`: the `playlist` of `hls/create`'s result.
/// The id is a ULID, which needs no percent-encoding (RFC 3986 §2.3).
pub fn hls_playlist_path(hls_id: &str) -> String {
    format!("{HLS_PATH}/{hls_id}/{PLAYLIST_NAME}")
}

/// `hls/create`'s result: the session, the MIME type of its media, and
/// where its playlist is fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct HlsCreateResult {
    /// The session: a ULID.
    pub hls_id: String,
    /// The MIME type of its segments with the RFC 6381 `codecs` parameter
    /// of what the container writes, `video/mp4; codecs="avc1.640028,mp4a.40.2"`:
    /// the video's entry, then the audio's when the session has audio.
    pub mime: String,
    /// The path to `GET` its Media Playlist from on the socket this command
    /// came over: `/v0/hls/{hls_id}/index.m3u8`. A session no request
    /// reaches within `limits.hls_idle_timeout_ms` ends `idle`.
    pub playlist: String,
}

/// An event of `hls/create`: warnings, then `closed` always last.
/// Each variant's schema title names the Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HlsEvent {
    /// Non-fatal: the session goes on. A live output's warning, the same
    /// codes.
    #[cfg_attr(feature = "schema", schemars(title = "HlsEventWarning"))]
    Warning {
        /// The stable code.
        code: LiveWarningCode,
        /// For humans.
        message: String,
    },
    /// The last event; the subscription ends with it, and the session's
    /// routes answer 404 `hls_not_found` from here on.
    #[cfg_attr(feature = "schema", schemars(title = "HlsEventClosed"))]
    Closed {
        /// The session.
        hls_id: String,
        /// Why.
        reason: HlsCloseReason,
    },
}

/// Why an LL-HLS session ended: the `reason` of `closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HlsCloseReason {
    /// `hls/close`.
    Closed,
    /// The control connection that created it closed, or unsubscribed.
    SessionClosed,
    /// No request reached it within `limits.hls_idle_timeout_ms`.
    Idle,
    /// The stream sent no keyframe for longer than `limits.hls_window_bytes`
    /// hold: a segment must start with one, so the stream cannot be served
    /// as LL-HLS.
    WindowFull,
    /// The stream was deleted, or its video track closed.
    StreamDeleted,
    /// The stream moved to another source connection, or the codec of what
    /// follows is not known.
    StreamChanged,
    /// A codec changed past what the init segment describes (another
    /// codec, profile, level or picture size): a new session needs a new
    /// init segment, so the client creates one.
    CodecChanged,
    /// The stream has no video track.
    NoVideoTrack,
    /// No keyframe came within `limits.live_start_timeout_ms`.
    SourceNotLive,
    /// The stream's worker process exited.
    WorkerCrashed,
    /// The daemon is stopping.
    ShuttingDown,
    /// The container failed, or the worker broke the contract.
    InternalError,
}

impl HlsCloseReason {
    /// The reason as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::SessionClosed => "session_closed",
            Self::Idle => "idle",
            Self::WindowFull => "window_full",
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
}

impl fmt::Display for HlsCloseReason {
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
    fn rfc3986_2_3_a_session_s_playlist_path_carries_its_id_unencoded() {
        assert_eq!(hls_playlist_path("01JH"), "/v0/hls/01JH/index.m3u8");
        let result = HlsCreateResult {
            hls_id: "01JH".into(),
            mime: "video/mp4; codecs=\"avc1.42c028\"".into(),
            playlist: hls_playlist_path("01JH"),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(
            json,
            json!({ "hls_id": "01JH", "mime": "video/mp4; codecs=\"avc1.42c028\"",
                    "playlist": "/v0/hls/01JH/index.m3u8" })
        );
        assert_eq!(
            serde_json::from_value::<HlsCreateResult>(json).unwrap(),
            result
        );
    }

    #[test]
    fn events_serialize_with_their_type_and_codes() {
        let warning = HlsEvent::Warning {
            code: LiveWarningCode::AudioOmitted,
            message: "pcmu".into(),
        };
        assert_eq!(
            serde_json::to_value(&warning).unwrap(),
            json!({ "type": "warning", "code": "audio_omitted", "message": "pcmu" })
        );
        let closed = HlsEvent::Closed {
            hls_id: "01JH".into(),
            reason: HlsCloseReason::WindowFull,
        };
        assert_eq!(
            serde_json::to_value(&closed).unwrap(),
            json!({ "type": "closed", "hls_id": "01JH", "reason": "window_full" })
        );
    }

    #[test]
    fn reasons_spell_as_the_api_does() {
        for reason in [
            HlsCloseReason::Closed,
            HlsCloseReason::SessionClosed,
            HlsCloseReason::Idle,
            HlsCloseReason::WindowFull,
            HlsCloseReason::StreamDeleted,
            HlsCloseReason::StreamChanged,
            HlsCloseReason::CodecChanged,
            HlsCloseReason::NoVideoTrack,
            HlsCloseReason::SourceNotLive,
            HlsCloseReason::WorkerCrashed,
            HlsCloseReason::ShuttingDown,
            HlsCloseReason::InternalError,
        ] {
            let json = serde_json::to_value(reason).unwrap();
            assert_eq!(json, serde_json::Value::String(reason.as_str().to_owned()));
            assert_eq!(
                serde_json::from_value::<HlsCloseReason>(json).unwrap(),
                reason
            );
            assert_eq!(reason.to_string(), reason.as_str());
        }
    }
}

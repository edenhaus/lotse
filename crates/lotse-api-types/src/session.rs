//! WebRTC sessions as the API sees them: the `ice_servers` of
//! `webrtc/offer`, the events of the `webrtc/offer` and `session/adopt`
//! subscriptions, and the `Session` of `session/get` and `session/list`.
//!
//! The events (`session`, `answer`, `candidate`) are the signaling
//! messages a client relays to the browser, so it can pass them on almost
//! one to one. The empty `candidate` is JSEP's end-of-candidates
//! (RFC 8829 §4.1.18, RFC 8838 §13).

use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use crate::limits::{MAX_ICE_URLS, MAX_TEXT_CHARS};

/// One entry of `webrtc/offer`'s `ice_servers`, as the client forwards what it
/// gave the browser (the W3C `RTCIceServer` dictionary). `Debug` redacts the
/// credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct IceServer {
    /// `stun:`, `turn:` or `turns:` URLs (RFC 7064, RFC 7065).
    #[cfg_attr(feature = "schema", schemars(length(max = MAX_ICE_URLS), inner(length(max = MAX_TEXT_CHARS))))]
    pub urls: Vec<String>,
    /// The TURN username.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(length(max = MAX_TEXT_CHARS)))]
    pub username: Option<String>,
    /// The TURN credential.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(length(max = MAX_TEXT_CHARS)))]
    pub credential: Option<String>,
}

/// Redacts the username and the credential. `Serialize` is the wire form
/// a client sends, so it keeps them; a serialized command is never logged.
impl fmt::Debug for IceServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceServer")
            .field("urls", &self.urls)
            .field("username", &self.username.as_ref().map(|_| "****"))
            .field("credential", &self.credential.as_ref().map(|_| "****"))
            .finish()
    }
}

/// An event of `webrtc/offer` and `session/adopt`, in the order 04 lists
/// them; `closed` is always the last.
/// Each variant's schema title names the Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    /// The first event: the session's id, the client's or a generated ULID.
    #[cfg_attr(feature = "schema", schemars(title = "SessionEventSession"))]
    Session {
        /// The session.
        session_id: String,
    },
    /// The SDP answer, before any candidate.
    #[cfg_attr(feature = "schema", schemars(title = "SessionEventAnswer"))]
    Answer {
        /// The SDP.
        sdp: String,
    },
    /// A local candidate; an empty `candidate` is end-of-candidates.
    #[cfg_attr(feature = "schema", schemars(title = "SessionEventCandidate"))]
    Candidate {
        /// The `candidate:` attribute value, or empty.
        candidate: String,
        /// The media section it belongs to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp_mid: Option<String>,
        /// The media section's index.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp_mline_index: Option<u32>,
    },
    /// ICE or DTLS changed; also the first event of `session/adopt`.
    #[cfg_attr(feature = "schema", schemars(title = "SessionEventState"))]
    State {
        /// The ICE state, as the browser names it.
        ice: String,
        /// The DTLS state, as the browser names it.
        dtls: String,
    },
    /// Non-fatal. Each code comes at most once per session, but `backchannel_declined`, which
    /// comes once per offer (`webrtc/offer` or `webrtc/renegotiate`) that
    /// asked for talk-back the session did not get: the talk-back m-line
    /// was answered `inactive` (or `sendonly` when it carries the
    /// stream's audio too, RFC 3264 §6.1), and `reason` says why.
    #[cfg_attr(feature = "schema", schemars(title = "SessionEventWarning"))]
    Warning {
        /// The stable code.
        code: WarningCode,
        /// For humans.
        message: String,
        /// Why, for `backchannel_declined`; absent for every other code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<DeclineReason>,
        /// The camera's status code for `refused`, when it gave one
        /// (an RTSP status, 453 Not Enough Bandwidth or 503 Service
        /// Unavailable when a camera's one backchannel is taken by
        /// another client); absent otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
    },
    /// The last event; the subscription ends with it. A session still
    /// waiting for its answer has no deadline of its own: it waits while
    /// its source connects, and closes with the source's error as soon as
    /// the attempt fails, at once when the offer reaches a source that has
    /// already failed. A live source that drops is retried, at once or
    /// after a delay, and the session waits for the retry; only a retry
    /// that fails closes it. While a `stream/put` switches the stream to
    /// another source, the old source's failures do not count. An answered
    /// session rides every reconnect instead. A talk-back request the
    /// stream cannot serve never closes a session: its answer declines
    /// it (`backchannel_declined`).
    #[cfg_attr(feature = "schema", schemars(title = "SessionEventClosed"))]
    Closed {
        /// The stable code. Before the answer, a failed source closes the
        /// session with its error's code, the one `stream/get` reports as
        /// `last_error`: `source_unreachable`, `source_auth_failed`,
        /// `source_timeout`, `source_protocol_error`, `source_ended` or
        /// `worker_crashed`.
        code: CloseCode,
        /// For humans; for a source's error, its text as `last_error`
        /// carries it, never the source's credentials.
        message: String,
    },
}

/// The code of a `warning` event: every code a session may warn with,
/// and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// Audio omitted from the session; the rest of it continues.
    AudioCodecUnsupported,
    /// A `turns:` entry of `ice_servers` was ignored.
    TurnUnsupported,
    /// Audio withdrawn because sync could not be held.
    AvSyncLost,
    /// The browser did not offer the stream's H.264 profile.
    H264ProfileMismatch,
    /// A `webrtc/candidate` the session could not parse was ignored.
    InvalidCandidate,
    /// A video frame needed more RTP packets than some libwebrtc receivers
    /// assemble; it was sent whole.
    FrameOverBrowserLimit,
    /// The offer asked for talk-back the session did not get; `reason`
    /// says why.
    BackchannelDeclined,
}

impl WarningCode {
    /// The code as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AudioCodecUnsupported => "audio_codec_unsupported",
            Self::TurnUnsupported => "turn_unsupported",
            Self::AvSyncLost => "av_sync_lost",
            Self::H264ProfileMismatch => "h264_profile_mismatch",
            Self::InvalidCandidate => "invalid_candidate",
            Self::FrameOverBrowserLimit => "frame_over_browser_limit",
            Self::BackchannelDeclined => "backchannel_declined",
        }
    }

    /// The code for its API name, as a worker reports it.
    pub fn parse(code: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(code.to_owned())).ok()
    }
}

impl fmt::Display for WarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The code of a `closed` event: every reason a session may end, and
/// nothing else. The `source_*` codes and `worker_crashed` are also the
/// codes of `stream/get`'s `last_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum CloseCode {
    /// The browser closed the peer connection.
    PeerClosed,
    /// `unsubscribe`, `session/close`, or the grace expired.
    SessionClosed,
    /// The stream was deleted.
    StreamDeleted,
    /// The codec family changed on reconnect.
    StreamChanged,
    /// The connection's worker process died.
    WorkerCrashed,
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
    /// The offer reached a worker that runs no source.
    SourceNotLive,
    /// ICE failed or stayed disconnected.
    IceFailed,
    /// The offer could not be parsed, or has neither a video nor an
    /// audio m-line.
    InvalidSdp,
    /// The offer has a video m-line, and the stream no video track.
    NoVideoTrack,
    /// No video codec both sides can use.
    VideoCodecUnsupported,
    /// The daemon is shutting down.
    ShuttingDown,
    /// An invariant failed, or a worker reported a code the API does not
    /// know; a bug, always logged with context.
    InternalError,
}

impl CloseCode {
    /// The code as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerClosed => "peer_closed",
            Self::SessionClosed => "session_closed",
            Self::StreamDeleted => "stream_deleted",
            Self::StreamChanged => "stream_changed",
            Self::WorkerCrashed => "worker_crashed",
            Self::SourceUnreachable => "source_unreachable",
            Self::SourceAuthFailed => "source_auth_failed",
            Self::SourceTimeout => "source_timeout",
            Self::SourceProtocolError => "source_protocol_error",
            Self::SourceEnded => "source_ended",
            Self::SourceNotLive => "source_not_live",
            Self::IceFailed => "ice_failed",
            Self::InvalidSdp => "invalid_sdp",
            Self::NoVideoTrack => "no_video_track",
            Self::VideoCodecUnsupported => "video_codec_unsupported",
            Self::ShuttingDown => "shutting_down",
            Self::InternalError => "internal_error",
        }
    }

    /// The code for its API name, as a worker or a connection error
    /// reports it.
    pub fn parse(code: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(code.to_owned())).ok()
    }
}

impl fmt::Display for CloseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an offer's talk-back was declined: the `reason` of a
/// `backchannel_declined` warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeclineReason {
    /// The stream has no backchannel the session can feed: its source
    /// protocol cannot carry audio back, no stream on its connection opted
    /// in to it, the camera offers none, or it takes a codec talk-back
    /// cannot produce from what the offer lists. Or the offer asks for
    /// talk-back on its `sendrecv` downlink audio m-line while the
    /// stream's audio codec cannot reach the camera, so no codec on that
    /// m-line goes both ways (RFC 3264 §6.1): it is answered `sendonly`,
    /// and an offer with a `sendonly` m-line for talk-back gets it. The
    /// message says which.
    Unsupported,
    /// Another session holds the backchannel; `backchannel/release`, its
    /// re-offer dropping talk-back, or its close frees it.
    Busy,
    /// The camera refused the backchannel for this session; `status`
    /// carries its status code when it gave one.
    Refused,
}

impl DeclineReason {
    /// The API name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Busy => "busy",
            Self::Refused => "refused",
        }
    }

    /// The reason for its API name.
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Unsupported, Self::Busy, Self::Refused]
            .into_iter()
            .find(|reason| reason.as_str() == name)
    }
}

/// `webrtc/renegotiate`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct WebrtcRenegotiateResult {
    /// The SDP answer to the re-offer.
    pub sdp: String,
}

/// A session as `session/get` and `session/list` return it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Session {
    /// The session.
    pub session_id: String,
    /// The stream it views.
    pub stream_id: String,
    /// The ICE state, as the browser names it.
    pub ice: String,
    /// The DTLS state, as the browser names it.
    pub dtls: String,
    /// The answer was sent.
    pub answered: bool,
    /// No control connection owns it; it closes when the grace expires
    /// unless a `session/adopt` takes it back.
    pub orphaned: bool,
    /// When the offer arrived, RFC 3339 UTC.
    pub since: String,
    /// Talk-back towards the camera's backchannel; `false` and null when
    /// the last answer did not negotiate it, and the counters zero until
    /// one of the session's answers does.
    #[serde(default)]
    pub backchannel: SessionBackchannel,
}

/// A session's talk-back, as `session/get` reports it.
/// The counters are the worker's, pushed once per second, so they may lag
/// by that much; `negotiated`, `codec` and `talker` are current. They add
/// up over the session's life and never go back: a re-offer that drops
/// talk-back keeps them, and one that adds it again counts on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SessionBackchannel {
    /// The answer accepted the browser's talk-back m-line (`recvonly`, or
    /// `sendrecv` on its downlink audio m-line).
    #[serde(default)]
    pub negotiated: bool,
    /// The session holds the camera's backchannel now: its offer claimed
    /// it, and it keeps it until it closes, re-offers without talk-back
    /// or `backchannel/release`.
    #[serde(default)]
    pub talker: bool,
    /// The talk-back codec the answer named first on that m-line, which the
    /// browser sends (`opus`, `pcmu`, `pcma`); null when not negotiated.
    #[serde(default)]
    pub codec: Option<String>,
    /// Talk-back RTP packets the session received and took.
    #[serde(default)]
    pub packets_received: u64,
    /// Of those, the ones dropped because the session did not hold the
    /// backchannel: its offer was declined, or it was released since.
    #[serde(default)]
    pub packets_dropped_busy: u64,
    /// Payload bytes handed to the camera's backchannel, after the reverse
    /// transcode.
    #[serde(default)]
    pub bytes_sent: u64,
}

/// `session/list`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SessionList {
    /// Every session on every connection, by id.
    pub sessions: Vec<Session>,
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
    fn events_serialize_like_the_contract_examples() {
        for (event, expected) in [
            (
                SessionEvent::Session {
                    session_id: "01J8ZK".into(),
                },
                json!({ "type": "session", "session_id": "01J8ZK" }),
            ),
            (
                SessionEvent::Answer { sdp: "v=0".into() },
                json!({ "type": "answer", "sdp": "v=0" }),
            ),
            (
                SessionEvent::Candidate {
                    candidate: "candidate:1 1 udp 1 192.0.2.1 18556 typ host".into(),
                    sdp_mid: Some("0".into()),
                    sdp_mline_index: None,
                },
                json!({ "type": "candidate",
                        "candidate": "candidate:1 1 udp 1 192.0.2.1 18556 typ host", "sdp_mid": "0" }),
            ),
            // RFC 8838 §13: end-of-candidates is the empty candidate.
            (
                SessionEvent::Candidate {
                    candidate: String::new(),
                    sdp_mid: None,
                    sdp_mline_index: None,
                },
                json!({ "type": "candidate", "candidate": "" }),
            ),
            (
                SessionEvent::State {
                    ice: "connected".into(),
                    dtls: "connected".into(),
                },
                json!({ "type": "state", "ice": "connected", "dtls": "connected" }),
            ),
            (
                SessionEvent::Warning {
                    code: WarningCode::TurnUnsupported,
                    message: "m".into(),
                    reason: None,
                    status: None,
                },
                json!({ "type": "warning", "code": "turn_unsupported", "message": "m" }),
            ),
            (
                SessionEvent::Warning {
                    code: WarningCode::BackchannelDeclined,
                    message: "m".into(),
                    reason: Some(DeclineReason::Busy),
                    status: None,
                },
                json!({ "type": "warning", "code": "backchannel_declined", "message": "m",
                        "reason": "busy" }),
            ),
            (
                SessionEvent::Warning {
                    code: WarningCode::BackchannelDeclined,
                    message: "m".into(),
                    reason: Some(DeclineReason::Refused),
                    status: Some(503),
                },
                json!({ "type": "warning", "code": "backchannel_declined", "message": "m",
                        "reason": "refused", "status": 503 }),
            ),
            (
                SessionEvent::Closed {
                    code: CloseCode::PeerClosed,
                    message: "m".into(),
                },
                json!({ "type": "closed", "code": "peer_closed", "message": "m" }),
            ),
        ] {
            assert_eq!(serde_json::to_value(&event).unwrap(), expected);
            assert_eq!(
                serde_json::from_value::<SessionEvent>(expected).unwrap(),
                event
            );
        }
    }

    #[test]
    fn event_codes_serialize_as_their_snake_case_names_and_parse_back() {
        let warnings = [
            WarningCode::AudioCodecUnsupported,
            WarningCode::TurnUnsupported,
            WarningCode::AvSyncLost,
            WarningCode::H264ProfileMismatch,
            WarningCode::InvalidCandidate,
            WarningCode::FrameOverBrowserLimit,
            WarningCode::BackchannelDeclined,
        ];
        for code in warnings {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(json, serde_json::Value::String(code.as_str().to_owned()));
            assert_eq!(WarningCode::parse(code.as_str()), Some(code));
            assert_eq!(code.to_string(), code.as_str());
        }
        let closes = [
            CloseCode::PeerClosed,
            CloseCode::SessionClosed,
            CloseCode::StreamDeleted,
            CloseCode::StreamChanged,
            CloseCode::WorkerCrashed,
            CloseCode::SourceUnreachable,
            CloseCode::SourceAuthFailed,
            CloseCode::SourceTimeout,
            CloseCode::SourceProtocolError,
            CloseCode::SourceEnded,
            CloseCode::SourceNotLive,
            CloseCode::IceFailed,
            CloseCode::InvalidSdp,
            CloseCode::NoVideoTrack,
            CloseCode::VideoCodecUnsupported,
            CloseCode::ShuttingDown,
            CloseCode::InternalError,
        ];
        for code in closes {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(json, serde_json::Value::String(code.as_str().to_owned()));
            assert_eq!(CloseCode::parse(code.as_str()), Some(code));
            assert_eq!(code.to_string(), code.as_str());
        }
        // A code of the other kind, or none at all, is not one.
        assert_eq!(WarningCode::parse("peer_closed"), None);
        assert_eq!(CloseCode::parse("turn_unsupported"), None);
        assert_eq!(CloseCode::parse("nope"), None);
        assert!(
            serde_json::from_value::<SessionEvent>(
                json!({ "type": "closed", "code": "turn_unsupported", "message": "m" })
            )
            .is_err()
        );
    }

    #[test]
    fn decline_reasons_carry_the_api_names_and_the_result_the_answer() {
        for (reason, name) in [
            (DeclineReason::Unsupported, "unsupported"),
            (DeclineReason::Busy, "busy"),
            (DeclineReason::Refused, "refused"),
        ] {
            assert_eq!(reason.as_str(), name);
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
            assert_eq!(DeclineReason::parse(name), Some(reason));
        }
        assert_eq!(DeclineReason::parse("tired"), None);
        let result = WebrtcRenegotiateResult { sdp: "v=0".into() };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json, json!({ "sdp": "v=0" }));
        assert_eq!(
            serde_json::from_value::<WebrtcRenegotiateResult>(json).unwrap(),
            result
        );
    }

    #[test]
    fn ice_servers_parse_strictly_and_redact_the_credential() {
        let server: IceServer = serde_json::from_value(json!({
            "urls": ["turn:turn.example:3478"], "username": "u", "credential": "hunter2"
        }))
        .unwrap();
        let debug = format!("{server:?}");
        assert_eq!(
            debug,
            r#"IceServer { urls: ["turn:turn.example:3478"], username: Some("****"), credential: Some("****") }"#
        );
        let bare: IceServer = serde_json::from_value(json!({ "urls": ["stun:s"] })).unwrap();
        assert_eq!((bare.username, bare.credential), (None, None));
        assert!(
            format!(
                "{:?}",
                IceServer {
                    urls: vec![],
                    username: None,
                    credential: None
                }
            )
            .contains("username: None, credential: None")
        );
        assert!(serde_json::from_value::<IceServer>(json!({ "urls": [], "url": "x" })).is_err());
    }

    #[test]
    fn sessions_serialize_with_every_field() {
        let session = Session {
            session_id: "s1".into(),
            stream_id: "front".into(),
            ice: "new".into(),
            dtls: "new".into(),
            answered: false,
            orphaned: true,
            since: "2026-09-30T10:00:00.000Z".into(),
            backchannel: SessionBackchannel::default(),
        };
        let list = serde_json::to_value(SessionList {
            sessions: vec![session],
        })
        .unwrap();
        assert_eq!(
            list,
            json!({ "sessions": [{ "session_id": "s1", "stream_id": "front", "ice": "new",
                                   "dtls": "new", "answered": false, "orphaned": true,
                                   "since": "2026-09-30T10:00:00.000Z",
                                   "backchannel": { "negotiated": false, "talker": false, "codec": null,
                                                    "packets_received": 0, "packets_dropped_busy": 0,
                                                    "bytes_sent": 0 } }] })
        );
    }

    #[test]
    fn a_session_from_a_daemon_without_talk_back_parses_with_it_off() {
        let session: Session = serde_json::from_value(json!({
            "session_id": "s1", "stream_id": "front", "ice": "new", "dtls": "new",
            "answered": true, "orphaned": false, "since": "2026-09-30T10:00:00.000Z"
        }))
        .unwrap();
        assert_eq!(session.backchannel, SessionBackchannel::default());
        let partial: SessionBackchannel =
            serde_json::from_value(json!({ "negotiated": true, "codec": "pcmu" })).unwrap();
        assert_eq!(
            (
                partial.negotiated,
                partial.codec.as_deref(),
                partial.bytes_sent
            ),
            (true, Some("pcmu"), 0)
        );
    }
}

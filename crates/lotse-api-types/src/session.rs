//! WebRTC sessions as the API sees them: the `ice_servers` of
//! `webrtc/offer`, the events of the `webrtc/offer` and `session/adopt`
//! subscriptions, and the `Session` of `session/get` and `session/list`.
//!
//! The events (`session`, `answer`, `candidate`) are the signaling
//! messages a client relays to the browser, so it can pass them on almost
//! one to one. The empty `candidate` is JSEP's end-of-candidates
//! (RFC 8829 §4.1.18, RFC 8838 §13).

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::limits::{MAX_ICE_URLS, MAX_TEXT_CHARS};

/// One entry of `webrtc/offer`'s `ice_servers`, as the client forwards what it
/// gave the browser (the W3C `RTCIceServer` dictionary). `Debug` redacts the
/// credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IceServer {
    /// `stun:`, `turn:` or `turns:` URLs (RFC 7064, RFC 7065).
    #[schemars(length(max = MAX_ICE_URLS), inner(length(max = MAX_TEXT_CHARS)))]
    pub urls: Vec<String>,
    /// The TURN username.
    #[serde(default)]
    #[schemars(length(max = MAX_TEXT_CHARS))]
    pub username: Option<String>,
    /// The TURN credential.
    #[serde(default)]
    #[schemars(length(max = MAX_TEXT_CHARS))]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    /// The first event: the session's id, the client's or a generated ULID.
    #[schemars(title = "SessionEventSession")]
    Session {
        /// The session.
        session_id: String,
    },
    /// The SDP answer, before any candidate.
    #[schemars(title = "SessionEventAnswer")]
    Answer {
        /// The SDP.
        sdp: String,
    },
    /// A local candidate; an empty `candidate` is end-of-candidates.
    #[schemars(title = "SessionEventCandidate")]
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
    #[schemars(title = "SessionEventState")]
    State {
        /// The ICE state, as the browser names it.
        ice: String,
        /// The DTLS state, as the browser names it.
        dtls: String,
    },
    /// Non-fatal (`audio_codec_unsupported`, `turn_unsupported`,
    /// `h264_profile_mismatch`, ...).
    #[schemars(title = "SessionEventWarning")]
    Warning {
        /// The stable code.
        code: String,
        /// For humans.
        message: String,
    },
    /// The last event; the subscription ends with it.
    #[schemars(title = "SessionEventClosed")]
    Closed {
        /// The stable code (`peer_closed`, `session_closed`, ...).
        code: String,
        /// For humans.
        message: String,
    },
}

/// A session as `session/get` and `session/list` return it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
}

/// `session/list`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
                    code: "turn_unsupported".into(),
                    message: "m".into(),
                },
                json!({ "type": "warning", "code": "turn_unsupported", "message": "m" }),
            ),
            (
                SessionEvent::Closed {
                    code: "peer_closed".into(),
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
        };
        let list = serde_json::to_value(SessionList {
            sessions: vec![session],
        })
        .unwrap();
        assert_eq!(
            list,
            json!({ "sessions": [{ "session_id": "s1", "stream_id": "front", "ice": "new",
                                   "dtls": "new", "answered": false, "orphaned": true,
                                   "since": "2026-09-30T10:00:00.000Z" }] })
        );
    }
}

//! The signaling of signaled sources as the API carries it: the events of
//! `signaling/subscribe` and the codes a signal closes with.
//!
//! A signaled source (a WebRTC camera whose signaling only the client can
//! reach, a Home Assistant camera entity's) is the offerer: each of its
//! connection attempts opens a signal, whose SDP offer (RFC 8829 §5.2) and
//! trickled candidates (RFC 8838 §8) reach the subscription for its stream
//! as `offer` and `candidate` events; the client relays them to the
//! camera, and the camera's answer (RFC 8829 §5.3), candidates and errors
//! back with `signaling/answer`, `signaling/candidate` and
//! `signaling/error`. An empty `candidate` is the end-of-candidates
//! indication (RFC 8838 §13). `closed` ends a signal, `superseded` the
//! subscription.

use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// An event of `signaling/subscribe`. Never coalesced or shed: a client
/// too slow to take one is disconnected (close code 1008), and the
/// signals of its subscription end. Each variant's schema title names the
/// Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalingEvent {
    /// A connection attempt of a signaled source opened the signal
    /// `signal_id` and offers this SDP; the first event of every signal.
    /// The signal belongs to this subscription: only its control
    /// connection may answer, trickle or end it.
    #[cfg_attr(feature = "schema", schemars(title = "SignalingEventOffer"))]
    Offer {
        /// The signal, a ULID, new for every connection attempt.
        signal_id: String,
        /// The stream whose source offers: the camera the client relays
        /// the offer to, as a signaled source has no address.
        stream_id: String,
        /// The signaled source's protocol (`webrtc`), one of
        /// `info.protocols`.
        protocol: String,
        /// The SDP offer (RFC 8829 §5.2).
        sdp: String,
    },
    /// A candidate of the source's, trickled after the offer (RFC 8838
    /// §8); an empty `candidate` is end-of-candidates for its media
    /// section (§8.2, §13), after which none of that section follows.
    #[cfg_attr(feature = "schema", schemars(title = "SignalingEventCandidate"))]
    Candidate {
        /// The signal.
        signal_id: String,
        /// The `candidate:` attribute value, or empty.
        candidate: String,
        /// The media section it belongs to, when the source named it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp_mid: Option<String>,
        /// The media section's index; always set, 0 for the first.
        sdp_mline_index: u16,
    },
    /// The signal ended; nothing more about it follows, and the client
    /// ends the camera's session. A source whose attempt ended connects
    /// again after its backoff, with a new signal.
    #[cfg_attr(feature = "schema", schemars(title = "SignalingEventClosed"))]
    Closed {
        /// The signal.
        signal_id: String,
        /// The stable code.
        code: SignalCloseCode,
        /// For humans; may change.
        message: String,
    },
    /// Another `signaling/subscribe` took this subscription's scope (the
    /// same stream, or every stream): the last event, after which the
    /// subscription has ended and its signals with it, without a `closed`
    /// each; their sources connect again, offering to the new subscription.
    #[cfg_attr(feature = "schema", schemars(title = "SignalingEventSuperseded"))]
    Superseded {},
}

/// The code of a signaling `closed` event: every reason a signal may end,
/// and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SignalCloseCode {
    /// The source stopped: no one wants the stream any more, it was
    /// deleted, or the daemon shuts down.
    SourceStopped,
    /// The camera's answer did not come in time.
    AnswerTimeout,
    /// The camera's answer could not be used.
    InvalidAnswer,
    /// ICE found no working candidate pair in time (RFC 8445 §8.1).
    IceFailed,
    /// The camera stopped answering ICE consent checks (RFC 7675 §5.1).
    ConsentLost,
    /// The camera closed the connection (a DTLS `close_notify` alert,
    /// RFC 5246 §7.2.1).
    PeerClosed,
    /// The client ended the signal with `signaling/error`, the camera's
    /// error.
    CameraError,
    /// The source lost its signaling: the relay toward the client failed.
    SignalingLost,
    /// The connection's worker process exited.
    WorkerGone,
    /// An invariant failed, or the worker reported a code the API does
    /// not know; a bug, always logged with context.
    InternalError,
}

impl SignalCloseCode {
    /// The code as the API spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceStopped => "source_stopped",
            Self::AnswerTimeout => "answer_timeout",
            Self::InvalidAnswer => "invalid_answer",
            Self::IceFailed => "ice_failed",
            Self::ConsentLost => "consent_lost",
            Self::PeerClosed => "peer_closed",
            Self::CameraError => "camera_error",
            Self::SignalingLost => "signaling_lost",
            Self::WorkerGone => "worker_gone",
            Self::InternalError => "internal_error",
        }
    }

    /// The code for its API name, as a worker reports it.
    pub fn parse(code: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(code.to_owned())).ok()
    }
}

impl fmt::Display for SignalCloseCode {
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
    fn close_codes_serialize_as_their_snake_case_names_and_parse_back() {
        let all = [
            SignalCloseCode::SourceStopped,
            SignalCloseCode::AnswerTimeout,
            SignalCloseCode::InvalidAnswer,
            SignalCloseCode::IceFailed,
            SignalCloseCode::ConsentLost,
            SignalCloseCode::PeerClosed,
            SignalCloseCode::CameraError,
            SignalCloseCode::SignalingLost,
            SignalCloseCode::WorkerGone,
            SignalCloseCode::InternalError,
        ];
        for code in all {
            let json = serde_json::to_value(code).unwrap();
            assert_eq!(json, serde_json::Value::String(code.as_str().to_owned()));
            assert_eq!(SignalCloseCode::parse(code.as_str()), Some(code));
            assert_eq!(code.to_string(), code.as_str());
        }
        assert_eq!(SignalCloseCode::parse("made_up"), None);
        // A session's close code is not a signal's.
        assert_eq!(SignalCloseCode::parse("session_closed"), None);
    }

    #[test]
    fn rfc8838_events_serialize_like_the_contract_examples() {
        let cases = [
            (
                SignalingEvent::Offer {
                    signal_id: "01JSIG".into(),
                    stream_id: "door".into(),
                    protocol: "webrtc".into(),
                    sdp: "v=0\r\n".into(),
                },
                json!({ "type": "offer", "signal_id": "01JSIG", "stream_id": "door",
                        "protocol": "webrtc", "sdp": "v=0\r\n" }),
            ),
            (
                SignalingEvent::Candidate {
                    signal_id: "01JSIG".into(),
                    candidate: "candidate:1 1 udp 1 192.0.2.1 9 typ host".into(),
                    sdp_mid: Some("0".into()),
                    sdp_mline_index: 0,
                },
                json!({ "type": "candidate", "signal_id": "01JSIG",
                        "candidate": "candidate:1 1 udp 1 192.0.2.1 9 typ host",
                        "sdp_mid": "0", "sdp_mline_index": 0 }),
            ),
            // End-of-candidates, its media section unnamed.
            (
                SignalingEvent::Candidate {
                    signal_id: "01JSIG".into(),
                    candidate: String::new(),
                    sdp_mid: None,
                    sdp_mline_index: 0,
                },
                json!({ "type": "candidate", "signal_id": "01JSIG", "candidate": "",
                        "sdp_mline_index": 0 }),
            ),
            (
                SignalingEvent::Closed {
                    signal_id: "01JSIG".into(),
                    code: SignalCloseCode::CameraError,
                    message: "camera: offline".into(),
                },
                json!({ "type": "closed", "signal_id": "01JSIG", "code": "camera_error",
                        "message": "camera: offline" }),
            ),
            (
                SignalingEvent::Superseded {},
                json!({ "type": "superseded" }),
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(serde_json::to_value(&event).unwrap(), expected);
            assert_eq!(
                serde_json::from_value::<SignalingEvent>(expected).unwrap(),
                event
            );
        }
    }
}

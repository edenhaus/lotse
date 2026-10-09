//! The frames on the WebSocket: `hello`, commands' `result`s, `event`s,
//! `pong` and `shutdown`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Declares the single-value `type` field of a frame. An explicit field
/// rather than `#[serde(tag)]`: it lands in the schema as a constant, and
/// a client parsing a frame gets the tag checked.
macro_rules! frame_tag {
    ($(#[$doc:meta])* $name:ident = $value:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
        pub enum $name {
            /// The only value.
            #[default]
            #[serde(rename = $value)]
            Tag,
        }
    };
}

frame_tag! {
    /// `"hello"`.
    HelloTag = "hello"
}
frame_tag! {
    /// `"result"`.
    ResultTag = "result"
}
frame_tag! {
    /// `"event"`.
    EventTag = "event"
}
frame_tag! {
    /// `"pong"`.
    PongTag = "pong"
}
frame_tag! {
    /// `"shutdown"`.
    ShutdownTag = "shutdown"
}

/// The first message on every connection, before any result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Hello {
    /// `"hello"`.
    #[serde(rename = "type")]
    pub kind: HelloTag,
    /// The API version (Semantic Versioning, [`crate::API_VERSION`]); a client checks it
    /// with [`crate::ApiVersion::accepts`].
    pub api: String,
    /// The daemon version (semver).
    pub version: String,
    /// The output kinds compiled in.
    pub outputs: Vec<String>,
    /// Capabilities inside outputs, for a client to gate features on.
    pub features: Vec<String>,
}

/// A successful `result`: exactly one per command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "Success_for_{T}")] // a definition per result type, named after it
pub struct Success<T> {
    /// `"result"`.
    #[serde(rename = "type")]
    pub kind: ResultTag,
    /// The command's id.
    pub id: u64,
    /// Always `true` here.
    pub success: bool,
    /// The command's result.
    pub result: T,
}

impl<T> Success<T> {
    /// The successful result of command `id`.
    pub const fn new(id: u64, result: T) -> Self {
        Self {
            kind: ResultTag::Tag,
            id,
            success: true,
            result,
        }
    }
}

/// A failed `result`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Failure {
    /// `"result"`.
    #[serde(rename = "type")]
    pub kind: ResultTag,
    /// The command's id; `null` when the frame had no readable one.
    pub id: Option<u64>,
    /// Always `false` here.
    pub success: bool,
    /// Why.
    pub error: ApiError,
}

impl Failure {
    /// The failed result of command `id`.
    pub const fn new(id: Option<u64>, error: ApiError) -> Self {
        Self {
            kind: ResultTag::Tag,
            id,
            success: false,
            error,
        }
    }
}

/// An `event` of a subscription; `id` is the subscribing command's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "EventFrame_for_{E}")] // a definition per event type, named after it
pub struct EventFrame<E> {
    /// `"event"`.
    #[serde(rename = "type")]
    pub kind: EventTag,
    /// The subscription's command id.
    pub id: u64,
    /// The event.
    pub event: E,
}

impl<E> EventFrame<E> {
    /// An event on subscription `id`.
    pub const fn new(id: u64, event: E) -> Self {
        Self {
            kind: EventTag::Tag,
            id,
            event,
        }
    }
}

/// The answer to `ping`, sent instead of a `result`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Pong {
    /// `"pong"`.
    #[serde(rename = "type")]
    pub kind: PongTag,
    /// The `ping`'s id.
    pub id: u64,
}

impl Pong {
    /// The answer to `ping` `id`.
    pub const fn new(id: u64) -> Self {
        Self {
            kind: PongTag::Tag,
            id,
        }
    }
}

/// Sent once when the daemon shuts down gracefully, before the close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Shutdown {
    /// `"shutdown"`.
    #[serde(rename = "type")]
    pub kind: ShutdownTag,
}

/// An empty result (`stream/delete`, `unsubscribe`, the subscriptions,
/// `webrtc/candidate`, `session/close`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Empty {}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use serde_json::json;

    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn frames_serialize_like_the_contract_examples() {
        let hello = Hello {
            kind: HelloTag::Tag,
            api: "0.1.0".into(),
            version: "0.1.0".into(),
            outputs: vec!["webrtc".into()],
            features: vec![],
        };
        assert_eq!(
            serde_json::to_value(&hello).unwrap(),
            json!({ "type": "hello", "api": "0.1.0", "version": "0.1.0", "outputs": ["webrtc"], "features": [] })
        );
        assert_eq!(
            serde_json::to_value(Success::new(3, json!({ "created": true }))).unwrap(),
            json!({ "id": 3, "type": "result", "success": true, "result": { "created": true } })
        );
        let failure = Failure::new(Some(3), ApiError::new(ErrorCode::SchemeUnsupported, "no"));
        assert_eq!(
            serde_json::to_value(&failure).unwrap(),
            json!({ "id": 3, "type": "result", "success": false,
                    "error": { "code": "scheme_unsupported", "message": "no" } })
        );
        assert_eq!(
            serde_json::to_value(EventFrame::new(
                7,
                json!({ "type": "answer", "sdp": "v=0" })
            ))
            .unwrap(),
            json!({ "id": 7, "type": "event", "event": { "type": "answer", "sdp": "v=0" } })
        );
        assert_eq!(
            serde_json::to_value(Pong::new(9)).unwrap(),
            json!({ "id": 9, "type": "pong" })
        );
        assert_eq!(
            serde_json::to_value(Shutdown::default()).unwrap(),
            json!({ "type": "shutdown" })
        );
        assert_eq!(serde_json::to_value(Empty::default()).unwrap(), json!({}));
    }

    #[test]
    fn frames_parse_back_for_the_client_side() {
        let hello: Hello = serde_json::from_value(
            json!({ "type": "hello", "api": "0.1.0", "version": "0.1.0", "outputs": [], "features": [] }),
        )
        .unwrap();
        assert_eq!(hello.api, "0.1.0");
        let ok: Success<Empty> = serde_json::from_value(
            json!({ "id": 1, "type": "result", "success": true, "result": {} }),
        )
        .unwrap();
        assert_eq!(ok, Success::new(1, Empty {}));
        let failed: Failure = serde_json::from_value(json!({ "id": 1, "type": "result", "success": false, "error": { "code": "id_reuse", "message": "m" } })).unwrap();
        assert_eq!(failed.error.code, ErrorCode::IdReuse);
        let unaddressed = Failure::new(None, ApiError::new(ErrorCode::InvalidRequest, "m"));
        assert_eq!(
            serde_json::to_value(&unaddressed).unwrap()["id"],
            serde_json::Value::Null
        );
        let pong: Pong = serde_json::from_value(json!({ "id": 2, "type": "pong" })).unwrap();
        assert_eq!(pong, Pong::new(2));
        let event: EventFrame<serde_json::Value> =
            serde_json::from_value(json!({ "id": 5, "type": "event", "event": { "type": "x" } }))
                .unwrap();
        assert_eq!(event.id, 5);
        assert!(
            serde_json::from_value::<Pong>(json!({ "id": 2, "type": "ping" })).is_err(),
            "wrong tag"
        );
    }
}

//! The commands a client sends, and how a text frame becomes one.
//!
//! Parsing is two-staged so a broken command still gets a `result` with
//! its `id`: the envelope (`id`, `type`) is read leniently first, then the
//! full command strictly. Unknown fields are rejected so typos fail loudly.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorCode};
use crate::limits::{
    ID_PATTERN, MAX_ICE_SERVERS, MAX_ICE_URLS, MAX_ID_CHARS, MAX_SDP_CHARS, MAX_SOURCES,
    MAX_TEXT_CHARS, MAX_URL_CHARS,
};
use crate::session::IceServer;
use crate::stream::{AudioMode, Orientation, SourceSpec};

/// `ping`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ping {
    /// The command id.
    pub id: u64,
}

/// `info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Info {
    /// The command id.
    pub id: u64,
}

/// `metrics/get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricsGet {
    /// The command id.
    pub id: u64,
}

/// `schema`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    /// The command id.
    pub id: u64,
}

/// `stream/put`: the idempotent upsert of a stream's desired state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamPut {
    /// The command id.
    pub id: u64,
    /// The stream, `^[A-Za-z0-9._-]{1,128}$`.
    #[schemars(regex(pattern = ID_PATTERN))]
    pub stream_id: String,
    /// The sources, in order; the first that provides a kind wins.
    #[schemars(length(min = 1, max = MAX_SOURCES))]
    pub sources: Vec<SourceSpec>,
    /// Keep the source connected without viewers: connected at put and
    /// reconnected after failures while set, so the first viewer gets a
    /// frame from the warm GOP cache. Changing only this never reconnects;
    /// turning it off with no viewers starts the linger.
    #[serde(default)]
    pub preload: bool,
    /// Audio handling.
    #[serde(default)]
    pub audio: AudioMode,
    /// How the picture is turned for display. A change reaches the open
    /// sessions too, from their next frame and without a new answer.
    /// Changing only this never reconnects.
    #[serde(default)]
    pub orientation: Orientation,
}

/// `stream/get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamGet {
    /// The command id.
    pub id: u64,
    /// The stream.
    #[schemars(regex(pattern = ID_PATTERN))]
    pub stream_id: String,
}

/// `stream/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamList {
    /// The command id.
    pub id: u64,
}

/// `stream/delete`; idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamDelete {
    /// The command id.
    pub id: u64,
    /// The stream.
    #[schemars(regex(pattern = ID_PATTERN))]
    pub stream_id: String,
}

/// `stream/subscribe`: a subscription to one stream's state, or every
/// stream's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamSubscribe {
    /// The command id, which becomes the subscription id.
    pub id: u64,
    /// One stream, or all when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = ID_PATTERN))]
    pub stream_id: Option<String>,
}

/// `unsubscribe`: ends a subscription of this connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Unsubscribe {
    /// The command id.
    pub id: u64,
    /// The subscribing command's id.
    pub subscription: u64,
}

/// `webrtc/offer`: opens a session; the subscription's events carry the
/// whole signaling conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebrtcOffer {
    /// The command id, which becomes the subscription id.
    pub id: u64,
    /// The stream to view.
    #[schemars(regex(pattern = ID_PATTERN))]
    pub stream_id: String,
    /// The client's session id, `^[A-Za-z0-9._-]{1,128}$`; a ULID when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = ID_PATTERN))]
    pub session_id: Option<String>,
    /// The browser's SDP offer.
    #[schemars(length(max = MAX_SDP_CHARS))]
    pub sdp: String,
    /// Overrides the configured ICE servers for this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = MAX_ICE_SERVERS))]
    pub ice_servers: Option<Vec<IceServer>>,
}

/// `webrtc/candidate`: a trickled candidate from the browser, taken only
/// from the connection that owns the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebrtcCandidate {
    /// The command id.
    pub id: u64,
    /// The session.
    #[schemars(regex(pattern = ID_PATTERN))]
    pub session_id: String,
    /// The `candidate:` attribute value; empty is end-of-candidates.
    #[schemars(length(max = MAX_TEXT_CHARS))]
    pub candidate: String,
    /// The media section, when the browser named it (a client may forward
    /// only this string; BUNDLE makes it redundant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = MAX_TEXT_CHARS))]
    pub sdp_mid: Option<String>,
    /// The media section's index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_mline_index: Option<u32>,
}

/// `session/get`, `session/close` and `session/adopt`: one session by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionRef {
    /// The command id.
    pub id: u64,
    /// The session.
    #[schemars(regex(pattern = ID_PATTERN))]
    pub session_id: String,
}

/// `session/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionListCommand {
    /// The command id.
    pub id: u64,
}

/// Every command, tagged by `type`. Each variant's schema title names the
/// Python client's class for it (`StreamPutCommand`), and its `type` names
/// the client's method: `domain/verb` is `client.domain.verb(...)`, a type
/// without a slash a method of the client itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum Command {
    /// `ping`: answered with `pong`, not a `result`.
    #[serde(rename = "ping")]
    #[schemars(title = "PingCommand")]
    Ping(Ping),
    /// `info`: version, build, schemes, outputs, codecs, limits and sandbox.
    #[serde(rename = "info")]
    #[schemars(title = "InfoCommand")]
    Info(Info),
    /// `metrics/get`: process, worker and stream counters.
    #[serde(rename = "metrics/get")]
    #[schemars(title = "MetricsGetCommand")]
    MetricsGet(MetricsGet),
    /// `schema`: the JSON Schema bundle of every message.
    #[serde(rename = "schema")]
    #[schemars(title = "SchemaCommand")]
    Schema(Schema),
    /// `stream/put`: the idempotent upsert of a stream's desired state.
    #[serde(rename = "stream/put")]
    #[schemars(title = "StreamPutCommand")]
    StreamPut(StreamPut),
    /// `stream/get`: one stream's state, sources, tracks and counters.
    #[serde(rename = "stream/get")]
    #[schemars(title = "StreamGetCommand")]
    StreamGet(StreamGet),
    /// `stream/list`: every stream, by id.
    #[serde(rename = "stream/list")]
    #[schemars(title = "StreamListCommand")]
    StreamList(StreamList),
    /// `stream/delete`: removes a stream and closes its sessions; idempotent.
    #[serde(rename = "stream/delete")]
    #[schemars(title = "StreamDeleteCommand")]
    StreamDelete(StreamDelete),
    /// `stream/subscribe`: a subscription to one stream's state, or every
    /// stream's.
    #[serde(rename = "stream/subscribe")]
    #[schemars(title = "StreamSubscribeCommand")]
    StreamSubscribe(StreamSubscribe),
    /// `unsubscribe`: ends a subscription of this connection.
    #[serde(rename = "unsubscribe")]
    #[schemars(title = "UnsubscribeCommand")]
    Unsubscribe(Unsubscribe),
    /// `webrtc/offer`: opens a session; the subscription's events carry the
    /// whole signaling conversation.
    #[serde(rename = "webrtc/offer")]
    #[schemars(title = "WebrtcOfferCommand")]
    WebrtcOffer(WebrtcOffer),
    /// `webrtc/candidate`: a trickled candidate from the browser, taken
    /// only from the connection that owns the session.
    #[serde(rename = "webrtc/candidate")]
    #[schemars(title = "WebrtcCandidateCommand")]
    WebrtcCandidate(WebrtcCandidate),
    /// `session/get`: one session's state.
    #[serde(rename = "session/get")]
    #[schemars(title = "SessionGetCommand")]
    SessionGet(SessionRef),
    /// `session/list`: every session.
    #[serde(rename = "session/list")]
    #[schemars(title = "SessionListCommand")]
    SessionList(SessionListCommand),
    /// `session/close`; idempotent.
    #[serde(rename = "session/close")]
    #[schemars(title = "SessionCloseCommand")]
    SessionClose(SessionRef),
    /// `session/adopt`: takes back an orphaned session.
    #[serde(rename = "session/adopt")]
    #[schemars(title = "SessionAdoptCommand")]
    SessionAdopt(SessionRef),
}

impl Command {
    /// Every command's `type`.
    pub const NAMES: &'static [&'static str] = &[
        "ping",
        "info",
        "metrics/get",
        "schema",
        "stream/put",
        "stream/get",
        "stream/list",
        "stream/delete",
        "stream/subscribe",
        "unsubscribe",
        "webrtc/offer",
        "webrtc/candidate",
        "session/get",
        "session/list",
        "session/close",
        "session/adopt",
    ];

    /// The command's id.
    pub const fn id(&self) -> u64 {
        match self {
            Self::Ping(c) => c.id,
            Self::Info(c) => c.id,
            Self::MetricsGet(c) => c.id,
            Self::Schema(c) => c.id,
            Self::StreamPut(c) => c.id,
            Self::StreamGet(c) => c.id,
            Self::StreamList(c) => c.id,
            Self::StreamDelete(c) => c.id,
            Self::StreamSubscribe(c) => c.id,
            Self::Unsubscribe(c) => c.id,
            Self::WebrtcOffer(c) => c.id,
            Self::WebrtcCandidate(c) => c.id,
            Self::SessionGet(c) | Self::SessionClose(c) | Self::SessionAdopt(c) => c.id,
            Self::SessionList(c) => c.id,
        }
    }

    /// The command's `type`.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ping(_) => "ping",
            Self::Info(_) => "info",
            Self::MetricsGet(_) => "metrics/get",
            Self::Schema(_) => "schema",
            Self::StreamPut(_) => "stream/put",
            Self::StreamGet(_) => "stream/get",
            Self::StreamList(_) => "stream/list",
            Self::StreamDelete(_) => "stream/delete",
            Self::StreamSubscribe(_) => "stream/subscribe",
            Self::Unsubscribe(_) => "unsubscribe",
            Self::WebrtcOffer(_) => "webrtc/offer",
            Self::WebrtcCandidate(_) => "webrtc/candidate",
            Self::SessionGet(_) => "session/get",
            Self::SessionList(_) => "session/list",
            Self::SessionClose(_) => "session/close",
            Self::SessionAdopt(_) => "session/adopt",
        }
    }
}

/// The lenient first look at a frame: whatever `id` and `type` it has.
#[derive(Debug, Default, Deserialize)]
struct Envelope {
    /// The id, if any.
    #[serde(default)]
    id: Option<u64>,
    /// The type, if any.
    #[serde(default, rename = "type")]
    kind: Option<String>,
}

/// A frame that is not a command, with the id to answer under if one was
/// readable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{error}")]
pub struct CommandError {
    /// The frame's id, when it had a usable one.
    pub id: Option<u64>,
    /// `invalid_request` or `unknown_command`.
    pub error: ApiError,
}

/// The longest parser message a `result` repeats, in characters.
const MAX_MESSAGE_CHARS: usize = 256;

/// The longest unknown command `type` a `result` repeats, in characters.
const MAX_ECHOED_TYPE_CHARS: usize = 64;

/// `text` cut to `max` characters, with `…` marking a cut.
fn shorten(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", text.get(..end).unwrap_or_default()),
        None => text.to_owned(),
    }
}

/// serde's message for `err` without the values it quotes, which may be a
/// source URL with its credentials: a string value (serde's
/// `Unexpected::Str`, `string "…"` with Debug escapes) becomes `a string`,
/// an unknown enum value (serde's "unknown variant" with the value in
/// backticks) is dropped, and the rest
/// is cut at [`MAX_MESSAGE_CHARS`]. Field names stay: they are keys, not
/// values, and name the mistake.
fn describe(err: &serde_json::Error) -> String {
    /// Where serde quotes a string value, Debug-escaped.
    const STRING: &str = "string \"";
    /// Where serde quotes an unknown enum value, unescaped.
    const VARIANT: &str = "unknown variant `";
    let message = err.to_string();
    let mut out = String::with_capacity(message.len());
    let mut rest = message.as_str();
    while let Some(start) = rest.find(STRING) {
        let (before, quoted) = rest.split_at(start);
        out.push_str(before);
        out.push_str("a string");
        rest = after_debug_string(quoted.get(STRING.len()..).unwrap_or_default());
    }
    out.push_str(rest);
    if let Some(start) = out.find(VARIANT) {
        let tail = out
            .get(start.saturating_add(VARIANT.len())..)
            .unwrap_or_default();
        let end = ["`, expected ", "`, there are no variants"]
            .iter()
            .filter_map(|marker| tail.find(marker))
            .min()
            .unwrap_or(tail.len());
        let after = tail.get(end.saturating_add(1)..).unwrap_or_default();
        out = format!(
            "{}unknown variant{after}",
            out.get(..start).unwrap_or_default()
        );
    }
    shorten(&out, MAX_MESSAGE_CHARS)
}

/// What follows a Debug-quoted string whose opening quote is already
/// consumed: everything after its closing quote, skipping escaped ones.
fn after_debug_string(quoted: &str) -> &str {
    let mut escaped = false;
    for (index, ch) in quoted.char_indices() {
        match ch {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return quoted.get(index.saturating_add(1)..).unwrap_or_default(),
            _ => {}
        }
    }
    ""
}

/// Parses one text frame into a command. A refusal never repeats a value
/// of the frame, only the names of its fields and a shortened `type`.
pub fn parse_command(text: &str) -> Result<Command, CommandError> {
    let envelope: Envelope = serde_json::from_str(text).map_err(|err| CommandError {
        id: None,
        error: ApiError::new(
            ErrorCode::InvalidRequest,
            format!("not a JSON command: {}", describe(&err)),
        ),
    })?;
    let id = envelope.id;
    let Some(kind) = envelope.kind else {
        return Err(CommandError {
            id,
            error: ApiError::new(ErrorCode::InvalidRequest, "missing `type`"),
        });
    };
    if !Command::NAMES.contains(&kind.as_str()) {
        let kind = shorten(&kind, MAX_ECHOED_TYPE_CHARS);
        return Err(CommandError {
            id,
            error: ApiError::new(
                ErrorCode::UnknownCommand,
                format!("{kind:?} is not a command"),
            )
            .with_detail("type", kind),
        });
    }
    if id.is_none() {
        return Err(CommandError {
            id,
            error: ApiError::new(ErrorCode::InvalidRequest, "missing or non-positive `id`"),
        });
    }
    let command = serde_json::from_str(text).map_err(|err| CommandError {
        id,
        error: ApiError::new(ErrorCode::InvalidRequest, describe(&err))
            .with_detail("type", kind.as_str()),
    })?;
    check_limits(&command).map_err(|error| CommandError {
        id,
        error: error.with_detail("type", kind),
    })?;
    Ok(command)
}

/// Holds a parsed command to the caps of [`crate::limits`], which the
/// schema advertises; the first field over its cap is named, its value is
/// not repeated.
fn check_limits(command: &Command) -> Result<(), ApiError> {
    match command {
        Command::StreamPut(put) => {
            cap_stream_id(&put.stream_id)?;
            cap_items("sources", put.sources.len(), MAX_SOURCES)?;
            for source in &put.sources {
                cap_chars("sources[].url", &source.url, MAX_URL_CHARS)?;
            }
        }
        Command::WebrtcOffer(offer) => {
            cap_stream_id(&offer.stream_id)?;
            let session_id = offer.session_id.as_deref().unwrap_or_default();
            cap_chars("session_id", session_id, MAX_ID_CHARS)?;
            cap_chars("sdp", &offer.sdp, MAX_SDP_CHARS)?;
            let servers = offer.ice_servers.as_deref().unwrap_or_default();
            cap_items("ice_servers", servers.len(), MAX_ICE_SERVERS)?;
            for server in servers {
                cap_items("ice_servers[].urls", server.urls.len(), MAX_ICE_URLS)?;
                for url in &server.urls {
                    cap_chars("ice_servers[].urls[]", url, MAX_TEXT_CHARS)?;
                }
                let username = server.username.as_deref().unwrap_or_default();
                cap_chars("ice_servers[].username", username, MAX_TEXT_CHARS)?;
                let credential = server.credential.as_deref().unwrap_or_default();
                cap_chars("ice_servers[].credential", credential, MAX_TEXT_CHARS)?;
            }
        }
        Command::WebrtcCandidate(candidate) => {
            cap_chars("session_id", &candidate.session_id, MAX_ID_CHARS)?;
            cap_chars("candidate", &candidate.candidate, MAX_TEXT_CHARS)?;
            let mid = candidate.sdp_mid.as_deref().unwrap_or_default();
            cap_chars("sdp_mid", mid, MAX_TEXT_CHARS)?;
        }
        Command::SessionGet(session)
        | Command::SessionClose(session)
        | Command::SessionAdopt(session) => {
            cap_chars("session_id", &session.session_id, MAX_ID_CHARS)?;
        }
        Command::StreamGet(StreamGet { stream_id, .. })
        | Command::StreamDelete(StreamDelete { stream_id, .. }) => cap_stream_id(stream_id)?,
        Command::StreamSubscribe(subscribe) => {
            cap_stream_id(subscribe.stream_id.as_deref().unwrap_or_default())?;
        }
        Command::Ping(_)
        | Command::Info(_)
        | Command::MetricsGet(_)
        | Command::Schema(_)
        | Command::StreamList(_)
        | Command::Unsubscribe(_)
        | Command::SessionList(_) => {}
    }
    Ok(())
}

/// `invalid_request` when `value` is longer than `max` characters.
fn cap_chars(field: &str, value: &str, max: usize) -> Result<(), ApiError> {
    let len = value.chars().count();
    if len > max {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("`{field}` is {len} characters long, the maximum is {max}"),
        )
        .with_detail("field", field));
    }
    Ok(())
}

/// `invalid_stream_id` when a `stream_id` is longer than an id can be, so
/// an over-long id keeps the code a malformed one gets where it is used
/// and is never repeated, whether it is used, looked up or deleted.
fn cap_stream_id(stream_id: &str) -> Result<(), ApiError> {
    cap_chars("stream_id", stream_id, MAX_ID_CHARS).map_err(|error| ApiError {
        code: ErrorCode::InvalidStreamId,
        ..error
    })
}

/// `invalid_request` when a list has more than `max` entries.
fn cap_items(field: &str, len: usize, max: usize) -> Result<(), ApiError> {
    if len > max {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            format!("`{field}` has {len} entries, the maximum is {max}"),
        )
        .with_detail("field", field));
    }
    Ok(())
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

    /// A copy of `lotse_core::let_assert!`, identical to it, for this
    /// crate's tests: `lotse-api-types` does not depend on `lotse-core`
    /// and gains no dependency for a test macro. Binds `$pattern` in
    /// `$value` or fails the test with the value, the failure arm on the
    /// call's lines, which a passing test runs, so the line-coverage gate
    /// counts them. Change both together.
    macro_rules! let_assert {
        ($pattern:pat = $value:expr) => {
            let value = $value;
            let $pattern = value else {
                panic!("`{}` does not match {value:?}", stringify!($pattern));
            };
        };
        ($pattern:pat = $value:expr, $($message:tt)+) => {
            let value = $value;
            let $pattern = value else {
                panic!("`{}` does not match {value:?}: {}", stringify!($pattern), format_args!($($message)+));
            };
        };
    }

    #[test]
    fn every_command_parses_from_the_contract_shape() {
        let put = parse_command(
            r#"{ "id": 3, "type": "stream/put", "stream_id": "front",
                 "sources": [ { "url": "rtsp://user:pass@192.168.1.10:554/h264",
                                "options": { "transport": "tcp" } } ],
                 "preload": true, "audio": "off", "orientation": "rotate_left" }"#,
        )
        .unwrap();
        assert_eq!((put.name(), put.id()), ("stream/put", 3));
        let_assert!(Command::StreamPut(put) = put);
        assert_eq!(
            (put.id, put.stream_id.as_str(), put.preload, put.audio),
            (3, "front", true, AudioMode::Off)
        );
        assert_eq!(put.sources[0].options["transport"], "tcp");
        assert_eq!(put.orientation, Orientation::RotateLeft);

        let cases = [
            (r#"{"id":1,"type":"ping"}"#, "ping"),
            (r#"{"id":2,"type":"info"}"#, "info"),
            (r#"{"id":3,"type":"metrics/get"}"#, "metrics/get"),
            (r#"{"id":4,"type":"schema"}"#, "schema"),
            (
                r#"{"id":5,"type":"stream/get","stream_id":"front"}"#,
                "stream/get",
            ),
            (r#"{"id":6,"type":"stream/list"}"#, "stream/list"),
            (
                r#"{"id":7,"type":"stream/delete","stream_id":"front"}"#,
                "stream/delete",
            ),
            (r#"{"id":8,"type":"stream/subscribe"}"#, "stream/subscribe"),
            (
                r#"{"id":9,"type":"stream/subscribe","stream_id":"front"}"#,
                "stream/subscribe",
            ),
            (
                r#"{"id":10,"type":"unsubscribe","subscription":8}"#,
                "unsubscribe",
            ),
            (
                r#"{"id":11,"type":"webrtc/offer","stream_id":"front","session_id":"01J8ZK","sdp":"v=0","ice_servers":[{"urls":["stun:stun.example.org:3478"],"username":null,"credential":null}]}"#,
                "webrtc/offer",
            ),
            (
                r#"{"id":12,"type":"webrtc/candidate","session_id":"01J8ZK","candidate":"candidate:1 1 udp 1 192.0.2.1 5 typ host","sdp_mid":"0","sdp_mline_index":0}"#,
                "webrtc/candidate",
            ),
            (
                r#"{"id":13,"type":"session/get","session_id":"s"}"#,
                "session/get",
            ),
            (r#"{"id":14,"type":"session/list"}"#, "session/list"),
            (
                r#"{"id":15,"type":"session/close","session_id":"s"}"#,
                "session/close",
            ),
            (
                r#"{"id":16,"type":"session/adopt","session_id":"s"}"#,
                "session/adopt",
            ),
        ];
        for (index, (text, name)) in cases.iter().enumerate() {
            let command = parse_command(text);
            assert!(command.is_ok(), "{text}: {command:?}");
            let command = command.unwrap();
            assert_eq!(command.name(), *name);
            assert_eq!(command.id(), u64::try_from(index).unwrap() + 1);
            // Commands serialize back into the same shape, for `lotse ctl`.
            let json = serde_json::to_value(&command).unwrap();
            assert_eq!(json["type"], *name);
            assert_eq!(serde_json::from_value::<Command>(json).unwrap(), command);
        }
        assert_eq!(Command::NAMES.len(), cases.len());
        let minimal = parse_command(
            r#"{"id":1,"type":"stream/put","stream_id":"x","sources":[{"url":"rtsp://c/"}]}"#,
        )
        .unwrap();
        let_assert!(Command::StreamPut(minimal) = minimal);
        assert!(
            !minimal.preload
                && minimal.audio == AudioMode::Auto
                && minimal.orientation == Orientation::NoTransform
                && minimal.sources[0].options.is_empty()
        );
        // A client may send only the offer and the stream; the rest defaults.
        let_assert!(
            Command::WebrtcOffer(offer) =
                parse_command(r#"{"id":1,"type":"webrtc/offer","stream_id":"x","sdp":"v=0"}"#)
                    .unwrap()
        );
        assert_eq!((offer.session_id, offer.ice_servers), (None, None));
        let_assert!(
            Command::WebrtcCandidate(candidate) = parse_command(
                r#"{"id":1,"type":"webrtc/candidate","session_id":"s","candidate":""}"#
            )
            .unwrap()
        );
        assert_eq!((candidate.sdp_mid, candidate.sdp_mline_index), (None, None));
    }

    /// `frame` parsed, or the field and message of its refusal; the
    /// refusal must never repeat a value.
    fn limited(frame: &serde_json::Value) -> Result<Command, (String, String)> {
        parse_command(&frame.to_string()).map_err(|err| {
            assert_eq!(err.id, Some(1));
            assert_eq!(err.error.code, ErrorCode::InvalidRequest);
            assert_eq!(err.error.details["type"], frame["type"]);
            assert!(!err.error.message.contains("xx"), "{}", err.error.message);
            let field = err.error.details["field"].as_str().unwrap().to_owned();
            (field, err.error.message)
        })
    }

    #[test]
    fn every_string_and_list_input_is_capped_at_its_limit_and_no_further() {
        let text = |n: usize| "x".repeat(n);
        let put = |sources: usize, url: usize| {
            let source = json!({ "url": format!("rtsp://c/{}", text(url - 9)) });
            json!({ "id": 1, "type": "stream/put", "stream_id": "a", "sources": vec![source; sources] })
        };
        let server = |urls: usize, url: usize, username: usize, credential: usize| json!({ "urls": vec![text(url); urls], "username": text(username), "credential": text(credential) });
        let offer = |sdp: usize, servers: Vec<serde_json::Value>| json!({ "id": 1, "type": "webrtc/offer", "stream_id": "a", "sdp": text(sdp), "ice_servers": servers });
        let candidate = |session: usize, candidate: usize, mid: usize| json!({ "id": 1, "type": "webrtc/candidate", "session_id": text(session), "candidate": text(candidate), "sdp_mid": text(mid) });
        let at_cap = server(MAX_ICE_URLS, MAX_TEXT_CHARS, MAX_TEXT_CHARS, MAX_TEXT_CHARS);
        let accepted = [
            put(MAX_SOURCES, MAX_URL_CHARS),
            offer(MAX_SDP_CHARS, vec![at_cap.clone(); MAX_ICE_SERVERS]),
            candidate(MAX_ID_CHARS, MAX_TEXT_CHARS, MAX_TEXT_CHARS),
        ];
        for frame in &accepted {
            assert!(limited(frame).is_ok(), "{}", frame["type"]);
        }
        let refused = [
            (put(MAX_SOURCES + 1, 10), "sources"),
            (put(1, MAX_URL_CHARS + 1), "sources[].url"),
            (offer(MAX_SDP_CHARS + 1, vec![]), "sdp"),
            (offer(1, vec![at_cap; MAX_ICE_SERVERS + 1]), "ice_servers"),
            (
                offer(1, vec![server(MAX_ICE_URLS + 1, 1, 1, 1)]),
                "ice_servers[].urls",
            ),
            (
                offer(1, vec![server(1, MAX_TEXT_CHARS + 1, 1, 1)]),
                "ice_servers[].urls[]",
            ),
            (
                offer(1, vec![server(1, 1, MAX_TEXT_CHARS + 1, 1)]),
                "ice_servers[].username",
            ),
            (
                offer(1, vec![server(1, 1, 1, MAX_TEXT_CHARS + 1)]),
                "ice_servers[].credential",
            ),
            (candidate(MAX_ID_CHARS + 1, 1, 1), "session_id"),
            (candidate(1, MAX_TEXT_CHARS + 1, 1), "candidate"),
            (candidate(1, 1, MAX_TEXT_CHARS + 1), "sdp_mid"),
        ];
        for (frame, field) in &refused {
            let (named, message) = limited(frame).unwrap_err();
            assert_eq!(named, *field, "{message}");
            assert!(message.starts_with(&format!("`{field}` ")), "{message}");
        }
        let (_, message) = limited(&put(MAX_SOURCES + 1, 10)).unwrap_err();
        assert_eq!(message, "`sources` has 9 entries, the maximum is 8");
        let (_, message) = limited(&candidate(1, 1, MAX_TEXT_CHARS + 1)).unwrap_err();
        assert_eq!(
            message,
            "`sdp_mid` is 1025 characters long, the maximum is 1024"
        );
        // Characters count, not bytes: 1024 two-byte characters fit.
        let mut wide = candidate(1, 1, 1);
        wide["candidate"] = json!("é".repeat(MAX_TEXT_CHARS));
        assert!(limited(&wide).is_ok());
        // Absent optional fields are within every cap.
        assert!(limited(&json!({ "id": 1, "type": "webrtc/offer", "stream_id": "a", "sdp": "v=0", "ice_servers": [{ "urls": [] }] })).is_ok());
        assert!(
            limited(
                &json!({ "id": 1, "type": "webrtc/candidate", "session_id": "s", "candidate": "" })
            )
            .is_ok()
        );
        for kind in ["session/get", "session/close", "session/adopt"] {
            let frame = |n| json!({ "id": 1, "type": kind, "session_id": text(n) });
            assert!(limited(&frame(MAX_ID_CHARS)).is_ok(), "{kind}");
            assert_eq!(
                limited(&frame(MAX_ID_CHARS + 1)).unwrap_err().0,
                "session_id",
                "{kind}"
            );
        }
        // The offer's own session id is capped like the looked-up ones.
        let offer_as = |n| json!({ "id": 1, "type": "webrtc/offer", "stream_id": "a", "session_id": text(n), "sdp": "v=0" });
        assert!(limited(&offer_as(MAX_ID_CHARS)).is_ok());
        assert_eq!(
            limited(&offer_as(MAX_ID_CHARS + 1)).unwrap_err().0,
            "session_id"
        );
    }

    #[test]
    fn every_stream_id_is_capped_at_parse_as_an_invalid_stream_id_without_its_value() {
        let id = |n: usize| "x".repeat(n);
        let frames = |n: usize| {
            [
                json!({ "id": 1, "type": "stream/put", "stream_id": id(n), "sources": [{ "url": "rtsp://c/" }] }),
                json!({ "id": 1, "type": "stream/get", "stream_id": id(n) }),
                json!({ "id": 1, "type": "stream/delete", "stream_id": id(n) }),
                json!({ "id": 1, "type": "stream/subscribe", "stream_id": id(n) }),
                json!({ "id": 1, "type": "webrtc/offer", "stream_id": id(n), "sdp": "v=0" }),
            ]
        };
        for frame in frames(MAX_ID_CHARS) {
            let kind = &frame["type"];
            assert!(parse_command(&frame.to_string()).is_ok(), "{kind}");
        }
        for frame in frames(MAX_ID_CHARS + 1) {
            let kind = &frame["type"];
            let err = parse_command(&frame.to_string()).unwrap_err();
            assert_eq!(err.id, Some(1));
            assert_eq!(err.error.code, ErrorCode::InvalidStreamId, "{kind}");
            assert_eq!(err.error.details["field"], "stream_id");
            assert_eq!(err.error.details["type"], frame["type"]);
            assert_eq!(
                err.error.message,
                "`stream_id` is 129 characters long, the maximum is 128"
            );
            assert!(!err.error.to_string().contains("xx"), "{}", err.error);
        }
        // Characters count, not bytes; a subscription to all has none.
        let wide = json!({ "id": 1, "type": "stream/get", "stream_id": "é".repeat(MAX_ID_CHARS) });
        assert!(parse_command(&wide.to_string()).is_ok());
        assert!(parse_command(r#"{"id":1,"type":"stream/subscribe"}"#).is_ok());
    }

    #[test]
    fn a_refusal_never_repeats_a_value_of_the_frame() {
        let refused = |text: &str| {
            let err = parse_command(text).unwrap_err();
            assert!(
                !err.error.message.contains("secret"),
                "{}",
                err.error.message
            );
            err.error.message
        };
        // A wrong-typed `sources` carrying a source URL with credentials.
        let message = refused(
            r#"{"id":1,"type":"stream/put","stream_id":"a","sources":"rtsp://user:secret@cam/"}"#,
        );
        assert!(
            message.starts_with("invalid type: a string, expected a sequence"),
            "{message}"
        );
        // Escaped quotes do not end the value early.
        let message =
            refused(r#"{"id":1,"type":"stream/put","stream_id":"a","sources":"x\"secret\"y"}"#);
        assert!(
            message.starts_with("invalid type: a string, expected"),
            "{message}"
        );
        let message = refused(
            r#"{"id":1,"type":"stream/put","stream_id":"a","sources":[{"url":"x"}],"audio":"secret"}"#,
        );
        assert!(
            message.starts_with("unknown variant, expected `auto` or `off`"),
            "{message}"
        );
        let message = refused(r#"{"id":"secret","type":"ping"}"#);
        assert!(
            message.starts_with("not a JSON command: invalid type: a string, expected u64"),
            "{message}"
        );

        // Field names stay, shortened with the rest of the message.
        let long_key = format!(r#"{{"id":1,"type":"ping","{}":1}}"#, "k".repeat(1000));
        let message = parse_command(&long_key).unwrap_err().error.message;
        assert!(message.starts_with("unknown field `kkk"), "{message}");
        assert_eq!(message.chars().count(), MAX_MESSAGE_CHARS + 1);
        assert!(message.ends_with("k…"));

        let long_type = format!(r#"{{"id":1,"type":"{}"}}"#, "t".repeat(1000));
        let err = parse_command(&long_type).unwrap_err();
        let echoed = format!("{}…", "t".repeat(MAX_ECHOED_TYPE_CHARS));
        assert_eq!(err.error.details["type"], echoed.as_str());
        assert_eq!(err.error.message, format!("{echoed:?} is not a command"));
    }

    #[test]
    fn serde_messages_lose_their_values_in_every_shape() {
        use serde::de::Error as _;

        #[derive(Debug, Deserialize)]
        enum Never {}
        let err = serde_json::from_str::<Never>(r#""secret""#).unwrap_err();
        let message = describe(&err);
        assert!(
            message.starts_with("unknown variant, there are no variants"),
            "{message}"
        );
        let custom = |message: &str| describe(&serde_json::Error::custom(message));
        assert_eq!(custom("unknown variant `secret"), "unknown variant");
        assert_eq!(
            custom(r#"first string "a", then string "b\"c" and the end"#),
            "first a string, then a string and the end"
        );
        assert_eq!(custom(r#"string "never closed"#), "a string");
        assert_eq!(after_debug_string(r#"a\"b" rest"#), " rest");
        assert_eq!(after_debug_string(r#"a\\" rest"#), " rest");
        assert_eq!(after_debug_string("open"), "");
        assert_eq!(shorten("abc", 3), "abc");
        assert_eq!(shorten("abcd", 3), "abc…");
        assert_eq!(shorten("äöüß", 2), "äö…");
    }

    #[test]
    fn broken_frames_get_the_right_code_and_keep_their_id() {
        let err = parse_command("not json").unwrap_err();
        assert_eq!((err.id, err.error.code), (None, ErrorCode::InvalidRequest));
        assert!(
            err.to_string()
                .starts_with("invalid_request: not a JSON command")
        );

        let err = parse_command(r#"{"id": 4}"#).unwrap_err();
        assert_eq!(
            (err.id, err.error.code),
            (Some(4), ErrorCode::InvalidRequest)
        );
        assert_eq!(err.error.message, "missing `type`");

        let err = parse_command(r#"{"id": 5, "type": "stream/explode"}"#).unwrap_err();
        assert_eq!(
            (err.id, err.error.code),
            (Some(5), ErrorCode::UnknownCommand)
        );
        assert_eq!(err.error.details["type"], "stream/explode");

        let err = parse_command(r#"{"type": "ping"}"#).unwrap_err();
        assert_eq!((err.id, err.error.code), (None, ErrorCode::InvalidRequest));
        assert!(err.error.message.contains("id"));

        let err = parse_command(r#"{"id": 6, "type": "ping", "extra": 1}"#).unwrap_err();
        assert_eq!(
            (err.id, err.error.code),
            (Some(6), ErrorCode::InvalidRequest)
        );
        assert!(err.error.message.contains("extra"), "{}", err.error.message);
        assert_eq!(err.error.details["type"], "ping");

        let err = parse_command(r#"{"id": 7, "type": "stream/get"}"#).unwrap_err();
        assert!(
            err.error.message.contains("stream_id"),
            "{}",
            err.error.message
        );

        let err = parse_command(r#"{"id": -1, "type": "ping"}"#).unwrap_err();
        assert_eq!((err.id, err.error.code), (None, ErrorCode::InvalidRequest));

        let err = parse_command(r#"{"id": 8, "type": "stream/put", "stream_id": "x", "sources": [{"url": "rtsp://c/", "opt": 1}]}"#).unwrap_err();
        assert!(err.error.message.contains("opt"), "{}", err.error.message);
        assert_eq!(
            err.error.to_string(),
            format!("invalid_request: {}", err.error.message)
        );
        let _ = json!({});
    }
}

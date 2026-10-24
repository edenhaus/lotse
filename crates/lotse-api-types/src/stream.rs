//! Streams as the API sees them: the `stream/put` parameters, the `Stream`
//! of `stream/get` and `stream/list`, and the events of `stream/subscribe`.

use std::collections::BTreeMap;
use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// One entry of `stream/put`'s `sources`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SourceSpec {
    /// The source URL, credentials included; redacted everywhere it is
    /// reported.
    #[cfg_attr(feature = "schema", schemars(length(max = crate::limits::MAX_URL_CHARS)))]
    pub url: String,
    /// Per-scheme options, typed by the scheme's factory; unknown fields
    /// there are rejected too.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// Prints the URL's scheme only and the options' names without their
/// values, which a future scheme may make secret. The URL is not parsed
/// yet, so where its userinfo, path and query end is not known, and any of
/// them can carry a secret. `Serialize` is the wire form a client sends,
/// so it keeps both; a serialized command is never logged.
impl fmt::Debug for SourceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceSpec")
            .field("url", &redact_unparsed(&self.url))
            .field("options", &self.options.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// `url` as `scheme://****` when it starts with a scheme (RFC 3986 §3.1:
/// a letter, then letters, digits, `+`, `-` and `.`) and `://`, else
/// `****`: the redacted form of a URL not parsed yet. A parsed source URL
/// prints its origin too (`lotse_core::secret::RedactedUrl`).
fn redact_unparsed(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, _))
            if scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            format!("{scheme}://****")
        }
        _ => "****".to_owned(),
    }
}

/// `stream/put`'s `audio`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AudioMode {
    /// Audio when the source has it.
    #[default]
    Auto,
    /// Video-first: audio m-lines answered `inactive`, no transcoder.
    Off,
}

/// `stream/put`'s `orientation`: how the picture is turned for display,
/// one of eight transforms by its lowercase name. Their numbers, 1 to 8,
/// follow the EXIF orientation tag's values, but 6 turns the picture a
/// quarter counterclockwise and 8 a quarter clockwise. A session
/// whose browser offered the video orientation extension carries it to
/// the browser, which turns the picture; others get it as the camera
/// sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Orientation {
    /// 1: as the camera sends it.
    #[default]
    NoTransform,
    /// 2: mirrored left to right.
    Mirror,
    /// 3: turned half way round.
    #[serde(rename = "rotate_180")]
    Rotate180,
    /// 4: flipped top to bottom.
    Flip,
    /// 5: turned a quarter counterclockwise, then flipped top to bottom.
    RotateLeftAndFlip,
    /// 6: turned a quarter counterclockwise.
    RotateLeft,
    /// 7: turned a quarter clockwise, then flipped top to bottom.
    RotateRightAndFlip,
    /// 8: turned a quarter clockwise.
    RotateRight,
}

impl Orientation {
    /// Its number, 1 to 8, which the supervisor
    /// hands the worker.
    pub const fn code(self) -> u8 {
        match self {
            Self::NoTransform => 1,
            Self::Mirror => 2,
            Self::Rotate180 => 3,
            Self::Flip => 4,
            Self::RotateLeftAndFlip => 5,
            Self::RotateLeft => 6,
            Self::RotateRightAndFlip => 7,
            Self::RotateRight => 8,
        }
    }
}

/// The connection state a stream shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    /// No demand, no worker.
    Idle,
    /// Connecting to the source.
    Connecting,
    /// Media flows.
    Live,
    /// The source dropped; reconnecting at once.
    Reconnecting,
    /// Waiting out the reconnect delay.
    Backoff,
    /// Demand went away; the linger timer runs.
    Draining,
    /// The worker crashed; the crash-backoff timer runs.
    Restarting,
}

impl StreamState {
    /// The API name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Live => "live",
            Self::Reconnecting => "reconnecting",
            Self::Backoff => "backoff",
            Self::Draining => "draining",
            Self::Restarting => "restarting",
        }
    }
}

/// The last error of a stream, or the connection it reads from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LastError {
    /// The error.
    #[serde(flatten)]
    pub error: ApiError,
    /// When it happened, RFC 3339.
    pub at: String,
}

/// The worker running a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct WorkerInfo {
    /// Its process id.
    pub pid: u32,
    /// Crash restarts so far.
    pub restarts: u32,
    /// When it last crashed, RFC 3339.
    pub last_crash: Option<String>,
    /// Its proportional set size, read by the supervisor.
    pub pss_bytes: Option<u64>,
}

/// The upstream connection behind a source: the stream's own, since a
/// source URL belongs to one stream (`source_in_use`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ConnectionInfo {
    /// The connection's id.
    pub id: String,
    /// Its worker, while one runs.
    pub worker: Option<WorkerInfo>,
}

/// A source as `stream/get` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SourceInfo {
    /// The URL redacted to its origin, `scheme://[****@]host[:port]`, then
    /// `/****` when the path is anything but empty or `/` and `?****` when
    /// a query is present: the path and query can carry secrets (a camera
    /// key, a session token) as the userinfo can.
    pub url: String,
    /// The protocol (`rtsp`).
    pub protocol: String,
    /// The connection's state.
    pub state: StreamState,
    /// Reconnects so far.
    pub reconnects: u32,
    /// The camera's backchannel, as the connection's probe found it, while
    /// the connection is live: what a microphone button is gated on. The
    /// probe asks the camera on a connection of its own each time the
    /// connection connects; nothing is opened until a talker claims it.
    /// Null when the probe found none (the camera has none, refused the
    /// question or could not be asked), when no stream on the connection
    /// opted in (an RTSP source's `backchannel` option, off by default,
    /// which turns the probe on and off without restarting the
    /// connection), and while the connection is not live.
    #[serde(default)]
    pub backchannel: Option<SourceBackchannel>,
    /// The shared connection.
    pub connection: ConnectionInfo,
}

/// A source's backchannel as `stream/get` reports it: the camera's reverse
/// audio path (an RTSP camera's ONVIF backchannel, ONVIF Streaming
/// Specification §5.3), one per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SourceBackchannel {
    /// The codec the camera takes (`pcmu`, `pcma`, `opus`); a viewer's
    /// talk-back in another codec is transcoded to it.
    pub codec: String,
    /// Whether a session holds it.
    pub state: BackchannelState,
}

/// Whether a session holds a source's backchannel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BackchannelState {
    /// Nobody talks and no camera session of it is open: the next offer
    /// that asks for talk-back claims it.
    Available,
    /// A session holds it, the stream's `backchannel.talker`: the
    /// camera's backchannel session for it is opening or open.
    InUse,
}

/// A track as `stream/get` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct TrackInfo {
    /// `v0`, `a0`, `a1`.
    pub id: String,
    /// `video` or `audio`.
    pub kind: String,
    /// The codec name (`h264`, `aac_lc`).
    pub codec: String,
    /// The native track a derived track came from.
    pub derived_from: Option<String>,
    /// How the track is timed now: `arrival` until the camera's first
    /// Sender Report for it, `sender_reports` from then on, `arrival` again
    /// on a new timeline until the next report; at most a second old. A
    /// derived track's is its source's.
    pub sync: String,
    /// The delay a derived track's transcoder adds, in milliseconds; absent
    /// on native tracks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_delay_ms: Option<u32>,
    /// An H.264 track's `profile-level-id` (RFC 6184 §8.1): its sequence
    /// parameter set's `profile_idc`, constraint flags and `level_idc` as
    /// six lowercase hex digits, as an SDP `fmtp` spells them (`42e01f`).
    /// Absent on other codecs, and until the camera sent its SPS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(regex(pattern = r"^[0-9a-f]{6}$")))]
    pub profile_level_id: Option<String>,
    /// A video track's picture width in pixels, cropping applied (ISO/IEC
    /// 14496-10 §7.4.2.1.1, ITU-T H.265 §7.4.3.2.1). Absent on audio and
    /// MJPEG tracks, and until the camera sent its SPS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// A video track's picture height in pixels, present with `width`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// An audio track's sampling rate in Hz, which is not always its RTP
    /// clock rate: G.722 samples at 16000 on an 8000 clock (RFC 3551
    /// §4.5.2), Opus is decoded at 48000 (RFC 7587 §4.1), AAC at its
    /// `AudioSpecificConfig`'s rate (ISO/IEC 14496-3 §1.6.2.1). Absent on
    /// video tracks and on codecs the daemon cannot carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<u32>,
    /// An audio track's channel count: 1 for G.711 and G.722 (RFC 3551
    /// §4.5), the stream's own for Opus and AAC. Absent where
    /// `sample_rate` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<u8>,
    /// Frames seen.
    pub frames: u64,
    /// Bytes seen.
    pub bytes: u64,
    /// What the track's pre-roll ring holds for clips; null without a
    /// window (`stream/put`'s `preroll_ms` 0). The worker's figures,
    /// pushed once per second.
    #[serde(default)]
    pub preroll: Option<TrackPreroll>,
}

/// A track's pre-roll ring, as `stream/get` reports it: whole GOPs of the
/// newest media, kept for clips while the stream has a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct TrackPreroll {
    /// The memory the ring holds: its frames' payloads plus a fixed cost
    /// per frame, at most `limits.preroll_bytes`. The open GOP is also in
    /// the track's GOP cache, so the two overlap; the frames are shared,
    /// not copied.
    pub bytes: u64,
    /// The window it holds, in milliseconds: from its oldest keyframe to
    /// its newest frame; shorter than `preroll_ms` while it fills, after
    /// a reconnect, or when `limits.preroll_bytes` caps it.
    pub held_ms: u32,
    /// GOPs larger than `limits.preroll_bytes` the ring could keep only
    /// the start of.
    pub truncations: u64,
}

/// A stream's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct StreamStats {
    /// Frames dropped as oversize.
    #[serde(default)]
    pub frames_dropped: u64,
    /// Video frames the live path carried in more RTP packets than some
    /// libwebrtc receivers assemble (2047), depending on their version;
    /// every session sends them whole, and those viewers may freeze until
    /// a keyframe that fits.
    #[serde(default)]
    pub frames_over_browser_limit: u64,
    /// Times the skew watchdog withdrew the stream's audio for sync; at
    /// most 1, since it stays withdrawn while the source runs.
    #[serde(default)]
    pub av_sync_lost: u64,
    /// RTP packets from the camera that never arrived, by their sequence
    /// numbers: loss on the network (RTSP over UDP) or packets the camera
    /// dropped itself.
    #[serde(default)]
    pub packets_lost: u64,
    /// RTP packets from the camera dropped because they came again or
    /// after a later one (RTSP over UDP): duplicates and reordering.
    #[serde(default)]
    pub packets_out_of_order: u64,
    /// Datagrams refused before they were read (RTSP over UDP): from an
    /// address other than the camera's media ports, not RTP, or from
    /// another synchronization source.
    #[serde(default)]
    pub datagrams_rejected: u64,
    /// Clips started on the stream.
    #[serde(default)]
    pub clips_started: u64,
    /// Clips that ended with their whole file written: `completed`,
    /// `stopped` or `max_duration`.
    #[serde(default)]
    pub clips_completed: u64,
    /// Gaps in the stream's clips.
    #[serde(default)]
    pub clip_gaps: u64,
    /// Bytes of clip files written to their bodies.
    #[serde(default)]
    pub clip_bytes: u64,
}

/// A stream, as `stream/get` returns it and `stream/list` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Stream {
    /// The id.
    pub stream_id: String,
    /// The connection's state.
    pub state: StreamState,
    /// Whether the stream stays connected without viewers.
    pub preload: bool,
    /// When the current state began, RFC 3339.
    pub since: String,
    /// The last error, if the stream is not live.
    pub last_error: Option<LastError>,
    /// The sources, in order.
    pub sources: Vec<SourceInfo>,
    /// The tracks.
    pub tracks: Vec<TrackInfo>,
    /// Open session ids.
    pub sessions: Vec<String>,
    /// The counters.
    pub stats: StreamStats,
    /// Who talks to the camera through its backchannel.
    #[serde(default)]
    pub backchannel: StreamBackchannel,
    /// The pre-roll window `stream/put` asked for, in milliseconds; 0
    /// without one. What each track holds is its `preroll`.
    #[serde(default)]
    pub preroll_ms: u32,
    /// Open clip ids.
    #[serde(default)]
    pub clips: Vec<String>,
}

/// The talker of a stream's backchannel, as `stream/get` reports it.
/// A camera has one backchannel, held by its source connection, so streams
/// that share the connection report the same talker.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct StreamBackchannel {
    /// The session holding the backchannel, or null when it is free.
    #[serde(default)]
    pub talker: Option<String>,
    /// When `talker` last changed, RFC 3339; null while no offer has
    /// claimed it since the connection's worker started.
    #[serde(default)]
    pub since: Option<String>,
}

/// Why a stream's talker changed: the `reason` of `talker_changed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TalkerReason {
    /// A session's offer (`webrtc/offer` or `webrtc/renegotiate`) asked
    /// for talk-back while nobody held the backchannel; it holds it now.
    Claimed,
    /// The talker's session closed; the backchannel is free.
    SessionClosed,
    /// `backchannel/release` freed it; the next offer that asks for
    /// talk-back claims it.
    Released,
    /// The talker's re-offer (`webrtc/renegotiate`) dropped talk-back;
    /// the backchannel is free.
    Renegotiated,
    /// The camera refused the talker's backchannel session, the session
    /// did not open in time, or its connection was lost while the talker
    /// held it: the backchannel is free, and the talker's session got a
    /// `backchannel_declined` warning with reason `refused`.
    Refused,
    /// No stream on the talker's connection asks for the camera's
    /// backchannel any more (the last one that did was put without the
    /// RTSP option `backchannel`): the camera's backchannel session is
    /// closed and the backchannel is no longer offered.
    OptedOut,
}

impl TalkerReason {
    /// The API name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::SessionClosed => "session_closed",
            Self::Released => "released",
            Self::Renegotiated => "renegotiated",
            Self::Refused => "refused",
            Self::OptedOut => "opted_out",
        }
    }

    /// The reason for its API name.
    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::Claimed,
            Self::SessionClosed,
            Self::Released,
            Self::Renegotiated,
            Self::Refused,
            Self::OptedOut,
        ]
        .into_iter()
        .find(|reason| reason.as_str() == name)
    }
}

/// `backchannel/release`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BackchannelReleaseResult {
    /// The session that held the backchannel when the command arrived, as
    /// the worker last reported it; null when it was free. A
    /// `talker_changed` with `released` follows on `stream/subscribe` when
    /// one was released. A release conditional on a `session_id` reports
    /// the talker the same way, whichever session it is: the worker frees
    /// the backchannel only if that session still holds it when the
    /// release arrives, so the `talker_changed` is what tells.
    pub talker: Option<String>,
}

/// `stream/list`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct StreamList {
    /// Every stream by id.
    pub streams: BTreeMap<String, Stream>,
}

/// `stream/put`'s result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct StreamPutResult {
    /// The stream did not exist before.
    pub created: bool,
}

/// An event of `stream/subscribe`.
/// Each variant's schema title names the Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// The stream's state, first as it is, then on every change.
    #[cfg_attr(feature = "schema", schemars(title = "StreamEventStream"))]
    Stream {
        /// The stream.
        stream_id: String,
        /// Its state.
        state: StreamState,
        /// Its last error, if any.
        last_error: Option<LastError>,
    },
    /// The stream was deleted.
    #[cfg_attr(feature = "schema", schemars(title = "StreamEventStreamRemoved"))]
    StreamRemoved {
        /// The stream.
        stream_id: String,
    },
    /// The talker of the stream's backchannel changed. Sent to the
    /// subscribers of every stream on the source connection, never
    /// coalesced or shed: a client too slow to take one is disconnected
    /// (close code 1008) and reads the talker again from `stream/get`. A
    /// burst of changes faster than the daemon passes them on may reach
    /// the subscribers as fewer, the last one naming the talker there is
    /// then.
    #[cfg_attr(feature = "schema", schemars(title = "StreamEventTalkerChanged"))]
    TalkerChanged {
        /// The stream.
        stream_id: String,
        /// The session holding the backchannel now: `session_id` after a
        /// claim, null otherwise.
        talker: Option<String>,
        /// The session it concerns: the new talker, or the one that let go.
        session_id: String,
        /// Why.
        reason: TalkerReason,
        /// When, RFC 3339: the `since` of `stream/get`'s `backchannel`.
        since: String,
    },
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
    use crate::error::ErrorCode;

    #[test]
    fn rfc3986_s3_1_debug_prints_a_source_urls_scheme_only_and_no_option_values() {
        let spec: SourceSpec = serde_json::from_value(json!({
            "url": "rtsp://admin:hunter2@cam.local:554/h264?x=1",
            "options": { "transport": "tcp" }
        }))
        .unwrap();
        assert_eq!(
            format!("{spec:?}"),
            r#"SourceSpec { url: "rtsp://****", options: ["transport"] }"#
        );
        // The command that carries it prints it the same way.
        let put = crate::parse_command(
            r#"{"id":1,"type":"stream/put","stream_id":"a","sources":[{"url":"rtsp://u:hunter2@c/"}]}"#,
        )
        .unwrap();
        let debug = format!("{put:?}");
        assert!(
            debug.contains(r#""rtsp://****""#) && !debug.contains("hunter2"),
            "{debug}"
        );
        // The wire form keeps the credentials a client sends.
        assert_eq!(
            serde_json::to_value(&spec).unwrap()["url"],
            "rtsp://admin:hunter2@cam.local:554/h264?x=1"
        );
        for (url, shown) in [
            ("rtsp://cam.local/key?token=t", "rtsp://****"),
            ("https://u:pa/ss?w#rd@cam/", "https://****"),
            ("svc+x-1.2://cam", "svc+x-1.2://****"),
            ("rtsp://", "rtsp://****"),
            ("u:p@cam/key", "****"),
            ("://cam/key", "****"),
            ("1rtsp://cam/key", "****"),
            ("x@y://cam/key", "****"),
            ("rt sp://cam/key", "****"),
            ("", "****"),
        ] {
            assert_eq!(redact_unparsed(url), shown, "{url}");
        }
    }

    #[test]
    fn stream_events_serialize_like_the_contract_examples() {
        let event = StreamEvent::Stream {
            stream_id: "front".into(),
            state: StreamState::Reconnecting,
            last_error: Some(LastError {
                error: ApiError::new(ErrorCode::SourceTimeout, "stall")
                    .with_detail("protocol", "rtsp"),
                at: "2026-09-28T11:02:03.000Z".into(),
            }),
        };
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            json!({ "type": "stream", "stream_id": "front", "state": "reconnecting",
                    "last_error": { "code": "source_timeout", "message": "stall",
                                    "details": { "protocol": "rtsp" }, "at": "2026-09-28T11:02:03.000Z" } })
        );
        assert_eq!(
            serde_json::to_value(StreamEvent::StreamRemoved {
                stream_id: "front".into()
            })
            .unwrap(),
            json!({ "type": "stream_removed", "stream_id": "front" })
        );
        let back: StreamEvent =
            serde_json::from_value(serde_json::to_value(&event).unwrap()).unwrap();
        assert_eq!(back, event);
    }

    /// A native H.264 track whose SPS is known and a derived Opus track.
    fn tracks() -> Vec<TrackInfo> {
        vec![
            TrackInfo {
                id: "v0".into(),
                kind: "video".into(),
                codec: "h264".into(),
                derived_from: None,
                sync: "arrival".into(),
                audio_delay_ms: None,
                profile_level_id: Some("42c028".into()),
                width: Some(640),
                height: Some(480),
                sample_rate: None,
                channels: None,
                frames: 1,
                bytes: 2,
                preroll: Some(TrackPreroll {
                    bytes: 14_201_337,
                    held_ms: 29_800,
                    truncations: 0,
                }),
            },
            TrackInfo {
                id: "a1".into(),
                kind: "audio".into(),
                codec: "opus".into(),
                derived_from: Some("a0".into()),
                sync: "sender_reports".into(),
                audio_delay_ms: Some(88),
                profile_level_id: None,
                width: None,
                height: None,
                sample_rate: Some(48_000),
                channels: Some(2),
                frames: 3,
                bytes: 4,
                preroll: None,
            },
        ]
    }

    #[test]
    fn rfc6184_8_1_a_tracks_codec_parameters_serialize_and_unknown_ones_are_left_out() {
        let json = serde_json::to_value(tracks()).unwrap();
        assert_eq!(
            (
                &json[0]["profile_level_id"],
                &json[0]["width"],
                &json[0]["height"],
            ),
            (&json!("42c028"), &json!(640), &json!(480))
        );
        assert_eq!(
            (&json[1]["sample_rate"], &json[1]["channels"]),
            (&json!(48_000), &json!(2))
        );
        for (track, absent) in [(0, ["sample_rate", "channels"]), (1, ["width", "height"])] {
            for field in absent {
                assert!(
                    json[track].get(field).is_none(),
                    "track {track} has no {field}"
                );
            }
        }
        assert!(json[1].get("profile_level_id").is_none());
        let back: Vec<TrackInfo> = serde_json::from_value(json).unwrap();
        assert_eq!(back, tracks());
    }

    #[test]
    fn a_stream_round_trips_and_states_have_names() {
        let stream = Stream {
            stream_id: "front".into(),
            state: StreamState::Live,
            preload: false,
            since: "2026-09-28T11:02:03.000Z".into(),
            last_error: None,
            sources: vec![SourceInfo {
                url: "rtsp://****@192.168.1.10:554/****".into(),
                protocol: "rtsp".into(),
                state: StreamState::Live,
                reconnects: 2,
                backchannel: Some(SourceBackchannel {
                    codec: "pcmu".into(),
                    state: BackchannelState::Available,
                }),
                connection: ConnectionInfo {
                    id: "c3".into(),
                    worker: Some(WorkerInfo {
                        pid: 4711,
                        restarts: 0,
                        last_crash: None,
                        pss_bytes: Some(5_242_880),
                    }),
                },
            }],
            tracks: tracks(),
            sessions: vec![],
            stats: StreamStats::default(),
            backchannel: StreamBackchannel {
                talker: Some("s1".into()),
                since: Some("2026-09-28T11:02:04.000Z".into()),
            },
            preroll_ms: 30_000,
            clips: vec!["01JB".into()],
        };
        let json = serde_json::to_value(&stream).unwrap();
        assert_eq!(
            (&json["preroll_ms"], &json["clips"]),
            (&json!(30_000), &json!(["01JB"]))
        );
        assert_eq!(
            json["tracks"][0]["preroll"],
            json!({ "bytes": 14_201_337, "held_ms": 29_800, "truncations": 0 })
        );
        assert!(json["tracks"][1]["preroll"].is_null(), "no window, null");
        assert_eq!(json["stats"]["clip_bytes"], 0);
        assert_eq!(json["state"], "live");
        assert_eq!(json["sources"][0]["connection"]["worker"]["pid"], 4711);
        assert_eq!(json["stats"]["frames_dropped"], 0);
        assert!(
            json["tracks"][0].get("audio_delay_ms").is_none(),
            "native tracks have no audio delay"
        );
        assert!(json["tracks"][0]["derived_from"].is_null());
        assert_eq!(json["tracks"][1]["derived_from"], "a0");
        assert_eq!(json["tracks"][1]["audio_delay_ms"], 88);
        let back: Stream = serde_json::from_value(json).unwrap();
        assert_eq!(back, stream);
        let mut list = StreamList::default();
        list.streams.insert("front".into(), stream);
        assert_eq!(
            serde_json::to_value(&list).unwrap()["streams"]["front"]["stream_id"],
            "front"
        );
        for state in [
            StreamState::Idle,
            StreamState::Connecting,
            StreamState::Live,
            StreamState::Reconnecting,
            StreamState::Backoff,
            StreamState::Draining,
            StreamState::Restarting,
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), state.as_str());
        }
        assert_eq!(
            serde_json::to_value(StreamPutResult { created: true }).unwrap(),
            json!({ "created": true })
        );
        assert_eq!(serde_json::to_value(AudioMode::Off).unwrap(), "off");
        assert_eq!(AudioMode::default(), AudioMode::Auto);
        assert_eq!(Orientation::default(), Orientation::NoTransform);
        // A partial stats object (older daemon, newer client) still parses.
        let partial: StreamStats = serde_json::from_value(json!({ "frames_dropped": 3 })).unwrap();
        assert_eq!(partial.frames_dropped, 3);
        assert_eq!(partial.frames_over_browser_limit, 0);
    }

    #[test]
    fn talker_changes_serialize_like_the_contract_examples() {
        let event = StreamEvent::TalkerChanged {
            stream_id: "front".into(),
            talker: Some("s1".into()),
            session_id: "s1".into(),
            reason: TalkerReason::Claimed,
            since: "2026-10-07T10:00:00.000Z".into(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(
            json,
            json!({ "type": "talker_changed", "stream_id": "front", "talker": "s1",
                    "session_id": "s1", "reason": "claimed", "since": "2026-10-07T10:00:00.000Z" })
        );
        assert_eq!(serde_json::from_value::<StreamEvent>(json).unwrap(), event);
        for (reason, name) in [
            (TalkerReason::Claimed, "claimed"),
            (TalkerReason::SessionClosed, "session_closed"),
            (TalkerReason::Released, "released"),
            (TalkerReason::Renegotiated, "renegotiated"),
            (TalkerReason::Refused, "refused"),
            (TalkerReason::OptedOut, "opted_out"),
        ] {
            assert_eq!(reason.as_str(), name);
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
            assert_eq!(TalkerReason::parse(name), Some(reason));
        }
        assert_eq!(TalkerReason::parse("stolen"), None);
        assert_eq!(
            serde_json::to_value(BackchannelReleaseResult { talker: None }).unwrap(),
            json!({ "talker": null })
        );
    }

    #[test]
    fn a_stream_from_a_daemon_without_talk_back_parses_with_nobody_talking() {
        let stream: Stream = serde_json::from_value(json!({
            "stream_id": "front", "state": "idle", "preload": false,
            "since": "2026-09-28T11:02:03.000Z", "last_error": null, "sources": [],
            "tracks": [], "sessions": [], "stats": {}
        }))
        .unwrap();
        assert_eq!(stream.backchannel, StreamBackchannel::default());
        assert_eq!((stream.preroll_ms, stream.clips.len()), (0, 0));
        let source: SourceInfo = serde_json::from_value(json!({
            "url": "rtsp://cam/", "protocol": "rtsp", "state": "live", "reconnects": 0,
            "connection": { "id": "c1", "worker": null }
        }))
        .unwrap();
        assert_eq!(source.backchannel, None, "a source without one");
        assert_eq!(
            serde_json::to_value(SourceBackchannel {
                codec: "pcmu".into(),
                state: BackchannelState::InUse,
            })
            .unwrap(),
            json!({ "codec": "pcmu", "state": "in_use" })
        );
        for (state, name) in [
            (BackchannelState::Available, "available"),
            (BackchannelState::InUse, "in_use"),
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), name);
        }
        assert_eq!(
            serde_json::to_value(StreamBackchannel {
                talker: Some("s1".into()),
                since: Some("2026-09-28T11:02:04.000Z".into()),
            })
            .unwrap(),
            json!({ "talker": "s1", "since": "2026-09-28T11:02:04.000Z" })
        );
    }

    #[test]
    fn a_track_without_codec_parameters_parses_with_none_known() {
        let track: TrackInfo = serde_json::from_value(json!({
            "id": "v0", "kind": "video", "codec": "mjpeg", "derived_from": null,
            "sync": "arrival", "frames": 0, "bytes": 0
        }))
        .unwrap();
        assert_eq!(
            (
                track.profile_level_id,
                track.width,
                track.height,
                track.sample_rate,
                track.channels
            ),
            (None, None, None, None, None)
        );
        assert_eq!(track.preroll, None, "an older daemon keeps no window");
    }

    #[test]
    fn the_ingest_counters_default_to_zero_when_a_daemon_leaves_them_out() {
        let partial: StreamStats = serde_json::from_value(json!({ "frames_dropped": 3 })).unwrap();
        assert_eq!(
            (
                partial.packets_lost,
                partial.packets_out_of_order,
                partial.datagrams_rejected
            ),
            (0, 0, 0)
        );
        assert_eq!(
            (
                partial.clips_started,
                partial.clips_completed,
                partial.clip_gaps,
                partial.clip_bytes
            ),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn orientations_have_their_names_and_numbers() {
        let all = [
            (Orientation::NoTransform, "no_transform"),
            (Orientation::Mirror, "mirror"),
            (Orientation::Rotate180, "rotate_180"),
            (Orientation::Flip, "flip"),
            (Orientation::RotateLeftAndFlip, "rotate_left_and_flip"),
            (Orientation::RotateLeft, "rotate_left"),
            (Orientation::RotateRightAndFlip, "rotate_right_and_flip"),
            (Orientation::RotateRight, "rotate_right"),
        ];
        for (code, (orientation, name)) in (1..).zip(all) {
            assert_eq!(orientation.code(), code, "{name}");
            assert_eq!(serde_json::to_value(orientation).unwrap(), name);
            assert_eq!(
                serde_json::from_value::<Orientation>(json!(name)).unwrap(),
                orientation
            );
        }
        // The numbers are not the API's spelling.
        assert!(serde_json::from_value::<Orientation>(json!(6)).is_err());
        assert!(serde_json::from_value::<Orientation>(json!("rotate180")).is_err());
    }
}

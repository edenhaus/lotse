//! Streams as the API sees them: the `stream/put` parameters, the `Stream`
//! of `stream/get` and `stream/list`, and the events of `stream/subscribe`.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// One entry of `stream/put`'s `sources`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSpec {
    /// The source URL, credentials included; redacted everywhere it is
    /// reported.
    #[schemars(length(max = crate::limits::MAX_URL_CHARS))]
    pub url: String,
    /// Per-scheme options, typed by the scheme's factory; unknown fields
    /// there are rejected too.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// Prints the URL without its userinfo and the options' names without
/// their values, which a future scheme may make secret. `Serialize` is the
/// wire form a client sends, so it keeps both; a serialized command is
/// never logged.
impl fmt::Debug for SourceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceSpec")
            .field("url", &redact_userinfo(&self.url))
            .field("options", &self.options.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// `url` with everything between the scheme's `://` (or the start, without
/// one) and the last `@` replaced by `****`, as `lotse_core::SourceUrl`
/// prints a parsed URL (`rtsp://****@host:554/path`). The URL is not
/// parsed yet, so a password with an unencoded `/`, `?`, `#` or `@` must
/// not end the userinfo early: the last `@` anywhere is taken, which
/// over-redacts a path that has one. No `@`, no userinfo
/// (RFC 3986 §3.2.1).
fn redact_userinfo(url: &str) -> String {
    let start = url.find("://").map_or(0, |at| at.saturating_add(3));
    match (url.get(..start), url.rfind('@')) {
        (Some(scheme), Some(at)) if at >= start => {
            format!("{scheme}****{}", url.get(at..).unwrap_or_default())
        }
        _ => url.to_owned(),
    }
}

/// `stream/put`'s `audio`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LastError {
    /// The error.
    #[serde(flatten)]
    pub error: ApiError,
    /// When it happened, RFC 3339.
    pub at: String,
}

/// The worker running a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConnectionInfo {
    /// The connection's id.
    pub id: String,
    /// Its worker, while one runs.
    pub worker: Option<WorkerInfo>,
}

/// A source as `stream/get` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceInfo {
    /// The URL, credentials redacted.
    pub url: String,
    /// The protocol (`rtsp`).
    pub protocol: String,
    /// The connection's state.
    pub state: StreamState,
    /// Reconnects so far.
    pub reconnects: u32,
    /// Protocol-specific detail, documented by the scheme's options schema.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub details: serde_json::Map<String, serde_json::Value>,
    /// The shared connection.
    pub connection: ConnectionInfo,
}

/// A track as `stream/get` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// Frames seen.
    pub frames: u64,
    /// Bytes seen.
    pub bytes: u64,
}

/// A stream's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
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
    /// Live packets skipped for age.
    #[serde(default)]
    pub age_skips: u64,
    /// Frames skipped as late after an ingest stall.
    #[serde(default)]
    pub ingest_late_skips: u64,
    /// Fan-out lag events.
    #[serde(default)]
    pub lag_events: u64,
    /// Stall watchdog hits.
    #[serde(default)]
    pub stalls: u64,
    /// Upstream keyframe requests.
    #[serde(default)]
    pub keyframe_requests: u64,
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
}

/// A stream, as `stream/get` returns it and `stream/list` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
}

/// `stream/list`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct StreamList {
    /// Every stream by id.
    pub streams: BTreeMap<String, Stream>,
}

/// `stream/put`'s result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StreamPutResult {
    /// The stream did not exist before.
    pub created: bool,
}

/// An event of `stream/subscribe`.
/// Each variant's schema title names the Python client's class for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// The stream's state, first as it is, then on every change.
    #[schemars(title = "StreamEventStream")]
    Stream {
        /// The stream.
        stream_id: String,
        /// Its state.
        state: StreamState,
        /// Its last error, if any.
        last_error: Option<LastError>,
    },
    /// The stream was deleted.
    #[schemars(title = "StreamEventStreamRemoved")]
    StreamRemoved {
        /// The stream.
        stream_id: String,
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
    fn rfc3986_s3_2_1_debug_never_prints_a_source_userinfo_or_option_values() {
        let spec: SourceSpec = serde_json::from_value(json!({
            "url": "rtsp://admin:hunter2@cam.local:554/h264?x=1",
            "options": { "transport": "tcp" }
        }))
        .unwrap();
        assert_eq!(
            format!("{spec:?}"),
            r#"SourceSpec { url: "rtsp://****@cam.local:554/h264?x=1", options: ["transport"] }"#
        );
        // The command that carries it prints it the same way.
        let put = crate::parse_command(
            r#"{"id":1,"type":"stream/put","stream_id":"a","sources":[{"url":"rtsp://u:hunter2@c/"}]}"#,
        )
        .unwrap();
        let debug = format!("{put:?}");
        assert!(
            debug.contains(r#""rtsp://****@c/""#) && !debug.contains("hunter2"),
            "{debug}"
        );
        // The wire form keeps the credentials a client sends.
        assert_eq!(
            serde_json::to_value(&spec).unwrap()["url"],
            "rtsp://admin:hunter2@cam.local:554/h264?x=1"
        );
        for (url, shown) in [
            ("rtsp://cam.local/h264", "rtsp://cam.local/h264"),
            ("rtsp://u:pa/ss?w#rd@cam/", "rtsp://****@cam/"),
            ("rtsp://u:p@ss@cam/", "rtsp://****@cam/"),
            ("u:p@cam/", "****@cam/"),
            ("@cam", "****@cam"),
            ("rtsp://", "rtsp://"),
            ("rtsp://@", "rtsp://****@"),
            ("x@y://cam/", "x@y://cam/"),
            ("", ""),
        ] {
            assert_eq!(redact_userinfo(url), shown, "{url}");
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

    #[test]
    fn a_stream_round_trips_and_states_have_names() {
        let stream = Stream {
            stream_id: "front".into(),
            state: StreamState::Live,
            preload: false,
            since: "2026-09-28T11:02:03.000Z".into(),
            last_error: None,
            sources: vec![SourceInfo {
                url: "rtsp://****@192.168.1.10:554/h264".into(),
                protocol: "rtsp".into(),
                state: StreamState::Live,
                reconnects: 2,
                details: serde_json::Map::new(),
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
            tracks: vec![
                TrackInfo {
                    id: "v0".into(),
                    kind: "video".into(),
                    codec: "h264".into(),
                    derived_from: None,
                    sync: "arrival".into(),
                    audio_delay_ms: None,
                    frames: 1,
                    bytes: 2,
                },
                TrackInfo {
                    id: "a1".into(),
                    kind: "audio".into(),
                    codec: "opus".into(),
                    derived_from: Some("a0".into()),
                    sync: "sender_reports".into(),
                    audio_delay_ms: Some(88),
                    frames: 3,
                    bytes: 4,
                },
            ],
            sessions: vec![],
            stats: StreamStats::default(),
        };
        let json = serde_json::to_value(&stream).unwrap();
        assert_eq!(json["state"], "live");
        assert_eq!(json["sources"][0]["connection"]["worker"]["pid"], 4711);
        assert!(
            json["sources"][0].get("details").is_none(),
            "empty details are omitted"
        );
        assert_eq!(json["stats"]["age_skips"], 0);
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
        let partial: StreamStats = serde_json::from_value(json!({ "stalls": 3 })).unwrap();
        assert_eq!(partial.stalls, 3);
        assert_eq!(partial.age_skips, 0);
        assert_eq!(partial.frames_over_browser_limit, 0);
    }

    #[test]
    fn the_ingest_counters_default_to_zero_when_a_daemon_leaves_them_out() {
        let partial: StreamStats = serde_json::from_value(json!({ "stalls": 3 })).unwrap();
        assert_eq!(
            (
                partial.packets_lost,
                partial.packets_out_of_order,
                partial.datagrams_rejected
            ),
            (0, 0, 0)
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

//! `GET /v0/metrics`: the daemon's metrics for Prometheus, on either
//! listener, through the same `Extension(peer)` path as the upgrade and a
//! recording's bytes. Over TLS a `control` or a `metrics` client may read
//! it (the `access` module lets a `metrics` client reach this route only);
//! nothing is ever served without the listener's authentication.
//!
//! The numbers are the snapshot `metrics/get` returns
//! ([`Handler::metrics_snapshot`]): one source, read once per request and
//! nothing collected on the media path for it. The exposition is written
//! by the Prometheus project's Rust client, `prometheus-client`, whose
//! `Collector` is made for metrics "retrieved ad-hoc on each scrape": each
//! request registers one over its snapshot, as `ConstCounter`s and
//! `ConstGauge`s, and has the client's encoder write it in one of two
//! formats, both as the Prometheus documentation defines them
//! (prometheus/docs, read on 2026-11-15):
//!
//! - OpenMetrics 1.0 text (`docs/specs/om/open_metrics_spec.md`): the
//!   client's `encoding::text`, with `# UNIT` lines and the closing
//!   `# EOF`, so a cut exposition is refused whole ("Partial or invalid
//!   expositions MUST be considered erroneous in their entirety"); sent as
//!   `application/openmetrics-text; version=1.0.0; charset=utf-8` with the
//!   escaping scheme the scraper named.
//! - The Prometheus text format 0.0.4 (`docs/instrumenting/
//!   exposition_formats.md`, "Prometheus Text Format"): the client's
//!   `encoding::prometheus_text`, sent as its `CONTENT_TYPE`,
//!   `text/plain; version=0.0.4; charset=utf-8`.
//!
//! Which one follows the scraper's `Accept` header, as Prometheus' "Scrape
//! protocol content negotiation" (`docs/instrumenting/
//! content_negotiation.md`) asks of a target: the representation the header
//! weighs highest, each weighed by the most specific range taking it in
//! (RFC 9110 §12.5.1), the header parsed by `mediatype`; with none taken in,
//! or a header that does not parse, the text format 0.0.4,
//! which "Selection of Format" makes the last resort a target MUST use. A
//! wildcard (`*/*`, as curl sends) gets the text format too: it names no
//! protocol. Prometheus' default `Accept` weighs OpenMetrics 1.0.0 highest,
//! so it gets OpenMetrics. Every metric name is in the legacy character
//! set, so the exposition is the same under every escaping scheme
//! (`allow-utf-8`, `underscores`, `dots`, `values`): the one asked for is
//! named in the response, as "Content-Type Response" requires of a text
//! format from 1.0.0 on, `underscores` when none was; an unknown scheme is
//! not offered. Not offered: the Prometheus text format 1.0.0 and
//! OpenMetrics 0.0.1, which the client does not write, and the protobuf
//! formats, which both specifications make optional; nor `gzip`, an
//! optional content coding.
//!
//! Names follow the Prometheus naming guidance (`docs/practices/naming.md`):
//! the application prefix `lotse_`, base units in the name (`_bytes`,
//! `_seconds`, which the client appends from the metric's unit), and
//! `_total` on every counter (the client's suffix). Labels are `connection`
//! (the daemon's own connection ids, `c1`) and `stream` (the client's
//! stream ids, `[A-Za-z0-9._-]`, which the encoders escape all the same):
//! never a URL, a credential, or anything a camera or browser sent. Their
//! cardinality is bounded by the daemon's stream cap, and the exposition
//! by [`MAX_EXPORTED_STREAMS`] and [`MAX_EXPORTED_WORKERS`] besides,
//! whatever `max_streams` is set to: what lies beyond is left out, which
//! logs one warning, rate-limited.
//!
//! Refusals carry the error body of the WebSocket's results and are those
//! of a recording's request: 403 for a request carrying `Origin` (RFC 6455
//! §10.2), 503 `shutting_down` (RFC 9110 §15.6.4), 403 `not_permitted` (RFC
//! 9110 §15.5.4) for a TLS client removed since its handshake, 405 with
//! `Allow: GET, HEAD` (RFC 9110 §15.5.6) for another method. Every answer
//! carries `Connection: close` (RFC 9112 §9.6): a scrape is one request,
//! and its connection gives its place among the pending upgrades back at
//! once.
//!
//! Standards: OpenMetrics 1.0, the Prometheus text format 0.0.4 and
//! Prometheus' scrape content negotiation (above), RFC 9110 §12.5.1
//! (`Accept`), RFC 9112 §9.6 (`Connection: close`).
//!
//! [`Handler::metrics_snapshot`]: crate::Handler::metrics_snapshot

use std::fmt;
use std::time::Duration;

use axum::Extension;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use lotse_api_types::Metrics;
use lotse_api_types::error::ErrorCode;
use lotse_api_types::info::{DemuxMetrics, ProcessMetrics, WorkerMetrics};
use lotse_api_types::stream::StreamStats;
use mediatype::MediaType;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric as _, MetricEncoder};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::registry::{Registry, Unit};

use crate::clients::ClientStore;
use crate::connection::refuse;
use crate::listener::PeerInfo;
use crate::{AppState, Handler, Limit, LimitLines};

/// The most streams in one exposition: 1024, each one series per stream
/// family. The daemon's default `max_streams` is 256.
pub const MAX_EXPORTED_STREAMS: usize = 1024;

/// The most workers in one exposition: 1024, each one series per worker
/// family. A worker runs one camera connection, which at least one stream
/// reads.
pub const MAX_EXPORTED_WORKERS: usize = 1024;

/// The prefix of every metric's name (`docs/practices/naming.md`: "a
/// (single-word) application prefix").
const PREFIX: &str = "lotse";

/// An escaping scheme of metric and label names a scraper may ask for with
/// a text format from version 1.0.0 on (`content_negotiation.md`,
/// "Escaping Scheme"). Every name here is in the legacy character set, so
/// none changes the exposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escaping {
    /// `allow-utf-8`: names as they are.
    AllowUtf8,
    /// `underscores`: other characters as `_`; named when the scraper
    /// named none.
    Underscores,
    /// `dots`: `.` as `_dot_`, other characters as `__`.
    Dots,
    /// `values`: other characters as their code point values.
    Values,
}

impl Escaping {
    /// The scheme's name in a media type's `escaping` parameter.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowUtf8 => "allow-utf-8",
            Self::Underscores => "underscores",
            Self::Dots => "dots",
            Self::Values => "values",
        }
    }
}

/// An exposition format the route offers (`content_negotiation.md`,
/// "Protocol Headers").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `OpenMetricsText1.0.0`, with the escaping scheme named in the
    /// response.
    OpenMetrics(Escaping),
    /// `PrometheusText0.0.4`, the last resort.
    PrometheusText,
}

impl Format {
    /// The response's `Content-Type` ("Content-Type Response": the media
    /// type, its version and, for a text format from 1.0.0 on, the
    /// escaping scheme).
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::OpenMetrics(Escaping::AllowUtf8) => {
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8"
            }
            Self::OpenMetrics(Escaping::Underscores) => {
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=underscores"
            }
            Self::OpenMetrics(Escaping::Dots) => {
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=dots"
            }
            Self::OpenMetrics(Escaping::Values) => {
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values"
            }
            Self::PrometheusText => prometheus_client::encoding::prometheus_text::CONTENT_TYPE,
        }
    }
}

/// One representation the route can send, with every parameter its
/// `Content-Type` carries: what an `Accept` range is matched against.
#[derive(Debug, Clone, Copy)]
struct Representation {
    /// The format it is written in.
    format: Format,
    /// The media type's type.
    ty: &'static str,
    /// The media type's subtype.
    subty: &'static str,
    /// Its parameters, names in lowercase.
    params: &'static [(&'static str, &'static str)],
}

/// The representations, in the server's order for a tie: the text format
/// 0.0.4 first, the last resort a wildcard gets too, then OpenMetrics 1.0.0
/// under each escaping scheme, `underscores` first, which a range naming
/// none gets.
const REPRESENTATIONS: [Representation; 5] = [
    Representation {
        format: Format::PrometheusText,
        ty: "text",
        subty: "plain",
        params: &[("version", "0.0.4"), ("charset", "utf-8")],
    },
    Representation {
        format: Format::OpenMetrics(Escaping::Underscores),
        ty: "application",
        subty: "openmetrics-text",
        params: &[
            ("version", "1.0.0"),
            ("charset", "utf-8"),
            ("escaping", "underscores"),
        ],
    },
    Representation {
        format: Format::OpenMetrics(Escaping::AllowUtf8),
        ty: "application",
        subty: "openmetrics-text",
        params: &[
            ("version", "1.0.0"),
            ("charset", "utf-8"),
            ("escaping", "allow-utf-8"),
        ],
    },
    Representation {
        format: Format::OpenMetrics(Escaping::Dots),
        ty: "application",
        subty: "openmetrics-text",
        params: &[
            ("version", "1.0.0"),
            ("charset", "utf-8"),
            ("escaping", "dots"),
        ],
    },
    Representation {
        format: Format::OpenMetrics(Escaping::Values),
        ty: "application",
        subty: "openmetrics-text",
        params: &[
            ("version", "1.0.0"),
            ("charset", "utf-8"),
            ("escaping", "values"),
        ],
    },
];

/// The weight `text` stands for, in thousandths (RFC 9110 §12.4.2:
/// `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`);
/// `None` for anything else.
fn qvalue(text: &str) -> Option<u16> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    let thousandths = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(3)
        .fold(0_u16, |sum, digit| {
            sum.saturating_mul(10)
                .saturating_add(u16::from(digit.saturating_sub(b'0')))
        });
    match whole {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// One media range of `Accept`: its type, subtype and parameters before
/// the weight, which RFC 9110 §12.5.1's grammar puts last (`media-range
/// weight`), and the weight in thousandths, 1000 without one.
struct Range {
    /// The type, `*` for any.
    ty: String,
    /// The subtype, `*` for any.
    subty: String,
    /// The parameters before the weight, names in lowercase.
    params: Vec<(String, String)>,
    /// The weight.
    quality: u16,
}

impl Range {
    /// The range `media_type` stands for; `None` when its weight is no
    /// qvalue.
    fn of(media_type: &MediaType<'_>) -> Option<Self> {
        use mediatype::ReadParams as _;

        let mut params = Vec::new();
        let mut quality = 1000;
        for (name, value) in media_type.params() {
            if name == "q" {
                quality = qvalue(&value.unquoted_str())?;
                break;
            }
            params.push((
                name.as_str().to_ascii_lowercase(),
                value.unquoted_str().into_owned(),
            ));
        }
        Some(Self {
            ty: media_type.ty.as_str().to_owned(),
            subty: media_type.subty.as_str().to_owned(),
            params,
            quality,
        })
    }

    /// Whether the range takes in `representation` (RFC 9110 §12.5.1): its
    /// type and subtype, or `*` for either, and every parameter it names
    /// with the same value, names and values compared without case.
    fn matches(&self, representation: &Representation) -> bool {
        let named = |range: &str, ours: &str| range == "*" || range.eq_ignore_ascii_case(ours);
        named(&self.ty, representation.ty)
            && named(&self.subty, representation.subty)
            && self.params.iter().all(|(name, value)| {
                representation.params.iter().any(|(ours, ours_value)| {
                    name == ours && value.eq_ignore_ascii_case(ours_value)
                })
            })
    }

    /// How specific the range is: a named type, a named subtype, then each
    /// parameter outranks the range without it (RFC 9110 §12.5.1: "the
    /// most specific reference has precedence").
    fn specificity(&self) -> usize {
        usize::from(self.ty != "*")
            .saturating_add(usize::from(self.subty != "*"))
            .saturating_add(self.params.len())
    }
}

/// The media ranges of `accept`, the `Accept` fields as one list (RFC 9110
/// §5.3); `None` when one does not parse or its weight is no qvalue
/// ("Security Considerations": the header is validated, not trusted).
fn ranges(accept: &str) -> Option<Vec<Range>> {
    mediatype::MediaTypeList::new(accept)
        .map(|media_type| media_type.ok().as_ref().and_then(Range::of))
        .collect()
}

/// The representation `ranges` accept most: each weighs what the most
/// specific range taking it in weighs (RFC 9110 §12.5.1), 0 without one,
/// and the heaviest above 0 wins, the first in the server's order on a
/// tie; `None` when every one weighs 0, which RFC 9110 §12.4.2 makes "not
/// acceptable".
fn chosen(ranges: &[Range]) -> Option<Format> {
    let mut best: Option<(u16, Format)> = None;
    for representation in &REPRESENTATIONS {
        let quality = ranges
            .iter()
            .filter(|range| range.matches(representation))
            .max_by_key(|range| range.specificity())
            .map_or(0, |range| range.quality);
        if quality > 0 && best.is_none_or(|(heaviest, _)| quality > heaviest) {
            best = Some((quality, representation.format));
        }
    }
    best.map(|(_, format)| format)
}

/// The format for `accept`, the `Accept` fields as one list: the
/// representation its ranges accept most, else the text format 0.0.4, the
/// last resort a target MUST use ("Selection of Format"), also for a header
/// that does not parse. An empty header takes in nothing, so it gets the
/// last resort too. Runs on any text: it never panics (fuzzed).
pub fn negotiate_accept(accept: &str) -> Format {
    ranges(accept)
        .as_deref()
        .and_then(chosen)
        .unwrap_or(Format::PrometheusText)
}

/// The format for a request with `headers` ([`negotiate_accept`] of its
/// `Accept` fields, an unreadable one left out).
pub fn negotiate(headers: &HeaderMap) -> Format {
    let fields: Vec<&str> = headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    negotiate_accept(&fields.join(", "))
}

/// A metric's type, as its `TYPE` line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Only ever grows while the process (or, for a worker's, its
    /// connection) lives; the encoder adds `_total`.
    Counter,
    /// Goes up and down.
    Gauge,
}

impl Kind {
    /// The client's type.
    const fn metric_type(self) -> MetricType {
        match self {
            Self::Counter => MetricType::Counter,
            Self::Gauge => MetricType::Gauge,
        }
    }
}

/// The base unit a metric's name ends in (`naming.md`, "Base units"),
/// which the encoders append and OpenMetrics names in `# UNIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// No unit: a count.
    None,
    /// `bytes`.
    Bytes,
    /// `seconds`.
    Seconds,
}

/// The client's [`Unit::Bytes`], for the encoders, which borrow it.
static BYTES: Unit = Unit::Bytes;

/// The client's [`Unit::Seconds`].
static SECONDS: Unit = Unit::Seconds;

impl Base {
    /// The client's unit, if any.
    fn unit(self) -> Option<&'static Unit> {
        match self {
            Self::None => None,
            Self::Bytes => Some(&BYTES),
            Self::Seconds => Some(&SECONDS),
        }
    }
}

/// A sample's value.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Number {
    /// A count or a number of bytes, written as an integer.
    Count(u64),
    /// A time in seconds, from milliseconds: an uptime, always a gauge.
    Seconds(f64),
}

impl Number {
    /// `ms` milliseconds as seconds.
    fn millis(ms: u64) -> Self {
        Self::Seconds(Duration::from_millis(ms).as_secs_f64())
    }
}

/// One metric of the exposition: its name without the prefix, the unit
/// and the counter suffix, its help, type and unit.
#[derive(Debug, Clone, Copy)]
struct Family {
    /// The name's middle part.
    name: &'static str,
    /// Its `HELP` text, without a backslash or a line feed: the OpenMetrics
    /// encoder writes it as it is.
    help: &'static str,
    /// Its type.
    kind: Kind,
    /// Its unit.
    base: Base,
}

/// A counter family without a unit.
const fn counter(name: &'static str, help: &'static str) -> Family {
    Family {
        name,
        help,
        kind: Kind::Counter,
        base: Base::None,
    }
}

/// A gauge family without a unit.
const fn gauge(name: &'static str, help: &'static str) -> Family {
    Family {
        name,
        help,
        kind: Kind::Gauge,
        base: Base::None,
    }
}

/// A family and what it takes from a part of the snapshot, `T`; `None`
/// where the snapshot lacks the figure, which is then left out.
type Field<T> = (Family, fn(&T) -> Option<Number>);

/// The process families, with their name's first part (`supervisor` or
/// `worker`).
fn process_families(of: &'static str) -> [Field<ProcessMetrics>; 4] {
    let supervisor = of == "supervisor";
    let name = |supervisor_name, worker_name| {
        if supervisor {
            supervisor_name
        } else {
            worker_name
        }
    };
    [
        (
            Family {
                name: name("supervisor_uptime", "worker_uptime"),
                help: "Time since the process started.",
                kind: Kind::Gauge,
                base: Base::Seconds,
            },
            |process| Some(Number::millis(process.uptime_ms)),
        ),
        (
            Family {
                name: name("supervisor_resident_memory", "worker_resident_memory"),
                help: "Resident set size of the process (Rss of smaps_rollup).",
                kind: Kind::Gauge,
                base: Base::Bytes,
            },
            |process| process.rss_bytes.map(Number::Count),
        ),
        (
            Family {
                name: name(
                    "supervisor_proportional_memory",
                    "worker_proportional_memory",
                ),
                help: "Proportional set size of the process (Pss of smaps_rollup): shared pages divided among the processes mapping them.",
                kind: Kind::Gauge,
                base: Base::Bytes,
            },
            |process| process.pss_bytes.map(Number::Count),
        ),
        (
            gauge(
                name("supervisor_tasks", "worker_tasks"),
                "Tokio tasks alive in the process's runtime.",
            ),
            |process| process.tasks.map(Number::Count),
        ),
    ]
}

/// The demux's families and what each takes from [`DemuxMetrics`].
const DEMUX_FAMILIES: [Field<DemuxMetrics>; 11] = [
    (
        counter(
            "demux_datagrams_received",
            "Datagrams read from the shared WebRTC UDP socket.",
        ),
        |demux| Some(Number::Count(demux.received)),
    ),
    (
        counter("demux_datagrams_forwarded", "Datagrams handed to a worker."),
        |demux| Some(Number::Count(demux.forwarded)),
    ),
    (
        counter(
            "demux_datagrams_unroutable",
            "Datagrams from unknown addresses that were not a usable STUN request.",
        ),
        |demux| Some(Number::Count(demux.unroutable)),
    ),
    (
        counter(
            "demux_stun_rejected",
            "STUN requests with an unknown ufrag or a wrong password.",
        ),
        |demux| Some(Number::Count(demux.stun_rejected)),
    ),
    (
        counter(
            "demux_addresses_learned",
            "Addresses learned through verified STUN requests.",
        ),
        |demux| Some(Number::Count(demux.addresses_learned)),
    ),
    (
        counter(
            "demux_addresses_moved",
            "Learned addresses moved to another session by a verified STUN request.",
        ),
        |demux| Some(Number::Count(demux.addresses_moved)),
    ),
    (
        counter(
            "demux_datagrams_worker_full",
            "Datagrams dropped because the worker's channel was full.",
        ),
        |demux| Some(Number::Count(demux.worker_full)),
    ),
    (
        counter(
            "demux_responses",
            "Responses to the supervisor's own STUN and TURN requests.",
        ),
        |demux| Some(Number::Count(demux.responses)),
    ),
    (
        counter(
            "demux_datagrams_relayed",
            "Datagrams a TURN server relayed from a peer, unwrapped and routed.",
        ),
        |demux| Some(Number::Count(demux.relayed)),
    ),
    (
        counter(
            "demux_relay_discarded",
            "Datagrams from a TURN server discarded.",
        ),
        |demux| Some(Number::Count(demux.relay_discarded)),
    ),
    (
        counter("demux_idle_wakeups", "Receive wake-ups without a datagram."),
        |demux| Some(Number::Count(demux.idle_wakeups)),
    ),
];

/// The per-worker families beyond its process figures, labelled with its
/// `connection`, and what each takes from the worker.
const WORKER_FAMILIES: [Field<WorkerMetrics>; 4] = [
    (
        counter(
            "connection_worker_restarts",
            "Crash restarts of the connection's worker.",
        ),
        |worker| Some(Number::Count(u64::from(worker.restarts))),
    ),
    (
        gauge("worker_sessions", "Open viewer sessions on the connection."),
        |worker| Some(Number::Count(u64::from(worker.sessions))),
    ),
    (
        counter(
            "worker_send_failures",
            "Datagrams the connection's sessions could not send.",
        ),
        |worker| Some(Number::Count(worker.send_failures)),
    ),
    (
        counter(
            "worker_relay_unbound",
            "Datagrams from a relay candidate dropped for want of a channel.",
        ),
        |worker| Some(Number::Count(worker.relay_unbound)),
    ),
];

/// The per-stream families, labelled with its `stream`, and what each
/// takes from [`StreamStats`].
const STREAM_FAMILIES: [Field<StreamStats>; 10] = [
    (
        counter("stream_frames_dropped", "Frames dropped as oversize."),
        |stats| Some(Number::Count(stats.frames_dropped)),
    ),
    (
        counter(
            "stream_frames_over_browser_limit",
            "Video frames carried in more RTP packets than some browsers assemble.",
        ),
        |stats| Some(Number::Count(stats.frames_over_browser_limit)),
    ),
    (
        counter(
            "stream_av_sync_lost",
            "Times the skew watchdog withdrew the stream's audio.",
        ),
        |stats| Some(Number::Count(stats.av_sync_lost)),
    ),
    (
        counter(
            "stream_packets_lost",
            "RTP packets from the camera that never arrived.",
        ),
        |stats| Some(Number::Count(stats.packets_lost)),
    ),
    (
        counter(
            "stream_packets_out_of_order",
            "RTP packets from the camera dropped as duplicates or reordered.",
        ),
        |stats| Some(Number::Count(stats.packets_out_of_order)),
    ),
    (
        counter(
            "stream_datagrams_rejected",
            "Datagrams refused before they were read (RTSP over UDP).",
        ),
        |stats| Some(Number::Count(stats.datagrams_rejected)),
    ),
    (
        counter(
            "stream_recordings_started",
            "Recordings started on the stream.",
        ),
        |stats| Some(Number::Count(stats.recordings_started)),
    ),
    (
        counter(
            "stream_recordings_completed",
            "Recordings that ended with their whole file written.",
        ),
        |stats| Some(Number::Count(stats.recordings_completed)),
    ),
    (
        counter("stream_recording_gaps", "Gaps in the stream's recordings."),
        |stats| Some(Number::Count(stats.recording_gaps)),
    ),
    (
        Family {
            name: "stream_recording",
            help: "The stream's recording files, as their workers report them.",
            kind: Kind::Counter,
            base: Base::Bytes,
        },
        |stats| Some(Number::Count(stats.recording_bytes)),
    ),
];

/// Writes `number` as `metric`'s sample: a count as an integer counter or
/// gauge, seconds as a gauge (only uptimes are in seconds).
fn sample(metric: MetricEncoder<'_>, kind: Kind, number: Number) -> fmt::Result {
    match (kind, number) {
        (Kind::Counter, Number::Count(count)) => ConstCounter::new(count).encode(metric),
        (Kind::Gauge, Number::Count(count)) => ConstGauge::new(count).encode(metric),
        (_, Number::Seconds(seconds)) => ConstGauge::new(seconds).encode(metric),
    }
}

/// `family` with its one unlabelled sample, if there is one.
fn single(
    encoder: &mut DescriptorEncoder<'_>,
    family: &Family,
    number: Option<Number>,
) -> fmt::Result {
    let Some(number) = number else {
        return Ok(());
    };
    // The `?` on a line that runs: alone on a line of its own, the error
    // path it stands for, which writing to a `String` never takes, would
    // count as a line no test reaches.
    let described = encoder.encode_descriptor(
        family.name,
        family.help,
        family.base.unit(),
        family.kind.metric_type(),
    );
    sample(described?, family.kind, number)
}

/// `family` with one sample per `(label value, number)`, labelled `label`;
/// nothing for a family without a sample.
fn labelled<'v>(
    encoder: &mut DescriptorEncoder<'_>,
    family: &Family,
    label: &'static str,
    samples: impl IntoIterator<Item = (&'v str, Number)>,
) -> fmt::Result {
    let mut samples = samples.into_iter().peekable();
    if samples.peek().is_none() {
        return Ok(());
    }
    let described = encoder.encode_descriptor(
        family.name,
        family.help,
        family.base.unit(),
        family.kind.metric_type(),
    );
    let mut metric = described?;
    for (value, number) in samples {
        let labels = [(label, value)];
        sample(metric.encode_family(&labels)?, family.kind, number)?;
    }
    Ok(())
}

/// One scrape's numbers, for the client's encoders: the snapshot within the
/// caps, and the counts before them.
#[derive(Debug)]
struct Exposition {
    /// The snapshot, at most [`MAX_EXPORTED_WORKERS`] workers and
    /// [`MAX_EXPORTED_STREAMS`] streams, the first by id.
    metrics: Metrics,
    /// The snapshot's workers, before the cap.
    workers: usize,
    /// The snapshot's streams, before the cap.
    streams: usize,
}

impl Exposition {
    /// `metrics` within the caps, and what they left out.
    fn capped(metrics: &Metrics) -> (Self, LeftOut) {
        let capped = Metrics {
            supervisor: metrics.supervisor.clone(),
            workers: metrics
                .workers
                .iter()
                .take(MAX_EXPORTED_WORKERS)
                .map(|(id, worker)| (id.clone(), worker.clone()))
                .collect(),
            worker_restarts: metrics.worker_restarts,
            sessions: metrics.sessions,
            streams: metrics
                .streams
                .iter()
                .take(MAX_EXPORTED_STREAMS)
                .map(|(id, stats)| (id.clone(), *stats))
                .collect(),
        };
        let left_out = LeftOut {
            streams: metrics.streams.len().saturating_sub(capped.streams.len()),
            workers: metrics.workers.len().saturating_sub(capped.workers.len()),
        };
        let exposition = Self {
            metrics: capped,
            workers: metrics.workers.len(),
            streams: metrics.streams.len(),
        };
        (exposition, left_out)
    }
}

impl Collector for Exposition {
    /// The supervisor's process figures and demux, the daemon's totals,
    /// then each worker's figures by `connection` and each stream's
    /// counters by `stream`, in the snapshot's order (by id), so repeated
    /// scrapes list them alike.
    fn encode(&self, mut encoder: DescriptorEncoder<'_>) -> fmt::Result {
        let metrics = &self.metrics;
        let supervisor = &metrics.supervisor;
        for (family, field) in process_families("supervisor") {
            single(&mut encoder, &family, field(&supervisor.process))?;
        }
        for (family, field) in DEMUX_FAMILIES {
            let number = supervisor.demux.as_ref().and_then(field);
            single(&mut encoder, &family, number)?;
        }
        let count = |value: usize| Number::Count(u64::try_from(value).unwrap_or(u64::MAX));
        let totals = [
            (
                counter(
                    "worker_restarts",
                    "Worker crash restarts since the daemon started.",
                ),
                Number::Count(metrics.worker_restarts),
            ),
            (
                gauge("sessions", "Open viewer sessions on all connections."),
                Number::Count(u64::from(metrics.sessions)),
            ),
            (
                gauge("workers", "Running workers, one per camera connection."),
                count(self.workers),
            ),
            (gauge("streams", "Streams."), count(self.streams)),
        ];
        for (family, number) in totals {
            single(&mut encoder, &family, Some(number))?;
        }
        for (family, field) in process_families("worker") {
            let samples = metrics.workers.iter().filter_map(|(id, worker)| {
                field(&worker.process).map(|number| (id.as_str(), number))
            });
            labelled(&mut encoder, &family, "connection", samples)?;
        }
        for (family, field) in WORKER_FAMILIES {
            let samples = metrics
                .workers
                .iter()
                .filter_map(|(id, worker)| field(worker).map(|number| (id.as_str(), number)));
            labelled(&mut encoder, &family, "connection", samples)?;
        }
        for (family, field) in STREAM_FAMILIES {
            let samples = metrics
                .streams
                .iter()
                .filter_map(|(id, stats)| field(stats).map(|number| (id.as_str(), number)));
            labelled(&mut encoder, &family, "stream", samples)?;
        }
        Ok(())
    }
}

/// What one exposition left out at its caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LeftOut {
    /// Streams beyond [`MAX_EXPORTED_STREAMS`].
    pub(crate) streams: usize,
    /// Workers beyond [`MAX_EXPORTED_WORKERS`].
    pub(crate) workers: usize,
}

/// `metrics` in `format`, by the client's encoder, and what the caps left
/// out; an error only if an encoder failed, which writing to a `String`
/// never does.
pub(crate) fn render(metrics: &Metrics, format: Format) -> Result<(String, LeftOut), fmt::Error> {
    let (exposition, left_out) = Exposition::capped(metrics);
    let mut registry = Registry::with_prefix(PREFIX);
    registry.register_collector(Box::new(exposition));
    let mut text = String::new();
    let encoded = match format {
        Format::OpenMetrics(_) => prometheus_client::encoding::text::encode(&mut text, &registry),
        Format::PrometheusText => {
            prometheus_client::encoding::prometheus_text::encode(&mut text, &registry)
        }
    };
    encoded?;
    Ok((text, left_out))
}

/// The exposition of `snapshot` in `format` as the response, after a
/// warning, at most one per interval on `limit_lines`, when the caps left
/// anything out; 503 without a snapshot, 500 if the encoder failed.
fn respond(snapshot: Option<Metrics>, format: Format, limit_lines: &LimitLines) -> Response {
    let Some(metrics) = snapshot else {
        tracing::error!("metrics refused: the handler keeps no metrics");
        return closing(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::InternalError,
            "no metrics",
        ));
    };
    answer(render(&metrics, format), &metrics, format, limit_lines)
}

/// The response to an exposition `rendered` from `metrics` in `format`.
fn answer(
    rendered: Result<(String, LeftOut), fmt::Error>,
    metrics: &Metrics,
    format: Format,
    limit_lines: &LimitLines,
) -> Response {
    let Ok((text, left_out)) = rendered else {
        tracing::error!("metrics refused: the exposition could not be encoded");
        return closing(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InternalError,
            "the metrics could not be encoded",
        ));
    };
    if left_out != LeftOut::default()
        && let Some(scrapes) = limit_lines.hit(Limit::ExportedSeries)
    {
        tracing::warn!(
            streams = metrics.streams.len(),
            workers = metrics.workers.len(),
            max_streams = MAX_EXPORTED_STREAMS,
            max_workers = MAX_EXPORTED_WORKERS,
            streams_left_out = left_out.streams,
            workers_left_out = left_out.workers,
            scrapes,
            "metrics exposition capped: streams or workers beyond the cap are left out"
        );
    }
    let content_type = HeaderValue::from_static(format.content_type());
    closing((StatusCode::OK, [(header::CONTENT_TYPE, content_type)], text).into_response())
}

/// `response` with `Connection: close` (RFC 9112 §9.6).
fn closing(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// A metrics request's refusal before the handler is asked, as for a
/// recording: `Origin`, shutdown, a TLS client removed since its
/// handshake; `None` lets it through. Not generic over the handler, so
/// every handler's route shares it.
fn refusal(
    peer: &PeerInfo,
    headers: &HeaderMap,
    shutting_down: bool,
    clients: Option<&ClientStore>,
) -> Option<Response> {
    if headers.contains_key(header::ORIGIN) {
        tracing::warn!(%peer, "metrics refused: the request carries Origin, as only a browser sends");
        return Some(closing(refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest,
            "requests carrying Origin are refused: the control API is not for browsers",
        )));
    }
    if shutting_down {
        return Some(closing(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ShuttingDown,
            "shutting down",
        )));
    }
    let removed = match (clients, peer) {
        (Some(clients), PeerInfo::Tls { pin, .. }) => !clients.allows(pin),
        _ => false,
    };
    if removed {
        tracing::warn!(%peer, "metrics refused: its client was removed");
        return Some(closing(refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::NotPermitted,
            "the client was removed",
        )));
    }
    None
}

/// `GET /v0/metrics` (HEAD answered alike, without the body): the checks,
/// then the handler's snapshot as the exposition in the negotiated format,
/// the TLS client's enrollment checked once more after the snapshot, so a
/// scraper removed while it was collected gets none of it. The whole
/// exposition is one body written at once, so nothing is left to stop
/// once it is answered.
pub(crate) async fn fetch<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    headers: HeaderMap,
) -> Response {
    let shutting_down = state.shutdown.is_cancelled();
    if let Some(refused) = refusal(&peer, &headers, shutting_down, state.clients.as_deref()) {
        return refused;
    }
    let format = negotiate(&headers);
    let snapshot = state.handler.metrics_snapshot().await;
    // The client may have been removed while the snapshot was collected:
    // checked again before a byte of it is sent, which is all at once.
    if let Some(refused) = refusal(&peer, &headers, shutting_down, state.clients.as_deref()) {
        return refused;
    }
    respond(snapshot, format, &state.limit_lines)
}

/// Any other method on the metrics path: 405 with `Allow: GET, HEAD` (RFC
/// 9110 §15.5.6).
pub(crate) async fn not_allowed() -> Response {
    let mut response = refuse(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::InvalidRequest,
        "the metrics are read with GET",
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
    closing(response)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::collections::HashSet;
    use std::sync::Arc;

    use lotse_api_types::info::SupervisorMetrics;
    use lotse_core::clock::FakeClock;

    use super::*;

    fn process(uptime_ms: u64, memory: Option<u64>) -> ProcessMetrics {
        ProcessMetrics {
            pid: 7,
            uptime_ms,
            rss_bytes: memory,
            pss_bytes: memory.map(|bytes| bytes / 2),
            tasks: memory.map(|_| 3),
        }
    }

    fn snapshot(streams: usize, workers: usize) -> Metrics {
        Metrics {
            supervisor: SupervisorMetrics {
                process: process(61_001, None),
                demux: None,
            },
            workers: (0..workers)
                .map(|index| {
                    (
                        format!("c{index}"),
                        WorkerMetrics {
                            process: process(1, None),
                            streams: vec![],
                            restarts: 0,
                            sessions: 0,
                            send_failures: 0,
                            relay_unbound: 0,
                        },
                    )
                })
                .collect(),
            worker_restarts: 0,
            sessions: 0,
            streams: (0..streams)
                .map(|index| (format!("s{index:05}"), StreamStats::default()))
                .collect(),
        }
    }

    /// A snapshot with a figure in every family.
    fn full() -> Metrics {
        let mut metrics = snapshot(0, 0);
        metrics.supervisor.process = process(1_500, Some(8192));
        metrics.supervisor.demux = Some(DemuxMetrics {
            received: 11,
            worker_full: 2,
            ..DemuxMetrics::default()
        });
        metrics.worker_restarts = 4;
        metrics.sessions = 3;
        metrics.workers.insert(
            "c1".into(),
            WorkerMetrics {
                process: process(250, Some(4096)),
                streams: vec!["front".into()],
                restarts: 2,
                sessions: 3,
                send_failures: 5,
                relay_unbound: 6,
            },
        );
        metrics.streams.insert(
            "front".into(),
            StreamStats {
                packets_lost: 9,
                recording_bytes: 1 << 40,
                ..StreamStats::default()
            },
        );
        metrics
    }

    fn text(metrics: &Metrics, format: Format) -> String {
        render(metrics, format).unwrap().0
    }

    fn has(text: &str, line: &str) -> bool {
        text.lines().any(|got| got == line)
    }

    /// The `Accept` of Prometheus 3's default scrape protocols, as
    /// `content_negotiation.md` gives it ("Default Accept Header"; its
    /// catch-all is `*/*`, which the page's Markdown shows as `/`).
    const PROMETHEUS_DEFAULT: &str = "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.5,application/openmetrics-text;version=0.0.1;q=0.4,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.3,text/plain;version=0.0.4;q=0.2,*/*;q=0.1";

    fn negotiated(accept: &[&str]) -> Format {
        let mut headers = HeaderMap::new();
        for value in accept {
            headers.append(header::ACCEPT, value.parse().unwrap());
        }
        negotiate(&headers)
    }

    #[test]
    fn prometheus_default_accept_gets_openmetrics_1_0_0_content_negotiation_selection_of_format() {
        assert_eq!(
            negotiated(&[PROMETHEUS_DEFAULT]),
            Format::OpenMetrics(Escaping::AllowUtf8)
        );
        for (scheme, escaping) in [
            ("allow-utf-8", Escaping::AllowUtf8),
            ("underscores", Escaping::Underscores),
            ("dots", Escaping::Dots),
            ("values", Escaping::Values),
        ] {
            let accept = format!(
                "application/openmetrics-text;version=1.0.0;escaping={scheme};q=0.5,text/plain;version=0.0.4;q=0.2"
            );
            assert_eq!(
                negotiated(&[&accept]),
                Format::OpenMetrics(escaping),
                "{scheme}"
            );
        }
        // OpenMetrics without a version is its oldest, 1.0.0 (OpenMetrics
        // 1.0, "Protocol Negotiation"); with one and no escaping, as asked.
        for accept in [
            "application/openmetrics-text",
            "application/openmetrics-text;version=1.0.0",
            "Application/OpenMetrics-Text;version=1.0.0;q=0.9",
            "application/openmetrics-text;q=0.9,text/plain;q=0.5",
        ] {
            assert_eq!(
                negotiated(&[accept]),
                Format::OpenMetrics(Escaping::Underscores),
                "{accept}"
            );
        }
        // Two fields are one list (RFC 9110 §5.3).
        assert_eq!(
            negotiated(&[
                "text/plain;version=0.0.4;q=0.1",
                "application/openmetrics-text;q=0.9"
            ]),
            Format::OpenMetrics(Escaping::Underscores)
        );
    }

    #[test]
    fn prometheus_text_0_0_4_is_the_last_resort_content_negotiation_selection_of_format() {
        for accept in [
            // Prometheus limited to the text format.
            "text/plain;version=0.0.4;q=0.2,*/*;q=0.1",
            "text/plain",
            "text/plain;q=0.5,application/openmetrics-text;q=0.4",
            // A wildcard names no protocol: curl's.
            "*/*",
            "text/*",
            // Offers it does not weigh higher, or none at all.
            "text/plain;version=0.0.4;q=0.9,application/openmetrics-text;version=1.0.0;q=0.5",
            "application/openmetrics-text;version=1.0.0;q=0,*/*",
            "application/openmetrics-text;version=0.0.1",
            "application/openmetrics-text;version=1.0.0;escaping=bogus",
            "text/plain;version=1.0.0;escaping=allow-utf-8",
            "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited",
            "application/json",
            // A header that does not parse is not trusted.
            "@@@",
            "",
        ] {
            assert_eq!(negotiated(&[accept]), Format::PrometheusText, "{accept}");
        }
        assert_eq!(negotiated(&[]), Format::PrometheusText, "no Accept");
        let mut opaque = HeaderMap::new();
        opaque.insert(header::ACCEPT, HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(negotiate(&opaque), Format::PrometheusText, "not text");
    }

    #[test]
    fn a_range_takes_in_a_representation_whose_parameters_it_names_rfc9110_12_5_1() {
        // A range naming a subset of a representation's parameters takes
        // it in, `charset` included, alone or with others.
        for (accept, expected) in [
            (
                "application/openmetrics-text;version=1.0.0;charset=utf-8",
                Format::OpenMetrics(Escaping::Underscores),
            ),
            (
                "application/openmetrics-text;charset=UTF-8;escaping=dots",
                Format::OpenMetrics(Escaping::Dots),
            ),
            (
                "application/openmetrics-text;version=1.0.0;charset=\"utf-8\";escaping=values;q=0.7",
                Format::OpenMetrics(Escaping::Values),
            ),
            (
                "text/plain;charset=utf-8;q=0.9,application/openmetrics-text;q=0.5",
                Format::PrometheusText,
            ),
        ] {
            assert_eq!(negotiated(&[accept]), expected, "{accept}");
        }
        // A parameter the representation lacks, or another value of one,
        // takes nothing in.
        for accept in [
            "application/openmetrics-text;charset=iso-8859-1",
            "application/openmetrics-text;version=1.0.0;format=other",
        ] {
            assert_eq!(negotiated(&[accept]), Format::PrometheusText, "{accept}");
        }
    }

    #[test]
    fn the_most_specific_range_weighs_a_representation_and_q_0_excludes_it_rfc9110_12_5_1() {
        // The versioned range forbids OpenMetrics 1.0.0, whatever the bare
        // one allows: it is more specific.
        for accept in [
            "application/openmetrics-text;version=1.0.0;q=0,application/openmetrics-text;q=1,text/plain;q=0.5",
            "application/openmetrics-text;q=1,application/openmetrics-text;version=1.0.0;q=0,text/plain;q=0.5",
            "*/*,application/openmetrics-text;q=0",
        ] {
            assert_eq!(negotiated(&[accept]), Format::PrometheusText, "{accept}");
        }
        // And allows it over a heavier, less specific one.
        assert_eq!(
            negotiated(&[
                "text/*;q=0.8,application/openmetrics-text;q=0.1,application/openmetrics-text;version=1.0.0;q=0.9"
            ]),
            Format::OpenMetrics(Escaping::Underscores)
        );
        // An escaping scheme narrows the range to its representation.
        assert_eq!(
            negotiated(&[
                "application/openmetrics-text;q=0.2,application/openmetrics-text;escaping=dots;q=0.9"
            ]),
            Format::OpenMetrics(Escaping::Dots)
        );
    }

    #[test]
    fn a_named_type_outranks_a_wildcard_and_a_weight_of_0_is_not_acceptable_rfc9110_12_5_1() {
        // The named range weighs OpenMetrics, the wildcard only what no
        // named range takes in, wherever each stands in the header.
        for accept in [
            "application/openmetrics-text;q=0.9,*/*;q=0.1,text/plain;q=0.5",
            "*/*;q=0.1,application/openmetrics-text;q=0.9,text/plain;q=0.5",
            "application/openmetrics-text;q=0.9,application/*;q=0.1,text/plain;q=0.5",
        ] {
            let ranges = ranges(accept).unwrap();
            assert_eq!(
                chosen(&ranges),
                Some(Format::OpenMetrics(Escaping::Underscores)),
                "{accept}"
            );
        }
        // Every representation weighed 0: none is acceptable, and the
        // route falls back to the last resort.
        let refused = "application/openmetrics-text;q=0,text/plain;q=0";
        assert_eq!(chosen(&ranges(refused).unwrap()), None);
        assert_eq!(negotiate_accept(refused), Format::PrometheusText);
        assert_eq!(chosen(&ranges("").unwrap()), None, "an empty header");
        assert!(ranges("text/plain;q=x").is_none());
        // A tie goes to the first in the server's order.
        assert_eq!(
            chosen(&ranges("*/*").unwrap()),
            Some(Format::PrometheusText)
        );
    }

    #[test]
    fn a_weight_is_a_qvalue_and_ends_the_range_s_parameters_rfc9110_12_4_2() {
        for (text, expected) in [
            ("0", Some(0)),
            ("0.", Some(0)),
            ("0.5", Some(500)),
            ("0.25", Some(250)),
            ("0.125", Some(125)),
            ("0.999", Some(999)),
            ("1", Some(1000)),
            ("1.", Some(1000)),
            ("1.000", Some(1000)),
            ("1.001", None),
            ("0.1234", None),
            ("2", None),
            ("0.5x", None),
            ("-0", None),
            (".5", None),
            ("", None),
        ] {
            assert_eq!(qvalue(text), expected, "{text:?}");
        }
        // A weight that is no qvalue makes the header invalid.
        assert_eq!(
            negotiated(&["application/openmetrics-text;q=2"]),
            Format::PrometheusText
        );
        // Parameters after the weight are `accept-ext`, not the media type's.
        assert_eq!(
            negotiated(&["application/openmetrics-text;q=0.9;version=0.0.1"]),
            Format::OpenMetrics(Escaping::Underscores)
        );
    }

    #[test]
    fn the_content_type_names_the_format_its_version_and_the_escaping_scheme() {
        assert_eq!(
            Format::PrometheusText.content_type(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        for (escaping, name) in [
            (Escaping::AllowUtf8, "allow-utf-8"),
            (Escaping::Underscores, "underscores"),
            (Escaping::Dots, "dots"),
            (Escaping::Values, "values"),
        ] {
            assert_eq!(escaping.as_str(), name);
            assert_eq!(
                Format::OpenMetrics(escaping).content_type(),
                format!(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping={name}"
                )
            );
        }
    }

    #[test]
    fn the_openmetrics_exposition_has_units_counter_suffixes_and_eof_openmetrics_1_0() {
        let text = text(&full(), Format::OpenMetrics(Escaping::AllowUtf8));
        let expected_start = "\
# HELP lotse_supervisor_uptime_seconds Time since the process started.
# TYPE lotse_supervisor_uptime_seconds gauge
# UNIT lotse_supervisor_uptime_seconds seconds
lotse_supervisor_uptime_seconds 1.5
";
        assert!(text.starts_with(expected_start), "{text}");
        assert!(text.ends_with("# EOF\n"), "{text}");
        for line in [
            "# UNIT lotse_supervisor_resident_memory_bytes bytes",
            "lotse_supervisor_resident_memory_bytes 8192",
            "lotse_supervisor_proportional_memory_bytes 4096",
            "lotse_supervisor_tasks 3",
            // A counter's family has no suffix, its sample `_total`.
            "# TYPE lotse_demux_datagrams_received counter",
            "lotse_demux_datagrams_received_total 11",
            "lotse_demux_datagrams_worker_full_total 2",
            "lotse_demux_idle_wakeups_total 0",
            "lotse_worker_restarts_total 4",
            "lotse_sessions 3",
            "lotse_workers 1",
            "lotse_streams 1",
            "lotse_worker_uptime_seconds{connection=\"c1\"} 0.25",
            "lotse_worker_resident_memory_bytes{connection=\"c1\"} 4096",
            "lotse_worker_proportional_memory_bytes{connection=\"c1\"} 2048",
            "lotse_worker_tasks{connection=\"c1\"} 3",
            "lotse_connection_worker_restarts_total{connection=\"c1\"} 2",
            "# TYPE lotse_worker_sessions gauge",
            "lotse_worker_sessions{connection=\"c1\"} 3",
            "lotse_worker_send_failures_total{connection=\"c1\"} 5",
            "lotse_worker_relay_unbound_total{connection=\"c1\"} 6",
            "lotse_stream_packets_lost_total{stream=\"front\"} 9",
            "# TYPE lotse_stream_recording_bytes counter",
            "# UNIT lotse_stream_recording_bytes bytes",
            "lotse_stream_recording_bytes_total{stream=\"front\"} 1099511627776",
        ] {
            assert!(has(&text, line), "{line}\n{text}");
        }
        // 4 + 11 supervisor, 4 totals, 8 worker, 10 stream families, each
        // described once.
        let types: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("# TYPE "))
            .collect();
        assert_eq!(types.len(), 37);
        assert_eq!(types.iter().collect::<HashSet<_>>().len(), 37);
        assert_eq!(
            text,
            self::text(&full(), Format::OpenMetrics(Escaping::Dots)),
            "every scheme alike"
        );
    }

    #[test]
    fn the_text_exposition_is_prometheus_text_0_0_4_without_units_or_eof() {
        let text = text(&full(), Format::PrometheusText);
        let expected_start = "\
# HELP lotse_supervisor_uptime_seconds Time since the process started.
# TYPE lotse_supervisor_uptime_seconds gauge
lotse_supervisor_uptime_seconds 1.5
";
        assert!(text.starts_with(expected_start), "{text}");
        assert!(
            !text.contains("# EOF") && !text.contains("# UNIT"),
            "{text}"
        );
        for line in [
            "# TYPE lotse_demux_datagrams_received_total counter",
            "lotse_demux_datagrams_received_total 11",
            "# TYPE lotse_stream_recording_bytes_total counter",
            "lotse_stream_recording_bytes_total{stream=\"front\"} 1099511627776",
            "lotse_worker_uptime_seconds{connection=\"c1\"} 0.25",
        ] {
            assert!(has(&text, line), "{line}\n{text}");
        }
        // "Grouping and sorting": one HELP and TYPE per name, before its
        // samples, each name and label set once; the same on every scrape.
        let mut seen = HashSet::new();
        let mut current = "";
        let mut series = HashSet::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# HELP ") {
                current = rest.split(' ').next().unwrap();
                assert!(seen.insert(current), "{current} grouped once");
            } else if let Some(rest) = line.strip_prefix("# TYPE ") {
                assert_eq!(rest.split(' ').next().unwrap(), current);
            } else {
                assert_eq!(line.split(['{', ' ']).next().unwrap(), current, "{line}");
                assert!(series.insert(line.rsplit_once(' ').unwrap().0), "{line}");
            }
        }
        assert_eq!(seen.len(), 37);
        assert_eq!(text, self::text(&full(), Format::PrometheusText));
    }

    #[test]
    fn a_figure_the_snapshot_lacks_is_left_out_not_zero() {
        for format in [
            Format::PrometheusText,
            Format::OpenMetrics(Escaping::AllowUtf8),
        ] {
            let text = text(&snapshot(0, 1), format);
            assert!(!text.contains("lotse_supervisor_resident_memory_bytes"));
            assert!(!text.contains("lotse_demux_"), "no front door");
            assert!(!text.contains("lotse_worker_tasks"));
            assert!(!text.contains("lotse_stream_"), "no stream");
            assert!(
                has(
                    &text,
                    "lotse_worker_uptime_seconds{connection=\"c0\"} 0.001"
                ),
                "{text}"
            );
            assert!(
                has(&text, "lotse_supervisor_uptime_seconds 61.001"),
                "{text}"
            );
            assert!(has(&text, "lotse_streams 0"), "{text}");
        }
    }

    #[test]
    fn label_values_escape_backslash_quote_and_line_feed_in_both_formats() {
        let mut metrics = snapshot(0, 0);
        metrics
            .streams
            .insert("q\"\\\n".into(), StreamStats::default());
        for format in [
            Format::PrometheusText,
            Format::OpenMetrics(Escaping::AllowUtf8),
        ] {
            let text = text(&metrics, format);
            assert!(
                has(
                    &text,
                    "lotse_stream_packets_lost_total{stream=\"q\\\"\\\\\\n\"} 0"
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn names_have_the_lotse_prefix_counters_get_total_and_help_needs_no_escaping() {
        let mut families: Vec<Family> = process_families("supervisor")
            .into_iter()
            .chain(process_families("worker"))
            .map(|(family, _)| family)
            .collect();
        families.extend(DEMUX_FAMILIES.iter().map(|(family, _)| *family));
        families.extend(WORKER_FAMILIES.iter().map(|(family, _)| *family));
        families.extend(STREAM_FAMILIES.iter().map(|(family, _)| *family));
        let mut names = HashSet::new();
        for family in &families {
            assert!(names.insert(family.name), "{} once", family.name);
            // The legacy character set, and no suffix the encoders add.
            assert!(
                family
                    .name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                "{}",
                family.name
            );
            assert!(!family.name.ends_with("_total"), "{}", family.name);
            assert!(!family.help.contains(['\\', '\n']), "{}", family.name);
        }
        assert_eq!(Kind::Counter.metric_type(), MetricType::Counter);
        assert_eq!(Kind::Gauge.metric_type(), MetricType::Gauge);
        assert_eq!(Base::None.unit(), None);
        assert_eq!(Base::Bytes.unit(), Some(&Unit::Bytes));
        assert_eq!(Base::Seconds.unit(), Some(&Unit::Seconds));
        assert_eq!(Number::millis(1_500), Number::Seconds(1.5));
    }

    #[test]
    fn the_exposition_stops_at_its_caps_and_says_so_once_per_interval() {
        let (logs, _guard) = crate::pairing::test_support::capture();
        let metrics = snapshot(MAX_EXPORTED_STREAMS + 2, MAX_EXPORTED_WORKERS + 1);
        let (text, left_out) = render(&metrics, Format::PrometheusText).unwrap();
        assert_eq!(
            left_out,
            LeftOut {
                streams: 2,
                workers: 1
            }
        );
        let count = |prefix: &str| text.lines().filter(|line| line.starts_with(prefix)).count();
        assert_eq!(
            count("lotse_stream_packets_lost_total{"),
            MAX_EXPORTED_STREAMS
        );
        assert_eq!(count("lotse_worker_sessions{"), MAX_EXPORTED_WORKERS);
        assert!(text.contains("{stream=\"s01023\"}"));
        assert!(
            !text.contains("{stream=\"s01024\"}"),
            "by id, the first ones"
        );
        assert!(has(&text, "lotse_streams 1026"), "the whole count");
        assert!(has(&text, "lotse_workers 1025"), "the whole count");

        let clock = Arc::new(FakeClock::default());
        let lines = LimitLines::new(clock.clone());
        let message = "metrics exposition capped";
        let capped = || {
            logs.text()
                .lines()
                .filter(|line| line.contains(message))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let format = Format::PrometheusText;
        for _ in 0..3 {
            assert_eq!(respond(Some(metrics.clone()), format, &lines).status(), 200);
        }
        let logged = capped();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("streams_left_out=2"), "{logged:?}");
        assert!(logged[0].contains("workers_left_out=1"), "{logged:?}");
        clock.advance(lotse_core::throttle::SUMMARY_INTERVAL);
        assert_eq!(respond(Some(metrics), format, &lines).status(), 200);
        let logged = capped();
        assert_eq!(logged.len(), 2, "{logged:?}");
        assert!(logged[1].ends_with("scrapes=3"), "{logged:?}");
        // Under the caps nothing is said.
        assert_eq!(respond(Some(snapshot(3, 3)), format, &lines).status(), 200);
        clock.advance(lotse_core::throttle::SUMMARY_INTERVAL);
        assert_eq!(respond(Some(snapshot(3, 3)), format, &lines).status(), 200);
        assert_eq!(capped().len(), 2);
    }

    async fn body_of(response: Response) -> (u16, HeaderMap, String) {
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn an_exposition_is_200_in_its_format_s_content_type_and_closes_the_connection() {
        let clock = Arc::new(FakeClock::default());
        let lines = LimitLines::new(clock);
        for format in [
            Format::PrometheusText,
            Format::OpenMetrics(Escaping::Values),
        ] {
            let (status, headers, body) = body_of(respond(Some(full()), format, &lines)).await;
            assert_eq!(status, 200);
            assert_eq!(headers[header::CONTENT_TYPE], format.content_type());
            assert_eq!(headers[header::CONNECTION], "close");
            assert_eq!(body, text(&full(), format));
        }
        let (logs, _guard) = crate::pairing::test_support::capture();
        let (status, headers, body) = body_of(respond(None, Format::PrometheusText, &lines)).await;
        assert_eq!(status, 503);
        assert_eq!(headers[header::CONNECTION], "close");
        assert!(body.contains("internal_error"), "{body}");
        assert!(logs.text().contains("the handler keeps no metrics"));
        // An encoder that failed: nothing of it is sent.
        let failed = answer(Err(fmt::Error), &full(), Format::PrometheusText, &lines);
        let (status, headers, body) = body_of(failed).await;
        assert_eq!(status, 500);
        assert_eq!(headers[header::CONNECTION], "close");
        assert!(body.contains("internal_error"), "{body}");
        assert!(logs.text().contains("the exposition could not be encoded"));
    }

    #[tokio::test]
    async fn refusals_are_those_of_a_recording_request_rfc9110_15_5_4_15_6_4() {
        let unix = PeerInfo::Unix { uid: 0, pid: None };
        let tls = PeerInfo::Tls {
            pin: lotse_core::fingerprint::Fingerprint::of(b"client"),
            addr: "192.0.2.1:1".parse().unwrap(),
        };
        let none = HeaderMap::new();
        assert!(refusal(&unix, &none, false, None).is_none());
        assert!(refusal(&tls, &none, false, None).is_none(), "no store");
        let mut origin = HeaderMap::new();
        origin.insert(header::ORIGIN, "https://example.com".parse().unwrap());
        let (status, headers, body) = body_of(refusal(&unix, &origin, false, None).unwrap()).await;
        assert_eq!(status, 403);
        assert_eq!(headers[header::CONNECTION], "close");
        assert!(body.contains("invalid_request"), "{body}");
        let (status, _, body) = body_of(refusal(&unix, &none, true, None).unwrap()).await;
        assert_eq!(status, 503);
        assert!(body.contains("shutting_down"), "{body}");
        let (status, headers, body) = body_of(not_allowed().await).await;
        assert_eq!(status, 405);
        assert_eq!(headers[header::ALLOW], "GET, HEAD");
        assert!(body.contains("invalid_request"), "{body}");
    }

    #[tokio::test]
    async fn a_tls_client_removed_since_its_handshake_is_refused_rfc9110_15_5_4() {
        use std::os::unix::fs::DirBuilderExt as _;

        use lotse_core::fingerprint::Fingerprint;

        let (logs, _guard) = crate::pairing::test_support::capture();
        let dir = std::env::temp_dir().join(format!("lotse-exporter-{}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let runtime = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let scraper = Fingerprint::of(b"scraper");
        let store = ClientStore::open(
            &std::fs::File::open(&dir).unwrap(),
            &dir,
            &[(scraper, lotse_api_types::clients::ClientRole::Metrics)],
            runtime,
        )
        .unwrap();
        let tls = |pin| PeerInfo::Tls {
            pin,
            addr: "192.0.2.1:1".parse().unwrap(),
        };
        let none = HeaderMap::new();
        assert!(refusal(&tls(scraper), &none, false, Some(&store)).is_none());
        let removed = refusal(&tls(Fingerprint::of(b"gone")), &none, false, Some(&store));
        let (status, headers, body) = body_of(removed.unwrap()).await;
        assert_eq!(status, 403);
        assert_eq!(headers[header::CONNECTION], "close");
        assert!(body.contains("not_permitted"), "{body}");
        assert!(
            logs.text()
                .contains("metrics refused: its client was removed")
        );
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

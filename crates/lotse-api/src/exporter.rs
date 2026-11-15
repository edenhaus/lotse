//! `GET /v0/metrics`: the daemon's metrics for Prometheus, on either
//! listener, through the same `Extension(peer)` path as the upgrade and a
//! recording's bytes. Over TLS a `control` or a `metrics` client may read
//! it (the `access` module lets a `metrics` client reach this route only);
//! nothing is ever served without the listener's authentication.
//!
//! The numbers are the snapshot `metrics/get` returns
//! ([`Handler::metrics_snapshot`]): one source, read once per request and
//! nothing collected on the media path for it. They are rendered in the
//! Prometheus text format, version 0.0.4, as the Prometheus documentation
//! defines it ("Exposition formats", section "Prometheus Text Format",
//! `docs/instrumenting/exposition_formats.md` of prometheus/docs, read on
//! 2026-11-15), and sent as `Content-Type: text/plain; version=0.0.4;
//! charset=utf-8` ([`CONTENT_TYPE`]; "Basic info": `text/plain` with the
//! `version=0.0.4` parameter, encoding UTF-8; "HTTP Content-Type
//! requirements": from Prometheus 3.0 a scrape without a valid
//! `Content-Type` fails). What the format asks and how it is met:
//!
//! - "Details": lines separated by a line feed, the last one ended by one.
//! - "Comments, help text, and type information": one `# HELP` and one
//!   `# TYPE` line per metric name, before its first sample; `HELP` text
//!   escapes the backslash and the line feed as `\\` and `\n`
//!   (`escape_help`).
//! - The sample syntax: `metric_name [ "{" labels "}" ] value`, every name
//!   in the legacy character set, so none is quoted; a label value escapes
//!   the backslash, the double quote and the line feed as `\\`, `\"` and
//!   `\n` (`escape_label`); a value is what Go's `ParseFloat` reads, here
//!   an integer or a decimal fraction; no timestamp.
//! - "Grouping and sorting": every line of a metric in one group, each
//!   name and label set once, in the same order on every scrape.
//!
//! Names follow the Prometheus naming guidance (`docs/practices/naming.md`
//! of prometheus/docs, read on 2026-11-15): the application prefix
//! `lotse_`, base units in the name (`_bytes`, `_seconds`), and `_total`
//! on every counter. Labels are `connection` (the daemon's own connection
//! ids, `c1`) and `stream` (the client's stream ids, `[A-Za-z0-9._-]`,
//! escaped all the same): never a URL, a credential, or anything a camera
//! or browser sent. Their cardinality is bounded by the daemon's stream
//! cap, and the exposition by [`MAX_EXPORTED_STREAMS`] and
//! [`MAX_EXPORTED_WORKERS`] besides, whatever `max_streams` is set to:
//! what lies beyond is left out, which logs one warning, rate-limited.
//!
//! SPEC-DEVIATION: `OpenMetrics` is not offered, whatever the scrape's
//! `Accept` asks: Prometheus falls back to the text format, which a target
//! may answer any scrape with ("Basic info": a missing `version` falls back
//! to the most recent text format; the response names its one format in
//! `Content-Type`).
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
//! Standards: the Prometheus text format 0.0.4 (above), RFC 9110 (HTTP),
//! RFC 9112 §9.6 (`Connection: close`).
//!
//! [`Handler::metrics_snapshot`]: crate::Handler::metrics_snapshot

use std::fmt::Write as _;

use axum::Extension;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use lotse_api_types::Metrics;
use lotse_api_types::error::ErrorCode;
use lotse_api_types::info::{DemuxMetrics, ProcessMetrics, WorkerMetrics};
use lotse_api_types::stream::StreamStats;

use crate::clients::ClientStore;
use crate::connection::refuse;
use crate::listener::PeerInfo;
use crate::{AppState, Handler, Limit, LimitLines};

/// The response's media type: the Prometheus text format, version 0.0.4,
/// in UTF-8 ("Basic info").
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The most streams in one exposition: 1024, each one `STREAM_FAMILIES`
/// series. The daemon's default `max_streams` is 256.
pub const MAX_EXPORTED_STREAMS: usize = 1024;

/// The most workers in one exposition: 1024, each one
/// `WORKER_FAMILIES` series. A worker runs one camera connection, which
/// at least one stream reads.
pub const MAX_EXPORTED_WORKERS: usize = 1024;

/// A metric's type, as its `# TYPE` line names it ("Comments, help text,
/// and type information").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Only ever grows while the process (or, for a worker's, its
    /// connection) lives; its name ends in `_total`.
    Counter,
    /// Goes up and down.
    Gauge,
}

impl Kind {
    /// The `# TYPE` line's word.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

/// A sample's value: what Go's `ParseFloat` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    /// A count or a number of bytes, as an integer.
    Count(u64),
    /// Milliseconds, as decimal seconds with three places (`1.234`): the
    /// base unit of time.
    Seconds(u64),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Count(count) => write!(f, "{count}"),
            Self::Seconds(ms) => write!(f, "{}.{:03}", ms / 1000, ms % 1000),
        }
    }
}

/// One metric of the exposition: its name, type and help.
#[derive(Debug, Clone, Copy)]
struct Family {
    /// The metric name, `lotse_`-prefixed.
    name: &'static str,
    /// Its type.
    kind: Kind,
    /// Its `# HELP` text.
    help: &'static str,
}

/// The process figures of the supervisor or a worker, as the families
/// [`process_families`] names: what each takes from [`ProcessMetrics`].
type ProcessField = fn(&ProcessMetrics) -> Option<Value>;

/// The process families with their prefix (`supervisor` or `worker`).
fn process_families(prefix: &'static str) -> [(Family, ProcessField); 4] {
    let (uptime, rss, pss, tasks) = if prefix == "supervisor" {
        (
            "lotse_supervisor_uptime_seconds",
            "lotse_supervisor_resident_memory_bytes",
            "lotse_supervisor_proportional_memory_bytes",
            "lotse_supervisor_tasks",
        )
    } else {
        (
            "lotse_worker_uptime_seconds",
            "lotse_worker_resident_memory_bytes",
            "lotse_worker_proportional_memory_bytes",
            "lotse_worker_tasks",
        )
    };
    [
        (
            Family {
                name: uptime,
                kind: Kind::Gauge,
                help: "Seconds since the process started.",
            },
            |process| Some(Value::Seconds(process.uptime_ms)),
        ),
        (
            Family {
                name: rss,
                kind: Kind::Gauge,
                help: "Resident set size of the process (Rss of smaps_rollup).",
            },
            |process| process.rss_bytes.map(Value::Count),
        ),
        (
            Family {
                name: pss,
                kind: Kind::Gauge,
                help: "Proportional set size of the process (Pss of smaps_rollup): shared pages divided among the processes mapping them.",
            },
            |process| process.pss_bytes.map(Value::Count),
        ),
        (
            Family {
                name: tasks,
                kind: Kind::Gauge,
                help: "Tokio tasks alive in the process's runtime.",
            },
            |process| process.tasks.map(Value::Count),
        ),
    ]
}

/// A family and what it takes from a part of the snapshot, `T`.
type Field<T> = (Family, fn(&T) -> u64);

/// The demux's families and what each takes from [`DemuxMetrics`].
const DEMUX_FAMILIES: [Field<DemuxMetrics>; 11] = [
    (
        counter(
            "lotse_demux_datagrams_received_total",
            "Datagrams read from the shared WebRTC UDP socket.",
        ),
        |demux| demux.received,
    ),
    (
        counter(
            "lotse_demux_datagrams_forwarded_total",
            "Datagrams handed to a worker.",
        ),
        |demux| demux.forwarded,
    ),
    (
        counter(
            "lotse_demux_datagrams_unroutable_total",
            "Datagrams from unknown addresses that were not a usable STUN request.",
        ),
        |demux| demux.unroutable,
    ),
    (
        counter(
            "lotse_demux_stun_rejected_total",
            "STUN requests with an unknown ufrag or a wrong password.",
        ),
        |demux| demux.stun_rejected,
    ),
    (
        counter(
            "lotse_demux_addresses_learned_total",
            "Addresses learned through verified STUN requests.",
        ),
        |demux| demux.addresses_learned,
    ),
    (
        counter(
            "lotse_demux_addresses_moved_total",
            "Learned addresses moved to another session by a verified STUN request.",
        ),
        |demux| demux.addresses_moved,
    ),
    (
        counter(
            "lotse_demux_datagrams_worker_full_total",
            "Datagrams dropped because the worker's channel was full.",
        ),
        |demux| demux.worker_full,
    ),
    (
        counter(
            "lotse_demux_responses_total",
            "Responses to the supervisor's own STUN and TURN requests.",
        ),
        |demux| demux.responses,
    ),
    (
        counter(
            "lotse_demux_datagrams_relayed_total",
            "Datagrams a TURN server relayed from a peer, unwrapped and routed.",
        ),
        |demux| demux.relayed,
    ),
    (
        counter(
            "lotse_demux_relay_discarded_total",
            "Datagrams from a TURN server discarded.",
        ),
        |demux| demux.relay_discarded,
    ),
    (
        counter(
            "lotse_demux_idle_wakeups_total",
            "Receive wake-ups without a datagram.",
        ),
        |demux| demux.idle_wakeups,
    ),
];

/// The per-worker families beyond its process figures, labelled with its
/// `connection`, and what each takes from the worker.
const WORKER_FAMILIES: [Field<WorkerMetrics>; 4] = [
    (
        counter(
            "lotse_connection_worker_restarts_total",
            "Crash restarts of the connection's worker.",
        ),
        |worker| u64::from(worker.restarts),
    ),
    (
        gauge(
            "lotse_worker_sessions",
            "Open viewer sessions on the connection.",
        ),
        |worker| u64::from(worker.sessions),
    ),
    (
        counter(
            "lotse_worker_send_failures_total",
            "Datagrams the connection's sessions could not send.",
        ),
        |worker| worker.send_failures,
    ),
    (
        counter(
            "lotse_worker_relay_unbound_total",
            "Datagrams from a relay candidate dropped for want of a channel.",
        ),
        |worker| worker.relay_unbound,
    ),
];

/// The per-stream families, labelled with its `stream`, and what each
/// takes from [`StreamStats`].
const STREAM_FAMILIES: [Field<StreamStats>; 10] = [
    (
        counter(
            "lotse_stream_frames_dropped_total",
            "Frames dropped as oversize.",
        ),
        |stats| stats.frames_dropped,
    ),
    (
        counter(
            "lotse_stream_frames_over_browser_limit_total",
            "Video frames carried in more RTP packets than some browsers assemble.",
        ),
        |stats| stats.frames_over_browser_limit,
    ),
    (
        counter(
            "lotse_stream_av_sync_lost_total",
            "Times the skew watchdog withdrew the stream's audio.",
        ),
        |stats| stats.av_sync_lost,
    ),
    (
        counter(
            "lotse_stream_packets_lost_total",
            "RTP packets from the camera that never arrived.",
        ),
        |stats| stats.packets_lost,
    ),
    (
        counter(
            "lotse_stream_packets_out_of_order_total",
            "RTP packets from the camera dropped as duplicates or reordered.",
        ),
        |stats| stats.packets_out_of_order,
    ),
    (
        counter(
            "lotse_stream_datagrams_rejected_total",
            "Datagrams refused before they were read (RTSP over UDP).",
        ),
        |stats| stats.datagrams_rejected,
    ),
    (
        counter(
            "lotse_stream_recordings_started_total",
            "Recordings started on the stream.",
        ),
        |stats| stats.recordings_started,
    ),
    (
        counter(
            "lotse_stream_recordings_completed_total",
            "Recordings that ended with their whole file written.",
        ),
        |stats| stats.recordings_completed,
    ),
    (
        counter(
            "lotse_stream_recording_gaps_total",
            "Gaps in the stream's recordings.",
        ),
        |stats| stats.recording_gaps,
    ),
    (
        counter(
            "lotse_stream_recording_bytes_total",
            "Bytes of the stream's recording files, as their workers report them.",
        ),
        |stats| stats.recording_bytes,
    ),
];

/// A counter family.
const fn counter(name: &'static str, help: &'static str) -> Family {
    Family {
        name,
        kind: Kind::Counter,
        help,
    }
}

/// A gauge family.
const fn gauge(name: &'static str, help: &'static str) -> Family {
    Family {
        name,
        kind: Kind::Gauge,
        help,
    }
}

/// `text` as a `# HELP` line's docstring: the backslash and the line feed
/// escaped as `\\` and `\n` ("Comments, help text, and type information").
fn escape_help(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n")
}

/// `text` as a label value: the backslash, the double quote and the line
/// feed escaped as `\\`, `\"` and `\n` (the sample syntax's
/// `label_value`).
fn escape_label(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// What one exposition left out at its caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LeftOut {
    /// Streams beyond [`MAX_EXPORTED_STREAMS`].
    pub(crate) streams: usize,
    /// Workers beyond [`MAX_EXPORTED_WORKERS`].
    pub(crate) workers: usize,
}

/// The exposition being written: one group per family, `# HELP` and
/// `# TYPE` first, only for a family with a sample.
struct Writer {
    /// The text so far.
    text: String,
}

impl Writer {
    /// `family`'s group with `samples`, each an optional label (its name and
    /// raw value) and a value; nothing for a family without a sample.
    fn family<'s>(
        &mut self,
        family: &Family,
        samples: impl IntoIterator<Item = (Option<(&'static str, &'s str)>, Value)>,
    ) {
        let mut samples = samples.into_iter().peekable();
        if samples.peek().is_none() {
            return;
        }
        // Writing to a `String` never fails.
        let _written = writeln!(
            self.text,
            "# HELP {} {}\n# TYPE {} {}",
            family.name,
            escape_help(family.help),
            family.name,
            family.kind.as_str()
        );
        for (label, value) in samples {
            let _written = match label {
                Some((name, raw)) => writeln!(
                    self.text,
                    "{}{{{name}=\"{}\"}} {value}",
                    family.name,
                    escape_label(raw)
                ),
                None => writeln!(self.text, "{} {value}", family.name),
            };
        }
    }
}

/// `metrics` in the text format, and what the caps left out: the
/// supervisor's process figures and demux, the daemon's totals, then each
/// worker's figures by `connection` and each stream's counters by
/// `stream`, in the snapshot's order (by id), so repeated scrapes list
/// them alike.
pub(crate) fn render(metrics: &Metrics) -> (String, LeftOut) {
    let mut out = Writer {
        text: String::new(),
    };
    let supervisor = &metrics.supervisor;
    for (family, field) in process_families("supervisor") {
        out.family(
            &family,
            field(&supervisor.process).map(|value| (None, value)),
        );
    }
    for (family, field) in DEMUX_FAMILIES {
        let value = supervisor.demux.as_ref().map(field);
        out.family(&family, value.map(|value| (None, Value::Count(value))));
    }
    let workers: Vec<_> = metrics.workers.iter().take(MAX_EXPORTED_WORKERS).collect();
    let streams: Vec<_> = metrics.streams.iter().take(MAX_EXPORTED_STREAMS).collect();
    let totals = [
        (
            counter(
                "lotse_worker_restarts_total",
                "Worker crash restarts since the daemon started.",
            ),
            metrics.worker_restarts,
        ),
        (
            gauge("lotse_sessions", "Open viewer sessions on all connections."),
            u64::from(metrics.sessions),
        ),
        (
            gauge(
                "lotse_workers",
                "Running workers, one per camera connection.",
            ),
            u64::try_from(metrics.workers.len()).unwrap_or(u64::MAX),
        ),
        (
            gauge("lotse_streams", "Streams."),
            u64::try_from(metrics.streams.len()).unwrap_or(u64::MAX),
        ),
    ];
    for (family, value) in totals {
        out.family(&family, [(None, Value::Count(value))]);
    }
    for (family, field) in process_families("worker") {
        out.family(
            &family,
            workers.iter().filter_map(|(id, worker)| {
                field(&worker.process).map(|value| (Some(("connection", id.as_str())), value))
            }),
        );
    }
    for (family, field) in WORKER_FAMILIES {
        out.family(
            &family,
            workers.iter().map(|(id, worker)| {
                (
                    Some(("connection", id.as_str())),
                    Value::Count(field(worker)),
                )
            }),
        );
    }
    for (family, field) in STREAM_FAMILIES {
        out.family(
            &family,
            streams
                .iter()
                .map(|(id, stats)| (Some(("stream", id.as_str())), Value::Count(field(stats)))),
        );
    }
    let left_out = LeftOut {
        streams: metrics.streams.len().saturating_sub(streams.len()),
        workers: metrics.workers.len().saturating_sub(workers.len()),
    };
    (out.text, left_out)
}

/// The exposition of `snapshot` as the response, after a warning, at most
/// one per interval on `limit_lines`, when the caps left anything out;
/// 503 without a snapshot.
fn respond(snapshot: Option<Metrics>, limit_lines: &LimitLines) -> Response {
    let Some(metrics) = snapshot else {
        tracing::error!("metrics refused: the handler keeps no metrics");
        return closing(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::InternalError,
            "no metrics",
        ));
    };
    let (text, left_out) = render(&metrics);
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
    closing(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE))],
            text,
        )
            .into_response(),
    )
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
/// then the handler's snapshot as the exposition.
pub(crate) async fn fetch<H: Handler>(
    State(state): State<AppState<H>>,
    Extension(peer): Extension<PeerInfo>,
    headers: HeaderMap,
) -> Response {
    let shutting_down = state.shutdown.is_cancelled();
    if let Some(refused) = refusal(&peer, &headers, shutting_down, state.clients.as_deref()) {
        return refused;
    }
    let snapshot = state.handler.metrics_snapshot().await;
    respond(snapshot, &state.limit_lines)
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

    /// Every sample line's metric name, in order of appearance.
    fn sample_names(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.split(['{', ' ']).next().unwrap())
            .collect()
    }

    #[test]
    fn the_exposition_is_text_format_0_0_4_with_help_and_type_before_each_group() {
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
        let (text, left_out) = render(&metrics);
        assert_eq!(left_out, LeftOut::default());
        // "Details": line feeds, the last line ended by one.
        assert!(text.ends_with('\n') && !text.contains('\r'));
        let expected_start = "\
# HELP lotse_supervisor_uptime_seconds Seconds since the process started.
# TYPE lotse_supervisor_uptime_seconds gauge
lotse_supervisor_uptime_seconds 1.500
# HELP lotse_supervisor_resident_memory_bytes Resident set size of the process (Rss of smaps_rollup).
# TYPE lotse_supervisor_resident_memory_bytes gauge
lotse_supervisor_resident_memory_bytes 8192
";
        assert!(text.starts_with(expected_start), "{text}");
        for line in [
            "lotse_supervisor_proportional_memory_bytes 4096",
            "lotse_supervisor_tasks 3",
            "# TYPE lotse_demux_datagrams_received_total counter",
            "lotse_demux_datagrams_received_total 11",
            "lotse_demux_datagrams_worker_full_total 2",
            "lotse_demux_idle_wakeups_total 0",
            "lotse_worker_restarts_total 4",
            "lotse_sessions 3",
            "lotse_workers 1",
            "lotse_streams 1",
            "lotse_worker_uptime_seconds{connection=\"c1\"} 0.250",
            "lotse_worker_resident_memory_bytes{connection=\"c1\"} 4096",
            "lotse_worker_proportional_memory_bytes{connection=\"c1\"} 2048",
            "lotse_worker_tasks{connection=\"c1\"} 3",
            "# TYPE lotse_connection_worker_restarts_total counter",
            "lotse_connection_worker_restarts_total{connection=\"c1\"} 2",
            "# TYPE lotse_worker_sessions gauge",
            "lotse_worker_sessions{connection=\"c1\"} 3",
            "lotse_worker_send_failures_total{connection=\"c1\"} 5",
            "lotse_worker_relay_unbound_total{connection=\"c1\"} 6",
            "lotse_stream_packets_lost_total{stream=\"front\"} 9",
            "lotse_stream_recording_bytes_total{stream=\"front\"} 1099511627776",
            "lotse_stream_frames_dropped_total{stream=\"front\"} 0",
        ] {
            assert!(text.lines().any(|got| got == line), "{line}\n{text}");
        }
        // "Grouping and sorting": one HELP and one TYPE per name, before
        // its samples, which are one group; each name and label set once.
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
                assert_eq!(sample_names(line), [current], "{line}");
                assert!(series.insert(line.rsplit_once(' ').unwrap().0), "{line}");
            }
        }
        // 4 + 11 supervisor, 4 totals, 8 worker, 10 stream families.
        assert_eq!(seen.len(), 37);
        // The same snapshot, the same text.
        assert_eq!(render(&metrics).0, text);
    }

    #[test]
    fn a_figure_the_snapshot_lacks_is_left_out_not_zero() {
        let (text, _) = render(&snapshot(0, 1));
        assert!(!text.contains("lotse_supervisor_resident_memory_bytes"));
        assert!(!text.contains("lotse_demux_"), "no front door");
        assert!(!text.contains("lotse_worker_tasks"));
        assert!(!text.contains("lotse_stream_"), "no stream");
        assert!(text.contains("lotse_worker_uptime_seconds{connection=\"c0\"} 0.001\n"));
        assert!(text.contains("lotse_streams 0\n"));
    }

    #[test]
    fn label_values_escape_backslash_quote_and_line_feed_text_format_label_value() {
        assert_eq!(escape_label(r#"a\b"c"#), r#"a\\b\"c"#);
        assert_eq!(escape_label("a\nb"), r"a\nb");
        assert_eq!(escape_label("front.door-1_x"), "front.door-1_x");
        let mut metrics = snapshot(0, 0);
        metrics
            .streams
            .insert("q\"\\\n".into(), StreamStats::default());
        let (text, _) = render(&metrics);
        assert!(
            text.contains("lotse_stream_packets_lost_total{stream=\"q\\\"\\\\\\n\"} 0\n"),
            "{text}"
        );
        assert!(
            text.lines().all(|line| !line.is_empty()),
            "no raw line feed"
        );
    }

    #[test]
    fn help_text_escapes_backslash_and_line_feed_text_format_help() {
        assert_eq!(escape_help("a\\b\nc \"d\""), "a\\\\b\\nc \"d\"");
    }

    #[test]
    fn values_are_integers_or_seconds_with_three_places_as_go_parsefloat_reads() {
        assert_eq!(Value::Count(0).to_string(), "0");
        assert_eq!(Value::Count(u64::MAX).to_string(), "18446744073709551615");
        assert_eq!(Value::Seconds(0).to_string(), "0.000");
        assert_eq!(Value::Seconds(1_500).to_string(), "1.500");
        assert_eq!(Value::Seconds(61_001).to_string(), "61.001");
        assert_eq!(Value::Seconds(999).to_string(), "0.999");
    }

    #[test]
    fn names_have_the_lotse_prefix_and_counters_end_in_total_prometheus_naming() {
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
            assert!(family.name.starts_with("lotse_"), "{}", family.name);
            // The legacy name character set, so no name is quoted.
            assert!(
                family
                    .name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                "{}",
                family.name
            );
            assert_eq!(
                family.name.ends_with("_total"),
                family.kind == Kind::Counter,
                "{}",
                family.name
            );
            assert!(!family.help.contains(['\\', '\n']), "{}", family.name);
        }
        assert_eq!(Kind::Counter.as_str(), "counter");
        assert_eq!(Kind::Gauge.as_str(), "gauge");
    }

    #[test]
    fn the_exposition_stops_at_its_caps_and_says_so_once_per_interval() {
        let (logs, _guard) = crate::pairing::test_support::capture();
        let metrics = snapshot(MAX_EXPORTED_STREAMS + 2, MAX_EXPORTED_WORKERS + 1);
        let (text, left_out) = render(&metrics);
        assert_eq!(
            left_out,
            LeftOut {
                streams: 2,
                workers: 1
            }
        );
        let streams = text
            .lines()
            .filter(|line| line.starts_with("lotse_stream_packets_lost_total{"))
            .count();
        assert_eq!(streams, MAX_EXPORTED_STREAMS);
        assert!(text.contains("{stream=\"s01023\"}"));
        assert!(
            !text.contains("{stream=\"s01024\"}"),
            "by id, the first ones"
        );
        let workers = text
            .lines()
            .filter(|line| line.starts_with("lotse_worker_sessions{"))
            .count();
        assert_eq!(workers, MAX_EXPORTED_WORKERS);
        assert!(text.contains("lotse_streams 1026\n"), "the whole count");

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
        for _ in 0..3 {
            assert_eq!(respond(Some(metrics.clone()), &lines).status(), 200);
        }
        let logged = capped();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("streams_left_out=2"), "{logged:?}");
        assert!(logged[0].contains("workers_left_out=1"), "{logged:?}");
        clock.advance(lotse_core::throttle::SUMMARY_INTERVAL);
        assert_eq!(respond(Some(metrics), &lines).status(), 200);
        let logged = capped();
        assert_eq!(logged.len(), 2, "{logged:?}");
        assert!(logged[1].ends_with("scrapes=3"), "{logged:?}");
        // Under the caps nothing is said.
        assert_eq!(respond(Some(snapshot(3, 3)), &lines).status(), 200);
        clock.advance(lotse_core::throttle::SUMMARY_INTERVAL);
        assert_eq!(respond(Some(snapshot(3, 3)), &lines).status(), 200);
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
    async fn an_exposition_is_200_in_its_content_type_and_closes_the_connection() {
        let clock = Arc::new(FakeClock::default());
        let lines = LimitLines::new(clock);
        let (status, headers, body) = body_of(respond(Some(snapshot(1, 1)), &lines)).await;
        assert_eq!(status, 200);
        assert_eq!(
            headers[header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        assert_eq!(headers[header::CONNECTION], "close");
        assert_eq!(body, render(&snapshot(1, 1)).0);
        let (logs, _guard) = crate::pairing::test_support::capture();
        let (status, headers, body) = body_of(respond(None, &lines)).await;
        assert_eq!(status, 503);
        assert_eq!(headers[header::CONNECTION], "close");
        assert!(body.contains("internal_error"), "{body}");
        assert!(logs.text().contains("the handler keeps no metrics"));
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
}

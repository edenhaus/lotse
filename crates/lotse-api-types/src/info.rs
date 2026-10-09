//! `info` and `metrics/get` results.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::stream::StreamStats;

/// How the daemon was built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BuildInfo {
    /// The target triple.
    pub target: String,
    /// The git commit, when known.
    pub git_sha: Option<String>,
    /// The Rust version.
    pub rustc: String,
}

/// The codecs the daemon can carry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Codecs {
    /// Video codec names.
    pub video: Vec<String>,
    /// Audio codec names.
    pub audio: Vec<String>,
}

/// The limits in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Limits {
    /// Streams.
    pub max_streams: u32,
    /// Sessions in total.
    pub max_sessions: u32,
    /// Sessions per stream.
    pub max_sessions_per_stream: u32,
    /// Control connections.
    pub max_connections: u32,
    /// How long an orphaned session outlives its connection.
    pub session_grace_ms: u64,
}

/// The Landlock layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandlockInfo {
    /// Filesystem rules: `enforced`, `unavailable` or `off`.
    pub fs: String,
    /// TCP rules: `enforced`, `unavailable` or `off`.
    pub net: String,
    /// The kernel's Landlock ABI; zero without Landlock.
    pub abi: u32,
}

/// The hardening layers of the supervisor, so a client can warn the user
/// when one is missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxInfo {
    /// `on`, `require` or `off`.
    pub mode: String,
    /// The real uid.
    pub uid: u32,
    /// The real gid.
    pub gid: u32,
    /// `PR_SET_NO_NEW_PRIVS` is set.
    pub no_new_privs: bool,
    /// The seccomp allowlist: `enforced`, `unavailable` or `off`.
    pub seccomp: String,
    /// The Landlock layers.
    pub landlock: LandlockInfo,
    /// Why layers are missing, for humans.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// `info`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InfoResult {
    /// The daemon version.
    pub version: String,
    /// The build.
    pub build: BuildInfo,
    /// The URL schemes a client may route here.
    pub schemes: Vec<String>,
    /// The output kinds compiled in.
    pub outputs: Vec<String>,
    /// Capabilities inside outputs.
    pub features: Vec<String>,
    /// The codecs.
    pub codecs: Codecs,
    /// The limits.
    pub limits: Limits,
    /// The sandbox.
    pub sandbox: SandboxInfo,
}

/// One process's figures.
/// Memory is read by the supervisor from the kernel, never reported by a
/// worker; `None` where the platform has no `/proc` (macOS) or the process
/// is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessMetrics {
    /// The process id.
    pub pid: u32,
    /// Milliseconds since it started.
    pub uptime_ms: u64,
    /// Resident set size (`Rss` of `smaps_rollup`).
    pub rss_bytes: Option<u64>,
    /// Proportional set size (`Pss` of `smaps_rollup`): the shared text
    /// pages divided among the processes mapping them, so the figures of
    /// all processes add up.
    pub pss_bytes: Option<u64>,
    /// Tokio tasks alive in its runtime; `None` until a worker's first
    /// counters arrive.
    pub tasks: Option<u64>,
}

/// The supervisor's demux counters: what the receive thread did with each
/// datagram on the shared UDP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct DemuxMetrics {
    /// Datagrams read.
    pub received: u64,
    /// Datagrams handed to a worker.
    pub forwarded: u64,
    /// Datagrams from unknown addresses that were not a usable STUN request.
    pub unroutable: u64,
    /// STUN requests with an unknown ufrag or a wrong password.
    pub stun_rejected: u64,
    /// Addresses learned through verified STUN requests.
    pub addresses_learned: u64,
    /// Datagrams dropped because the worker's channel was full.
    pub worker_full: u64,
    /// Responses to the supervisor's own STUN and TURN requests.
    pub responses: u64,
    /// Datagrams a TURN server relayed from a peer, unwrapped and routed.
    pub relayed: u64,
    /// Datagrams from a TURN server discarded: not on a held channel, not
    /// from a permitted peer, or neither STUN nor `ChannelData`.
    pub relay_discarded: u64,
    /// Receive wake-ups without a datagram.
    pub idle_wakeups: u64,
}

/// The supervisor process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SupervisorMetrics {
    /// Its process figures.
    #[serde(flatten)]
    pub process: ProcessMetrics,
    /// The demux, when the WebRTC UDP socket is open.
    pub demux: Option<DemuxMetrics>,
}

/// One worker process: the one running a source connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkerMetrics {
    /// Its process figures; the uptime counts from this worker's start, a
    /// restart starts it again.
    #[serde(flatten)]
    pub process: ProcessMetrics,
    /// The streams reading from its connection.
    pub streams: Vec<String>,
    /// Crash restarts of the connection's worker so far.
    pub restarts: u32,
    /// Open viewer sessions.
    pub sessions: u32,
    /// Datagrams its sessions could not send.
    pub send_failures: u64,
    /// Datagrams from a relay candidate dropped for want of a channel.
    pub relay_unbound: u64,
}

/// `metrics/get`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Metrics {
    /// The supervisor.
    pub supervisor: SupervisorMetrics,
    /// The running workers, by connection id (`c1`).
    pub workers: BTreeMap<String, WorkerMetrics>,
    /// Worker crash restarts since start.
    pub worker_restarts: u64,
    /// Open viewer sessions on all connections.
    pub sessions: u32,
    /// Per stream.
    pub streams: BTreeMap<String, StreamStats>,
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
    fn info_serializes_like_the_contract_example() {
        let info = InfoResult {
            version: "0.1.0".into(),
            build: BuildInfo {
                target: "aarch64-unknown-linux-musl".into(),
                git_sha: Some("abc123".into()),
                rustc: "1.98.0".into(),
            },
            schemes: vec!["rtsp".into(), "rtsps".into()],
            outputs: vec!["webrtc".into()],
            features: vec![],
            codecs: Codecs {
                video: vec!["h264".into()],
                audio: vec!["opus".into()],
            },
            limits: Limits {
                max_streams: 256,
                max_sessions: 256,
                max_sessions_per_stream: 16,
                max_connections: 8,
                session_grace_ms: 10_000,
            },
            sandbox: SandboxInfo {
                mode: "on".into(),
                uid: 65534,
                gid: 65534,
                no_new_privs: true,
                seccomp: "enforced".into(),
                landlock: LandlockInfo {
                    fs: "enforced".into(),
                    net: "unavailable".into(),
                    abi: 3,
                },
                notes: vec![],
            },
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["build"]["git_sha"], "abc123");
        assert_eq!(json["limits"]["session_grace_ms"], 10_000);
        assert_eq!(
            json["sandbox"],
            json!({ "mode": "on", "uid": 65534, "gid": 65534, "no_new_privs": true,
                    "seccomp": "enforced", "landlock": { "fs": "enforced", "net": "unavailable", "abi": 3 } })
        );
        let back: InfoResult = serde_json::from_value(json).unwrap();
        assert_eq!(back, info);

        let mut metrics = Metrics {
            supervisor: SupervisorMetrics {
                process: ProcessMetrics {
                    pid: 1,
                    uptime_ms: 2,
                    rss_bytes: Some(8_192),
                    pss_bytes: None,
                    tasks: Some(3),
                },
                demux: Some(DemuxMetrics {
                    forwarded: 4,
                    ..DemuxMetrics::default()
                }),
            },
            workers: BTreeMap::new(),
            worker_restarts: 0,
            sessions: 1,
            streams: BTreeMap::new(),
        };
        metrics
            .streams
            .insert("front".into(), StreamStats::default());
        metrics.workers.insert(
            "c1".into(),
            WorkerMetrics {
                process: ProcessMetrics {
                    pid: 4711,
                    uptime_ms: 5,
                    rss_bytes: None,
                    pss_bytes: Some(5_242_880),
                    tasks: None,
                },
                streams: vec!["front".into()],
                restarts: 0,
                sessions: 1,
                send_failures: 0,
                relay_unbound: 0,
            },
        );
        let json = serde_json::to_value(&metrics).unwrap();
        // The process figures sit beside the rest, not under a key.
        assert_eq!(json["supervisor"]["pid"], 1);
        assert_eq!(json["supervisor"]["pss_bytes"], serde_json::Value::Null);
        assert_eq!(json["supervisor"]["demux"]["forwarded"], 4);
        assert_eq!(json["workers"]["c1"]["pss_bytes"], 5_242_880);
        assert_eq!(json["workers"]["c1"]["streams"], json!(["front"]));
        assert_eq!(json["streams"]["front"]["stalls"], 0);
        assert_eq!(serde_json::from_value::<Metrics>(json).unwrap(), metrics);
        assert_eq!(Codecs::default().video.len(), 0);
    }
}

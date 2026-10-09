//! Drives the supervisor in-process against real workers: `stream/put`
//! with `preload` starts a `lotse worker` running the fake source, the
//! stream goes live with its tracks, losing demand lingers then stops the
//! worker, a crashing worker is restarted with backoff, connection
//! attempts take turns under `sources.connect_concurrency`, and shutdown
//! stops everything within the budget. Needs the `source-fake` feature (on with
//! `--all-features`).

#![cfg(feature = "source-fake")]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lotse_api_types::command::parse_command;
use lotse_api_types::info::{BuildInfo, LandlockInfo, SandboxInfo};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::registry::Registries;
use lotse_core::test_util::FakeSourceFactory;
use lotse_supervisor::api::{ConnectionId, Event, Handler as _, Outcome};
use lotse_supervisor::worker::WorkerConfig;
use lotse_supervisor::{Environment, Identity, Limits, Settings, Supervisor};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// A supervisor whose workers are the built binary, with a short linger.
fn supervisor() -> Supervisor {
    supervisor_with(lotse_supervisor::DEFAULT_CONNECT_CONCURRENCY)
}

/// [`supervisor`] allowing `connects` connection attempts at once.
fn supervisor_with(connects: NonZeroUsize) -> Supervisor {
    let settings = Settings {
        socket: PathBuf::from("/nonexistent/lotse.sock"),
        owner_uid: 0,
        allow_uid: 0,
        udp_listen: "[::]:18556".parse().unwrap(),
        tcp_listen: None,
        limits: Limits {
            max_connections: 8,
            max_streams: 8,
            max_sessions: 256,
            max_sessions_per_stream: 16,
            session_grace: Duration::from_secs(10),
            worker_threads: 1,
            worker_address_space: 1 << 30,
        },
        linger: Duration::from_millis(200),
        connect_concurrency: connects,
        shutdown_budget: Duration::from_secs(2),
    };
    let mut registries = Registries::default();
    registries
        .sources
        .register(Arc::new(FakeSourceFactory::new(&["fake"])))
        .unwrap();
    let environment = Environment {
        registries,
        worker: WorkerConfig {
            binary: PathBuf::from(env!("CARGO_BIN_EXE_lotse")),
            log_format: "json".into(),
            log_level: "debug".into(),
            sandbox: "off".into(),
            worker_threads: 1,
            worker_address_space: 1 << 30,
            max_sessions: 256,
        },
        udp: None,
        front_door: None,
        identity: Identity {
            version: "0.0.0-test".into(),
            build: BuildInfo {
                target: "test".into(),
                git_sha: None,
                rustc: "test".into(),
            },
            sandbox: SandboxInfo {
                mode: "off".into(),
                uid: 0,
                gid: 0,
                no_new_privs: false,
                seccomp: "off".into(),
                landlock: LandlockInfo {
                    fs: "off".into(),
                    net: "off".into(),
                    abi: 0,
                },
                notes: vec![],
            },
        },
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    Supervisor::new(settings, environment, clock)
}

async fn call(supervisor: &Supervisor, command: Value) -> Outcome {
    let command = parse_command(&command.to_string()).expect("a command");
    supervisor.handle(ConnectionId(1), command).await
}

fn result(outcome: Outcome) -> Value {
    match outcome {
        Outcome::Result(value) => value,
        Outcome::Error(err) => panic!("error {err}"),
        Outcome::Subscribed(_) => panic!("subscription"),
    }
}

fn subscription(outcome: Outcome) -> mpsc::Receiver<Event> {
    match outcome {
        Outcome::Subscribed(rx) => rx,
        other => panic!("not a subscription: {other:?}"),
    }
}

/// The next `stream` event's state, skipping nothing: every change counts.
async fn next_state(events: &mut mpsc::Receiver<Event>) -> (String, Option<String>) {
    let event = events.recv().await.expect("an event").payload;
    assert_eq!(event["type"], "stream", "{event}");
    (
        event["state"].as_str().unwrap().to_owned(),
        event["last_error"]["code"].as_str().map(str::to_owned),
    )
}

fn put(stream_id: &str, options: &Value, preload: bool) -> Value {
    json!({ "id": 1, "type": "stream/put", "stream_id": stream_id,
            "sources": [{ "url": "fake://127.0.0.1/", "options": options }], "preload": preload })
}

#[tokio::test]
async fn preload_starts_a_worker_that_goes_live_and_linger_stops_it() {
    let s = supervisor();
    let mut events = subscription(call(&s, json!({ "id": 1, "type": "stream/subscribe" })).await);
    assert_eq!(
        result(call(&s, put("front", &json!({}), true)).await)["created"],
        true
    );
    for expected in ["idle", "connecting", "live"] {
        assert_eq!(next_state(&mut events).await.0, expected);
    }
    let front = result(
        call(
            &s,
            json!({ "id": 2, "type": "stream/get", "stream_id": "front" }),
        )
        .await,
    );
    assert_eq!(front["state"], "live");
    assert_eq!(front["last_error"], Value::Null);
    assert_eq!(front["tracks"][0]["id"], "v0");
    assert_eq!(front["tracks"][0]["codec"], "h264");
    assert_eq!(front["tracks"][0]["kind"], "video");
    let worker = &front["sources"][0]["connection"]["worker"];
    assert!(worker["pid"].as_u64().unwrap() > 0, "{front}");
    assert_eq!(worker["restarts"], 0);
    // No demand: the linger runs, then the worker is stopped.
    assert_eq!(
        result(call(&s, put("front", &json!({}), false)).await)["created"],
        false
    );
    assert_eq!(next_state(&mut events).await.0, "draining");
    assert_eq!(next_state(&mut events).await.0, "idle");
    let front = result(
        call(
            &s,
            json!({ "id": 3, "type": "stream/get", "stream_id": "front" }),
        )
        .await,
    );
    assert_eq!(front["sources"][0]["connection"]["worker"], Value::Null);
    // Demand within the next linger would have kept it; here it restarts.
    result(call(&s, put("front", &json!({}), true)).await);
    for expected in ["connecting", "live"] {
        assert_eq!(next_state(&mut events).await.0, expected);
    }
    result(
        call(
            &s,
            json!({ "id": 4, "type": "stream/delete", "stream_id": "front" }),
        )
        .await,
    );
    assert_eq!(
        events.recv().await.unwrap().payload["type"],
        "stream_removed"
    );
    s.shutdown().await;
}

#[tokio::test]
async fn rfc3550_6_4_1_stream_get_reports_the_sync_tracks_have_now() {
    // The fake camera's Sender Reports start a second after it went live
    // (RFC 3550 §6.4.1): the tracks were announced mapping by arrival,
    // and map from the reports soon after.
    let s = supervisor();
    let mut events = subscription(call(&s, json!({ "id": 1, "type": "stream/subscribe" })).await);
    result(call(&s, put("front", &json!({ "audio": "aac_drifting" }), true)).await);
    for expected in ["idle", "connecting", "live"] {
        assert_eq!(next_state(&mut events).await.0, expected);
    }
    let clock = SystemClock;
    let deadline = clock.now() + Duration::from_secs(10);
    loop {
        let front = result(
            call(
                &s,
                json!({ "id": 2, "type": "stream/get", "stream_id": "front" }),
            )
            .await,
        );
        let syncs: Vec<&str> = front["tracks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|track| track["sync"].as_str().unwrap())
            .collect();
        if syncs == ["sender_reports", "sender_reports"] {
            break;
        }
        assert!(clock.now() < deadline, "still {syncs:?}: {front}");
        clock.sleep(Duration::from_millis(50)).await;
    }
    s.shutdown().await;
}

#[tokio::test]
async fn a_crashing_worker_is_restarted_with_backoff_and_shutdown_stops_it() {
    let s = supervisor();
    let mut events = subscription(call(&s, json!({ "id": 1, "type": "stream/subscribe" })).await);
    result(call(&s, put("crash", &json!({ "crash": true }), true)).await);
    assert_eq!(next_state(&mut events).await.0, "idle");
    assert_eq!(next_state(&mut events).await.0, "connecting");
    // The fake source aborts the worker right after going live; whether the
    // `live` report races ahead of the exit or not, the crash is seen.
    let (state, error) = loop {
        let next = next_state(&mut events).await;
        if next.0 != "live" {
            break next;
        }
    };
    assert_eq!(
        (state.as_str(), error.as_deref()),
        ("restarting", Some("worker_crashed"))
    );
    let crash = result(
        call(
            &s,
            json!({ "id": 2, "type": "stream/get", "stream_id": "crash" }),
        )
        .await,
    );
    assert_eq!(crash["last_error"]["code"], "worker_crashed");
    assert_eq!(crash["sources"][0]["connection"]["worker"], Value::Null);
    // After the 0.5 s backoff a new worker is started.
    assert_eq!(next_state(&mut events).await.0, "connecting");
    let metrics = result(call(&s, json!({ "id": 3, "type": "metrics/get" })).await);
    assert!(
        metrics["worker_restarts"].as_u64().unwrap() >= 1,
        "{metrics}"
    );
    s.shutdown().await;
}

#[tokio::test]
async fn with_one_connect_permit_two_preloaded_cameras_connect_one_at_a_time() {
    let s = supervisor_with(NonZeroUsize::MIN);
    let mut events = subscription(call(&s, json!({ "id": 1, "type": "stream/subscribe" })).await);
    // Each camera takes 400 ms to go live; one permit means the attempt
    // that waits starts only once the other is live.
    for (stream, port) in [("first", 1), ("second", 2)] {
        result(
            call(
                &s,
                json!({ "id": 1, "type": "stream/put", "stream_id": stream,
                        "sources": [{ "url": format!("fake://127.0.0.1:{port}/"),
                                      "options": { "ready_after_ms": 400 } }],
                        "preload": true }),
            )
            .await,
        );
    }
    let mut live = Vec::new();
    while live.len() < 2 {
        let event = events.recv().await.expect("an event").payload;
        if event["state"] == "live" {
            live.push((
                event["stream_id"].as_str().unwrap().to_owned(),
                SystemClock.now(),
            ));
        }
    }
    assert_ne!(live[0].0, live[1].0, "{live:?}");
    let apart = live[1].1.saturating_duration_since(live[0].1);
    assert!(
        apart >= Duration::from_millis(300),
        "the second connected while the first held the permit: {apart:?}"
    );
    s.shutdown().await;
}

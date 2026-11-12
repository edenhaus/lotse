//! A signaled source's signaling through the control API, the test playing
//! the client that relays it to the camera: the supervisor in-process
//! with a real `lotse worker` running the fake signaled source behind
//! `stream/put`. `signaling/subscribe` gets the source's offer, its host
//! candidates and end-of-candidates; `signaling/answer` makes the stream
//! live. `signaling/error` closes the signal, and the source offers again,
//! with a new signal, after its backoff; only the subscribing control
//! connection may answer. A later subscription supersedes the earlier,
//! whose signal ends, and an `unsubscribe` ends the new one's: each time
//! the source connects again and offers to whichever subscription takes
//! its stream then.
//! Needs the `source-fake` feature (on with `--all-features`).

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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lotse_api_types::command::parse_command;
use lotse_api_types::info::{BuildInfo, LandlockInfo, SandboxInfo};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::registry::Registries;
use lotse_core::test_util::{FAKE_SIGNALED_OFFER, FakeSignaledSourceFactory};
use lotse_supervisor::api::{ConnectionId, Event, EventClass, Handler as _, Outcome};
use lotse_supervisor::net::demux::Registrations;
use lotse_supervisor::worker::WorkerConfig;
use lotse_supervisor::{Environment, FrontDoor, Identity, Limits, Settings, Supervisor};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// The host candidates' address the front door answers with: the one
/// address a signaled source gathers on.
const HOST: &str = "127.0.0.1:18556";

/// The answer the test relays as the camera's: SDP lines, as the fake
/// source wants them.
const ANSWER: &str = "v=0\r\ns=camera\r\n";

/// A supervisor whose workers are the built binary, with the signaled
/// fake source and a front door on [`HOST`].
fn supervisor() -> Supervisor {
    let settings = Settings {
        socket: PathBuf::from("/nonexistent/lotse.sock"),
        owners: lotse_supervisor::Owners::only(0),
        allow_uid: 0,
        control_tls: None,
        udp_listen: HOST.parse().unwrap(),
        tcp_listen: None,
        advertise: Vec::new(),
        limits: Limits {
            max_connections: 8,
            max_streams: 8,
            max_sessions: 16,
            max_sessions_per_stream: 16,
            session_grace: Duration::from_secs(10),
            worker_threads: 1,
            worker_address_space: 1 << 30,
            recordings: lotse_supervisor::RecordingLimits::DEFAULT,
        },
        linger: Duration::from_millis(200),
        connect_concurrency: lotse_supervisor::DEFAULT_CONNECT_CONCURRENCY,
        shutdown_budget: Duration::from_secs(2),
    };
    let mut registries = Registries::default();
    registries
        .sources
        .register_signaled(Arc::new(FakeSignaledSourceFactory::new("fake-signaled")))
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
            max_sessions: 16,
            recordings: lotse_supervisor::RecordingLimits::DEFAULT,
        },
        udp: None,
        front_door: Some(FrontDoor {
            registrations: Arc::new(Registrations::default()),
            hosts: vec![HOST.parse().unwrap()],
            tcp_hosts: vec![],
            scan: None,
            stun: None,
            turn: None,
            demux: None,
        }),
        identity: Identity {
            version: "0.0.0-test".into(),
            build: BuildInfo {
                target: "test".into(),
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

/// `command` from control connection `connection`.
async fn call(s: &Supervisor, connection: u64, command: &Value) -> Outcome {
    let command = parse_command(&command.to_string()).expect("a command");
    s.handle(ConnectionId(connection), command).await
}

fn result(outcome: Outcome) -> Value {
    match outcome {
        Outcome::Result(value) => value,
        Outcome::Error(err) => panic!("error {err}"),
        Outcome::Subscribed(_) | Outcome::SubscribedWith { .. } => panic!("subscription"),
    }
}

fn error_code(outcome: Outcome) -> String {
    match outcome {
        Outcome::Error(err) => err.code.as_str().to_owned(),
        other => panic!("not an error: {other:?}"),
    }
}

fn subscription(outcome: Outcome) -> mpsc::Receiver<Event> {
    match outcome {
        Outcome::Subscribed(rx) => rx,
        other => panic!("not a subscription: {other:?}"),
    }
}

/// `signaling/subscribe` `id` of control connection `connection`, for
/// `stream_id` or every stream.
async fn subscribe(
    s: &Supervisor,
    connection: u64,
    id: u64,
    stream_id: Option<&str>,
) -> mpsc::Receiver<Event> {
    let mut command = json!({ "id": id, "type": "signaling/subscribe" });
    if let Some(stream_id) = stream_id {
        command["stream_id"] = json!(stream_id);
    }
    subscription(call(s, connection, &command).await)
}

/// The next event, a signaling one that is never shed; 15 s without one
/// fail the test (a backoff is a second or two).
async fn next(events: &mut mpsc::Receiver<Event>) -> Value {
    tokio::select! {
        event = events.recv() => {
            let event = event.expect("an event");
            assert_eq!(event.class, EventClass::Signaling);
            event.payload
        }
        () = SystemClock.sleep(Duration::from_secs(15)) => panic!("no event within 15 s"),
    }
}

/// The next signal's offer and trickled candidates on `events`: its id,
/// after checking them against the fake source's.
async fn offer(events: &mut mpsc::Receiver<Event>) -> String {
    let offer = next(events).await;
    assert_eq!(offer["type"], "offer", "{offer}");
    let signal_id = offer["signal_id"].as_str().unwrap().to_owned();
    assert_eq!(signal_id.len(), 26, "a ULID: {offer}");
    assert_eq!(offer["stream_id"], "door");
    assert_eq!(offer["protocol"], "fake-signaled");
    assert!(offer.get("source").is_none(), "{offer}");
    assert_eq!(offer["sdp"], FAKE_SIGNALED_OFFER);
    // One host candidate per address of the front door's hosts, then
    // end-of-candidates (RFC 8838 §13).
    assert_eq!(
        next(events).await,
        json!({ "type": "candidate", "signal_id": signal_id, "sdp_mid": "0", "sdp_mline_index": 0,
                "candidate": "candidate:1 1 udp 2130706431 127.0.0.1 9 typ host" })
    );
    assert_eq!(
        next(events).await,
        json!({ "type": "candidate", "signal_id": signal_id, "sdp_mid": "0", "sdp_mline_index": 0,
                "candidate": "" })
    );
    signal_id
}

fn put() -> Value {
    json!({ "id": 1, "type": "stream/put", "stream_id": "door",
            "sources": [{ "protocol": "fake-signaled" }], "preload": true })
}

fn answer(id: u64, signal_id: &str) -> Value {
    json!({ "id": id, "type": "signaling/answer", "signal_id": signal_id, "sdp": ANSWER })
}

/// Waits until `door` is live, failing after 10 s.
async fn until_live(s: &Supervisor) -> Value {
    for _ in 0..200 {
        let door = result(
            call(
                s,
                9,
                &json!({ "id": 1, "type": "stream/get", "stream_id": "door" }),
            )
            .await,
        );
        if door["state"] == "live" {
            return door;
        }
        SystemClock.sleep(Duration::from_millis(50)).await;
    }
    panic!("door never went live");
}

#[tokio::test]
async fn rfc8829_the_client_answers_a_signaled_source_s_offer_and_the_stream_goes_live() {
    let s = supervisor();
    let mut door = subscribe(&s, 1, 1, Some("door")).await;
    assert_eq!(result(call(&s, 1, &put()).await)["created"], true);
    let signal_id = offer(&mut door).await;
    // The camera's candidate, then its answer.
    let candidate = json!({ "id": 2, "type": "signaling/candidate", "signal_id": signal_id,
        "candidate": "candidate:1 1 udp 2130706431 192.0.2.9 50000 typ host", "sdp_mline_index": 0 });
    assert_eq!(result(call(&s, 1, &candidate).await), json!({}));
    assert_eq!(result(call(&s, 1, &answer(3, &signal_id)).await), json!({}));
    let live = until_live(&s).await;
    assert_eq!(live["tracks"][0]["codec"], "h264");
    assert_eq!(live["last_error"], Value::Null);
    // One answer per signal.
    assert_eq!(
        error_code(call(&s, 1, &answer(4, &signal_id)).await),
        "invalid_request"
    );
    s.shutdown().await;
}

#[tokio::test]
async fn a_camera_error_closes_the_signal_and_the_source_offers_again_with_a_new_one() {
    let s = supervisor();
    let mut all = subscribe(&s, 1, 1, None).await;
    assert_eq!(result(call(&s, 1, &put()).await)["created"], true);
    let first = offer(&mut all).await;
    // Only the subscribing connection signals for it.
    assert_eq!(
        error_code(call(&s, 2, &answer(1, &first)).await),
        "signal_not_found"
    );
    let error = json!({ "id": 2, "type": "signaling/error", "signal_id": first,
        "code": "webrtc_offer_failed", "message": "the camera is offline" });
    assert_eq!(result(call(&s, 1, &error).await), json!({}));
    assert_eq!(
        next(&mut all).await,
        json!({ "type": "closed", "signal_id": first, "code": "camera_error",
                "message": "camera: webrtc_offer_failed: the camera is offline" })
    );
    // The attempt failed before an answer: unreachable, then a new
    // attempt after the backoff, with a new signal.
    let second = offer(&mut all).await;
    assert_ne!(second, first);
    assert_eq!(
        error_code(call(&s, 1, &answer(3, &first)).await),
        "signal_not_found"
    );
    assert_eq!(result(call(&s, 1, &answer(4, &second)).await), json!({}));
    until_live(&s).await;
    s.shutdown().await;
}

#[tokio::test]
async fn a_later_subscription_supersedes_the_earlier_and_an_unsubscribe_ends_its_signal() {
    let s = supervisor();
    let mut earlier = subscribe(&s, 1, 1, None).await;
    assert_eq!(result(call(&s, 1, &put()).await)["created"], true);
    let first = offer(&mut earlier).await;
    assert_eq!(result(call(&s, 1, &answer(2, &first)).await), json!({}));
    until_live(&s).await;
    // A later subscription for every stream takes the scope: the earlier
    // gets `superseded` last, and its signal ends, live as it was.
    let mut later = subscribe(&s, 2, 1, None).await;
    assert_eq!(next(&mut earlier).await, json!({ "type": "superseded" }));
    assert!(
        earlier.recv().await.is_none(),
        "the earlier subscription ended"
    );
    // The source connects again and offers to the later one.
    let second = offer(&mut later).await;
    assert_ne!(second, first);
    assert_eq!(
        error_code(call(&s, 1, &answer(3, &second)).await),
        "signal_not_found"
    );
    // Its unsubscribe ends that signal too; the source's next attempt,
    // after its backoff, offers to the subscription that takes its stream
    // then. (An open that comes before any subscription waits for one:
    // the registry's and the driver's tests pin that wait on a fake
    // clock.)
    assert!(s.unsubscribed(ConnectionId(2), 1).is_none());
    assert_eq!(
        error_code(call(&s, 2, &answer(2, &second)).await),
        "signal_not_found"
    );
    let mut door = subscribe(&s, 3, 1, Some("door")).await;
    let third = offer(&mut door).await;
    assert_ne!(third, second);
    assert_eq!(result(call(&s, 3, &answer(2, &third)).await), json!({}));
    until_live(&s).await;
    s.shutdown().await;
}

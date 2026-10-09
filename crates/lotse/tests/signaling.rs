//! One viewer through the control API: the supervisor in-process with the
//! real demux and a real `lotse worker` subprocess, the fake RTSP camera
//! behind `stream/put`, and the headless viewer negotiating only through
//! `webrtc/offer` events and `webrtc/candidate`, with a server-reflexive
//! candidate from a fake STUN server that plays a NAT. The control connection
//! then drops: media keeps flowing to the orphan, `session/adopt` takes it
//! back, and `session/close` ends it. A preloaded stream serves its first
//! viewer from the warm GOP cache without a new camera connection, and the
//! linger keeps the connection for a viewer that comes back. A viewer the
//! daemon reaches only through a TURN relay plays through the fake TURN
//! server's loopback relay, allocated over UDP and over TCP.
//! Needs the `source-rtsp` and `output-webrtc` features (the defaults).

#![cfg(all(feature = "source-rtsp", feature = "output-webrtc"))]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lotse_api_types::command::parse_command;
use lotse_api_types::info::{BuildInfo, LandlockInfo, SandboxInfo};
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::registry::Registries;
use lotse_supervisor::api::{ConnectionId, Event, Handler as _, Outcome};
use lotse_supervisor::net::allocation::AllocationConfig;
use lotse_supervisor::net::demux::{Demux, DemuxStats};
use lotse_supervisor::net::stun;
use lotse_supervisor::net::stun_client::{StunClient, StunClientConfig};
use lotse_supervisor::net::tcp::{IceTcpConfig, IceTcpStats, accept_loop};
use lotse_supervisor::net::turn_client::TurnClient;
use lotse_supervisor::net::udp::{bind_tcp, bind_udp};
use lotse_supervisor::worker::WorkerConfig;
use lotse_supervisor::{Environment, FrontDoor, Identity, Limits, Settings, Supervisor};
use lotse_testing::fake_camera::Stats;
use lotse_testing::fake_turn::{FakeTurn, FakeTurnServer};
use lotse_testing::viewer::{Outgoing, Viewer};
use lotse_testing::{CameraConfig, FakeCamera};
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// The supervisor, its demux on a loopback socket, both halves of the
/// front door wired as `serve` wires them.
/// The supervisor and its front door, with the ICE-TCP acceptor running.
struct Daemon {
    supervisor: Supervisor,
    demux: Demux,
    tcp: SocketAddr,
    tcp_stats: Arc<IceTcpStats>,
    stop_tcp: CancellationToken,
}

fn supervisor() -> Daemon {
    supervisor_with(Duration::from_millis(200))
}

/// [`supervisor`] with this `stream.linger`.
fn supervisor_with(linger: Duration) -> Daemon {
    let bound = bind_udp("127.0.0.1:0".parse().unwrap()).expect("the shared socket");
    let demux = Demux::start(
        Arc::clone(&bound.socket),
        bound.local,
        bound.hosts.clone(),
        Arc::new(SystemClock),
    )
    .expect("the demux");
    let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).expect("the ice-tcp listener");
    let tcp = listener.local_addr().unwrap();
    let tcp_stats = Arc::new(IceTcpStats::default());
    let stop_tcp = CancellationToken::new();
    lotse_core::task::spawn_named(
        "test.ice_tcp",
        accept_loop(
            tokio::net::TcpListener::from_std(listener).unwrap(),
            demux.registrations(),
            IceTcpConfig::default(),
            clock(),
            Arc::clone(&tcp_stats),
            stop_tcp.clone(),
        ),
    );
    let settings = Settings {
        socket: PathBuf::from("/nonexistent/lotse.sock"),
        owner_uid: 0,
        allow_uid: 0,
        udp_listen: bound.local,
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
        linger,
        connect_concurrency: lotse_supervisor::DEFAULT_CONNECT_CONCURRENCY,
        shutdown_budget: Duration::from_secs(2),
    };
    let mut registries = Registries::default();
    registries
        .outputs
        .register(Arc::new(lotse_webrtc::WebRtcFactory))
        .unwrap();
    registries
        .sources
        .register(Arc::new(lotse_rtsp::RtspFactory::default()))
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
        udp: Some(Arc::clone(&bound.socket)),
        front_door: Some(FrontDoor {
            registrations: demux.registrations(),
            hosts: bound.hosts,
            tcp_hosts: vec![tcp],
            stun: Some(Arc::new(StunClient::new(
                Arc::clone(&bound.socket),
                demux.responses(),
                clock(),
                StunClientConfig::default(),
            ))),
            turn: Some(Arc::new(TurnClient::new(
                Arc::clone(&bound.socket),
                &demux,
                clock(),
                AllocationConfig::default(),
            ))),
            demux: Some(demux.stats()),
        }),
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
    Daemon {
        supervisor: Supervisor::new(settings, environment, clock()),
        demux,
        tcp,
        tcp_stats,
        stop_tcp,
    }
}

/// A STUN server that answers every Binding with `mapped`, as if the
/// daemon sat behind a NAT.
fn stun_server(mapped: SocketAddr) -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0_u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let Ok(request) = stun::parse(&buf[..n]) else {
                continue;
            };
            let reply = stun::Builder::new(
                stun::Class::Success,
                stun::METHOD_BINDING,
                request.transaction_id,
            )
            .xor_mapped_address(mapped)
            .build();
            let _sent = socket.send_to(&reply, from);
        }
    });
    addr
}

async fn call(supervisor: &Supervisor, connection: u64, command: &Value) -> Outcome {
    let command = parse_command(&command.to_string()).expect("a command");
    supervisor.handle(ConnectionId(connection), command).await
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

/// Sends what the viewer wants sent. Checks towards the srflx candidate's
/// documentation address cannot leave loopback; like a browser's, that
/// pair just fails.
async fn send_all(socket: &UdpSocket, out: &mut Vec<Outgoing>) {
    for datagram in out.drain(..) {
        let sent = socket
            .send_to(&datagram.payload, datagram.destination)
            .await;
        assert!(
            sent.is_ok() || !datagram.destination.ip().is_loopback(),
            "viewer send to {}: {sent:?}",
            datagram.destination
        );
    }
}

/// Runs the viewer's side until `done` holds for the events seen so far
/// and the viewer, handing every session event to `on_event` first.
async fn drive(
    viewer: &mut Viewer,
    socket: &UdpSocket,
    events: &mut mpsc::Receiver<Event>,
    seen: &mut Vec<Value>,
    mut on_event: impl FnMut(&Value, &mut Viewer, &mut Vec<Outgoing>),
    done: impl Fn(&[Value], &Viewer) -> bool,
) {
    let mut out = Vec::new();
    let mut buf = vec![0_u8; 2_000];
    let mut deadline = clock().sleep(Duration::from_secs(20));
    while !done(seen, viewer) {
        let next_timeout = viewer
            .next_timeout()
            .map_or(Duration::from_millis(20), |at| {
                at.saturating_duration_since(clock().now())
            });
        tokio::select! {
            event = events.recv() => {
                let event = event.expect("the subscription is open").payload;
                on_event(&event, viewer, &mut out);
                seen.push(event);
            }
            received = socket.recv_from(&mut buf) => {
                let (len, source) = received.expect("viewer recv");
                viewer.receive(clock().now(), source, &buf[..len], &mut out);
            }
            () = clock().sleep(next_timeout) => viewer.timeout(clock().now(), &mut out),
            () = &mut deadline => panic!("timed out; {} packets, events {seen:?}", viewer.packets().len()),
        }
        send_all(socket, &mut out).await;
    }
}

/// The signaling a client relays: the answer and the daemon's candidates
/// go to the viewer.
fn relay_signaling(event: &Value, viewer: &mut Viewer, out: &mut Vec<Outgoing>) {
    match event["type"].as_str() {
        Some("answer") => {
            viewer
                .accept_answer(event["sdp"].as_str().unwrap(), out)
                .expect("the answer applies");
        }
        Some("candidate") => {
            viewer.add_remote_candidate(event["candidate"].as_str().unwrap(), out);
        }
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_that_changes_the_source_url_switches_the_playing_session_to_it() {
    // The fake camera serves any path, so the put below is the same camera
    // under another URL on the same port, as a client that edits a
    // camera's path or credentials: the worker connects it as a standby
    // and the session plays on from its first keyframe, never closed.
    let cam = FakeCamera::start(
        CameraConfig {
            fps: 30,
            gop: 10,
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let Daemon {
        supervisor: s,
        demux,
        stop_tcp,
        ..
    } = supervisor();
    result(
        call(
            &s,
            1,
            &json!({ "id": 1, "type": "stream/put", "stream_id": "front", "sources": [{ "url": cam.url() }] }),
        )
        .await,
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    let mut events = subscription(
        call(
            &s,
            1,
            &json!({ "id": 2, "type": "webrtc/offer", "stream_id": "front", "session_id": "ha-1", "sdp": viewer.offer() }),
        )
        .await,
    );
    let mut seen = Vec::new();
    drive(
        &mut viewer,
        &socket,
        &mut events,
        &mut seen,
        relay_signaling,
        |_, viewer| viewer.is_connected() && viewer.packets().len() >= 20,
    )
    .await;
    let before = viewer.packets().len();
    let describes = || {
        cam.stats()
            .describes
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    assert_eq!(describes(), 1);

    let other = format!("{}/other", cam.url().trim_end_matches("/stream"));
    let put = result(
        call(
            &s,
            1,
            &json!({ "id": 3, "type": "stream/put", "stream_id": "front", "sources": [{ "url": other }] }),
        )
        .await,
    );
    assert_eq!(put["created"], false);
    // Two more seconds of pictures: the standby connected (a second
    // DESCRIBE), took the tracks over, and the session was never closed.
    drive(
        &mut viewer,
        &socket,
        &mut events,
        &mut seen,
        relay_signaling,
        |seen, viewer| {
            viewer.packets().len() >= before + 60 || seen.iter().any(|e| e["type"] == "closed")
        },
    )
    .await;
    assert!(seen.iter().all(|e| e["type"] != "closed"), "{seen:?}");
    assert!(viewer.packets().len() >= before + 60);
    assert_eq!(describes(), 2, "the standby connected to the camera");
    let front = result(
        call(
            &s,
            1,
            &json!({ "id": 4, "type": "stream/get", "stream_id": "front" }),
        )
        .await,
    );
    assert_eq!(front["sources"][0]["url"], other);
    assert_eq!(front["state"], "live");
    assert_eq!(front["sessions"], json!(["ha-1"]));
    assert_eq!(front["last_error"], Value::Null);
    assert_eq!(front["sources"][0]["connection"]["id"], "c1");

    s.shutdown().await;
    demux.stop();
    stop_tcp.cancel();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_plays_through_the_control_api_and_survives_a_control_reconnect() {
    let cam = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .expect("camera");
    let Daemon {
        supervisor: s,
        demux,
        stop_tcp,
        ..
    } = supervisor();
    result(
        call(
            &s,
            1,
            &json!({ "id": 1, "type": "stream/put", "stream_id": "front", "sources": [{ "url": cam.url() }] }),
        )
        .await,
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    let viewer_addr = socket.local_addr().unwrap();
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(viewer_addr, clock().now()).expect("a viewer");
    let stun = stun_server("203.0.113.7:40000".parse().unwrap());
    // A client's shape: its own session id, the ICE servers it gave the browser.
    let mut events = subscription(
        call(
            &s,
            1,
            &json!({ "id": 2, "type": "webrtc/offer", "stream_id": "front", "session_id": "ha-1",
                     "sdp": viewer.offer(), "ice_servers": [{ "urls": [format!("stun:{stun}")] }] }),
        )
        .await,
    );

    // Signaling: session, answer, the daemon's candidates, then connected.
    let mut seen = Vec::new();
    let viewer_candidate = format!(
        "candidate:1 1 udp 2130706431 {} {} typ host",
        viewer_addr.ip(),
        viewer_addr.port()
    );
    drive(
        &mut viewer,
        &socket,
        &mut events,
        &mut seen,
        |event, viewer, out| match event["type"].as_str() {
            Some("answer") => {
                viewer
                    .accept_answer(event["sdp"].as_str().unwrap(), out)
                    .expect("the answer applies");
            }
            Some("candidate") => {
                viewer.add_remote_candidate(event["candidate"].as_str().unwrap(), out);
            }
            _ => {}
        },
        |seen, viewer| {
            seen.iter()
                .any(|e| e["type"] == "candidate" && e["candidate"] == "")
                && viewer.is_connected()
                && viewer.packets().len() >= 20
        },
    )
    .await;
    assert_eq!(seen[0], json!({ "type": "session", "session_id": "ha-1" }));
    assert_eq!(
        seen[1]["type"], "answer",
        "the answer precedes every candidate: {seen:?}"
    );
    let answer = seen[1]["sdp"].as_str().unwrap();
    let ufrag = answer
        .lines()
        .find_map(|line| line.strip_prefix("a=ice-ufrag:"))
        .expect("an ice-ufrag in the answer");
    assert_eq!(ufrag.len(), 8, "the supervisor's credentials: {answer}");
    assert!(
        seen.iter()
            .any(|e| e["type"] == "candidate"
                && e["candidate"].as_str().unwrap().contains("127.0.0.1")),
        "a host candidate on the shared socket: {seen:?}"
    );
    // The NAT's mapping as srflx, based on the host address, and
    // end-of-candidates only after it (RFC 8838 §13).
    let candidates: Vec<&str> = seen
        .iter()
        .filter(|e| e["type"] == "candidate")
        .map(|e| e["candidate"].as_str().unwrap())
        .collect();
    let srflx = candidates
        .iter()
        .position(|c| c.contains("203.0.113.7 40000 typ srflx raddr 127.0.0.1"))
        .unwrap_or_else(|| panic!("a srflx candidate: {candidates:?}"));
    assert_eq!(candidates.last(), Some(&""), "{candidates:?}");
    assert!(srflx < candidates.len() - 1);
    assert_eq!(candidates.iter().filter(|c| c.is_empty()).count(), 1);
    // The browser trickles its own candidate through the client.
    result(
        call(
            &s,
            1,
            &json!({ "id": 3, "type": "webrtc/candidate", "session_id": "ha-1", "candidate": viewer_candidate }),
        )
        .await,
    );
    let session = result(
        call(
            &s,
            1,
            &json!({ "id": 4, "type": "session/get", "session_id": "ha-1" }),
        )
        .await,
    );
    assert_eq!(
        (
            &session["stream_id"],
            &session["answered"],
            &session["orphaned"]
        ),
        (&json!("front"), &json!(true), &json!(false))
    );
    let stream = result(
        call(
            &s,
            1,
            &json!({ "id": 5, "type": "stream/get", "stream_id": "front" }),
        )
        .await,
    );
    assert_eq!(
        (&stream["state"], &stream["sessions"]),
        (&json!("live"), &json!(["ha-1"]))
    );
    // `metrics/get` per process: the supervisor with its demux, and the
    // worker the supervisor started, once its counters show the session.
    let worker_pid = &stream["sources"][0]["connection"]["worker"]["pid"];
    let metrics = loop {
        let metrics = result(call(&s, 1, &json!({ "id": 5, "type": "metrics/get" })).await);
        if metrics["workers"]["c1"]["sessions"] == 1 {
            break metrics;
        }
        clock().sleep(Duration::from_millis(50)).await;
    };
    let supervisor = &metrics["supervisor"];
    assert_eq!(supervisor["pid"], std::process::id());
    assert!(supervisor["tasks"].as_u64().unwrap() > 0, "{metrics}");
    assert!(
        supervisor["demux"]["forwarded"].as_u64().unwrap() > 0,
        "{metrics}"
    );
    let worker = &metrics["workers"]["c1"];
    assert_eq!(&worker["pid"], worker_pid, "{metrics}");
    assert_eq!(worker["streams"], json!(["front"]));
    assert!(worker["tasks"].as_u64().unwrap() > 0, "{metrics}");
    assert_eq!(metrics["sessions"], 1);
    // The kernel's figures where there is a `/proc`, read by the
    // supervisor: its own, and the worker's through the descriptor it
    // handed over.
    for process in [supervisor, worker] {
        assert_eq!(
            process["pss_bytes"].as_u64().is_some_and(|pss| pss > 0),
            cfg!(target_os = "linux"),
            "{metrics}"
        );
        assert!(process["rss_bytes"].as_u64() >= process["pss_bytes"].as_u64());
    }
    assert_eq!(
        stream["sources"][0]["connection"]["worker"]["pss_bytes"]
            .as_u64()
            .is_some_and(|pss| pss > 0),
        cfg!(target_os = "linux")
    );

    // A malformed offer for the same stream, one payload type for two
    // codecs (RFC 9143 §9.1.1), which aborted the worker inside str0m: it
    // is refused with `invalid_sdp`, and the worker plays on to the viewer.
    let malformed = lotse_testing::viewer::with_audio_codecs(
        Viewer::new_with_audio(viewer_addr, clock().now())
            .expect("a viewer")
            .offer(),
        "a=rtpmap:109 opus/48000/2\n",
    );
    let mut refused = subscription(
        call(
            &s,
            1,
            &json!({ "id": 6, "type": "webrtc/offer", "stream_id": "front", "session_id": "ha-bad", "sdp": malformed }),
        )
        .await,
    );
    let mut refusal = None;
    while let Some(event) = refused.recv().await {
        refusal = Some(event.payload);
    }
    let refusal = refusal.expect("events for the refused offer");
    assert_eq!(
        (&refusal["type"], &refusal["code"]),
        (&json!("closed"), &json!("invalid_sdp")),
        "{refusal}"
    );
    assert!(
        refusal["message"]
            .as_str()
            .unwrap()
            .contains("payload type 109 is audio opus/48000/2"),
        "{refusal}"
    );
    let before = viewer.packets().len();
    drive(
        &mut viewer,
        &socket,
        &mut events,
        &mut seen,
        |_, _, _| {},
        |_, viewer| viewer.packets().len() >= before + 20,
    )
    .await;
    assert!(
        !seen.iter().any(|e| e["type"] == "closed"),
        "the first session lives on: {seen:?}"
    );

    // The control connection drops: the session is orphaned, media flows.
    s.connection_closed(ConnectionId(1));
    drop(events);
    let before = viewer.packets().len();
    let (_unused_tx, mut quiet) = mpsc::channel(1);
    drive(
        &mut viewer,
        &socket,
        &mut quiet,
        &mut Vec::new(),
        |_, _, _| {},
        |_, viewer| viewer.packets().len() >= before + 20,
    )
    .await;
    let session = result(
        call(
            &s,
            2,
            &json!({ "id": 1, "type": "session/get", "session_id": "ha-1" }),
        )
        .await,
    );
    assert_eq!(session["orphaned"], true);

    // A new connection adopts it: a state snapshot first, then live events.
    let mut adopted = subscription(
        call(
            &s,
            2,
            &json!({ "id": 2, "type": "session/adopt", "session_id": "ha-1" }),
        )
        .await,
    );
    let snapshot = adopted.recv().await.expect("the snapshot").payload;
    assert_eq!(snapshot["type"], "state");
    assert_eq!(snapshot["ice"], "connected", "{snapshot}");
    result(
        call(
            &s,
            2,
            &json!({ "id": 3, "type": "session/close", "session_id": "ha-1" }),
        )
        .await,
    );
    let mut closed = None;
    while let Some(event) = adopted.recv().await {
        closed = Some(event.payload);
    }
    assert_eq!(
        closed,
        Some(
            json!({ "type": "closed", "code": "session_closed", "message": "closed by session/close" })
        )
    );
    assert!(
        demux.registrations().is_empty(),
        "the demux forgot the session"
    );
    assert!(DemuxStats::get(&demux.stats().forwarded) > 0);
    let list = result(call(&s, 2, &json!({ "id": 4, "type": "session/list" })).await);
    assert_eq!(list["sessions"], json!([]));

    s.shutdown().await;
    stop_tcp.cancel();
    demux.stop();
    cam.stop().await;
}

/// The next `stream` event's state.
async fn next_state(events: &mut mpsc::Receiver<Event>) -> String {
    let event = events.recv().await.expect("an event").payload;
    assert_eq!(event["type"], "stream", "{event}");
    event["state"].as_str().unwrap().to_owned()
}

/// Opens session `session_id` on `front` for a new viewer and plays until
/// the viewer has a keyframe; returns how long that took from the offer.
async fn first_keyframe(s: &Supervisor, session_id: &str) -> Duration {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    let offered = clock().now();
    let mut events = subscription(
        call(
            s,
            1,
            &json!({ "id": 2, "type": "webrtc/offer", "stream_id": "front", "session_id": session_id,
                     "sdp": viewer.offer() }),
        )
        .await,
    );
    drive(
        &mut viewer,
        &socket,
        &mut events,
        &mut Vec::new(),
        |event, viewer, out| match event["type"].as_str() {
            Some("answer") => {
                viewer
                    .accept_answer(event["sdp"].as_str().unwrap(), out)
                    .expect("the answer applies");
            }
            Some("candidate") => {
                viewer.add_remote_candidate(event["candidate"].as_str().unwrap(), out);
            }
            _ => {}
        },
        |_, viewer| viewer.keyframe_starts() >= 1,
    )
    .await;
    clock().now().saturating_duration_since(offered)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preloaded_stream_serves_the_first_frame_from_its_gop_cache_and_lingers() {
    // One keyframe every 20 s: a viewer that gets one within seconds got
    // the cached one, not the camera's next.
    let cam = FakeCamera::start(
        CameraConfig {
            gop: 600,
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let linger = Duration::from_secs(1);
    let daemon = supervisor_with(linger);
    let s = &daemon.supervisor;
    let mut states = subscription(
        call(
            s,
            1,
            &json!({ "id": 1, "type": "stream/subscribe", "stream_id": "front" }),
        )
        .await,
    );
    let put = |preload: bool| {
        json!({ "id": 1, "type": "stream/put", "stream_id": "front",
                "sources": [{ "url": cam.url() }], "preload": preload })
    };
    let get = json!({ "id": 3, "type": "stream/get", "stream_id": "front" });
    // `preload` connects at put, with no viewer.
    assert_eq!(result(call(s, 1, &put(true)).await)["created"], true);
    for expected in ["idle", "connecting", "live"] {
        assert_eq!(next_state(&mut states).await, expected);
    }
    let front = result(call(s, 1, &get).await);
    assert_eq!(
        (&front["state"], &front["preload"]),
        (&json!("live"), &json!(true))
    );
    let pid = front["sources"][0]["connection"]["worker"]["pid"].clone();
    // Let the cached keyframe age past the catch-up window: what the
    // viewer gets is the keyframe still from the GOP cache.
    clock().sleep(Duration::from_secs(1)).await;
    let took = first_keyframe(s, "first").await;
    assert!(
        took < Duration::from_secs(5),
        "first keyframe after {took:?}"
    );
    assert_eq!(
        Stats::get(&cam.stats().connections),
        1,
        "no new camera connection"
    );

    // Preload off while a viewer watches: nothing changes.
    assert_eq!(result(call(s, 1, &put(false)).await)["created"], false);
    let front = result(call(s, 1, &get).await);
    assert_eq!(
        (&front["state"], &front["preload"]),
        (&json!("live"), &json!(false))
    );
    assert_eq!(front["sources"][0]["connection"]["worker"]["pid"], pid);
    assert!(states.try_recv().is_err(), "no state change");

    // The viewer leaves: the connection lingers, and a viewer within the
    // linger gets the warm connection and its cache.
    let close =
        |session_id: &str| json!({ "id": 4, "type": "session/close", "session_id": session_id });
    result(call(s, 1, &close("first")).await);
    assert_eq!(next_state(&mut states).await, "draining");
    let opened = clock().now();
    let mut second = Box::pin(first_keyframe(s, "second"));
    assert_eq!(
        tokio::select! {
            state = next_state(&mut states) => state,
            _ = &mut second => panic!("the session played while draining"),
        },
        "live"
    );
    assert!(
        clock().now().saturating_duration_since(opened) < linger,
        "the viewer came within the linger"
    );
    let took = second.await;
    assert!(
        took < Duration::from_secs(5),
        "first keyframe after {took:?}"
    );
    assert_eq!(
        Stats::get(&cam.stats().connections),
        1,
        "still one camera connection"
    );
    let front = result(call(s, 1, &get).await);
    assert_eq!(front["sources"][0]["connection"]["worker"]["pid"], pid);

    // Without preload the last viewer leaving ends it after the linger.
    result(call(s, 1, &close("second")).await);
    assert_eq!(next_state(&mut states).await, "draining");
    let drained = clock().now();
    assert_eq!(next_state(&mut states).await, "idle");
    assert!(clock().now().saturating_duration_since(drained) >= Duration::from_millis(950));
    let front = result(call(s, 1, &get).await);
    assert_eq!(front["sources"][0]["connection"]["worker"], Value::Null);
    assert_eq!(Stats::get(&cam.stats().connections), 1);

    s.shutdown().await;
    daemon.stop_tcp.cancel();
    daemon.demux.stop();
    cam.stop().await;
}

/// The browser side of ICE-TCP: one connection per daemon address the
/// viewer sends to, RFC 4571 frames both ways; frames read arrive on
/// `incoming` with the daemon address they came from.
struct TcpSide {
    writers: std::collections::HashMap<SocketAddr, tokio::net::tcp::OwnedWriteHalf>,
    incoming: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

impl TcpSide {
    async fn send(&mut self, out: &mut Vec<Outgoing>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        for datagram in out.drain(..) {
            assert!(datagram.tcp, "the viewer only has a tcp candidate");
            if !self.writers.contains_key(&datagram.destination) {
                let stream = tokio::net::TcpStream::connect(datagram.destination)
                    .await
                    .expect("connects to the passive candidate");
                let (mut read, write) = stream.into_split();
                let incoming = self.incoming.clone();
                let from = datagram.destination;
                lotse_core::task::spawn_named("test.tcp_read", async move {
                    while let Ok(len) = read.read_u16().await {
                        let mut frame = vec![0_u8; usize::from(len)];
                        if read.read_exact(&mut frame).await.is_err()
                            || incoming.send((from, frame)).await.is_err()
                        {
                            return;
                        }
                    }
                });
                self.writers.insert(datagram.destination, write);
            }
            let writer = self.writers.get_mut(&datagram.destination).unwrap();
            let len = u16::try_from(datagram.payload.len()).unwrap();
            let mut frame = len.to_be_bytes().to_vec();
            frame.extend_from_slice(&datagram.payload);
            writer.write_all(&frame).await.expect("frame written");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_behind_a_udp_block_plays_over_ice_tcp() {
    let cam = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .expect("camera");
    let daemon = supervisor();
    let s = &daemon.supervisor;
    result(
        call(
            s,
            1,
            &json!({ "id": 1, "type": "stream/put", "stream_id": "front", "sources": [{ "url": cam.url() }] }),
        )
        .await,
    );
    // Port 9 as browsers announce it (RFC 6544 §4.5); the connection comes
    // from an ephemeral port, which the daemon learns as peer-reflexive.
    lotse_webrtc::install_crypto_provider();
    let mut viewer =
        Viewer::new_tcp("127.0.0.1:9".parse().unwrap(), clock().now()).expect("a viewer");
    let mut events = subscription(
        call(
            s,
            1,
            &json!({ "id": 2, "type": "webrtc/offer", "stream_id": "front", "session_id": "tcp-1", "sdp": viewer.offer() }),
        )
        .await,
    );
    let (incoming_tx, mut incoming) = mpsc::channel(256);
    let mut side = TcpSide {
        writers: std::collections::HashMap::new(),
        incoming: incoming_tx,
    };
    let mut out = Vec::new();
    let mut seen = Vec::new();
    let mut deadline = clock().sleep(Duration::from_secs(20));
    while !(viewer.is_connected() && viewer.packets().len() >= 20) {
        let next_timeout = viewer
            .next_timeout()
            .map_or(Duration::from_millis(20), |at| {
                at.saturating_duration_since(clock().now())
            });
        tokio::select! {
            event = events.recv() => {
                let event = event.expect("the subscription is open").payload;
                match event["type"].as_str() {
                    Some("answer") => viewer.accept_answer(event["sdp"].as_str().unwrap(), &mut out).expect("the answer applies"),
                    Some("candidate") => viewer.add_remote_candidate(event["candidate"].as_str().unwrap(), &mut out),
                    _ => {}
                }
                seen.push(event);
            }
            Some((from, frame)) = incoming.recv() => viewer.receive(clock().now(), from, &frame, &mut out),
            () = clock().sleep(next_timeout) => viewer.timeout(clock().now(), &mut out),
            () = &mut deadline => panic!("timed out; {} packets, events {seen:?}", viewer.packets().len()),
        }
        side.send(&mut out).await;
    }
    let tcp = seen
        .iter()
        .filter(|e| e["type"] == "candidate")
        .find_map(|e| {
            e["candidate"]
                .as_str()
                .filter(|c| c.contains("tcptype passive"))
        })
        .unwrap_or_else(|| panic!("a passive tcp candidate: {seen:?}"));
    assert!(
        tcp.contains(&format!("127.0.0.1 {} typ host", daemon.tcp.port())),
        "{tcp}"
    );
    assert_eq!(
        IceTcpStats::get(&daemon.tcp_stats.handed_off),
        1,
        "the acceptor verified the first request and handed the connection over"
    );
    assert!(viewer.keyframe_starts() >= 1);
    result(
        call(
            s,
            1,
            &json!({ "id": 3, "type": "session/close", "session_id": "tcp-1" }),
        )
        .await,
    );
    let mut closed = None;
    while let Some(event) = events.recv().await {
        closed = Some(event.payload);
    }
    assert_eq!(closed.unwrap()["code"], "session_closed");
    s.shutdown().await;
    daemon.stop_tcp.cancel();
    daemon.demux.stop();
    cam.stop().await;
}

/// The candidate events' lines, end-of-candidates included.
fn candidate_lines(seen: &[Value]) -> Vec<&str> {
    seen.iter()
        .filter(|e| e["type"] == "candidate")
        .map(|e| e["candidate"].as_str().unwrap())
        .collect()
}

/// The address a `typ relay` candidate line names.
fn relay_address(line: &str) -> Option<SocketAddr> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    (fields.get(6..8) == Some(&["typ", "relay"][..]))
        .then(|| format!("{}:{}", fields[4], fields[5]).parse().ok())
        .flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_reachable_only_through_a_turn_relay_plays_through_it() {
    relayed_viewer(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8656_12_5_a_viewer_reachable_only_through_a_turn_relay_over_tcp_plays_through_it() {
    relayed_viewer(true).await;
}

/// A viewer the daemon reaches only through the fake TURN server's
/// loopback relay, allocated over TCP when `tcp` (RFC 8656 §3.1).
async fn relayed_viewer(tcp: bool) {
    let cam = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .expect("camera");
    let turn = Arc::new(FakeTurn::new(
        clock(),
        "lotse.test",
        Duration::from_secs(600),
    ));
    turn.add_user("ha-cloud", "secret");
    let server = FakeTurnServer::start_relaying(Arc::clone(&turn), 1)
        .await
        .expect("the turn server");
    let daemon = supervisor();
    let s = &daemon.supervisor;
    put_front(s, &cam).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    let viewer_addr = socket.local_addr().unwrap();
    // A hosted TURN service's shape: a `turn:` URL with the entry's credential.
    let url = if tcp {
        format!("turn:{}?transport=tcp", server.tcp_addr())
    } else {
        format!("turn:{}", server.udp_addr())
    };
    let relayed = play_relayed(
        &daemon,
        &socket,
        json!([{ "urls": [url], "username": "ha-cloud", "credential": "secret" }]),
        &host_candidate(viewer_addr),
        |viewer| viewer.packets().len() >= 20,
    )
    .await;
    let allocations = turn.allocations();
    assert_eq!(allocations.len(), 1, "{allocations:?}");
    assert_eq!(allocations[0].username, "ha-cloud");
    assert_eq!(allocations[0].tcp, tcp);
    assert_eq!(allocations[0].relayed, relayed.relays[0]);
    assert!(
        allocations[0]
            .channels
            .iter()
            .any(|(_, peer)| *peer == viewer_addr),
        "a channel to the browser's candidate: {allocations:?}"
    );
    close_relayed(s, relayed.events).await;
    // The last session's lease went with it: the allocation is deleted.
    let mut waited = clock().sleep(Duration::from_secs(5));
    while !turn.allocations().is_empty() {
        tokio::select! {
            () = clock().sleep(Duration::from_millis(20)) => {}
            () = &mut waited => panic!("the allocation outlived its last session"),
        }
    }
    stop(daemon, cam).await;
}

/// Puts the stream `front` on `cam`.
async fn put_front(s: &Supervisor, cam: &FakeCamera) {
    result(
        call(
            s,
            1,
            &json!({ "id": 1, "type": "stream/put", "stream_id": "front", "sources": [{ "url": cam.url() }] }),
        )
        .await,
    );
}

/// Shuts the daemon down and stops the camera.
async fn stop(daemon: Daemon, cam: FakeCamera) {
    daemon.supervisor.shutdown().await;
    daemon.stop_tcp.cancel();
    daemon.demux.stop();
    cam.stop().await;
}

/// The browser's host candidate line for `addr`.
fn host_candidate(addr: SocketAddr) -> String {
    format!(
        "candidate:1 1 udp 2130706431 {} {} typ host",
        addr.ip(),
        addr.port()
    )
}

/// What [`play_relayed`] leaves for the test to check.
struct Relayed {
    /// The session's events, still subscribed.
    events: mpsc::Receiver<Event>,
    /// The relayed addresses the daemon's candidates named, in order.
    relays: Vec<SocketAddr>,
}

/// Offers the stream `front` as session `relay-1` to a viewer on `socket`
/// with `ice_servers`, trickles `candidate` (the browser's, through the client)
/// after the answer, and runs the viewer's side behind a network that
/// passes only the relayed addresses until the viewer is connected and
/// `done` holds. Checks that a relay candidate came before
/// end-of-candidates, that the daemon tried a pair the network dropped,
/// and that the media came through the relay.
async fn play_relayed(
    daemon: &Daemon,
    socket: &UdpSocket,
    ice_servers: Value,
    candidate: &str,
    mut done: impl FnMut(&Viewer) -> bool,
) -> Relayed {
    let s = &daemon.supervisor;
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    let mut events = subscription(
        call(
            s,
            1,
            &json!({ "id": 2, "type": "webrtc/offer", "stream_id": "front", "session_id": "relay-1",
                     "sdp": viewer.offer(), "ice_servers": ice_servers }),
        )
        .await,
    );
    // The network between the two: only the relayed address passes, so
    // the host pairs fail as behind a symmetric NAT on each side.
    let mut relays: Vec<SocketAddr> = Vec::new();
    let mut out = Vec::new();
    let mut seen: Vec<Value> = Vec::new();
    let mut buf = vec![0_u8; 2_000];
    let mut dropped = 0_usize;
    let mut trickled = false;
    let mut deadline = clock().sleep(Duration::from_secs(60));
    while !(viewer.is_connected() && done(&viewer)) {
        let next_timeout = viewer
            .next_timeout()
            .map_or(Duration::from_millis(20), |at| {
                at.saturating_duration_since(clock().now())
            });
        tokio::select! {
            event = events.recv() => {
                let event = event.expect("the subscription is open").payload;
                match event["type"].as_str() {
                    Some("answer") => viewer.accept_answer(event["sdp"].as_str().unwrap(), &mut out).expect("the answer applies"),
                    Some("candidate") => {
                        let line = event["candidate"].as_str().unwrap();
                        relays.extend(relay_address(line));
                        viewer.add_remote_candidate(line, &mut out);
                    }
                    _ => {}
                }
                seen.push(event);
            }
            received = socket.recv_from(&mut buf) => {
                let (len, source) = received.expect("viewer recv");
                if relays.contains(&source) {
                    viewer.receive(clock().now(), source, &buf[..len], &mut out);
                } else {
                    dropped += 1;
                }
            }
            () = clock().sleep(next_timeout) => viewer.timeout(clock().now(), &mut out),
            () = &mut deadline => panic!("timed out; {} packets, events {seen:?}", viewer.packets().len()),
        }
        if !trickled && seen.iter().any(|e| e["type"] == "answer") {
            // The browser's candidate, through the client: the daemon checks it
            // from the relay, which binds a channel to it.
            trickled = true;
            result(
                call(
                    s,
                    1,
                    &json!({ "id": 3, "type": "webrtc/candidate", "session_id": "relay-1",
                             "candidate": candidate }),
                )
                .await,
            );
        }
        for datagram in out.drain(..) {
            if relays.contains(&datagram.destination) {
                socket
                    .send_to(&datagram.payload, datagram.destination)
                    .await
                    .expect("viewer send");
            }
        }
    }
    let candidates = candidate_lines(&seen);
    let relay = candidates
        .iter()
        .position(|c| relay_address(c).is_some())
        .unwrap_or_else(|| panic!("a relay candidate: {candidates:?}"));
    assert!(
        relay < candidates.len() - 1 && candidates.last() == Some(&""),
        "end-of-candidates after the relay candidate (RFC 8838 §13): {candidates:?}"
    );
    assert!(
        dropped > 0,
        "the daemon tried the host pair too, which this network drops"
    );
    assert!(DemuxStats::get(&daemon.demux.stats().relayed) > 0);
    assert!(viewer.keyframe_starts() >= 1);
    Relayed { events, relays }
}

/// Closes session `relay-1` and checks that its events end with
/// `session_closed`.
async fn close_relayed(s: &Supervisor, mut events: mpsc::Receiver<Event>) {
    result(
        call(
            s,
            1,
            &json!({ "id": 4, "type": "session/close", "session_id": "relay-1" }),
        )
        .await,
    );
    let mut closed = None;
    while let Some(event) = events.recv().await {
        closed = Some(event.payload);
    }
    assert_eq!(closed.unwrap()["code"], "session_closed");
}

// Against a real coturn: `mise run turn-e2e` starts it in Docker
// (`scripts/turn-e2e.sh`), sets the variables below and runs these alone
// and one at a time, since they count the server's allocations.

/// The long-term user `scripts/turn-e2e.sh` gives the coturn without
/// REST credentials (RFC 8489 §9.2).
const COTURN_USER: (&str, &str) = ("lotse", "lotse-static");

/// The coturn variable `name` that `scripts/turn-e2e.sh` sets.
#[expect(
    clippy::disallowed_methods,
    reason = "the test reads where the script started coturn"
)]
fn coturn_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} unset: run `mise run turn-e2e`"))
}

/// The coturn variable `name` as an address.
fn coturn_addr(name: &str) -> SocketAddr {
    coturn_env(name).parse().expect("an address")
}

/// The server-reflexive address of `socket` as the STUN server at
/// `server` sees it (RFC 8489 §6.1), which a browser would trickle: with
/// coturn on the host's network, the viewer's own address.
async fn reflexive(socket: &UdpSocket, server: SocketAddr) -> SocketAddr {
    let transaction_id = *b"lotse-e2e-01";
    let mut buf = vec![0_u8; 1_500];
    for _ in 0..5 {
        socket
            .send_to(&stun::binding_request(transaction_id), server)
            .await
            .expect("binding request");
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, _) = received.expect("viewer recv");
                let response = stun::parse(&buf[..len]).expect("a STUN response");
                assert_eq!(response.transaction_id, transaction_id);
                return response.xor_mapped_address().expect("XOR-MAPPED-ADDRESS");
            }
            () = clock().sleep(Duration::from_secs(1)) => {}
        }
    }
    panic!("no binding response from {server}");
}

/// The browser's candidate line for its server-reflexive address
/// `mapped`, a host one when no NAT is in between (RFC 8445 §5.1.1).
fn browser_candidate(local: SocketAddr, mapped: SocketAddr) -> String {
    if mapped == local {
        host_candidate(local)
    } else {
        format!(
            "candidate:2 1 udp 1694498815 {} {} typ srflx raddr {} rport {}",
            mapped.ip(),
            mapped.port(),
            local.ip(),
            local.port()
        )
    }
}

/// The allocations coturn's Prometheus endpoint at `metrics` counts,
/// over every client transport (`turn_total_allocations`).
async fn coturn_allocations(metrics: SocketAddr) -> u64 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::net::TcpStream::connect(metrics)
        .await
        .expect("the metrics endpoint");
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: coturn\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).await.unwrap();
    body.lines()
        .filter(|line| line.starts_with("turn_total_allocations"))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// A viewer the daemon reaches only through the coturn whose listener is
/// at `stun` and metrics at `metrics`, with `ice_servers`; it plays for
/// `past` and keeps playing after it, and the allocation is gone once
/// the session closes.
async fn coturn_viewer(ice_servers: Value, stun: SocketAddr, metrics: SocketAddr, past: Duration) {
    assert_eq!(coturn_allocations(metrics).await, 0, "a fresh server");
    let cam = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .expect("camera");
    let daemon = supervisor();
    let s = &daemon.supervisor;
    put_front(s, &cam).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    let local = socket.local_addr().unwrap();
    let mapped = reflexive(&socket, stun).await;
    let start = clock().now();
    let mut counted: Option<usize> = None;
    let relayed = play_relayed(
        &daemon,
        &socket,
        ice_servers,
        &browser_candidate(local, mapped),
        |viewer| {
            let packets = viewer.packets().len();
            if counted.is_none() && clock().now().saturating_duration_since(start) >= past {
                counted = Some(packets);
            }
            counted.is_some_and(|at| packets >= at + 20)
        },
    )
    .await;
    assert_eq!(relayed.relays.len(), 1, "{:?}", relayed.relays);
    assert_eq!(coturn_allocations(metrics).await, 1);
    close_relayed(s, relayed.events).await;
    let mut waited = clock().sleep(Duration::from_secs(5));
    while coturn_allocations(metrics).await > 0 {
        tokio::select! {
            () = clock().sleep(Duration::from_millis(50)) => {}
            () = &mut waited => panic!("the allocation outlived its last session"),
        }
    }
    stop(daemon, cam).await;
}

/// A `turn:` entry over UDP with a long-term user; the server caps the
/// lifetime at 20 s and lets nonces go stale after 8 s, so the viewer
/// playing past 25 s means the allocation was refreshed, each time after
/// a 438 (RFC 8656 §7.2, §8; RFC 8489 §9.2.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs coturn in Docker: mise run turn-e2e"]
async fn coturn_rfc8656_7_a_viewer_plays_through_a_udp_allocation_past_its_lifetime() {
    let server = coturn_addr("LOTSE_COTURN_STATIC");
    coturn_viewer(
        json!([{ "urls": [format!("turn:{server}")],
                 "username": COTURN_USER.0, "credential": COTURN_USER.1 }]),
        server,
        coturn_addr("LOTSE_COTURN_STATIC_METRICS"),
        Duration::from_secs(25),
    )
    .await;
}

/// A hosted TURN service's shape: a `turn:` entry over TCP with a time-limited REST
/// credential (draft-uberti-behave-turn-rest-00 §2.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs coturn in Docker: mise run turn-e2e"]
async fn coturn_rfc8656_5_a_viewer_plays_through_a_tcp_allocation_with_a_rest_credential() {
    let server = coturn_addr("LOTSE_COTURN_REST");
    coturn_viewer(
        json!([{ "urls": [format!("turn:{server}?transport=tcp")],
                 "username": coturn_env("LOTSE_COTURN_REST_USERNAME"),
                 "credential": coturn_env("LOTSE_COTURN_REST_CREDENTIAL") }]),
        server,
        coturn_addr("LOTSE_COTURN_REST_METRICS"),
        Duration::ZERO,
    )
    .await;
}

/// A hosted TURN service's list shape, the same server over UDP and TCP with a REST
/// credential: one allocation, over UDP (RFC 8656 §7.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs coturn in Docker: mise run turn-e2e"]
async fn coturn_rfc8656_7_1_a_server_listed_over_udp_and_tcp_gets_one_allocation() {
    let server = coturn_addr("LOTSE_COTURN_REST");
    coturn_viewer(
        json!([{ "urls": [format!("turn:{server}"), format!("turn:{server}?transport=tcp")],
                 "username": coturn_env("LOTSE_COTURN_REST_USERNAME"),
                 "credential": coturn_env("LOTSE_COTURN_REST_CREDENTIAL") }]),
        server,
        coturn_addr("LOTSE_COTURN_REST_METRICS"),
        Duration::ZERO,
    )
    .await;
}

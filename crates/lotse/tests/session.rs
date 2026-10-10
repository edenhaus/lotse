//! One viewer, end to end without the control API: the fake camera, a real
//! `lotse worker` subprocess with the RTSP source and the WebRTC output,
//! the supervisor's UDP demux in front of it, and the headless viewer on a
//! second UDP socket.
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
    clippy::cast_possible_truncation,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lotse_core::clock::{Clock, SystemClock};
use lotse_core::connection::WorkerReport;
use lotse_supervisor::net::demux::{Demux, DemuxStats, WorkerSink};
use lotse_supervisor::net::udp::bind_udp;
use lotse_supervisor::worker::{
    SessionEvent, SessionSpec, SourceSpec, Worker, WorkerConfig, WorkerEvent, WorkerManager,
};
use lotse_testing::fake_camera::{CameraAudio, CameraUdp, CameraVideo, Stats};
use lotse_testing::latency::{Latencies, stamp_in_payload};
use lotse_testing::libwebrtc::H265Receiver;
use lotse_testing::viewer::{Direction, Outgoing, Viewer, capture_seconds, with_video_codecs};
use lotse_testing::{CameraConfig, FakeCamera};
use tokio::net::UdpSocket;

const UFRAG: &str = "lotseufrag";
const PASS: &str = "lotsepassword0123456789ab";

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

fn spec(id: &str, offer: &str, local: SocketAddr) -> SessionSpec {
    SessionSpec {
        session_id: id.into(),
        kind: "webrtc".into(),
        offer: offer.into(),
        ice_ufrag: UFRAG.into(),
        ice_pass: PASS.into(),
        candidates: vec![local],
        tcp_candidates: vec![],
        audio: false,
        orientation: 1,
    }
}

/// The shared socket, its demux and a worker holding a duplicate.
struct FrontDoor {
    local: SocketAddr,
    demux: Demux,
    worker: Worker,
}

fn front_door() -> FrontDoor {
    front_door_with("off", &[])
}

/// [`front_door`] with a worker in `sandbox` mode, allowed TCP to `ports`.
/// A sandboxed worker gets its loopback relay, as the supervisor gives an
/// `rtsp` source one: Landlock lets it bind no other port.
fn front_door_with(sandbox: &str, ports: &[u16]) -> FrontDoor {
    let bound = bind_udp("127.0.0.1:0".parse().unwrap()).expect("the shared socket");
    let demux = Demux::start(
        Arc::clone(&bound.socket),
        bound.local,
        bound.hosts,
        Arc::new(SystemClock),
    )
    .expect("the demux");
    let manager = WorkerManager::new(
        WorkerConfig {
            binary: PathBuf::from(env!("CARGO_BIN_EXE_lotse")),
            log_format: "json".into(),
            log_level: "debug".into(),
            sandbox: sandbox.into(),
            // The daemon's default (`limits.worker_threads`): with one thread
            // the camera's ingest and the session's egress share it, and on
            // GitHub's runners the session fell behind a 2.5 MB keyframe
            // by more than `max_packet_age` and skipped it (2026-10-09).
            worker_threads: 2,
            worker_address_space: 1 << 30,
            max_sessions: 256,
        },
        Some(bound.socket),
    );
    let worker = manager.spawn(ports, sandbox != "off").expect("spawns");
    FrontDoor {
        local: bound.local,
        demux,
        worker,
    }
}

async fn send_all(socket: &UdpSocket, out: &mut Vec<Outgoing>) {
    for datagram in out.drain(..) {
        socket
            .send_to(&datagram.payload, datagram.destination)
            .await
            .expect("viewer send");
    }
}

/// The next `closed` event: the session id and the code.
async fn closed(worker: &mut Worker) -> (String, String) {
    loop {
        match worker.next_event().await {
            WorkerEvent::Session {
                session_id,
                event: SessionEvent::Closed { code, .. },
            } => return (session_id, code),
            WorkerEvent::Exited(status) => panic!("worker exited: {status:?}"),
            _ => {}
        }
    }
}

/// Runs the source until it is live, granting its attempt as the
/// supervisor would.
async fn run_camera(door: &mut FrontDoor, cam: &FakeCamera) {
    run_camera_with(door, cam, "null").await;
}

/// [`run_camera`] with the source's `options` (JSON).
async fn run_camera_with(door: &mut FrontDoor, cam: &FakeCamera, options: &str) {
    door.worker
        .run_source(&SourceSpec {
            connection_id: "c1".into(),
            url: cam.url(),
            options: options.into(),
            peer_host: "127.0.0.1".into(),
            peer_addrs: vec![cam.addr()],
        })
        .await
        .expect("run source");
    loop {
        match door.worker.next_event().await {
            WorkerEvent::Report(WorkerReport::Live) => break,
            WorkerEvent::Report(WorkerReport::Connecting) => {
                door.worker.grant_connect().await.expect("grant");
            }
            WorkerEvent::Exited(status) => panic!("worker exited: {status:?}"),
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_gets_h264_from_the_fake_camera_through_a_worker() {
    viewer_gets_h264("off").await;
}

/// Regression for SBX-4 and WRK-8: the same session through a worker under
/// its sandbox, whose seccomp filter keeps it to sending on the shared
/// socket at its fixed number and to passing descriptors on its control
/// channel only. The session plays and the worker exits cleanly, so
/// nothing a worker does on its media path or on the way out is denied.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sandboxed_worker_plays_a_session_on_the_shared_socket() {
    viewer_gets_h264("on").await;
}

/// One viewer's H.264 session through a worker in `sandbox` mode: the
/// answer, the candidates, the packets, an orientation change, the close
/// and a clean exit.
#[expect(
    clippy::cognitive_complexity,
    reason = "one session's whole life in order, as the test it was written as"
)]
async fn viewer_gets_h264(sandbox: &str) {
    let cam = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .expect("camera");
    let mut door = front_door_with(sandbox, &[cam.addr().port()]);
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    let viewer_addr = socket.local_addr().unwrap();
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(viewer_addr, clock().now()).expect("a viewer");
    let mut out = Vec::new();
    // Turned left (6): the viewer offers CVO, as Chrome does.
    let mut session = spec("s1", viewer.offer(), door.local);
    session.orientation = 6;
    door.worker
        .open_session(&session)
        .await
        .expect("open session");

    let mut events = Vec::new();
    let mut answered = false;
    let mut closed = None;
    // The packets the viewer had when the stream turned right (8).
    let mut turned_at = None;
    let mut buf = vec![0_u8; 2_000];
    let mut deadline = clock().sleep(Duration::from_secs(20));
    while closed.is_none() {
        if answered && viewer.packets().len() >= 40 && viewer.keyframe_starts() >= 1 {
            match turned_at {
                None => {
                    door.worker
                        .session_orientation("s1", 8)
                        .await
                        .expect("turn");
                    turned_at = Some(viewer.packets().len());
                }
                Some(at) if viewer.packets().len() >= at + 40 => {
                    door.worker
                        .close_session("s1", "session_closed", "enough")
                        .await
                        .expect("close");
                    // Wait for the closed event only from here.
                    answered = false;
                }
                Some(_) => {}
            }
        }
        let next_timeout = viewer
            .next_timeout()
            .map_or(Duration::from_millis(20), |at| {
                at.saturating_duration_since(clock().now())
            });
        tokio::select! {
            event = door.worker.next_event() => match event {
                WorkerEvent::Session { session_id, event } => {
                    assert_eq!(session_id, "s1");
                    match &event {
                        SessionEvent::Answer { sdp, .. } => {
                            assert!(sdp.contains("a=ice-ufrag:lotseufrag"), "{sdp}");
                            viewer.accept_answer(sdp, &mut out).expect("answer applies");
                            send_all(&socket, &mut out).await;
                            // Trickle the viewer's own candidate too, as a client would.
                            door.worker
                                .candidate("s1", &format!("candidate:1 1 udp 2130706431 {} {} typ host", viewer_addr.ip(), viewer_addr.port()))
                                .await
                                .expect("candidate");
                            answered = true;
                        }
                        SessionEvent::Closed { code, .. } => closed = Some(code.clone()),
                        _ => {}
                    }
                    events.push(event);
                }
                WorkerEvent::Exited(status) => panic!("worker exited: {status:?}"),
                _ => {}
            },
            received = socket.recv_from(&mut buf) => {
                let (len, source) = received.expect("viewer recv");
                viewer.receive(clock().now(), source, &buf[..len], &mut out);
                send_all(&socket, &mut out).await;
            }
            () = clock().sleep(next_timeout) => {
                viewer.timeout(clock().now(), &mut out);
                send_all(&socket, &mut out).await;
            }
            () = &mut deadline => panic!("no closed event in time; {} packets, events {events:?}", viewer.packets().len()),
        }
    }
    assert_eq!(closed.as_deref(), Some("session_closed"), "{events:?}");
    assert!(viewer.is_connected(), "{events:?}");
    assert!(
        events.iter().any(|e| matches!(e, SessionEvent::Candidate { candidate, .. } if candidate.contains("typ host"))),
        "{events:?}"
    );
    assert!(events.contains(&SessionEvent::Candidate {
        candidate: String::new(),
        mid: None
    }));
    assert!(
        events.iter().any(|e| matches!(e, SessionEvent::State { ice, dtls } if ice == "connected" && dtls == "connected")),
        "{events:?}"
    );
    let packets = viewer.packets();
    assert!(packets.len() >= 40);
    assert!(viewer.keyframe_starts() >= 1);
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(*packet.seq_no, i as u64, "renumbered from zero");
    }
    assert!(packets.iter().any(|p| p.header.marker));
    // TS 26.114 §7.4.5: each frame's last packet says the receiver turns it
    // 90° counterclockwise (R = 11, str0m's `Deg90`), and once the stream
    // turned right 90° clockwise (R = 01, `Deg270`), in the one session;
    // the others carry none.
    let marked: Vec<String> = packets
        .iter()
        .filter(|p| p.header.marker)
        .map(|p| format!("{:?}", p.header.ext_vals.video_orientation))
        .collect();
    let turn = marked
        .iter()
        .position(|value| value == "Some(Deg270)")
        .expect("turned");
    assert!(
        turn > 0
            && marked[..turn].iter().all(|value| value == "Some(Deg90)")
            && marked[turn..].iter().all(|value| value == "Some(Deg270)"),
        "{marked:?}"
    );
    assert!(
        packets.iter().filter(|p| !p.header.marker).all(|p| p
            .header
            .ext_vals
            .video_orientation
            .is_none())
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, SessionEvent::Answer { .. }))
            .count(),
        1
    );
    let first = packets[0].header.timestamp;
    let last = packets[packets.len() - 1].header.timestamp;
    assert!(last.wrapping_sub(first) > 0 && last.wrapping_sub(first) < 90_000 * 30);
    let demux_stats = door.demux.stats();
    assert!(
        DemuxStats::get(&demux_stats.forwarded) > 0,
        "the demux forwarded the viewer's uplink"
    );
    assert_eq!(
        events.last(),
        closed
            .map(|code| SessionEvent::Closed {
                code,
                message: "enough".into()
            })
            .as_ref()
    );

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_are_refused_with_a_code_when_they_cannot_start() {
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    lotse_webrtc::install_crypto_provider();
    let viewer = Viewer::new("127.0.0.1:40000".parse().unwrap(), clock().now()).expect("a viewer");
    // No source yet.
    door.worker
        .open_session(&spec("early", viewer.offer(), door.local))
        .await
        .expect("open");
    assert_eq!(
        closed(&mut door.worker).await,
        ("early".to_owned(), "source_not_live".to_owned())
    );
    let cam = FakeCamera::start(CameraConfig::default(), clock())
        .await
        .expect("camera");
    run_camera(&mut door, &cam).await;
    // An offer without video.
    let no_video = viewer.offer().replace("m=video", "m=audio");
    door.worker
        .open_session(&spec("audio", &no_video, door.local))
        .await
        .expect("open");
    assert_eq!(
        closed(&mut door.worker).await,
        ("audio".to_owned(), "no_video_track".to_owned())
    );
    // An unknown output kind, and a second session under an id in use.
    let mut unknown = spec("nope", viewer.offer(), door.local);
    unknown.kind = "hls".into();
    door.worker.open_session(&unknown).await.expect("open");
    assert_eq!(
        closed(&mut door.worker).await,
        ("nope".to_owned(), "internal_error".to_owned())
    );
    door.worker
        .open_session(&spec("dup", viewer.offer(), door.local))
        .await
        .expect("open");
    door.worker
        .open_session(&spec("dup", viewer.offer(), door.local))
        .await
        .expect("open");
    assert_eq!(
        closed(&mut door.worker).await,
        ("dup".to_owned(), "internal_error".to_owned())
    );
    // Candidates and closes for unknown sessions are ignored; the live
    // one is closed by the shutdown.
    door.worker
        .candidate("ghost", "candidate:1 1 udp 1 127.0.0.1 1 typ host")
        .await
        .expect("candidate");
    door.worker
        .close_session("ghost", "session_closed", "")
        .await
        .expect("close");
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

/// Drives the worker and the viewer until `done` holds: answers the offer
/// on the way and records the session's events and the worker's reports.
async fn drive(
    door: &mut FrontDoor,
    socket: &UdpSocket,
    viewer: &mut Viewer,
    events: &mut Vec<SessionEvent>,
    reports: &mut Vec<WorkerReport>,
    mut done: impl FnMut(&Viewer, &[WorkerReport]) -> bool,
) {
    let viewer_addr = socket.local_addr().unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0_u8; 2_000];
    let mut deadline = clock().sleep(Duration::from_secs(20));
    while !done(viewer, reports) {
        let next_timeout = viewer
            .next_timeout()
            .map_or(Duration::from_millis(20), |at| {
                at.saturating_duration_since(clock().now())
            });
        tokio::select! {
            event = door.worker.next_event() => match event {
                WorkerEvent::Session { event, .. } => {
                    if let SessionEvent::Answer { sdp, .. } = &event {
                        viewer.accept_answer(sdp, &mut out).expect("answer applies");
                        send_all(socket, &mut out).await;
                        door.worker
                            .candidate("s1", &format!("candidate:1 1 udp 2130706431 {} {} typ host", viewer_addr.ip(), viewer_addr.port()))
                            .await
                            .expect("candidate");
                    }
                    events.push(event);
                }
                WorkerEvent::Report(report) => {
                    // Every attempt gets the grant the supervisor would send.
                    if matches!(report, WorkerReport::Connecting | WorkerReport::Reconnecting(_)) {
                        door.worker.grant_connect().await.expect("grant");
                    }
                    reports.push(report);
                }
                WorkerEvent::Exited(status) => panic!("worker exited: {status:?}"),
                _ => {}
            },
            received = socket.recv_from(&mut buf) => {
                let (len, source) = received.expect("viewer recv");
                viewer.receive(clock().now(), source, &buf[..len], &mut out);
                send_all(socket, &mut out).await;
            }
            () = clock().sleep(next_timeout) => {
                viewer.timeout(clock().now(), &mut out);
                send_all(socket, &mut out).await;
            }
            () = &mut deadline => panic!("not reached in time; {} packets, events {events:?}, reports {reports:?}", viewer.packets().len()),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_survives_a_camera_reconnect_and_its_clock_continues() {
    // Every connection hangs up after about 3 s, and the camera restarts
    // its RTP clock on the next, as a rebooted camera does.
    let cam = FakeCamera::start(
        CameraConfig {
            packets_before_close: Some(120),
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");

    let (mut events, mut reports) = (Vec::new(), Vec::new());
    // Playing on the first connection.
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| v.packets().len() >= 20,
    )
    .await;
    // The hang-up, and the worker back live on a new connection.
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |_, r| {
            r.iter()
                .skip_while(|r| !matches!(r, WorkerReport::Reconnecting(_)))
                .any(|r| *r == WorkerReport::Live)
        },
    )
    .await;
    let at_reconnect = viewer.packets().len();
    let keyframes = viewer.keyframe_starts();
    // Media resumes on the same session, from a keyframe.
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| v.packets().len() >= at_reconnect + 20 && v.keyframe_starts() > keyframes,
    )
    .await;

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SessionEvent::Closed { .. })),
        "the session stays open: {events:?}"
    );
    let packets = viewer.packets();
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(
            *packet.seq_no, i as u64,
            "one sequence space across the reconnect"
        );
    }
    // The session's clock only moves forward, by no more than the gap,
    // though the camera's went back to its first timestamp.
    for pair in packets.windows(2) {
        let step = pair[1]
            .header
            .timestamp
            .wrapping_sub(pair[0].header.timestamp);
        assert!(
            step < 90_000 * 2,
            "the session clock jumped by {step} ticks"
        );
    }

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

/// Frames the latency gate measures: two seconds at 30 fps.
const LATENCY_FRAMES: usize = 60;

/// How far apart the camera sends the packets of one frame in the latency
/// gate: a frame of four packets takes 15 ms to arrive in full.
const PACKET_SPACING: Duration = Duration::from_millis(5);

/// The gate's bounds on the first packet's latency, median and p99. A debug
/// build on a shared CI runner, loopback on both legs: loose enough to
/// hold there, tight enough to catch buffering, a stalled pacer or a wait
/// for a whole frame (about 1.3 ms and 8 ms measured on 2026-09-30). The
/// release budget of 1 ms p99 is the lab's to measure.
const FIRST_PACKET_P50: Duration = Duration::from_millis(5);

/// See [`FIRST_PACKET_P50`].
const FIRST_PACKET_P99: Duration = Duration::from_millis(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_adds_little_latency_and_never_waits_for_a_whole_frame() {
    // Every frame stamped with its send time and spread over 15 ms: the
    // daemon's share is what the viewer sees minus the stamp, and a daemon
    // that waited for frames to complete would add the spread to the
    // first packet.
    let origin = clock().now();
    let cam = FakeCamera::start(
        CameraConfig {
            stamp_origin: Some(origin),
            packet_spacing: PACKET_SPACING,
            p_bytes: 3_000,
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| Latencies::of_viewer(v.packets(), origin).whole_frame.len() >= LATENCY_FRAMES,
    )
    .await;

    let latencies = Latencies::of_viewer(viewer.packets(), origin);
    let p = |values: &[Duration], q| Latencies::percentile(values, q).unwrap();
    let (first, whole) = (&latencies.first_packet, &latencies.whole_frame);
    println!(
        "daemon latency over {} frames: first packet p50 {:?} p99 {:?} max {:?}; whole frame p50 {:?} p99 {:?}",
        whole.len(),
        p(first, 50),
        p(first, 99),
        p(first, 100),
        p(whole, 50),
        p(whole, 99),
    );
    assert!(
        p(first, 50) <= FIRST_PACKET_P50,
        "median {:?}",
        p(first, 50)
    );
    assert!(p(first, 99) <= FIRST_PACKET_P99, "p99 {:?}", p(first, 99));
    // Cut-through: the first packet leaves while the rest of its frame is
    // still on the way, so the whole frame takes its spread longer.
    let spread = p(whole, 50).saturating_sub(p(first, 50));
    assert!(
        spread >= PACKET_SPACING * 2,
        "the first packet waited for its frame: {spread:?} between first and last"
    );
    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

/// How far a frame's `abs-capture-time` may be from the camera's stamp of
/// it: the clock map puts the capture at the camera's clock plus the
/// smallest transit it saw, loopback here, and the stamp is taken before
/// the frame's first packet is sent; the latency gate's p99.
const CAPTURE_TIME_TO_STAMP: Duration = FIRST_PACKET_P99;

/// How far a packet's `abs-capture-time` may be from the capture time the
/// last Sender Report before it gives it: the report extrapolates the
/// clock map as it stood when the report left, and the map may have
/// moved since by the most one camera report moves it, 5 ms;
/// 1.2 to 1.6 ms seen (2026-10-07).
const CAPTURE_TIME_TO_REPORT: Duration = Duration::from_millis(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abs_capture_time_carries_the_clock_maps_capture_time_to_the_viewer() {
    // The camera stamps each frame with its send time and sends Sender
    // Reports; the worker's clock map gives each packet its capture time,
    // which str0m's Sender Reports and the extension both carry
    // (abs-capture-time, observed 2026-10-07).
    let (origin, origin_wall) = (clock().now(), clock().wall_now());
    let cam = FakeCamera::start(
        CameraConfig {
            stamp_origin: Some(origin),
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    let carriers = |v: &Viewer| {
        v.packets()
            .iter()
            .filter(|p| p.header.ext_vals.abs_capture_time.is_some())
            .count()
    };
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    // A carrier after the stream's first Sender Report, which the check
    // against the reports needs: the first carriers can all come before
    // it when the clock map slews and join frames go out (seen in 5 runs
    // of 8, 2026-10-07).
    let reported = |v: &Viewer| {
        v.packets()
            .iter()
            .any(|p| p.header.ext_vals.abs_capture_time.is_some() && p.last_sender_info.is_some())
    };
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    // The first one, and two more a second apart.
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| carriers(v) >= 3 && reported(v),
    )
    .await;

    let packets = viewer.packets();
    let stamps: std::collections::HashMap<u32, Duration> = packets
        .iter()
        .filter_map(|p| stamp_in_payload(&p.payload).map(|sent| (p.header.timestamp, sent)))
        .collect();
    let mut checked = (0, 0);
    for (index, packet) in packets
        .iter()
        .filter(|p| p.header.ext_vals.abs_capture_time.is_some())
        .enumerate()
    {
        let value = packet.header.ext_vals.abs_capture_time.unwrap();
        assert_eq!(value.clock_offset, Some(0));
        let ours = value
            .capture_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        // The capture time the Sender Reports give the same packet: one
        // clock map, one wall clock.
        if let Some(by_report) = capture_seconds(packet) {
            assert!(
                (ours - by_report).abs() < CAPTURE_TIME_TO_REPORT.as_secs_f64(),
                "{ours} against the reports' {by_report}"
            );
            checked.0 += 1;
        }
        // The camera's own stamp of the frame, on this process's wall
        // clock; the first carrier may be a join frame, stamped long ago
        // and sent as of now.
        if let Some(sent) = stamps.get(&packet.header.timestamp).filter(|_| index > 0) {
            let stamped = (origin_wall + *sent)
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            assert!(
                (ours - stamped).abs() < CAPTURE_TIME_TO_STAMP.as_secs_f64(),
                "capture time {ours} against the stamp {stamped}"
            );
            checked.1 += 1;
        }
    }
    assert!(checked.0 >= 1 && checked.1 >= 1, "checked {checked:?}");
    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

/// Datagrams each viewer receives in the two-viewer test.
const TWO_VIEWER_PACKETS: usize = 600;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sessions_on_one_stream_send_every_datagram() {
    // Two viewers of one camera send from the same socket on the worker's
    // two threads at once. `MSG_DONTWAIT` made macOS drop their datagrams
    // whenever the other held the socket's send lock (2026-09-30: both
    // viewers lost most packets, one alone none); the worker's
    // `send_failures` must stay zero. Large keyframes make the bursts
    // overlap.
    let cam = FakeCamera::start(
        CameraConfig {
            idr_bytes: 40_000,
            p_bytes: 4_000,
            fps: 15,
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let bound = bind_udp("127.0.0.1:0".parse().unwrap()).expect("the shared socket");
    let demux = Demux::start(
        Arc::clone(&bound.socket),
        bound.local,
        bound.hosts,
        Arc::new(SystemClock),
    )
    .expect("the demux");
    let manager = WorkerManager::new(
        WorkerConfig {
            binary: PathBuf::from(env!("CARGO_BIN_EXE_lotse")),
            log_format: "json".into(),
            log_level: "info".into(),
            sandbox: "off".into(),
            worker_threads: 2,
            worker_address_space: 1 << 30,
            max_sessions: 256,
        },
        Some(bound.socket),
    );
    let worker = manager.spawn(&[], false).expect("spawns");
    let mut door = FrontDoor {
        local: bound.local,
        demux,
        worker,
    };
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let mut viewers = Vec::new();
    for (index, ufrag) in ["ufragone", "ufragtwo"].into_iter().enumerate() {
        let registration = registrations.register(
            ufrag,
            PASS.as_bytes().to_vec(),
            Arc::new(WorkerSink {
                datagrams: door.worker.datagrams(),
            }),
        );
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
        lotse_webrtc::install_crypto_provider();
        let viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
        let mut session = spec(&format!("s{index}"), viewer.offer(), door.local);
        session.ice_ufrag = ufrag.into();
        door.worker
            .open_session(&session)
            .await
            .expect("open session");
        viewers.push((socket, viewer, Vec::new(), registration));
    }

    let mut buffers = [vec![0_u8; 2_000], vec![0_u8; 2_000]];
    let mut pushed = None;
    let mut deadline = clock().sleep(Duration::from_secs(30));
    let mut enough = false;
    // Until both have their packets and a stats push came after that.
    while !(enough && pushed.is_some()) {
        let [first, second] = viewers.as_mut_slice() else {
            panic!("two viewers");
        };
        let [buf_a, buf_b] = &mut buffers;
        tokio::select! {
            event = door.worker.next_event() => match event {
                WorkerEvent::Session { session_id, event: SessionEvent::Answer { sdp, .. } } => {
                    let (socket, viewer, out, _) = if session_id == "s0" { &mut *first } else { &mut *second };
                    viewer.accept_answer(&sdp, out).expect("answer applies");
                    send_all(socket, out).await;
                }
                WorkerEvent::Stats(counters) if enough => pushed = Some(counters),
                WorkerEvent::Exited(status) => panic!("worker exited: {status:?}"),
                _ => {}
            },
            received = first.0.recv_from(buf_a) => {
                let (len, source) = received.unwrap();
                first.1.receive(clock().now(), source, &buf_a[..len], &mut first.2);
                send_all(&first.0, &mut first.2).await;
            }
            received = second.0.recv_from(buf_b) => {
                let (len, source) = received.unwrap();
                second.1.receive(clock().now(), source, &buf_b[..len], &mut second.2);
                send_all(&second.0, &mut second.2).await;
            }
            () = clock().sleep(Duration::from_millis(5)) => {
                for (socket, viewer, out, _) in &mut viewers {
                    viewer.timeout(clock().now(), out);
                    send_all(socket, out).await;
                }
            }
            () = &mut deadline => panic!(
                "not reached: {} and {} packets",
                viewers[0].1.packets().len(),
                viewers[1].1.packets().len()
            ),
        }
        enough = viewers
            .iter()
            .all(|(_, viewer, _, _)| viewer.packets().len() >= TWO_VIEWER_PACKETS);
    }
    let counters = pushed.expect("a stats push");
    assert_eq!(counters.sessions, 2);
    assert_eq!(counters.send_failures, 0, "datagrams dropped at the socket");

    drop(viewers);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_gets_pcmu_audio_in_sync_with_video() {
    // The camera sends a video frame and the audio due by then together,
    // stamping both from one clock, so the last packets of each were
    // captured within 20 ms of each other; the daemon's Sender Reports
    // must say so.
    let cam = FakeCamera::start(
        CameraConfig {
            audio: Some(CameraAudio::Pcmu),
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer =
        Viewer::new_with_audio(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    let mut session = spec("s1", viewer.offer(), door.local);
    session.audio = true;
    door.worker
        .open_session(&session)
        .await
        .expect("open session");
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    // Three seconds of audio: long enough for Sender Reports of both.
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| {
            v.audio_packets().len() >= 150
                && v.audio_packets()
                    .last()
                    .is_some_and(|p| p.last_sender_info.is_some())
                && v.packets()
                    .last()
                    .is_some_and(|p| p.last_sender_info.is_some())
        },
    )
    .await;

    let audio = viewer.audio_packets();
    assert!(audio.iter().all(|p| *p.header.payload_type == 0), "PCMU");
    for (i, packet) in audio.iter().enumerate() {
        assert_eq!(*packet.seq_no, i as u64, "one sequence space from zero");
    }
    assert!(
        audio
            .windows(2)
            .all(|w| w[1].header.timestamp.wrapping_sub(w[0].header.timestamp) == 160),
        "20 ms apart"
    );
    assert!(viewer.packets().len() >= 40, "video alongside");
    let audio_at = capture_seconds(audio.last().unwrap()).expect("an audio SR");
    let video_at = capture_seconds(viewer.packets().last().unwrap()).expect("a video SR");
    let offset_ms = (audio_at - video_at) * 1_000.0;
    assert!(
        offset_ms.abs() < 40.0,
        "audio {offset_ms:.1} ms from video by the daemon's Sender Reports"
    );

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8829_5_3_1_a_video_first_session_answers_audio_inactive_and_plays_video() {
    // `audio: "off"` on a PCMU camera: the session asks for no audio, the
    // viewer's audio m-line is answered inactive, still bundled, and only
    // video arrives.
    let cam = FakeCamera::start(
        CameraConfig {
            audio: Some(CameraAudio::Pcmu),
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer =
        Viewer::new_with_audio(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| v.packets().len() >= 40,
    )
    .await;

    assert_eq!(viewer.audio_direction(), Some(Direction::Inactive));
    let answer = events
        .iter()
        .find_map(|e| match e {
            SessionEvent::Answer { sdp, .. } => Some(sdp.clone()),
            _ => None,
        })
        .expect("an answer");
    assert!(answer.contains("a=inactive"), "{answer}");
    assert!(!answer.contains("m=audio 0 "), "{answer}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SessionEvent::Warning { .. })),
        "off is no warning: {events:?}"
    );
    // A second of video more: still no audio.
    let target = viewer.packets().len() + 25;
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| v.packets().len() >= target,
    )
    .await;
    assert!(viewer.audio_packets().is_empty());

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_gets_opus_from_an_aac_camera_in_sync_with_video_by_ebu_r37() {
    use lotse_testing::fake_camera::{AUDIO_FIRST_TIMESTAMP, FIRST_TIMESTAMP};

    // The camera's AAC reaches the viewer as Opus from the worker's
    // transcoder. The camera stamps audio and video from one clock, both
    // starting when it plays: an AAC timestamp `s` is captured
    // (s − AUDIO_FIRST_TIMESTAMP) / 16000 s in, a video timestamp `v`
    // (v − FIRST_TIMESTAMP) / 90000 s in. The Opus
    // timestamps are the AAC ones on the 48 kHz clock, compensated for the
    // chain's delay, and in the first epoch the session's timestamps are
    // the tracks' own. So the capture instant of any packet the viewer
    // gets is known, and the daemon's Sender Reports must map audio and
    // video to the same offsets from it: EBU R37 allows audio at most
    // 40 ms early (and 60 ms late); the check holds it to 40 ms either way,
    // as for PCMU. The transcoder's delay (88.5 ms at 16 kHz) is latency,
    // which this does not measure.
    let cam = FakeCamera::start(
        CameraConfig {
            audio: Some(CameraAudio::Aac),
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer =
        Viewer::new_with_audio(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    let mut session = spec("s1", viewer.offer(), door.local);
    session.audio = true;
    door.worker
        .open_session(&session)
        .await
        .expect("open session");
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    // Three seconds of audio: long enough for Sender Reports of both.
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| {
            v.audio_packets().len() >= 150
                && v.audio_packets()
                    .last()
                    .is_some_and(|p| p.last_sender_info.is_some())
                && v.packets()
                    .last()
                    .is_some_and(|p| p.last_sender_info.is_some())
        },
    )
    .await;

    // Opus, under the payload type the answer gave it (RFC 7587 §7).
    let answer = events
        .iter()
        .find_map(|event| match event {
            SessionEvent::Answer { sdp, .. } => Some(sdp.clone()),
            _ => None,
        })
        .expect("an answer");
    let opus_pt: u8 = answer
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("a=rtpmap:")?;
            let (pt, codec) = rest.split_once(' ')?;
            codec
                .to_ascii_lowercase()
                .starts_with("opus/48000")
                .then(|| pt.parse().ok())?
        })
        .expect("opus in the answer");
    let audio = viewer.audio_packets();
    assert!(
        audio.iter().all(|p| *p.header.payload_type == opus_pt),
        "Opus"
    );
    for (i, packet) in audio.iter().enumerate() {
        assert_eq!(*packet.seq_no, i as u64, "one sequence space from zero");
    }
    // RFC 7587 §4.2: one 20 ms frame per packet, on the 48 kHz clock.
    assert!(
        audio
            .windows(2)
            .all(|w| w[1].header.timestamp.wrapping_sub(w[0].header.timestamp) == 960),
        "20 ms apart"
    );
    assert!(viewer.packets().len() >= 40, "video alongside");

    let since_start =
        |ts: u32, first: u32, rate: f64| f64::from(ts.wrapping_sub(first).cast_signed()) / rate;
    let last_audio = audio.last().unwrap();
    let last_video = viewer.packets().last().unwrap();
    let audio_at = capture_seconds(last_audio).expect("an audio SR");
    let video_at = capture_seconds(last_video).expect("a video SR");
    let audio_captured = since_start(
        last_audio.header.timestamp,
        AUDIO_FIRST_TIMESTAMP.wrapping_mul(3),
        48_000.0,
    );
    let video_captured = since_start(last_video.header.timestamp, FIRST_TIMESTAMP, 90_000.0);
    let offset_ms = ((audio_at - video_at) - (audio_captured - video_captured)) * 1_000.0;
    assert!(
        offset_ms.abs() < 40.0,
        "audio {offset_ms:.1} ms from video captured at the same instant, by the daemon's Sender Reports"
    );

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc7798_an_h265_camera_plays_cut_through_where_the_offer_lists_h265() {
    // An H.265 camera: a viewer that offers H.265 gets it cut through, one
    // that offers only H.264 is refused with the code a client falls back on.
    h265_camera_plays_and_refuses(
        CameraVideo::H265,
        &[],
        "profile-id=1;tier-flag=0;level-id=180",
        "a=rtpmap:96 H264/90000\na=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\n",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn itu_t_h265_a_4_1_a_high_tier_camera_plays_only_to_a_high_tier_viewer() {
    // A High tier camera: a viewer that offers the High tier gets it, one
    // that offers H.265 only in the Main tier, as Chrome and Safari do, is
    // refused with the code a client falls back on.
    h265_camera_plays_and_refuses(
        CameraVideo::H265HighTier,
        &[(1, 1, 153)],
        "profile-id=1;tier-flag=1;level-id=153",
        "a=rtpmap:96 H265/90000\na=fmtp:96 level-id=180;profile-id=1;tier-flag=0;tx-mode=SRST\n",
    )
    .await;
}

/// An H.265 camera of `video` through a worker: a viewer offering the
/// H.265 `entries` (str0m's own when empty) is answered with `answered`
/// in its `fmtp` and gets the stream cut through; an offer of `refused`
/// video codecs closes with `video_codec_unsupported`.
async fn h265_camera_plays_and_refuses(
    video: CameraVideo,
    entries: &[(u8, u8, u8)],
    answered: &str,
    refused: &str,
) {
    use lotse_codec::h265::nal;

    let cam = FakeCamera::start(
        CameraConfig {
            video,
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let addr = socket.local_addr().unwrap();
    let mut viewer = if entries.is_empty() {
        Viewer::new(addr, clock().now())
    } else {
        Viewer::new_h265(addr, clock().now(), entries)
    }
    .expect("a viewer");
    let refused = with_video_codecs(viewer.offer(), refused);
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    // An IRAP picture with its parameter sets in an aggregation packet
    // (RFC 7798 §4.4.2), then its slices in fragmentation units (§4.4.3).
    let keyframe = |v: &Viewer| {
        v.packets().iter().any(|p| {
            nal::nal_type(p.payload[0]) == nal::FU
                && p.payload
                    .get(2)
                    .is_some_and(|fu| fu & 0x80 != 0 && nal::is_irap(fu & 0x3f))
        })
    };
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| v.packets().len() >= 40 && keyframe(v),
    )
    .await;
    let answer = events
        .iter()
        .find_map(|e| match e {
            SessionEvent::Answer { sdp, .. } => Some(sdp.clone()),
            _ => None,
        })
        .expect("an answer");
    assert!(answer.contains(" H265/90000"), "{answer}");
    assert!(answer.contains(answered), "{answer}");
    assert!(!answer.contains(" H264/90000"), "{answer}");
    let packets = viewer.packets();
    assert!(
        packets
            .iter()
            .any(|p| nal::nal_type(p.payload[0]) == nal::AP),
        "the parameter sets"
    );
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(*packet.seq_no, i as u64, "renumbered from zero");
    }
    assert!(packets.iter().any(|p| p.header.marker));

    door.worker
        .open_session(&spec("s2", &refused, door.local))
        .await
        .expect("open session");
    assert_eq!(
        closed(&mut door.worker).await,
        ("s2".to_owned(), "video_codec_unsupported".to_owned())
    );

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

/// The Reolink Duo 3 main stream's shape, scaled down: H.265 at 20 fps, an
/// IDR picture every second whose fragments take 300 ms to arrive, as a
/// camera on a link only somewhat faster than its stream delivers a large
/// keyframe (2026-10-03: the Duo 3's 2160×7680 pictures, about 1.4 MB per
/// IDR, reached Chrome over 250 ms each).
fn duo_shaped_camera() -> CameraConfig {
    CameraConfig {
        video: CameraVideo::H265,
        fps: 20,
        gop: 20,
        mtu: 1_400,
        idr_bytes: 100 * 1_397,
        p_bytes: 3_000,
        packet_spacing: Duration::from_millis(3),
        ..CameraConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn libwebrtc_assembles_every_picture_after_a_keyframe_that_arrives_slowly() {
    // The pictures after a slow keyframe queue behind it on the camera's
    // link: they are late only by the keyframe's own transfer, not after
    // an ingest stall, so the session sends them, and Chrome's receiver
    // (`lotse_testing::libwebrtc`) assembles and hands on every one.
    // Before, the first of them counted as late, and the session skipped
    // every delta frame to the next keyframe: Chrome showed 1 fps.
    let cam = FakeCamera::start(duo_shaped_camera(), clock())
        .await
        .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    // Three IRAP pictures received: two whole groups of pictures between.
    let irap_starts = |v: &Viewer| {
        v.packets()
            .iter()
            .filter(|p| {
                p.payload.first().is_some_and(|&b| (b >> 1) & 0x3f == 49)
                    && p.payload
                        .get(2)
                        .is_some_and(|fu| fu & 0x80 != 0 && (16..=23).contains(&(fu & 0x3f)))
            })
            .count()
    };
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| irap_starts(v) >= 3,
    )
    .await;

    let mut chrome = H265Receiver::new();
    for p in viewer.packets() {
        chrome.insert(
            p.header.sequence_number,
            p.header.timestamp,
            p.header.marker,
            &p.payload,
        );
    }
    let frames = chrome.frames();
    let keyframes: Vec<usize> = (0..frames.len()).filter(|&i| frames[i].keyframe).collect();
    assert!(keyframes.len() >= 2, "{frames:?}");
    // Every picture of the whole group between the last two keyframes.
    let gop = keyframes[keyframes.len() - 1] - keyframes[keyframes.len() - 2];
    assert_eq!(
        gop,
        20,
        "pictures handed on between two keyframes; {} stashed",
        chrome.stashed()
    );

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h265_7_4_2_4_4_parameter_sets_between_slice_segments_never_reach_the_browser() {
    // A Reolink camera's H.265 main stream (observed 2026-10-09) codes each
    // picture as three slice segments and sends VPS, SPS and PPS again
    // before every one of them. Chrome's decoder ends the picture at the
    // repeat and fails the segments after it
    // (`lotse_testing::libwebrtc::Frame::misplaced_sets`), so Chrome showed
    // nothing. The session's packets carry parameter sets only before each
    // picture's first segment, and Chrome's receiver assembles and hands on
    // every picture.
    let cam = FakeCamera::start(
        CameraConfig {
            fps: 10,
            gop: 5,
            idr_bytes: 9_000,
            p_bytes: 1_500,
            slices: 3,
            sets_before_every_slice: true,
            video: CameraVideo::H265,
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    // Three IDR pictures of three fragmented segments each received: two
    // whole groups of pictures between.
    let irap_starts = |v: &Viewer| {
        v.packets()
            .iter()
            .filter(|p| {
                p.payload.first().is_some_and(|&b| (b >> 1) & 0x3f == 49)
                    && p.payload
                        .get(2)
                        .is_some_and(|fu| fu & 0x80 != 0 && (16..=23).contains(&(fu & 0x3f)))
            })
            .count()
    };
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| irap_starts(v) >= 9,
    )
    .await;

    let mut chrome = H265Receiver::new();
    for p in viewer.packets() {
        chrome.insert(
            p.header.sequence_number,
            p.header.timestamp,
            p.header.marker,
            &p.payload,
        );
    }
    let frames = chrome.frames();
    assert!(
        frames.iter().all(|frame| frame.misplaced_sets == 0),
        "a parameter set after a picture's first segment: {frames:?}"
    );
    let keyframes: Vec<usize> = (0..frames.len()).filter(|&i| frames[i].keyframe).collect();
    assert!(keyframes.len() >= 2, "{frames:?}");
    let gop = keyframes[keyframes.len() - 1] - keyframes[keyframes.len() - 2];
    assert_eq!(
        gop,
        5,
        "pictures handed on between two keyframes; {} stashed",
        chrome.stashed()
    );

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn libwebrtc_max_frame_packets_a_larger_keyframe_is_sent_whole_with_a_warning_and_a_count() {
    // Every other keyframe is 2.5 MB, about 2180 packets at the payload
    // target: more than some libwebrtc receivers assemble. The session
    // sends it whole, warns once, and the stream counts it.
    let cam = FakeCamera::start(
        CameraConfig {
            fps: 10,
            gop: 5,
            alternate_idr_bytes: Some(2_500_000),
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera(&mut door, &cam).await;
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    // The large keyframe: the first timestamp whose packets span more
    // sequence numbers than a frame cut at the limit would, its 2047
    // packets and the two filler units sent after them until 2026-10-05;
    // done once three frames ended after it. The fake camera sends
    // a frame's packets at once, so loopback drops part of such a burst
    // and which packets arrive varies (the session tests of `lotse-webrtc`
    // count every one); the span shows the frame went past the limit.
    let large = |v: &Viewer| {
        let mut frames = std::collections::BTreeMap::new();
        for p in v.packets() {
            let seq = p.header.sequence_number;
            let span = frames.entry(p.header.timestamp).or_insert((seq, seq));
            if seq.wrapping_sub(span.1) < 1 << 15 {
                span.1 = seq;
            }
            if span.0.wrapping_sub(seq) < 1 << 15 {
                span.0 = seq;
            }
        }
        frames
            .into_iter()
            .map(|(ts, (first, last))| (ts, usize::from(last.wrapping_sub(first)) + 1))
            .find(|&(_, span)| span > 2_049)
    };
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| {
            large(v).is_some_and(|(ts, _)| {
                v.packets()
                    .iter()
                    .filter(|p| {
                        p.header.marker
                            && p.header.timestamp.wrapping_sub(ts) < 1 << 31
                            && p.header.timestamp != ts
                    })
                    .count()
                    >= 3
            })
        },
    )
    .await;
    // The warning, and the stream's count for `metrics/get` in the
    // worker's stats, may still be on their way.
    let is_warning = |e: &SessionEvent| matches!(e, SessionEvent::Warning { code, .. } if code == "frame_over_browser_limit");
    let mut counted = 0;
    while counted == 0 || !events.iter().any(is_warning) {
        match door.worker.next_event().await {
            WorkerEvent::Stats(stats) => {
                counted = stats
                    .tracks
                    .iter()
                    .map(|(_, t)| t.frames_over_browser_limit)
                    .sum();
            }
            WorkerEvent::Session { event, .. } => events.push(event),
            WorkerEvent::Exited(status) => panic!("worker exited: {status:?}"),
            _ => {}
        }
    }
    let warnings: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Warning { code, message } if code == "frame_over_browser_limit" => {
                Some(message.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(warnings.len(), 1, "{events:?}");
    assert!(
        warnings[0].contains("sent whole") && warnings[0].contains("substream"),
        "{}",
        warnings[0]
    );

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_39_a_viewer_plays_a_camera_over_udp_and_the_worker_counts_its_loss() {
    // RTP over UDP with one datagram in nine lost and a stranger on the
    // LAN sending copies from another port: the viewer still plays, and
    // the worker's counters say what happened.
    let cam = FakeCamera::start(
        CameraConfig {
            udp: CameraUdp {
                drop_every: Some(9),
                foreign_every: Some(7),
                ..CameraUdp::default()
            },
            ..CameraConfig::default()
        },
        clock(),
    )
    .await
    .expect("camera");
    let mut door = front_door();
    assert!(matches!(
        door.worker.next_event().await,
        WorkerEvent::Ready { .. }
    ));
    run_camera_with(&mut door, &cam, r#"{"transport": "udp"}"#).await;
    assert_eq!(Stats::get(&cam.stats().udp_setups), 1);
    let registrations = door.demux.registrations();
    let _registration = registrations.register(
        UFRAG,
        PASS.as_bytes().to_vec(),
        Arc::new(WorkerSink {
            datagrams: door.worker.datagrams(),
        }),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("viewer socket");
    lotse_webrtc::install_crypto_provider();
    let mut viewer = Viewer::new(socket.local_addr().unwrap(), clock().now()).expect("a viewer");
    door.worker
        .open_session(&spec("s1", viewer.offer(), door.local))
        .await
        .expect("open session");
    let (mut events, mut reports) = (Vec::new(), Vec::new());
    drive(
        &mut door,
        &socket,
        &mut viewer,
        &mut events,
        &mut reports,
        |v, _| v.packets().len() >= 40 && v.keyframe_starts() >= 1,
    )
    .await;
    assert!(viewer.is_connected(), "{events:?}");
    // The loss and the refused copies reach the worker's counters.
    let mut deadline = clock().sleep(Duration::from_secs(10));
    loop {
        tokio::select! {
            event = door.worker.next_event() => match event {
                WorkerEvent::Stats(stats) if stats.packets_lost > 0 && stats.datagrams_rejected > 0 => break,
                WorkerEvent::Exited(status) => panic!("worker exited: {status:?}"),
                _ => {}
            },
            () = &mut deadline => panic!("no loss counted in time"),
        }
    }

    registrations.unregister(UFRAG);
    let exit = door.worker.stop(Duration::from_secs(5), &clock()).await;
    assert!(exit.success(), "clean exit, got {exit:?}");
    door.demux.stop();
    cam.stop().await;
}

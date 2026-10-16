//! The RTSP source's ONVIF backchannel (ONVIF Streaming Specification
//! §5.3) against the fake camera of `lotse-testing`: the session that
//! plays the stream never asks for it; once it plays, a stream that opted
//! in has the camera probed with `Require` on a connection of its own,
//! which closes, a `551` remembered and any other failure asked again; a
//! claim opens the backchannel in a session of its own beside the
//! viewing one, `SETUP` of the backchannel alone, TCP interleaved over
//! either transport, and its packets reach the camera; the release sends
//! `TEARDOWN` with `Require` and closes the connection; a refusal, a
//! hang-up, a camera that never answers and a lost connection each say
//! why; a reconnect of the viewing session leaves the backchannel's
//! alone; and the probe waits for a connect permit while a claim's
//! connection does not.

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

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::{Clock, SystemClock};
use lotse_core::codec::{Codec, Kind};
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::runner::{ProbeAsk, ProbeGate};
use lotse_core::source::{
    BackchannelOffer, BackchannelRefused, BackchannelSession, BackchannelSlot, ResolvedPeer,
    Source, SourceFactory as _,
};
use lotse_core::source_url::SourceUrl;
use lotse_rtsp::RtspFactory;
use lotse_testing::fake_camera::{
    BackchannelCodec, BackchannelRtp, BackchannelSetup, CameraAudio, CameraBackchannel, CameraTls,
    ConnectionLog, RequireAnswer, Stats,
};
use lotse_testing::{CameraConfig, FakeCamera, Harness};
use serde_json::json;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Every log line's fields are evaluated, as in production at `trace`;
/// the lines go nowhere.
fn traced() {
    let _installed = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(std::io::sink)
        .try_init();
}

async fn camera(config: CameraConfig) -> FakeCamera {
    traced();
    FakeCamera::start(config, clock())
        .await
        .expect("camera binds")
}

fn peer(camera: &FakeCamera) -> ResolvedPeer {
    ResolvedPeer {
        host: "127.0.0.1".into(),
        addrs: vec![camera.addr()],
    }
}

/// The RTSP source of `camera` with `options`, opted in to the backchannel
/// unless they say otherwise: it is off by default.
fn source(camera: &FakeCamera, options: &serde_json::Value) -> Box<dyn Source> {
    let mut options = if options.is_null() {
        json!({})
    } else {
        options.clone()
    };
    if let Some(fields) = options.as_object_mut() {
        fields.entry("backchannel").or_insert(json!(true));
    }
    as_given(camera, &options)
}

/// The RTSP source of `camera` with `options` as they are.
fn as_given(camera: &FakeCamera, options: &serde_json::Value) -> Box<dyn Source> {
    RtspFactory::default()
        .validate(&SourceUrl::parse(&camera.url()).unwrap(), options)
        .expect("valid source")
}

/// A camera with video, `audio` and a backchannel in `codec`, changed by
/// `backchannel`, which keeps a connection open after its `TEARDOWN` so
/// that the close is the client's.
fn config(
    audio: Option<CameraAudio>,
    codec: BackchannelCodec,
    backchannel: impl FnOnce(&mut CameraBackchannel),
) -> CameraConfig {
    let mut offered = CameraBackchannel::new(codec);
    backchannel(&mut offered);
    CameraConfig {
        audio,
        backchannel: Some(offered),
        keep_open_on_teardown: true,
        ..CameraConfig::default()
    }
}

/// Waits up to `steps` × 20 ms for `done`.
async fn eventually(steps: u32, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..steps {
        if done() {
            return true;
        }
        clock().sleep(Duration::from_millis(20)).await;
    }
    done()
}

fn count(counter: &std::sync::atomic::AtomicU64) -> u64 {
    Stats::get(counter)
}

/// What the camera logged of its connections.
fn log(cam: &FakeCamera) -> Vec<ConnectionLog> {
    cam.stats().connection_log()
}

/// Waits until the source's probe, the camera's `connections`th
/// connection, is over and its connection closed.
async fn probed(cam: &FakeCamera, connections: usize, slot: &BackchannelSlot) {
    assert!(
        eventually(250, || {
            let logs = log(cam);
            logs.len() >= connections && logs[connections - 1].closed && !slot.is_probing()
        })
        .await,
        "the probe's connection closed: {:?}",
        log(cam)
    );
}

/// The backchannel the source's probe offered on `slot`, once one is.
async fn offered(slot: &BackchannelSlot) -> BackchannelOffer {
    assert!(
        eventually(250, || !slot.is_probing() && slot.current().is_some()).await,
        "offered"
    );
    slot.current().unwrap()
}

/// Opens the backchannel `slot` offers.
async fn open(slot: &BackchannelSlot) -> Result<BackchannelSession, BackchannelRefused> {
    let offer = offered(slot).await;
    tokio::select! {
        opened = offer.opener.open() => opened,
        () = clock().sleep(Duration::from_secs(15)) => panic!("not opened within 15 s"),
    }
}

/// The packet the talk-back chain hands the backchannel: `n` of a
/// talkspurt from timestamp 1000, `step` ticks apart, its payload `n`
/// repeated `len` times.
fn uplink(n: u8, step: u32, len: usize) -> MediaPacket {
    MediaPacket {
        arrival: clock().now(),
        rtp: RtpHeaderFields {
            pt: 0,
            seq: u16::from(n),
            ts: 1_000 + u32::from(n) * step,
            marker: n == 0,
            ssrc: 7,
        },
        frame_start: true,
        keyframe_start: false,
        epoch: 0,
        lateness: Duration::ZERO,
        payload: Arc::from(vec![n; len]),
    }
}

/// Sends `packets` of `step` ticks and `len` bytes on `session` and waits
/// until the camera recorded as many: what it recorded.
async fn talk(
    session: &BackchannelSession,
    cam: &FakeCamera,
    packets: u8,
    (step, len): (u32, usize),
) -> Vec<BackchannelRtp> {
    let before = cam.stats().backchannel().len();
    for n in 0..packets {
        session.sender.try_send(uplink(n, step, len)).unwrap();
        clock().sleep(Duration::from_millis(5)).await;
    }
    let want = before + usize::from(packets);
    assert!(
        eventually(250, || cam.stats().backchannel().len() >= want).await,
        "the camera recorded {} of {want}",
        cam.stats().backchannel().len()
    );
    cam.stats().backchannel()[before..].to_vec()
}

/// RFC 3550 §5.1: one stream, as the talk-back chain stamped it: the
/// camera's payload type, one SSRC, consecutive sequence numbers,
/// timestamps `step` apart, the marker on the talkspurt's first packet
/// (RFC 3551 §4.1), the payloads as sent.
fn check_stream(recorded: &[BackchannelRtp], pt: u8, step: u32, len: usize) {
    for (i, packet) in recorded.iter().enumerate() {
        assert_eq!(packet.payload_type, pt, "packet {i}");
        assert_eq!(packet.marker, i == 0, "packet {i}");
        assert_eq!(
            packet.payload,
            vec![u8::try_from(i).unwrap(); len],
            "packet {i}"
        );
        assert_eq!(packet.ssrc, recorded[0].ssrc, "packet {i}");
        if let Some(next) = recorded.get(i + 1) {
            assert_eq!(next.sequence_number, packet.sequence_number.wrapping_add(1));
            assert_eq!(next.timestamp.wrapping_sub(packet.timestamp), step);
        }
    }
}

/// Ends the attempt.
async fn finish(harness: Harness) {
    harness.cancel();
    let _exit = harness.finish().await;
}

/// `future`'s output, or a failed test after five seconds.
async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::select! {
        output = future => output,
        () = clock().sleep(Duration::from_secs(5)) => panic!("nothing within 5 s"),
    }
}

/// Waits for `session`'s loss: why it ended on the camera's side.
async fn lost(session: &mut BackchannelSession) -> BackchannelRefused {
    tokio::select! {
        lost = &mut session.lost => lost.unwrap(),
        () = clock().sleep(Duration::from_secs(5)) => panic!("not lost within 5 s"),
    }
}

/// The session that plays the stream asks for nothing; the probe asks on
/// a connection of its own, which closes; the claim opens the backchannel
/// alone in a session of its own beside the viewing one, whose packets
/// reach the camera; its release tears it down with `Require` and closes
/// its connection, and the viewing session plays on throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_a_probe_and_a_claimed_backchannel_session_beside_the_viewing_one() {
    let cam = camera(config(
        Some(CameraAudio::Pcmu),
        BackchannelCodec::Pcma,
        |backchannel| backchannel.ptime = Some(40),
    ))
    .await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let slot = harness.backchannel.clone();
    probed(&cam, 2, &slot).await;
    let logs = log(&cam);
    // ONVIF Streaming Specification §5.3.1: the viewing `DESCRIBE`
    // carries no `Require`, and its session sets up the media alone.
    assert_eq!(logs[0].describes, [false]);
    assert_eq!(logs[0].setups, ["track0", "track1"]);
    assert!(logs[0].played && !logs[0].closed);
    // The probe: one `DESCRIBE` with `Require` on a connection of its
    // own, nothing set up, the connection closed by the source.
    assert_eq!(logs[1].describes, [true]);
    assert!(logs[1].setups.is_empty() && !logs[1].played);
    assert!(logs[1].closed_by_client, "{:?}", logs[1]);
    assert_eq!(logs[1].teardown, None, "nothing set up, nothing torn down");
    // Never a track: the camera's own PCMU is the audio.
    let tracks = harness.tracks.tracks();
    assert_eq!(tracks.len(), 2);
    assert_eq!(
        (tracks[1].kind(), tracks[1].codec().as_ref()),
        (Kind::Audio, &Codec::Pcmu)
    );
    // The offer names the backchannel's codec and its `a=ptime` (RFC
    // 8866 §6.4) as the frame.
    let offer = offered(&slot).await;
    assert_eq!(offer.codec, Codec::Pcma);
    assert_eq!(offer.frame, Duration::from_millis(40));

    // The claim opens a session of its own: `DESCRIBE` with `Require`,
    // `SETUP` of the backchannel alone, `PLAY`.
    let session = open(&slot).await.unwrap();
    assert_eq!(
        (session.codec.clone(), session.frame),
        (Codec::Pcma, Duration::from_millis(40))
    );
    let logs = log(&cam);
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[2].describes, [true]);
    assert_eq!(logs[2].setups, ["backchannel"]);
    assert!(logs[2].played && logs[2].backchannel_only());
    assert_eq!(count(&cam.stats().backchannel_playing), 1);
    assert_eq!(count(&cam.stats().playing), 1, "the viewing session alone");
    let recorded = talk(&session, &cam, 6, (320, 320)).await;
    check_stream(&recorded, 8, 320, 320);
    assert!(recorded.iter().all(|packet| packet.connection == 2));
    assert!(
        eventually(100, || count(&cam.stats().backchannel_rtcp) > 0).await,
        "retina's Sender Reports"
    );
    // The release: `TEARDOWN` with `Require`, and the source closes the
    // connection, which the camera keeps open.
    drop(session);
    assert!(
        eventually(100, || log(&cam)[2].closed).await,
        "{:?}",
        log(&cam)[2]
    );
    let logs = log(&cam);
    assert_eq!(logs[2].teardown, Some(true), "TEARDOWN with Require");
    assert!(logs[2].closed_by_client);
    assert_eq!(count(&cam.stats().backchannel_playing), 0);
    assert!(!logs[0].closed, "the viewing session plays on");
    // The next claim opens another.
    let again = open(&slot).await.unwrap();
    let recorded = talk(&again, &cam, 2, (160, 160)).await;
    assert!(recorded.iter().all(|packet| packet.connection == 3));
    drop(again);
    finish(harness).await;
    cam.stop().await;
}

/// ONVIF Streaming Specification §5.3.2: a `551` to the probe means the
/// camera has no backchannel, and the source does not ask again; any
/// other failure means none for this attempt, and the next one asks
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_2_a_551_to_the_probe_is_remembered_and_another_failure_asked_again() {
    for (answer, again) in [
        (RequireAnswer::OptionNotSupported, false),
        (RequireAnswer::Status(503), true),
    ] {
        let cam = camera(config(None, BackchannelCodec::Pcmu, |backchannel| {
            backchannel.require = answer;
        }))
        .await;
        let source = source(&cam, &serde_json::Value::Null);
        let slot = BackchannelSlot::default();
        let mut first = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
        assert!(first.wait_ready().await, "{answer:?}: plays");
        probed(&cam, 2, &slot).await;
        assert_eq!(count(&cam.stats().require_rejected), 1, "{answer:?}");
        assert!(slot.current().is_none(), "{answer:?}: none");
        assert_eq!(first.tracks.tracks().len(), 1, "{answer:?}: the video");
        finish(first).await;
        // The source's next attempt, a reconnect.
        let mut second = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
        assert!(second.wait_ready().await, "{answer:?}");
        if again {
            probed(&cam, 4, &slot).await;
            assert_eq!(count(&cam.stats().require_rejected), 2, "{answer:?}");
        } else {
            clock().sleep(Duration::from_millis(200)).await;
            assert_eq!(log(&cam).len(), 3, "{answer:?}: not asked again");
            assert_eq!(count(&cam.stats().require_rejected), 1, "{answer:?}");
        }
        finish(second).await;
        cam.stop().await;
    }
}

/// Every connect probes again: a reconnect whose probe finds no
/// backchannel (the camera's answer offers none now) withdraws the offer
/// the last probe found.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_2_a_reconnect_whose_probe_finds_none_withdraws_the_offer() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
    let source = source(&cam, &serde_json::Value::Null);
    let slot = BackchannelSlot::default();
    let mut first = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
    assert!(first.wait_ready().await, "ready");
    assert_eq!(offered(&slot).await.codec, Codec::Pcmu);
    finish(first).await;
    cam.set_backchannel_setup(BackchannelSetup::NoMedia);
    let mut second = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
    assert!(second.wait_ready().await, "reconnected");
    probed(&cam, 4, &slot).await;
    assert!(slot.current().is_none(), "withdrawn");
    finish(second).await;
    cam.stop().await;
}

/// A stream that does not opt in never probes: off by default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_1_a_stream_that_does_not_opt_in_sends_no_require() {
    for options in [
        serde_json::Value::Null,
        json!({}),
        json!({ "backchannel": false }),
    ] {
        let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
        let source = as_given(&cam, &options);
        let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
        assert!(harness.wait_ready().await, "{options}: ready");
        clock().sleep(Duration::from_millis(100)).await;
        assert_eq!(log(&cam).len(), 1, "{options}: no probe");
        assert_eq!(count(&cam.stats().backchannel_describes), 0, "{options}");
        assert!(harness.backchannel.current().is_none(), "{options}");
        finish(harness).await;
        cam.stop().await;
    }
}

/// The camera refuses the backchannel session at its `SETUP` or its
/// `PLAY`, offers none in its answer, hangs up or never answers: each
/// says why, with the camera's status when it gave one, and a `461` is
/// named as the unsupported transport it is. The next claim opens one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_4_a_refused_backchannel_session_says_why() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
    let source = source(&cam, &json!({ "timeout_ms": 500 }));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let slot = harness.backchannel.clone();
    probed(&cam, 2, &slot).await;
    for (setup, status, says) in [
        (BackchannelSetup::RefuseDescribe(503), Some(503), "503"),
        (BackchannelSetup::Refuse(453), Some(453), "453"),
        (BackchannelSetup::RefusePlay(503), Some(503), "503"),
        (
            BackchannelSetup::Refuse(461),
            Some(461),
            "unsupported transport",
        ),
        (
            BackchannelSetup::NoMedia,
            None,
            "the camera's answer offers no backchannel the talk-back chain can feed",
        ),
        (BackchannelSetup::HangUp, None, ""),
        (BackchannelSetup::Silent, None, "no answer within"),
    ] {
        cam.set_backchannel_setup(setup);
        let connections = log(&cam).len();
        let refused = open(&slot).await.unwrap_err();
        assert_eq!(refused.status, status, "{setup:?}: {refused:?}");
        assert!(refused.message.contains(says), "{setup:?}: {refused:?}");
        assert!(
            eventually(100, || {
                let logs = log(&cam);
                logs.len() > connections && logs[connections].closed
            })
            .await,
            "{setup:?}: its connection closed"
        );
        if setup == BackchannelSetup::RefusePlay(503) {
            assert_eq!(
                log(&cam)[connections].teardown,
                Some(true),
                "the session set up is torn down"
            );
        }
    }
    cam.set_backchannel_setup(BackchannelSetup::Accept);
    let session = open(&slot).await.unwrap();
    assert_eq!(talk(&session, &cam, 2, (160, 160)).await.len(), 2);
    assert_eq!(count(&cam.stats().max_backchannel_playing), 1);
    drop(session);
    finish(harness).await;
    cam.stop().await;
}

/// The backchannel session's connection drops while it is held, or a
/// packet retina cannot send ends it: its loss says why. A viewing
/// session that reconnects leaves it alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_12_a_lost_backchannel_session_says_why_and_a_viewing_reconnect_leaves_it() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
    let source = source(&cam, &serde_json::Value::Null);
    let slot = BackchannelSlot::default();
    let mut harness = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
    assert!(harness.wait_ready().await, "ready");
    probed(&cam, 2, &slot).await;
    let mut session = open(&slot).await.unwrap();
    // The viewing session's connection drops: its attempt ends, the
    // backchannel's session plays on, and the next attempt (a reconnect)
    // probes again while it does.
    cam.hang_up_where(|log| !log.backchannel_only());
    let _exit = harness.finish().await;
    let mut again = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
    assert!(again.wait_ready().await, "reconnected");
    assert_eq!(talk(&session, &cam, 3, (160, 160)).await.len(), 3);
    assert!(!log(&cam)[2].closed, "the backchannel session is its own");
    // The camera drops the backchannel's connection: lost.
    cam.hang_up_backchannel();
    let why = lost(&mut session).await;
    assert_eq!(why.status, None, "{why:?}");
    drop(session);
    // RFC 2326 §10.12: an interleaved frame's length has 16 bits; a
    // packet longer ends the session, with why.
    let mut session = open(&slot).await.unwrap();
    session.sender.try_send(uplink(0, 160, 70_000)).unwrap();
    let why = lost(&mut session).await;
    assert!(why.message.contains("70000"), "{why:?}");
    // A camera that sends what is no RTSP ends it too, with why.
    cam.set_backchannel_setup(BackchannelSetup::Unreadable);
    let mut session = open(&slot).await.unwrap();
    let why = lost(&mut session).await;
    assert_eq!(why.status, None, "{why:?}");
    assert!(!why.message.is_empty());
    finish(again).await;
    cam.stop().await;
}

/// A camera that is gone when the claim comes: refused without a
/// status, saying the connection failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_4_a_camera_gone_before_the_claim_refuses_without_a_status() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let slot = harness.backchannel.clone();
    probed(&cam, 2, &slot).await;
    cam.stop().await;
    let refused = open(&slot).await.unwrap_err();
    assert_eq!(refused.status, None, "{refused:?}");
    assert!(refused.message.contains("connect"), "{refused:?}");
    finish(harness).await;
}

/// RFC 7826 §19.2: an `rtsps` camera's probe and backchannel session take
/// TLS too, through the same pre-bound relay listener as the session that
/// plays the stream, one connection at a time from its bind to its
/// accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc7826_19_2_over_rtsps_the_backchannel_takes_tls_through_the_shared_relay() {
    let tls = CameraTls::self_signed(&["camera.test"]).unwrap();
    let pin = tls.fingerprint();
    let cam = camera(CameraConfig {
        tls: Some(tls),
        ..config(None, BackchannelCodec::Pcmu, |_| {})
    })
    .await;
    let relay = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let source = RtspFactory::new(Some(relay))
        .validate(
            &SourceUrl::parse(&format!("rtsps://camera.test:{}/stream", cam.addr().port()))
                .unwrap(),
            &json!({ "tls_fingerprint": pin, "backchannel": true }),
        )
        .unwrap();
    let peer = ResolvedPeer {
        host: "camera.test".into(),
        addrs: vec![cam.addr()],
    };
    let mut harness = Harness::start(source.as_ref(), peer, clock());
    assert!(harness.wait_ready().await, "ready");
    let slot = harness.backchannel.clone();
    probed(&cam, 2, &slot).await;
    let session = open(&slot).await.unwrap();
    assert_eq!(talk(&session, &cam, 3, (160, 160)).await.len(), 3);
    drop(session);
    assert!(
        eventually(100, || log(&cam)[2].closed).await,
        "{:?}",
        log(&cam)
    );
    assert_eq!(log(&cam)[2].teardown, Some(true));
    assert_eq!(count(&cam.stats().tls_failures), 0);
    finish(harness).await;
    cam.stop().await;
}

/// Over UDP the viewing session takes the UDP relay, while the
/// backchannel's session is set up TCP interleaved on a connection of its
/// own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_39_over_udp_the_backchannel_session_is_tcp_interleaved() {
    let cam = camera(config(
        Some(CameraAudio::Pcmu),
        BackchannelCodec::Pcmu,
        |_| {},
    ))
    .await;
    let source = source(&cam, &json!({ "transport": "udp" }));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "RTP arrived over UDP");
    let slot = harness.backchannel.clone();
    probed(&cam, 2, &slot).await;
    assert_eq!(count(&cam.stats().udp_setups), 2, "the video and the audio");
    let session = open(&slot).await.unwrap();
    assert_eq!(count(&cam.stats().backchannel_setups), 1, "interleaved");
    let recorded = talk(&session, &cam, 5, (160, 160)).await;
    check_stream(&recorded, 0, 160, 160);
    drop(session);
    finish(harness).await;
    cam.stop().await;
}

/// A dynamic payload type for PCMU, the only one the camera takes (ONVIF
/// Streaming Specification §5.3.2): every packet carries it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_2_3_a_camera_that_takes_only_its_offered_payload_type_records_every_packet() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |backchannel| {
        backchannel.payload_type = Some(110);
        backchannel.accept_only = Some(110);
    }))
    .await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let slot = harness.backchannel.clone();
    let offer = offered(&slot).await;
    assert_eq!(offer.frame, BackchannelOffer::DEFAULT_FRAME, "no a=ptime");
    let session = open(&slot).await.unwrap();
    let recorded = talk(&session, &cam, 5, (160, 160)).await;
    check_stream(&recorded, 110, 160, 160);
    assert_eq!(count(&cam.stats().backchannel_refused), 0);
    drop(session);
    finish(harness).await;
    cam.stop().await;
}

/// What the probe finds when the camera's answer has a backchannel the
/// source cannot send on, or the camera's own audio is the `sendonly`
/// one: none, or that one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8866_6_7_the_probe_takes_the_first_sendonly_audio_retina_sends_on() {
    // A valueless `a=fmtp` breaks RFC 8866 §6.15's grammar: retina drops
    // the media, so no stream it sends on has the backchannel's payload
    // type, while the offer, which reads no `a=fmtp`, still finds it.
    let cam = camera(config(None, BackchannelCodec::Pcmu, |backchannel| {
        backchannel.attributes = "a=fmtp\r\n".into();
    }))
    .await;
    let unparsed = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(unparsed.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "plays");
    let slot = harness.backchannel.clone();
    probed(&cam, 2, &slot).await;
    assert!(slot.current().is_none());
    finish(harness).await;
    cam.stop().await;
    // The session's `a=sendonly` makes the camera's own audio, which
    // states no direction, the first `sendonly` audio media (§6.7): to
    // the probe, which asks with `Require`, the backchannel (ONVIF
    // Streaming Specification §5.3.2); to the viewing session, which does
    // not, audio the camera sends, and a track.
    let mut config = config(Some(CameraAudio::Pcmu), BackchannelCodec::Pcma, |_| {});
    config.sdp_session_lines = "a=sendonly\r\n".into();
    config.video_fmtp = "\r\na=sendrecv".into();
    let cam = camera(config).await;
    let sendonly = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(sendonly.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "plays");
    let offer = offered(&harness.backchannel).await;
    assert_eq!(offer.codec, Codec::Pcmu);
    assert_eq!(harness.tracks.tracks().len(), 2, "the video and the audio");
    finish(harness).await;
    cam.stop().await;
}

/// The probe waits for its connect permit like any connection attempt;
/// a claim's connection does not, so a talker is served while the probe
/// of a reconnect still waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_bypasses_the_connect_gate_while_the_probe_waits_for_a_permit() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
    let source = source(&cam, &serde_json::Value::Null);
    let (gate, mut asks) = ProbeGate::closed();
    let slot = BackchannelSlot::gated(gate.clone());
    let mut first = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
    assert!(first.wait_ready().await, "ready");
    assert_eq!(bounded(asks.recv()).await, Some(ProbeAsk::Connecting));
    clock().sleep(Duration::from_millis(100)).await;
    assert_eq!(log(&cam).len(), 1, "the probe waits for its permit");
    assert!(slot.is_probing());
    gate.grant();
    probed(&cam, 2, &slot).await;
    assert_eq!(bounded(asks.recv()).await, Some(ProbeAsk::Ended));
    finish(first).await;
    // A reconnect's probe waits again, with the gate busy; the offer the
    // last probe found stands meanwhile, and a claim opens it at once.
    let mut second = Harness::start_with(source.as_ref(), peer(&cam), clock(), slot.clone());
    assert!(second.wait_ready().await, "reconnected");
    assert_eq!(bounded(asks.recv()).await, Some(ProbeAsk::Connecting));
    let offer = slot.current().expect("the last probe's offer");
    let session = tokio::select! {
        opened = offer.opener.open() => opened.unwrap(),
        () = clock().sleep(Duration::from_secs(5)) => panic!("not opened"),
    };
    assert!(slot.is_probing(), "the probe still waits");
    assert!(log(&cam).iter().any(ConnectionLog::backchannel_only));
    assert_eq!(talk(&session, &cam, 2, (160, 160)).await.len(), 2);
    // The attempt ends before the probe got its permit: it gives the ask
    // back and leaves the offer as it was.
    finish(second).await;
    assert_eq!(bounded(asks.recv()).await, Some(ProbeAsk::Ended));
    assert!(!slot.is_probing());
    assert!(slot.current().is_some());
    drop(session);
    cam.stop().await;
}

/// RFC 1122 §4.2.3.4: the backchannel's packets, handed over every 20 ms,
/// reach the camera as evenly. Nagle's algorithm holds a small write until
/// the last is acknowledged: neither retina's connection to the relay nor
/// the relay's to the camera may hold one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc1122_4_2_3_4_the_backchannels_packets_reach_the_camera_as_evenly_as_handed_over() {
    for transport in ["tcp", "udp"] {
        let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
        let source = source(&cam, &json!({ "transport": transport }));
        let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
        assert!(harness.wait_ready().await, "{transport}: ready");
        let session = open(&harness.backchannel).await.unwrap();
        let start = clock().now();
        let mut sent = Vec::new();
        for n in 0..50_u8 {
            let due = start + Duration::from_millis(20) * u32::from(n);
            clock()
                .sleep(due.saturating_duration_since(clock().now()))
                .await;
            let mut packet = uplink(n, 160, 160);
            packet.arrival = clock().now();
            sent.push(packet.arrival);
            session.sender.try_send(packet).unwrap();
        }
        assert!(eventually(250, || cam.stats().backchannel().len() >= 50).await);
        let latencies: Vec<Duration> = cam
            .stats()
            .backchannel()
            .iter()
            .zip(&sent)
            .map(|(packet, sent)| packet.arrival.saturating_duration_since(*sent))
            .collect();
        let least = *latencies.iter().min().unwrap();
        let mut spread: Vec<Duration> = latencies
            .iter()
            .map(|latency| latency.saturating_sub(least))
            .collect();
        spread.sort_unstable();
        let p95 = spread[spread.len() * 95 / 100];
        assert!(
            p95 <= Duration::from_millis(5),
            "{transport}: p95 {p95:?} later than the earliest: {latencies:?}"
        );
        drop(session);
        finish(harness).await;
        cam.stop().await;
    }
}

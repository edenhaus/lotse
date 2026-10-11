//! The RTSP source's ONVIF backchannel (ONVIF Streaming Specification
//! §5.3) against the fake camera of `lotse-testing`: the `Require` header
//! on `DESCRIBE` and its refusal retried without it, remembered for the
//! source's next attempts; the backchannel media set up last, TCP
//! interleaved over either transport, never declared as a track; the
//! handle offered while the session plays and withdrawn after; what the
//! camera records of the packets sent on it; and a refused or failed
//! `SETUP` of it, a stream that asks for none, a media retina does not
//! send on and a packet retina cannot send.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::sync::Arc;
use std::time::Duration;

use lotse_core::clock::{Clock, SystemClock};
use lotse_core::codec::{Codec, Kind};
use lotse_core::media::{MediaPacket, RtpHeaderFields};
use lotse_core::source::{
    BackchannelHandle, ResolvedPeer, Source, SourceError, SourceExit, SourceFactory as _,
};
use lotse_core::source_url::SourceUrl;
use lotse_rtsp::RtspFactory;
use lotse_testing::fake_camera::{
    BackchannelCodec, BackchannelRtp, BackchannelSetup, CameraAudio, CameraBackchannel,
    RequireAnswer, Stats,
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
/// `backchannel`.
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

/// Sends `packets` of `step` ticks and `len` bytes on `handle` and waits
/// until the camera recorded as many: what it recorded.
async fn talk(
    handle: &BackchannelHandle,
    cam: &FakeCamera,
    packets: u8,
    (step, len): (u32, usize),
) -> Vec<BackchannelRtp> {
    let before = cam.stats().backchannel().len();
    for n in 0..packets {
        handle.sender.try_send(uplink(n, step, len)).unwrap();
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

/// Ends the attempt and checks the handle was withdrawn with it.
async fn finish(harness: Harness) -> SourceExit {
    harness.cancel();
    let slot = harness.backchannel.clone();
    let exit = harness.finish().await;
    assert!(slot.current().is_none(), "withdrawn with the session");
    exit
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_2_the_backchannel_is_set_up_last_offered_and_its_packets_reach_the_camera() {
    let cam = camera(config(
        Some(CameraAudio::Pcmu),
        BackchannelCodec::Pcma,
        |backchannel| backchannel.ptime = Some(40),
    ))
    .await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let stats = cam.stats();
    // §5.3.1: asked for with `Require`, answered with the backchannel
    // media, set up after the video and the audio.
    assert_eq!(count(&stats.backchannel_describes), 1);
    assert_eq!(count(&stats.require_rejected), 0);
    assert_eq!(
        (count(&stats.setups), count(&stats.backchannel_setups)),
        (3, 1)
    );
    // Never a track: the camera's own PCMU is the audio.
    let tracks = harness.tracks.tracks();
    assert_eq!(tracks.len(), 2);
    assert_eq!(
        (tracks[1].kind(), tracks[1].codec().as_ref()),
        (Kind::Audio, &Codec::Pcmu)
    );
    // The handle names the backchannel's codec and its `a=ptime` (RFC 8866
    // §6.4) as the frame.
    let handle = harness
        .backchannel
        .current()
        .expect("offered while playing");
    assert_eq!(handle.codec, Codec::Pcma);
    assert_eq!(handle.frame, Duration::from_millis(40));
    let recorded = talk(&handle, &cam, 6, (320, 320)).await;
    check_stream(&recorded, 8, 320, 320);
    assert!(
        matches!(
            finish(harness).await,
            SourceExit::Ended(SourceError::Ended(_))
        ),
        "cancelled"
    );
    assert!(eventually(100, || count(&cam.stats().teardowns) == 1).await);
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_2_1_a_551_or_400_to_require_is_described_again_without_it_and_remembered() {
    for answer in [RequireAnswer::OptionNotSupported, RequireAnswer::BadRequest] {
        let cam = camera(config(None, BackchannelCodec::Pcmu, |backchannel| {
            backchannel.require = answer;
        }))
        .await;
        let source = source(&cam, &serde_json::Value::Null);
        let mut first = Harness::start(source.as_ref(), peer(&cam), clock());
        assert!(first.wait_ready().await, "{answer:?}: plays without it");
        let stats = cam.stats();
        // The refusal, then the same attempt asked again without the
        // header on a fresh connection, at once.
        assert_eq!(count(&stats.require_rejected), 1, "{answer:?}");
        assert_eq!(count(&stats.connections), 2, "{answer:?}");
        assert_eq!(count(&stats.describes), 1, "{answer:?}");
        assert_eq!(count(&stats.backchannel_describes), 0, "{answer:?}");
        assert!(first.backchannel.current().is_none(), "{answer:?}: none");
        assert_eq!(first.tracks.tracks().len(), 1, "{answer:?}: the video");
        let _exit = finish(first).await;
        // The source's next attempt, a reconnect, leaves the header out.
        let mut second = Harness::start(source.as_ref(), peer(&cam), clock());
        assert!(second.wait_ready().await, "{answer:?}");
        assert_eq!(count(&stats.require_rejected), 1, "{answer:?}: remembered");
        assert_eq!(count(&stats.connections), 3, "{answer:?}");
        assert_eq!(count(&stats.describes), 2, "{answer:?}");
        let _exit = finish(second).await;
        cam.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_2_3_a_camera_that_takes_only_its_offered_payload_type_records_every_packet() {
    // A dynamic payload type for PCMU, the only one the camera takes.
    let cam = camera(config(None, BackchannelCodec::Pcmu, |backchannel| {
        backchannel.payload_type = Some(110);
        backchannel.accept_only = Some(110);
    }))
    .await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let handle = harness.backchannel.current().expect("offered");
    assert_eq!(handle.frame, BackchannelHandle::DEFAULT_FRAME, "no a=ptime");
    let recorded = talk(&handle, &cam, 5, (160, 160)).await;
    check_stream(&recorded, 110, 160, 160);
    assert_eq!(count(&cam.stats().backchannel_refused), 0);
    let _exit = finish(harness).await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_39_over_udp_the_backchannel_is_set_up_tcp_interleaved() {
    // The camera answers a UDP `SETUP` of its backchannel with 461.
    let cam = camera(config(
        Some(CameraAudio::Pcmu),
        BackchannelCodec::Pcmu,
        |_| {},
    ))
    .await;
    let source = source(&cam, &json!({ "transport": "udp" }));
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "RTP arrived over UDP");
    let stats = cam.stats();
    assert_eq!(count(&stats.udp_setups), 2, "the video and the audio");
    assert_eq!(count(&stats.backchannel_setups), 1, "interleaved");
    let handle = harness.backchannel.current().expect("offered");
    let recorded = talk(&handle, &cam, 5, (160, 160)).await;
    check_stream(&recorded, 0, 160, 160);
    let _exit = finish(harness).await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_2_a_camera_with_a_backchannel_and_no_audio_of_its_own_declares_video_only() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let tracks = harness.tracks.tracks();
    assert_eq!(tracks.len(), 1, "the backchannel is no audio track");
    assert_eq!(tracks[0].kind(), Kind::Video);
    assert_eq!(count(&cam.stats().backchannel_setups), 1);
    assert_eq!(
        harness.backchannel.current().map(|handle| handle.codec),
        Some(Codec::Pcmu)
    );
    let _exit = finish(harness).await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_11_3_3_a_refused_backchannel_setup_plays_without_it() {
    let cam = camera(config(
        Some(CameraAudio::Pcmu),
        BackchannelCodec::Pcmu,
        |backchannel| backchannel.setup = BackchannelSetup::Busy,
    ))
    .await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "the media play on");
    assert_eq!(count(&cam.stats().backchannel_describes), 1);
    assert_eq!(count(&cam.stats().setups), 2);
    assert_eq!(count(&cam.stats().plays), 1);
    assert!(harness.backchannel.current().is_none(), "none offered");
    assert_eq!(harness.tracks.tracks().len(), 2);
    let _exit = finish(harness).await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_4_a_camera_that_hangs_up_at_the_backchannels_setup_ends_the_attempt() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |backchannel| {
        backchannel.setup = BackchannelSetup::HangUp;
    }))
    .await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(!harness.wait_ready().await, "never plays");
    let slot = harness.backchannel.clone();
    let tracks = Arc::clone(&harness.tracks);
    let exit = harness.finish().await;
    let SourceExit::Ended(error) = &exit else {
        panic!("{exit:?}");
    };
    assert_ne!(
        error,
        &SourceError::Ended("cancelled".into()),
        "the camera ended it"
    );
    // No status: the connection failed, and the attempt ends at the
    // backchannel's `SETUP`, before any track is declared.
    assert!(tracks.tracks().is_empty());
    assert_eq!(count(&cam.stats().plays), 0);
    assert!(slot.current().is_none());
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onvif_5_3_1_a_stream_that_does_not_opt_in_sends_no_require() {
    // Off by default: no option, or `backchannel: false`.
    for options in [
        serde_json::Value::Null,
        json!({}),
        json!({ "backchannel": false }),
    ] {
        let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
        let source = as_given(&cam, &options);
        let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
        assert!(harness.wait_ready().await, "{options}: ready");
        assert_eq!(count(&cam.stats().describes), 1, "{options}");
        assert_eq!(count(&cam.stats().backchannel_describes), 0, "{options}");
        assert!(harness.backchannel.current().is_none(), "{options}");
        let _exit = finish(harness).await;
        cam.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8866_6_7_a_backchannel_retina_sends_on_no_stream_of_plays_without_it() {
    // The session's `a=sendonly` makes the camera's own audio, which
    // states no direction, the first `sendonly` audio media (RFC 8866
    // §6.7); retina reads the media's own attribute only and sends on the
    // PCMA backchannel, whose payload type is another.
    let mut config = config(Some(CameraAudio::Pcmu), BackchannelCodec::Pcma, |_| {});
    config.sdp_session_lines = "a=sendonly\r\n".into();
    config.video_fmtp = "\r\na=sendrecv".into();
    let cam = camera(config).await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "plays");
    assert_eq!(count(&cam.stats().backchannel_describes), 1);
    assert_eq!(count(&cam.stats().backchannel_setups), 0, "never set up");
    assert!(harness.backchannel.current().is_none());
    assert_eq!(harness.tracks.tracks().len(), 2, "the camera's audio stays");
    let _exit = finish(harness).await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_12_a_packet_retina_cannot_send_interleaved_ends_the_attempt() {
    let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
    let source = source(&cam, &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let handle = harness.backchannel.current().expect("offered");
    // RFC 2326 §10.12: an interleaved frame's length has 16 bits.
    handle.sender.try_send(uplink(0, 160, 70_000)).unwrap();
    let slot = harness.backchannel.clone();
    let exit = harness.finish().await;
    assert!(
        matches!(&exit, SourceExit::Ended(SourceError::Protocol(message)) if message.contains("70000")),
        "{exit:?}"
    );
    assert!(slot.current().is_none());
    assert!(cam.stats().backchannel().is_empty());
    cam.stop().await;
}

/// RFC 1122 §4.2.3.4: the backchannel's packets, handed over every 20 ms,
/// reach the camera as evenly, over either transport. Nagle's algorithm
/// holds a small write until the last is acknowledged, and an ACK riding
/// on the camera's next video frame comes up to 33 ms late: neither
/// retina's connection to the relay nor the relay's to the camera may
/// hold one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc1122_4_2_3_4_the_backchannels_packets_reach_the_camera_as_evenly_as_handed_over() {
    for transport in ["tcp", "udp"] {
        let cam = camera(config(None, BackchannelCodec::Pcmu, |_| {})).await;
        let source = source(&cam, &json!({ "transport": transport }));
        let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
        assert!(harness.wait_ready().await, "{transport}: ready");
        let handle = harness.backchannel.current().expect("offered");
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
            handle.sender.try_send(packet).unwrap();
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
        let _exit = finish(harness).await;
        cam.stop().await;
    }
}

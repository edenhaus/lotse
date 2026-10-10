//! The RTSP source against the fake camera of `lotse-testing`: the first
//! rows of the source conformance suite:
//! cut-through packets and side-branch frames, sync hints, credentials,
//! typed errors for unreachable, timeout and ended, cancellation with a
//! teardown, a camera without marker bits, a timestamp reset (one epoch),
//! a reconnect through core's runner (same tracks, one epoch), PCMU audio
//! cut through, AAC audio framed on the side branch, an H.265 camera
//! through the RFC 7798 normalizers, an H.265 camera whose payloads carry
//! decoding order numbers declared unsupported, an SDP retina cannot parse
//! refused and an `m=` line without a format skipped, a keyframe over
//! the libwebrtc packet limit counted and warned about, and a URL whose
//! path, query and password never reach a log line, an error or the
//! description.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lotse_codec::h264::{DEFAULT_MAX_PAYLOAD, nal};
use lotse_core::backoff::ReconnectBackoff;
use lotse_core::clock::{Clock, SystemClock};
use lotse_core::clock_map::{ClockMapper, SyncMode};
use lotse_core::codec::Codec;
use lotse_core::media::{MediaFrame, MediaPacket};
use lotse_core::runner::{ConnectGate, RunnerConfig, RunnerEvent, SourceRunner};
use lotse_core::source::{
    BackchannelSlot, ResolvedPeer, SourceError, SourceExit, SourceFactory as _, TrackSet,
};
use lotse_core::source_url::SourceUrl;
use lotse_core::task::spawn_named;
use lotse_core::track::{
    SubscriptionError, Track, TrackEvent, TrackLimits, TrackSubscription, Unit,
};
use lotse_rtsp::RtspFactory;
use lotse_rtsp::options::RtspOptions;
use lotse_testing::fake_camera::{CameraAudio, CameraVideo};
use lotse_testing::{CameraConfig, FakeCamera, Harness};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

async fn camera(config: CameraConfig) -> FakeCamera {
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

fn make_source(url: &str, options: &serde_json::Value) -> Box<dyn lotse_core::source::Source> {
    let url = SourceUrl::parse(url).expect("url");
    RtspFactory::default()
        .validate(&url, options)
        .expect("valid source")
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

/// What `track` publishes until `done` holds for it, or 10 s passed: its
/// live packets and its side-branch frames.
async fn collect_media(
    track: &Track,
    mut done: impl FnMut(&[Arc<MediaPacket>], &[Arc<MediaFrame>]) -> bool,
) -> (Vec<Arc<MediaPacket>>, Vec<Arc<MediaFrame>>) {
    let mut packets = track.subscribe_packets();
    let mut frames = track.subscribe_frames();
    let mut seen_packets = Vec::new();
    let mut seen_frames = Vec::new();
    let deadline = clock().now() + Duration::from_secs(10);
    while clock().now() < deadline {
        // Everything queued each tick: a packet a tick would fall behind
        // the frames and end the loop with packets still queued.
        loop {
            match packets.try_recv() {
                Ok(Some(packet)) => seen_packets.push(packet),
                Ok(None) | Err(SubscriptionError::Closed) => break,
                Err(SubscriptionError::Lagged(_)) => {}
            }
        }
        loop {
            match frames.try_recv() {
                Ok(Some(frame)) => seen_frames.push(frame),
                Ok(None) | Err(SubscriptionError::Closed) => break,
                Err(SubscriptionError::Lagged(_)) => {}
            }
        }
        if done(&seen_packets, &seen_frames) {
            break;
        }
        clock().sleep(Duration::from_millis(10)).await;
    }
    (seen_packets, seen_frames)
}

/// Two keyframes, twelve frames and twenty packets went by. Over TCP the
/// source is ready at the `PLAY` answer, and the camera sends its first
/// frame right after it: a subscription made once ready sees all of
/// that frame, part of it or none (2026-10-07: 17 packets at twelve
/// frames under load), so the count is waited for, not assumed.
fn two_gops(packets: &[Arc<MediaPacket>], frames: &[Arc<MediaFrame>]) -> bool {
    frames.iter().filter(|f| f.keyframe).count() >= 2 && frames.len() >= 12 && packets.len() >= 20
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h265_flows_cut_through_and_as_frames_with_its_sprop_sets_rfc7798() {
    use lotse_codec::h265;
    let cam = camera(CameraConfig {
        video: CameraVideo::H265,
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let tracks = harness.tracks.tracks();
    let v0 = &tracks[0];
    // RFC 7798 §7.1: the three sets from the SDP, read by retina.
    let Codec::H265 { vps, sps, pps } = v0.codec().as_ref().clone() else {
        panic!("h265 from the SDP");
    };
    assert_eq!(vps.as_deref(), Some(&h265::test_data::vps()[..]));
    assert_eq!(sps.as_deref(), Some(&h265::test_data::sps(640, 480)[..]));
    assert_eq!(pps.as_deref(), Some(&h265::test_data::pps()[..]));

    let (seen_packets, seen_frames) = collect_media(v0, two_gops).await;
    assert!(seen_packets.len() >= 20, "{} packets", seen_packets.len());
    assert!(
        seen_packets
            .iter()
            .all(|p| p.payload.len() <= DEFAULT_MAX_PAYLOAD)
    );
    // Keyframe starts are the camera's own aggregates of the three sets
    // (§4.4.2), the IDR re-split into fragmentation units (§4.4.3).
    let starts: Vec<_> = seen_packets.iter().filter(|p| p.keyframe_start).collect();
    assert!(!starts.is_empty(), "keyframe starts");
    assert!(
        starts
            .iter()
            .all(|p| h265::nal::nal_type(p.payload[0]) == h265::nal::AP)
    );
    assert!(
        seen_packets
            .iter()
            .any(|p| h265::nal::nal_type(p.payload[0]) == h265::nal::FU),
        "re-split IDR"
    );
    // Side branch: Annex B units, keyframes led by the VPS.
    let first = seen_frames.iter().find(|f| f.keyframe).expect("a keyframe");
    assert!(
        first.payload.starts_with(&[0, 0, 0, 1, 0x40, 0x01]),
        "VPS first"
    );
    assert!(seen_frames.iter().any(|f| !f.keyframe), "P frames");
    let ticks: Vec<i64> = seen_frames.iter().map(|f| f.ts.ticks()).collect();
    assert!(ticks.windows(2).all(|w| w[1] - w[0] == 3_000), "{ticks:?}");
    harness.cancel();
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Ended(_))),
        "{exit:?}"
    );
    cam.stop().await;
}

/// RFC 7798 §4.4.1: with `sprop-max-don-diff` above 0 every payload
/// carries a DONL field the normalizers do not read; §7.2.3 has the
/// receiver reject such a value, so the track is declared unsupported and
/// its packets are never parsed as H.265.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h265_with_decoding_order_numbers_is_declared_unsupported_rfc7798_7_2_3() {
    let cam = camera(CameraConfig {
        video: CameraVideo::H265,
        video_fmtp: ";sprop-max-don-diff=2;sprop-depack-buf-nalus=2".into(),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let tracks = harness.tracks.tracks();
    let v0 = &tracks[0];
    let unsupported = Codec::Unsupported {
        kind: lotse_core::codec::Kind::Video,
        name: "h265_don".into(),
    };
    assert_eq!(v0.codec().as_ref(), &unsupported);
    let (seen_packets, seen_frames) = collect_media(v0, |packets, _| packets.len() >= 20).await;
    assert!(seen_packets.len() >= 20, "{} packets", seen_packets.len());
    assert!(seen_frames.is_empty(), "{} frames", seen_frames.len());
    assert_eq!(v0.codec().as_ref(), &unsupported);
    harness.cancel();
    let _exit = harness.finish().await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h264_flows_cut_through_and_as_frames_with_sync_hints_then_tears_down() {
    let cam = camera(CameraConfig::default()).await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let tracks = harness.tracks.tracks();
    assert_eq!(tracks.len(), 1);
    let v0 = &tracks[0];
    assert_eq!(v0.clock_rate(), 90_000);
    let Codec::H264 {
        profile_level_id,
        sps,
        pps,
    } = v0.codec().as_ref().clone()
    else {
        panic!("h264 from the SDP");
    };
    assert_eq!(profile_level_id, Some([0x42, 0xc0, 0x28]));
    assert!(sps.is_some() && pps.is_some(), "sprop-parameter-sets");

    // The camera's Sender Reports go with every 30th frame, the first
    // with the frame right after the `PLAY` answer, which the subscription
    // may have missed: media is collected until a report's frame was seen.
    let mut reports = Vec::new();
    let sent_with = |reports: &[lotse_core::source::ClockReport], packets: &[Arc<MediaPacket>]| {
        reports.iter().position(|report| {
            matches!(report.hint, lotse_core::source::SyncHint::RtcpSenderReport { rtp_ts, .. }
                if packets.iter().any(|p| p.rtp.ts == rtp_ts))
        })
    };
    let (seen_packets, seen_frames) = collect_media(v0, |packets, frames| {
        while let Ok(report) = harness.reports.try_recv() {
            reports.push(report);
        }
        two_gops(packets, frames) && sent_with(&reports, packets).is_some()
    })
    .await;
    // Cut-through: every packet fits the datagram target, keyframe starts
    // are parameter-set aggregates, and access units end with the marker.
    assert!(seen_packets.len() >= 20, "{} packets", seen_packets.len());
    assert!(
        seen_packets
            .iter()
            .all(|p| p.payload.len() <= DEFAULT_MAX_PAYLOAD)
    );
    let starts: Vec<_> = seen_packets.iter().filter(|p| p.keyframe_start).collect();
    assert!(!starts.is_empty(), "keyframe starts");
    assert!(
        starts
            .iter()
            .all(|p| nal::nal_type(p.payload[0]) == nal::STAP_A)
    );
    assert!(seen_packets.iter().any(|p| p.rtp.marker));
    assert!(seen_packets.iter().any(|p| p.frame_start));
    assert!(
        seen_packets
            .iter()
            .any(|p| nal::nal_type(p.payload[0]) == nal::FU_A),
        "re-split IDR"
    );
    // Side branch: Annex B units, keyframes led by the SPS, timestamps 33 ms apart.
    let first = seen_frames.iter().find(|f| f.keyframe).expect("a keyframe");
    assert!(first.payload.starts_with(&[0, 0, 0, 1, 0x67]), "SPS first");
    assert!(seen_frames.iter().any(|f| !f.keyframe), "P frames");
    let ticks: Vec<i64> = seen_frames.iter().map(|f| f.ts.ticks()).collect();
    assert!(ticks.windows(2).all(|w| w[1] - w[0] == 3_000), "{ticks:?}");
    assert!(seen_frames.iter().all(|f| f.epoch == 0 && !f.discontinuity));
    // Sync hints: the camera's Sender Report reached the clock mapper.
    let report = reports.swap_remove(
        sent_with(&reports, &seen_packets).expect("a sender report hint with its frame"),
    );
    let lotse_core::source::SyncHint::RtcpSenderReport { rtp_ts, .. } = report.hint else {
        panic!("a sender report, not {:?}", report.hint);
    };
    assert!(rtp_ts >= 1_000_000);
    assert_eq!(report.clock_rate, 90_000, "the track's declared clock");
    // Fed to the mapper, it maps the track from the camera's clock: the
    // frame it was sent with was captured when it arrived, on loopback.
    assert_eq!(harness.mapper.mode(v0.id()), SyncMode::Arrival);
    harness.mapper.ingest(report);
    assert_eq!(harness.mapper.mode(v0.id()), SyncMode::SenderReports);
    let packet = seen_packets
        .iter()
        .find(|p| p.rtp.ts == rtp_ts)
        .expect("the frame sent with the report");
    let mapped = harness.mapper.map(v0.id(), rtp_ts, packet.arrival);
    let apart = mapped
        .saturating_duration_since(packet.arrival)
        .max(packet.arrival.saturating_duration_since(mapped));
    assert!(apart < Duration::from_millis(50), "{apart:?}");
    // Cancel: the exit says so, and the camera got its TEARDOWN.
    harness.cancel();
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Ended(ref m)) if m == "cancelled"),
        "{exit:?}"
    );
    let counters = cam.stats();
    assert!(
        eventually(50, || lotse_testing::fake_camera::Stats::get(
            &counters.teardowns
        ) == 1)
        .await,
        "teardown sent"
    );
    assert_eq!(lotse_testing::fake_camera::Stats::get(&counters.plays), 1);
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_are_checked_and_never_reported() {
    let cam = camera(CameraConfig {
        auth: Some(("admin".into(), "secret".into())),
        ..CameraConfig::default()
    })
    .await;
    // No credentials, then wrong ones: auth_failed.
    for url in [
        format!("rtsp://{}/stream", cam.addr()),
        format!("rtsp://admin:wrong@{}/stream", cam.addr()),
    ] {
        let source = make_source(&url, &serde_json::Value::Null);
        let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
        assert!(!harness.wait_ready().await);
        let exit = harness.finish().await;
        assert!(
            matches!(exit, SourceExit::Ended(SourceError::AuthFailed(_))),
            "{exit:?}"
        );
    }
    assert!(lotse_testing::fake_camera::Stats::get(&cam.stats().unauthorized) >= 2);
    // The right ones: live, and the description hides them.
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let described = format!("{:?} {}", source.describe(), source.describe().url);
    assert!(!described.contains("secret"), "{described}");
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_port_is_unreachable_and_a_silent_camera_times_out() {
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let source = make_source(&format!("rtsp://{addr}/stream"), &serde_json::Value::Null);
    let mut harness = Harness::start(
        source.as_ref(),
        ResolvedPeer {
            host: "127.0.0.1".into(),
            addrs: vec![addr],
        },
        clock(),
    );
    assert!(!harness.wait_ready().await);
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Unreachable(_))),
        "{exit:?}"
    );

    let cam = camera(CameraConfig {
        silent: true,
        ..CameraConfig::default()
    })
    .await;
    let options = serde_json::to_value(RtspOptions {
        timeout_ms: 200,
        ..RtspOptions::default()
    })
    .unwrap();
    let source = make_source(&cam.url(), &options);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(!harness.wait_ready().await);
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Timeout(ref m)) if m.starts_with("DESCRIBE")),
        "{exit:?}"
    );
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_camera_that_hangs_up_ends_the_source() {
    let cam = camera(CameraConfig {
        packets_before_close: Some(8),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Ended(ref m)) if m == "the camera closed the session"),
        "{exit:?}"
    );
    cam.stop().await;
}

/// A camera whose SDP has a malformed line followed by an attribute
/// (found by the `rtsp_session` fuzz target), which retina once aborted
/// on: a protocol error before any `SETUP`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_sdp_retina_cannot_parse_is_refused_as_protocol_rfc8866_5() {
    let cam = camera(CameraConfig {
        sdp_session_lines: " \r\n".into(),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let harness = Harness::start(source.as_ref(), peer(&cam), clock());
    let exit = harness.finish().await;
    let SourceExit::Ended(SourceError::Protocol(message)) = exit else {
        panic!("a protocol error, not {exit:?}");
    };
    assert!(message.contains("Unable to parse SDP"), "{message}");
    assert_eq!(
        lotse_testing::fake_camera::Stats::get(&cam.stats().setups),
        0
    );
    cam.stop().await;
}

/// A camera whose `DESCRIBE` answer is larger than retina is told to read
/// (`max_message_size`, 64 KiB): a protocol error, not a buffer that grows
/// with whatever the camera sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_describe_answer_over_64_kib_is_refused_as_protocol() {
    let cam = camera(CameraConfig {
        sdp_session_lines: "a=x-pad:0123456789abcdef0123456789abcdef\r\n".repeat(2_000),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let harness = Harness::start(source.as_ref(), peer(&cam), clock());
    // Read in full, the answer would play: the attempt would never end.
    let exit = tokio::select! {
        exit = harness.finish() => exit,
        () = clock().sleep(Duration::from_secs(10)) => panic!("the answer was read"),
    };
    let SourceExit::Ended(SourceError::Protocol(message)) = exit else {
        panic!("a protocol error, not {exit:?}");
    };
    assert!(message.contains("max_message_size"), "{message}");
    cam.stop().await;
}

/// A camera whose SDP has an RTP `m=` line without a format (found by the
/// `rtsp_session` fuzz target), which retina once aborted on: that media
/// description is skipped and the camera's streams play.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_rtp_media_line_without_a_format_is_skipped_rfc8866_5_14() {
    let cam = camera(CameraConfig {
        sdp_session_lines: "m=video 0 RTP/AVP \r\n".into(),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    assert_eq!(harness.tracks.tracks().len(), 1);
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

/// A camera whose SDP describes a metadata stream before its video: the
/// application media is no track, and the video plays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8866_5_14_an_application_stream_is_skipped_and_the_video_plays() {
    let cam = camera(CameraConfig {
        sdp_session_lines:
            "m=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\n".into(),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    assert_eq!(harness.tracks.tracks().len(), 1);
    assert_eq!(
        lotse_testing::fake_camera::Stats::get(&cam.stats().setups),
        1
    );
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

/// A camera whose SDP describes two video streams: the first one is the
/// video track, the second is not set up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc8866_5_14_of_two_video_streams_the_first_plays() {
    let cam = camera(CameraConfig {
        sdp_session_lines: "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n".into(),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    assert_eq!(harness.tracks.tracks().len(), 1);
    assert_eq!(
        lotse_testing::fake_camera::Stats::get(&cam.stats().setups),
        1
    );
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

/// A URL whose request outgrows the relay's bound (64 KiB, as retina
/// reads) before it is whole: the relay refuses retina's `DESCRIBE`, a
/// protocol error before the camera sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_over_64_kib_is_refused_by_the_relay_as_protocol() {
    let cam = camera(CameraConfig::default()).await;
    let url = format!("{}/{}", cam.url(), "x".repeat(200_000));
    let source = make_source(&url, &serde_json::Value::Null);
    let harness = Harness::start(source.as_ref(), peer(&cam), clock());
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Protocol(ref m)) if m.contains("retina's request is unreadable")),
        "{exit:?}"
    );
    assert_eq!(
        lotse_testing::fake_camera::Stats::get(&cam.stats().describes),
        0
    );
    cam.stop().await;
}

/// A scripted camera on one connection: every RTSP request answered with
/// `200 OK`, the `DESCRIBE` with `sdp`, the `SETUP` with an interleaved
/// session, and `after_play` sent after the `PLAY` answer; until the
/// client closes.
async fn answer_with(listener: tokio::net::TcpListener, sdp: &'static str, after_play: &[u8]) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (mut stream, _) = listener.accept().await.unwrap();
    let mut pending = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") else {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            pending.extend_from_slice(&buf[..n]);
            continue;
        };
        let head = String::from_utf8_lossy(&pending[..end]).into_owned();
        pending.drain(..end + 4);
        let cseq = head
            .lines()
            .find_map(|line| line.strip_prefix("CSeq: "))
            .unwrap_or("0");
        let rest = if head.starts_with("DESCRIBE ") {
            format!(
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                sdp.len()
            )
        } else if head.starts_with("SETUP ") {
            "Session: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n".to_owned()
        } else {
            "Session: 1\r\n\r\n".to_owned()
        };
        let answer = format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n{rest}");
        stream.write_all(answer.as_bytes()).await.unwrap();
        if head.starts_with("PLAY ") {
            stream.write_all(after_play).await.unwrap();
        }
    }
}

/// A scripted camera on `127.0.0.1` ([`answer_with`]) and its source.
async fn scripted(
    sdp: &'static str,
    after_play: &'static [u8],
) -> (
    Box<dyn lotse_core::source::Source>,
    ResolvedPeer,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let camera = spawn_named("test.camera", answer_with(listener, sdp, after_play));
    let source = make_source(&format!("rtsp://{addr}/stream"), &serde_json::Value::Null);
    let peer = ResolvedPeer {
        host: "127.0.0.1".into(),
        addrs: vec![addr],
    };
    (source, peer, camera)
}

/// A camera that sends what no RTSP parser reads while it plays: retina's
/// error ends the source as protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_10_12_an_unreadable_message_while_playing_ends_the_source_as_protocol() {
    let (source, peer, camera) = scripted(
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=video\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track0\r\n",
        b"\x01\x02 junk\r\n\r\n",
    )
    .await;
    let harness = Harness::start(source.as_ref(), peer, clock());
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Protocol(_))),
        "{exit:?}"
    );
    camera.await.unwrap();
}

/// A camera whose SDP describes a metadata stream alone: nothing to play,
/// a protocol error before any `SETUP`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_sdp_without_video_or_audio_is_refused_as_protocol_rfc8866_5_14() {
    let (source, peer, camera) = scripted(
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=metadata\r\nt=0 0\r\nm=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\na=control:track0\r\n",
        b"",
    )
    .await;
    let harness = Harness::start(source.as_ref(), peer, clock());
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Protocol(ref m)) if m == "the SDP describes no video or audio stream"),
        "{exit:?}"
    );
    camera.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_camera_without_marker_bits_still_yields_frames() {
    let cam = camera(CameraConfig {
        marker_bit: false,
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    let v0 = harness.tracks.tracks()[0].clone();
    let mut frames = v0.subscribe_frames();
    let mut count = 0;
    assert!(
        eventually(200, || {
            while let Ok(Some(_)) = frames.try_recv() {
                count += 1;
            }
            count >= 5
        })
        .await,
        "frames complete on the next timestamp: {count}"
    );
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

/// The next event of `sub`, within 10 s.
async fn next_event(sub: &mut TrackSubscription) -> TrackEvent {
    tokio::select! {
        event = sub.next() => event.expect("the track is open"),
        () = clock().sleep(Duration::from_secs(10)) => panic!("no track event in 10 s"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timestamp_reset_starts_one_epoch_and_forgets_the_clock_fit() {
    // Mid-GOP, 2 s in, the camera's clock jumps by 0x9000_0000 ticks: back
    // by ~22 000 s on the signed 32-bit clock.
    let jump = 0x9000_0000_u32;
    let cam = camera(CameraConfig {
        timestamp_jump: Some((65, jump)),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await);
    let v0 = harness.tracks.tracks()[0].clone();
    let mut sub = v0.subscribe(Unit::Frames);
    // The first Sender Report maps the track from the camera's clock.
    let report = tokio::select! {
        report = harness.reports.recv() => report.expect("a sender report"),
        () = clock().sleep(Duration::from_secs(10)) => panic!("no sender report"),
    };
    harness.mapper.ingest(report);
    assert_eq!(v0.epoch(), 0, "fitted before the jump");
    assert_eq!(harness.mapper.mode(v0.id()), SyncMode::SenderReports);

    let mut epochs = Vec::new();
    let mut seen = 0;
    let first = loop {
        seen += 1;
        assert!(seen < 200, "no frame of a new epoch in {seen} events");
        match next_event(&mut sub).await {
            TrackEvent::Frame(frame) if frame.epoch == 0 => assert!(!frame.discontinuity),
            TrackEvent::Frame(frame) => break frame,
            TrackEvent::EpochStart { epoch } => epochs.push(epoch),
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(epochs, [1], "one epoch, before its first frame");
    assert!(first.discontinuity);
    assert_eq!(v0.epoch(), 1);
    // The side branch restarts at the camera's new timestamp.
    let expected = lotse_testing::fake_camera::FIRST_TIMESTAMP
        .wrapping_add(65 * 3_000)
        .wrapping_add(jump);
    assert_eq!(first.ts.ticks(), i64::from(expected));
    // The fit of the old timeline is gone; the next report anchors anew.
    assert_eq!(harness.mapper.mode(v0.id()), SyncMode::Arrival);
    // Still one timeline after it: no further epochs.
    for _ in 0..10 {
        if let TrackEvent::Frame(frame) = next_event(&mut sub).await {
            assert_eq!(frame.epoch, 1);
        }
    }
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_keeps_the_tracks_and_starts_one_epoch_for_them() {
    // The camera hangs up about a second into every connection.
    let cam = camera(CameraConfig {
        packets_before_close: Some(40),
        ..CameraConfig::default()
    })
    .await;
    let tracks = TrackSet::new(TrackLimits::default(), clock().now());
    let (tx, mut events) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let runner = SourceRunner::new(
        make_source(&cam.url(), &serde_json::Value::Null),
        peer(&cam),
        Arc::clone(&tracks),
        Arc::new(ClockMapper::new()),
        BackchannelSlot::default(),
        clock(),
        RunnerConfig::default(),
        ReconnectBackoff::new(1),
        tx,
        ConnectGate::open(),
        cancel.clone(),
    );
    let runner = spawn_named("test.runner", runner.run());
    assert_eq!(
        events.recv().await,
        Some(RunnerEvent::Connecting { attempt: 1 })
    );
    assert_eq!(events.recv().await, Some(RunnerEvent::Live));
    let v0 = tracks.tracks()[0].clone();
    let mut sub = v0.subscribe(Unit::Frames);
    let Some(RunnerEvent::Reconnecting { error }) = events.recv().await else {
        panic!("the hang-up is retried at once");
    };
    assert_eq!(error.code(), "source_ended", "{error}");
    assert_eq!(events.recv().await, Some(RunnerEvent::Live));

    // The same track, one epoch later.
    let now = tracks.tracks();
    assert_eq!(now.len(), 1);
    assert!(Arc::ptr_eq(&now[0], &v0));
    assert_eq!(v0.epoch(), 1);
    // Subscribers see the loss, the epoch and the restore, then the new
    // connection's frames, a keyframe first.
    let mut control = Vec::new();
    let first = loop {
        match next_event(&mut sub).await {
            TrackEvent::Frame(frame) if frame.epoch == 0 => {}
            TrackEvent::Frame(frame) => break frame,
            event => control.push(event),
        }
    };
    assert_eq!(
        control,
        [
            TrackEvent::SourceLost,
            TrackEvent::EpochStart { epoch: 1 },
            TrackEvent::SourceRestored
        ]
    );
    assert!(first.keyframe && first.discontinuity);
    assert!(lotse_testing::fake_camera::Stats::get(&cam.stats().connections) >= 2);

    cancel.cancel();
    while let Some(event) = events.recv().await {
        if event == RunnerEvent::Stopped {
            break;
        }
    }
    runner.await.unwrap();
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_camera_with_pcmu_audio_declares_both_tracks_and_cuts_audio_through() {
    let cam = camera(CameraConfig {
        audio: Some(CameraAudio::Pcmu),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let tracks = harness.tracks.tracks();
    assert_eq!(tracks.len(), 2, "video and audio");
    let a0 = tracks
        .iter()
        .find(|t| t.kind() == lotse_core::codec::Kind::Audio)
        .expect("an audio track")
        .clone();
    assert_eq!(*a0.codec(), Codec::Pcmu);
    assert_eq!(a0.clock_rate(), 8_000, "RFC 3551 §4.5.14");
    // RFC 3551 §4.5.14: one 20 ms G.711 packet is one frame, cut through.
    let mut packets = a0.subscribe_packets();
    let mut seen = Vec::new();
    assert!(
        eventually(200, || {
            while let Ok(Some(packet)) = packets.try_recv() {
                seen.push(packet);
            }
            seen.len() >= 20
        })
        .await,
        "audio flows: {}",
        seen.len()
    );
    assert!(seen.iter().all(|p| p.frame_start && p.payload.len() == 160));
    assert!(
        seen.windows(2)
            .all(|w| w[1].rtp.ts.wrapping_sub(w[0].rtp.ts) == 160)
    );
    // Sender Reports for both tracks reach the clock mapper's channel.
    let mut reported = std::collections::BTreeSet::new();
    assert!(
        eventually(100, || {
            while let Ok(report) = harness.reports.try_recv() {
                reported.insert(report.track);
            }
            reported.len() == 2
        })
        .await,
        "sender reports for video and audio: {reported:?}"
    );
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc2326_12_33_a_play_answer_without_rtptime_plays_two_streams_on_the_first_attempt() {
    // MediaMTX 1.21.1 answers a path's first reader so (observed
    // 2026-10-06): `seq` without `rtptime`. Timing comes from Sender
    // Reports and arrival, never from `rtptime`.
    let cam = camera(CameraConfig {
        audio: Some(CameraAudio::Pcmu),
        omit_rtptime: true,
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "live on the first attempt");
    let tracks = harness.tracks.tracks();
    assert_eq!(tracks.len(), 2, "video and audio");
    for track in &tracks {
        let mut packets = track.subscribe_packets();
        assert!(
            eventually(200, || matches!(packets.try_recv(), Ok(Some(_)))).await,
            "{} flows",
            track.id()
        );
    }
    let counters = cam.stats();
    assert_eq!(lotse_testing::fake_camera::Stats::get(&counters.plays), 1);
    assert_eq!(
        lotse_testing::fake_camera::Stats::get(&counters.connections),
        1
    );
    harness.cancel();
    let exit = harness.finish().await;
    assert!(
        matches!(exit, SourceExit::Ended(SourceError::Ended(ref m)) if m == "cancelled"),
        "{exit:?}"
    );
    cam.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3640_aac_audio_is_framed_on_the_side_branch() {
    let cam = camera(CameraConfig {
        audio: Some(CameraAudio::Aac),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let a0 = harness
        .tracks
        .tracks()
        .into_iter()
        .find(|t| t.kind() == lotse_core::codec::Kind::Audio)
        .expect("an audio track");
    assert_eq!(
        *a0.codec(),
        Codec::AacLc {
            sample_rate: 16_000,
            channels: 1,
            config: bytes::Bytes::from_static(&[0x14, 0x08])
        }
    );
    // RFC 3640 §3.3.6: the AU header section is gone, each unit is one
    // raw AAC frame of 1024 samples, in the track's 16 kHz clock.
    let mut frames = a0.subscribe_frames();
    let mut seen = Vec::new();
    assert!(
        eventually(250, || {
            while let Ok(Some(frame)) = frames.try_recv() {
                seen.push(frame);
            }
            seen.len() >= 5
        })
        .await,
        "AAC frames flow: {}",
        seen.len()
    );
    let recorded = lotse_codec::aac::test_data::frames(lotse_codec::aac::test_data::SINE_16K_MONO);
    assert!(
        seen.iter()
            .all(|f| f.keyframe && recorded.contains(&&f.payload[..]))
    );
    assert!(
        seen.windows(2)
            .all(|w| w[1].ts.checked_sub(w[0].ts) == Some(1024))
    );
    harness.cancel();
    harness.finish().await;
    cam.stop().await;
}

/// A log writer that keeps every line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn libwebrtc_max_frame_packets_a_larger_keyframe_is_counted_and_warned_about() {
    // Every other keyframe is 2.5 MB: about 2180 packets at the payload
    // target, more than some libwebrtc receivers assemble.
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let _logs = tracing::subscriber::set_default(subscriber);
    let cam = camera(CameraConfig {
        fps: 10,
        gop: 3,
        alternate_idr_bytes: Some(2_500_000),
        ..CameraConfig::default()
    })
    .await;
    let source = make_source(&cam.url(), &serde_json::Value::Null);
    let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
    assert!(harness.wait_ready().await, "ready");
    let v0 = Arc::clone(&harness.tracks.tracks()[0]);
    // Two within the summary interval: counted twice, warned about once.
    assert!(
        eventually(500, || v0.stats().frames_over_browser_limit >= 2).await,
        "{:?}",
        v0.stats()
    );
    harness.cancel();
    let _exit = harness.finish().await;
    cam.stop().await;
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let warnings: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("frame_over_browser_limit"))
        .collect();
    assert_eq!(warnings.len(), 1, "{logs}");
    let warning = warnings[0];
    assert!(
        warning.contains("WARN")
            && warning.contains("codec=\"h264\"")
            && warning.contains("limit=2047")
            && warning.contains("keyframe=true")
            && warning.contains("substream"),
        "{warning}"
    );
}

/// A camera key in the path, a token in the query and a password: none
/// of them in any log line (down to `trace`), in the exit of a failed or a
/// cancelled session, or in the description.
#[tokio::test(flavor = "current_thread")]
async fn a_urls_path_query_and_password_reach_no_log_error_or_description() {
    const SECRETS: [&str; 3] = ["camkey7f3a", "tok9d2e", "pw5b1c"];
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _logs = tracing::subscriber::set_default(subscriber);
    let cam = camera(CameraConfig {
        auth: Some(("admin".into(), "pw5b1c".into())),
        ..CameraConfig::default()
    })
    .await;
    let mut printed = Vec::new();
    for (password, plays) in [("wrong", false), ("pw5b1c", true)] {
        let url = format!(
            "rtsp://admin:{password}@{}/camkey7f3a/live?token=tok9d2e",
            cam.addr()
        );
        let source = make_source(&url, &serde_json::Value::Null);
        let described = source.describe();
        assert_eq!(
            described.url.to_string(),
            format!("rtsp://****@{}/****?****", cam.addr())
        );
        printed.push(format!("{described:?} {} {source:?}", described.url));
        let mut harness = Harness::start(source.as_ref(), peer(&cam), clock());
        assert_eq!(harness.wait_ready().await, plays, "{password}");
        harness.cancel();
        let exit = harness.finish().await;
        printed.push(format!("{exit:?}"));
        if let SourceExit::Ended(error) = exit {
            printed.push(error.to_string());
        }
    }
    cam.stop().await;
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("rtsp: describing"), "{logs}");
    let printed = printed.join("\n");
    assert!(printed.contains("AuthFailed"), "{printed}");
    for secret in SECRETS {
        assert!(!logs.contains(secret), "{secret} logged:\n{logs}");
        assert!(!printed.contains(secret), "{secret} printed:\n{printed}");
    }
}

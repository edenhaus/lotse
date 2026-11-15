#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use std::io::Write as _;

use lotse_api::{Handler as _, Outcome};
use lotse_api_types::hls::PLAYLIST_NAME;
use lotse_core::clock::{Clock, FakeClock, SystemClock};
use lotse_core::let_assert;
use lotse_hls::{Blocking, Resource};
use lotse_ipc::STOPPED_AS_ASKED;
use lotse_ipc::fragments::header;
use serde_json::{Value, json};

use super::*;
use crate::handler::tests::{
    LIVE_MIME, blocking_worker, call, call_on, demand, error, intercept, live_closed, live_report,
    live_started, next, put, result, session_settings, settle, started, within,
};
use crate::handler::{Environment, Supervisor};
use crate::live::LiveLimits;
use crate::test_support::{Captured, environment, private_dir};

/// The environment of a supervisor with the fake live container, whose
/// workers run `binary`.
fn live_environment(binary: &str) -> Environment {
    let mut environment = environment(binary);
    environment.registries.live = Some(Arc::new(
        lotse_core::test_util::FakeLiveMuxerFactory::default(),
    ));
    environment
}

/// A supervisor with LL-HLS under `limits`, on `clock`, with stream `front`
/// put, and the commands its connection's driver gets.
async fn rig(
    dir: &std::path::Path,
    limits: HlsLimits,
    clock: Arc<dyn Clock>,
) -> (Arc<Supervisor>, mpsc::Receiver<DriverCommand>) {
    let mut settings = session_settings();
    settings.limits.hls = Some(limits);
    let s = Arc::new(Supervisor::new(
        settings,
        live_environment(&blocking_worker(dir)),
        clock,
    ));
    result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
    let commands = intercept(&s, 32);
    (s, commands)
}

fn hls_create(id: u64, stream_id: &str, audio: bool) -> String {
    json!({ "id": id, "type": "hls/create", "stream_id": stream_id, "audio": audio }).to_string()
}

/// `hls/create` in a task of its own, as it waits for the start.
fn spawn_create(s: &Arc<Supervisor>, id: u64, audio: bool) -> tokio::task::JoinHandle<Outcome> {
    let s = Arc::clone(s);
    spawn_named("test.hls_create", async move {
        call(&s, &hls_create(id, "front", audio)).await
    })
}

/// The start the driver gets: the live output's spec and its pipe's write
/// end.
async fn output_start(commands: &mut mpsc::Receiver<DriverCommand>) -> (LiveSpec, std::fs::File) {
    let_assert!(Some(DriverCommand::StartLive { spec, pipe }) = within(commands.recv()).await);
    (spec, std::fs::File::from(pipe))
}

/// A record of `kind` with `bytes`, header first.
fn record(kind: RecordKind, bytes: &[u8]) -> Vec<u8> {
    let mut record = header(kind, bytes.len()).unwrap().to_vec();
    record.extend_from_slice(bytes);
    record
}

fn fragment(independent: bool, ms: u64) -> RecordKind {
    RecordKind::Fragment {
        independent,
        duration: Duration::from_millis(ms),
    }
}

/// A first segment of ten 100 ms frames and the next segment's keyframe:
/// five 200 ms parts, then the first part of segment 1 open.
fn first_segment() -> Vec<u8> {
    let mut bytes = record(RecordKind::Init, b"init");
    for frame in 0..11 {
        bytes.extend(record(fragment(frame % 10 == 0, 100), &[frame; 4]));
    }
    bytes
}

/// The feed of `live_id`'s output.
fn feed(s: &Supervisor, live_id: &str) -> Arc<Feed> {
    Arc::clone(&s.shared.lock().hls.outputs[live_id].feed)
}

/// Waits until `live_id`'s window was made and published `parts` parts.
async fn published(s: &Supervisor, live_id: &str, parts: u64) {
    let mut published = feed(s, live_id).published.subscribe();
    within(published.wait_for(|n| *n > parts)).await.unwrap();
}

fn hls_id(answer: &Value) -> HlsId {
    HlsId::new(answer["hls_id"].as_str().unwrap()).unwrap()
}

fn playlist(blocking: Blocking) -> HlsRequest {
    HlsRequest::Playlist(blocking)
}

/// Starts an output through a first session: its live id, pipe, the
/// session's id and events.
async fn first_session(
    s: &Arc<Supervisor>,
    commands: &mut mpsc::Receiver<DriverCommand>,
) -> (String, std::fs::File, HlsId, mpsc::Receiver<Event>) {
    let create = spawn_create(s, 2, true);
    let (spec, pipe) = output_start(commands).await;
    live_report(s, &spec.live_id, live_started());
    let (answer, events) = started(within(create).await.unwrap());
    let_assert!(Some(DriverCommand::FetchLive { .. }) = within(commands.recv()).await);
    (spec.live_id, pipe, hls_id(&answer), events)
}

/// Shuts `s` down on `clock`, moving it on until the workers' budget
/// passes. A test on a fake clock moves it less than the worker's silence
/// limit (10 s) before, so the worker stays.
async fn stop(s: &Arc<Supervisor>, clock: &FakeClock) {
    let stopping = {
        let s = Arc::clone(s);
        spawn_named("test.hls_stop", async move { s.shutdown().await })
    };
    while !stopping.is_finished() {
        clock.advance(Duration::from_millis(100));
        SystemClock.sleep(Duration::from_millis(5)).await;
    }
}

/// Requests `request` of session `id` in a task of its own, as it may
/// block.
fn spawn_request(
    s: &Arc<Supervisor>,
    id: &HlsId,
    request: HlsRequest,
) -> tokio::task::JoinHandle<Result<(HlsReply, InFlight), HlsError>> {
    let s = Arc::clone(s);
    let id = id.clone();
    spawn_named("test.hls_request", async move { s.hls(&id, request).await })
}

#[test]
fn a_pipe_is_read_64_kib_at_most_at_once() {
    assert_eq!(READ_BYTES, 65_536);
}

#[test]
fn the_default_limits_are_the_documented_ones_and_make_the_window_s_config() {
    assert_eq!(
        HlsLimits::DEFAULT,
        HlsLimits {
            max_outputs: 8,
            max_sessions: 32,
            max_sessions_per_stream: 8,
            window_bytes: 32 << 20,
            part_target: Duration::from_millis(200),
            segment_target: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(30),
            max_blocked_per_session: 4,
            max_blocked: 128,
            max_requests_per_session: 8,
            max_requests: 256,
        }
    );
    assert_eq!(HlsLimits::DEFAULT.window(), Config::default());
}

#[test]
fn a_session_ends_with_its_live_output_s_reason_but_what_only_a_fetched_body_ends_with() {
    for (live, hls) in [
        (LiveCloseReason::Closed, HlsCloseReason::Closed),
        (
            LiveCloseReason::SessionClosed,
            HlsCloseReason::SessionClosed,
        ),
        (
            LiveCloseReason::StreamDeleted,
            HlsCloseReason::StreamDeleted,
        ),
        (
            LiveCloseReason::StreamChanged,
            HlsCloseReason::StreamChanged,
        ),
        (LiveCloseReason::CodecChanged, HlsCloseReason::CodecChanged),
        (LiveCloseReason::NoVideoTrack, HlsCloseReason::NoVideoTrack),
        (
            LiveCloseReason::SourceNotLive,
            HlsCloseReason::SourceNotLive,
        ),
        (
            LiveCloseReason::WorkerCrashed,
            HlsCloseReason::WorkerCrashed,
        ),
        (LiveCloseReason::ShuttingDown, HlsCloseReason::ShuttingDown),
        (LiveCloseReason::ClientGone, HlsCloseReason::InternalError),
        (LiveCloseReason::NotFetched, HlsCloseReason::InternalError),
        (
            LiveCloseReason::InternalError,
            HlsCloseReason::InternalError,
        ),
    ] {
        assert_eq!(hls_reason(live), hls, "{live}");
    }
    for (hls, live) in [
        (
            HlsCloseReason::SourceNotLive,
            LiveCloseReason::SourceNotLive,
        ),
        (HlsCloseReason::ShuttingDown, LiveCloseReason::ShuttingDown),
        (
            HlsCloseReason::InternalError,
            LiveCloseReason::InternalError,
        ),
        (HlsCloseReason::WindowFull, LiveCloseReason::Closed),
        (HlsCloseReason::Idle, LiveCloseReason::Closed),
        (HlsCloseReason::Closed, LiveCloseReason::Closed),
    ] {
        assert_eq!(live_reason(hls), live, "{hls}");
    }
}

#[test]
fn an_output_ended_before_its_start_refuses_its_creates_with_why() {
    for (reason, code) in [
        (HlsCloseReason::NoVideoTrack, ErrorCode::NoVideoTrack),
        (HlsCloseReason::SourceNotLive, ErrorCode::SourceNotLive),
        (HlsCloseReason::WorkerCrashed, ErrorCode::WorkerCrashed),
        (HlsCloseReason::ShuttingDown, ErrorCode::ShuttingDown),
        (HlsCloseReason::StreamDeleted, ErrorCode::StreamNotFound),
        (HlsCloseReason::WindowFull, ErrorCode::InternalError),
    ] {
        assert_eq!(start_error(reason).code, code, "{reason}");
    }
    assert_eq!(
        start_error(HlsCloseReason::CodecChanged).details["reason"],
        "codec_changed"
    );
    assert_eq!(Start::Starting.outcome(), None);
}

/// The whole path: `hls/create` starts a framed live output, raises
/// demand, answers once the worker started it with the MIME type and the
/// playlist's path, and tells the worker its reader took it; the window
/// fills from the pipe and answers the playlist, the init segment, a part
/// and a segment; `hls/close` ends the session and, its last, the output.
#[tokio::test]
async fn rfc8216bis_6_2_5_2_an_hls_session_serves_its_output_s_window_until_it_closes() {
    let dir = private_dir("hls-path");
    let (s, mut commands) = rig(&dir, HlsLimits::DEFAULT, Arc::new(SystemClock)).await;
    let info = result(call(&s, r#"{"id":1,"type":"info"}"#).await);
    assert_eq!(info["outputs"], json!(["live", "hls"]));
    let create = spawn_create(&s, 2, true);
    let (spec, mut pipe) = output_start(&mut commands).await;
    assert!(spec.framed && spec.audio);
    assert_eq!(spec.buffer_bytes, LiveLimits::DEFAULT.buffer_bytes);
    assert_eq!(demand(&s).viewers, 1, "an LL-HLS output is a viewer");
    assert!(!create.is_finished(), "it waits for the init segment");
    live_report(&s, &spec.live_id, live_started());
    let (answer, mut events) = started(within(create).await.unwrap());
    let id = hls_id(&answer);
    assert_eq!(
        answer,
        json!({ "hls_id": id.as_str(), "mime": LIVE_MIME,
                "playlist": format!("/v0/hls/{id}/{PLAYLIST_NAME}") })
    );
    let_assert!(Some(DriverCommand::FetchLive { live_id }) = within(commands.recv()).await);
    assert_eq!(live_id, spec.live_id);
    // A blocking reload waits for the segment it asks for.
    let reload = spawn_request(&s, &id, playlist(Blocking::Segment { msn: 1 }));
    pipe.write_all(&first_segment()).unwrap();
    published(&s, &spec.live_id, 5).await;
    settle().await;
    assert!(!reload.is_finished(), "segment 1 is not complete");
    let_assert!(
        Ok((HlsReply::Playlist(text), _)) = within(s.hls(&id, playlist(Blocking::None))).await
    );
    assert!(text.contains("#EXT-X-TARGETDURATION:1\n"), "{text}");
    let_assert!(
        Ok((HlsReply::Media(init), _)) =
            within(s.hls(&id, HlsRequest::Media(Resource::Init))).await
    );
    assert_eq!(init.as_slice().concat(), b"init");
    let_assert!(
        Ok((HlsReply::Media(part), _)) =
            within(s.hls(&id, HlsRequest::Media(Resource::Part { msn: 0, index: 1 }))).await
    );
    assert_eq!(part.len(), 8);
    let_assert!(
        Ok((HlsReply::Media(segment), _)) =
            within(s.hls(&id, HlsRequest::Media(Resource::Segment { msn: 0 }))).await
    );
    assert_eq!(segment.len(), 40);
    assert_eq!(
        within(s.hls(&id, HlsRequest::Media(Resource::Segment { msn: 9 })))
            .await
            .err(),
        Some(HlsError::ResourceNotFound)
    );
    assert_eq!(
        within(s.hls(&id, playlist(Blocking::Segment { msn: 9 })))
            .await
            .err(),
        Some(HlsError::BadRequest)
    );
    // Segment 1 completes: the blocked reload is answered.
    for frame in 0..10 {
        pipe.write_all(&record(fragment(frame == 9, 100), &[frame; 4]))
            .unwrap();
    }
    let_assert!(Ok(Ok((HlsReply::Playlist(text), _))) = within(reload).await);
    assert!(text.contains("seg1.m4s"), "{text}");
    let close = json!({ "id": 3, "type": "hls/close", "hls_id": id.as_str() });
    assert_eq!(result(call(&s, &close.to_string()).await), json!({}));
    assert_eq!(
        next(&mut events).await,
        json!({ "type": "closed", "hls_id": id.as_str(), "reason": "closed" })
    );
    assert!(events.recv().await.is_none(), "closed is the last event");
    let_assert!(Some(DriverCommand::StopLive { live_id }) = within(commands.recv()).await);
    assert_eq!(live_id, spec.live_id, "its last session left");
    live_report(&s, &spec.live_id, live_closed(STOPPED_AS_ASKED));
    assert!(s.shared.lock().lives.is_empty());
    assert_eq!(demand(&s).viewers, 0);
    let err = error(call(&s, &close.to_string()).await);
    assert_eq!(
        (err.code, &err.details["hls_id"]),
        (ErrorCode::HlsNotFound, &json!(id.as_str()))
    );
    assert_eq!(
        within(s.hls(&id, playlist(Blocking::None))).await.err(),
        Some(HlsError::NotFound)
    );
    s.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// Sessions of one stream and audio choice share one output, those of the
/// other choice get their own; a session joining a started output is
/// answered at once, and gets the output's warning; the limits refuse a
/// session or an output past them, each cap warned once per interval.
#[tokio::test]
async fn sessions_share_an_output_per_audio_choice_within_the_limits() {
    let captured = Captured::default();
    let _logs = captured.install();
    let dir = private_dir("hls-share");
    let limits = HlsLimits {
        max_outputs: 2,
        max_sessions: 3,
        max_sessions_per_stream: 3,
        ..HlsLimits::DEFAULT
    };
    let (s, mut commands) = rig(&dir, limits, Arc::new(SystemClock)).await;
    let err = error(call(&s, &hls_create(1, "bad id", true)).await);
    assert_eq!(err.code, ErrorCode::InvalidStreamId);
    let err = error(call(&s, &hls_create(1, "back", true)).await);
    assert_eq!(err.code, ErrorCode::StreamNotFound);
    let create = spawn_create(&s, 2, true);
    let (spec, _pipe) = output_start(&mut commands).await;
    let warning = lotse_ipc::LiveReport::Warning {
        code: "audio_omitted".into(),
        message: "pcmu".into(),
    };
    live_report(&s, &spec.live_id, warning);
    live_report(&s, &spec.live_id, live_started());
    let (first, mut first_events) = started(within(create).await.unwrap());
    assert_eq!(
        next(&mut first_events).await,
        json!({ "type": "warning", "code": "audio_omitted", "message": "pcmu" })
    );
    let (second, mut second_events) = started(within(spawn_create(&s, 3, true)).await.unwrap());
    assert_ne!(first["hls_id"], second["hls_id"]);
    assert_eq!(second["mime"], LIVE_MIME);
    assert_eq!(next(&mut second_events).await["code"], "audio_omitted");
    let_assert!(Some(DriverCommand::FetchLive { .. }) = within(commands.recv()).await);
    assert!(
        commands.try_recv().is_err(),
        "the second joined the first's output"
    );
    assert_eq!(demand(&s).viewers, 1);
    // The other audio choice starts its own output.
    let video = spawn_create(&s, 4, false);
    let (video_spec, _video_pipe) = output_start(&mut commands).await;
    assert!(!video_spec.audio);
    // Its warning reaches its own sessions only: the first output's next
    // event is its close.
    let video_warning = lotse_ipc::LiveReport::Warning {
        code: "audio_omitted".into(),
        message: "video".into(),
    };
    live_report(&s, &video_spec.live_id, video_warning);
    assert_eq!(demand(&s).viewers, 2);
    let err = error(call(&s, &hls_create(5, "front", true)).await);
    assert_eq!(err.details["limit"], "max_hls_sessions");
    s.shared.lock().hls.limits = Some(HlsLimits {
        max_sessions: 9,
        ..limits
    });
    let err = error(call(&s, &hls_create(6, "front", true)).await);
    assert_eq!(err.details["limit"], "max_hls_sessions_per_stream");
    // A second stream finds every output taken.
    result(call(&s, &put("back", "fake://127.0.0.1:2/", false)).await);
    for id in [7, 8] {
        let err = error(call(&s, &hls_create(id, "back", true)).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("max_hls_outputs"))
        );
    }
    let refused = captured.lines("LL-HLS refused at its limit");
    for limit in [
        "max_hls_sessions\"",
        "max_hls_sessions_per_stream",
        "max_hls_outputs",
    ] {
        assert_eq!(
            refused.iter().filter(|line| line.contains(limit)).count(),
            1,
            "{limit}: the first and none more within the interval: {refused:?}"
        );
    }
    // An output is a live output: the live limits hold it too.
    s.shared.lock().hls.limits = Some(HlsLimits {
        max_outputs: 9,
        max_sessions: 9,
        ..limits
    });
    s.shared.lock().live_limits.max_live = 2;
    let err = error(call(&s, &hls_create(9, "back", true)).await);
    assert_eq!(err.details["limit"], "max_live");
    let lines = captured.lines("live output refused at its limit");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("hls/create"), "{lines:?}");
    live_report(&s, &video_spec.live_id, live_closed("no_video_track"));
    let err = error(within(video).await.unwrap());
    assert_eq!(err.code, ErrorCode::NoVideoTrack);
    assert!(err.details["hls_id"].is_string());
    s.shutdown().await;
    assert_eq!(next(&mut first_events).await["reason"], "shutting_down");
    assert_eq!(next(&mut second_events).await["reason"], "shutting_down");
    std::fs::remove_dir_all(dir).unwrap();
}

/// No LL-HLS without the limits a build with it resolves, nor without a
/// live container to make its outputs.
#[tokio::test]
async fn a_build_without_ll_hls_refuses_every_session() {
    let dir = private_dir("hls-none");
    for (hls, live) in [(None, true), (Some(HlsLimits::DEFAULT), false)] {
        let mut settings = session_settings();
        settings.limits.hls = hls;
        let environment = if live {
            live_environment(&blocking_worker(&dir))
        } else {
            environment(&blocking_worker(&dir))
        };
        let s = Supervisor::new(settings, environment, Arc::new(SystemClock));
        let info = result(call(&s, r#"{"id":1,"type":"info"}"#).await);
        assert!(!info["outputs"].as_array().unwrap().contains(&json!("hls")));
        result(call(&s, &put("front", "fake://127.0.0.1:1/", false)).await);
        let err = error(call(&s, &hls_create(2, "front", true)).await);
        assert_eq!(
            (err.code, &err.details["limit"]),
            (ErrorCode::LimitReached, &json!("max_hls_outputs"))
        );
        s.shutdown().await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// A start no worker answers within the live start timeout and its slack
/// ends the output `source_not_live`, its stop asked of the worker, and
/// every create waiting for it with it; a session that ended while its
/// create waited is no session once the output starts.
#[tokio::test]
async fn an_output_not_started_in_time_refuses_every_create_waiting_for_it() {
    let dir = private_dir("hls-start");
    let clock = Arc::new(FakeClock::from_system());
    let (s, mut commands) = rig(&dir, HlsLimits::DEFAULT, clock.clone()).await;
    let start_timeout = Duration::from_secs(1);
    s.shared.lock().live_limits.start_timeout = start_timeout;
    let first = spawn_create(&s, 2, true);
    let (spec, _pipe) = output_start(&mut commands).await;
    let second = spawn_create(&s, 3, true);
    settle().await;
    assert_eq!(s.shared.lock().hls.sessions.len(), 2);
    clock.advance(start_timeout + LIVE_CREATE_SLACK);
    for create in [first, second] {
        let err = error(within(create).await.unwrap());
        assert_eq!(err.code, ErrorCode::SourceNotLive);
    }
    let_assert!(Some(DriverCommand::StopLive { live_id }) = within(commands.recv()).await);
    assert_eq!(live_id, spec.live_id);
    assert!(s.shared.lock().hls.sessions.is_empty());
    let create = spawn_create(&s, 4, true);
    let (spec, _pipe) = output_start(&mut commands).await;
    settle().await;
    // The session leaves its id; one in its place keeps the output.
    let waiting = {
        let mut state = s.shared.lock();
        let waiting = state.hls.sessions.keys().next().unwrap().clone();
        let moved = state.hls.sessions.remove(&waiting).unwrap();
        state.hls.sessions.insert("other".into(), moved);
        waiting
    };
    live_report(&s, &spec.live_id, live_started());
    let err = error(within(create).await.unwrap());
    assert_eq!(
        (err.code, &err.details["hls_id"]),
        (ErrorCode::HlsNotFound, &json!(waiting))
    );
    stop(&s, &clock).await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// The output ends with its live output, every session with the reason
/// mapped from the worker's: a codec change, a stream deleted (asked of the
/// worker first), the worker gone.
#[tokio::test]
async fn an_output_ends_its_sessions_with_its_live_output_s_reason() {
    let dir = private_dir("hls-ends");
    for reason in ["codec_changed", "stream_deleted", "worker_crashed"] {
        let (s, mut commands) = rig(&dir, HlsLimits::DEFAULT, Arc::new(SystemClock)).await;
        let (live_id, _pipe, id, mut events) = first_session(&s, &mut commands).await;
        match reason {
            "codec_changed" => live_report(&s, &live_id, live_closed(reason)),
            "stream_deleted" => {
                let delete = json!({ "id": 9, "type": "stream/delete", "stream_id": "front" });
                result(call(&s, &delete.to_string()).await);
                let_assert!(Some(DriverCommand::StopLive { .. }) = within(commands.recv()).await);
            }
            _ => s.shared.lock().lives_worker_gone("c1"),
        }
        assert_eq!(
            next(&mut events).await,
            json!({ "type": "closed", "hls_id": id.as_str(), "reason": reason })
        );
        assert!(events.recv().await.is_none());
        assert!(commands.try_recv().is_err(), "no stop: the output is gone");
        assert!(s.shared.lock().hls.outputs.is_empty());
        s.shutdown().await;
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// A session ends `session_closed` with its control connection; one
/// unsubscribed ends without `closed`, the `unsubscribe` answering for it.
#[tokio::test]
async fn a_session_ends_with_its_subscription_or_control_connection() {
    let dir = private_dir("hls-owner");
    let (s, mut commands) = rig(&dir, HlsLimits::DEFAULT, Arc::new(SystemClock)).await;
    let (live_id, _pipe, _id, mut first) = first_session(&s, &mut commands).await;
    let create = |id: u64| json!({ "id": id, "type": "hls/create", "stream_id": "front" });
    // The same control connection's later subscription, and another's.
    let (_answer, mut later) = started(within(call_on(&s, 1, &create(3))).await);
    let (_answer, mut other) = started(within(call_on(&s, 7, &create(4))).await);
    assert!(s.unsubscribed(ConnectionId(1), 3).is_none());
    assert!(
        within(later.recv()).await.is_none(),
        "no closed after unsubscribe"
    );
    assert!(first.try_recv().is_err(), "the first subscription stays");
    assert_eq!(s.shared.lock().hls.sessions.len(), 2);
    assert!(s.unsubscribed(ConnectionId(1), 3).is_none());
    s.connection_closed(ConnectionId(7));
    assert_eq!(next(&mut other).await["reason"], "session_closed");
    assert!(
        s.shared.lock().hls.outputs.contains_key(&live_id),
        "the first session keeps the output"
    );
    assert!(commands.try_recv().is_err());
    s.connection_closed(ConnectionId(1));
    assert_eq!(next(&mut first).await["reason"], "session_closed");
    let_assert!(Some(DriverCommand::StopLive { .. }) = within(commands.recv()).await);
    assert!(s.shared.lock().hls.outputs.is_empty());
    s.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// A session no request reaches within the idle timeout ends `idle`; a
/// request restarts its clock.
#[tokio::test]
async fn a_session_without_a_request_within_the_idle_timeout_ends_idle() {
    let captured = Captured::default();
    let _logs = captured.install();
    let dir = private_dir("hls-idle");
    let clock = Arc::new(FakeClock::from_system());
    let limits = HlsLimits {
        idle_timeout: Duration::from_secs(4),
        ..HlsLimits::DEFAULT
    };
    let (s, mut commands) = rig(&dir, limits, clock.clone()).await;
    let (live_id, mut pipe, id, mut events) = first_session(&s, &mut commands).await;
    pipe.write_all(&first_segment()).unwrap();
    published(&s, &live_id, 5).await;
    clock.advance(Duration::from_secs(3));
    settle().await;
    assert!(within(s.hls(&id, playlist(Blocking::None))).await.is_ok());
    clock.advance(Duration::from_secs(3));
    settle().await;
    assert!(
        events.try_recv().is_err(),
        "the request restarted its clock"
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        next(&mut events).await,
        json!({ "type": "closed", "hls_id": id.as_str(), "reason": "idle" })
    );
    let_assert!(Some(DriverCommand::StopLive { .. }) = within(commands.recv()).await);
    let lines = captured.lines("LL-HLS session idle: no request in time");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("timeout_ms=4000"), "{lines:?}");
    stop(&s, &clock).await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// Blocked requests are bounded at once, per session and in all (429), and
/// in time: three Target Durations once the window publishes, the start
/// timeout before (503); a request whose session ends while it waits is
/// one for no session.
#[tokio::test]
async fn rfc8216bis_6_2_5_2_blocked_requests_are_bounded_in_number_and_time() {
    let captured = Captured::default();
    let _logs = captured.install();
    let dir = private_dir("hls-blocked");
    let clock = Arc::new(FakeClock::from_system());
    let limits = HlsLimits {
        max_blocked_per_session: 1,
        max_blocked: 2,
        idle_timeout: Duration::from_secs(3600),
        ..HlsLimits::DEFAULT
    };
    let (s, mut commands) = rig(&dir, limits, clock.clone()).await;
    let start_timeout = Duration::from_secs(2);
    s.shared.lock().live_limits.start_timeout = start_timeout;
    let (live_id, mut pipe, id, _events) = first_session(&s, &mut commands).await;
    // Before the window, the init segment waits too, bounded by the start
    // timeout.
    let early = spawn_request(&s, &id, HlsRequest::Media(Resource::Init));
    settle().await;
    assert_eq!(
        within(s.hls(&id, playlist(Blocking::None))).await.err(),
        Some(HlsError::TooManyBlocked {
            limit: "max_hls_blocked_per_session"
        })
    );
    clock.advance(start_timeout);
    assert_eq!(within(early).await.unwrap().err(), Some(HlsError::Timeout));
    pipe.write_all(&first_segment()).unwrap();
    published(&s, &live_id, 5).await;
    let hinted = HlsRequest::Media(Resource::Part { msn: 1, index: 0 });
    let blocked = spawn_request(&s, &id, hinted);
    let create = |id: u64| json!({ "id": id, "type": "hls/create", "stream_id": "front" });
    let (second, _second_events) = started(within(call_on(&s, 1, &create(5))).await);
    let second = hls_id(&second);
    let ahead = spawn_request(&s, &second, playlist(Blocking::Segment { msn: 2 }));
    settle().await;
    let (third, _third_events) = started(within(call_on(&s, 1, &create(6))).await);
    let third = hls_id(&third);
    for _ in 0..2 {
        assert_eq!(
            within(s.hls(&third, hinted)).await.err(),
            Some(HlsError::TooManyBlocked {
                limit: "max_hls_blocked"
            })
        );
    }
    assert_eq!(
        captured.lines("LL-HLS request refused at its limit").len(),
        2
    );
    // The hinted part completes; the other waits out three Target
    // Durations.
    pipe.write_all(&record(fragment(false, 100), &[11; 4]))
        .unwrap();
    let_assert!(Ok(Ok((HlsReply::Media(part), _))) = within(blocked).await);
    assert_eq!(part.len(), 8);
    settle().await;
    assert!(!ahead.is_finished());
    clock.advance(Duration::from_secs(3));
    assert_eq!(within(ahead).await.unwrap().err(), Some(HlsError::Timeout));
    let gone = spawn_request(&s, &third, playlist(Blocking::Segment { msn: 2 }));
    settle().await;
    let close = json!({ "id": 7, "type": "hls/close", "hls_id": third.as_str() });
    result(call(&s, &close.to_string()).await);
    assert_eq!(within(gone).await.unwrap().err(), Some(HlsError::NotFound));
    stop(&s, &clock).await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// Requests are bounded in flight, per session and in all (429), from
/// their arrival until their response is dropped, blocked ones included,
/// each cap warned once per interval; a response held past its session's
/// end still holds its place in all.
#[tokio::test]
async fn requests_in_flight_are_bounded_until_their_responses_are_dropped() {
    let captured = Captured::default();
    let _logs = captured.install();
    let dir = private_dir("hls-in-flight");
    let clock = Arc::new(FakeClock::from_system());
    let limits = HlsLimits {
        max_requests_per_session: 2,
        max_requests: 3,
        idle_timeout: Duration::from_secs(3600),
        ..HlsLimits::DEFAULT
    };
    let (s, mut commands) = rig(&dir, limits, clock.clone()).await;
    let (live_id, mut pipe, id, _events) = first_session(&s, &mut commands).await;
    pipe.write_all(&first_segment()).unwrap();
    published(&s, &live_id, 5).await;
    let init = HlsRequest::Media(Resource::Init);
    let in_flight = || s.shared.lock().hls.requests.available_permits();
    let first = within(s.hls(&id, init)).await.unwrap();
    let blocked = spawn_request(&s, &id, playlist(Blocking::Segment { msn: 1 }));
    while in_flight() != 1 {
        settle().await;
    }
    let per_session = Some(HlsError::TooManyRequests {
        limit: "max_hls_requests_per_session",
    });
    assert_eq!(within(s.hls(&id, init)).await.err(), per_session);
    let create = json!({ "id": 5, "type": "hls/create", "stream_id": "front" });
    let (second, _second_events) = started(within(call_on(&s, 1, &create)).await);
    let second = hls_id(&second);
    let held = within(s.hls(&second, init)).await.unwrap();
    for _ in 0..2 {
        assert_eq!(
            within(s.hls(&second, init)).await.err(),
            Some(HlsError::TooManyRequests {
                limit: "max_hls_requests"
            })
        );
    }
    let refused = captured.lines("LL-HLS request refused at its limit");
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert!(
        refused[0].contains("max_hls_requests_per_session"),
        "{refused:?}"
    );
    // A sent or dropped response, and a blocked request that ends, give
    // their places back.
    drop(first);
    blocked.abort();
    while in_flight() != 2 {
        settle().await;
    }
    let again = within(s.hls(&id, init)).await.unwrap();
    assert_eq!(in_flight(), 1);
    let close = json!({ "id": 6, "type": "hls/close", "hls_id": id.as_str() });
    result(call(&s, &close.to_string()).await);
    assert_eq!(
        in_flight(),
        1,
        "the session's end leaves its response's place"
    );
    drop((again, held));
    assert_eq!(in_flight(), 3);
    stop(&s, &clock).await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// An init segment asked for after `hls/create` answered but before the
/// reader made the window waits for the window, and is answered as the
/// window is made, before any part publishes: on a fake clock that never
/// moves, nothing else would end its wait.
#[tokio::test]
async fn an_init_request_waiting_for_the_window_is_answered_as_the_window_is_made() {
    let dir = private_dir("hls-init-wait");
    let clock = Arc::new(FakeClock::from_system());
    let (s, mut commands) = rig(&dir, HlsLimits::DEFAULT, clock.clone()).await;
    let (live_id, mut pipe, id, _events) = first_session(&s, &mut commands).await;
    let early = spawn_request(&s, &id, HlsRequest::Media(Resource::Init));
    let all = HlsLimits::DEFAULT.max_blocked as usize;
    while s.shared.lock().hls.blocked.available_permits() == all {
        settle().await;
    }
    pipe.write_all(&record(RecordKind::Init, b"init")).unwrap();
    let_assert!(Ok(Ok((HlsReply::Media(init), _))) = within(early).await);
    assert_eq!(init.as_slice().concat(), b"init");
    assert_eq!(*feed(&s, &live_id).published.borrow(), 1, "no part yet");
    stop(&s, &clock).await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// What a worker writes into the pipe is untrusted: a broken record, a
/// second init segment and a fragment before the first end the output
/// `internal_error`, a window that cannot hold the open segment
/// `window_full`, a window the limits make none of `internal_error`; the
/// pipe's end alone ends nothing.
#[tokio::test]
async fn a_pipe_the_window_cannot_take_ends_its_output() {
    let captured = Captured::default();
    let _logs = captured.install();
    let dir = private_dir("hls-reader");
    let broken = {
        let mut bytes = record(RecordKind::Init, b"init");
        bytes[0] = b'X';
        bytes
    };
    let twice = [
        record(RecordKind::Init, b"a"),
        record(RecordKind::Init, b"b"),
    ]
    .concat();
    let early = record(fragment(true, 100), b"frame");
    let overflow = [
        record(RecordKind::Init, b"init"),
        record(fragment(true, 100), &[0; 64]),
    ]
    .concat();
    let small = HlsLimits {
        window_bytes: 64,
        ..HlsLimits::DEFAULT
    };
    let zero = HlsLimits {
        part_target: Duration::ZERO,
        ..HlsLimits::DEFAULT
    };
    for (limits, bytes, reason) in [
        (HlsLimits::DEFAULT, broken, "internal_error"),
        (HlsLimits::DEFAULT, twice, "internal_error"),
        (HlsLimits::DEFAULT, early, "internal_error"),
        (small, overflow, "window_full"),
        (zero, record(RecordKind::Init, b"init"), "internal_error"),
    ] {
        let (s, mut commands) = rig(&dir, limits, Arc::new(SystemClock)).await;
        let (live_id, mut pipe, _id, mut events) = first_session(&s, &mut commands).await;
        pipe.write_all(&bytes).unwrap();
        assert_eq!(next(&mut events).await["reason"], reason);
        let_assert!(
            Some(DriverCommand::StopLive { live_id: stopped }) = within(commands.recv()).await
        );
        assert_eq!(stopped, live_id);
        s.shutdown().await;
    }
    for line in [
        "LL-HLS output's records are broken",
        "LL-HLS records: a second init segment",
        "LL-HLS records: a fragment before the init segment",
        "LL-HLS window full",
        "LL-HLS window refused its configuration",
    ] {
        assert_eq!(captured.lines(line).len(), 1, "{line}");
    }
    let (s, mut commands) = rig(&dir, HlsLimits::DEFAULT, Arc::new(SystemClock)).await;
    let (live_id, pipe, _id, mut events) = first_session(&s, &mut commands).await;
    drop(pipe);
    let mut tries = 0;
    while captured.lines("LL-HLS output's pipe ended").is_empty() {
        tries += 1;
        assert!(tries < 500, "the reader saw the pipe's end");
        SystemClock.sleep(Duration::from_millis(5)).await;
    }
    assert!(events.try_recv().is_err());
    assert!(s.shared.lock().hls.outputs.contains_key(&live_id));
    s.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

/// A reader that fails at once.
struct Failing;

impl AsyncRead for Failing {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("the pipe broke")))
    }
}

/// A pipe whose read fails ends its output `internal_error`.
#[tokio::test]
async fn a_pipe_whose_read_fails_ends_its_output() {
    let captured = Captured::default();
    let _logs = captured.install();
    let dir = private_dir("hls-read-fails");
    let (s, mut commands) = rig(&dir, HlsLimits::DEFAULT, Arc::new(SystemClock)).await;
    let (live_id, _pipe, _id, mut events) = first_session(&s, &mut commands).await;
    let feed = feed(&s, &live_id);
    read(
        Arc::clone(&s.shared),
        live_id.clone(),
        Box::new(Failing),
        feed,
        HlsLimits::DEFAULT.window(),
    )
    .await;
    assert_eq!(next(&mut events).await["reason"], "internal_error");
    let lines = captured.lines("LL-HLS output's pipe failed");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("the pipe broke"), "{lines:?}");
    s.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

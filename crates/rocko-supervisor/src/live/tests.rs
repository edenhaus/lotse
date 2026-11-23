#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use rocko_core::let_assert;
use serde_json::{Value, json};

use super::*;
use crate::test_support::Captured;

/// A registry with one live output `l1` of stream `front` on connection
/// `c1`, owned by control connection 1's subscription 7; the driver's queue
/// its slots send on, the owner's events, and the create's wait.
struct Rig {
    state: State,
    driver: mpsc::Receiver<DriverCommand>,
    events: mpsc::Receiver<Event>,
    started: oneshot::Receiver<Result<String, LiveCloseReason>>,
}

fn new_rig() -> Rig {
    let mut state = State::default();
    let (commands, driver) = mpsc::channel(8);
    let (events_tx, events) = mpsc::channel(LIVE_QUEUE);
    let (waiting, started) = oneshot::channel();
    let (reader, _writer) = std::io::pipe().unwrap();
    let body = pipe::Receiver::from_owned_fd(reader.into()).unwrap();
    state.lives.insert(
        "l1".into(),
        LiveEntry {
            serial: 1,
            stream_id: "front".into(),
            connection: "c1".into(),
            owner: Some(LiveOwner {
                connection: ConnectionId(1),
                subscription: 7,
                events: events_tx,
            }),
            waiting: Some(waiting),
            mime: None,
            body: Some(body),
            fetch_slot: Some(commands.clone().try_reserve_owned().unwrap()),
            stop_slot: Some(commands.try_reserve_owned().unwrap()),
            ending: None,
            warned: false,
            timer: None,
        },
    );
    Rig {
        state,
        driver,
        events,
        started,
    }
}

const MIME: &str = "video/mp4; codecs=\"avc1.42c028,mp4a.40.2\"";

fn started_report() -> LiveReport {
    LiveReport::Started {
        mime: MIME.into(),
        video: "h264".into(),
        audio: Some("aac_lc".into()),
    }
}

fn closed_report(reason: &str) -> LiveReport {
    LiveReport::Closed {
        reason: reason.into(),
        bytes: 4096,
        dropped_frames: 3,
        drops: 1,
    }
}

impl Rig {
    fn report(&mut self, report: LiveReport) {
        self.state.live_report("c1", "l1", report);
    }

    fn event(&mut self) -> Value {
        self.events.try_recv().expect("an event").payload
    }

    fn stop_sent(&mut self) -> bool {
        matches!(self.driver.try_recv(), Ok(DriverCommand::StopLive { live_id }) if live_id == "l1")
    }
}

fn closed(reason: &str, bytes: u64, dropped: u64, drops: u32) -> Value {
    json!({ "type": "closed", "live_id": "l1", "reason": reason, "bytes": bytes,
            "dropped_frames": dropped, "drops": drops })
}

#[tokio::test]
async fn the_default_limits_are_the_documented_ones_and_none_takes_no_output() {
    assert_eq!(
        LiveLimits::DEFAULT,
        LiveLimits {
            buffer_bytes: 1 << 20,
            fetch_timeout: Duration::from_secs(10),
            start_timeout: Duration::from_secs(10),
            max_live: 16,
            max_live_per_stream: 8,
        }
    );
    assert_eq!(LiveLimits::default(), LiveLimits::NONE);
    assert_eq!(
        (
            LiveLimits::NONE.max_live,
            LiveLimits::NONE.max_live_per_stream
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn a_worker_s_mime_type_must_be_the_live_container_s_in_printable_ascii() {
    assert!(valid_mime(MIME));
    assert!(valid_mime(&format!(
        "video/mp4{}",
        "x".repeat(MAX_MIME_BYTES - 9)
    )));
    assert!(!valid_mime(&format!(
        "video/mp4{}",
        "x".repeat(MAX_MIME_BYTES - 8)
    )));
    assert!(!valid_mime("audio/mp4"));
    assert!(!valid_mime("video/mp4\n"));
    assert!(!valid_mime("video/mp4; codecs=\"é\""));
}

#[tokio::test]
async fn a_worker_may_give_its_own_reasons_and_its_stop_only_when_asked() {
    assert_eq!(
        worker_reason("codec_changed", None),
        Some(LiveCloseReason::CodecChanged)
    );
    assert_eq!(
        worker_reason(STOPPED_AS_ASKED, Some(LiveCloseReason::NotFetched)),
        Some(LiveCloseReason::NotFetched)
    );
    assert_eq!(worker_reason(STOPPED_AS_ASKED, None), None);
    for theirs in [
        "closed",
        "session_closed",
        "not_fetched",
        "worker_crashed",
        "made_up",
    ] {
        assert_eq!(worker_reason(theirs, None), None, "{theirs}");
    }
}

#[tokio::test]
async fn started_answers_the_create_and_closed_ends_the_output_with_its_figures() {
    let mut rig = new_rig();
    rig.report(started_report());
    assert_eq!(rig.started.try_recv(), Ok(Ok(MIME.into())));
    rig.report(LiveReport::Warning {
        code: "audio_omitted".into(),
        message: "pcmu\nhere".into(),
    });
    assert_eq!(
        rig.event(),
        json!({ "type": "warning", "code": "audio_omitted", "message": "pcmu here" })
    );
    rig.report(closed_report("client_gone"));
    assert_eq!(rig.event(), closed("client_gone", 4096, 3, 1));
    assert!(rig.state.lives.is_empty());
    assert!(
        rig.events.recv().await.is_none(),
        "closed is the last event"
    );
}

#[tokio::test]
async fn a_report_that_breaks_the_contract_ends_the_output_internal_error() {
    let malformed = [
        vec![started_report(), started_report()],
        vec![LiveReport::Started {
            mime: "text/plain".into(),
            video: "h264".into(),
            audio: None,
        }],
        vec![LiveReport::Warning {
            code: "made_up".into(),
            message: String::new(),
        }],
        vec![
            LiveReport::Warning {
                code: "audio_omitted".into(),
                message: String::new(),
            },
            LiveReport::Warning {
                code: "audio_omitted".into(),
                message: String::new(),
            },
        ],
    ];
    for reports in malformed {
        let captured = Captured::default();
        let _logs = captured.install();
        let mut rig = new_rig();
        for report in reports {
            rig.report(report);
        }
        assert!(rig.stop_sent(), "the worker is asked to stop it");
        assert_eq!(
            rig.state.lives["l1"].ending,
            Some(LiveCloseReason::InternalError)
        );
        assert_eq!(
            captured
                .lines("a worker reported a malformed live report")
                .len(),
            1
        );
        rig.report(closed_report(STOPPED_AS_ASKED));
        let mut last = rig.event();
        if last["type"] == "warning" {
            last = rig.event();
        }
        assert_eq!(last, closed("internal_error", 4096, 3, 1));
    }
    // A `Closed` that breaks it ends the output at once: the worker runs it
    // no more.
    let mut rig = new_rig();
    rig.report(closed_report("not_fetched"));
    assert!(!rig.stop_sent());
    assert_eq!(rig.event(), closed("internal_error", 0, 0, 0));
    assert_eq!(
        rig.started.try_recv(),
        Ok(Err(LiveCloseReason::InternalError))
    );
}

#[tokio::test]
async fn a_report_of_another_connection_or_of_an_output_not_held_changes_nothing() {
    let captured = Captured::default();
    let _logs = captured.install();
    let mut rig = new_rig();
    rig.state.live_report("c2", "l1", started_report());
    assert!(rig.state.lives["l1"].mime.is_none());
    assert_eq!(
        captured
            .lines("a worker reported a live output it does not run")
            .len(),
        1
    );
    rig.state
        .live_report("c1", &format!("l\n{}", "x".repeat(200)), started_report());
    let lines = captured.lines("report for a live output the supervisor does not hold");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("live.id=l x"), "{lines:?}");
}

#[tokio::test]
async fn the_supervisor_s_end_asks_the_worker_once_tells_a_waiting_create_and_names_the_close() {
    let captured = Captured::default();
    let _logs = captured.install();
    let mut rig = new_rig();
    rig.state.end_live("l1", LiveCloseReason::Closed);
    assert_eq!(rig.started.try_recv(), Ok(Err(LiveCloseReason::Closed)));
    assert!(rig.stop_sent());
    rig.state.end_live("l1", LiveCloseReason::NotFetched);
    assert!(rig.driver.try_recv().is_err(), "asked once");
    rig.state.end_live("gone", LiveCloseReason::Closed);
    assert_eq!(
        captured
            .lines("end of a live output that is not open")
            .len(),
        1
    );
    rig.report(closed_report(STOPPED_AS_ASKED));
    assert_eq!(rig.event(), closed("closed", 4096, 3, 1));
}

#[tokio::test]
async fn a_closed_control_connection_or_its_unsubscribe_ends_its_outputs_session_closed() {
    let mut rig = new_rig();
    rig.state.lives_connection_closed(ConnectionId(2));
    assert!(!rig.stop_sent(), "another connection's");
    rig.state.lives_connection_closed(ConnectionId(1));
    assert!(rig.stop_sent());
    assert_eq!(
        rig.state.lives["l1"].ending,
        Some(LiveCloseReason::SessionClosed)
    );

    let mut rig = new_rig();
    assert!(!rig.state.unsubscribe_live(ConnectionId(1), 8));
    assert!(!rig.state.unsubscribe_live(ConnectionId(2), 7));
    assert!(rig.state.unsubscribe_live(ConnectionId(1), 7));
    assert!(rig.stop_sent());
    assert!(
        rig.state.lives["l1"].owner.is_none(),
        "no event after unsubscribe"
    );
    rig.report(closed_report(STOPPED_AS_ASKED));
    assert!(rig.state.lives.is_empty());
}

#[tokio::test]
async fn the_body_is_taken_once_after_the_start_and_the_worker_hears_of_it() {
    let mut rig = new_rig();
    assert!(matches!(
        rig.state.take_live_body("gone"),
        Err(LiveBodyError::NotFound)
    ));
    assert!(
        matches!(rig.state.take_live_body("l1"), Err(LiveBodyError::NotFound)),
        "not started: no result named it yet"
    );
    rig.report(started_report());
    let_assert!(Ok(body) = rig.state.take_live_body("l1"));
    assert_eq!(body.mime, MIME);
    assert!(
        matches!(rig.driver.try_recv(), Ok(DriverCommand::FetchLive { live_id }) if live_id == "l1")
    );
    assert!(matches!(
        rig.state.take_live_body("l1"),
        Err(LiveBodyError::AlreadyFetched)
    ));
    // Fetched: its deadline changes nothing.
    rig.state.live_fetch_deadline("l1", 1);
    assert!(rig.state.lives["l1"].ending.is_none());
}

#[tokio::test]
async fn the_fetch_deadline_ends_an_output_not_fetched_unless_it_is_another_s() {
    let mut rig = new_rig();
    rig.state.live_fetch_deadline("l1", 2);
    assert!(rig.state.lives["l1"].ending.is_none(), "a later output's");
    rig.state.live_fetch_deadline("gone", 1);
    rig.state.live_fetch_deadline("l1", 1);
    assert_eq!(
        rig.state.lives["l1"].ending,
        Some(LiveCloseReason::NotFetched)
    );
}

#[tokio::test]
async fn a_worker_gone_or_a_start_unqueued_ends_the_output_at_once() {
    let mut rig = new_rig();
    rig.state.lives_worker_gone("c2");
    assert_eq!(rig.state.lives.len(), 1, "another connection's");
    rig.state.lives_worker_gone("c1");
    assert_eq!(rig.event(), closed("worker_crashed", 0, 0, 0));

    let mut rig = new_rig();
    rig.state.end_live("l1", LiveCloseReason::StreamDeleted);
    rig.state.lives_worker_gone("c1");
    assert_eq!(rig.event(), closed("stream_deleted", 0, 0, 0));

    let mut rig = new_rig();
    rig.state.end_live("l1", LiveCloseReason::Closed);
    rig.state.live_unqueued("l1");
    assert_eq!(rig.event(), closed("closed", 0, 0, 0));
    let mut rig = new_rig();
    rig.state.live_unqueued("l1");
    assert_eq!(rig.event(), closed("internal_error", 0, 0, 0));
    rig.state
        .close_live("l1", LiveCloseReason::Closed, (0, 0, 0));
}

#[tokio::test]
async fn outputs_are_counted_per_stream_and_in_all_and_a_full_subscription_drops_an_event() {
    let captured = Captured::default();
    let _logs = captured.install();
    let mut rig = new_rig();
    assert_eq!(rig.state.lives_open("front"), (1, 1));
    assert_eq!(rig.state.lives_open("back"), (0, 1));
    for _ in 0..LIVE_QUEUE {
        rig.report(LiveReport::Warning {
            code: "audio_omitted".into(),
            message: String::new(),
        });
        rig.state.lives.get_mut("l1").unwrap().warned = false;
    }
    rig.report(LiveReport::Warning {
        code: "audio_omitted".into(),
        message: String::new(),
    });
    assert_eq!(
        captured.lines("live event dropped").len(),
        1,
        "the queue holds {LIVE_QUEUE}"
    );
}

//! The source runner: runs one source's connections in a worker until told
//! to stop, with reconnect backoff, the stall watchdog and hot swap, and
//! reports every state change.
//!
//! Protocol-independent: a source only runs one connection and reports how
//! it ended. Tracks keep their identity across reconnects through the
//! `TrackSet`; a reconnect starts a new epoch on every track together and
//! tells subscribers when the source is lost and back.
//!
//! Every attempt is announced (`Connecting`, `Reconnecting`) and then waits
//! at its [`ConnectGate`] for the supervisor's grant, which keeps at most
//! `sources.connect_concurrency` attempts running across the daemon.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::backoff::ReconnectBackoff;
use crate::clock::Clock;
use crate::clock_map::ClockMapper;
use crate::codec::Kind;
use crate::connection::DEFAULT_STABLE_AFTER;
use crate::source::{
    BackchannelSlot, ClockInput, ResolvedPeer, Source, SourceCtx, SourceError, SourceExit, TrackSet,
};
use crate::task::BoxFuture;

/// Default of `sources.stall_timeout` for video.
pub const DEFAULT_STALL_VIDEO: Duration = Duration::from_secs(5);

/// Default of `sources.stall_timeout` for audio.
pub const DEFAULT_STALL_AUDIO: Duration = Duration::from_secs(10);

/// How often the watchdog looks.
pub const DEFAULT_STALL_CHECK: Duration = Duration::from_secs(1);

/// How long a connection may take to declare its tracks before the runner
/// gives up on it. A belt over the source's own connect timeout.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a cancelled source may run on before the runner drops its
/// future. Five times the ingest contract's 100 ms,
/// which covers the RTSP source's 100 ms wait for its `TEARDOWN` answer,
/// and half the worker's 1 s stop deadline, so a forced stop still ends
/// the runner before the worker gives up on it.
pub const DEFAULT_STOP_GRACE: Duration = Duration::from_millis(500);

/// The runner's tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerConfig {
    /// No video for this long after going live is a stall.
    pub stall_video: Duration,
    /// No audio for this long after going live is a stall.
    pub stall_audio: Duration,
    /// The watchdog interval.
    pub stall_check: Duration,
    /// Not ready within this is a timeout.
    pub ready_timeout: Duration,
    /// Streaming this long resets the reconnect backoff.
    pub stable_after: Duration,
    /// A source still running this long after its cancel is dropped.
    pub stop_grace: Duration,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            stall_video: DEFAULT_STALL_VIDEO,
            stall_audio: DEFAULT_STALL_AUDIO,
            stall_check: DEFAULT_STALL_CHECK,
            ready_timeout: DEFAULT_READY_TIMEOUT,
            stable_after: DEFAULT_STABLE_AFTER,
            stop_grace: DEFAULT_STOP_GRACE,
        }
    }
}

/// Where a connection attempt waits for the supervisor's permission
/// (`sources.connect_concurrency`): the runner announces the attempt, then
/// waits here until [`ConnectGate::grant`] lets it through. One grant lets
/// one attempt through, and at most one is stored, so a duplicate grant
/// never lets a second attempt run without a permit.
#[derive(Debug, Clone)]
pub struct ConnectGate {
    /// The stored grant; `None` for a gate that never waits.
    grants: Option<Arc<Notify>>,
}

impl ConnectGate {
    /// A gate that lets one attempt through per grant: the worker's.
    pub fn closed() -> Self {
        Self {
            grants: Some(Arc::new(Notify::new())),
        }
    }

    /// A gate that never waits, for tests that run a source without a
    /// supervisor.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn open() -> Self {
        Self { grants: None }
    }

    /// Lets the waiting attempt, or the next one, through.
    pub fn grant(&self) {
        if let Some(grants) = &self.grants {
            grants.notify_one();
        }
    }

    /// Waits for a grant.
    async fn granted(&self) {
        if let Some(grants) = &self.grants {
            grants.notified().await;
        }
    }
}

/// What the runner reports; the worker forwards it to the supervisor,
/// whose machine maps it to the connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerEvent {
    /// An attempt started after idle or a backoff.
    Connecting {
        /// Attempts so far, this one included.
        attempt: u32,
    },
    /// The tracks are declared; media flows.
    Live,
    /// The live source dropped; an attempt starts at once.
    Reconnecting {
        /// Why it dropped.
        error: SourceError,
    },
    /// An attempt failed; the next one starts in `retry_in`.
    Backoff {
        /// Why it failed.
        error: SourceError,
        /// The wait.
        retry_in: Duration,
    },
    /// The runner was cancelled and the source is torn down.
    Stopped,
}

/// How one connection attempt ended.
#[derive(Debug)]
struct Outcome {
    /// The tracks were declared.
    reached_live: bool,
    /// How long it streamed.
    live_for: Duration,
    /// Why it ended.
    error: SourceError,
}

/// What the runner announces before the next attempt.
#[derive(Debug)]
enum Announce {
    /// `Connecting`.
    Connecting,
    /// `Reconnecting` with the error that caused it.
    Reconnecting(SourceError),
}

/// Runs one source's connections.
#[derive(Debug)]
pub struct SourceRunner {
    /// The source.
    source: Box<dyn Source>,
    /// Where to connect.
    peer: ResolvedPeer,
    /// The connection's tracks.
    tracks: Arc<TrackSet>,
    /// The connection's clock mapper; hints from the source go here.
    mapper: Arc<ClockMapper>,
    /// The backchannel slot shared with the connection.
    backchannel: BackchannelSlot,
    /// The clock.
    clock: Arc<dyn Clock>,
    /// The tunables.
    config: RunnerConfig,
    /// The reconnect schedule.
    backoff: ReconnectBackoff,
    /// Where reports go.
    events: mpsc::Sender<RunnerEvent>,
    /// Where each attempt waits for the supervisor's grant.
    gate: ConnectGate,
    /// Cancelled to stop the runner.
    cancel: CancellationToken,
}

impl SourceRunner {
    /// A runner for `source` toward `peer`.
    #[expect(
        clippy::too_many_arguments,
        reason = "a constructor wiring the connection's shared parts; the runner is built once per connection"
    )]
    pub fn new(
        source: Box<dyn Source>,
        peer: ResolvedPeer,
        tracks: Arc<TrackSet>,
        mapper: Arc<ClockMapper>,
        backchannel: BackchannelSlot,
        clock: Arc<dyn Clock>,
        config: RunnerConfig,
        backoff: ReconnectBackoff,
        events: mpsc::Sender<RunnerEvent>,
        gate: ConnectGate,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            source,
            peer,
            tracks,
            mapper,
            backchannel,
            clock,
            config,
            backoff,
            events,
            gate,
            cancel,
        }
    }

    /// Runs connections until cancelled, then reports `Stopped`. A cancel
    /// is over once the running source returns, which the ingest contract
    /// bounds at 100 ms;
    /// a source that ignores it is dropped after `stop_grace`, so neither a
    /// stop nor a stall's reconnect waits on it.
    pub async fn run(mut self) {
        let mut attempt: u32 = 0;
        let mut connections: u32 = 0;
        let mut announce = Announce::Connecting;
        while !self.cancel.is_cancelled() {
            attempt = attempt.saturating_add(1);
            let event = match announce {
                Announce::Connecting => RunnerEvent::Connecting { attempt },
                Announce::Reconnecting(error) => RunnerEvent::Reconnecting { error },
            };
            self.emit(event).await;
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => break,
                () = self.gate.granted() => {}
            }
            tracing::debug!(attempt, "connect granted");
            let outcome = self.run_once(connections > 0).await;
            if outcome.reached_live {
                connections = connections.saturating_add(1);
            }
            if self.cancel.is_cancelled() {
                break;
            }
            if outcome.live_for >= self.config.stable_after {
                tracing::debug!(
                    live_ms = outcome.live_for.as_millis(),
                    "stable streaming; reconnect backoff reset"
                );
                self.backoff.reset();
            }
            let retry_in = self.backoff.next_delay(outcome.reached_live);
            tracing::warn!(
                error.code = outcome.error.code(),
                error = %outcome.error,
                attempt,
                retry_ms = retry_in.as_millis(),
                "source connection ended"
            );
            if retry_in.is_zero() {
                announce = Announce::Reconnecting(outcome.error);
                continue;
            }
            self.emit(RunnerEvent::Backoff {
                error: outcome.error,
                retry_in,
            })
            .await;
            tokio::select! {
                () = self.clock.sleep(retry_in) => {}
                () = self.cancel.cancelled() => break,
            }
            announce = Announce::Connecting;
        }
        tracing::info!(attempts = attempt, "source runner stopped");
        self.emit(RunnerEvent::Stopped).await;
    }

    /// One connection attempt. `reconnect` says tracks were declared before,
    /// so the attempt is a hot swap: a new epoch before the source runs,
    /// and `SourceRestored` once it is ready.
    async fn run_once(&self, reconnect: bool) -> Outcome {
        // A new connection is a new RTP timeline: fits of the last one
        // would map its timestamps to nonsense.
        self.mapper.reset();
        if reconnect {
            // Before the source runs: it may publish in the same poll that
            // makes it ready, before this task sees it.
            self.tracks.start_epoch();
        }
        let cancel = self.cancel.child_token();
        let (clock_input, mut reports) = ClockInput::channel(Arc::clone(&self.mapper));
        let ctx = SourceCtx {
            peer: self.peer.clone(),
            tracks: self.tracks.publisher(),
            clock: clock_input,
            time: Arc::clone(&self.clock),
            backchannel: self.backchannel.clone(),
            cancel: cancel.clone(),
        };
        let mut run = self.source.run(ctx);
        let mut ready = self.tracks.ready();
        let started = self.clock.now();
        let mut live_since: Option<Instant> = None;
        let mut watchdog_error: Option<SourceError> = None;
        let mut check = self.clock.sleep(self.config.stall_check);

        let exit = loop {
            tokio::select! {
                exit = &mut run => break exit,
                // The watchdog's cancel or the runner's own.
                () = cancel.cancelled() => {
                    let reason = watchdog_error
                        .as_ref()
                        .map_or_else(|| "runner stopped".to_owned(), ToString::to_string);
                    break self.wind_down(run, &reason).await;
                }
                changed = ready.changed(), if live_since.is_none() => {
                    if changed.is_ok() && *ready.borrow_and_update() {
                        let now = self.clock.now();
                        live_since = Some(now);
                        self.on_live(reconnect, now.saturating_duration_since(started)).await;
                    }
                }
                Some(report) = reports.recv() => self.mapper.ingest(report),
                () = &mut check => {
                    check = self.clock.sleep(self.config.stall_check);
                    if let Some(error) = self.watchdog(started, live_since) {
                        watchdog_error = Some(error);
                        cancel.cancel();
                    }
                }
            }
        };

        self.tracks.reset_ready();
        if live_since.is_some() {
            self.tracks.set_source_lost(true);
        }
        let error = watchdog_error.unwrap_or_else(|| match exit {
            SourceExit::Ended(error) => error,
            SourceExit::Resolved(spec) => {
                tracing::warn!(url = %spec.url, "source resolved to another spec, which is not supported yet");
                SourceError::Protocol("resolver sources are not supported yet".into())
            }
        });
        Outcome {
            reached_live: live_since.is_some(),
            live_for: live_since.map_or(Duration::ZERO, |since| {
                self.clock.now().saturating_duration_since(since)
            }),
            error,
        }
    }

    /// Waits for a cancelled source to return, at most `stop_grace`. A
    /// source still running then is dropped, which ends it at the await it
    /// is stuck in, and the attempt ends as a timeout; `reason` says why it
    /// was cancelled. Security review WRK-3: before, a source that ignored
    /// its cancel held a stop or a stall's reconnect forever.
    async fn wind_down(&self, run: BoxFuture<'static, SourceExit>, reason: &str) -> SourceExit {
        let grace_ms = self.config.stop_grace.as_millis();
        tokio::select! {
            exit = run => exit,
            () = self.clock.sleep(self.config.stop_grace) => {
                tracing::warn!(grace_ms, reason, "source ignored its cancel; dropped");
                SourceExit::Ended(SourceError::Timeout(format!(
                    "source still running {grace_ms} ms after its cancel"
                )))
            }
        }
    }

    /// The tracks are ready: splice the connection in and report.
    async fn on_live(&self, reconnect: bool, after: Duration) {
        if reconnect {
            self.tracks.set_source_lost(false);
        }
        tracing::info!(
            reconnect,
            connect_ms = after.as_millis(),
            tracks = self.tracks.tracks().len(),
            "source live"
        );
        self.emit(RunnerEvent::Live).await;
    }

    /// The stall watchdog: not ready in time, or a live track without
    /// items for longer than its stall timeout.
    fn watchdog(&self, started: Instant, live_since: Option<Instant>) -> Option<SourceError> {
        let now = self.clock.now();
        let Some(live_since) = live_since else {
            let waited = now.saturating_duration_since(started);
            return (waited >= self.config.ready_timeout).then(|| {
                SourceError::Timeout(format!(
                    "no tracks declared within {} ms",
                    self.config.ready_timeout.as_millis()
                ))
            });
        };
        for track in self.tracks.tracks() {
            let limit = match track.kind() {
                Kind::Video => self.config.stall_video,
                Kind::Audio => self.config.stall_audio,
            };
            // Activity from a previous connection does not count.
            let last = track
                .last_activity()
                .map_or(live_since, |last| last.max(live_since));
            let silent = now.saturating_duration_since(last);
            if silent >= limit {
                return Some(SourceError::Timeout(format!(
                    "no {} for {} ms (track {})",
                    track.kind(),
                    silent.as_millis(),
                    track.id()
                )));
            }
        }
        None
    }

    /// Reports; a closed receiver means nobody listens any more.
    async fn emit(&self, event: RunnerEvent) {
        tracing::debug!(event = ?event, "runner event");
        let _nobody_listening = self.events.send(event).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::clock::FakeClock;
    use crate::media::{MediaPacket, RtpHeaderFields};
    use crate::source::SourceFactory as _;
    use crate::source_url::SourceUrl;
    use crate::task::spawn_named;
    use crate::test_logs::Logs;
    use crate::test_util::FakeSourceFactory;
    use crate::track::{TrackEvent, TrackLimits, Unit};

    struct Harness {
        clock: Arc<FakeClock>,
        tracks: Arc<TrackSet>,
        mapper: Arc<ClockMapper>,
        events: mpsc::Receiver<RunnerEvent>,
        cancel: CancellationToken,
        runner: tokio::task::JoinHandle<()>,
    }

    fn start(config: RunnerConfig) -> Harness {
        start_with(config, &serde_json::Value::Null)
    }

    /// [`start`] with the fake source's `options`.
    fn start_with(config: RunnerConfig, options: &serde_json::Value) -> Harness {
        start_gated(config, options, ConnectGate::open())
    }

    /// [`start_with`] behind `gate`.
    fn start_gated(
        config: RunnerConfig,
        options: &serde_json::Value,
        gate: ConnectGate,
    ) -> Harness {
        let clock = Arc::new(FakeClock::default());
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let (tx, events) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let mapper = Arc::new(ClockMapper::new());
        let source = FakeSourceFactory::new(&["fake"])
            .validate(&SourceUrl::parse("fake://cam/").unwrap(), options)
            .unwrap();
        let runner = SourceRunner::new(
            source,
            ResolvedPeer {
                host: "cam".into(),
                addrs: vec![],
            },
            Arc::clone(&tracks),
            Arc::clone(&mapper),
            BackchannelSlot::default(),
            clock.clone(),
            config,
            ReconnectBackoff::new(1),
            tx,
            gate,
            cancel.clone(),
        );
        let runner = spawn_named("test.runner", runner.run());
        Harness {
            clock,
            tracks,
            mapper,
            events,
            cancel,
            runner,
        }
    }

    /// The runner's next event, or `None` once it is done; a runner that
    /// goes quiet fails the test instead of hanging it.
    async fn next(events: &mut mpsc::Receiver<RunnerEvent>) -> Option<RunnerEvent> {
        use crate::clock::{Clock as _, SystemClock};
        tokio::select! {
            event = events.recv() => event,
            () = SystemClock.sleep(Duration::from_secs(5)) => panic!("no runner event within 5 s"),
        }
    }

    fn packet(arrival: Instant) -> MediaPacket {
        MediaPacket {
            arrival,
            rtp: RtpHeaderFields {
                pt: 96,
                seq: 0,
                ts: 0,
                marker: false,
                ssrc: 0,
            },
            frame_start: true,
            keyframe_start: true,
            epoch: 0,
            lateness: Duration::ZERO,
            payload: Arc::from(&[0_u8][..]),
        }
    }

    /// Advances the fake clock one watchdog interval at a time, letting the
    /// runner observe each tick, until `total` has passed.
    async fn tick(h: &Harness, total: Duration) {
        let step = DEFAULT_STALL_CHECK;
        let mut passed = Duration::ZERO;
        while passed < total {
            h.clock.advance(step);
            passed += step;
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn connects_goes_live_and_stops_on_cancel() {
        let mut h = start(RunnerConfig::default());
        assert_eq!(
            next(&mut h.events).await,
            Some(RunnerEvent::Connecting { attempt: 1 })
        );
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        assert_eq!(h.tracks.tracks().len(), 1);
        assert!(*h.tracks.ready().borrow());
        h.cancel.cancel();
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Stopped));
        h.runner.await.unwrap();
        assert!(!*h.tracks.ready().borrow(), "not ready once torn down");
    }

    /// No event within a few scheduler turns.
    async fn quiet(events: &mut mpsc::Receiver<RunnerEvent>) -> bool {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        events.try_recv().is_err()
    }

    #[tokio::test]
    async fn every_attempt_waits_for_one_grant_and_a_cancel_ends_the_wait() {
        let gate = ConnectGate::closed();
        let mut h = start_gated(
            RunnerConfig::default(),
            &serde_json::Value::Null,
            gate.clone(),
        );
        assert_eq!(
            next(&mut h.events).await,
            Some(RunnerEvent::Connecting { attempt: 1 })
        );
        // Announced, but no connection without the supervisor's grant.
        assert!(quiet(&mut h.events).await);
        assert!(h.tracks.tracks().is_empty(), "the source did not run");
        // Two grants store one: the attempt goes live, the stalled
        // reconnect after it uses the stored grant, the next waits again.
        gate.grant();
        gate.grant();
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Reconnecting { .. })
        ));
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Backoff { .. })
        ));
        // The first backoff is 1 s, jittered by at most a fifth.
        h.clock.advance(Duration::from_secs(2));
        assert_eq!(
            next(&mut h.events).await,
            Some(RunnerEvent::Connecting { attempt: 3 })
        );
        assert!(quiet(&mut h.events).await, "the third attempt waits");
        // A cancel while waiting stops the runner without connecting.
        h.cancel.cancel();
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Stopped));
        h.runner.await.unwrap();
        ConnectGate::open().grant();
    }

    #[tokio::test]
    async fn a_stalled_track_reconnects_at_once_then_backs_off() {
        let mut h = start(RunnerConfig::default());
        assert_eq!(
            next(&mut h.events).await,
            Some(RunnerEvent::Connecting { attempt: 1 })
        );
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        let video = h.tracks.tracks().remove(0);
        let mut sub = video.subscribe(Unit::Packets);
        // The first connection's camera sends a Sender Report.
        h.mapper.ingest(crate::source::ClockReport {
            track: video.id(),
            clock_rate: 90_000,
            hint: crate::source::SyncHint::RtcpSenderReport {
                ntp: 1 << 32,
                rtp_ts: 0,
            },
            arrival: h.clock.now(),
        });
        assert_eq!(
            h.mapper.mode(video.id()),
            crate::clock_map::SyncMode::SenderReports
        );

        // Packets keep the watchdog quiet.
        for _ in 0..4 {
            tick(&h, Duration::from_secs(1)).await;
            video.publish_packet(packet(h.clock.now()));
        }
        assert!(h.events.try_recv().is_err(), "no event while media flows");

        // Silence for the video stall timeout: the first loss after a live
        // period is retried at once, as a hot swap.
        tick(&h, DEFAULT_STALL_VIDEO).await;
        let Some(RunnerEvent::Reconnecting { error }) = next(&mut h.events).await else {
            panic!("reconnecting expected");
        };
        assert_eq!(error.code(), "source_timeout");
        assert!(error.to_string().contains("no video for"), "{error}");
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        assert_eq!(h.tracks.tracks().len(), 1, "same track, hot swapped");
        assert_eq!(
            h.mapper.mode(video.id()),
            crate::clock_map::SyncMode::Arrival,
            "the last connection's fit is gone with its timeline"
        );
        assert_eq!(video.epoch(), 1);
        // Control events come before the packets still queued, and packets
        // carry their epoch, so a sink can tell old from new.
        // All of it is queued already: polled once each, so a missing item
        // fails here rather than hanging.
        let mut seen = Vec::new();
        for _ in 0..4 {
            let mut next = std::pin::pin!(sub.next());
            let polled = next
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
            let std::task::Poll::Ready(Some(event)) = polled else {
                panic!("queued events expected, got {seen:?}");
            };
            seen.push(event);
        }
        assert_eq!(
            &seen[..3],
            [
                TrackEvent::SourceLost,
                TrackEvent::EpochStart { epoch: 1 },
                TrackEvent::SourceRestored
            ]
        );
        assert!(matches!(&seen[3], TrackEvent::Packet(p) if p.epoch == 0));

        // The second loss before stable streaming waits out the schedule.
        tick(&h, DEFAULT_STALL_VIDEO).await;
        let Some(RunnerEvent::Backoff { error, retry_in }) = next(&mut h.events).await else {
            panic!("backoff expected");
        };
        assert_eq!(error.code(), "source_timeout");
        assert!(retry_in >= Duration::from_millis(800) && retry_in <= Duration::from_millis(1200));
        assert!(h.events.try_recv().is_err(), "waiting");
        tick(&h, Duration::from_secs(2)).await;
        assert_eq!(
            next(&mut h.events).await,
            Some(RunnerEvent::Connecting { attempt: 3 })
        );
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        assert_eq!(video.epoch(), 2);

        h.cancel.cancel();
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Stopped));
        h.runner.await.unwrap();
    }

    /// Security review WRK-1: a camera's RTCP Sender Report (RFC 3550
    /// §6.4.1) whose RTP timestamp sits 2³¹ − 1 ticks behind its media maps
    /// every frame about 6.6 h ahead. Activity is timed by arrival, so one
    /// frame stamped that far ahead and then silence still stalls in time.
    #[tokio::test]
    async fn a_rfc3550_6_4_1_sender_report_mapping_frames_hours_ahead_still_stalls() {
        let mut h = start(RunnerConfig::default());
        next(&mut h.events).await;
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        let video = h.tracks.tracks().remove(0);
        h.mapper.ingest(crate::source::ClockReport {
            track: video.id(),
            clock_rate: 90_000,
            hint: crate::source::SyncHint::RtcpSenderReport {
                ntp: 1 << 32,
                rtp_ts: 0,
            },
            arrival: h.clock.now(),
        });
        let rtp_ts = 0x7fff_ffff;
        let arrival = h.clock.now();
        let wallclock = h.mapper.map(video.id(), rtp_ts, arrival);
        assert!(
            wallclock >= arrival + Duration::from_hours(6),
            "the report maps the frame hours ahead"
        );
        video.publish_packet(MediaPacket {
            rtp: RtpHeaderFields {
                ts: rtp_ts,
                ..packet(arrival).rtp
            },
            ..packet(arrival)
        });
        assert!(video.publish_frame(crate::media::MediaFrame {
            ts: crate::media::MediaTime::from_ticks(i64::from(rtp_ts)),
            wallclock,
            arrival,
            keyframe: true,
            discontinuity: false,
            epoch: 0,
            payload: bytes::Bytes::from_static(&[0]),
        }));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        let Some(RunnerEvent::Reconnecting { error }) = next(&mut h.events).await else {
            panic!("reconnecting expected");
        };
        assert!(
            error.to_string().contains("no video for 5000 ms"),
            "{error}"
        );
        h.cancel.cancel();
    }

    #[tokio::test]
    async fn stable_streaming_resets_the_backoff() {
        let config = RunnerConfig {
            stable_after: Duration::from_secs(10),
            ..RunnerConfig::default()
        };
        let mut h = start(config);
        next(&mut h.events).await;
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        let video = h.tracks.tracks().remove(0);
        // Two losses: the immediate retry, then a scheduled one.
        tick(&h, DEFAULT_STALL_VIDEO).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Reconnecting { .. })
        ));
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Backoff { .. })
        ));
        tick(&h, Duration::from_secs(2)).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Connecting { .. })
        ));
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        // Stream past `stable_after`, then lose it: immediate again.
        for _ in 0..12 {
            tick(&h, Duration::from_secs(1)).await;
            video.publish_packet(packet(h.clock.now()));
        }
        tick(&h, DEFAULT_STALL_VIDEO).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Reconnecting { .. })
        ));
        h.cancel.cancel();
    }

    #[tokio::test]
    async fn cancel_during_backoff_stops_without_another_attempt() {
        let mut h = start(RunnerConfig::default());
        next(&mut h.events).await;
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        next(&mut h.events).await; // reconnecting
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Backoff { .. })
        ));
        h.cancel.cancel();
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Stopped));
        assert_eq!(next(&mut h.events).await, None);
        h.runner.await.unwrap();
    }

    /// The hang behind a flaky worker shutdown: a stall reconnects while
    /// the fake clock runs, the new connection waits to go live, the clock
    /// stops, and a stop must still end the runner. Nothing advances the
    /// clock after the cancel, so only the source honoring it can.
    #[tokio::test]
    async fn a_cancel_while_a_reconnect_waits_to_go_live_stops_the_runner() {
        let mut h = start_with(
            RunnerConfig::default(),
            &serde_json::json!({"ready_after_ms": 1000}),
        );
        next(&mut h.events).await;
        tick(&h, Duration::from_secs(1)).await;
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        assert!(matches!(
            next(&mut h.events).await,
            Some(RunnerEvent::Reconnecting { .. })
        ));
        h.cancel.cancel();
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Stopped));
        assert_eq!(next(&mut h.events).await, None);
        h.runner.await.unwrap();
        assert!(!*h.tracks.ready().borrow());
    }

    #[tokio::test]
    async fn a_reconnect_stamps_the_new_epoch_on_media_published_with_ready() {
        // A source that publishes in the same poll as `ready`, as RTSP does
        // when the first RTP packet shares a read with the PLAY answer.
        #[derive(Debug, Default)]
        struct Eager {
            runs: std::sync::atomic::AtomicU32,
        }
        impl Source for Eager {
            fn describe(&self) -> crate::source::SourceDescriptor {
                crate::source::SourceDescriptor {
                    protocol: "eager",
                    url: SourceUrl::parse("eager://x/").unwrap(),
                    options: serde_json::Value::Null,
                }
            }
            fn connection_options(&self) -> serde_json::Value {
                serde_json::Value::Null
            }
            fn run(&self, mut ctx: SourceCtx) -> BoxFuture<'static, SourceExit> {
                let run = self.runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Box::pin(async move {
                    let codec = crate::codec::Codec::Pcmu;
                    let track = ctx.tracks.declare(Kind::Video, codec, 90_000);
                    ctx.tracks.ready();
                    let mut p = packet(ctx.time.now());
                    p.rtp.seq = u16::try_from(run).unwrap();
                    track.publish_packet(p);
                    ctx.cancel.cancelled().await;
                    SourceExit::Ended(SourceError::Ended("cancelled".into()))
                })
            }
        }
        assert_eq!(Eager::default().describe().protocol, "eager");
        assert_eq!(
            Eager::default().connection_options(),
            serde_json::Value::Null
        );
        let clock = Arc::new(FakeClock::default());
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let (tx, mut events) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let runner = SourceRunner::new(
            Box::new(Eager::default()),
            ResolvedPeer {
                host: "x".into(),
                addrs: vec![],
            },
            Arc::clone(&tracks),
            Arc::new(ClockMapper::new()),
            BackchannelSlot::default(),
            clock.clone(),
            RunnerConfig::default(),
            ReconnectBackoff::new(1),
            tx,
            ConnectGate::open(),
            cancel.clone(),
        );
        let runner = spawn_named("test.runner", runner.run());
        assert_eq!(
            next(&mut events).await,
            Some(RunnerEvent::Connecting { attempt: 1 })
        );
        let mut sub = tracks.tracks().remove(0).subscribe(Unit::Packets);
        assert_eq!(next(&mut events).await, Some(RunnerEvent::Live));
        // The first connection stalls.
        for _ in 0..DEFAULT_STALL_VIDEO.as_secs() {
            clock.advance(DEFAULT_STALL_CHECK);
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            next(&mut events).await,
            Some(RunnerEvent::Reconnecting { .. })
        ));
        assert_eq!(next(&mut events).await, Some(RunnerEvent::Live));
        let mut packets = Vec::new();
        while let Some(event) = sub.next().await {
            let TrackEvent::Packet(p) = event else {
                continue;
            };
            packets.push((p.rtp.seq, p.epoch));
            if p.rtp.seq == 1 {
                break;
            }
        }
        assert_eq!(
            packets.last(),
            Some(&(1, 1)),
            "the second connection's packet: {packets:?}"
        );
        cancel.cancel();
        runner.await.unwrap();
    }

    /// A source that never declares tracks, so it hits the ready timeout.
    #[derive(Debug)]
    struct Silent;
    impl Source for Silent {
        fn describe(&self) -> crate::source::SourceDescriptor {
            crate::source::SourceDescriptor {
                protocol: "silent",
                url: SourceUrl::parse("silent://x/").unwrap(),
                options: serde_json::Value::Null,
            }
        }
        fn connection_options(&self) -> serde_json::Value {
            serde_json::Value::Null
        }
        fn run(&self, ctx: SourceCtx) -> BoxFuture<'static, SourceExit> {
            Box::pin(async move {
                ctx.cancel.cancelled().await;
                SourceExit::Resolved(crate::source::SourceSpec {
                    url: SourceUrl::parse("rtsp://x/").unwrap(),
                    options: serde_json::Value::Null,
                })
            })
        }
    }

    #[tokio::test]
    async fn audio_uses_its_own_stall_timeout_and_a_slow_ready_times_out() {
        let clock = Arc::new(FakeClock::default());
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let (tx, mut events) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let config = RunnerConfig {
            ready_timeout: Duration::from_secs(3),
            ..RunnerConfig::default()
        };
        assert_eq!(
            (Silent.describe().protocol, Silent.connection_options()),
            ("silent", serde_json::Value::Null)
        );
        let runner = SourceRunner::new(
            Box::new(Silent),
            ResolvedPeer {
                host: "x".into(),
                addrs: vec![],
            },
            Arc::clone(&tracks),
            Arc::new(ClockMapper::new()),
            BackchannelSlot::default(),
            clock.clone(),
            config,
            ReconnectBackoff::new(1),
            tx,
            ConnectGate::open(),
            cancel.clone(),
        );
        let runner = spawn_named("test.runner", runner.run());
        assert_eq!(
            next(&mut events).await,
            Some(RunnerEvent::Connecting { attempt: 1 })
        );
        for _ in 0..3 {
            clock.advance(Duration::from_secs(1));
            tokio::task::yield_now().await;
        }
        let Some(RunnerEvent::Backoff { error, .. }) = next(&mut events).await else {
            panic!("backoff expected");
        };
        assert_eq!(
            error.to_string(),
            "source timed out: no tracks declared within 3000 ms"
        );
        cancel.cancel();
        // The cancel may race a retry that already started; it ends either way.
        while let Some(event) = next(&mut events).await {
            if event == RunnerEvent::Stopped {
                break;
            }
            assert!(matches!(event, RunnerEvent::Connecting { .. }), "{event:?}");
        }
        runner.await.unwrap();

        // A resolved exit without the watchdog is reported as a protocol error.
        let (tx, mut events) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let runner = SourceRunner::new(
            Box::new(Silent),
            ResolvedPeer {
                host: "x".into(),
                addrs: vec![],
            },
            Arc::clone(&tracks),
            Arc::new(ClockMapper::new()),
            BackchannelSlot::default(),
            clock.clone(),
            RunnerConfig::default(),
            ReconnectBackoff::new(1),
            tx,
            ConnectGate::open(),
            cancel.clone(),
        );
        let outcome = {
            let cancel_soon = cancel.clone();
            spawn_named("test.cancel", async move {
                tokio::task::yield_now().await;
                cancel_soon.cancel();
            });
            runner.run_once(false).await
        };
        assert!(!outcome.reached_live);
        assert_eq!(outcome.error.code(), "source_protocol_error");
        assert!(events.try_recv().is_err(), "run_once alone reports nothing");
    }

    /// The warning of a source dropped after `stop_grace`.
    const DROPPED: &str = "source ignored its cancel; dropped";

    /// A source that goes live and then never looks at its cancel: it
    /// waits on something that never comes, as a source stuck in an
    /// upstream await would. Counts its runs and the runs dropped.
    #[derive(Debug, Default)]
    struct Deaf {
        runs: Arc<std::sync::atomic::AtomicU32>,
        dropped: Arc<std::sync::atomic::AtomicU32>,
    }

    /// Counts a drop of the future that holds it.
    struct DropCount(Arc<std::sync::atomic::AtomicU32>);

    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl Source for Deaf {
        fn describe(&self) -> crate::source::SourceDescriptor {
            crate::source::SourceDescriptor {
                protocol: "deaf",
                url: SourceUrl::parse("deaf://x/").unwrap(),
                options: serde_json::Value::Null,
            }
        }
        fn connection_options(&self) -> serde_json::Value {
            serde_json::Value::Null
        }
        fn run(&self, mut ctx: SourceCtx) -> BoxFuture<'static, SourceExit> {
            self.runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dropped = DropCount(Arc::clone(&self.dropped));
            Box::pin(async move {
                let _dropped = dropped;
                ctx.tracks
                    .declare(Kind::Video, crate::codec::Codec::Pcmu, 90_000);
                ctx.tracks.ready();
                std::future::pending::<SourceExit>().await
            })
        }
    }

    /// A runner of [`Deaf`]: the harness, its run count and its drop count.
    fn start_deaf() -> (
        Harness,
        Arc<std::sync::atomic::AtomicU32>,
        Arc<std::sync::atomic::AtomicU32>,
    ) {
        let deaf = Deaf::default();
        assert_eq!(
            (deaf.describe().protocol, deaf.connection_options()),
            ("deaf", serde_json::Value::Null)
        );
        let (runs, dropped) = (Arc::clone(&deaf.runs), Arc::clone(&deaf.dropped));
        let clock = Arc::new(FakeClock::default());
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let (tx, events) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let mapper = Arc::new(ClockMapper::new());
        let runner = SourceRunner::new(
            Box::new(deaf),
            ResolvedPeer {
                host: "x".into(),
                addrs: vec![],
            },
            Arc::clone(&tracks),
            Arc::clone(&mapper),
            BackchannelSlot::default(),
            clock.clone(),
            RunnerConfig::default(),
            ReconnectBackoff::new(1),
            tx,
            ConnectGate::open(),
            cancel.clone(),
        );
        let runner = spawn_named("test.runner", runner.run());
        let harness = Harness {
            clock,
            tracks,
            mapper,
            events,
            cancel,
            runner,
        };
        (harness, runs, dropped)
    }

    /// Security review WRK-3: a stalled source that ignores the watchdog's
    /// cancel is dropped `stop_grace` later, and the reconnect runs with
    /// the watchdog's error.
    #[tokio::test]
    async fn a_stalled_source_ignoring_its_cancel_is_dropped_and_reconnects() {
        let (warnings, _guard) = Logs::capture();
        let (mut h, runs, dropped) = start_deaf();
        next(&mut h.events).await;
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        tick(&h, DEFAULT_STALL_VIDEO).await;
        // Cancelled, still running: no reconnect before the grace is over.
        h.clock.advance(
            DEFAULT_STOP_GRACE
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        );
        assert!(quiet(&mut h.events).await, "waits out the grace");
        assert_eq!(
            (
                runs.load(std::sync::atomic::Ordering::Relaxed),
                dropped.load(std::sync::atomic::Ordering::Relaxed)
            ),
            (1, 0)
        );
        assert_eq!(warnings.count(tracing::Level::WARN, DROPPED), 0);
        h.clock.advance(Duration::from_millis(1));
        let Some(RunnerEvent::Reconnecting { error }) = next(&mut h.events).await else {
            panic!("reconnecting expected");
        };
        assert!(error.to_string().contains("no video for"), "{error}");
        assert_eq!(dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(warnings.count(tracing::Level::WARN, DROPPED), 1);
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        assert_eq!(runs.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(h.tracks.tracks().len(), 1, "same track, hot swapped");
        h.cancel.cancel();
        assert!(quiet(&mut h.events).await, "waits out the grace");
        h.clock.advance(DEFAULT_STOP_GRACE);
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Stopped));
        h.runner.await.unwrap();
        assert_eq!(warnings.count(tracing::Level::WARN, DROPPED), 2);
    }

    /// Security review WRK-3: a stop is over `stop_grace` after the cancel
    /// even when the source ignores it.
    #[tokio::test]
    async fn a_stop_drops_a_source_ignoring_its_cancel_after_the_grace() {
        let (warnings, _guard) = Logs::capture();
        let (mut h, _runs, dropped) = start_deaf();
        next(&mut h.events).await;
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Live));
        h.cancel.cancel();
        assert!(quiet(&mut h.events).await, "waits out the grace");
        h.clock.advance(DEFAULT_STOP_GRACE);
        assert_eq!(next(&mut h.events).await, Some(RunnerEvent::Stopped));
        h.runner.await.unwrap();
        assert_eq!(dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(warnings.count(tracing::Level::WARN, DROPPED), 1);
        assert!(!*h.tracks.ready().borrow(), "not ready once torn down");
    }

    /// The attempt a forced stop ends is a timeout naming the grace; a
    /// source that honors its cancel ends with its own error and no warning.
    #[tokio::test]
    async fn a_forced_stop_ends_the_attempt_as_a_timeout_and_a_cooperative_one_does_not() {
        let (warnings, _guard) = Logs::capture();
        let clock = Arc::new(FakeClock::default());
        let tracks = TrackSet::new(TrackLimits::default(), clock.now());
        let runner = |source: Box<dyn Source>, cancel: &CancellationToken| {
            SourceRunner::new(
                source,
                ResolvedPeer {
                    host: "x".into(),
                    addrs: vec![],
                },
                Arc::clone(&tracks),
                Arc::new(ClockMapper::new()),
                BackchannelSlot::default(),
                clock.clone(),
                RunnerConfig::default(),
                ReconnectBackoff::new(1),
                mpsc::channel(1).0,
                ConnectGate::open(),
                cancel.clone(),
            )
        };

        let cancel = CancellationToken::new();
        let deaf = runner(Box::<Deaf>::default(), &cancel);
        let forced = clock.clone();
        let stop = cancel.clone();
        spawn_named("test.cancel", async move {
            tokio::task::yield_now().await;
            stop.cancel();
            tokio::task::yield_now().await;
            forced.advance(DEFAULT_STOP_GRACE);
        });
        let outcome = {
            use crate::clock::SystemClock;
            tokio::select! {
                outcome = deaf.run_once(false) => outcome,
                () = SystemClock.sleep(Duration::from_secs(5)) => panic!("not dropped within 5 s"),
            }
        };
        assert!(outcome.reached_live);
        assert_eq!(outcome.error.code(), "source_timeout");
        assert_eq!(
            outcome.error.to_string(),
            "source timed out: source still running 500 ms after its cancel"
        );
        assert_eq!(warnings.count(tracing::Level::WARN, DROPPED), 1);

        // The fake source honors its cancel: its own exit, no clock moved.
        let cancel = CancellationToken::new();
        let source = FakeSourceFactory::new(&["fake"])
            .validate(
                &SourceUrl::parse("fake://cam/").unwrap(),
                &serde_json::Value::Null,
            )
            .unwrap();
        let cooperative = runner(source, &cancel);
        let stop = cancel.clone();
        spawn_named("test.cancel", async move {
            tokio::task::yield_now().await;
            stop.cancel();
        });
        let outcome = cooperative.run_once(false).await;
        assert_eq!(outcome.error.code(), "source_ended");
        assert_eq!(
            warnings.count(tracing::Level::WARN, DROPPED),
            1,
            "no second warning"
        );
    }

    #[test]
    fn config_defaults_follow_the_documented_values() {
        let config = RunnerConfig::default();
        assert_eq!(config.stall_video, Duration::from_secs(5));
        assert_eq!(config.stall_audio, Duration::from_secs(10));
        assert_eq!(config.ready_timeout, Duration::from_secs(30));
        assert_eq!(config.stable_after, Duration::from_secs(60));
        assert_eq!(config.stop_grace, Duration::from_millis(500));
    }
}

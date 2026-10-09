//! The source-connection state machine as the supervisor drives it: demand,
//! the worker's reports, the worker's exit and two timers in; worker
//! spawn and stop, linger and crash-backoff timers out.
//!
//! Pure: no I/O, no clock of its own. The driver feeds inputs with the
//! current instant and performs the actions, so every transition is unit
//! tested here. One machine runs per `SourceConnection`; demand is the sum
//! over every stream and sink that references it.

use std::time::{Duration, Instant};

use crate::backoff::CrashBackoff;
use crate::source::SourceError;

/// Default of `stream.linger`.
pub const DEFAULT_LINGER: Duration = Duration::from_secs(5);

/// How long a worker must run before its crash backoff resets, and a
/// source must stream before its reconnect backoff resets.
pub const DEFAULT_STABLE_AFTER: Duration = Duration::from_secs(60);

/// The state of a source connection, as `stream/get` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// No demand, no worker.
    Idle,
    /// A worker is connecting to the source.
    Connecting,
    /// Tracks are ready; media flows.
    Live,
    /// The source dropped; the worker is reconnecting at once.
    Reconnecting,
    /// An attempt failed; the worker waits out the reconnect delay.
    Backoff,
    /// Demand dropped to zero; the linger timer runs before the worker stops.
    Draining,
    /// The worker crashed; the crash-backoff timer runs before a new one.
    Restarting,
}

impl ConnectionState {
    /// The API name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Live => "live",
            Self::Reconnecting => "reconnecting",
            Self::Backoff => "backoff",
            Self::Draining => "draining",
            Self::Restarting => "restarting",
        }
    }
}

/// The last thing that went wrong on a connection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionError {
    /// The source reported an error.
    #[error(transparent)]
    Source(SourceError),
    /// The connection's worker process died.
    #[error("worker crashed")]
    WorkerCrashed,
}

impl ConnectionError {
    /// The stable API code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Source(error) => error.code(),
            Self::WorkerCrashed => "worker_crashed",
        }
    }
}

/// What the worker reports about its source connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerReport {
    /// An attempt started after idle or a backoff.
    Connecting,
    /// Tracks are ready.
    Live,
    /// The live source dropped for this reason; an attempt starts at once.
    Reconnecting(SourceError),
    /// An attempt failed; the next one is `retry_in` away.
    Backoff {
        /// Why the attempt failed.
        error: SourceError,
        /// The wait before the next attempt.
        retry_in: Duration,
    },
}

/// What the driver feeds the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Demand changed: the total over sessions, requests, persistent
    /// outputs and `preload` of every referencing stream.
    Demand(u32),
    /// The worker reported.
    Report(WorkerReport),
    /// The worker process exited, expected or not.
    WorkerExited,
    /// The linger timer the machine asked for fired.
    LingerExpired,
    /// The crash-backoff timer the machine asked for fired.
    CrashBackoffExpired,
}

/// What the driver must do after an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Start a worker for this connection.
    SpawnWorker,
    /// Stop the worker: close its sessions, tear the source down, exit.
    StopWorker,
    /// Start the linger timer; feed `LingerExpired` when it fires.
    StartLinger(Duration),
    /// Cancel the linger timer.
    CancelLinger,
    /// Start the crash-backoff timer; feed `CrashBackoffExpired` when it fires.
    StartCrashBackoff(Duration),
    /// Cancel the crash-backoff timer.
    CancelCrashBackoff,
}

/// The tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Grace after the last demand goes away before the worker stops.
    pub linger: Duration,
    /// A worker that ran this long resets the crash backoff.
    pub stable_after: Duration,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            linger: DEFAULT_LINGER,
            stable_after: DEFAULT_STABLE_AFTER,
        }
    }
}

/// The machine.
#[derive(Debug)]
pub struct ConnectionMachine {
    /// The tunables.
    config: ConnectionConfig,
    /// The current state.
    state: ConnectionState,
    /// The current demand.
    demand: u32,
    /// The crash-restart schedule.
    crash: CrashBackoff,
    /// A `StopWorker` was issued and the exit is expected.
    stopping: bool,
    /// When the running worker was spawned.
    worker_since: Option<Instant>,
    /// The last error, cleared when the connection goes live.
    last_error: Option<ConnectionError>,
    /// Worker crashes so far, for `stream/get`.
    crashes: u32,
}

impl ConnectionMachine {
    /// An idle machine.
    pub const fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            state: ConnectionState::Idle,
            demand: 0,
            crash: CrashBackoff::new(),
            stopping: false,
            worker_since: None,
            last_error: None,
            crashes: 0,
        }
    }

    /// The current state.
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// The current demand.
    pub const fn demand(&self) -> u32 {
        self.demand
    }

    /// The last error, if the connection is not live.
    pub const fn last_error(&self) -> Option<&ConnectionError> {
        self.last_error.as_ref()
    }

    /// Worker crashes so far.
    pub const fn crashes(&self) -> u32 {
        self.crashes
    }

    /// Feeds one input at `now` and returns what the driver must do.
    pub fn handle(&mut self, input: Input, now: Instant) -> Vec<Action> {
        let from = self.state;
        let mut actions = Vec::new();
        let reason = match input {
            Input::Demand(demand) => {
                self.demand = demand;
                self.on_demand(now, &mut actions);
                "demand"
            }
            Input::Report(report) => {
                self.on_report(report);
                "worker report"
            }
            Input::WorkerExited => {
                self.on_worker_exited(now, &mut actions);
                "worker exited"
            }
            Input::LingerExpired => {
                if self.state == ConnectionState::Draining {
                    self.stop_worker(&mut actions);
                }
                "linger expired"
            }
            Input::CrashBackoffExpired => {
                if self.state == ConnectionState::Restarting {
                    self.spawn_worker(now, &mut actions);
                }
                "crash backoff expired"
            }
        };
        if from != self.state {
            tracing::info!(
                from = from.name(),
                to = self.state.name(),
                reason,
                demand = self.demand,
                error = self.last_error.as_ref().map(ConnectionError::code),
                "connection state changed"
            );
        }
        actions
    }

    /// Demand changed.
    fn on_demand(&mut self, now: Instant, actions: &mut Vec<Action>) {
        let wanted = self.demand > 0;
        match (self.state, wanted) {
            (ConnectionState::Idle, true) => self.spawn_worker(now, actions),
            (
                ConnectionState::Connecting
                | ConnectionState::Reconnecting
                | ConnectionState::Backoff,
                false,
            ) => self.stop_worker(actions),
            (ConnectionState::Live, false) => {
                actions.push(Action::StartLinger(self.config.linger));
                self.state = ConnectionState::Draining;
            }
            (ConnectionState::Draining, true) => {
                actions.push(Action::CancelLinger);
                self.state = ConnectionState::Live;
            }
            (ConnectionState::Restarting, false) => {
                actions.push(Action::CancelCrashBackoff);
                self.state = ConnectionState::Idle;
            }
            (ConnectionState::Idle | ConnectionState::Draining, false)
            | (
                ConnectionState::Connecting
                | ConnectionState::Live
                | ConnectionState::Reconnecting
                | ConnectionState::Backoff
                | ConnectionState::Restarting,
                true,
            ) => {}
        }
    }

    /// The worker reported. Reports while no worker is wanted are stale.
    fn on_report(&mut self, report: WorkerReport) {
        use ConnectionState as S;
        match (self.state, report) {
            (S::Connecting | S::Reconnecting | S::Backoff, WorkerReport::Live) => {
                self.last_error = None;
                self.state = S::Live;
            }
            (S::Reconnecting | S::Backoff, WorkerReport::Connecting) => {
                self.state = S::Connecting;
            }
            (S::Live | S::Reconnecting, WorkerReport::Reconnecting(error)) => {
                self.last_error = Some(ConnectionError::Source(error));
                self.state = S::Reconnecting;
            }
            (S::Connecting | S::Reconnecting | S::Live, WorkerReport::Backoff { error, .. }) => {
                self.last_error = Some(ConnectionError::Source(error));
                self.state = S::Backoff;
            }
            (
                S::Draining,
                WorkerReport::Reconnecting(error) | WorkerReport::Backoff { error, .. },
            ) => {
                self.last_error = Some(ConnectionError::Source(error));
            }
            (S::Draining, WorkerReport::Live) => {
                self.last_error = None;
            }
            (S::Idle | S::Restarting, _)
            | (S::Connecting | S::Live | S::Draining, WorkerReport::Connecting)
            | (S::Live, WorkerReport::Live)
            | (S::Connecting | S::Backoff, WorkerReport::Reconnecting(_))
            | (S::Backoff, WorkerReport::Backoff { .. }) => {}
        }
    }

    /// The worker exited: expected after `StopWorker`, a crash otherwise.
    fn on_worker_exited(&mut self, now: Instant, actions: &mut Vec<Action>) {
        if self.stopping {
            self.stopping = false;
            self.worker_since = None;
            self.state = ConnectionState::Idle;
            return;
        }
        if self.state == ConnectionState::Idle {
            return;
        }
        self.crashes = self.crashes.saturating_add(1);
        if self
            .worker_since
            .is_some_and(|since| now.saturating_duration_since(since) >= self.config.stable_after)
        {
            self.crash.reset();
        }
        self.worker_since = None;
        self.last_error = Some(ConnectionError::WorkerCrashed);
        if self.state == ConnectionState::Draining {
            actions.push(Action::CancelLinger);
        }
        if self.demand > 0 {
            let delay = self.crash.next_delay();
            tracing::warn!(
                crashes = self.crashes,
                retry_ms = delay.as_millis(),
                "worker crashed; restarting after backoff"
            );
            actions.push(Action::StartCrashBackoff(delay));
            self.state = ConnectionState::Restarting;
        } else {
            tracing::warn!(crashes = self.crashes, "worker crashed with no demand left");
            self.state = ConnectionState::Idle;
        }
    }

    /// Asks for a worker and moves to `Connecting`.
    fn spawn_worker(&mut self, now: Instant, actions: &mut Vec<Action>) {
        actions.push(Action::SpawnWorker);
        self.worker_since = Some(now);
        self.state = ConnectionState::Connecting;
    }

    /// Asks the worker to stop and moves to `Idle`; its exit is then expected.
    fn stop_worker(&mut self, actions: &mut Vec<Action>) {
        actions.push(Action::StopWorker);
        self.stopping = true;
        self.state = ConnectionState::Idle;
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
    use crate::clock::{Clock as _, SystemClock};

    use ConnectionState as S;

    fn machine() -> ConnectionMachine {
        ConnectionMachine::new(ConnectionConfig::default())
    }

    fn timeout() -> SourceError {
        SourceError::Timeout("stall".into())
    }

    #[test]
    fn names_match_the_api() {
        let names: Vec<&str> = [
            S::Idle,
            S::Connecting,
            S::Live,
            S::Reconnecting,
            S::Backoff,
            S::Draining,
            S::Restarting,
        ]
        .iter()
        .map(|s| s.name())
        .collect();
        assert_eq!(
            names,
            [
                "idle",
                "connecting",
                "live",
                "reconnecting",
                "backoff",
                "draining",
                "restarting"
            ]
        );
        assert_eq!(ConnectionError::WorkerCrashed.code(), "worker_crashed");
        assert_eq!(ConnectionError::WorkerCrashed.to_string(), "worker crashed");
        let source = ConnectionError::Source(timeout());
        assert_eq!(source.code(), "source_timeout");
        assert_eq!(source.to_string(), "source timed out: stall");
        assert_eq!(ConnectionConfig::default().linger, DEFAULT_LINGER);
    }

    #[test]
    fn demand_starts_a_worker_and_the_worker_goes_live() {
        let now = SystemClock.now();
        let mut m = machine();
        assert_eq!(m.state(), S::Idle);
        assert_eq!(m.handle(Input::Demand(1), now), [Action::SpawnWorker]);
        assert_eq!((m.state(), m.demand()), (S::Connecting, 1));
        assert!(m.handle(Input::Demand(2), now).is_empty());
        assert!(
            m.handle(Input::Report(WorkerReport::Connecting), now)
                .is_empty()
        );
        assert!(m.handle(Input::Report(WorkerReport::Live), now).is_empty());
        assert_eq!(m.state(), S::Live);
        assert_eq!(m.last_error(), None);
    }

    #[test]
    fn connect_failures_back_off_and_retry() {
        let now = SystemClock.now();
        let mut m = machine();
        m.handle(Input::Demand(1), now);
        let backoff = WorkerReport::Backoff {
            error: SourceError::Unreachable("refused".into()),
            retry_in: Duration::from_secs(1),
        };
        assert!(m.handle(Input::Report(backoff), now).is_empty());
        assert_eq!(m.state(), S::Backoff);
        assert_eq!(m.last_error().unwrap().code(), "source_unreachable");
        assert!(
            m.handle(Input::Report(WorkerReport::Connecting), now)
                .is_empty()
        );
        assert_eq!(m.state(), S::Connecting);
        m.handle(Input::Report(WorkerReport::Live), now);
        assert_eq!(m.state(), S::Live);
        assert!(m.last_error().is_none(), "cleared when live");
    }

    #[test]
    fn a_live_source_that_drops_reconnects_then_backs_off() {
        let now = SystemClock.now();
        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        assert!(
            m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now)
                .is_empty()
        );
        assert_eq!(m.state(), S::Reconnecting);
        assert_eq!(m.last_error().unwrap().code(), "source_timeout");
        m.handle(Input::Report(WorkerReport::Live), now);
        assert_eq!(m.state(), S::Live);
        m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now);
        m.handle(
            Input::Report(WorkerReport::Backoff {
                error: SourceError::Ended("eof".into()),
                retry_in: Duration::from_secs(5),
            }),
            now,
        );
        assert_eq!(m.state(), S::Backoff);
        assert_eq!(m.last_error().unwrap().code(), "source_ended");
        // Stale or meaningless reports change nothing.
        m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now);
        assert_eq!(m.state(), S::Backoff);
        m.handle(Input::Report(WorkerReport::Connecting), now);
        m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now);
        assert_eq!(m.state(), S::Connecting);
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(Input::Report(WorkerReport::Connecting), now);
        assert_eq!(m.state(), S::Live);
    }

    #[test]
    fn losing_demand_lingers_then_stops_the_worker() {
        let now = SystemClock.now();
        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        assert_eq!(
            m.handle(Input::Demand(0), now),
            [Action::StartLinger(DEFAULT_LINGER)]
        );
        assert_eq!(m.state(), S::Draining);
        assert!(m.handle(Input::Demand(0), now).is_empty());
        // Demand returns within the linger: back to live, no reconnect.
        assert_eq!(m.handle(Input::Demand(1), now), [Action::CancelLinger]);
        assert_eq!(m.state(), S::Live);
        m.handle(Input::Demand(0), now);
        // Reports during the linger only update the error.
        m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now);
        assert_eq!(m.state(), S::Draining);
        assert_eq!(m.last_error().unwrap().code(), "source_timeout");
        m.handle(Input::Report(WorkerReport::Connecting), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        assert_eq!(m.state(), S::Draining);
        assert!(m.last_error().is_none());
        m.handle(
            Input::Report(WorkerReport::Backoff {
                error: timeout(),
                retry_in: Duration::from_secs(1),
            }),
            now,
        );
        assert_eq!(m.state(), S::Draining);
        assert_eq!(m.handle(Input::LingerExpired, now), [Action::StopWorker]);
        assert_eq!(m.state(), S::Idle);
        assert!(
            m.handle(Input::WorkerExited, now).is_empty(),
            "expected exit"
        );
        assert_eq!(m.state(), S::Idle);
        assert_eq!(m.crashes(), 0);
        assert!(
            m.handle(Input::LingerExpired, now).is_empty(),
            "stale timer"
        );
    }

    #[test]
    fn losing_demand_while_not_live_stops_the_worker_at_once() {
        let now = SystemClock.now();
        for report in [
            None,
            Some(WorkerReport::Backoff {
                error: timeout(),
                retry_in: Duration::from_secs(1),
            }),
        ] {
            let mut m = machine();
            m.handle(Input::Demand(1), now);
            if let Some(report) = report {
                m.handle(Input::Report(report), now);
            }
            assert_eq!(m.handle(Input::Demand(0), now), [Action::StopWorker]);
            assert_eq!(m.state(), S::Idle);
            m.handle(Input::WorkerExited, now);
            assert_eq!(m.state(), S::Idle);
        }
        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now);
        assert_eq!(m.handle(Input::Demand(0), now), [Action::StopWorker]);
        assert_eq!(m.state(), S::Idle);
    }

    #[test]
    fn a_crash_restarts_with_backoff_while_demand_remains() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let now = SystemClock.now();
        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        assert_eq!(
            m.handle(Input::WorkerExited, now),
            [Action::StartCrashBackoff(Duration::from_millis(500))]
        );
        assert_eq!(m.state(), S::Restarting);
        assert_eq!(m.last_error(), Some(&ConnectionError::WorkerCrashed));
        assert_eq!(m.crashes(), 1);
        let crashed = logs.lines(
            tracing::Level::WARN,
            "worker crashed; restarting after backoff",
        );
        assert_eq!(crashed.len(), 1);
        assert_eq!(crashed[0].fields, " crashes=1 retry_ms=500");
        let changed = logs.lines(tracing::Level::INFO, "connection state changed");
        assert_eq!(
            changed.last().map(|line| line.fields.as_str()),
            Some(
                " from=\"live\" to=\"restarting\" reason=\"worker exited\" demand=1 error=\"worker_crashed\""
            )
        );
        // Reports from the dead worker are ignored.
        m.handle(Input::Report(WorkerReport::Live), now);
        assert_eq!(m.state(), S::Restarting);
        assert!(m.handle(Input::Demand(2), now).is_empty());
        assert_eq!(
            m.handle(Input::CrashBackoffExpired, now),
            [Action::SpawnWorker]
        );
        assert_eq!(m.state(), S::Connecting);
        // A second crash before it ran stably doubles the delay.
        let soon = now + Duration::from_secs(10);
        assert_eq!(
            m.handle(Input::WorkerExited, soon),
            [Action::StartCrashBackoff(Duration::from_secs(1))]
        );
        m.handle(Input::CrashBackoffExpired, soon);
        // A worker that ran stably resets the schedule.
        let later = soon + DEFAULT_STABLE_AFTER;
        assert_eq!(
            m.handle(Input::WorkerExited, later),
            [Action::StartCrashBackoff(Duration::from_millis(500))]
        );
        assert_eq!(m.crashes(), 3);
        assert!(
            m.handle(Input::CrashBackoffExpired, later)
                .contains(&Action::SpawnWorker)
        );
        assert!(
            m.handle(Input::CrashBackoffExpired, later).is_empty(),
            "stale timer"
        );
    }

    #[test]
    fn a_crash_without_demand_goes_idle() {
        let now = SystemClock.now();
        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(Input::Demand(0), now);
        assert_eq!(m.state(), S::Draining);
        assert_eq!(m.handle(Input::WorkerExited, now), [Action::CancelLinger]);
        assert_eq!(m.state(), S::Idle);
        assert_eq!(m.crashes(), 1);

        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::WorkerExited, now);
        assert_eq!(m.state(), S::Restarting);
        assert_eq!(
            m.handle(Input::Demand(0), now),
            [Action::CancelCrashBackoff]
        );
        assert_eq!(m.state(), S::Idle);
        assert!(
            m.handle(Input::WorkerExited, now).is_empty(),
            "nothing running"
        );
        assert_eq!(m.crashes(), 1);
    }
}

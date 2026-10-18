//! The source-connection state machine as the supervisor drives it: demand,
//! the worker's reports, the worker's exit and three timers in; worker
//! spawn and stop, linger, crash-backoff and backoff-window timers out.
//!
//! A failed attempt or a crash opens a backoff window: until the delay the
//! worker reported, or the crash backoff, is over, no new worker connects
//! to the source. A worker stopped for want of demand inside the window
//! leaves the connection idle but failed, so a viewer that re-offers in a
//! loop is refused with the last error instead of making the camera see a
//! new login each time; demand inside the window waits for its end.
//!
//! Pure: no I/O, no clock of its own. The driver feeds inputs with the
//! current instant and performs the actions, so every transition is unit
//! tested here. One machine runs per `SourceConnection`; demand is the sum
//! over every stream and sink that references it.

use std::time::{Duration, Instant};

use crate::backoff::{BackoffPosition, CrashBackoff};
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
    /// The worker keeps reporting, and new demand resumes the state its
    /// reports since leaving `Live` lead to.
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
    /// The source streamed long enough that the worker's reconnect
    /// schedule starts over at its first step.
    Stable,
    /// The live source dropped for this reason; an attempt starts at once:
    /// the schedule's immediate attempt, which is used from now on.
    Reconnecting(SourceError),
    /// An attempt failed; the next one is `retry_in` away.
    Backoff {
        /// Why the attempt failed.
        error: SourceError,
        /// The wait before the next attempt.
        retry_in: Duration,
        /// Where the worker's reconnect schedule stands, this delay
        /// included.
        position: BackoffPosition,
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
    /// The backoff-window timer the machine asked for fired.
    BackoffWindowExpired,
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
    /// Start the backoff-window timer, replacing one that runs; feed
    /// `BackoffWindowExpired` when it fires.
    StartBackoffWindow(Duration),
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

/// The reconnect state of the standby a switch in place runs beside the
/// source: its own schedule position and delay, which become the
/// connection's once it takes over or the next worker runs its source.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Standby {
    /// The switch it was started for: reports of a standby it replaced,
    /// still on their way, carry an older one and are stale.
    generation: u64,
    /// Where its reconnect schedule stands, as it reported.
    position: BackoffPosition,
    /// The delay it waits out after a failed attempt or a drop.
    delay: Option<StandbyDelay>,
    /// It was live at its last report, so a delay now follows a drop.
    live: bool,
}

/// A standby's reconnect delay and why it waits it out.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StandbyDelay {
    /// Its end.
    until: Instant,
    /// The error of the attempt that failed, or of the drop.
    error: SourceError,
    /// It follows a drop of the live standby, not a failed attempt.
    dropped: bool,
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
    /// The `Backoff` under way follows a live source that dropped, not an
    /// attempt that failed: the source may well come back.
    dropped: bool,
    /// While `Draining`, the state the worker's reports since leaving
    /// `Live` lead to, which new demand resumes: `Live` until one says
    /// otherwise, and only ever `Live`, `Connecting`, `Reconnecting` or
    /// `Backoff`.
    resume: ConnectionState,
    /// Worker crashes so far, for `stream/get`.
    crashes: u32,
    /// The end of the backoff window: the earliest a new worker may connect
    /// to the source, after the reconnect delay the last failed attempt
    /// reported or the crash backoff. Cleared once an attempt starts or the
    /// source goes live, when the backoff-window timer fires, and on
    /// entering `Idle` when it is already over: while `Idle` it is always
    /// in the future, with the timer running until it.
    not_before: Option<Instant>,
    /// Where the worker's reconnect schedule stands, as its reports say:
    /// where the next worker's schedule continues, so a source that keeps
    /// failing is not retried at the first step's pace, nor at once again,
    /// whenever a worker starts over. A `Backoff` carries it whole, a
    /// `Reconnecting` uses the immediate attempt, and `Stable` starts it
    /// over; the machine never moves it on its own.
    backoff: BackoffPosition,
    /// The standby of a switch in place, until it takes over or its worker
    /// goes.
    standby: Option<Standby>,
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
            dropped: false,
            resume: ConnectionState::Live,
            crashes: 0,
            not_before: None,
            backoff: BackoffPosition {
                attempts: 0,
                immediate_used: false,
            },
            standby: None,
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

    /// The failure a viewer still waiting for its answer cannot ride out:
    /// the last error while an attempt failed (`Backoff`), the worker
    /// crashed (`Restarting`), or either left the connection idle inside
    /// its backoff window, where a new viewer would get no attempt before
    /// the window ends. In any other state the last error is stale, from an
    /// attempt before the current one, or a drop the worker is retrying: a
    /// live source that dropped is retried at once (`Reconnecting`) or,
    /// after its first drop since streaming stably, after a delay
    /// (`Backoff` from `Live`), and only a retry that fails is one.
    pub const fn failure(&self) -> Option<&ConnectionError> {
        match self.state {
            ConnectionState::Backoff if !self.dropped => self.last_error.as_ref(),
            ConnectionState::Idle if self.not_before.is_some() && !self.dropped => {
                self.last_error.as_ref()
            }
            ConnectionState::Restarting => self.last_error.as_ref(),
            ConnectionState::Idle
            | ConnectionState::Connecting
            | ConnectionState::Live
            | ConnectionState::Reconnecting
            | ConnectionState::Backoff
            | ConnectionState::Draining => None,
        }
    }

    /// Worker crashes so far.
    pub const fn crashes(&self) -> u32 {
        self.crashes
    }

    /// Where the worker's reconnect schedule stands, and the next
    /// worker's starts.
    pub const fn backoff_position(&self) -> BackoffPosition {
        self.backoff
    }

    /// The connection runs another source from now on, which has failed
    /// no attempt yet. With `standby_generation`, a running worker starts
    /// it as a standby for that switch beside the old source, whose reports
    /// still count until it takes over ([`Self::standby_report`],
    /// [`Self::standby_took_over`]); without, the next worker runs it, its
    /// schedule at the first step. A backoff window under way still holds
    /// either way, so the switch is no way around it to a new login.
    pub fn source_switched(&mut self, standby_generation: Option<u64>) {
        self.standby = standby_generation.map(|generation| Standby {
            generation,
            position: BackoffPosition::default(),
            delay: None,
            live: false,
        });
        if standby_generation.is_none() {
            self.backoff = BackoffPosition::default();
        }
    }

    /// The standby of switch `generation` reported at `now`: a failed
    /// attempt or a drop opens its own delay, an attempt under way or a
    /// live standby ends it, and its position moves as the connection's
    /// does. A report of another switch's standby, or without one, is
    /// stale.
    pub fn standby_report(&mut self, generation: u64, report: &WorkerReport, now: Instant) {
        let Some(standby) = self
            .standby
            .as_mut()
            .filter(|standby| standby.generation == generation)
        else {
            tracing::debug!(generation, "report of a standby that is gone; ignored");
            return;
        };
        match report {
            WorkerReport::Backoff {
                error,
                retry_in,
                position,
            } => {
                let dropped = standby.live;
                standby.delay = now.checked_add(*retry_in).map(|until| StandbyDelay {
                    until,
                    error: error.clone(),
                    dropped,
                });
                standby.position = *position;
                standby.live = false;
            }
            WorkerReport::Stable => standby.position = BackoffPosition::default(),
            WorkerReport::Live => {
                standby.delay = None;
                standby.live = true;
            }
            WorkerReport::Reconnecting(_) => {
                standby.delay = None;
                standby.live = false;
                standby.position.immediate_used = true;
            }
            WorkerReport::Connecting => standby.delay = None,
        }
    }

    /// The standby took over: it is the source now, live, and its schedule
    /// position is the connection's.
    pub fn standby_took_over(&mut self) {
        if let Some(standby) = self.standby.take() {
            self.backoff = standby.position;
        }
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
                self.on_report(report, now);
                "worker report"
            }
            Input::WorkerExited => {
                self.on_worker_exited(now, &mut actions);
                "worker exited"
            }
            Input::LingerExpired => {
                if self.state == ConnectionState::Draining {
                    self.stop_worker(now, &mut actions);
                }
                "linger expired"
            }
            Input::CrashBackoffExpired => {
                if self.state == ConnectionState::Restarting {
                    self.spawn_worker(now, &mut actions);
                }
                "crash backoff expired"
            }
            Input::BackoffWindowExpired => {
                self.on_window_expired(now, &mut actions);
                "backoff window expired"
            }
        };
        if from != self.state {
            tracing::info!(
                from = from.name(),
                to = self.state.name(),
                reason,
                demand = self.demand,
                error = self.last_error.as_ref().map(ConnectionError::code),
                failed = self.failure().is_some(),
                "connection state changed"
            );
        }
        actions
    }

    /// Demand changed.
    fn on_demand(&mut self, now: Instant, actions: &mut Vec<Action>) {
        let wanted = self.demand > 0;
        match (self.state, wanted) {
            (ConnectionState::Idle, true) => match self.window_left(now) {
                Some(left) => tracing::info!(
                    demand = self.demand,
                    remaining_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX),
                    error = self.last_error.as_ref().map(ConnectionError::code),
                    reason = "the last attempt failed or the worker crashed",
                    "demand inside the backoff window; no worker connects to the source before it ends"
                ),
                None => self.spawn_worker(now, actions),
            },
            (
                ConnectionState::Connecting
                | ConnectionState::Reconnecting
                | ConnectionState::Backoff,
                false,
            ) => self.stop_worker(now, actions),
            (ConnectionState::Live, false) => {
                actions.push(Action::StartLinger(self.config.linger));
                self.resume = ConnectionState::Live;
                self.state = ConnectionState::Draining;
            }
            (ConnectionState::Draining, true) => {
                actions.push(Action::CancelLinger);
                self.state = self.resume;
            }
            (ConnectionState::Restarting, false) => {
                actions.push(Action::CancelCrashBackoff);
                self.enter_idle(now, actions);
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

    /// The worker reported at `now`. Reports while no worker is wanted are
    /// stale; while `Draining` they move the state new demand resumes, as
    /// they would move the state with demand, so a drop or a failed retry
    /// during the linger is not resumed as `Live`. A failed attempt opens
    /// the backoff window until its reconnect delay is over.
    fn on_report(&mut self, report: WorkerReport, now: Instant) {
        use ConnectionState as S;
        if self.state == S::Draining {
            self.state = self.resume;
            self.on_report(report, now);
            self.resume = self.state;
            self.state = S::Draining;
            return;
        }
        match (self.state, report) {
            (S::Connecting | S::Reconnecting | S::Backoff, WorkerReport::Live) => {
                self.last_error = None;
                self.not_before = None;
                self.state = S::Live;
            }
            (S::Reconnecting | S::Backoff, WorkerReport::Connecting) => {
                self.not_before = None;
                self.state = S::Connecting;
            }
            (S::Live, WorkerReport::Stable) => {
                tracing::info!(
                    attempts = self.backoff.attempts,
                    "source streamed stably; the next worker's reconnect schedule starts at its first step"
                );
                self.backoff = BackoffPosition::default();
            }
            (S::Live | S::Reconnecting, WorkerReport::Reconnecting(error)) => {
                self.last_error = Some(ConnectionError::Source(error));
                self.backoff.immediate_used = true;
                self.state = S::Reconnecting;
            }
            (
                from @ (S::Connecting | S::Reconnecting | S::Live),
                WorkerReport::Backoff {
                    error,
                    retry_in,
                    position,
                },
            ) => {
                self.last_error = Some(ConnectionError::Source(error));
                self.dropped = from == S::Live;
                self.not_before = now.checked_add(retry_in);
                self.backoff = position;
                self.state = S::Backoff;
            }
            // `Draining` is handled above, on the state it resumes.
            (S::Idle | S::Restarting | S::Draining, _)
            | (S::Connecting | S::Live, WorkerReport::Connecting)
            | (S::Live, WorkerReport::Live)
            | (S::Connecting | S::Backoff, WorkerReport::Reconnecting(_))
            | (S::Connecting | S::Reconnecting | S::Backoff, WorkerReport::Stable)
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
        // A crash is a failure whatever the attempt before it was.
        self.dropped = false;
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
        // The next worker waits out the crash backoff or the source's own
        // delay, whichever ends later, with demand or without; the crash is
        // the failure.
        self.adopt_standby(true);
        let source_left = self.window_left(now).unwrap_or_default();
        let wait = self.crash.next_delay().max(source_left);
        self.not_before = now.checked_add(wait);
        if self.demand > 0 {
            tracing::warn!(
                crashes = self.crashes,
                retry_ms = wait.as_millis(),
                "worker crashed; restarting after backoff"
            );
            actions.push(Action::StartCrashBackoff(wait));
            self.state = ConnectionState::Restarting;
        } else {
            tracing::warn!(crashes = self.crashes, "worker crashed with no demand left");
            self.enter_idle(now, actions);
        }
    }

    /// The backoff-window timer fired: demand that waited for it starts a
    /// worker. Only an idle connection has the timer running; one that
    /// spawned a worker meanwhile, because demand came at the window's
    /// end before the timer, has no window left and ignores it.
    fn on_window_expired(&mut self, now: Instant, actions: &mut Vec<Action>) {
        if self.state == ConnectionState::Idle && self.not_before.take().is_some() {
            tracing::info!(
                demand = self.demand,
                "backoff window over; demand connects to the source again"
            );
            if self.demand > 0 {
                self.spawn_worker(now, actions);
            }
        }
    }

    /// What is left of the backoff window at `now`; `None` once `now`
    /// reaches its end.
    fn window_left(&self, now: Instant) -> Option<Duration> {
        self.not_before
            .filter(|until| now < *until)
            .map(|until| until.saturating_duration_since(now))
    }

    /// Asks for a worker and moves to `Connecting`. Every spawn comes at
    /// or after the backoff window's end, so the window needs no clearing.
    fn spawn_worker(&mut self, now: Instant, actions: &mut Vec<Action>) {
        actions.push(Action::SpawnWorker);
        self.worker_since = Some(now);
        self.state = ConnectionState::Connecting;
    }

    /// Asks the worker to stop and moves to `Idle`; its exit is then expected.
    fn stop_worker(&mut self, now: Instant, actions: &mut Vec<Action>) {
        actions.push(Action::StopWorker);
        self.stopping = true;
        self.adopt_standby(false);
        self.enter_idle(now, actions);
    }

    /// The worker goes with a standby beside its source: the next worker
    /// runs the source switched to, so its position is the standby's, and
    /// a delay the standby waits out holds as long as the old source's
    /// would. After a normal stop that delay's error and its kind, failed
    /// attempt or drop, are the connection's, so an offer meanwhile is
    /// refused as it would be for the source's own failure; after a crash
    /// the crash is.
    fn adopt_standby(&mut self, crashed: bool) {
        if let Some(standby) = self.standby.take() {
            self.backoff = standby.position;
            if let Some(delay) = standby.delay {
                self.not_before = self.not_before.max(Some(delay.until));
                if !crashed {
                    self.last_error = Some(ConnectionError::Source(delay.error));
                    self.dropped = delay.dropped;
                }
            }
        }
    }

    /// Moves to `Idle` without a worker. A backoff window still open keeps
    /// the connection failed until it ends, with its timer started; one
    /// already over is forgotten.
    fn enter_idle(&mut self, now: Instant, actions: &mut Vec<Action>) {
        self.state = ConnectionState::Idle;
        match self.window_left(now) {
            Some(left) => {
                tracing::info!(
                    remaining_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX),
                    error = self.last_error.as_ref().map(ConnectionError::code),
                    failed = !self.dropped,
                    reason = "the last attempt failed or the worker crashed",
                    "connection idle inside its backoff window; no worker connects to the source before it ends"
                );
                actions.push(Action::StartBackoffWindow(left));
            }
            None => self.not_before = None,
        }
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
    use crate::clock::{Clock as _, FakeClock, SystemClock};

    use ConnectionState as S;

    fn machine() -> ConnectionMachine {
        ConnectionMachine::new(ConnectionConfig::default())
    }

    fn at(attempts: u32) -> BackoffPosition {
        BackoffPosition {
            attempts,
            immediate_used: false,
        }
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
    fn a_failed_attempt_and_a_crash_are_failures_a_drop_is_not() {
        let now = SystemClock.now();
        let mut m = machine();
        let backoff = |error| {
            Input::Report(WorkerReport::Backoff {
                error,
                retry_in: Duration::from_secs(1),
                position: at(1),
            })
        };
        m.handle(Input::Demand(1), now);
        assert_eq!(m.failure(), None);
        // The first attempt fails.
        m.handle(backoff(SourceError::Unreachable("refused".into())), now);
        assert_eq!(
            m.failure().map(ConnectionError::code),
            Some("source_unreachable")
        );
        // The retry connects: the error is stale.
        m.handle(Input::Report(WorkerReport::Connecting), now);
        assert_eq!(m.state(), S::Connecting);
        assert_eq!(m.failure(), None);
        m.handle(Input::Report(WorkerReport::Live), now);
        assert_eq!(m.failure(), None);
        // A live source that drops is retried, at once or after a delay.
        m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now);
        assert_eq!(m.failure(), None);
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(backoff(SourceError::Ended("eof".into())), now);
        assert_eq!(m.state(), S::Backoff);
        assert_eq!(m.failure(), None, "a drop");
        // Its retry fails.
        m.handle(Input::Report(WorkerReport::Connecting), now);
        m.handle(backoff(timeout()), now);
        assert_eq!(
            m.failure().map(ConnectionError::code),
            Some("source_timeout")
        );
        // The immediate retry after a drop fails.
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(Input::Report(WorkerReport::Reconnecting(timeout())), now);
        m.handle(backoff(SourceError::Ended("eof".into())), now);
        assert_eq!(m.failure().map(ConnectionError::code), Some("source_ended"));
        // The worker crashes.
        m.handle(Input::WorkerExited, now);
        assert_eq!(m.state(), S::Restarting);
        assert_eq!(m.failure(), Some(&ConnectionError::WorkerCrashed));
        // Lingering is no failure, whatever came before.
        m.handle(Input::CrashBackoffExpired, now);
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(Input::Demand(0), now);
        assert_eq!(m.state(), S::Draining);
        m.handle(backoff(timeout()), now);
        assert_eq!(m.failure(), None);
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
            position: at(1),
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
                position: at(1),
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
                position: at(1),
            }),
            now,
        );
        assert_eq!(m.state(), S::Draining);
        // The attempt failed: the window of its delay holds.
        assert_eq!(
            m.handle(Input::LingerExpired, now),
            [
                Action::StopWorker,
                Action::StartBackoffWindow(Duration::from_secs(1))
            ]
        );
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
    fn demand_during_the_linger_resumes_what_the_worker_last_reported() {
        let clock = FakeClock::default();
        let backoff = |error| {
            Input::Report(WorkerReport::Backoff {
                error,
                retry_in: Duration::from_secs(1),
                position: at(1),
            })
        };
        let draining = || {
            let mut m = machine();
            m.handle(Input::Demand(1), clock.now());
            m.handle(Input::Report(WorkerReport::Live), clock.now());
            m.handle(Input::Demand(0), clock.now());
            assert_eq!(m.state(), S::Draining);
            m
        };

        // The source dropped and is being retried at once: no failure yet.
        let mut m = draining();
        m.handle(
            Input::Report(WorkerReport::Reconnecting(timeout())),
            clock.now(),
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::CancelLinger]
        );
        assert_eq!(m.state(), S::Reconnecting);
        assert_eq!(m.failure(), None);
        // The retry fails: the failure a waiting viewer closes with.
        m.handle(backoff(SourceError::Ended("eof".into())), clock.now());
        assert_eq!(m.state(), S::Backoff);
        assert_eq!(m.failure().map(ConnectionError::code), Some("source_ended"));
        // It recovers; the next linger starts from live again.
        m.handle(Input::Report(WorkerReport::Connecting), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(Input::Demand(0), clock.now());
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::CancelLinger]
        );
        assert_eq!(m.state(), S::Live);

        // The retry already failed during the linger.
        let mut m = draining();
        m.handle(
            Input::Report(WorkerReport::Reconnecting(timeout())),
            clock.now(),
        );
        m.handle(backoff(SourceError::Ended("eof".into())), clock.now());
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::CancelLinger]
        );
        assert_eq!(m.state(), S::Backoff);
        assert_eq!(m.failure().map(ConnectionError::code), Some("source_ended"));

        // The source dropped straight into a delay: a drop, no failure.
        let mut m = draining();
        m.handle(backoff(timeout()), clock.now());
        m.handle(Input::Demand(1), clock.now());
        assert_eq!(m.state(), S::Backoff);
        assert_eq!(
            m.last_error().map(ConnectionError::code),
            Some("source_timeout")
        );
        assert_eq!(m.failure(), None, "a drop");
        // Its retry is under way.
        let mut m = draining();
        m.handle(backoff(timeout()), clock.now());
        m.handle(Input::Report(WorkerReport::Connecting), clock.now());
        m.handle(Input::Demand(1), clock.now());
        assert_eq!(m.state(), S::Connecting);
        assert_eq!(m.failure(), None);

        // The source came back during the linger: live again.
        let mut m = draining();
        m.handle(
            Input::Report(WorkerReport::Reconnecting(timeout())),
            clock.now(),
        );
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::CancelLinger]
        );
        assert_eq!(m.state(), S::Live);
        assert_eq!(m.last_error(), None);
    }

    #[test]
    fn losing_demand_while_not_live_stops_the_worker_at_once() {
        let now = SystemClock.now();
        for (report, stop) in [
            (None, vec![Action::StopWorker]),
            (
                Some(WorkerReport::Backoff {
                    error: timeout(),
                    retry_in: Duration::from_secs(1),
                    position: at(1),
                }),
                vec![
                    Action::StopWorker,
                    Action::StartBackoffWindow(Duration::from_secs(1)),
                ],
            ),
        ] {
            let mut m = machine();
            m.handle(Input::Demand(1), now);
            if let Some(report) = report {
                m.handle(Input::Report(report), now);
            }
            assert_eq!(m.handle(Input::Demand(0), now), stop);
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
                " from=\"live\" to=\"restarting\" reason=\"worker exited\" demand=1 error=\"worker_crashed\" failed=true"
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

    fn failed_attempt(retry_in: Duration) -> Input {
        Input::Report(WorkerReport::Backoff {
            error: SourceError::AuthFailed("401".into()),
            retry_in,
            position: at(1),
        })
    }

    /// A re-offer right after a failed attempt is no new camera login:
    /// until the reconnect delay the worker reported is over, an idle
    /// connection counts as failed and demand starts no worker; the window
    /// timer's end lets the demand that waited connect.
    #[test]
    fn a_re_offer_inside_the_reconnect_delay_connects_to_nothing() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_attempt(Duration::from_secs(5)), clock.now());
        // The waiting viewer closes with the failure; the demand goes.
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [
                Action::StopWorker,
                Action::StartBackoffWindow(Duration::from_secs(5))
            ]
        );
        assert_eq!(m.state(), S::Idle);
        assert_eq!(
            m.failure().map(ConnectionError::code),
            Some("source_auth_failed")
        );
        let idle = logs.lines(
            tracing::Level::INFO,
            "connection idle inside its backoff window; no worker connects to the source before it ends",
        );
        assert_eq!(idle.len(), 1);
        assert_eq!(
            idle[0].fields,
            " remaining_ms=5000 error=\"source_auth_failed\" failed=true reason=\"the last attempt failed or the worker crashed\""
        );
        // The viewer re-offers: no worker, still failed.
        clock.advance(Duration::from_secs(1));
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());
        assert_eq!(m.state(), S::Idle);
        assert!(m.failure().is_some());
        let held = logs.lines(
            tracing::Level::INFO,
            "demand inside the backoff window; no worker connects to the source before it ends",
        );
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].fields,
            " demand=1 remaining_ms=4000 error=\"source_auth_failed\" reason=\"the last attempt failed or the worker crashed\""
        );
        m.handle(Input::Demand(0), clock.now());
        // A moment before the end: still nothing.
        clock.advance(Duration::from_secs(4) - Duration::from_nanos(1));
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());
        // The timer fires at the end: the demand that waited connects.
        clock.advance(Duration::from_nanos(1));
        assert_eq!(
            m.handle(Input::BackoffWindowExpired, clock.now()),
            [Action::SpawnWorker]
        );
        assert_eq!(m.state(), S::Connecting);
        assert_eq!(m.failure(), None);
        assert_eq!(
            logs.lines(
                tracing::Level::INFO,
                "backoff window over; demand connects to the source again"
            )[0]
            .fields,
            " demand=1"
        );
    }

    /// The window ends exactly at the reported delay: demand then connects
    /// even before the timer is seen, and the timer after it is stale.
    #[test]
    fn demand_exactly_at_the_window_s_end_connects() {
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_attempt(Duration::from_secs(5)), clock.now());
        m.handle(Input::Demand(0), clock.now());
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::SpawnWorker]
        );
        assert!(
            m.handle(Input::BackoffWindowExpired, clock.now())
                .is_empty(),
            "stale timer"
        );
        assert_eq!(m.state(), S::Connecting);

        // The timer without demand only ends the failure.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_attempt(Duration::from_secs(5)), clock.now());
        m.handle(Input::Demand(0), clock.now());
        clock.advance(Duration::from_secs(5));
        assert!(
            m.handle(Input::BackoffWindowExpired, clock.now())
                .is_empty()
        );
        assert_eq!((m.state(), m.failure()), (S::Idle, None));
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::SpawnWorker]
        );
    }

    /// The worker stopped exactly at the window's end, or after it: no
    /// window is left, the connection is idle and not failed.
    #[test]
    fn a_worker_stopped_at_the_window_s_end_leaves_no_window() {
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_attempt(Duration::from_secs(5)), clock.now());
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [Action::StopWorker]
        );
        assert_eq!((m.state(), m.failure()), (S::Idle, None));
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::SpawnWorker]
        );

        // A moment before the end, the rest of it holds.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_attempt(Duration::from_secs(5)), clock.now());
        clock.advance(Duration::from_secs(5) - Duration::from_nanos(1));
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [
                Action::StopWorker,
                Action::StartBackoffWindow(Duration::from_nanos(1))
            ]
        );
        assert!(m.failure().is_some());
    }

    /// The crash backoff is a window too: a worker that crashed is not
    /// restarted early because the demand went and came back.
    #[test]
    fn a_re_offer_inside_the_crash_backoff_connects_to_nothing() {
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        assert_eq!(
            m.handle(Input::WorkerExited, clock.now()),
            [Action::StartCrashBackoff(Duration::from_millis(500))]
        );
        clock.advance(Duration::from_millis(100));
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [
                Action::CancelCrashBackoff,
                Action::StartBackoffWindow(Duration::from_millis(400))
            ]
        );
        assert_eq!(m.failure(), Some(&ConnectionError::WorkerCrashed));
        clock.advance(Duration::from_millis(399));
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());
        m.handle(Input::Demand(0), clock.now());
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            m.handle(Input::Demand(1), clock.now()),
            [Action::SpawnWorker]
        );

        // A crash is a failure even after a drop that was not one.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(failed_attempt(Duration::from_secs(1)), clock.now());
        assert_eq!(m.failure(), None, "a drop");
        m.handle(Input::WorkerExited, clock.now());
        m.handle(Input::Demand(0), clock.now());
        assert_eq!(m.state(), S::Idle);
        assert_eq!(m.failure(), Some(&ConnectionError::WorkerCrashed));

        // A crash during the linger keeps the window of the failed attempt.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(Input::Demand(0), clock.now());
        m.handle(Input::Report(WorkerReport::Connecting), clock.now());
        m.handle(failed_attempt(Duration::from_secs(10)), clock.now());
        assert_eq!(
            m.handle(Input::WorkerExited, clock.now()),
            [
                Action::CancelLinger,
                Action::StartBackoffWindow(Duration::from_secs(10))
            ]
        );
        assert_eq!(m.failure(), Some(&ConnectionError::WorkerCrashed));
    }

    /// A live source that dropped into a delay is no failure: a viewer
    /// during its window waits, and connects once it ends, rather than
    /// being refused.
    #[test]
    fn demand_inside_the_window_of_a_drop_waits_for_its_end() {
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(failed_attempt(Duration::from_secs(1)), clock.now());
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [
                Action::StopWorker,
                Action::StartBackoffWindow(Duration::from_secs(1))
            ]
        );
        assert_eq!(m.failure(), None, "a drop");
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            m.handle(Input::BackoffWindowExpired, clock.now()),
            [Action::SpawnWorker]
        );
    }

    /// An attempt under way or a live source ends the window: the worker
    /// waited the delay out itself.
    #[test]
    fn an_attempt_or_going_live_ends_the_window() {
        let clock = FakeClock::default();
        for report in [WorkerReport::Connecting, WorkerReport::Live] {
            let mut m = machine();
            m.handle(Input::Demand(1), clock.now());
            m.handle(failed_attempt(Duration::from_secs(10)), clock.now());
            m.handle(Input::Report(report), clock.now());
            // Stopped at once while connecting, after the linger once live.
            let mut actions = m.handle(Input::Demand(0), clock.now());
            actions.extend(m.handle(Input::LingerExpired, clock.now()));
            assert!(actions.contains(&Action::StopWorker), "{actions:?}");
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, Action::StartBackoffWindow(_))),
                "{actions:?}"
            );
            assert_eq!(m.state(), S::Idle);
            assert_eq!(m.failure(), None);
            assert_eq!(
                m.handle(Input::Demand(1), clock.now()),
                [Action::SpawnWorker]
            );
        }
        // A window timer while the worker runs is stale, and the window
        // is still there when it stops.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_attempt(Duration::from_secs(5)), clock.now());
        assert!(
            m.handle(Input::BackoffWindowExpired, clock.now())
                .is_empty()
        );
        assert_eq!(m.state(), S::Backoff);
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [
                Action::StopWorker,
                Action::StartBackoffWindow(Duration::from_secs(5))
            ]
        );
    }

    fn failed_at(attempts: u32) -> Input {
        Input::Report(WorkerReport::Backoff {
            error: timeout(),
            retry_in: Duration::from_secs(1),
            position: at(attempts),
        })
    }

    /// The position the next worker's schedule continues from is where the
    /// worker's own schedule stood at its last failed attempt: kept across
    /// workers and crashes, moved by reports during the linger, and not
    /// rewound by a brief recovery, after which the worker's schedule goes
    /// on where it was.
    #[test]
    fn backoff_attempts_follow_the_worker_s_schedule() {
        let clock = FakeClock::default();
        let mut m = machine();
        assert_eq!(m.backoff_position().attempts, 0);
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_at(5), clock.now());
        assert_eq!(m.backoff_position().attempts, 5);
        // A repeated report is stale.
        m.handle(failed_at(9), clock.now());
        assert_eq!(m.backoff_position().attempts, 5);
        // A brief recovery: live, a drop, its retry fails a step further.
        m.handle(Input::Report(WorkerReport::Connecting), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        assert_eq!(
            m.backoff_position().attempts,
            5,
            "not rewound by going live"
        );
        m.handle(
            Input::Report(WorkerReport::Reconnecting(timeout())),
            clock.now(),
        );
        m.handle(failed_at(6), clock.now());
        assert_eq!(m.backoff_position().attempts, 6);
        // The next worker continues it, after a stop or a crash.
        m.handle(Input::Demand(0), clock.now());
        m.handle(Input::WorkerExited, clock.now());
        clock.advance(Duration::from_secs(1));
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::WorkerExited, clock.now());
        assert_eq!(m.state(), S::Restarting);
        assert_eq!(m.backoff_position().attempts, 6);
        clock.advance(Duration::from_secs(1));
        m.handle(Input::CrashBackoffExpired, clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        // During the linger too: a worker that streamed stably starts over.
        m.handle(Input::Demand(0), clock.now());
        m.handle(failed_at(1), clock.now());
        assert_eq!(m.backoff_position().attempts, 1);
    }

    /// Another source starts its schedule at the first step, but the
    /// backoff window of the last one's failure still holds.
    #[test]
    fn a_switched_source_starts_its_schedule_over_inside_the_window() {
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_at(4), clock.now());
        m.handle(Input::Demand(0), clock.now());
        m.source_switched(None);
        assert_eq!(m.backoff_position().attempts, 0);
        assert!(m.failure().is_some());
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());
    }

    fn failed_for(retry_in: Duration, attempts: u32) -> WorkerReport {
        WorkerReport::Backoff {
            error: timeout(),
            retry_in,
            position: at(attempts),
        }
    }

    /// The worker's schedule starts over once the source streamed stably:
    /// the next worker starts at the first step after a stop while
    /// streaming or during the immediate retry of a stable drop, but a
    /// stale report changes nothing.
    #[test]
    fn stable_streaming_starts_the_next_worker_s_schedule_over() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clock = FakeClock::default();
        let streaming = || {
            let mut m = machine();
            m.handle(Input::Demand(1), clock.now());
            m.handle(failed_at(20), clock.now());
            m.handle(Input::Report(WorkerReport::Connecting), clock.now());
            m.handle(Input::Report(WorkerReport::Live), clock.now());
            m
        };
        // A normal stop after stable streaming.
        let mut m = streaming();
        m.handle(Input::Report(WorkerReport::Stable), clock.now());
        assert_eq!(m.backoff_position().attempts, 0);
        m.handle(Input::Demand(0), clock.now());
        m.handle(Input::LingerExpired, clock.now());
        m.handle(Input::WorkerExited, clock.now());
        assert_eq!((m.state(), m.backoff_position().attempts), (S::Idle, 0));
        let stable = logs.lines(
            tracing::Level::INFO,
            "source streamed stably; the next worker's reconnect schedule starts at its first step",
        );
        assert_eq!(stable[0].fields, " attempts=20");
        // A stop during a stable drop's immediate retry.
        let mut m = streaming();
        m.handle(Input::Report(WorkerReport::Stable), clock.now());
        m.handle(
            Input::Report(WorkerReport::Reconnecting(timeout())),
            clock.now(),
        );
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [Action::StopWorker]
        );
        assert_eq!(m.backoff_position().attempts, 0);
        // Stable during the linger.
        let mut m = streaming();
        m.handle(Input::Demand(0), clock.now());
        m.handle(Input::Report(WorkerReport::Stable), clock.now());
        assert_eq!(m.backoff_position().attempts, 0);
        // A stale one, while the worker waits out a delay.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_at(3), clock.now());
        m.handle(Input::Report(WorkerReport::Stable), clock.now());
        assert_eq!(m.backoff_position().attempts, 3);
    }

    /// A crash keeps the source's own delay when it is the longer: a
    /// worker in a 60 s delay that crashes is not restarted after the
    /// crash backoff's 500 ms, with demand or without.
    #[test]
    fn a_crash_waits_out_the_longer_of_its_backoff_and_the_source_s_delay() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(
            Input::Report(failed_for(Duration::from_secs(60), 1)),
            clock.now(),
        );
        clock.advance(Duration::from_secs(10));
        assert_eq!(
            m.handle(Input::WorkerExited, clock.now()),
            [Action::StartCrashBackoff(Duration::from_secs(50))]
        );
        assert_eq!(
            logs.lines(
                tracing::Level::WARN,
                "worker crashed; restarting after backoff"
            )[0]
            .fields,
            " crashes=1 retry_ms=50000"
        );
        // The demand goes and comes back: the window is the same.
        assert_eq!(
            m.handle(Input::Demand(0), clock.now()),
            [
                Action::CancelCrashBackoff,
                Action::StartBackoffWindow(Duration::from_secs(50))
            ]
        );
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());

        // Without demand: a healthy worker crashes during the linger.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(Input::Demand(0), clock.now());
        m.handle(Input::WorkerExited, clock.now());
        assert_eq!(m.failure(), Some(&ConnectionError::WorkerCrashed));
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());
        clock.advance(Duration::from_millis(500));
        assert_eq!(
            m.handle(Input::BackoffWindowExpired, clock.now()),
            [Action::SpawnWorker]
        );
    }

    /// A standby's own failure keeps its window and position: stopping
    /// the worker while the standby waits out a delay hands both to the
    /// next worker, which runs the source switched to.
    #[test]
    fn a_stop_during_the_standby_s_delay_keeps_its_window_and_position() {
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(failed_at(7), clock.now());
        m.handle(Input::Report(WorkerReport::Connecting), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.source_switched(Some(1));
        m.standby_report(1, &failed_for(Duration::from_secs(60), 2), clock.now());
        m.handle(Input::Demand(0), clock.now());
        assert_eq!(
            m.handle(Input::LingerExpired, clock.now()),
            [
                Action::StopWorker,
                Action::StartBackoffWindow(Duration::from_secs(60))
            ]
        );
        assert_eq!(m.backoff_position().attempts, 2, "the standby's");
        assert!(m.handle(Input::Demand(1), clock.now()).is_empty());

        // A crash hands them on too.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.source_switched(Some(1));
        m.standby_report(1, &failed_for(Duration::from_secs(60), 3), clock.now());
        assert_eq!(
            m.handle(Input::WorkerExited, clock.now()),
            [Action::StartCrashBackoff(Duration::from_secs(60))]
        );
        assert_eq!(m.backoff_position().attempts, 3);
    }

    /// A standby that takes over brings its position, not its finished
    /// delay; reports after it, with no standby left, are stale.
    #[test]
    fn a_standby_that_takes_over_brings_its_position() {
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(failed_at(9), clock.now());
        m.handle(Input::Report(WorkerReport::Connecting), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.source_switched(Some(1));
        m.standby_report(1, &failed_for(Duration::from_secs(60), 2), clock.now());
        m.standby_report(1, &WorkerReport::Connecting, clock.now());
        m.standby_report(1, &WorkerReport::Live, clock.now());
        m.standby_took_over();
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        assert_eq!(m.backoff_position().attempts, 2);
        m.standby_report(1, &failed_for(Duration::from_secs(60), 5), clock.now());
        m.standby_took_over();
        m.handle(Input::Demand(0), clock.now());
        assert_eq!(
            m.handle(Input::LingerExpired, clock.now()),
            [Action::StopWorker]
        );
        assert_eq!(m.backoff_position().attempts, 2);

        // A standby that streamed stably starts over; a drop or a retry
        // under way ends its delay.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.source_switched(Some(1));
        m.standby_report(1, &failed_for(Duration::from_secs(60), 4), clock.now());
        m.standby_report(1, &WorkerReport::Reconnecting(timeout()), clock.now());
        m.standby_report(1, &WorkerReport::Stable, clock.now());
        m.handle(Input::Demand(0), clock.now());
        assert_eq!(
            m.handle(Input::LingerExpired, clock.now()),
            [Action::StopWorker]
        );
        assert_eq!(m.backoff_position().attempts, 0);
    }

    /// The whole schedule position carries over: a worker stopped after
    /// its immediate attempt hands on that it is used, so the next one gets
    /// no second immediate retry; a failed attempt's report carries it, and
    /// stable streaming starts both over.
    #[test]
    fn the_position_carries_a_used_immediate_attempt() {
        let clock = FakeClock::default();
        let used = |attempts| BackoffPosition {
            attempts,
            immediate_used: true,
        };
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(
            Input::Report(WorkerReport::Reconnecting(timeout())),
            clock.now(),
        );
        assert_eq!(m.backoff_position(), used(0));
        m.handle(Input::Demand(0), clock.now());
        assert_eq!(m.backoff_position(), used(0), "the stopped worker's");
        // A report carries both halves.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(
            Input::Report(WorkerReport::Backoff {
                error: timeout(),
                retry_in: Duration::from_secs(1),
                position: used(3),
            }),
            clock.now(),
        );
        assert_eq!(m.backoff_position(), used(3));
        m.handle(Input::Report(WorkerReport::Connecting), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.handle(Input::Report(WorkerReport::Stable), clock.now());
        assert_eq!(m.backoff_position(), BackoffPosition::default());
    }

    /// Reports of a standby that a later switch replaced, still on their
    /// way, are not the new standby's: it takes over with its own position,
    /// and the replaced one's delay holds nothing back.
    #[test]
    fn a_replaced_standby_s_reports_are_stale() {
        let (logs, _guard) = crate::test_logs::Logs::capture();
        let clock = FakeClock::default();
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.source_switched(Some(1));
        m.standby_report(1, &failed_for(Duration::from_secs(1), 2), clock.now());
        m.source_switched(Some(2));
        m.standby_report(1, &failed_for(Duration::from_secs(60), 20), clock.now());
        assert_eq!(
            logs.lines(
                tracing::Level::DEBUG,
                "report of a standby that is gone; ignored"
            )[0]
            .fields,
            " generation=1"
        );
        m.standby_report(2, &WorkerReport::Connecting, clock.now());
        m.standby_report(2, &WorkerReport::Live, clock.now());
        m.standby_took_over();
        assert_eq!(m.backoff_position(), at(0), "the new standby's own");
        // A stale delay holds nothing back when the worker stops.
        m.source_switched(Some(3));
        m.standby_report(2, &failed_for(Duration::from_secs(60), 20), clock.now());
        m.handle(Input::Demand(0), clock.now());
        assert_eq!(
            m.handle(Input::LingerExpired, clock.now()),
            [Action::StopWorker]
        );
        assert_eq!(m.failure(), None);
    }

    /// The source switched to failed while the old one streamed: after a
    /// normal stop its failure is the connection's, so an offer inside its
    /// delay is refused; a drop of the live standby waits instead, and a
    /// crash stays the crash.
    #[test]
    fn a_standby_s_failure_is_the_connection_s_after_a_stop() {
        let clock = FakeClock::default();
        let stopped = |reports: &[WorkerReport]| {
            let mut m = machine();
            m.handle(Input::Demand(1), clock.now());
            m.handle(Input::Report(WorkerReport::Live), clock.now());
            m.source_switched(Some(1));
            for report in reports {
                m.standby_report(1, report, clock.now());
            }
            m.handle(Input::Demand(0), clock.now());
            let actions = m.handle(Input::LingerExpired, clock.now());
            assert_eq!(
                actions,
                [
                    Action::StopWorker,
                    Action::StartBackoffWindow(Duration::from_secs(60))
                ]
            );
            m
        };
        // RFC 2326 §7.1.1: a 401 is a credential failure.
        let auth = WorkerReport::Backoff {
            error: SourceError::AuthFailed("401".into()),
            retry_in: Duration::from_secs(60),
            position: at(1),
        };
        let m = stopped(std::slice::from_ref(&auth));
        assert_eq!(
            m.failure().map(ConnectionError::code),
            Some("source_auth_failed")
        );
        // A drop of the live standby is no failure; its retry failing is.
        let drop = failed_for(Duration::from_secs(60), 1);
        let m = stopped(&[WorkerReport::Live, drop.clone()]);
        assert_eq!(m.failure(), None, "a drop");
        let m = stopped(&[
            WorkerReport::Live,
            WorkerReport::Reconnecting(timeout()),
            drop,
        ]);
        assert_eq!(
            m.failure().map(ConnectionError::code),
            Some("source_timeout")
        );
        // A crash is the failure, whatever the standby's.
        let mut m = machine();
        m.handle(Input::Demand(1), clock.now());
        m.handle(Input::Report(WorkerReport::Live), clock.now());
        m.source_switched(Some(1));
        m.standby_report(1, &auth, clock.now());
        m.handle(Input::WorkerExited, clock.now());
        assert_eq!(m.failure(), Some(&ConnectionError::WorkerCrashed));
    }

    #[test]
    fn a_crash_without_demand_goes_idle() {
        let now = SystemClock.now();
        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::Report(WorkerReport::Live), now);
        m.handle(Input::Demand(0), now);
        assert_eq!(m.state(), S::Draining);
        // The crash backoff holds as a window: no early restart.
        assert_eq!(
            m.handle(Input::WorkerExited, now),
            [
                Action::CancelLinger,
                Action::StartBackoffWindow(Duration::from_millis(500))
            ]
        );
        assert_eq!(m.state(), S::Idle);
        assert_eq!(m.crashes(), 1);

        let mut m = machine();
        m.handle(Input::Demand(1), now);
        m.handle(Input::WorkerExited, now);
        assert_eq!(m.state(), S::Restarting);
        // The crash backoff's window holds.
        assert_eq!(
            m.handle(Input::Demand(0), now),
            [
                Action::CancelCrashBackoff,
                Action::StartBackoffWindow(Duration::from_millis(500))
            ]
        );
        assert_eq!(m.state(), S::Idle);
        assert!(
            m.handle(Input::WorkerExited, now).is_empty(),
            "nothing running"
        );
        assert_eq!(m.crashes(), 1);
    }
}

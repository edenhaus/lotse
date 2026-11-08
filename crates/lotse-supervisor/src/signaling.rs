//! The routing of signaled sources' signaling between their workers and
//! the control-API client that relays it: the registry's side.
//!
//! A worker's signaled source asks for a signaling channel per connection
//! attempt (`lotse_core::signaling`); its driver checks the worker's
//! reports, untrusted, and hands them here ([`State::signal_report`]),
//! and what the registry answers goes back to the worker through the
//! driver's queue as [`DriverCommand::Signal`]. No control-API client
//! relays signaling yet, so every open is refused
//! [`NO_SIGNALING_CLIENT`]: the source's attempt ends unreachable, and its
//! connection backs off with that as its last error. No signal is open
//! on the supervisor's side, so a worker's report about one is dropped.
//!
//! Standards: RFC 8829 (JSEP) and RFC 8838 (Trickle ICE), the exchange
//! the signals carry, as `lotse_core::signaling` cites them.

use std::time::{Duration, Instant};

use lotse_ipc::{SignalCommand, SignalReport};

use crate::connect::CONNECT_LEASE;
use crate::driver::DriverCommand;
use crate::registry::State;

/// The refusal code of an open no control-API client relays.
pub(crate) const NO_SIGNALING_CLIENT: &str = "no_signaling_client";

/// The most opens a worker may have waiting for an answer: its source and
/// a standby open one each per connection attempt. One past them is
/// refused at once.
pub(crate) const MAX_PENDING_OPENS: usize = 2;

/// How long the driver keeps an open waiting for its answer: as long as
/// the connection attempt that asked may take ([`CONNECT_LEASE`]), after
/// which the worker has abandoned it. An answer or a cancel lost on a full
/// queue so frees its place in [`MAX_PENDING_OPENS`] by then.
pub(crate) const OPEN_EXPIRY: Duration = CONNECT_LEASE;

/// The most signals a driver remembers having ended itself, so it drops
/// what their worker still reports on them: twice the channels a worker
/// holds at once.
pub(crate) const MAX_ENDED_SIGNALS: usize = 8;

/// Where a signal report comes from, and so where the registry's answer
/// goes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignalFrom<'a> {
    /// The connection whose worker reported it.
    pub(crate) connection: &'a str,
    /// The driver's serial of that worker: the answer is dropped unless it
    /// still runs ([`DriverCommand::Signal`]).
    pub(crate) worker: u64,
}

impl State {
    /// The checked signal `report` of the worker `from`, at `now`. An open
    /// is refused [`NO_SIGNALING_CLIENT`] through the connection's driver,
    /// its line rate-limited (a worker opens and cancels as fast as it
    /// sends);
    /// anything else concerns no signal the supervisor holds and is
    /// dropped (a second close of a signal among them).
    pub(crate) fn signal_report(
        &mut self,
        from: &SignalFrom<'_>,
        report: SignalReport,
        now: Instant,
    ) {
        let connection = from.connection;
        match report {
            SignalReport::Open { request } => {
                if let Some(count) = self.signal_refused_lines.hit(now) {
                    tracing::info!(
                        connection.id = connection,
                        request,
                        count,
                        "signaling channel refused: no client relays the source's signaling"
                    );
                }
                self.signal_worker(
                    from,
                    now,
                    SignalCommand::Refused {
                        request,
                        code: NO_SIGNALING_CLIENT.to_owned(),
                        message: "no control-API client relays this source's signaling".to_owned(),
                    },
                );
            }
            SignalReport::Cancel { request } => tracing::debug!(
                connection.id = connection,
                request,
                "signaling open cancelled; nothing holds it"
            ),
            SignalReport::Offer { signal_id, .. }
            | SignalReport::Candidate { signal_id, .. }
            | SignalReport::Closed { signal_id, .. } => tracing::debug!(
                connection.id = connection,
                signal = %signal_id,
                "a worker reported on a signal the supervisor does not hold; dropped"
            ),
        }
    }

    /// Queues `command` for the worker `to`, through its connection's
    /// driver. A full queue drops it, with a line rate-limited at `now`:
    /// the open it answers waits for its source's own timeout, and the
    /// driver forgets it after [`OPEN_EXPIRY`].
    fn signal_worker(&mut self, to: &SignalFrom<'_>, now: Instant, command: SignalCommand) {
        let connection = to.connection;
        let Some(entry) = self.connections.get(connection) else {
            tracing::debug!(
                connection.id = connection,
                ?command,
                "signal command for a connection that is gone; dropped"
            );
            return;
        };
        let queued = DriverCommand::Signal {
            worker: to.worker,
            command,
        };
        if let Err(err) = entry.commands.try_send(queued)
            && let Some(count) = self.signal_queue_lines.hit(now)
        {
            tracing::warn!(connection.id = connection, command = ?err.into_inner(), count, "the driver's queue is full; signal command dropped");
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

    use std::time::SystemTime;

    use lotse_core::clock::{Clock as _, SystemClock};
    use lotse_core::let_assert;
    use tokio::sync::{mpsc, watch};

    use super::*;
    use crate::registry::{ConnectionEntry, ConnectionKey, ConnectionSnapshot, Talker};
    use crate::test_support::Captured;

    /// A state with the connection `c1`, whose driver's queue holds
    /// `capacity` commands.
    fn state_with_c1(capacity: usize) -> (State, mpsc::Receiver<DriverCommand>) {
        let mut state = State::default();
        let (commands, queued) = mpsc::channel(capacity);
        state.connections.insert(
            "c1".into(),
            ConnectionEntry {
                key: ConnectionKey {
                    target: crate::registry::SourceTarget::Signaled {
                        protocol: "webrtc",
                        stream: "front".into(),
                    },
                    options: serde_json::Value::Null,
                },
                port: None,
                backchannel: false,
                prerecord_ms: 0,
                demand: watch::channel(crate::driver::Demand::default()).0,
                snapshot: ConnectionSnapshot::idle(SystemTime::UNIX_EPOCH),
                switches: 0,
                streams: std::collections::BTreeSet::new(),
                commands,
                talker: Talker::default(),
            },
        );
        (state, queued)
    }

    /// Worker 3 of `connection`.
    fn from(connection: &str) -> SignalFrom<'_> {
        SignalFrom {
            connection,
            worker: 3,
        }
    }

    #[test]
    fn an_open_is_refused_no_signaling_client_through_the_connection_s_driver() {
        let captured = Captured::default();
        let _guard = captured.install();
        let (mut state, mut queued) = state_with_c1(1);
        let now = SystemClock.now();
        state.signal_report(&from("c1"), SignalReport::Open { request: 3 }, now);
        let_assert!(Ok(DriverCommand::Signal { worker, command }) = queued.try_recv());
        // For the worker that asked, which the driver checks.
        assert_eq!(worker, 3);
        assert_eq!(
            command,
            SignalCommand::Refused {
                request: 3,
                code: "no_signaling_client".into(),
                message: "no control-API client relays this source's signaling".into(),
            }
        );
        // A full queue drops the next, with a line rate-limited on the
        // time given: one now, one a summary interval later.
        state.signal_report(&from("c1"), SignalReport::Open { request: 4 }, now);
        for request in 5..8 {
            state.signal_report(&from("c1"), SignalReport::Open { request }, now);
        }
        let later = now + lotse_core::throttle::SUMMARY_INTERVAL;
        state.signal_report(&from("c1"), SignalReport::Open { request: 8 }, later);
        assert!(queued.try_recv().is_ok());
        assert!(queued.try_recv().is_err());
        let dropped = captured.lines("the driver's queue is full; signal command dropped");
        assert_eq!(dropped.len(), 2, "{dropped:?}");
        assert!(dropped[1].contains("count=3"), "{dropped:?}");
        // The refusal's own line is rate-limited the same way: one for the
        // five opens now, one with their count a summary interval later.
        let refused =
            captured.lines("signaling channel refused: no client relays the source's signaling");
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(refused[0].contains("count=1"), "{refused:?}");
        assert!(refused[1].contains("count=5"), "{refused:?}");
        // A connection that is gone takes none.
        state.signal_report(&from("gone"), SignalReport::Open { request: 6 }, now);
        assert_eq!(
            captured
                .lines("signal command for a connection that is gone; dropped")
                .len(),
            1
        );
    }

    #[test]
    fn reports_on_signals_the_supervisor_does_not_hold_are_dropped() {
        let captured = Captured::default();
        let _guard = captured.install();
        let (mut state, mut queued) = state_with_c1(4);
        let now = SystemClock.now();
        state.signal_report(&from("c1"), SignalReport::Cancel { request: 1 }, now);
        let closed = SignalReport::Closed {
            signal_id: "sig".into(),
            code: "source_stopped".into(),
            message: "stopped".into(),
        };
        for report in [
            SignalReport::Offer {
                signal_id: "sig".into(),
                sdp: "v=0\r\n".into(),
            },
            SignalReport::Candidate {
                signal_id: "sig".into(),
                candidate: String::new(),
                mid: None,
                mline_index: Some(0),
            },
            closed.clone(),
            // A second close of one signal is dropped as the first was.
            closed,
        ] {
            state.signal_report(&from("c1"), report, now);
        }
        assert!(queued.try_recv().is_err());
        assert_eq!(
            captured
                .lines("signaling open cancelled; nothing holds it")
                .len(),
            1
        );
        assert_eq!(
            captured
                .lines("a worker reported on a signal the supervisor does not hold; dropped")
                .len(),
            4
        );
    }
}

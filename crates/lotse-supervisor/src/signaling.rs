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

use lotse_ipc::{SignalCommand, SignalReport};

use crate::driver::DriverCommand;
use crate::registry::State;

/// The refusal code of an open no control-API client relays.
pub(crate) const NO_SIGNALING_CLIENT: &str = "no_signaling_client";

/// The most opens a worker may have waiting for an answer: its source and
/// a standby open one each per connection attempt. One past them is
/// refused at once.
pub(crate) const MAX_PENDING_OPENS: usize = 2;

impl State {
    /// The checked signal `report` of the worker of `connection`. An open
    /// is refused [`NO_SIGNALING_CLIENT`] through the connection's driver;
    /// anything else concerns no signal the supervisor holds and is
    /// dropped.
    pub(crate) fn signal_report(&self, connection: &str, report: SignalReport) {
        match report {
            SignalReport::Open { request } => {
                tracing::info!(
                    connection.id = connection,
                    request,
                    "signaling channel refused: no client relays the source's signaling"
                );
                self.signal_worker(
                    connection,
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

    /// Queues `command` for the worker of `connection`, through its
    /// driver. A full queue drops it: the open it answers waits for its
    /// source's own timeout.
    fn signal_worker(&self, connection: &str, command: SignalCommand) {
        let Some(entry) = self.connections.get(connection) else {
            tracing::debug!(
                connection.id = connection,
                ?command,
                "signal command for a connection that is gone; dropped"
            );
            return;
        };
        if let Err(err) = entry.commands.try_send(DriverCommand::Signal(command)) {
            tracing::warn!(connection.id = connection, command = ?err.into_inner(), "the driver's queue is full; signal command dropped");
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

    use lotse_core::let_assert;
    use lotse_core::source_url::SourceUrl;
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
                    url: SourceUrl::parse("webrtc://camera.front_door").unwrap(),
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

    #[test]
    fn an_open_is_refused_no_signaling_client_through_the_connection_s_driver() {
        let captured = Captured::default();
        let _guard = captured.install();
        let (state, mut queued) = state_with_c1(1);
        state.signal_report("c1", SignalReport::Open { request: 3 });
        let_assert!(Ok(DriverCommand::Signal(command)) = queued.try_recv());
        assert_eq!(
            command,
            SignalCommand::Refused {
                request: 3,
                code: "no_signaling_client".into(),
                message: "no control-API client relays this source's signaling".into(),
            }
        );
        // A full queue drops the next.
        state.signal_report("c1", SignalReport::Open { request: 4 });
        state.signal_report("c1", SignalReport::Open { request: 5 });
        assert!(queued.try_recv().is_ok());
        assert!(queued.try_recv().is_err());
        assert_eq!(
            captured
                .lines("the driver's queue is full; signal command dropped")
                .len(),
            1
        );
        // A connection that is gone takes none.
        state.signal_report("gone", SignalReport::Open { request: 6 });
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
        let (state, mut queued) = state_with_c1(4);
        state.signal_report("c1", SignalReport::Cancel { request: 1 });
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
            SignalReport::Closed {
                signal_id: "sig".into(),
                code: "source_stopped".into(),
                message: "stopped".into(),
            },
        ] {
            state.signal_report("c1", report);
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
            3
        );
    }
}

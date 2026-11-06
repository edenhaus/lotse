//! The worker's end of its signaled sources' signaling: the
//! [`SignalingOpener`] a signaled source gets in its context
//! (`SourceCapabilities::signaled`), which carries each channel through
//! the supervisor to the control-API client that relays the source's
//! signaling.
//!
//! An open asks the supervisor with [`SignalReport::Open`] and waits for
//! its [`SignalCommand::Opened`] or [`SignalCommand::Refused`]; an open
//! abandoned before that sends [`SignalReport::Cancel`], and an `Opened`
//! that crosses it is closed at once. An opened channel's offer,
//! candidates and close go to the supervisor as reports in the order the
//! source sent them, from a relay task per channel that reads the
//! outgoing signals ahead of the close; the client's answer, candidates
//! and failure come back as commands and are queued for the source
//! without waiting. A queue the source does not drain in time ends the
//! signal: its incoming end is dropped, which the source reads as the
//! client gone, as it does a [`SignalCommand::Gone`]. A worker holds at
//! most [`MAX_SIGNALS`] channels; an `Opened` past them is refused.
//!
//! Every report is bounded so its message fits the IPC frame
//! ([`MAX_SIGNAL_SDP_BYTES`], [`MAX_SIGNAL_TEXT_BYTES`]): a source's
//! longer offer or candidate ends its signal instead, and its close's
//! message is cut. A supervisor's command for a signal the worker does
//! not hold is ignored.
//!
//! Standards: RFC 8829 (JSEP) for the offer and answer the channel
//! carries; RFC 8838 (Trickle ICE) for the candidates and the
//! end-of-candidates indication, as `lotse_core::signaling` cites them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lotse_core::signaling::{
    LocalSignal, RemoteSignal, SignalCandidate, SignalClosed, SignalingChannel, SignalingOpener,
    SignalingRefused, close,
};
use lotse_core::task::{BoxFuture, spawn_named};
use lotse_core::text::plain;
use lotse_ipc::{MAX_SIGNAL_SDP_BYTES, MAX_SIGNAL_TEXT_BYTES, SignalCommand, SignalReport};
use tokio::sync::{mpsc, oneshot};

/// The most signaling channels a worker holds at once: its source and a
/// standby open one per connection attempt, so two at a time, with room
/// for channels whose close is still on its way.
pub(crate) const MAX_SIGNALS: usize = 4;

/// The reports the relay tasks and the opens may have queued for the main
/// loop before they wait for it: a few signals' offers and candidates.
pub(crate) const REPORT_CAPACITY: usize = 64;

/// The close code of a signal the worker ends itself, and the refusal
/// code of an open it refuses itself: the control API's `internal_error`.
const INTERNAL_ERROR: &str = "internal_error";

/// What a pending open is answered with.
type OpenAnswer = Result<SignalingChannel, SignalingRefused>;

/// The signaling of a worker's sources: their opener, and the dispatcher
/// of the supervisor's [`SignalCommand`]s.
#[derive(Debug)]
pub(crate) struct WorkerSignaling {
    /// The pending opens and the open channels.
    state: Arc<Mutex<Signals>>,
    /// Where the reports for the supervisor go: the main loop.
    reports: mpsc::Sender<SignalReport>,
}

/// The pending opens and the open channels.
#[derive(Debug, Default)]
struct Signals {
    /// The last open's id; the next counts on from it.
    last_request: u64,
    /// The opens waiting for the supervisor's answer, by id.
    opening: HashMap<u64, oneshot::Sender<OpenAnswer>>,
    /// The open channels' incoming ends, by signal id.
    open: HashMap<String, mpsc::Sender<RemoteSignal>>,
}

/// Locks the signals; a poisoned lock is taken as it is, since every
/// change to them is a single map operation.
fn lock(state: &Mutex<Signals>) -> MutexGuard<'_, Signals> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl WorkerSignaling {
    /// The opener and the reports the main loop sends to the supervisor.
    pub(crate) fn new() -> (Arc<Self>, mpsc::Receiver<SignalReport>) {
        let (reports, rx) = mpsc::channel(REPORT_CAPACITY);
        let signaling = Arc::new(Self {
            state: Arc::default(),
            reports,
        });
        (signaling, rx)
    }

    /// The supervisor's `command`; what to report back at once, if
    /// anything: the close of a signal the worker cannot take.
    pub(crate) fn command(&self, command: SignalCommand) -> Option<SignalReport> {
        match command {
            SignalCommand::Opened {
                request,
                signal_id,
                local_addrs,
            } => self.opened(request, signal_id, local_addrs),
            SignalCommand::Refused {
                request,
                code,
                message,
            } => {
                let waiting = lock(&self.state).opening.remove(&request);
                if let Some(waiting) = waiting {
                    tracing::info!(request, code, detail = %message, "signaling channel refused by the supervisor");
                    // An open abandoned meanwhile hears nothing.
                    let _abandoned = waiting.send(Err(SignalingRefused { code, message }));
                } else {
                    tracing::debug!(request, "refusal of an open that is over; ignored");
                }
                None
            }
            SignalCommand::Answer { signal_id, sdp } => {
                self.deliver(&signal_id, RemoteSignal::Answer(sdp), false);
                None
            }
            SignalCommand::Candidate {
                signal_id,
                candidate,
                mid,
                mline_index,
            } => {
                let candidate = SignalCandidate {
                    candidate,
                    sdp_mid: mid,
                    sdp_mline_index: mline_index,
                };
                self.deliver(&signal_id, RemoteSignal::Candidate(candidate), false);
                None
            }
            SignalCommand::Failed {
                signal_id,
                code,
                message,
            } => {
                self.deliver(&signal_id, RemoteSignal::Failed { code, message }, true);
                None
            }
            SignalCommand::Gone { signal_id } => {
                if lock(&self.state).open.remove(&signal_id).is_some() {
                    tracing::info!(signal = %signal_id, "the signaling client is gone; the source is told");
                } else {
                    tracing::debug!(signal = %signal_id, "client gone for a signal the worker does not hold; ignored");
                }
                None
            }
        }
    }

    /// `Opened`: the open `request` gets the channel `signal_id`, whose
    /// source may gather on `local_addrs`, and its relay starts. One that
    /// is over, or past [`MAX_SIGNALS`], is closed at once.
    fn opened(
        &self,
        request: u64,
        signal_id: String,
        local_addrs: Vec<std::net::IpAddr>,
    ) -> Option<SignalReport> {
        let mut state = lock(&self.state);
        let Some(waiting) = state.opening.remove(&request) else {
            drop(state);
            tracing::debug!(request, signal = %signal_id, "channel opened for an open that is over; closed");
            return Some(SignalReport::Closed {
                signal_id,
                code: close::SOURCE_STOPPED.to_owned(),
                message: "the attempt that asked for the channel is over".to_owned(),
            });
        };
        let duplicate = state.open.contains_key(&signal_id);
        if duplicate || state.open.len() >= MAX_SIGNALS {
            drop(state);
            let message = if duplicate {
                "the signal id names an open channel"
            } else {
                "the worker holds as many signaling channels as it may"
            };
            tracing::warn!(request, signal = %signal_id, reason = message, "signaling channel refused by the worker");
            // An open abandoned meanwhile hears nothing.
            let _abandoned = waiting.send(Err(SignalingRefused {
                code: INTERNAL_ERROR.to_owned(),
                message: message.to_owned(),
            }));
            // A duplicate's id is the open channel's, which goes on.
            return (!duplicate).then(|| SignalReport::Closed {
                signal_id,
                code: INTERNAL_ERROR.to_owned(),
                message: message.to_owned(),
            });
        }
        let (channel, relay) = lotse_core::signaling::channel(signal_id.clone(), local_addrs);
        state.open.insert(signal_id.clone(), relay.incoming);
        drop(state);
        tracing::info!(request, signal = %signal_id, local_addrs = ?channel.local_addrs, "signaling channel opened");
        let _relay = spawn_named(
            "signal.relay",
            relay_signal(
                Arc::clone(&self.state),
                self.reports.clone(),
                signal_id,
                relay.outgoing,
                relay.closed,
            ),
        );
        // An open abandoned meanwhile drops the channel, which closes it
        // as `source_stopped`.
        let _abandoned = waiting.send(Ok(channel));
        None
    }

    /// Queues `signal` for the source of `signal_id` without waiting;
    /// `last` ends the signal after it. A full queue ends the signal too,
    /// and a source that let go of its end is let go of.
    fn deliver(&self, signal_id: &str, signal: RemoteSignal, last: bool) {
        let mut state = lock(&self.state);
        let Some(incoming) = state.open.get(signal_id) else {
            drop(state);
            tracing::debug!(signal = %signal_id, ?signal, "signal for a channel the worker does not hold; ignored");
            return;
        };
        match incoming.try_send(signal) {
            Ok(()) if !last => {}
            Ok(()) => {
                state.open.remove(signal_id);
                drop(state);
                tracing::info!(signal = %signal_id, "the camera failed the signal; the source is told");
            }
            Err(mpsc::error::TrySendError::Full(signal)) => {
                state.open.remove(signal_id);
                drop(state);
                tracing::warn!(signal = %signal_id, ?signal, "the source does not take its signals in time; signal ended");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                state.open.remove(signal_id);
                drop(state);
                tracing::debug!(signal = %signal_id, "the source let go of its channel; dropped");
            }
        }
    }
}

impl SignalingOpener for WorkerSignaling {
    fn open(&self) -> BoxFuture<'static, Result<SignalingChannel, SignalingRefused>> {
        let state = Arc::clone(&self.state);
        let reports = self.reports.clone();
        Box::pin(async move {
            let (answer, waiting) = oneshot::channel();
            let request = {
                let mut signals = lock(&state);
                signals.last_request = signals.last_request.wrapping_add(1);
                let request = signals.last_request;
                signals.opening.insert(request, answer);
                request
            };
            let _pending = PendingOpen {
                state: Arc::clone(&state),
                reports: reports.clone(),
                request,
            };
            tracing::debug!(request, "signaling channel asked of the supervisor");
            if reports.send(SignalReport::Open { request }).await.is_err() {
                return Err(stopping());
            }
            waiting.await.unwrap_or_else(|_dropped| Err(stopping()))
        })
    }
}

/// The refusal of an open while the worker stops: nothing answers it.
fn stopping() -> SignalingRefused {
    SignalingRefused {
        code: INTERNAL_ERROR.to_owned(),
        message: "the worker stops".to_owned(),
    }
}

/// An open waiting for the supervisor's answer: dropped before it came,
/// it leaves the pending opens and tells the supervisor so
/// ([`SignalReport::Cancel`]).
struct PendingOpen {
    /// The pending opens.
    state: Arc<Mutex<Signals>>,
    /// Where the cancel goes.
    reports: mpsc::Sender<SignalReport>,
    /// The open's id.
    request: u64,
}

impl Drop for PendingOpen {
    fn drop(&mut self) {
        if lock(&self.state).opening.remove(&self.request).is_none() {
            return;
        }
        let request = self.request;
        // A full queue loses the cancel: the supervisor's answer then
        // finds no open and is closed or ignored ([`WorkerSignaling::command`]).
        let sent = self
            .reports
            .try_send(SignalReport::Cancel { request })
            .is_ok();
        tracing::debug!(request, sent, "signaling open abandoned before its answer");
    }
}

/// Relays the channel `signal_id`'s `outgoing` signals to `reports` as
/// the supervisor's reports, ahead of its close from `closed`, which goes
/// last; then the channel leaves `state`. A signal too long for the IPC
/// frame ends the signal there.
async fn relay_signal(
    state: Arc<Mutex<Signals>>,
    reports: mpsc::Sender<SignalReport>,
    signal_id: String,
    mut outgoing: mpsc::Receiver<LocalSignal>,
    closed: SignalClosed,
) {
    let mut closed = std::pin::pin!(closed.wait());
    let (code, message) = loop {
        tokio::select! {
            biased;
            Some(signal) = outgoing.recv() => match report(&signal_id, signal) {
                Ok(report) => {
                    // The main loop drains the reports while the worker
                    // runs; a send fails only as it exits.
                    if reports.send(report).await.is_err() {
                        lock(&state).open.remove(&signal_id);
                        return;
                    }
                }
                Err(reason) => {
                    tracing::warn!(signal = %signal_id, reason, "the source sent a signal longer than the supervisor takes; signal ended");
                    break (INTERNAL_ERROR, reason.to_owned());
                }
            },
            close = &mut closed => break (close.code, close.message),
        }
    };
    lock(&state).open.remove(&signal_id);
    tracing::debug!(signal = %signal_id, code, "signaling channel closed");
    let _exiting = reports
        .send(SignalReport::Closed {
            signal_id,
            code: code.to_owned(),
            message: plain(&message, MAX_SIGNAL_TEXT_BYTES),
        })
        .await;
}

/// `signal` of `signal_id` as the supervisor's report, or why it does not
/// fit one: an offer over [`MAX_SIGNAL_SDP_BYTES`], a candidate line or
/// `mid` over [`MAX_SIGNAL_TEXT_BYTES`].
fn report(signal_id: &str, signal: LocalSignal) -> Result<SignalReport, &'static str> {
    match signal {
        LocalSignal::Offer(sdp) if sdp.len() > MAX_SIGNAL_SDP_BYTES => Err("offer too long"),
        LocalSignal::Offer(sdp) => Ok(SignalReport::Offer {
            signal_id: signal_id.to_owned(),
            sdp,
        }),
        LocalSignal::Candidate(candidate)
            if candidate.candidate.len() > MAX_SIGNAL_TEXT_BYTES
                || candidate
                    .sdp_mid
                    .as_ref()
                    .is_some_and(|mid| mid.len() > MAX_SIGNAL_TEXT_BYTES) =>
        {
            Err("candidate too long")
        }
        LocalSignal::Candidate(candidate) => Ok(SignalReport::Candidate {
            signal_id: signal_id.to_owned(),
            candidate: candidate.candidate,
            mid: candidate.sdp_mid,
            mline_index: candidate.sdp_mline_index,
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use lotse_core::clock::{Clock as _, SystemClock};
    use lotse_core::let_assert;
    use lotse_core::signaling::INCOMING_CAPACITY;
    use lotse_core::text::CUT_MARK;

    use super::*;

    fn host() -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
    }

    fn opened(request: u64, signal_id: &str) -> SignalCommand {
        SignalCommand::Opened {
            request,
            signal_id: signal_id.into(),
            local_addrs: host(),
        }
    }

    /// The next report, failing the test after ten seconds of real time
    /// without one.
    async fn next(reports: &mut mpsc::Receiver<SignalReport>) -> SignalReport {
        tokio::select! {
            report = reports.recv() => report.expect("the reports go on"),
            () = SystemClock.sleep(Duration::from_secs(10)) => panic!("no report within 10 s"),
        }
    }

    /// Opens a channel through `signaling` as the supervisor's `signal_id`.
    async fn open(
        signaling: &WorkerSignaling,
        reports: &mut mpsc::Receiver<SignalReport>,
        signal_id: &str,
    ) -> SignalingChannel {
        let opening = signaling.open();
        let opening = spawn_named("test.open", opening);
        let_assert!(SignalReport::Open { request } = next(reports).await);
        assert_eq!(signaling.command(opened(request, signal_id)), None);
        opening.await.unwrap().unwrap()
    }

    fn held(signaling: &WorkerSignaling) -> usize {
        lock(&signaling.state).open.len()
    }

    #[tokio::test]
    async fn rfc8829_5_an_opened_channel_carries_the_offer_and_candidates_out_and_the_answer_in() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let mut channel = open(&signaling, &mut reports, "sig-1").await;
        assert_eq!(channel.id, "sig-1");
        assert_eq!(channel.local_addrs, host());
        assert_eq!(held(&signaling), 1);

        let host_candidate = SignalCandidate {
            candidate: "candidate:1 1 udp 2130706431 192.0.2.7 9 typ host".into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
        };
        for signal in [
            LocalSignal::Offer("v=0 offer".into()),
            LocalSignal::Candidate(host_candidate),
            LocalSignal::Candidate(SignalCandidate::end_of_candidates(None, Some(0))),
        ] {
            channel.outgoing.send(signal).await.unwrap();
        }
        assert_eq!(
            next(&mut reports).await,
            SignalReport::Offer {
                signal_id: "sig-1".into(),
                sdp: "v=0 offer".into(),
            }
        );
        assert_eq!(
            next(&mut reports).await,
            SignalReport::Candidate {
                signal_id: "sig-1".into(),
                candidate: "candidate:1 1 udp 2130706431 192.0.2.7 9 typ host".into(),
                mid: Some("0".into()),
                mline_index: Some(0),
            }
        );
        assert_eq!(
            next(&mut reports).await,
            SignalReport::Candidate {
                signal_id: "sig-1".into(),
                candidate: String::new(),
                mid: None,
                mline_index: Some(0),
            }
        );

        for command in [
            SignalCommand::Answer {
                signal_id: "sig-1".into(),
                sdp: "v=0 answer".into(),
            },
            SignalCommand::Candidate {
                signal_id: "sig-1".into(),
                candidate: "candidate:2 1 udp 1 198.51.100.9 5000 typ host".into(),
                mid: None,
                mline_index: Some(1),
            },
        ] {
            assert_eq!(signaling.command(command), None);
        }
        assert_eq!(
            channel.incoming.recv().await,
            Some(RemoteSignal::Answer("v=0 answer".into()))
        );
        assert_eq!(
            channel.incoming.recv().await,
            Some(RemoteSignal::Candidate(SignalCandidate {
                candidate: "candidate:2 1 udp 1 198.51.100.9 5000 typ host".into(),
                sdp_mid: None,
                sdp_mline_index: Some(1),
            }))
        );

        // Everything sent before the close goes ahead of it.
        channel
            .outgoing
            .send(LocalSignal::Candidate(SignalCandidate::end_of_candidates(
                Some("1".into()),
                Some(1),
            )))
            .await
            .unwrap();
        channel.close(close::ICE_FAILED, "no pair\nconnected".into());
        assert!(matches!(
            next(&mut reports).await,
            SignalReport::Candidate {
                mline_index: Some(1),
                ..
            }
        ));
        assert_eq!(
            next(&mut reports).await,
            SignalReport::Closed {
                signal_id: "sig-1".into(),
                code: "ice_failed".into(),
                message: "no pair connected".into(),
            }
        );
        assert_eq!(held(&signaling), 0);
        // What the client relays for the closed signal finds nothing.
        assert_eq!(
            signaling.command(SignalCommand::Answer {
                signal_id: "sig-1".into(),
                sdp: "v=0".into(),
            }),
            None
        );
    }

    #[tokio::test]
    async fn a_dropped_channel_closes_as_source_stopped_with_its_message_cut() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let channel = open(&signaling, &mut reports, "sig-1").await;
        drop(channel);
        assert_eq!(
            next(&mut reports).await,
            SignalReport::Closed {
                signal_id: "sig-1".into(),
                code: "source_stopped".into(),
                message: "the source stopped".into(),
            }
        );
        let channel = open(&signaling, &mut reports, "sig-2").await;
        channel.close(close::CAMERA_ERROR, "x".repeat(2 * MAX_SIGNAL_TEXT_BYTES));
        let_assert!(SignalReport::Closed { message, .. } = next(&mut reports).await);
        assert_eq!(message.len(), MAX_SIGNAL_TEXT_BYTES);
        assert!(message.ends_with(CUT_MARK));
    }

    #[tokio::test]
    async fn a_refused_open_fails_with_the_supervisor_s_code_and_a_stale_refusal_is_ignored() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let opening = spawn_named("test.open", signaling.open());
        let_assert!(SignalReport::Open { request } = next(&mut reports).await);
        assert_eq!(request, 1);
        let refused = SignalCommand::Refused {
            request,
            code: "no_signaling_client".into(),
            message: "nobody relays".into(),
        };
        assert_eq!(signaling.command(refused.clone()), None);
        assert_eq!(
            opening.await.unwrap().unwrap_err(),
            SignalingRefused {
                code: "no_signaling_client".into(),
                message: "nobody relays".into(),
            }
        );
        // Again, for an open that is over: nothing happens.
        assert_eq!(signaling.command(refused), None);
        // The next open has the next id.
        let _opening = spawn_named("test.open", signaling.open());
        assert_eq!(next(&mut reports).await, SignalReport::Open { request: 2 });
    }

    #[tokio::test]
    async fn an_abandoned_open_is_cancelled_and_its_late_channel_closed_at_once() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let opening = spawn_named("test.open", signaling.open());
        let_assert!(SignalReport::Open { request } = next(&mut reports).await);
        opening.abort();
        assert!(opening.await.unwrap_err().is_cancelled());
        assert_eq!(next(&mut reports).await, SignalReport::Cancel { request });
        assert_eq!(
            signaling.command(opened(request, "sig-late")),
            Some(SignalReport::Closed {
                signal_id: "sig-late".into(),
                code: "source_stopped".into(),
                message: "the attempt that asked for the channel is over".into(),
            })
        );
        assert_eq!(held(&signaling), 0);
    }

    #[tokio::test]
    async fn an_open_answered_but_abandoned_before_it_took_its_channel_closes_it() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let (answer, waiting) = oneshot::channel();
        lock(&signaling.state).opening.insert(7, answer);
        drop(waiting);
        assert_eq!(signaling.command(opened(7, "sig-7")), None);
        assert_eq!(
            next(&mut reports).await,
            SignalReport::Closed {
                signal_id: "sig-7".into(),
                code: "source_stopped".into(),
                message: "the source stopped".into(),
            }
        );
        assert_eq!(held(&signaling), 0);
    }

    #[tokio::test]
    async fn a_cancel_that_finds_the_reports_full_is_dropped() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let opening = spawn_named("test.open", signaling.open());
        let_assert!(SignalReport::Open { .. } = next(&mut reports).await);
        for _ in 0..REPORT_CAPACITY {
            signaling
                .reports
                .try_send(SignalReport::Open { request: 0 })
                .unwrap();
        }
        opening.abort();
        assert!(opening.await.unwrap_err().is_cancelled());
        for _ in 0..REPORT_CAPACITY {
            assert_eq!(next(&mut reports).await, SignalReport::Open { request: 0 });
        }
        assert!(reports.try_recv().is_err());
        assert!(lock(&signaling.state).opening.is_empty());
    }

    #[tokio::test]
    async fn an_open_while_the_worker_stops_is_refused() {
        let (signaling, reports) = WorkerSignaling::new();
        drop(reports);
        let refused = signaling.open().await.unwrap_err();
        assert_eq!(refused.code, "internal_error");
        assert_eq!(refused.message, "the worker stops");
        assert!(lock(&signaling.state).opening.is_empty());

        let (signaling, mut reports) = WorkerSignaling::new();
        let opening = spawn_named("test.open", signaling.open());
        let_assert!(SignalReport::Open { request } = next(&mut reports).await);
        // Its answer's sender goes without an answer.
        drop(lock(&signaling.state).opening.remove(&request));
        assert_eq!(opening.await.unwrap().unwrap_err(), stopping());
    }

    #[tokio::test]
    async fn a_failure_reaches_the_source_last_and_gone_ends_its_signal() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let mut failed = open(&signaling, &mut reports, "sig-1").await;
        let mut gone = open(&signaling, &mut reports, "sig-2").await;
        assert_eq!(held(&signaling), 2);
        assert_eq!(
            signaling.command(SignalCommand::Failed {
                signal_id: "sig-1".into(),
                code: "webrtc_offer_failed".into(),
                message: "the camera said no".into(),
            }),
            None
        );
        assert_eq!(
            failed.incoming.recv().await,
            Some(RemoteSignal::Failed {
                code: "webrtc_offer_failed".into(),
                message: "the camera said no".into(),
            })
        );
        assert_eq!(failed.incoming.recv().await, None);
        assert_eq!(
            signaling.command(SignalCommand::Gone {
                signal_id: "sig-2".into(),
            }),
            None
        );
        assert_eq!(gone.incoming.recv().await, None);
        assert_eq!(held(&signaling), 0);
        // Either again finds no signal.
        for command in [
            SignalCommand::Gone {
                signal_id: "sig-2".into(),
            },
            SignalCommand::Failed {
                signal_id: "sig-2".into(),
                code: "x".into(),
                message: "y".into(),
            },
        ] {
            assert_eq!(signaling.command(command), None);
        }
    }

    #[tokio::test]
    async fn a_source_that_does_not_take_its_signals_in_time_loses_its_signal() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let mut channel = open(&signaling, &mut reports, "sig-1").await;
        let candidate = |n: usize| SignalCommand::Candidate {
            signal_id: "sig-1".into(),
            candidate: format!("candidate:{n} 1 udp 1 198.51.100.9 5000 typ host"),
            mid: None,
            mline_index: Some(0),
        };
        for n in 0..=INCOMING_CAPACITY {
            assert_eq!(signaling.command(candidate(n)), None);
        }
        assert_eq!(held(&signaling), 0);
        for _ in 0..INCOMING_CAPACITY {
            assert!(matches!(
                channel.incoming.recv().await,
                Some(RemoteSignal::Candidate(_))
            ));
        }
        // The one that did not fit is not there, and nothing follows.
        assert_eq!(channel.incoming.recv().await, None);
    }

    #[tokio::test]
    async fn a_source_that_let_go_of_its_incoming_end_is_let_go_of() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let channel = open(&signaling, &mut reports, "sig-1").await;
        drop(channel.incoming);
        assert_eq!(
            signaling.command(SignalCommand::Answer {
                signal_id: "sig-1".into(),
                sdp: "v=0".into(),
            }),
            None
        );
        assert_eq!(held(&signaling), 0);
    }

    #[tokio::test]
    async fn a_worker_holds_at_most_max_signals_channels_and_no_id_twice() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let mut channels = Vec::new();
        for n in 0..MAX_SIGNALS {
            channels.push(open(&signaling, &mut reports, &format!("sig-{n}")).await);
        }
        let refused = |message: &str| SignalingRefused {
            code: "internal_error".into(),
            message: message.into(),
        };

        let opening = spawn_named("test.open", signaling.open());
        let_assert!(SignalReport::Open { request } = next(&mut reports).await);
        assert_eq!(
            signaling.command(opened(request, "sig-over")),
            Some(SignalReport::Closed {
                signal_id: "sig-over".into(),
                code: "internal_error".into(),
                message: "the worker holds as many signaling channels as it may".into(),
            })
        );
        assert_eq!(
            opening.await.unwrap().unwrap_err(),
            refused("the worker holds as many signaling channels as it may")
        );

        let opening = spawn_named("test.open", signaling.open());
        let_assert!(SignalReport::Open { request } = next(&mut reports).await);
        // A duplicate's id is an open channel's, which goes on unclosed.
        assert_eq!(signaling.command(opened(request, "sig-0")), None);
        assert_eq!(
            opening.await.unwrap().unwrap_err(),
            refused("the signal id names an open channel")
        );
        assert_eq!(held(&signaling), MAX_SIGNALS);
        drop(channels);
    }

    #[tokio::test]
    async fn a_signal_longer_than_the_frame_takes_ends_its_signal() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let long_offer = LocalSignal::Offer("v".repeat(MAX_SIGNAL_SDP_BYTES + 1));
        let long_candidate = LocalSignal::Candidate(SignalCandidate {
            candidate: "c".repeat(MAX_SIGNAL_TEXT_BYTES + 1),
            sdp_mid: None,
            sdp_mline_index: Some(0),
        });
        let long_mid = LocalSignal::Candidate(SignalCandidate {
            candidate: String::new(),
            sdp_mid: Some("m".repeat(MAX_SIGNAL_TEXT_BYTES + 1)),
            sdp_mline_index: Some(0),
        });
        for (n, (signal, reason)) in [
            (long_offer, "offer too long"),
            (long_candidate, "candidate too long"),
            (long_mid, "candidate too long"),
        ]
        .into_iter()
        .enumerate()
        {
            let signal_id = format!("sig-{n}");
            let mut channel = open(&signaling, &mut reports, &signal_id).await;
            channel.outgoing.send(signal).await.unwrap();
            assert_eq!(
                next(&mut reports).await,
                SignalReport::Closed {
                    signal_id,
                    code: "internal_error".into(),
                    message: reason.into(),
                }
            );
            // The source learns the client is gone.
            assert_eq!(channel.incoming.recv().await, None);
        }
        // The longest that fit pass.
        let channel = open(&signaling, &mut reports, "sig-fit").await;
        for signal in [
            LocalSignal::Offer("v".repeat(MAX_SIGNAL_SDP_BYTES)),
            LocalSignal::Candidate(SignalCandidate {
                candidate: "c".repeat(MAX_SIGNAL_TEXT_BYTES),
                sdp_mid: Some("m".repeat(MAX_SIGNAL_TEXT_BYTES)),
                sdp_mline_index: None,
            }),
        ] {
            channel.outgoing.send(signal).await.unwrap();
        }
        assert!(matches!(
            next(&mut reports).await,
            SignalReport::Offer { .. }
        ));
        assert!(matches!(
            next(&mut reports).await,
            SignalReport::Candidate { .. }
        ));
        drop(channel.incoming);
    }

    #[tokio::test]
    async fn a_relay_whose_reports_end_stops() {
        let (signaling, mut reports) = WorkerSignaling::new();
        let channel = open(&signaling, &mut reports, "sig-1").await;
        drop(reports);
        // The offer finds nobody to take it; the relay ends, and the
        // source's end with it.
        channel
            .outgoing
            .send(LocalSignal::Offer("v=0".into()))
            .await
            .unwrap();
        channel.outgoing.closed().await;
        assert_eq!(held(&signaling), 0);
    }
}

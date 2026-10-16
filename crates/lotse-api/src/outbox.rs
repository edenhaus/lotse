//! The bounded outbound queue of one connection, with its shedding rules:
//! stream-state events are coalesced (latest per stream), diagnostics are
//! coalesced (latest per subscription) and dropped when they would take
//! the queue past half its budget, and results and signaling are never
//! dropped, so a client that still fills the budget is disconnected.
//! Diagnostics alone never take more than that half, so they cannot be
//! what disconnects a client.
//!
//! A coalesced frame's replacement goes to the back of the queue, not
//! into the old one's place: every frame the client reads is still in the
//! order it was pushed, relative to its subscription's signaling too (a
//! session's `state` never moves ahead of the answer or candidate it
//! followed), and only the superseded frames are missing.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use tokio::sync::Notify;

use crate::EventClass;

/// What the queue holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outgoing {
    /// A text frame.
    Text {
        /// How it may be shed.
        class: Class,
        /// The JSON.
        text: String,
    },
    /// A close frame; the writer sends it and stops.
    Close {
        /// RFC 6455 §7.4.1 code.
        code: u16,
        /// The reason.
        reason: &'static str,
    },
}

/// How a text frame may be shed; results count as signaling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Class {
    /// Never dropped.
    Signaling,
    /// Coalesced per stream.
    StreamState(String),
    /// Coalesced per subscription, its command id, which a connection
    /// never reuses: a subscription's queued diagnostic is replaced by its
    /// newer one, so each holds at most one and a flood of them takes a
    /// frame's worth of the queue. Dropped when it would take the queue
    /// past half its budget; as one per subscription is small, that is a
    /// queue mostly full of signaling, about to be disconnected.
    Diagnostic(u64),
}

impl Class {
    /// How an event of `class` of subscription `subscription` is shed;
    /// `None` for the handler's [`EventClass::Overflowed`], which is no
    /// frame.
    pub(crate) fn of(class: EventClass, subscription: u64) -> Option<Self> {
        match class {
            EventClass::Signaling => Some(Self::Signaling),
            EventClass::StreamState { stream_id } => Some(Self::StreamState(stream_id)),
            EventClass::Diagnostic => Some(Self::Diagnostic(subscription)),
            EventClass::Overflowed => None,
        }
    }
}

/// The queue's state.
#[derive(Debug)]
struct State {
    /// The items in order.
    queue: VecDeque<Outgoing>,
    /// Bytes of text queued.
    bytes: usize,
    /// The byte budget.
    budget: usize,
    /// The bytes a diagnostic may fill the queue to: half the budget, so
    /// the diagnostics in it never take more than that half and signaling
    /// always has the rest. A source of diagnostics that outpaces the
    /// client's reader, a worker repeating its session's state for one,
    /// cannot leave the next signaling frame without room and have the
    /// client disconnected for it.
    diagnostic_budget: usize,
    /// No more items will be accepted.
    closed: bool,
    /// A non-droppable item did not fit.
    overflowed: bool,
    /// Diagnostics dropped.
    dropped: u64,
    /// Stream-state and diagnostic events replaced by a newer one.
    coalesced: u64,
}

/// The queue counters, for the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct OutboxStats {
    /// Diagnostics dropped.
    pub(crate) dropped: u64,
    /// Stream-state and diagnostic events replaced by a newer one.
    pub(crate) coalesced: u64,
    /// Bytes queued now.
    pub(crate) bytes: usize,
}

/// The queue: pushed by the connection and its subscriptions, popped by
/// the writer task.
#[derive(Debug)]
pub(crate) struct Outbox {
    /// The state.
    state: Mutex<State>,
    /// Wakes the writer.
    wake: Notify,
    /// Wakes the connection on overflow.
    overflow: Notify,
}

/// A non-droppable item did not fit the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("outbound queue overflowed")]
pub(crate) struct Overflow;

impl Outbox {
    /// A queue with `budget` bytes.
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                bytes: 0,
                budget,
                diagnostic_budget: budget / 2,
                closed: false,
                overflowed: false,
                dropped: 0,
                coalesced: 0,
            }),
            wake: Notify::new(),
            overflow: Notify::new(),
        }
    }

    /// Queues a text frame under the shedding rules.
    pub(crate) fn push(&self, class: Class, text: String) -> Result<(), Overflow> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return Ok(());
        }
        if class != Class::Signaling {
            let before = state.queue.len();
            let mut freed: usize = 0;
            state.queue.retain(|item| match item {
                Outgoing::Text {
                    class: queued,
                    text,
                } if *queued == class => {
                    freed = freed.saturating_add(text.len());
                    false
                }
                Outgoing::Text { .. } | Outgoing::Close { .. } => true,
            });
            let removed = before.saturating_sub(state.queue.len());
            state.bytes = state.bytes.saturating_sub(freed);
            state.coalesced = state
                .coalesced
                .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
        }
        let after = state.bytes.saturating_add(text.len());
        if matches!(class, Class::Diagnostic(_)) && after > state.diagnostic_budget {
            state.dropped = state.dropped.saturating_add(1);
            return Ok(());
        }
        if after > state.budget {
            drop(state);
            return Err(self.overflow());
        }
        state.bytes = after;
        state.queue.push_back(Outgoing::Text { class, text });
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    /// Marks the queue overflowed and wakes the connection, which closes:
    /// a non-droppable item did not fit, here or on its way here.
    pub(crate) fn overflow(&self) -> Overflow {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .overflowed = true;
        self.overflow.notify_one();
        Overflow
    }

    /// Queues a close frame and accepts nothing more.
    pub(crate) fn close(&self, code: u16, reason: &'static str) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.closed {
            state.closed = true;
            state.queue.push_back(Outgoing::Close { code, reason });
        }
        drop(state);
        self.wake.notify_one();
    }

    /// The next item, waiting for one; `None` once closed and drained.
    pub(crate) async fn pop(&self) -> Option<Outgoing> {
        loop {
            {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(item) = state.queue.pop_front() {
                    if let Outgoing::Text { text, .. } = &item {
                        state.bytes = state.bytes.saturating_sub(text.len());
                    }
                    return Some(item);
                }
                if state.closed {
                    return None;
                }
            }
            self.wake.notified().await;
        }
    }

    /// Resolves when a non-droppable item did not fit.
    pub(crate) async fn overflowed(&self) {
        loop {
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .overflowed
            {
                return;
            }
            self.overflow.notified().await;
        }
    }

    /// The counters.
    pub(crate) fn stats(&self) -> OutboxStats {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        OutboxStats {
            dropped: state.dropped,
            coalesced: state.coalesced,
            bytes: state.bytes,
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

    fn text(n: usize) -> String {
        "x".repeat(n)
    }

    #[tokio::test]
    async fn pops_in_order_and_ends_after_close() {
        let outbox = Outbox::new(100);
        outbox.push(Class::Signaling, "a".into()).unwrap();
        outbox.push(Class::Diagnostic(1), "b".into()).unwrap();
        outbox.close(1001, "going away");
        outbox.push(Class::Signaling, "late".into()).unwrap();
        assert!(matches!(outbox.pop().await, Some(Outgoing::Text { text, .. }) if text == "a"));
        assert!(matches!(outbox.pop().await, Some(Outgoing::Text { text, .. }) if text == "b"));
        assert_eq!(
            outbox.pop().await,
            Some(Outgoing::Close {
                code: 1001,
                reason: "going away"
            })
        );
        assert_eq!(outbox.pop().await, None);
        assert_eq!(outbox.stats().bytes, 0);
    }

    #[tokio::test]
    async fn stream_state_is_coalesced_per_stream() {
        let outbox = Outbox::new(1000);
        outbox
            .push(Class::StreamState("front".into()), "front-1".into())
            .unwrap();
        outbox
            .push(Class::StreamState("back".into()), "back-1".into())
            .unwrap();
        outbox.push(Class::Signaling, "answer".into()).unwrap();
        outbox
            .push(Class::StreamState("front".into()), "front-2".into())
            .unwrap();
        let mut texts = Vec::new();
        for _ in 0..3 {
            lotse_core::let_assert!(Some(Outgoing::Text { text, .. }) = outbox.pop().await);
            texts.push(text);
        }
        assert_eq!(texts, ["back-1", "answer", "front-2"]);
        assert_eq!(outbox.stats().coalesced, 1);
    }

    #[tokio::test]
    async fn diagnostics_are_dropped_under_pressure_but_signaling_overflows() {
        let outbox = Outbox::new(10);
        outbox.push(Class::Diagnostic(1), text(3)).unwrap();
        outbox.push(Class::Signaling, text(2)).unwrap();
        outbox.push(Class::Diagnostic(2), text(1)).unwrap();
        assert_eq!(outbox.stats().dropped, 1, "over half the budget");
        outbox.push(Class::Signaling, text(5)).unwrap();
        assert_eq!(outbox.stats().bytes, 10);
        assert_eq!(outbox.push(Class::Signaling, text(1)), Err(Overflow));
        outbox.overflowed().await;
        assert_eq!(
            outbox.push(Class::StreamState("s".into()), text(1)),
            Err(Overflow)
        );
        assert_eq!(Overflow.to_string(), "outbound queue overflowed");
    }

    /// Regression for SUP-30: diagnostics were dropped only once the queue
    /// held the whole budget, so a flood of them left the next signaling
    /// frame no room and the client was disconnected for it.
    #[tokio::test]
    async fn diagnostics_leave_half_the_budget_to_signaling() {
        let outbox = Outbox::new(10);
        for subscription in 0..5 {
            outbox
                .push(Class::Diagnostic(subscription), text(1))
                .unwrap();
        }
        assert_eq!(
            outbox.stats(),
            OutboxStats {
                dropped: 0,
                coalesced: 0,
                bytes: 5
            }
        );
        for subscription in 5..105 {
            outbox
                .push(Class::Diagnostic(subscription), text(1))
                .unwrap();
        }
        assert_eq!(outbox.stats().dropped, 100);
        outbox.push(Class::Signaling, text(5)).unwrap();
        assert_eq!(outbox.stats().bytes, 10, "the whole budget");
    }

    /// Regression for SUP-30: a worker flipping its session between two
    /// states made each report a change and took the diagnostics' half of
    /// the queue, so another session's `state` was dropped, and with
    /// repeats suppressed its last transition never came again.
    #[tokio::test]
    async fn a_flapping_session_s_state_is_coalesced_and_another_session_s_still_goes_out() {
        let outbox = Outbox::new(1000);
        outbox.push(Class::Signaling, "answer-a".into()).unwrap();
        for n in 0..10_000 {
            outbox
                .push(Class::Diagnostic(1), format!("state-a-{}", n % 2))
                .unwrap();
            if n == 5_000 {
                outbox.push(Class::Diagnostic(2), "state-b".into()).unwrap();
            }
        }
        outbox.push(Class::Signaling, "candidate-a".into()).unwrap();
        outbox
            .push(Class::Diagnostic(1), "state-a-last".into())
            .unwrap();
        assert_eq!(
            outbox.stats(),
            OutboxStats {
                dropped: 0,
                coalesced: 10_000,
                bytes: 8 + 7 + 11 + 12
            }
        );
        outbox.close(1000, "done");
        let mut texts = Vec::new();
        while let Some(Outgoing::Text { text, .. }) = outbox.pop().await {
            texts.push(text);
        }
        // One state per session, the latest; it follows the candidate it
        // was pushed after.
        assert_eq!(
            texts,
            ["answer-a", "state-b", "candidate-a", "state-a-last"]
        );
    }

    #[tokio::test]
    async fn the_writer_wakes_when_an_item_arrives() {
        let outbox = std::sync::Arc::new(Outbox::new(100));
        let waiter = lotse_core::task::spawn_named("test.pop", {
            let outbox = std::sync::Arc::clone(&outbox);
            async move { outbox.pop().await }
        });
        tokio::task::yield_now().await;
        outbox.push(Class::Signaling, "hi".into()).unwrap();
        assert!(matches!(waiter.await.unwrap(), Some(Outgoing::Text { text, .. }) if text == "hi"));
        assert_eq!(
            Class::of(EventClass::Diagnostic, 7),
            Some(Class::Diagnostic(7))
        );
        assert_eq!(
            Class::of(
                EventClass::StreamState {
                    stream_id: "s".into()
                },
                7
            ),
            Some(Class::StreamState("s".into()))
        );
        assert_eq!(Class::of(EventClass::Signaling, 7), Some(Class::Signaling));
        assert_eq!(Class::of(EventClass::Overflowed, 7), None, "no frame");
    }

    #[tokio::test]
    async fn an_overflow_from_upstream_closes_the_connection_as_its_own_does() {
        let outbox = Outbox::new(100);
        outbox.push(Class::Signaling, text(1)).unwrap();
        assert_eq!(outbox.overflow(), Overflow);
        outbox.overflowed().await;
        assert_eq!(outbox.stats().bytes, 1, "what was queued stays");
    }
}

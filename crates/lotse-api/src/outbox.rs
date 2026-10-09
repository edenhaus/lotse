//! The bounded outbound queue of one connection, with its shedding rules:
//! stream-state events are coalesced (latest per stream), diagnostics are
//! dropped when the queue is under pressure, and results and signaling are
//! never dropped, so a client that still fills the budget is disconnected.

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
    /// Dropped under pressure.
    Diagnostic,
}

impl From<EventClass> for Class {
    fn from(class: EventClass) -> Self {
        match class {
            EventClass::Signaling => Self::Signaling,
            EventClass::StreamState { stream_id } => Self::StreamState(stream_id),
            EventClass::Diagnostic => Self::Diagnostic,
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
    /// No more items will be accepted.
    closed: bool,
    /// A non-droppable item did not fit.
    overflowed: bool,
    /// Diagnostics dropped.
    dropped: u64,
    /// Stream-state events replaced by a newer one.
    coalesced: u64,
}

/// The queue counters, for the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct OutboxStats {
    /// Diagnostics dropped.
    pub(crate) dropped: u64,
    /// Stream-state events coalesced.
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
        if let Class::StreamState(stream_id) = &class {
            let before = state.queue.len();
            let mut freed: usize = 0;
            state.queue.retain(|item| match item {
                Outgoing::Text {
                    class: Class::StreamState(queued),
                    text,
                } if queued == stream_id => {
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
        if after > state.budget {
            match class {
                Class::Diagnostic => {
                    state.dropped = state.dropped.saturating_add(1);
                    return Ok(());
                }
                Class::Signaling | Class::StreamState(_) => {
                    state.overflowed = true;
                    drop(state);
                    self.overflow.notify_one();
                    return Err(Overflow);
                }
            }
        }
        state.bytes = after;
        state.queue.push_back(Outgoing::Text { class, text });
        drop(state);
        self.wake.notify_one();
        Ok(())
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
        outbox.push(Class::Diagnostic, "b".into()).unwrap();
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
            let Some(Outgoing::Text { text, .. }) = outbox.pop().await else {
                panic!("text")
            };
            texts.push(text);
        }
        assert_eq!(texts, ["back-1", "answer", "front-2"]);
        assert_eq!(outbox.stats().coalesced, 1);
    }

    #[tokio::test]
    async fn diagnostics_are_dropped_under_pressure_but_signaling_overflows() {
        let outbox = Outbox::new(10);
        outbox.push(Class::Signaling, text(8)).unwrap();
        outbox.push(Class::Diagnostic, text(5)).unwrap();
        assert_eq!(outbox.stats().dropped, 1);
        outbox.push(Class::Diagnostic, text(2)).unwrap();
        assert_eq!(outbox.stats().bytes, 10);
        assert_eq!(outbox.push(Class::Signaling, text(1)), Err(Overflow));
        outbox.overflowed().await;
        assert_eq!(
            outbox.push(Class::StreamState("s".into()), text(1)),
            Err(Overflow)
        );
        assert_eq!(Overflow.to_string(), "outbound queue overflowed");
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
        assert_eq!(Class::from(EventClass::Diagnostic), Class::Diagnostic);
        assert_eq!(
            Class::from(EventClass::StreamState {
                stream_id: "s".into()
            }),
            Class::StreamState("s".into())
        );
        assert_eq!(Class::from(EventClass::Signaling), Class::Signaling);
    }
}

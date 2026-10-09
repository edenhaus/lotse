//! The log lines a test made, for asserting what is logged and how often.
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::missing_panics_doc,
    reason = "test code"
)]

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use tracing::Level;

/// One event: its level, its message and its other fields as
/// `name=value` pairs, values Debug-formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    pub(crate) level: Level,
    pub(crate) message: String,
    pub(crate) fields: String,
}

/// The events logged on this thread while captured. Also makes every
/// field expression of the lines logged run.
#[derive(Debug, Clone, Default)]
pub(crate) struct Logs(Arc<Mutex<Vec<Line>>>);

impl Logs {
    /// Captures this thread's events until the guard is dropped.
    pub(crate) fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
        let logs = Self::default();
        let guard = tracing::subscriber::set_default(logs.clone());
        (logs, guard)
    }

    /// How many events at `level` had `message`.
    pub(crate) fn count(&self, level: Level, message: &str) -> usize {
        self.lines(level, message).len()
    }

    /// The events at `level` with `message`, in order.
    pub(crate) fn lines(&self, level: Level, message: &str) -> Vec<Line> {
        let seen = self.0.lock().unwrap();
        seen.iter()
            .filter(|line| line.level == level && line.message == message)
            .cloned()
            .collect()
    }
}

/// An event's message and fields.
#[derive(Default)]
struct Visitor {
    message: String,
    fields: String,
}

impl tracing::field::Visit for Visitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            write!(self.fields, " {}={value:?}", field.name()).unwrap();
        }
    }
}

impl tracing::Subscriber for Logs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        self.0.lock().unwrap().push(Line {
            level: *event.metadata().level(),
            message: visitor.message,
            fields: visitor.fields,
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn logs_capture_takes_every_kind_of_call() {
    let (logs, _guard) = Logs::capture();
    let span = tracing::info_span!("span", field = tracing::field::Empty);
    span.record("field", 1);
    span.follows_from(tracing::span::Id::from_u64(2));
    span.in_scope(|| {
        tracing::info!(n = 1, "inside");
        tracing::warn!(n = 2, text = "a", "inside");
    });
    assert_eq!(logs.count(Level::INFO, "inside"), 1);
    assert_eq!(
        logs.lines(Level::WARN, "inside"),
        [Line {
            level: Level::WARN,
            message: "inside".into(),
            fields: " n=2 text=\"a\"".into(),
        }]
    );
}

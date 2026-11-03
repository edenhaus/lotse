//! Which of retina's spans and events may reach a log line.
//!
//! retina logs through `tracing` and names the URL of its request in a
//! `url` field: on its `rtsp_request` and `rtsp_teardown` spans, so every
//! retina event inside one carries it, and on a few events of its own (a
//! `DESCRIBE` answer without a content type, a repaired schemeless URL, an
//! unknown stream in `RTP-Info`, a `TEARDOWN` starting). The URL retina is
//! given is the source URL with the address of the crate's loopback relay
//! for its host: the credentials are gone, but the path and query stay,
//! which may hold a camera key or a token and which lotse logs only
//! redacted (`lotse_core::secret::RedactedUrl`). So a log subscriber leaves
//! out every retina span or event with that field ([`loggable`]): such a
//! span drops out of the line's context while the events inside it stay,
//! and such an event is dropped whole.

/// Whether a span or event of `metadata` may reach a log line: not when it
/// is retina's and has a `url` field. For a per-layer filter of the
/// subscriber's line layer (`tracing_subscriber::filter::filter_fn`).
pub fn loggable(metadata: &tracing::Metadata<'_>) -> bool {
    let target = metadata.target();
    let retina = target == "retina" || target.starts_with("retina::");
    !(retina && metadata.fields().field("url").is_some())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::{Arc, Mutex};

    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    /// A log sink the test reads back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn retinas_spans_and_events_with_a_url_are_left_out_and_nothing_else() {
        let mut captured = Captured::default();
        let writer = captured.clone();
        let lines = tracing_subscriber::fmt::layer()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::filter_fn(loggable));
        let subscriber = tracing_subscriber::registry().with(lines);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                target: "retina::client::session_core",
                "rtsp_request",
                url = "rtsp://127.0.0.1:41000/camkey7f3a?token=tok9d2e"
            );
            let _entered = span.enter();
            tracing::warn!(target: "retina::client::parse", "ignoring invalid fmtp attribute value");
            tracing::warn!(
                target: "retina::client::parse",
                url = "rtsp://127.0.0.1:41000/camkey7f3a?token=tok9d2e",
                "DESCRIBE response has no content type"
            );
            tracing::debug!(target: "retina", url = "rtsp://cam/camkey7f3a", "TEARDOWN starting");
            tracing::info!(target: "retinal", url = "rtsp://cam/****", "not retina's");
        });
        std::io::Write::flush(&mut captured).unwrap();
        let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(!logs.contains("camkey7f3a"), "{logs}");
        assert!(!logs.contains("rtsp_request"), "{logs}");
        assert!(!logs.contains("no content type"), "{logs}");
        assert!(!logs.contains("TEARDOWN starting"), "{logs}");
        assert!(
            logs.contains("ignoring invalid fmtp attribute value"),
            "{logs}"
        );
        assert!(
            logs.contains("not retina's url=\"rtsp://cam/****\""),
            "{logs}"
        );
    }
}

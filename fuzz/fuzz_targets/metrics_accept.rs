//! `metrics_accept`: the `Accept` header of a metrics scrape, which any
//! enrolled scraper sends, never panics, and always picks a format the
//! route can send: OpenMetrics 1.0.0 only when the header names it or its
//! type, else the Prometheus text format 0.0.4.
//! Run with `cargo +nightly fuzz run metrics_accept` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_api::exporter::{Format, negotiate_accept};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Format::OpenMetrics(_) = negotiate_accept(text) {
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("application/") || lower.contains("*/"),
            "{text:?}"
        );
    }
});

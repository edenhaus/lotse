//! The output conformance suite against the WebRTC session output.

#![allow(clippy::missing_docs_in_private_items, reason = "test code")]

use rocko_core::clock::{Clock as _, SystemClock};
use rocko_testing::output_suite::check_all;
use rocko_webrtc::WebRtcFactory;

#[test]
fn the_webrtc_session_passes_the_output_conformance_suite() {
    rocko_webrtc::install_crypto_provider();
    let violations = check_all(&WebRtcFactory, SystemClock.now());
    assert!(violations.is_empty(), "{violations:#?}");
}

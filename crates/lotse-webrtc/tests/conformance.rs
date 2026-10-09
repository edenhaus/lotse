//! The output conformance suite against the WebRTC session output.

#![allow(clippy::missing_docs_in_private_items, reason = "test code")]

use lotse_core::clock::{Clock as _, SystemClock};
use lotse_testing::output_suite::check_all;
use lotse_webrtc::WebRtcFactory;

#[test]
fn the_webrtc_session_passes_the_output_conformance_suite() {
    lotse_webrtc::install_crypto_provider();
    let violations = check_all(&WebRtcFactory, SystemClock.now());
    assert!(violations.is_empty(), "{violations:#?}");
}

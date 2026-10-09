//! `h264_sps`: reading a sequence parameter set or a recovery-point SEI
//! from arbitrary bytes never panics.
//! Run with `cargo +nightly fuzz run h264_sps` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::h264::{has_recovery_point, parse_sps};

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = parse_sps(data) {
        assert!(info.width > 0 && info.height > 0);
    }
    let _ = has_recovery_point(data);
});

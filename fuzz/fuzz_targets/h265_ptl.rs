//! `h265_ptl`: reading the profile, tier, level and picture size of a
//! sequence parameter set, or a recovery-point SEI, from arbitrary bytes
//! never panics, a size it reports is a picture, and its sub-layers,
//! chroma format and bit depths lie in their ranges (ITU-T H.265
//! §7.3.2.2.1, §7.4.3.2.1, §7.3.3, D.2.8).
//! Run with `cargo +nightly fuzz run h265_ptl` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::h265::{has_recovery_point, parse_sps};

fuzz_target!(|data: &[u8]| {
    if let Ok(info) = parse_sps(data) {
        assert!(info.width > 0 && info.height > 0);
        assert!(info.profile_space < 4 && info.profile_idc < 32);
        assert!((1..=7).contains(&info.sub_layers) && info.chroma_format_idc <= 3);
        assert!(
            (8..=16).contains(&info.bit_depth_luma) && (8..=16).contains(&info.bit_depth_chroma)
        );
    }
    let _ = has_recovery_point(data);
});

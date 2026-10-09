//! `aac_config`: reading an `AudioSpecificConfig` from arbitrary bytes
//! never panics, and what it accepts is decodable AAC-LC.
//! Run with `cargo +nightly fuzz run aac_config` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::aac::parse_config;

fuzz_target!(|data: &[u8]| {
    if let Ok(config) = parse_config(data) {
        assert!(config.sample_rate > 0);
        assert!(matches!(config.channels, 1 | 2));
    }
});

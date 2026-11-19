//! `client_pins`: the control TLS listener's enrolled pins file, a pin and
//! its role per line, a pin alone in files from before roles, never
//! panics, and what it accepts is written back as it reads it: rendered and
//! parsed again, the same pins with the same roles.
//! Run with `cargo +nightly fuzz run client_pins` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_api::{parse_pins, render_pins};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(pins) = parse_pins(text) {
        let rendered = render_pins(&pins);
        assert_eq!(rendered.lines().count(), pins.len());
        assert_eq!(parse_pins(&rendered), Ok(pins), "{rendered:?}");
    }
});

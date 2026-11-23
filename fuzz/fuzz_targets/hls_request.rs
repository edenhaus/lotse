//! `hls_request`: what an LL-HLS client sends the supervisor's window never
//! panics, and what is accepted is exact. The input, split at its first NUL
//! byte, is a request and a script of fragments.
//!
//! The request is parsed as a resource's name, as a playlist request's
//! query and as a decimal-integer: a name is accepted only as the window
//! writes it (it round-trips), a value only as 1 to 20 digits. The script
//! builds a window as a compromised worker could, 4 bytes a fragment
//! (independence, length, duration in milliseconds), with a small byte
//! cap: the window never holds more than its cap, and every request is
//! answered, from the window as built and the parsed directives and name.
//! Run with `cargo +nightly fuzz run hls_request` from the repository root.

#![no_main]

use std::time::Duration;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rocko_hls::{
    Blocking, Config, Fragment, Lookup, MSN_DIRECTIVE, PART_DIRECTIVE, Resource, Window,
    decimal_integer,
};

/// The window's byte cap: small, so the script reaches it.
const MAX_BYTES: usize = 64 * 1024;

/// Builds a window from a script of 4-byte fragments.
fn build(script: &[u8]) -> Window {
    let config = Config {
        max_bytes: MAX_BYTES,
        segments: 3,
        ..Config::default()
    };
    let mut window = Window::new(config, Bytes::from_static(b"init")).unwrap();
    for step in script.chunks_exact(4) {
        let fragment = Fragment {
            bytes: Bytes::from(vec![0; usize::from(step[1]) * 64]),
            independent: step[0] & 1 == 1,
            duration: Duration::from_millis(u64::from(u16::from_be_bytes([step[2], step[3]]))),
        };
        if window.push(fragment).is_err() {
            break;
        }
        assert!(window.bytes() <= MAX_BYTES + 4);
    }
    window
}

fuzz_target!(|data: &[u8]| {
    let (request, script) = match data.iter().position(|byte| *byte == 0) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &data[..0]),
    };
    let window = build(script);
    if let Some(playlist) = window.playlist() {
        assert!(playlist.starts_with("#EXTM3U\n"));
    }
    let Ok(request) = std::str::from_utf8(request) else {
        return;
    };

    if let Some(resource) = Resource::parse(request) {
        assert_eq!(resource.to_string(), request);
        if let Lookup::Ready(chunks) = window.get(resource) {
            let len: usize = chunks.as_slice().iter().map(Bytes::len).sum();
            assert_eq!(len, chunks.len());
            assert!(len <= MAX_BYTES);
        }
    }
    if let Some(value) = decimal_integer(request) {
        assert!((1..=20).contains(&request.len()));
        let significant = request.trim_start_matches('0');
        let expected = if significant.is_empty() {
            "0"
        } else {
            significant
        };
        assert_eq!(value.to_string(), expected);
    }
    if let Ok(blocking) = Blocking::parse(request) {
        let names = || request.split('&').map(|pair| pair.split('=').next());
        if blocking == Blocking::None {
            assert!(
                names().all(|name| name != Some(MSN_DIRECTIVE) && name != Some(PART_DIRECTIVE))
            );
        }
        window.reload(blocking);
    }
});

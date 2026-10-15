//! `pair_request`: the body of a pairing request, which arrives from a
//! client that only proved it holds some key, never panics, and what it
//! accepts is exactly `{"secret":"<32 hex digits>"}`.
//! Run with `cargo +nightly fuzz run pair_request` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_api::pairing::parse_request;

fuzz_target!(|data: &[u8]| {
    if let Some(secret) = parse_request(data) {
        let text = std::str::from_utf8(data).expect("accepted bodies are JSON text");
        let value: serde_json::Value =
            serde_json::from_str(text).expect("accepted bodies are JSON");
        let digits = value["secret"].as_str().expect("a secret string");
        assert_eq!(digits.len(), 32);
        let decoded: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect();
        assert_eq!(decoded, secret);
    }
});

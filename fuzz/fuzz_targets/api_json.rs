//! `api_json`: a control-API text frame never panics the command parser;
//! a frame that parses names a known command, re-serializes to the same
//! command (up to serde_json's float rounding in free-form source options),
//! and stops parsing once it carries a field the command does not
//! define, so a typo fails loudly.
//! Run with `cargo +nightly fuzz run api_json` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_api_types::{Command, parse_command};

/// Whether `value` holds a number that is not an integer.
fn has_float(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(n) => n.is_f64(),
        serde_json::Value::Array(items) => items.iter().any(has_float),
        serde_json::Value::Object(fields) => fields.values().any(has_float),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(command) = parse_command(text) else {
        return;
    };
    assert!(Command::NAMES.contains(&command.name()));
    let json = serde_json::to_value(&command).expect("a command serializes");
    let again = parse_command(&json.to_string()).expect("a serialized command parses");
    // serde_json's default float parser is not correctly rounded, so a
    // float in a source's free-form options may come back one ULP off.
    if !has_float(&json) {
        assert_eq!(again, command);
    }
    assert_eq!((again.name(), again.id()), (command.name(), command.id()));
    let serde_json::Value::Object(mut fields) = json else {
        panic!("a command is an object");
    };
    fields.insert("lotse_fuzz_unknown".into(), serde_json::Value::Null);
    assert!(
        parse_command(&serde_json::Value::Object(fields).to_string()).is_err(),
        "an unknown field is rejected"
    );
});

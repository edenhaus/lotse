//! `ipc_message`: the supervisor's view of worker bytes never panics, never
//! hangs and allocates only what the bytes describe.
//! Run with `cargo +nightly fuzz run ipc_message` from `fuzz/`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_ipc::{ToSupervisor, ToWorker, decode, encode};

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = decode::<ToSupervisor>(data) {
        // What decodes must encode back to the same message.
        let bytes = encode(&message).expect("a decoded message encodes");
        assert_eq!(decode::<ToSupervisor>(&bytes).ok(), Some(message));
    }
    let _ = decode::<ToWorker>(data);
});

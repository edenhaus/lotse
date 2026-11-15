//! `live_records`: the supervisor's reader of a framed live output's pipe
//! (`lotse_ipc::fragments::Decoder`), whose bytes a worker writes and so are
//! untrusted, never panics whatever the bytes and however the reads split
//! them; the records it takes are the same for every split, each within
//! its bounds, and it never asks for more than one record ahead.
//! The first input byte sets the read size (1 to 256 bytes).
//! Run with `cargo +nightly fuzz run live_records` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_ipc::fragments::{Decoder, MAX_RECORD_BYTES, Record, RecordError};

/// The records of `stream` read `step` bytes at a time, and the error that
/// ended it, if any.
fn read(stream: &[u8], step: usize) -> (Vec<Record>, Option<RecordError>) {
    let mut decoder = Decoder::new();
    let mut records = Vec::new();
    for chunk in stream.chunks(step) {
        assert!(decoder.wants() <= usize::try_from(MAX_RECORD_BYTES).unwrap() + 16);
        match decoder.push(chunk) {
            Ok(more) => records.extend(more),
            Err(err) => return (records, Some(err)),
        }
    }
    (records, None)
}

fuzz_target!(|data: &[u8]| {
    let Some((&step, stream)) = data.split_first() else {
        return;
    };
    let (whole, ended) = read(stream, stream.len().max(1));
    let (split, split_ended) = read(stream, usize::from(step) + 1);
    assert_eq!(ended, split_ended);
    // Read in pieces, a broken header is met after the records before it
    // too, and no record is taken that the whole read did not.
    assert_eq!(whole, split);
    for record in &whole {
        assert!(record.bytes.len() <= usize::try_from(MAX_RECORD_BYTES).unwrap());
    }
});

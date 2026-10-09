//! `aac_depacketize`: the RFC 3640 depacketizer never panics and never
//! hangs on arbitrary packets, and emits only non-empty frames within the
//! size limit.
//! Run with `cargo +nightly fuzz run aac_depacketize` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::aac::AacDepacketizer;

fuzz_target!(|data: &[u8]| {
    // The input is a sequence of packets: [len:u8][ts_delta:u8][flags:u8][payload...].
    let mut depacketizer = AacDepacketizer::new(512);
    let mut rest = data;
    let mut ts = 0_u32;
    let mut seq = 0_u16;
    let mut frames = Vec::new();
    while let Some((&len, after)) = rest.split_first() {
        let Some((&delta, after)) = after.split_first() else {
            break;
        };
        let Some((&flags, after)) = after.split_first() else {
            break;
        };
        let Some((payload, after)) = after.split_at_checked(usize::from(len)) else {
            break;
        };
        rest = after;
        ts = ts.wrapping_add(u32::from(delta));
        // Bit 1 skips a sequence number: a lost packet.
        seq = seq.wrapping_add(if flags & 2 != 0 { 2 } else { 1 });
        frames.clear();
        let _ = depacketizer.push(seq, ts, flags & 1 != 0, payload, &mut frames);
        for frame in &frames {
            assert!(!frame.payload.is_empty());
            assert!(frame.payload.len() <= 512);
        }
    }
});

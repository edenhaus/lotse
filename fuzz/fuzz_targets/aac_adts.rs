//! `aac_adts`: the ADTS splitter never panics and never hangs on arbitrary
//! bytes in arbitrary pieces, emits only non-empty frames within the size
//! limit with increasing sequences, holds at most one frame (ISO/IEC
//! 13818-7 §6.2.2: 13-bit `frame_length`) plus one byte, and splits the
//! same bytes into the same frames however they are cut.
//! Run with `cargo +nightly fuzz run aac_adts` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_codec::aac::{AdtsSplitter, MAX_ADTS_FRAME, parse_config};

/// The frame limit: short frames fit, longer ones are dropped.
const MAX_FRAME: usize = 64;

fuzz_target!(|data: &[u8]| {
    // The input is a sequence of pushes: [len:u8][bytes...].
    let mut pieces = AdtsSplitter::new(MAX_FRAME);
    let mut whole = Vec::new();
    let mut frames = Vec::new();
    let mut last_anchor = None;
    let mut rest = data;
    while let Some((&len, after)) = rest.split_first() {
        let take = usize::from(len).min(after.len());
        let (piece, after) = after.split_at(take);
        rest = after;
        whole.extend_from_slice(piece);
        let before = frames.len();
        let anchor = pieces.push(piece, &mut frames);
        if let Some(anchor) = anchor {
            assert!(
                last_anchor.is_none_or(|last| anchor > last),
                "anchors go back"
            );
            last_anchor = Some(anchor);
        }
        assert!(
            pieces.buffered() <= MAX_ADTS_FRAME + 1,
            "held {}",
            pieces.buffered()
        );
        for frame in &frames[before..] {
            assert!(!frame.payload.is_empty());
            assert!(frame.payload.len() <= MAX_FRAME);
            assert_eq!(
                frame.config.parsed,
                parse_config(&frame.config.audio_specific_config)
            );
        }
    }
    assert!(
        frames.windows(2).all(|w| w[0].sequence < w[1].sequence),
        "sequences do not increase"
    );
    let mut once = AdtsSplitter::new(MAX_FRAME);
    let mut all = Vec::new();
    let _ = once.push(&whole, &mut all);
    assert_eq!(all, frames, "the cut changed the frames");
    assert_eq!(once.stats(), pieces.stats());
    assert_eq!(once.buffered(), pieces.buffered());
});

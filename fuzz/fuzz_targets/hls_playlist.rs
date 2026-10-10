//! `hls_playlist`: parsing an HLS playlist from arbitrary bytes never
//! panics, and what it accepts is bounded, of the playlist's origin and
//! without fragments. Each input is parsed as it is and behind `#EXTM3U`,
//! so the fuzzer reaches the tags without first finding the header.
//! Run with `cargo +nightly fuzz run hls_playlist` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_http::hls::{MAX_RENDITIONS, MAX_SEGMENTS, MAX_VARIANTS, Playlist, parse};
use url::Url;

/// Checks one URL a parsed playlist holds against the playlist's own.
fn check(url: &Url, base: &Url) {
    assert_eq!(url.origin(), base.origin());
    assert!(url.fragment().is_none());
}

/// Parses one input and checks what it accepts.
fn run(data: &[u8], base: &Url) {
    match parse(data, base) {
        Ok(Playlist::Media(playlist)) => {
            assert!(!playlist.target_duration.is_zero());
            assert!(playlist.segments.len() <= MAX_SEGMENTS);
            assert!(
                playlist
                    .start
                    .is_none_or(|start| start.time_offset.is_finite())
            );
            for segment in &playlist.segments {
                assert!(!segment.duration.is_zero());
                check(&segment.uri, base);
                if let Some(map) = &segment.map {
                    check(map, base);
                }
            }
        }
        Ok(Playlist::Multivariant(playlist)) => {
            assert!(playlist.variants.len() <= MAX_VARIANTS);
            assert!(playlist.audio.len() <= MAX_RENDITIONS);
            for variant in &playlist.variants {
                check(&variant.uri, base);
            }
            for rendition in &playlist.audio {
                if let Some(uri) = &rendition.uri {
                    check(uri, base);
                }
            }
        }
        Err(_) => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let base = Url::parse("http://camera.invalid:8080/live/index.m3u8").unwrap();
    run(data, &base);
    run(&[b"#EXTM3U\n", data].concat(), &base);
});

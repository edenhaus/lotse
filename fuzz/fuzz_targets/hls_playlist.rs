//! `hls_playlist`: parsing an HLS playlist from arbitrary bytes never
//! panics, and what it accepts is bounded (its URLs included, an
//! `EXT-X-MAP` held once for its segments), of the playlist's origin and
//! without fragments. Each input is parsed as it is and behind `#EXTM3U`,
//! so the fuzzer reaches the tags without first finding the header; a
//! variant is chosen from every multivariant playlist accepted.
//!
//! The input, split at its first NUL byte, is then two loads of one media
//! playlist (behind `#EXTM3U` and a target duration): the tracker following
//! them never yields a segment twice or out of order unless the stream
//! restarted, and reloads after the target duration or half of it.
//! Run with `cargo +nightly fuzz run hls_playlist` from the repository root.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lotse_http::hls::{
    Event, MAX_RENDITIONS, MAX_SEGMENTS, MAX_URL_BYTES, MAX_VARIANTS, MediaPlaylist, Playlist,
    Tracker, choose_variant, parse, start_index,
};
use std::sync::Arc;

use url::Url;

/// Checks one URL a parsed playlist holds against the playlist's own,
/// and returns its length.
fn check(url: &Url, base: &Url) -> usize {
    assert_eq!(url.origin(), base.origin());
    assert!(url.fragment().is_none());
    url.as_str().len()
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
            let mut urls = 0;
            let mut last_map: Option<&Arc<Url>> = None;
            for segment in &playlist.segments {
                assert!(!segment.duration.is_zero());
                urls += check(&segment.uri, base);
                if let Some(map) = &segment.map {
                    let length = check(map, base);
                    // A map is held once: a segment shares the one before
                    // it unless another EXT-X-MAP came between them.
                    if !last_map.is_some_and(|last| Arc::ptr_eq(last, map)) {
                        urls += length;
                    }
                    last_map = Some(map);
                }
            }
            assert!(urls <= MAX_URL_BYTES, "{urls} bytes of URLs");
        }
        Ok(Playlist::Multivariant(playlist)) => {
            assert!(playlist.variants.len() <= MAX_VARIANTS);
            assert!(playlist.audio.len() <= MAX_RENDITIONS);
            let mut urls = 0;
            for variant in &playlist.variants {
                urls += check(&variant.uri, base);
            }
            for rendition in &playlist.audio {
                if let Some(uri) = &rendition.uri {
                    urls += check(uri, base);
                }
            }
            assert!(urls <= MAX_URL_BYTES, "{urls} bytes of URLs");
            for max_bandwidth in [None, Some(1_000_000)] {
                if let Ok(choice) = choose_variant(&playlist, max_bandwidth) {
                    assert!(playlist.variants.contains(&choice.variant));
                    if let Some(audio) = &choice.audio {
                        assert!(playlist.audio.contains(audio));
                        assert_eq!(Some(&audio.group_id), choice.variant.audio_group.as_ref());
                    }
                }
            }
        }
        Err(_) => {}
    }
}

/// Parses `data` as a media playlist, behind a header and a target duration.
fn media(data: &[u8], base: &Url) -> Option<MediaPlaylist> {
    match parse(
        &[b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n", data].concat(),
        base,
    ) {
        Ok(Playlist::Media(playlist)) => Some(playlist),
        _ => None,
    }
}

/// Follows two loads of a media playlist and checks what the tracker yields.
fn track(first: &[u8], second: &[u8], base: &Url) {
    let mut tracker = Tracker::new();
    let mut last: Option<u64> = None;
    for playlist in [first, second]
        .into_iter()
        .filter_map(|data| media(data, base))
    {
        if let Some(index) = start_index(&playlist) {
            assert!(index < playlist.segments.len());
        }
        let update = tracker.update(&playlist);
        if update.event == Some(Event::Restart) {
            last = None;
        }
        for fetch in &update.segments {
            assert!(last.is_none_or(|last| fetch.sequence > last));
            assert!(fetch.sequence < u64::MAX);
            last = Some(fetch.sequence);
        }
        if let Some(reload_after) = update.reload_after {
            assert!(
                reload_after == playlist.target_duration
                    || reload_after == playlist.target_duration / 2
            );
        } else {
            assert!(playlist.end_list);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let base = Url::parse("http://camera.invalid:8080/live/index.m3u8").unwrap();
    run(data, &base);
    run(&[b"#EXTM3U\n", data].concat(), &base);
    let (first, second) = match data.iter().position(|byte| *byte == 0) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &data[..0]),
    };
    track(first, second, &base);
});

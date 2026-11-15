#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    reason = "test code"
)]

use super::*;

const INIT: &[u8] = b"init";

const MS: u64 = 1_000_000;

fn window(config: Config) -> Window {
    Window::new(config, Bytes::from_static(INIT)).unwrap()
}

/// A fragment of `len` bytes, all `tag`, lasting `nanos`.
fn fragment(tag: u8, len: usize, independent: bool, nanos: u64) -> Fragment {
    Fragment {
        bytes: Bytes::from(vec![tag; len]),
        independent,
        duration: Duration::from_nanos(nanos),
    }
}

/// What a fragment of [`push_frames`] and [`push_200_ms`] costs the window:
/// its 72 bytes and the overhead.
const EACH: usize = 72 + FRAGMENT_OVERHEAD;

/// Pushes `count` fragments of `ms` each and 72 bytes ([`EACH`] with the
/// overhead), the `n`th tagged `n` and independent when `n % gop == 0`;
/// returns what the last became.
fn push_frames(window: &mut Window, from: usize, count: usize, ms: u64, gop: usize) -> Pushed {
    let mut last = Pushed::Dropped;
    for n in from..from + count {
        last = window
            .push(fragment(
                u8::try_from(n).unwrap(),
                72,
                n % gop == 0,
                ms * MS,
            ))
            .unwrap();
    }
    last
}

/// A window after `count` fragments of 200 ms, a keyframe every 5: one
/// fragment a part, five parts a segment of 1 s.
fn five_part_segments(config: Config, count: usize) -> Window {
    let mut window = window(config);
    push_frames(&mut window, 0, count, 200, 5);
    window
}

/// Pushes fragments `from` to `to` (excluded) of 200 ms and 72 bytes
/// ([`EACH`] with the overhead), the `n`th tagged `n` (wrapping) and independent when
/// `independent(n)`: one fragment a part. The window's clock is then `to`
/// × 200 ms.
fn push_200_ms(window: &mut Window, from: usize, to: usize, independent: fn(usize) -> bool) {
    for n in from..to {
        window
            .push(fragment(
                u8::try_from(n % 256).unwrap(),
                72,
                independent(n),
                200 * MS,
            ))
            .unwrap();
    }
}

/// A first segment of 1.4 s (7 fragments), then segments of 1 s (5): the
/// Target Duration is 1.
fn first_1400_ms(n: usize) -> bool {
    n == 0 || (n >= 7 && (n - 7).is_multiple_of(5))
}

/// A first segment of 2 s (10 fragments), then segments of 1 s (5): the
/// Target Duration is 2, and a playlist of 6 segments lasts 6 or 7 s.
fn first_2_s(n: usize) -> bool {
    n == 0 || (n >= 10 && n.is_multiple_of(5))
}

/// Whether the window serves segment `msn` and its part 0.
fn serves(window: &Window, msn: u64) -> bool {
    let segment = matches!(window.get(Resource::Segment { msn }), Lookup::Ready(_));
    let part = matches!(
        window.get(Resource::Part { msn, index: 0 }),
        Lookup::Ready(_)
    );
    assert_eq!(segment, part, "segment {msn} and its part 0");
    segment
}

/// Asserts that every parent in `playlist` lists its part tags from Part
/// Index 0 on, consecutively: a client numbers them by their position after
/// the previous segment's URI (§3.2).
fn assert_part_tags_start_at_0(playlist: &str) {
    let mut position = 0;
    for line in playlist.lines() {
        if let Some(part) = line.strip_prefix("#EXT-X-PART:") {
            let uri = part.split("URI=\"").nth(1).unwrap();
            let index = uri.split('.').nth(1).unwrap();
            assert_eq!(index, position.to_string(), "{line} in\n{playlist}");
            position += 1;
        } else if !line.starts_with('#') {
            position = 0;
        }
    }
}

fn chunks_of(lookup: Lookup) -> Vec<Bytes> {
    match lookup {
        Lookup::Ready(chunks) => chunks.into_vec(),
        other => panic!("not ready: {other:?}"),
    }
}

/// The tags of the fragments a lookup's chunks are.
fn tags(lookup: Lookup) -> Vec<u8> {
    chunks_of(lookup).iter().map(|chunk| chunk[0]).collect()
}

#[test]
fn the_defaults_are_the_documented_ones() {
    assert_eq!(
        Config::default(),
        Config {
            part_target: Duration::from_millis(200),
            segment_target: Duration::from_secs(1),
            segments: 6,
            max_bytes: 32 * 1024 * 1024,
        }
    );
}

#[test]
fn a_config_the_window_cannot_run_with_is_refused() {
    let refused = |config| Window::new(config, Bytes::new()).unwrap_err();
    assert_eq!(
        refused(Config {
            part_target: Duration::ZERO,
            ..Config::default()
        }),
        ConfigError::ZeroPartTarget
    );
    assert_eq!(
        refused(Config {
            segments: 0,
            ..Config::default()
        }),
        ConfigError::NoSegments
    );
    assert_eq!(
        refused(Config {
            max_bytes: 0,
            ..Config::default()
        }),
        ConfigError::ZeroMaxBytes
    );
}

#[test]
fn the_errors_say_what_went_wrong() {
    assert_eq!(
        ConfigError::ZeroPartTarget.to_string(),
        "the part target is zero"
    );
    assert_eq!(
        ConfigError::NoSegments.to_string(),
        "the window lists no segment"
    );
    assert_eq!(
        ConfigError::ZeroMaxBytes.to_string(),
        "the window's byte cap is zero"
    );
    assert_eq!(
        PushError::Overflow { max_bytes: 7 }.to_string(),
        "the open segment would hold more than the window's 7 bytes"
    );
}

#[test]
fn fragments_before_the_first_independent_one_are_dropped() {
    let mut window = window(Config::default());
    assert_eq!(
        window.push(fragment(1, 10, false, 40 * MS)),
        Ok(Pushed::Dropped)
    );
    assert_eq!(window.push(fragment(2, 10, false, 0)), Ok(Pushed::Dropped));
    assert_eq!(window.bytes(), INIT.len());
    assert_eq!(window.init(), &Bytes::from_static(INIT));
    assert_eq!(
        window.push(fragment(3, 10, true, 40 * MS)),
        Ok(Pushed::Held)
    );
    assert_eq!(window.bytes(), INIT.len() + 10 + FRAGMENT_OVERHEAD);
}

#[test]
fn rfc8216bis_6_2_1_nothing_is_published_before_the_first_segment_completes() {
    let mut window = window(Config::default());
    assert_eq!(push_frames(&mut window, 0, 25, 40, 25), Pushed::Published);
    assert_eq!(window.playlist(), None);
    assert_eq!(window.target_duration(), None);
    assert_eq!(window.next_part(), None);
    assert_eq!(window.reload(Blocking::None), Reload::Wait);
    // A closed part is served, but nothing is hinted: no playlist names it.
    assert_eq!(
        tags(window.get(Resource::Part { msn: 0, index: 0 })),
        [0, 1, 2, 3, 4]
    );
    assert_eq!(
        window.get(Resource::Part { msn: 0, index: 5 }),
        Lookup::NotFound
    );
    assert_eq!(push_frames(&mut window, 25, 1, 40, 25), Pushed::Published);
    assert!(window.playlist().is_some());
    assert_eq!(window.target_duration(), Some(Duration::from_secs(1)));
    assert_eq!(window.next_part(), Some((1, 0)));
    assert_eq!(window.reload(Blocking::None), Reload::Ready);
}

#[test]
fn rfc8216bis_4_4_4_9_a_part_closes_once_one_more_fragment_as_long_would_pass_the_limit() {
    // The limit before publication: the target plus the jitter, 200 ms.
    let mut window = window(Config {
        part_target: Duration::from_millis(199),
        ..Config::default()
    });
    // 4 × 40 = 160 ms: one more makes 200, the limit, not past it.
    assert_eq!(push_frames(&mut window, 0, 4, 40, 25), Pushed::Held);
    // 5 × 40 = 200 ms: one more would pass it. Closed at once.
    assert_eq!(push_frames(&mut window, 4, 1, 40, 25), Pushed::Published);
    assert_eq!(
        tags(window.get(Resource::Part { msn: 0, index: 0 })),
        [0, 1, 2, 3, 4]
    );
}

#[test]
fn rfc8216bis_4_4_4_9_a_part_closes_before_a_fragment_that_would_take_it_past_the_limit() {
    // Limit 201 ms.
    let mut window = window(Config::default());
    push_frames(&mut window, 0, 4, 40, 25);
    // 160 + 41 = 201: within it.
    assert_eq!(
        window.push(fragment(4, 10, false, 41 * MS)),
        Ok(Pushed::Published)
    );
    assert_eq!(
        tags(window.get(Resource::Part { msn: 0, index: 0 })),
        [0, 1, 2, 3, 4]
    );
    push_frames(&mut window, 5, 4, 40, 25);
    // 160 + 42 = 202: past it, so the part closes before the fragment, and
    // the fragment holds, as one more like it fits.
    assert_eq!(
        window.push(fragment(9, 10, false, 42 * MS)),
        Ok(Pushed::Published)
    );
    assert_eq!(
        tags(window.get(Resource::Part { msn: 0, index: 1 })),
        [5, 6, 7, 8]
    );
    assert_eq!(
        window.get(Resource::Part { msn: 0, index: 2 }),
        Lookup::NotFound
    );
    assert_eq!(push_frames(&mut window, 10, 1, 40, 25), Pushed::Held);
}

#[test]
fn a_fragment_of_audio_alone_joins_the_open_part_and_closes_none() {
    let mut window = window(Config::default());
    push_frames(&mut window, 0, 5, 40, 25);
    // The open part is empty: audio alone lasts nothing and holds.
    assert_eq!(window.push(fragment(50, 10, false, 0)), Ok(Pushed::Held));
    assert_eq!(window.push(fragment(51, 10, false, 0)), Ok(Pushed::Held));
    // A frame longer than the limit closes no part of audio alone before
    // it, but closes with it.
    assert_eq!(
        window.push(fragment(52, 10, false, 300 * MS)),
        Ok(Pushed::Published)
    );
    assert_eq!(
        tags(window.get(Resource::Part { msn: 0, index: 1 })),
        [50, 51, 52]
    );
}

#[test]
fn rfc8216bis_4_4_2_1_a_segment_starts_at_the_first_independent_fragment_once_it_lasts_the_target()
{
    let mut window = window(Config::default());
    // A keyframe at 960 ms stays in the segment, and so does a frame at
    // 1000 ms that is not one.
    push_frames(&mut window, 0, 24, 40, 100);
    window.push(fragment(24, 10, true, 40 * MS)).unwrap();
    assert_eq!(push_frames(&mut window, 25, 1, 40, 100), Pushed::Held);
    assert_eq!(window.playlist(), None);
    // 1040 ms: the next keyframe starts segment 1, and the open part closes
    // as segment 0's last.
    assert_eq!(
        window.push(fragment(26, 10, true, 40 * MS)),
        Ok(Pushed::Published)
    );
    assert_eq!(
        tags(window.get(Resource::Segment { msn: 0 })),
        (0..26).collect::<Vec<u8>>()
    );
    assert_eq!(tags(window.get(Resource::Part { msn: 0, index: 5 })), [25]);
    assert_eq!(window.get(Resource::Segment { msn: 1 }), Lookup::NotFound);
}

#[test]
fn rfc8216bis_4_4_2_1_a_keyframe_exactly_at_the_target_starts_a_segment() {
    let window = five_part_segments(Config::default(), 6);
    assert_eq!(
        tags(window.get(Resource::Segment { msn: 0 })),
        [0, 1, 2, 3, 4]
    );
}

/// 30 frames a second of 3000 ticks at 90 kHz each convert to 33 333 333 ns,
/// so a second of them sums to 10 ns short of it: the keyframe a second in
/// still starts the next segment, as it would one exactly at the target.
#[test]
fn rfc8216bis_4_4_2_1_a_keyframe_a_rounding_short_of_the_target_starts_a_segment() {
    let mut window = window(Config::default());
    for n in 0_u8..30 {
        window.push(fragment(n, 10, n == 0, 33_333_333)).unwrap();
    }
    assert_eq!(
        window.push(fragment(30, 10, true, 33_333_333)),
        Ok(Pushed::Published)
    );
    assert_eq!(
        tags(window.get(Resource::Segment { msn: 0 })),
        (0..30).collect::<Vec<u8>>()
    );
    // JITTER short of the target is at it; a nanosecond more short is not.
    for (nanos, pushed) in [(999 * MS, Pushed::Published), (999 * MS - 1, Pushed::Held)] {
        let mut short = Window::new(Config::default(), Bytes::from_static(INIT)).unwrap();
        short.push(fragment(0, 10, true, nanos)).unwrap();
        assert_eq!(short.push(fragment(1, 10, true, MS)), Ok(pushed), "{nanos}");
    }
}

#[test]
fn a_zero_segment_target_starts_a_segment_at_every_independent_fragment() {
    let mut window = window(Config {
        segment_target: Duration::ZERO,
        ..Config::default()
    });
    push_frames(&mut window, 0, 3, 40, 1);
    // Each part of one 40 ms frame: the measured Part Target Duration is 41 ms.
    assert_eq!(window.next_part(), Some((2, 1)));
    assert_eq!(tags(window.get(Resource::Segment { msn: 1 })), [1]);
}

#[test]
fn rfc8216bis_4_4_4_9_a_part_holding_an_independent_fragment_is_independent() {
    let mut window = window(Config::default());
    // A keyframe at frame 7, in part 1, before the segment target.
    for n in 0..30 {
        window
            .push(fragment(n, 10, n == 0 || n == 7 || n == 25, 40 * MS))
            .unwrap();
    }
    let playlist = window.playlist().unwrap();
    for line in [
        "#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part0.0.m4s\"\n",
        "#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part0.1.m4s\"\n",
        "#EXT-X-PART:DURATION=0.200000,URI=\"part0.2.m4s\"\n",
        "#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part1.0.m4s\"\n",
    ] {
        assert!(playlist.contains(line), "{line}");
    }
}

#[test]
fn rfc8216bis_4_golden_playlist() {
    let window = five_part_segments(Config::default(), 22);
    let expected = "\
#EXTM3U
#EXT-X-VERSION:6
#EXT-X-TARGETDURATION:1
#EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES,PART-HOLD-BACK=0.603000
#EXT-X-PART-INF:PART-TARGET=0.201000
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-INDEPENDENT-SEGMENTS
#EXT-X-MAP:URI=\"init.mp4\"
#EXTINF:1.000000,
seg0.m4s
#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part1.0.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part1.1.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part1.2.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part1.3.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part1.4.m4s\"
#EXTINF:1.000000,
seg1.m4s
#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part2.0.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part2.1.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part2.2.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part2.3.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part2.4.m4s\"
#EXTINF:1.000000,
seg2.m4s
#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part3.0.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part3.1.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part3.2.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part3.3.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part3.4.m4s\"
#EXTINF:1.000000,
seg3.m4s
#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part4.0.m4s\"
#EXT-X-PART:DURATION=0.200000,URI=\"part4.1.m4s\"
#EXT-X-PRELOAD-HINT:TYPE=PART,URI=\"part4.2.m4s\"
";
    assert_eq!(window.playlist().unwrap(), expected);
}

#[test]
fn rfc8216bis_6_2_2_a_segment_s_part_tags_go_together_once_its_end_is_more_than_three_target_durations_from_the_end()
 {
    // 4.4 s of media, a Target Duration of 1: segment 0 ends at 1 s, more
    // than 3 s from the end, and lists no part tag; segment 1 ends at 2 s
    // and lists all of its, part 1.0 too, which ends at 1.2 s.
    let playlist = five_part_segments(Config::default(), 22)
        .playlist()
        .unwrap();
    assert!(!playlist.contains("part0."));
    for index in 0..5 {
        assert!(playlist.contains(&format!("part1.{index}.m4s")), "{index}");
    }
    // 5 s: segment 1 ends exactly 3 s from the end and keeps its tags.
    let playlist = five_part_segments(Config::default(), 25)
        .playlist()
        .unwrap();
    assert!(playlist.contains("URI=\"part1.0.m4s\""));
    assert!(playlist.contains("URI=\"part1.4.m4s\""));
    // One part more: 5.2 s, and all go together.
    let playlist = five_part_segments(Config::default(), 26)
        .playlist()
        .unwrap();
    assert!(!playlist.contains("part1."));
    assert!(playlist.contains("#EXTINF:1.000000,\nseg1.m4s\n"));
    assert!(playlist.contains("URI=\"part2.0.m4s\""));
}

/// Part Indexes are positions: a client counts the `EXT-X-PART` tags after
/// the previous segment's URI from 0 (§3.2: "the position of the Partial
/// Segment within its Parent Segment"; hls.js 1.7.4 `m3u8-parser.ts`, read
/// 2026-11-15, numbers them so and places the first at its parent's start),
/// so no playlist lists a parent's later parts without its first.
#[test]
fn rfc8216bis_3_2_every_listed_parent_s_part_tags_start_at_part_index_0() {
    let patterns: [fn(usize) -> bool; 3] = [|n| n.is_multiple_of(5), first_1400_ms, first_2_s];
    for independent in patterns {
        let mut window = window(Config::default());
        for n in 0..90 {
            push_200_ms(&mut window, n, n + 1, independent);
            if let Some(playlist) = window.playlist() {
                assert_part_tags_start_at_0(&playlist);
            }
        }
    }
}

/// A first segment of 1.4 s and segments of 1 s after, 6 listed: segment 0
/// appeared at 1.6 s (completed by the 200 ms fragment that starts segment
/// 1), and the longest playlist listing it, segments 0 to 5, lasts 6.4 s, so
/// it is served until 1.6 + 1.4 + 6.4 = 9.4 s; its part tags left at 4.6 s,
/// and 3 Target Durations after is earlier. It was delisted at 7.6 s, and a
/// window that served one delisted segment dropped it at 8.6 s.
#[test]
fn rfc8216bis_6_2_2_a_delisted_segment_is_served_its_availability_duration_past_its_first_appearance()
 {
    let mut window = window(Config::default());
    push_200_ms(&mut window, 0, 38, first_1400_ms);
    assert!(
        window
            .playlist()
            .unwrap()
            .contains("#EXT-X-MEDIA-SEQUENCE:1\n")
    );
    push_200_ms(&mut window, 38, 43, first_1400_ms);
    assert!(serves(&window, 0), "8.6 s");
    push_200_ms(&mut window, 43, 46, first_1400_ms);
    assert!(serves(&window, 0), "9.2 s");
    assert_eq!(window.bytes(), 46 * EACH + INIT.len());
    push_200_ms(&mut window, 46, 47, first_1400_ms);
    assert!(!serves(&window, 0), "9.4 s");
    assert_eq!(window.bytes(), (47 - 7) * EACH + INIT.len());
    // Segment 1 appeared at 2.6 s and was listed in the 6.4 s playlist too,
    // not only in the 6 s ones of segments of 1 s: served until 10 s.
    assert!(serves(&window, 1));
    push_200_ms(&mut window, 47, 49, first_1400_ms);
    assert!(serves(&window, 1), "9.8 s");
    push_200_ms(&mut window, 49, 50, first_1400_ms);
    assert!(!serves(&window, 1), "10 s");
}

/// A first segment of 2 s and segments of 1 s after (the Target Duration is
/// 2), 6 listed: segment 0's part tags left with it at 8.2 s, so its parts,
/// and so it, are served until 3 Target Durations later, 14.2 s, past its
/// Availability Duration (2.2 + 2 + 7 = 11.2 s). A window that served one
/// delisted segment dropped it at 9.2 s.
#[test]
fn rfc8216bis_6_2_2_a_part_is_served_three_target_durations_past_its_tag() {
    let mut window = window(Config::default());
    push_200_ms(&mut window, 0, 40, first_2_s);
    assert!(window.playlist().unwrap().contains("part0.0.m4s"));
    push_200_ms(&mut window, 40, 41, first_2_s);
    let playlist = window.playlist().unwrap();
    assert!(!playlist.contains("seg0.m4s"));
    assert!(!playlist.contains("part0."));
    push_200_ms(&mut window, 41, 46, first_2_s);
    assert!(serves(&window, 0), "9.2 s");
    push_200_ms(&mut window, 46, 70, first_2_s);
    assert!(serves(&window, 0), "14 s");
    push_200_ms(&mut window, 70, 71, first_2_s);
    assert!(!serves(&window, 0), "14.2 s");
}

/// As above, 8 listed: segment 2 ends at 4 s, so its part tags leave once
/// the playlist's end passes 4 + 6 = 10 s, at 10.2 s, while it is still
/// listed; it is served until 10.2 + 6 = 16.2 s, not 6 s past its
/// delisting at 12.2 s, and past its Availability Duration (4.2 + 1 + 9 =
/// 14.2 s).
#[test]
fn rfc8216bis_6_2_2_a_part_is_served_three_target_durations_past_the_time_its_tag_left() {
    let mut window = window(Config {
        segments: 8,
        ..Config::default()
    });
    push_200_ms(&mut window, 0, 50, first_2_s);
    assert!(window.playlist().unwrap().contains("part2.0.m4s"));
    push_200_ms(&mut window, 50, 51, first_2_s);
    let playlist = window.playlist().unwrap();
    assert!(playlist.contains("#EXTINF:1.000000,\nseg2.m4s\n"));
    assert!(!playlist.contains("part2."));
    push_200_ms(&mut window, 51, 61, first_2_s);
    assert!(!window.playlist().unwrap().contains("seg2.m4s"), "12.2 s");
    push_200_ms(&mut window, 61, 80, first_2_s);
    assert!(serves(&window, 2), "16 s");
    push_200_ms(&mut window, 80, 81, first_2_s);
    assert!(!serves(&window, 2), "16.2 s");
}

#[test]
fn rfc8216bis_6_2_2_the_media_sequence_advances_as_segments_are_delisted() {
    let config = Config {
        segments: 2,
        ..Config::default()
    };
    let mut window = five_part_segments(config, 22);
    let playlist = window.playlist().unwrap();
    assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:2\n"));
    assert!(!playlist.contains("seg1.m4s"));
    assert!(playlist.contains("#EXTINF:1.000000,\nseg2.m4s\n"));
    // The delisted segments are still served, with their parts: their part
    // tags left with them, at 3.2 and 4.2 s, and are served 3 Target
    // Durations more.
    assert_eq!(
        tags(window.get(Resource::Segment { msn: 1 })),
        [5, 6, 7, 8, 9]
    );
    assert_eq!(tags(window.get(Resource::Part { msn: 1, index: 4 })), [9]);
    assert!(serves(&window, 0));
    // Segments 0 to 3 of 5 fragments and the open one of 2, EACH each.
    assert_eq!(window.bytes(), 22 * EACH + INIT.len());
    // 6.2 s: segment 0 is retired.
    push_frames(&mut window, 22, 8, 200, 5);
    assert!(serves(&window, 0));
    push_frames(&mut window, 30, 1, 200, 5);
    assert!(!serves(&window, 0));
    assert!(serves(&window, 1));
    assert_eq!(window.bytes(), (31 - 5) * EACH + INIT.len());
}

#[test]
fn every_resource_is_looked_up_by_its_name() {
    let window = five_part_segments(Config::default(), 22);
    assert_eq!(
        window.get(Resource::Init),
        Lookup::Ready(Chunks::from(Bytes::from_static(INIT)))
    );
    let segment = chunks_of(window.get(Resource::Segment { msn: 3 }));
    assert_eq!(segment.len(), 5);
    assert_eq!(segment[0], Bytes::from(vec![15; 72]));
    assert_eq!(
        tags(window.get(Resource::Segment { msn: 3 })),
        [15, 16, 17, 18, 19]
    );
    assert_eq!(tags(window.get(Resource::Part { msn: 3, index: 2 })), [17]);
    assert_eq!(tags(window.get(Resource::Part { msn: 4, index: 1 })), [21]);
    for gone in [
        Resource::Segment { msn: 4 },
        Resource::Segment { msn: 5 },
        Resource::Segment { msn: u64::MAX },
        Resource::Part { msn: 3, index: 5 },
        Resource::Part { msn: 4, index: 3 },
        Resource::Part {
            msn: 4,
            index: u64::MAX,
        },
        Resource::Part { msn: 5, index: 0 },
    ] {
        assert_eq!(window.get(gone), Lookup::NotFound, "{gone:?}");
    }
}

#[test]
fn rfc8216bis_4_4_5_3_the_hinted_part_waits_until_it_is_published_or_never_will_be() {
    let mut window = window(Config::default());
    push_frames(&mut window, 0, 26, 40, 25);
    assert_eq!(window.next_part(), Some((1, 0)));
    assert_eq!(
        window.get(Resource::Part { msn: 1, index: 0 }),
        Lookup::Wait
    );
    push_frames(&mut window, 26, 4, 40, 25);
    assert_eq!(
        tags(window.get(Resource::Part { msn: 1, index: 0 })),
        [25, 26, 27, 28, 29]
    );
    push_frames(&mut window, 30, 20, 40, 25);
    assert_eq!(window.next_part(), Some((1, 5)));
    assert_eq!(
        window.get(Resource::Part { msn: 1, index: 5 }),
        Lookup::Wait
    );
    // §6.2.6: the keyframe ends the segment instead; the hinted part is never
    // published, and part 0 of the next one is hinted.
    push_frames(&mut window, 50, 1, 40, 25);
    assert_eq!(
        window.get(Resource::Part { msn: 1, index: 5 }),
        Lookup::NotFound
    );
    assert_eq!(window.next_part(), Some((2, 0)));
}

#[test]
fn rfc8216bis_4_4_3_1_the_target_duration_is_the_first_segment_rounded_at_least_1() {
    let mut window = window(Config {
        segment_target: Duration::ZERO,
        ..Config::default()
    });
    window.push(fragment(0, 10, true, 400 * MS)).unwrap();
    window.push(fragment(1, 10, true, 400 * MS)).unwrap();
    assert_eq!(window.target_duration(), Some(Duration::from_secs(1)));
    assert!(
        window
            .playlist()
            .unwrap()
            .contains("#EXT-X-TARGETDURATION:1\n")
    );
}

#[test]
fn rfc8216bis_4_4_3_1_the_target_duration_rises_to_a_longer_segment_and_never_falls() {
    let mut window = window(Config {
        segment_target: Duration::ZERO,
        ..Config::default()
    });
    window.push(fragment(0, 10, true, 1_499 * MS)).unwrap();
    window.push(fragment(1, 10, true, 1_500 * MS)).unwrap();
    // 1.499 s rounds to 1.
    assert_eq!(window.target_duration(), Some(Duration::from_secs(1)));
    window.push(fragment(2, 10, true, 400 * MS)).unwrap();
    // SPEC-DEVIATION (§6.2.1): 1.5 s rounds to 2, and the target rises.
    assert_eq!(window.target_duration(), Some(Duration::from_secs(2)));
    window.push(fragment(3, 10, true, 400 * MS)).unwrap();
    assert_eq!(window.target_duration(), Some(Duration::from_secs(2)));
    let playlist = window.playlist().unwrap();
    assert!(playlist.contains("#EXT-X-TARGETDURATION:2\n"));
    assert!(playlist.contains("#EXTINF:1.499000,\nseg0.m4s\n"));
    assert!(playlist.contains("#EXTINF:1.500000,\nseg1.m4s\n"));
}

#[test]
fn rfc8216bis_4_4_3_1_durations_round_to_the_nearest_second_half_up() {
    assert_eq!(rounded_seconds(Duration::ZERO), 0);
    assert_eq!(rounded_seconds(Duration::from_nanos(499_999_999)), 0);
    assert_eq!(rounded_seconds(Duration::from_millis(500)), 1);
    assert_eq!(rounded_seconds(Duration::from_nanos(1_499_999_999)), 1);
    assert_eq!(rounded_seconds(Duration::from_millis(1_500)), 2);
    assert_eq!(rounded_seconds(Duration::MAX), u64::MAX);
}

#[test]
fn the_part_target_is_the_longest_part_and_the_jitter_rounded_up_to_the_millisecond() {
    assert_eq!(
        part_target(Duration::from_millis(200)),
        Duration::from_millis(201)
    );
    assert_eq!(
        part_target(Duration::from_nanos(200_000_001)),
        Duration::from_millis(202)
    );
    assert_eq!(
        part_target(Duration::from_nanos(199_999_999)),
        Duration::from_millis(201)
    );
    assert_eq!(part_target(Duration::ZERO), Duration::from_millis(1));
    assert!(part_target(Duration::MAX) >= Duration::from_secs(u64::MAX / 1000));
}

#[test]
fn rfc8216bis_4_4_4_9_parts_of_29_97_frames_a_second_fit_a_measured_part_target() {
    // 3003 ticks of 90 kHz: 33 366 667 ns. Six fit 200 ms and the jitter.
    let frame = 33_366_667;
    let mut window = window(Config::default());
    for n in 0..31 {
        window.push(fragment(n, 10, n % 30 == 0, frame)).unwrap();
    }
    let playlist = window.playlist().unwrap();
    assert!(playlist.contains("#EXT-X-PART-INF:PART-TARGET=0.202000\n"));
    assert!(playlist.contains("PART-HOLD-BACK=0.606000\n"));
    assert!(playlist.contains("#EXT-X-PART:DURATION=0.200200,URI=\"part0.4.m4s\"\n"));
    assert!(playlist.contains("#EXTINF:1.001000,\nseg0.m4s\n"));
    // §4.4.4.9: each part within the target and at least 85 % of it.
    for index in 0..5 {
        let part = window.part(0, index).unwrap();
        assert!(part.duration <= Duration::from_millis(202));
        assert!(part.duration * 100 >= Duration::from_millis(202) * 85);
    }
}

#[test]
fn rfc8216bis_4_4_4_9_the_part_target_rises_to_a_part_of_one_longer_fragment() {
    let mut window = five_part_segments(Config::default(), 6);
    // A fragment of exactly the Part Target Duration keeps it.
    window.push(fragment(6, 10, false, 201 * MS)).unwrap();
    assert!(
        window
            .playlist()
            .unwrap()
            .contains("PART-TARGET=0.201000\n")
    );
    // SPEC-DEVIATION (§6.2.1): a longer one raises it.
    window.push(fragment(7, 10, false, 500 * MS)).unwrap();
    let playlist = window.playlist().unwrap();
    assert!(playlist.contains("PART-TARGET=0.501000\n"));
    assert!(playlist.contains("PART-HOLD-BACK=1.503000\n"));
    // Parts close at the raised target: two fragments of 200 ms now.
    assert_eq!(push_frames(&mut window, 8, 1, 200, 100), Pushed::Held);
    assert_eq!(push_frames(&mut window, 9, 1, 200, 100), Pushed::Published);
    assert!(
        window
            .playlist()
            .unwrap()
            .contains("PART-TARGET=0.501000\n")
    );
}

#[test]
fn the_byte_cap_drops_the_delisted_segment_first_and_holds_up_to_the_cap() {
    // EACH a fragment, 5 × EACH a segment; one segment listed.
    let mut window = window(Config {
        segments: 1,
        max_bytes: 12 * EACH,
        ..Config::default()
    });
    push_frames(&mut window, 0, 11, 200, 5);
    assert_eq!(window.bytes(), 11 * EACH + INIT.len());
    // 12 fragments: at the cap, nothing drops.
    push_frames(&mut window, 11, 1, 200, 5);
    assert_eq!(window.bytes(), 12 * EACH + INIT.len());
    assert!(matches!(
        window.get(Resource::Segment { msn: 0 }),
        Lookup::Ready(_)
    ));
    // 13: the delisted segment drops first.
    push_frames(&mut window, 12, 1, 200, 5);
    assert_eq!(window.bytes(), 8 * EACH + INIT.len());
    assert_eq!(window.get(Resource::Segment { msn: 0 }), Lookup::NotFound);
    assert!(matches!(
        window.get(Resource::Segment { msn: 1 }),
        Lookup::Ready(_)
    ));
}

#[test]
fn the_byte_cap_drops_listed_segments_down_to_the_open_one() {
    let mut window = window(Config {
        max_bytes: 5 * EACH,
        ..Config::default()
    });
    // Segment 0 holds the cap exactly; the keyframe that starts segment 1
    // joins no segment, and segment 0 drops for it.
    push_frames(&mut window, 0, 5, 200, 5);
    assert_eq!(push_frames(&mut window, 5, 1, 200, 5), Pushed::Published);
    assert_eq!(window.bytes(), EACH + INIT.len());
    assert_eq!(window.get(Resource::Segment { msn: 0 }), Lookup::NotFound);
    let playlist = window.playlist().unwrap();
    assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:1\n"));
    assert!(!playlist.contains("#EXTINF"));
    assert!(playlist.ends_with(
        "#EXT-X-PART:DURATION=0.200000,INDEPENDENT=YES,URI=\"part1.0.m4s\"\n\
         #EXT-X-PRELOAD-HINT:TYPE=PART,URI=\"part1.1.m4s\"\n"
    ));
    assert_eq!(window.reload(Blocking::Segment { msn: 0 }), Reload::Ready);
}

#[test]
fn an_open_segment_past_the_byte_cap_ends_the_window() {
    let mut window = window(Config {
        max_bytes: 5 * EACH,
        ..Config::default()
    });
    push_frames(&mut window, 0, 5, 200, 100);
    let overflow = Err(PushError::Overflow {
        max_bytes: 5 * EACH,
    });
    assert_eq!(window.push(fragment(5, 72, false, 200 * MS)), overflow);
    // It takes nothing more, a keyframe neither, and serves what it holds.
    assert_eq!(window.push(fragment(6, 72, true, 200 * MS)), overflow);
    assert_eq!(window.bytes(), 5 * EACH + INIT.len());
    assert_eq!(tags(window.get(Resource::Part { msn: 0, index: 4 })), [4]);
}

#[test]
fn a_first_fragment_past_the_byte_cap_ends_the_window() {
    let mut window = window(Config {
        max_bytes: 1_000,
        ..Config::default()
    });
    assert_eq!(
        window.push(fragment(0, 1_000, true, 200 * MS)),
        Err(PushError::Overflow { max_bytes: 1_000 })
    );
    assert_eq!(window.bytes(), INIT.len());
}

/// The most the window allocates for a fragment that is its own part and
/// its own segment, on the target the test runs on, as
/// [`FRAGMENT_OVERHEAD`]'s docs count it: 4 handles and 4 parts (a `Vec`'s
/// first capacity), a segment and a delisted one twice over (a
/// `VecDeque`'s doubling), the 3 words of a `Bytes`' shared header, and an
/// allocator's header on its buffer, that header and the two vectors.
fn worst_case_fragment_footprint() -> usize {
    /// An allocator's header, rounded up: glibc's and musl's are at most 16
    /// bytes on the 64-bit targets.
    const ALLOCATION_HEADER: usize = 16;
    4 * size_of::<Bytes>()
        + 4 * size_of::<Part>()
        + 2 * size_of::<Segment>()
        + 2 * size_of::<Delisted>()
        + 3 * size_of::<usize>()
        + 4 * ALLOCATION_HEADER
}

#[test]
fn the_fragment_overhead_covers_a_one_fragment_segment_s_allocations() {
    assert!(
        worst_case_fragment_footprint() <= FRAGMENT_OVERHEAD,
        "{} bytes",
        worst_case_fragment_footprint()
    );
}

/// Fragments of no byte, each its own segment: each costs the overhead, at
/// least its footprint, so a cap of 10 overheads holds 10 of them (the open
/// segment and 9 listed) and drops the oldest for the 11th; a cap below one
/// overhead takes none.
#[test]
fn fragments_of_no_byte_are_charged_their_worst_case_footprint() {
    let config = Config {
        segment_target: Duration::ZERO,
        segments: 100,
        max_bytes: 10 * FRAGMENT_OVERHEAD,
        ..Config::default()
    };
    let mut window = window(config);
    for n in 1..=10 {
        window.push(fragment(0, 0, true, 40 * MS)).unwrap();
        assert_eq!(window.bytes(), n * FRAGMENT_OVERHEAD + INIT.len());
        assert!(window.bytes() >= n * worst_case_fragment_footprint() + INIT.len());
    }
    assert!(matches!(
        window.get(Resource::Segment { msn: 0 }),
        Lookup::Ready(_)
    ));
    window.push(fragment(0, 0, true, 40 * MS)).unwrap();
    assert_eq!(window.bytes(), 10 * FRAGMENT_OVERHEAD + INIT.len());
    assert_eq!(window.listed.len(), 9);
    assert_eq!(window.get(Resource::Segment { msn: 0 }), Lookup::NotFound);
    assert!(matches!(
        window.get(Resource::Segment { msn: 1 }),
        Lookup::Ready(_)
    ));

    let mut window = self::window(Config {
        max_bytes: FRAGMENT_OVERHEAD - 1,
        ..config
    });
    assert_eq!(
        window.push(fragment(0, 0, true, 40 * MS)),
        Err(PushError::Overflow {
            max_bytes: FRAGMENT_OVERHEAD - 1
        })
    );
    assert_eq!(window.bytes(), INIT.len());
}

#[test]
fn chunks_hold_their_slices_and_their_length() {
    let mut chunks = Chunks::default();
    assert!(chunks.is_empty());
    assert_eq!(chunks.len(), 0);
    chunks.push(Bytes::from_static(b"moof"));
    chunks.push(Bytes::from_static(b"mdat!"));
    assert!(!chunks.is_empty());
    assert_eq!(chunks.len(), 9);
    assert_eq!(chunks.as_slice().len(), 2);
    assert_eq!(
        chunks.into_vec(),
        [Bytes::from_static(b"moof"), Bytes::from_static(b"mdat!")]
    );
    assert_eq!(Chunks::from(Bytes::from_static(b"x")).len(), 1);
}

#[test]
fn rfc8216bis_6_2_5_2_a_reload_waits_for_the_segment_it_asks_for() {
    // Segments 0 to 3 complete, segment 4 open with 2 parts.
    let window = five_part_segments(Config::default(), 22);
    assert_eq!(window.reload(Blocking::None), Reload::Ready);
    assert_eq!(window.reload(Blocking::Segment { msn: 0 }), Reload::Ready);
    assert_eq!(window.reload(Blocking::Segment { msn: 3 }), Reload::Ready);
    assert_eq!(window.reload(Blocking::Segment { msn: 4 }), Reload::Wait);
    assert_eq!(window.reload(Blocking::Segment { msn: 5 }), Reload::Wait);
}

#[test]
fn rfc8216bis_6_2_5_2_a_msn_past_the_last_segment_plus_two_is_a_bad_request() {
    let window = five_part_segments(Config::default(), 22);
    assert_eq!(
        window.reload(Blocking::Segment { msn: 6 }),
        Reload::BadRequest
    );
    assert_eq!(
        window.reload(Blocking::Segment { msn: u64::MAX }),
        Reload::BadRequest
    );
    assert_eq!(
        window.reload(Blocking::Part { msn: 6, part: 0 }),
        Reload::BadRequest
    );
    // Before any segment completes, the last is the one before segment 0.
    let empty = self::window(Config::default());
    assert_eq!(empty.reload(Blocking::Segment { msn: 1 }), Reload::Wait);
    assert_eq!(
        empty.reload(Blocking::Segment { msn: 2 }),
        Reload::BadRequest
    );
}

#[test]
fn rfc8216bis_6_2_5_2_a_reload_waits_for_the_part_it_asks_for() {
    let window = five_part_segments(Config::default(), 22);
    let reload = |msn, part| window.reload(Blocking::Part { msn, part });
    assert_eq!(reload(0, 0), Reload::Ready);
    assert_eq!(reload(2, u64::MAX), Reload::Ready, "an older segment");
    assert_eq!(reload(3, 4), Reload::Ready);
    // Past the last part of segment 3: part 0 of segment 4, which is in.
    assert_eq!(reload(3, 5), Reload::Ready);
    assert_eq!(reload(4, 1), Reload::Ready);
    assert_eq!(reload(4, 2), Reload::Wait);
    assert_eq!(reload(5, 0), Reload::Wait);
}

#[test]
fn rfc8216bis_6_2_5_2_a_part_index_past_a_segment_s_last_asks_for_part_0_of_the_next() {
    let mut window = window(Config::default());
    // Segment 0 has 5 parts; segment 1 has none closed yet.
    push_frames(&mut window, 0, 26, 40, 25);
    assert_eq!(
        window.reload(Blocking::Part { msn: 0, part: 4 }),
        Reload::Ready
    );
    assert_eq!(
        window.reload(Blocking::Part { msn: 0, part: 5 }),
        Reload::Wait
    );
    push_frames(&mut window, 26, 4, 40, 25);
    assert_eq!(
        window.reload(Blocking::Part { msn: 0, part: 5 }),
        Reload::Ready
    );
}

#[test]
fn rfc8216bis_6_2_5_2_nothing_is_ready_before_the_playlist_is_published() {
    let mut window = window(Config::default());
    push_frames(&mut window, 0, 5, 40, 25);
    assert_eq!(
        window.reload(Blocking::Part { msn: 0, part: 0 }),
        Reload::Wait
    );
    assert_eq!(window.reload(Blocking::Segment { msn: 0 }), Reload::Wait);
}

#[test]
fn rfc8216bis_6_2_5_2_the_advance_part_limit_below_a_second_is_three_seconds_of_parts() {
    // A Part Target Duration of 201 ms: 14 parts are 2.814 s, 15 are 3.015 s.
    let window = five_part_segments(Config::default(), 22);
    let reload = |msn, part| window.reload(Blocking::Part { msn, part });
    // Segment 4 has parts 0 and 1: part 15 is 14 ahead, part 16 is 15.
    assert_eq!(reload(4, 15), Reload::Wait);
    assert_eq!(reload(4, 16), Reload::BadRequest);
    assert_eq!(reload(4, u64::MAX), Reload::BadRequest);
    // Part 13 of segment 5 is at least 14 ahead.
    assert_eq!(reload(5, 13), Reload::Wait);
    assert_eq!(reload(5, 14), Reload::BadRequest);
    assert_eq!(reload(5, u64::MAX), Reload::BadRequest);
}

#[test]
fn rfc8216bis_6_2_5_2_the_advance_part_limit_is_exact_at_three_seconds() {
    // Parts of one fragment of 199 ms: a Part Target Duration of 200 ms, and
    // 15 parts are 3 s, not past it.
    let mut window = window(Config {
        segment_target: Duration::ZERO,
        ..Config::default()
    });
    push_frames(&mut window, 0, 2, 199, 1);
    assert!(
        window
            .playlist()
            .unwrap()
            .contains("PART-TARGET=0.200000\n")
    );
    // Segment 1 has part 0.
    let reload = |msn, part| window.reload(Blocking::Part { msn, part });
    assert_eq!(reload(1, 15), Reload::Wait);
    assert_eq!(reload(1, 16), Reload::BadRequest);
}

#[test]
fn rfc8216bis_6_2_5_2_the_advance_part_limit_from_a_second_on_is_three_parts() {
    for (frame_ms, target) in [(999, "1.000000"), (1_499, "1.500000")] {
        let mut window = window(Config {
            segment_target: Duration::ZERO,
            ..Config::default()
        });
        push_frames(&mut window, 0, 2, frame_ms, 1);
        let playlist = window.playlist().unwrap();
        assert!(playlist.contains(&format!("PART-TARGET={target}\n")));
        let reload = |msn, part| window.reload(Blocking::Part { msn, part });
        assert_eq!(reload(1, 3), Reload::Wait, "{target}");
        assert_eq!(reload(1, 4), Reload::BadRequest, "{target}");
    }
}

#[test]
fn rfc8216bis_6_2_5_2_before_publication_the_advance_part_limit_counts_the_configured_target() {
    // 200 ms configured: 15 parts are 3 s.
    let window = window(Config::default());
    let reload = |part| window.reload(Blocking::Part { msn: 0, part });
    assert_eq!(reload(14), Reload::Wait);
    assert_eq!(reload(15), Reload::BadRequest);
}

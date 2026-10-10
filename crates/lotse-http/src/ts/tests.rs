#![allow(
    clippy::arithmetic_side_effects,
    clippy::missing_docs_in_private_items,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test code"
)]

use lotse_codec::aac::test_data::{CONFIG_16K_MONO, CONFIG_48K_MONO, SINE_16K_MONO, SINE_48K_MONO};
use lotse_codec::aac::{AdtsSplitter, parse_config};
use lotse_codec::{h264, h265};

use super::align::PACKET;
use super::test_data::{
    AUDIO_PID, H264_AAC, H264_AAC16K, H264_BFRAMES_WRAP, H265_V1, PROGRAMS, VIDEO_PID,
};
use super::*;

const MAX: usize = 4 << 20;

/// The events of `input` pushed whole and flushed, and the demuxer.
fn demux(input: &[u8], max_frame_bytes: usize) -> (Vec<Event>, Demuxer) {
    let mut demuxer = Demuxer::new(max_frame_bytes);
    let mut events = Vec::new();
    demuxer.push(input, &mut events);
    demuxer.flush(&mut events);
    (events, demuxer)
}

fn layouts(events: &[Event]) -> Vec<&Layout> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Layout(layout) => Some(layout),
            Event::Unit(_) => None,
        })
        .collect()
}

fn units(events: &[Event], track: usize) -> Vec<&Unit> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Unit(unit) if unit.track == track => Some(unit),
            _ => None,
        })
        .collect()
}

fn pid(packet: &[u8]) -> u16 {
    u16::from(packet[1] & 0x1f) << 8 | u16::from(packet[2])
}

fn pusi(packet: &[u8]) -> bool {
    packet[1] & 0x40 != 0
}

/// The packets of `ts` that `keep` keeps, with their index.
fn filtered(ts: &[u8], keep: impl Fn(usize, &[u8]) -> bool) -> Vec<u8> {
    ts.chunks(PACKET)
        .enumerate()
        .filter(|(i, packet)| keep(*i, packet))
        .flat_map(|(_, packet)| packet.to_vec())
        .collect()
}

/// `ts` with the PES header of the `nth` PES packet on `pid` changed by
/// `patch`, which gets the bytes from its start code on.
fn patch_pes(ts: &[u8], pid_: u16, nth: usize, patch: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut out = ts.to_vec();
    let packet = out
        .chunks_mut(PACKET)
        .filter(|packet| pid(packet) == pid_ && pusi(packet))
        .nth(nth)
        .unwrap();
    let start = if packet[3] & 0x20 != 0 {
        5 + usize::from(packet[4])
    } else {
        4
    };
    assert_eq!(&packet[start..start + 3], &[0, 0, 1]);
    patch(&mut packet[start..]);
    out
}

fn h264() -> Codec {
    Codec::H264 {
        profile_level_id: None,
        sps: None,
        pps: None,
    }
}

fn aac(sample_rate: u32, config: [u8; 2]) -> Codec {
    Codec::AacLc {
        sample_rate,
        channels: 1,
        config: Bytes::copy_from_slice(&config),
    }
}

fn track(pid: u16, stream_type: u8, kind: Kind, codec: Codec, clock_rate: u32) -> LayoutTrack {
    LayoutTrack {
        pid,
        stream_type,
        kind,
        codec,
        clock_rate,
    }
}

fn unsupported_track(pid: u16, stream_type: u8, kind: Kind, name: &str) -> LayoutTrack {
    track(
        pid,
        stream_type,
        kind,
        Codec::Unsupported {
            kind,
            name: name.to_owned(),
        },
        TS_CLOCK_RATE,
    )
}

#[test]
fn iso13818_1_2_4_4_8_h264_and_adts_give_one_layout_then_their_units() {
    let (events, demuxer) = demux(H264_AAC, MAX);
    let Event::Layout(layout) = &events[0] else {
        panic!("the layout comes first");
    };
    assert_eq!(
        layout,
        &Layout {
            program_number: 1,
            tracks: vec![
                track(VIDEO_PID, 0x1b, Kind::Video, h264(), 90_000),
                track(
                    AUDIO_PID,
                    0x0f,
                    Kind::Audio,
                    aac(48_000, CONFIG_48K_MONO),
                    48_000
                ),
            ],
        }
    );
    assert_eq!(layouts(&events).len(), 1);
    let video = units(&events, 0);
    assert_eq!(video.len(), 10);
    for (i, unit) in video.iter().enumerate() {
        assert_eq!(unit.ts, 127_920 + 9_000 * i as i64);
        assert_eq!(unit.decode_time, unit.ts);
        assert_eq!(&unit.payload[..4], &[0, 0, 0, 1]);
    }
    let audio = units(&events, 1);
    assert_eq!(audio.len(), 48);
    // 1.4 s at 48 kHz, then 1024 samples a frame.
    for (i, unit) in audio.iter().enumerate() {
        assert_eq!(unit.ts, 67_200 + 1_024 * i as i64);
        assert_eq!(unit.decode_time, 126_000 + 1_920 * i as i64);
    }
    let stats = demuxer.stats();
    assert_eq!(
        stats,
        DemuxStats {
            packets: (H264_AAC.len() / PACKET) as u64,
            ..DemuxStats::default()
        }
    );
    assert_eq!(demuxer.buffered(), 0);
    assert!(format!("{demuxer:?}").starts_with("Demuxer"));
}

#[test]
fn iso13818_1_2_14_h264_units_go_through_the_framed_normalizer() {
    let (events, _) = demux(H264_AAC, MAX);
    let mut normalizer = h264::FramedNormalizer::new(1_200, MAX, h264::ParameterSets::default());
    let mut packets = Vec::new();
    let mut access_units = Vec::new();
    for unit in units(&events, 0) {
        normalizer.push(
            unit.ts as u32,
            &unit.payload,
            &mut packets,
            &mut access_units,
        );
    }
    assert_eq!(access_units.len(), 10);
    assert!(access_units[0].keyframe);
    assert!(access_units[0].sps.is_some());
    assert!(packets.iter().any(|packet| packet.keyframe_start));
}

#[test]
fn iso13818_1_2_17_h265_gives_its_layout_and_units() {
    let (events, _) = demux(H265_V1, MAX);
    assert_eq!(
        layouts(&events),
        [&Layout {
            program_number: 1,
            tracks: vec![track(
                VIDEO_PID,
                0x24,
                Kind::Video,
                Codec::H265 {
                    vps: None,
                    sps: None,
                    pps: None
                },
                90_000
            )],
        }]
    );
    let video = units(&events, 0);
    assert_eq!(video.len(), 10);
    let mut normalizer = h265::FramedNormalizer::new(1_200, MAX, h265::ParameterSets::default());
    let mut packets = Vec::new();
    let mut access_units = Vec::new();
    for unit in video {
        normalizer.push(
            unit.ts as u32,
            &unit.payload,
            &mut packets,
            &mut access_units,
        );
    }
    assert_eq!(access_units.len(), 10);
    assert!(access_units[0].keyframe);
}

#[test]
fn iso13818_1_2_4_3_7_b_frames_carry_their_dts_across_the_33_bit_wrap() {
    let (events, _) = demux(H264_BFRAMES_WRAP, MAX);
    let video = units(&events, 0);
    assert_eq!(video.len(), 10);
    // ffmpeg's first DTS, 46592 ticks before the wrap, then 9000 apart:
    // the timeline goes on past 2^33 instead of back to 0.
    let first = (1 << 33) - 46_592;
    for (i, unit) in video.iter().enumerate() {
        assert_eq!(unit.decode_time, first + 9_000 * i as i64);
    }
    assert!(video.last().unwrap().decode_time > 1 << 33);
    assert!(video.iter().any(|unit| unit.ts != unit.decode_time));
    assert!(video.iter().all(|unit| unit.ts >= unit.decode_time));
    let mut presented: Vec<i64> = video.iter().map(|unit| unit.ts).collect();
    presented.sort_unstable();
    assert!(presented.windows(2).all(|pair| pair[1] - pair[0] == 9_000));
}

#[test]
fn iso13818_1_2_4_3_7_timestamps_extend_to_the_nearest_value_modulo_2_33() {
    let wrap = 1_i64 << 33;
    let mut ctx = Ctx::new(MAX);
    assert_eq!(ctx.extend(5), 5);
    assert_eq!(ctx.extend((wrap - 10) as u64), -10);
    assert_eq!(ctx.extend(20), 20);
    assert_eq!(ctx.extend(10), 10);
    let mut ctx = Ctx::new(MAX);
    assert_eq!(ctx.extend((wrap - 5) as u64), wrap - 5);
    assert_eq!(ctx.extend(3), wrap + 3);
    // Exactly half the span ahead counts as behind; just under it, ahead.
    let mut ctx = Ctx::new(MAX);
    assert_eq!(ctx.extend(0), 0);
    assert_eq!(ctx.extend((wrap / 2) as u64), -wrap / 2);
    let mut ctx = Ctx::new(MAX);
    assert_eq!(ctx.extend(0), 0);
    assert_eq!(ctx.extend((wrap / 2 - 1) as u64), wrap / 2 - 1);
}

#[test]
fn iso13818_1_2_4_3_6_an_unbounded_pes_ends_at_the_next_one_or_at_flush() {
    let mut demuxer = Demuxer::new(MAX);
    let mut events = Vec::new();
    demuxer.push(H264_AAC, &mut events);
    // ffmpeg writes video PES packets with PES_packet_length 0: the last
    // one waits for the next, or for the end of the input.
    assert_eq!(units(&events, 0).len(), 9);
    assert!(demuxer.buffered() > 0);
    demuxer.flush(&mut events);
    assert_eq!(units(&events, 0).len(), 10);
    demuxer.flush(&mut events);
    assert_eq!(units(&events, 0).len(), 10);
}

#[test]
fn iso13818_1_2_4_3_6_a_flush_inside_a_pes_drops_its_rest() {
    // Cut inside the third video PES packet: flushed there, it goes out
    // short; its continuation is dropped.
    let third = H264_AAC
        .chunks(PACKET)
        .enumerate()
        .filter(|(_, packet)| pid(packet) == VIDEO_PID && pusi(packet))
        .nth(2)
        .unwrap()
        .0;
    let cut = (third + 1) * PACKET;
    let (whole, _) = demux(H264_AAC, MAX);
    let mut demuxer = Demuxer::new(MAX);
    let mut events = Vec::new();
    demuxer.push(&H264_AAC[..cut], &mut events);
    demuxer.flush(&mut events);
    demuxer.push(&H264_AAC[cut..], &mut events);
    demuxer.flush(&mut events);
    let video = units(&events, 0);
    assert_eq!(video.len(), 10);
    assert!(video[2].payload.len() < units(&whole, 0)[2].payload.len());
    assert_eq!(video[3], units(&whole, 0)[3]);
}

#[test]
fn iso13818_1_2_4_3_2_any_cut_of_the_bytes_gives_the_same_events() {
    let (whole, _) = demux(H264_AAC, MAX);
    for size in [1, 7, 188, 1_000, 4_096] {
        let mut demuxer = Demuxer::new(MAX);
        let mut events = Vec::new();
        for chunk in H264_AAC.chunks(size) {
            demuxer.push(chunk, &mut events);
        }
        demuxer.flush(&mut events);
        assert_eq!(events, whole, "pieces of {size}");
    }
}

#[test]
fn iso13818_1_2_4_3_2_garbage_is_skipped_and_sync_found_again() {
    let mut input = vec![0x55; 7];
    let middle = 40 * PACKET;
    input.extend_from_slice(&H264_AAC[..middle]);
    input.extend_from_slice(&[0; 100]);
    input.extend_from_slice(&H264_AAC[middle..]);
    let (events, demuxer) = demux(&input, MAX);
    let (whole, _) = demux(H264_AAC, MAX);
    assert_eq!(events, whole);
    let stats = demuxer.stats();
    assert_eq!(stats.skipped_bytes, 107);
    assert_eq!(stats.sync_losses, 1);
    assert_eq!(stats.continuity_errors, 0);
}

#[test]
fn iso13818_1_2_4_3_3_a_lost_packet_is_a_continuity_error_and_its_pes_is_dropped() {
    // The second packet of the first video PES packet, the IDR.
    let first = H264_AAC
        .chunks(PACKET)
        .position(|packet| pid(packet) == VIDEO_PID && pusi(packet))
        .unwrap();
    let lost = H264_AAC
        .chunks(PACKET)
        .enumerate()
        .skip(first + 1)
        .find(|(_, packet)| pid(packet) == VIDEO_PID)
        .unwrap()
        .0;
    let input = filtered(H264_AAC, |i, _| i != lost);
    let (events, demuxer) = demux(&input, MAX);
    let video = units(&events, 0);
    assert_eq!(video.len(), 9);
    assert_eq!(video[0].ts, 136_920);
    let stats = demuxer.stats();
    assert_eq!(stats.continuity_errors, 1);
    assert_eq!(stats.dropped_incomplete, 1);
}

#[test]
fn iso13818_1_2_4_3_6_a_pes_over_the_limit_is_dropped() {
    // The IDR is 3241 bytes: kept at that limit, dropped below it.
    let (events, demuxer) = demux(H264_AAC, 3_241);
    assert_eq!(units(&events, 0).len(), 10);
    assert_eq!(demuxer.stats().dropped_oversize, 0);
    let (events, demuxer) = demux(H264_AAC, 3_240);
    let video = units(&events, 0);
    assert_eq!(video.len(), 9);
    assert_eq!(video[0].ts, 136_920);
    assert_eq!(demuxer.stats().dropped_oversize, 1);
}

#[test]
fn iso13818_1_2_4_4_8_a_new_program_map_version_with_other_streams_is_a_new_layout() {
    let mut input = H264_AAC.to_vec();
    input.extend_from_slice(H265_V1);
    let (events, _) = demux(&input, MAX);
    let all = layouts(&events);
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].tracks.len(), 1);
    assert_eq!(all[1].tracks[0].stream_type, 0x24);
    let second = events
        .iter()
        .position(|event| matches!(event, Event::Layout(layout) if layout == all[1]))
        .unwrap();
    // Every unit of the first program comes before the new layout.
    assert_eq!(units(&events[..second], 0).len(), 10);
    assert_eq!(units(&events[..second], 1).len(), 48);
    assert_eq!(units(&events[second..], 0).len(), 10);
    assert!(units(&events[second..], 1).is_empty());
}

#[test]
fn iso13818_7_6_2_another_adts_configuration_is_a_new_layout() {
    // The same streams in a new version of the program map: the PES
    // filters start again, ending the PES packets still open, and only
    // the AAC changes.
    let mut input = H264_AAC.to_vec();
    input.extend_from_slice(H264_AAC16K);
    let (events, demuxer) = demux(&input, MAX);
    let all = layouts(&events);
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].tracks[0], all[0].tracks[0]);
    assert_eq!(
        all[1].tracks[1],
        track(
            AUDIO_PID,
            0x0f,
            Kind::Audio,
            aac(16_000, CONFIG_16K_MONO),
            16_000
        )
    );
    let second = events
        .iter()
        .position(|event| matches!(event, Event::Layout(layout) if layout == all[1]))
        .unwrap();
    let audio = units(&events[second..], 1);
    assert_eq!(audio.len(), 9);
    // The timestamps restart from the PES PTS at the new rate: 1.4 s at
    // 16 kHz.
    assert_eq!(audio[0].ts, 22_400);
    assert_eq!(audio[1].ts, 22_400 + 1_024);
    assert_eq!(audio[0].decode_time, 126_000);
    assert_eq!(units(&events, 0).len(), 15);
    let stats = demuxer.stats();
    assert_eq!(stats.audio_reanchors, 0);
    assert_eq!(stats.dropped_incomplete, 0);
    assert_eq!(stats.continuity_errors, 0);
}

#[test]
fn iso13818_1_table_2_34_other_codecs_are_declared_unsupported_and_only_the_first_program_read() {
    let (events, _) = demux(PROGRAMS, MAX);
    assert_eq!(
        layouts(&events),
        [&Layout {
            program_number: 1,
            tracks: vec![
                track(VIDEO_PID, 0x1b, Kind::Video, h264(), 90_000),
                unsupported_track(AUDIO_PID, 0x03, Kind::Audio, "mpeg1_audio"),
                unsupported_track(0x102, 0x11, Kind::Audio, "aac_latm"),
            ],
        }]
    );
    assert_eq!(units(&events, 0).len(), 5);
    assert_eq!(events.len(), 6);
}

#[test]
fn iso13818_1_table_2_34_stream_types() {
    assert_eq!(classify(0x1b), StreamClass::H264);
    assert_eq!(classify(0x24), StreamClass::H265);
    assert_eq!(classify(0x0f), StreamClass::Adts);
    for (stream_type, kind, name) in [
        (0x01, Kind::Video, "mpeg1_video"),
        (0x02, Kind::Video, "mpeg2_video"),
        (0x10, Kind::Video, "mpeg4_visual"),
        (0x42, Kind::Video, "avs"),
        (0x03, Kind::Audio, "mpeg1_audio"),
        (0x04, Kind::Audio, "mpeg2_audio"),
        (0x11, Kind::Audio, "aac_latm"),
        (0x1c, Kind::Audio, "mpeg4_audio"),
    ] {
        assert_eq!(classify(stream_type), StreamClass::Unsupported(kind, name));
    }
    for other in [0x00, 0x05, 0x06, 0x15, 0x81, 0x86, 0xff] {
        assert_eq!(classify(other), StreamClass::Other);
        assert!(Track::new(0x100, other, MAX).is_none());
    }
}

#[test]
fn iso13818_1_2_4_4_8_the_layout_waits_for_the_first_adts_header_within_a_bound() {
    // No audio packets: the video is held until the bound, then the
    // layout goes out with the AAC track unsupported.
    let input = filtered(H264_AAC, |_, packet| pid(packet) != AUDIO_PID);
    let (events, _) = demux(&input, 4_000);
    let all = layouts(&events);
    assert_eq!(all.len(), 1);
    assert_eq!(
        all[0].tracks[1],
        unsupported_track(AUDIO_PID, 0x0f, Kind::Audio, "aac")
    );
    assert!(matches!(events[0], Event::Layout(_)));
    assert_eq!(units(&events, 0).len(), 10);
    // Audio that comes later is dropped.
    let half = H264_AAC.len() / PACKET / 2;
    let input = filtered(H264_AAC, |i, packet| i >= half || pid(packet) != AUDIO_PID);
    let (events, _) = demux(&input, 4_000);
    assert_eq!(layouts(&events).len(), 1);
    assert_eq!(units(&events, 0).len(), 10);
    assert!(units(&events, 1).is_empty());
}

#[test]
fn iso13818_1_2_4_4_8_a_program_map_replaces_a_layout_still_waiting_with_its_units() {
    let mut input = filtered(H264_AAC, |_, packet| pid(packet) != AUDIO_PID);
    input.extend_from_slice(H265_V1);
    let (events, _) = demux(&input, MAX);
    let all = layouts(&events);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].tracks[0].stream_type, 0x24);
    assert_eq!(units(&events, 0).len(), 10);
}

#[test]
fn iso13818_1_2_4_3_7_a_video_pes_without_a_pts_is_dropped() {
    let input = patch_pes(H264_AAC, VIDEO_PID, 1, |pes| pes[7] &= 0x3f);
    let (events, demuxer) = demux(&input, MAX);
    let video = units(&events, 0);
    assert_eq!(video.len(), 9);
    assert_eq!(video[1].ts, 145_920);
    assert_eq!(demuxer.stats().dropped_untimed, 1);
}

#[test]
fn iso13818_1_2_4_3_7_an_unreadable_pes_header_is_dropped() {
    // PTS_DTS_flags 01 is forbidden.
    let flags = patch_pes(H264_AAC, VIDEO_PID, 1, |pes| pes[7] = pes[7] & 0x3f | 0x40);
    // A stream_id without the optional header (padding_stream).
    let padding = patch_pes(H264_AAC, VIDEO_PID, 1, |pes| pes[3] = 0xbe);
    // The '10' bits before the optional header are missing.
    let bits = patch_pes(H264_AAC, VIDEO_PID, 1, |pes| pes[6] = 0);
    // A PTS marker bit is cleared.
    let marker = patch_pes(H264_AAC, VIDEO_PID, 1, |pes| pes[9] &= 0xfe);
    for input in [flags, padding, bits, marker] {
        let (events, demuxer) = demux(&input, MAX);
        assert_eq!(units(&events, 0).len(), 9);
        assert_eq!(demuxer.stats().dropped_malformed, 1);
    }
}

#[test]
fn iso13818_1_2_4_3_7_an_adts_pes_without_a_pts_follows_the_frame_count() {
    let input = patch_pes(H264_AAC, AUDIO_PID, 1, |pes| pes[7] &= 0x3f);
    let (events, demuxer) = demux(&input, MAX);
    let (whole, _) = demux(H264_AAC, MAX);
    assert_eq!(units(&events, 1), units(&whole, 1));
    assert_eq!(demuxer.stats().dropped_untimed, 0);
    // Without the first PTS, the frames before the next one are dropped.
    let input = patch_pes(H264_AAC, AUDIO_PID, 0, |pes| pes[7] &= 0x3f);
    let (events, demuxer) = demux(&input, MAX);
    let audio = units(&events, 1);
    let dropped = demuxer.stats().dropped_untimed;
    assert!(dropped > 0);
    assert_eq!(audio.len() as u64 + dropped, 48);
    assert_eq!(audio[0], units(&whole, 1)[dropped as usize]);
}

/// A context holding one AAC track (and a second one waiting if
/// `second`), its layout pending.
fn audio_ctx(second: bool) -> Ctx {
    let mut ctx = Ctx::new(MAX);
    ctx.program = Some(1);
    ctx.tracks = vec![Track::new(AUDIO_PID, 0x0f, MAX).unwrap()];
    if second {
        ctx.tracks.push(Track::new(0x102, 0x0f, MAX).unwrap());
    }
    ctx
}

/// Feeds `adts` to track 0 of `ctx` as one PES packet with `pts`.
fn feed(ctx: &mut Ctx, adts: &[u8], pts: Option<i64>) {
    ctx.tracks[0].pes = Some(Pes {
        timing: pts.map(|pts| Timing { pts, dts: pts }),
        data: adts.to_vec(),
    });
    ctx.finish(0);
}

/// The first `count` ADTS frames of `adts`.
fn adts_frames(adts: &[u8], count: usize) -> &[u8] {
    let mut end = 0;
    for _ in 0..count {
        let length = usize::from(adts[end + 3] & 0x03) << 11
            | usize::from(adts[end + 4]) << 3
            | usize::from(adts[end + 5] >> 5);
        end += length;
    }
    &adts[..end]
}

fn timestamps(events: &[Event]) -> Vec<i64> {
    units(events, 0).iter().map(|unit| unit.ts).collect()
}

#[test]
fn iso13818_1_2_4_3_7_adts_timestamps_restart_only_half_a_frame_or_more_away() {
    let mut ctx = audio_ctx(false);
    // 48 kHz: 1024 samples are 1920 ticks; 512 samples 960 ticks.
    feed(&mut ctx, adts_frames(SINE_48K_MONO, 1), Some(0));
    assert!(matches!(ctx.events[0], Event::Layout(_)));
    // A PTS exactly half a frame off is still rounding.
    feed(&mut ctx, adts_frames(SINE_48K_MONO, 1), Some(1_920 + 960));
    assert_eq!(ctx.stats.audio_reanchors, 0);
    // Further off, the timestamps restart from it.
    feed(
        &mut ctx,
        adts_frames(SINE_48K_MONO, 1),
        Some(2 * 1_920 + 962),
    );
    assert_eq!(ctx.stats.audio_reanchors, 1);
    assert_eq!(timestamps(&ctx.events), [0, 1_024, 2_048 + 513]);
    // Before the first PTS of a track there is nothing to count from.
    let mut ctx = audio_ctx(false);
    feed(&mut ctx, adts_frames(SINE_48K_MONO, 2), None);
    assert_eq!(ctx.stats.dropped_untimed, 2);
    assert!(units(&ctx.events, 0).is_empty());
}

#[test]
fn iso13818_7_6_2_a_configuration_change_before_the_layout_only_updates_it() {
    // Two AAC tracks; the first changes its configuration while the
    // second has none yet: no layout goes out until the second's comes.
    let mut ctx = audio_ctx(true);
    feed(&mut ctx, adts_frames(SINE_48K_MONO, 1), Some(0));
    feed(&mut ctx, adts_frames(SINE_16K_MONO, 1), Some(5_760));
    assert!(ctx.events.is_empty());
    assert_eq!(ctx.held.len(), 2);
    // The new configuration counts from its own PTS: 0.064 s at 16 kHz.
    assert_eq!(ctx.held[1].ts, 1_024);
    ctx.tracks[1].pes = Some(Pes {
        timing: Some(Timing { pts: 0, dts: 0 }),
        data: adts_frames(SINE_48K_MONO, 1).to_vec(),
    });
    ctx.finish(1);
    let all = layouts(&ctx.events);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].tracks[0].codec, aac(16_000, CONFIG_16K_MONO));
    assert_eq!(all[0].tracks[1].codec, aac(48_000, CONFIG_48K_MONO));
    assert_eq!(ctx.events.len(), 4);
}

#[test]
fn iso14496_3_1_6_2_1_an_undecodable_adts_configuration_is_unsupported_without_units() {
    // AAC Main (profile 0): ADTS can say it, the decoder does not take it.
    let mut adts = adts_frames(SINE_48K_MONO, 2).to_vec();
    let second =
        usize::from(adts[3] & 0x03) << 11 | usize::from(adts[4]) << 3 | usize::from(adts[5] >> 5);
    adts[2] &= 0x3f;
    adts[second + 2] &= 0x3f;
    let mut ctx = audio_ctx(false);
    feed(&mut ctx, &adts, Some(0));
    let all = layouts(&ctx.events);
    let err = parse_config(&[0x09, 0x88]).unwrap_err();
    assert_eq!(
        all[0].tracks[0],
        unsupported_track(AUDIO_PID, 0x0f, Kind::Audio, err.codec_name())
    );
    assert!(units(&ctx.events, 0).is_empty());
    // The splitter read both frames all the same.
    let mut splitter = AdtsSplitter::new(MAX);
    let mut frames = Vec::new();
    let _ = splitter.push(&adts, &mut frames);
    assert_eq!(frames.len(), 2);
}

#[test]
fn iso13818_1_2_4_4_8_units_are_held_at_most_two_seconds_or_max_frame_bytes() {
    let unit = |decode_time: i64, bytes: usize| Unit {
        track: 1,
        decode_time,
        ts: decode_time,
        payload: Bytes::from(vec![0; bytes]),
    };
    // Two seconds of the 90 kHz clock.
    assert_eq!(HOLD_TICKS, 180_000);
    let mut ctx = audio_ctx(false);
    ctx.emit(unit(1_000, 10));
    ctx.emit(unit(1_000 + HOLD_TICKS as i64, 10));
    assert!(ctx.events.is_empty());
    ctx.emit(unit(1_000 + HOLD_TICKS as i64 + 1, 10));
    assert_eq!(layouts(&ctx.events).len(), 1);
    assert_eq!(ctx.events.len(), 4);
    assert_eq!(ctx.held_bytes, 0);
    // Earlier units count by distance too.
    let mut ctx = audio_ctx(false);
    ctx.emit(unit(0, 10));
    ctx.emit(unit(-(HOLD_TICKS as i64) - 1, 10));
    assert_eq!(layouts(&ctx.events).len(), 1);
    // By bytes: up to the limit they wait.
    let mut ctx = audio_ctx(false);
    ctx.max_frame_bytes = 100;
    ctx.emit(unit(0, 60));
    ctx.emit(unit(0, 40));
    assert!(ctx.events.is_empty());
    assert_eq!(ctx.held_bytes, 100);
    ctx.emit(unit(0, 1));
    assert_eq!(layouts(&ctx.events).len(), 1);
}

#[test]
fn clamp_saturates_at_the_range_of_i64() {
    assert_eq!(clamp(5), 5);
    assert_eq!(clamp(-5), -5);
    assert_eq!(clamp(i128::MAX), i64::MAX);
    assert_eq!(clamp(i128::MIN), i64::MIN);
    assert_eq!(clamp(i128::from(i64::MAX) + 1), i64::MAX);
    assert_eq!(clamp(i128::from(i64::MIN) - 1), i64::MIN);
}

#[test]
fn the_configs_of_the_aac_fixtures_are_what_the_tests_expect() {
    assert_eq!(parse_config(&CONFIG_48K_MONO).unwrap().sample_rate, 48_000);
    assert_eq!(parse_config(&CONFIG_16K_MONO).unwrap().sample_rate, 16_000);
}

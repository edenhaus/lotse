//! Recorded HLS MPEG-TS segments for the source's tests, in
//! `crates/lotse-http/testdata/`.
//!
//! Made by ffmpeg 9.0.2 (the macOS arm64 build `mise.toml` pins) on
//! 2026-10-08 from its `lavfi` test sources with
//! `ffmpeg -hide_banner -loglevel error -y -fflags +bitexact -flags +bitexact
//! -f lavfi -i testsrc2=size=160x90:rate=10:duration=3
//! -f lavfi -i sine=frequency=1000:sample_rate=48000:duration=3
//! -c:v libx264 -profile:v baseline -g 10 -pix_fmt yuv420p -c:a aac
//! -b:a 32k -ac 1 -f hls -hls_time 1 -hls_list_size 0
//! -hls_segment_type mpegts -hls_segment_filename 'live_%d.m2t' live.m3u8`;
//! the playlist ffmpeg wrote is not kept. Three one-second segments of
//! one timeline: H.264 (no B-frames, a keyframe each) and AAC-LC 48 kHz
//! mono, their timestamps running on from one segment into the next.

/// The first second: 10 access units.
pub(crate) const LIVE_0: &[u8] = include_bytes!("../../testdata/live_0.m2t");

/// The second second.
pub(crate) const LIVE_1: &[u8] = include_bytes!("../../testdata/live_1.m2t");

/// The third second.
pub(crate) const LIVE_2: &[u8] = include_bytes!("../../testdata/live_2.m2t");

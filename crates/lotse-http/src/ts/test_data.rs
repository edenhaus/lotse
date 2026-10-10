//! Recorded MPEG-TS for the demultiplexer's tests and the `ts_demux`
//! fuzz target's seeds, in `crates/lotse-http/testdata/`.
//!
//! Made by ffmpeg 9.0.2 (the macOS arm64 build `mise.toml` pins) on
//! 2026-10-08 from its `lavfi` test sources, each with
//! `ffmpeg -hide_banner -loglevel error -y -fflags +bitexact -flags +bitexact`
//! followed by:
//!
//! - `h264_aac.m2t`: `-f lavfi -i testsrc2=size=160x90:rate=10:duration=1
//!   -f lavfi -i sine=frequency=1000:sample_rate=48000:duration=1
//!   -c:v libx264 -profile:v baseline -g 10 -pix_fmt yuv420p -c:a aac
//!   -b:a 32k -ac 1 -f mpegts h264_aac.m2t`
//! - `h264_bframes_wrap.m2t`: `-f lavfi
//!   -i testsrc2=size=160x90:rate=10:duration=1 -c:v libx264 -profile:v main
//!   -bf 2 -g 10 -pix_fmt yuv420p -output_ts_offset 95442 -f mpegts
//!   h264_bframes_wrap.m2t` (the offset puts the 33-bit wrap of PTS and DTS,
//!   2^33 / 90 kHz = 95443.7 s, inside the second of video)
//! - `h265_v1.m2t`: `-f lavfi -i testsrc2=size=160x90:rate=10:duration=1
//!   -c:v libx265 -x265-params log-level=none:bframes=0 -g 10
//!   -pix_fmt yuv420p -tables_version 1 -f mpegts h265_v1.m2t` (PAT and PMT
//!   `version_number` 1)
//! - `h264_aac16k.m2t`: `-f lavfi -i testsrc2=size=160x90:rate=10:duration=0.5
//!   -f lavfi -i sine=frequency=1000:sample_rate=16000:duration=0.5
//!   -c:v libx264 -profile:v baseline -g 10 -pix_fmt yuv420p -c:a aac
//!   -b:a 32k -ac 1 -tables_version 1 -f mpegts h264_aac16k.m2t` (the
//!   streams of `h264_aac.m2t` in table version 1, with another AAC
//!   configuration)
//! - `programs.m2t`: `-f lavfi -i testsrc2=size=160x90:rate=10:duration=0.5
//!   -f lavfi -i sine=frequency=1000:sample_rate=48000:duration=0.5
//!   -map 0:v -map 1:a -map 1:a -c:v libx264 -profile:v baseline -g 10
//!   -pix_fmt yuv420p -c:a:0 mp2 -c:a:1 aac -b:a 32k -ac 1
//!   -mpegts_flags latm -program program_num=1:st=0:st=1:st=2
//!   -program program_num=2:st=1 -f mpegts programs.m2t` (MPEG-1 audio,
//!   `stream_type` 0x03, and AAC in LATM, 0x11, in two programs)
//!
//! They are named `.m2t`, one of ffmpeg's MPEG-TS extensions: the file
//! hygiene hooks take `.ts` for TypeScript text and would rewrite them.
//!
//! What ffmpeg's own demultiplexer reads in them (`ffmpeg -i <file> -map 0
//! -c copy -copyts -f framecrc -`) is what the tests expect: PIDs 0x100
//! (video) and 0x101 (audio), 10 video frames per second, the first PTS at
//! 1.4 s (126000).

/// One second of H.264 (no B-frames) and AAC-LC 48 kHz mono: 10 access
/// units and 48 AAC frames.
pub(super) const H264_AAC: &[u8] = include_bytes!("../../testdata/h264_aac.m2t");

/// One second of H.264 with B-frames, its PTS and DTS wrapping: 10 access
/// units.
pub(super) const H264_BFRAMES_WRAP: &[u8] = include_bytes!("../../testdata/h264_bframes_wrap.m2t");

/// One second of H.265 with table version 1: 10 access units.
pub(super) const H265_V1: &[u8] = include_bytes!("../../testdata/h265_v1.m2t");

/// Half a second of H.264 and AAC-LC 16 kHz mono: 5 access units and 9
/// AAC frames.
pub(super) const H264_AAC16K: &[u8] = include_bytes!("../../testdata/h264_aac16k.m2t");

/// Half a second of H.264, MPEG-1 audio and AAC in LATM, in two programs.
pub(super) const PROGRAMS: &[u8] = include_bytes!("../../testdata/programs.m2t");

/// The PID of the video stream, as ffmpeg numbers it.
pub(super) const VIDEO_PID: u16 = 0x100;

/// The PID of the first audio stream, as ffmpeg numbers it.
pub(super) const AUDIO_PID: u16 = 0x101;

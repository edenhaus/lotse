//! Recorded fragmented MP4 HLS streams for the reader's tests and the
//! `fmp4_segment` fuzz target's seeds, in `crates/lotse-http/testdata/`.
//!
//! Made by ffmpeg 9.0.2 (the macOS arm64 build `mise.toml` pins) on
//! 2026-10-08 from its `lavfi` test sources, each with
//! `ffmpeg -hide_banner -loglevel error -y -fflags +bitexact -flags +bitexact`
//! followed by the options below and `-f hls -hls_time 1 -hls_list_size 0
//! -hls_segment_type fmp4`; the playlists ffmpeg wrote with them are not
//! kept:
//!
//! - `h264_aac_init.mp4`, `h264_aac_0.m4s`, `h264_aac_1.m4s`: `-f lavfi
//!   -i testsrc2=size=160x90:rate=10:duration=2 -f lavfi
//!   -i sine=frequency=1000:sample_rate=48000:duration=2 -c:v libx264
//!   -profile:v baseline -g 10 -pix_fmt yuv420p -c:a aac -b:a 32k -ac 1`
//!   and `-hls_fmp4_init_filename h264_aac_init.mp4
//!   -hls_segment_filename 'h264_aac_%d.m4s' h264_aac.m3u8`
//! - `h265_init.mp4`, `h265_0.m4s`: `-f lavfi
//!   -i testsrc2=size=160x90:rate=10:duration=1 -c:v libx265
//!   -x265-params log-level=none:bframes=0 -g 10 -pix_fmt yuv420p
//!   -tag:v hvc1` and `-hls_fmp4_init_filename h265_init.mp4
//!   -hls_segment_filename 'h265_%d.m4s' h265.m3u8`
//! - `h264_bframes_init.mp4`, `h264_bframes_0.m4s`: `-f lavfi
//!   -i testsrc2=size=160x90:rate=10:duration=1 -c:v libx264 -profile:v main
//!   -bf 2 -g 10 -pix_fmt yuv420p` and
//!   `-hls_segment_options movflags=+negative_cts_offsets
//!   -hls_fmp4_init_filename h264_bframes_init.mp4
//!   -hls_segment_filename 'h264_bframes_%d.m4s' h264_bframes.m3u8`
//!   (version 1 runs with negative composition offsets)
//! - `split_video_init.mp4`, `split_video_0.m4s`, `split_audio_init.mp4`,
//!   `split_audio_0.m4s`: the inputs and codecs of `h264_aac` for one
//!   second, `-map 0:v -map 1:a`, and
//!   `-var_stream_map "v:0,agroup:aud,name:video a:0,agroup:aud,name:audio"
//!   -master_pl_name split.m3u8 -hls_fmp4_init_filename 'split_%v_init.mp4'
//!   -hls_segment_filename 'split_%v_%d.m4s' 'split_%v.m3u8'` (a variant
//!   with its audio in a separate rendition)
//! - `opus_init.mp4`: `-f lavfi -i sine=frequency=1000:sample_rate=48000:duration=1
//!   -c:a libopus -b:a 32k -ac 1` and `-hls_fmp4_init_filename opus_init.mp4
//!   -hls_segment_filename 'opus_%d.m4s' opus.m3u8` (the init segment only)
//!
//! What ffmpeg's own demultiplexer reads in them (the init segment and a
//! media segment concatenated, `ffmpeg -i <file> -map 0 -c copy -copyts
//! -f framecrc -`, with and without `-ignore_editlist 1`) is what the
//! tests expect: video `timescale` 10240, 1024 a frame; AAC 48000, 1024 a
//! frame; the H.264 video of `h264_aac` delayed 1026/48000 s by an empty
//! edit, that of `h264_bframes` 200/1000 s.

/// The init segment of H.264 (no B-frames) and AAC-LC 48 kHz mono.
pub(crate) const H264_AAC_INIT: &[u8] = include_bytes!("../../testdata/h264_aac_init.mp4");

/// Its first second: 10 access units and 48 AAC frames.
pub(crate) const H264_AAC_0: &[u8] = include_bytes!("../../testdata/h264_aac_0.m4s");

/// Its second second: 10 access units and 47 AAC frames.
pub(crate) const H264_AAC_1: &[u8] = include_bytes!("../../testdata/h264_aac_1.m4s");

/// The init segment of H.265 in `hvc1`.
pub(crate) const H265_INIT: &[u8] = include_bytes!("../../testdata/h265_init.mp4");

/// Its one second: 10 access units.
pub(crate) const H265_0: &[u8] = include_bytes!("../../testdata/h265_0.m4s");

/// The init segment of H.264 with B-frames.
pub(crate) const H264_BFRAMES_INIT: &[u8] = include_bytes!("../../testdata/h264_bframes_init.mp4");

/// Its one second: 10 access units in a version 1 run.
pub(crate) const H264_BFRAMES_0: &[u8] = include_bytes!("../../testdata/h264_bframes_0.m4s");

/// The init segment of a variant's H.264 video.
pub(crate) const SPLIT_VIDEO_INIT: &[u8] = include_bytes!("../../testdata/split_video_init.mp4");

/// Its one second: 10 access units.
pub(crate) const SPLIT_VIDEO_0: &[u8] = include_bytes!("../../testdata/split_video_0.m4s");

/// The init segment of its audio rendition, AAC-LC 48 kHz mono.
pub(crate) const SPLIT_AUDIO_INIT: &[u8] = include_bytes!("../../testdata/split_audio_init.mp4");

/// Its first second: 47 AAC frames.
pub(crate) const SPLIT_AUDIO_0: &[u8] = include_bytes!("../../testdata/split_audio_0.m4s");

/// The init segment of Opus audio.
pub(crate) const OPUS_INIT: &[u8] = include_bytes!("../../testdata/opus_init.mp4");

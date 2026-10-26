//! Bitstream normalizers (RTP payloads, Annex B, AVCC and ADTS in; canonical
//! access units out), G.711, AAC-LC decode, Opus, resampling and the
//! transcoders built from them.
//!
//! Runs inside a worker process, on camera bytes: every parser here is fuzzed.
//! Depends on `lotse-core` only. Used by the source and output crates and by
//! the binary, which registers the transcoders.
//!
//! Standards: ISO/IEC 14496-10 and RFC 6184 (H.264), ITU-T H.265 and RFC 7798,
//! RFC 3640 and ISO/IEC 14496-3 (AAC), ITU-T G.711 and RFC 3551, RFC 6716 (Opus).

pub mod aac;
pub mod g711;
pub mod h264;
pub mod h265;
pub mod opus;
pub mod resample;
pub mod transcode;

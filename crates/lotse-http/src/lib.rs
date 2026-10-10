//! HTTP source (M6): HLS with MPEG-TS and fragmented MP4 segments, and raw
//! MPEG-TS over HTTP. So far the HLS playlist parser and the choice of
//! variant, audio rendition and segments from the parsed playlists, the
//! MPEG-TS demultiplexer and the fragmented MP4 reader, the pacing
//! and publishing of their units on the tracks, and the HTTP/1.1 client
//! that fetches playlists and segments.
//!
//! Runs in a worker, on bytes from the network: every parser here is fuzzed.
//! May depend on `lotse-core` and `lotse-codec` only, never on another source
//! crate.
//!
//! Standards: RFC 8216 (HTTP Live Streaming), RFC 6381 §3 (the codec names
//! of a variant's `CODECS`), RFC 3986 §5.2 (reference resolution of
//! playlist URIs), RFC 6454 §4 and §5 (the origin a URI must share with its
//! playlist), ISO/IEC 13818-1 (MPEG-TS), ISO/IEC 14496-12 and 14496-15
//! (fragmented MP4 with AVC and HEVC), RFC 9110 and RFC 9112 (HTTP/1.1
//! GET, redirects, status codes), RFC 7617 and RFC 7616 (Basic and Digest
//! authentication).

pub mod client;
pub mod fmp4;
pub mod hls;
pub mod media;
pub mod pace;
pub mod publish;
pub mod ts;

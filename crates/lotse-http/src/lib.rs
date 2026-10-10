//! HTTP source (M6): HLS with MPEG-TS and fragmented MP4 segments, and raw
//! MPEG-TS over HTTP. So far the HLS playlist parser and the choice of
//! variant, audio rendition and segments from the parsed playlists.
//!
//! Runs in a worker, on bytes from the network: every parser here is fuzzed.
//! May depend on `lotse-core` and `lotse-codec` only, never on another source
//! crate.
//!
//! Standards: RFC 8216 (HTTP Live Streaming), RFC 6381 §3 (the codec names
//! of a variant's `CODECS`), RFC 3986 §5.2 (reference resolution of
//! playlist URIs), RFC 6454 §4 and §5 (the origin a URI must share with its
//! playlist).

pub mod hls;

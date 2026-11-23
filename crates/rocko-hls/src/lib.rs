//! LL-HLS output: the [`Window`] that turns a live output's fragments, one
//! fragmented MP4 `moof`+`mdat` per video frame, into Media Segments and
//! Partial Segments and renders the Media Playlist of them, with the names
//! of its resources ([`Resource`]) and the Delivery Directives of a playlist
//! request ([`Blocking`]) parsed back from what a client sends.
//!
//! Runs in the supervisor, which serves the playlist and the segments over
//! HTTP. The supervisor never parses camera bytes: the window takes each
//! fragment's bytes as opaque and uses only what describes it, whether it
//! is independent and how long it lasts, and its length. Sans-IO and pure:
//! no I/O, no clock (a blocked request is the caller's to hold and time out),
//! no logging (the caller logs). Depends on `bytes` and `thiserror` only;
//! never on a source, output, codec or process crate, nor on `rocko-core`
//! (its input is its own [`Fragment`], see there why).
//!
//! Standards: "HTTP Live Streaming 2nd Edition",
//! draft-pantos-hls-rfc8216bis-22 (1 May 2026, the current revision when
//! this was written,
//! <https://www.ietf.org/archive/id/draft-pantos-hls-rfc8216bis-22.txt>),
//! which obsoletes RFC 8216 and defines its Low-Latency extensions: Partial
//! Segments (§3.2), the Media Playlist tags (§4.4), the server's
//! responsibilities (§6.2), Blocking Playlist Reload (§6.2.5.2), Preload
//! Hints (§6.2.6), version compatibility (§8) and the Low-Latency Server
//! Configuration Profile (Appendix B.1). Every section cited in this crate
//! is of that revision. Each module names its clauses.
//!
//! The playlist is written here, not by a crate. m3u8-rs 6.0.1, already in
//! the tree for the HTTP source's playlists (and kept to rocko-http by
//! `.cargo/layering.toml`), types none of the Low-Latency tags
//! (`EXT-X-PART`, `EXT-X-PART-INF`, `EXT-X-SERVER-CONTROL`,
//! `EXT-X-PRELOAD-HINT`): it writes them only as untyped tag lines whose
//! text the caller formats anyway. broadcast-hls 0.7.0 (MIT OR Apache-2.0,
//! crates.io, read 2026-11-15) types and writes them all, from the same
//! revision, but it is three months old with ten breaking releases, one
//! maintainer, and a parser and dependencies (broadcast-common, jiff) the
//! supervisor has no use for; what it would replace is a few `writeln!`s,
//! each citing its clause.

mod name;
mod query;
mod window;

pub use crate::name::{INIT_NAME, Resource};
pub use crate::query::{Blocking, DirectiveError, MSN_DIRECTIVE, PART_DIRECTIVE, decimal_integer};
pub use crate::window::{
    Chunks, Config, ConfigError, DEFAULT_MAX_BYTES, DEFAULT_PART_TARGET, DEFAULT_SEGMENT_TARGET,
    DEFAULT_SEGMENTS, FRAGMENT_OVERHEAD, Fragment, JITTER, Lookup, PushError, Pushed, Reload,
    Window,
};

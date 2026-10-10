//! HTTP Live Streaming: the playlists a source reads.
//!
//! Standards: RFC 8216.

pub mod playlist;

pub use playlist::{
    AudioRendition, MAX_PLAYLIST_BYTES, MAX_RENDITIONS, MAX_SEGMENTS, MAX_VARIANTS, MediaPlaylist,
    MultivariantPlaylist, Playlist, PlaylistError, Segment, Start, Variant, parse,
};

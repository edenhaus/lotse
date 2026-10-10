//! HTTP Live Streaming: the playlists a source reads and what it plays
//! from them.
//!
//! Standards: RFC 8216, RFC 6381.

pub mod playlist;
pub mod select;

pub use playlist::{
    AudioRendition, MAX_PLAYLIST_BYTES, MAX_RENDITIONS, MAX_SEGMENTS, MAX_VARIANTS, MediaPlaylist,
    MultivariantPlaylist, Playlist, PlaylistError, Segment, Start, Variant, parse,
};
pub use select::{Choice, Event, Fetch, SelectError, Tracker, Update, choose_variant, start_index};

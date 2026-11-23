//! Serde DTOs of the control API: every command, result, event and error
//! code, plus the JSON Schema bundle that the `schema` command returns and
//! the `AsyncAPI` document and the generated Python client are built from;
//! generating it (`schemars`) takes the `schema` feature.
//!
//! Shared by the server (`rocko-api`), the supervisor and `rocko ctl`. Holds
//! no behavior and no domain types: conversions from `rocko-core` live in the
//! supervisor, so a client never links the media core. Unknown fields in
//! commands are rejected; unknown fields in results and events must be
//! ignored by clients, so additive changes need no version bump.
//!
//! Standards: JSON Schema 2020-12, RFC 3339, ULID, Semantic Versioning
//! 2.0.0; the recording and live DTOs describe fragmented MP4 (ISO/IEC 14496-12)
//! whose bytes are chunked HTTP bodies (RFC 9112 §7.1), the live output's
//! MIME type with its RFC 6381 `codecs` parameter; the LL-HLS DTOs name a
//! Media Playlist of draft-pantos-hls-rfc8216bis-22.

pub mod clients;
pub mod command;
pub mod error;
pub mod frame;
pub mod hls;
pub mod info;
pub mod limits;
pub mod live;
pub mod pairing;
pub mod recording;
pub mod schema;
pub mod session;
pub mod signaling;
pub mod source;
pub mod stream;
pub mod time;
pub mod version;

pub use command::{Command, CommandError, parse_command};
pub use error::{ApiError, ErrorCode};
pub use frame::{EventFrame, Failure, Hello, Pong, Shutdown, Success};
pub use info::{InfoResult, Metrics};
pub use stream::{Stream, StreamEvent, StreamState};
pub use version::{
    API_VERSION, ApiVersion, HLS_PATH, LIVE_PATH, METRICS_PATH, PAIR_PATH, RECORDING_PATH, WS_PATH,
};

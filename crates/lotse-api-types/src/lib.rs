//! Serde DTOs of the control API: every command, result, event and error
//! code, plus the JSON Schema bundle that the `schema` command returns and
//! the `AsyncAPI` document and the generated Python client are built from;
//! generating it (`schemars`) takes the `schema` feature.
//!
//! Shared by the server (`lotse-api`), the supervisor and `lotse ctl`. Holds
//! no behavior and no domain types: conversions from `lotse-core` live in the
//! supervisor, so a client never links the media core. Unknown fields in
//! commands are rejected; unknown fields in results and events must be
//! ignored by clients, so additive changes need no version bump.
//!
//! Standards: JSON Schema 2020-12, RFC 3339, ULID, Semantic Versioning
//! 2.0.0; the clip DTOs describe fragmented MP4 files (ISO/IEC 14496-12)
//! whose bytes are chunked HTTP bodies (RFC 9112 §7.1).

pub mod clients;
pub mod clip;
pub mod command;
pub mod error;
pub mod frame;
pub mod info;
pub mod limits;
pub mod pairing;
pub mod schema;
pub mod session;
pub mod stream;
pub mod time;
pub mod version;

pub use command::{Command, CommandError, parse_command};
pub use error::{ApiError, ErrorCode};
pub use frame::{EventFrame, Failure, Hello, Pong, Shutdown, Success};
pub use info::{InfoResult, Metrics};
pub use stream::{Stream, StreamEvent, StreamState};
pub use version::{API_VERSION, ApiVersion, CLIPS_PATH, WS_PATH};

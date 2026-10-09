//! The shape and length caps of command inputs, checked by
//! [`parse_command`](crate::parse_command) and published in the schema
//! bundle as `pattern`, `maxLength` and `maxItems`.
//!
//! Lengths count characters (Unicode scalar values), as JSON Schema's
//! `maxLength` does (JSON Schema Validation 2020-12 §6.3.1). The caps are
//! design limits, not a standard's: each is far above what browsers and
//! the clients relaying them send (observed 2026-10) and far below the 64 KiB frame,
//! except the SDP's, which is the frame's own size. Identifier shapes are
//! checked where they are used; their length is capped here, every
//! `stream_id` and session id, so no refusal or log carries a longer one.
//! An over-long `stream_id` is `invalid_stream_id`, as a malformed one is.

/// The shape of a stream or session id, as `lotse_core::id` checks it.
pub const ID_PATTERN: &str = "^[A-Za-z0-9._-]{1,128}$";

/// The longest stream or session id, `lotse_core::id::MAX_LEN`.
pub const MAX_ID_CHARS: usize = 128;

/// The most `sources` of one `stream/put`; v1 uses one, failover a few.
pub const MAX_SOURCES: usize = 8;

/// The longest source URL, credentials and query included.
pub const MAX_URL_CHARS: usize = 4096;

/// The longest SDP offer: the whole 64 KiB frame.
pub const MAX_SDP_CHARS: usize = 64 * 1024;

/// The most `ice_servers` of one `webrtc/offer`.
pub const MAX_ICE_SERVERS: usize = 16;

/// The most `urls` of one ICE server.
pub const MAX_ICE_URLS: usize = 16;

/// The longest ICE server URL, TURN username or credential, trickled
/// candidate or `sdp_mid`.
pub const MAX_TEXT_CHARS: usize = 1024;

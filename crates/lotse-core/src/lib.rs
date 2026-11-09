//! Protocol-blind media core: tracks, packets, frames, the source and output
//! contracts, the signaling channel a source whose signaling the control-API
//! client relays opens at each attempt, factory registries, source
//! supervision (backoff, stall watchdog, hot swap), clock mapping and its
//! skew watchdog, fan-out, the pre-record ring, a recording's reliable queue
//! and interleaver and its container contract, track negotiation and a
//! session's uplink track for talk-back, and the path of the viewers'
//! keyframe requests to the source feeding a track.
//!
//! Runs inside a worker process. Knows nothing about RTSP, WebRTC, HTTP or
//! processes: it defines the traits the protocol crates implement and never
//! depends on one of them. The layering is enforced by the `[bans] deny`
//! wrappers in `.cargo/deny.toml`. Test fakes for core's own types live behind
//! its `test-util` feature, never in `lotse-testing`.
//!
//! Standards: RFC 3550 (RTP timestamps, sequence numbers, Sender Reports);
//! the keyframe requests stand for RFC 4585 §6.3.1 PLIs and RFC 5104
//! §4.3.1 FIR messages, which the protocol crates send and receive;
//! the signaling channel carries RFC 8829 (JSEP) offers and answers and
//! RFC 8838 (Trickle ICE) candidates as opaque text.

pub mod backoff;
pub mod clock;
pub mod clock_map;
pub mod codec;
pub mod connection;
pub mod discontinuity;
pub mod fingerprint;
pub mod id;
pub mod ingest;
pub mod interleave;
pub mod keyframe;
pub mod lateness;
pub mod media;
pub mod negotiate;
pub mod orientation;
pub mod output;
pub mod prerecord;
pub mod recording;
pub mod registry;
pub mod runner;
pub mod secret;
pub mod session;
pub mod signaling;
pub mod skew;
pub mod source;
pub mod source_url;
pub mod task;
#[cfg(test)]
mod test_logs;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
pub mod text;
pub mod throttle;
pub mod track;
pub mod transcode;
pub mod uplink;

pub use clock::{Clock, SystemClock};
pub use clock_map::{ClockMapper, SyncMode};
pub use codec::{Codec, CodecFamily, Kind};
pub use connection::{ConnectionMachine, ConnectionState};
pub use id::{IdError, SessionId, StreamId};
pub use media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields};
pub use negotiate::{NegotiationError, TrackInfo, TrackPlan, negotiate};
pub use orientation::Orientation;
pub use output::{OutputFactory, TrackRequest};
pub use registry::Registries;
pub use runner::{RunnerConfig, RunnerEvent, SourceRunner};
pub use secret::{RedactedUrl, Secret};
pub use source::{Source, SourceCtx, SourceError, SourceFactory, TrackSet};
pub use source_url::{Credentials, SourceUrl, SourceUrlError};
pub use track::{GopSnapshot, Track, TrackEvent, TrackId, TrackLimits, TrackSubscription, Unit};
pub use transcode::Transcoder;

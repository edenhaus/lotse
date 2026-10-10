//! Protocol-blind media core: tracks, packets, frames, the source and output
//! contracts, factory registries, source supervision (backoff, stall watchdog,
//! hot swap), clock mapping and its skew watchdog, fan-out, track
//! negotiation and a session's uplink track for talk-back.
//!
//! Runs inside a worker process. Knows nothing about RTSP, WebRTC, HTTP or
//! processes: it defines the traits the protocol crates implement and never
//! depends on one of them. The layering is enforced by the `[bans] deny`
//! wrappers in `.cargo/deny.toml`. Test fakes for core's own types live behind
//! its `test-util` feature, never in `lotse-testing`.
//!
//! Standards: RFC 3550 (RTP timestamps, sequence numbers, Sender Reports).

pub mod backoff;
pub mod clock;
pub mod clock_map;
pub mod codec;
pub mod connection;
pub mod discontinuity;
pub mod id;
pub mod ingest;
pub mod lateness;
pub mod media;
pub mod negotiate;
pub mod orientation;
pub mod output;
pub mod registry;
pub mod runner;
pub mod secret;
pub mod session;
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
pub use output::{Delivery, JoinPolicy, OutputFactory, Sink, StreamSubscription, TrackRequest};
pub use registry::Registries;
pub use runner::{RunnerConfig, RunnerEvent, SourceRunner};
pub use secret::Secret;
pub use source::{Source, SourceCtx, SourceError, SourceExit, SourceFactory, TrackSet};
pub use source_url::{Credentials, SourceUrl, SourceUrlError};
pub use track::{GopSnapshot, Track, TrackEvent, TrackId, TrackLimits, TrackSubscription, Unit};
pub use transcode::Transcoder;

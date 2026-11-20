//! WebRTC cameras as sources: lotse makes the offer, the control-API
//! client relays it to the camera through its cloud integration (Nest,
//! Ring, Matter) and relays the answer and candidates back over the
//! source's signaling channel (`lotse_core::signaling`); the media arrives
//! on UDP sockets the source binds itself, one per host address the
//! supervisor enumerated.
//!
//! [`WebRtcSourceFactory`] is the signaled protocol `webrtc`: a camera
//! has no address, so it checks [`WebRtcOptions`] only; each attempt of its source runs an [`IngestEngine`]
//! (sans-I/O, on str0m) in a thin loop that does the I/O
//! ([`source`]). Standards: RFC 8829 (JSEP, the offerer's side), RFC 8445
//! (ICE, controlling), RFC 8838 (Trickle ICE), RFC 5763 and RFC 5764
//! (DTLS-SRTP, `actpass`), RFC 7675 (consent freshness), RFC 4585 §6.3.1
//! (PLI), RFC 3550 §6.4.1 (Sender Reports), RFC 8831 and RFC 8832 (data
//! channels), and the payload formats of RFC 6184, RFC 7798 and RFC 7587.

pub mod engine;
pub mod factory;
pub mod options;
pub mod source;

pub use engine::{IngestEnd, IngestEngine, IngestOutput, IngestStats, IngestTrack};
pub use factory::WebRtcSourceFactory;
pub use options::WebRtcOptions;
pub use source::WebRtcSource;

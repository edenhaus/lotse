//! RTSP and RTSPS source on `retina`, the ONVIF keyframe-request client and
//! the backchannel extension point (M4).
//!
//! First implementation of the source contract; runs in a worker. Depends on
//! `lotse-core` and `lotse-codec` only, never on another source. The binary
//! registers its factory behind the `source-rtsp` feature.
//!
//! Standards: RFC 2326 (RTSP 1.0), RFC 3550 (RTP/RTCP), RFC 6184, RFC 7798,
//! RFC 3640, RFC 7587, RFC 7616, RFC 7826 §4.2 and §19.2 (`rtsps`), RFC 8446
//! and RFC 5246 (TLS 1.3 and 1.2, through rustls), RFC 2326 §12.39 with
//! RFC 3550 §11 and §A.1 (opt-in RTP over UDP), RFC 3550 §6.4.2 with
//! §6.2, §6.3.1 and §A.1, §A.3, §A.8 (receiver reports to the camera), ONVIF Streaming
//! Specification §5.3.

pub mod backchannel;
pub mod error;
mod factory;
mod fmtp;
mod framer;
pub mod options;
mod relay;
mod rtcp;
mod source;
mod tap;
pub mod tls;
mod udp;

pub use factory::{BACKCHANNEL, DEFAULT_PORT, DEFAULT_TLS_PORT, PROTOCOL, RtspFactory};
pub use source::RtspSource;

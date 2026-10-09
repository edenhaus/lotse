//! H.265 in RTP form: the packet layer on the live path and the frame
//! layer on the side branch, as for H.264.
//!
//! Standards: RFC 7798 (RTP payload format, without decoding order
//! numbers), ITU-T H.265 (NAL units, SPS `profile_tier_level`, SEI,
//! Annex B).

pub mod frame;
pub mod nal;
pub mod packet;
pub mod sps;

pub use frame::{AccessUnit, Depacketizer};
pub use nal::{ParameterSets, PayloadError, packetize};
pub use packet::PacketNormalizer;
#[cfg(any(test, feature = "test-util"))]
pub use sps::test_data;
pub use sps::{SpsError, SpsInfo, has_recovery_point, parse_sps};

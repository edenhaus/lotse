//! H.264 in RTP form: the packet layer on the live path and the frame
//! layer on the side branch.
//!
//! Standards: RFC 6184 (packetization mode 1), ISO/IEC 14496-10 (NAL
//! units, SPS, SEI, Annex B).

pub mod frame;
pub mod nal;
pub mod packet;
pub mod sps;

pub use frame::{AccessUnit, Depacketizer, FrameStats};
pub use nal::{ParameterSets, PayloadError, annex_b_units, packetize};
pub use packet::{
    DEFAULT_MAX_PAYLOAD, FrameOverLimit, LIBWEBRTC_MAX_FRAME_PACKETS, NormalizedPacket,
    PacketNormalizer, PacketStats,
};
#[cfg(any(test, feature = "test-util"))]
pub use sps::test_data;
pub use sps::{SpsError, SpsInfo, has_recovery_point, parse_sps};

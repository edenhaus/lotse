//! AAC-LC on the side branch: the `AudioSpecificConfig`, RFC 3640
//! depacketization and ADTS stripping, feeding the AAC-LC → Opus
//! transcoder.
//!
//! Standards: ISO/IEC 14496-3 (`AudioSpecificConfig`), RFC 3640
//! (AAC-hbr), ISO/IEC 13818-7 (ADTS).

pub mod config;
pub mod decode;
pub mod rtp;
#[cfg(any(test, feature = "test-util"))]
pub mod test_data;

pub use config::{AacConfig, ConfigError, FRAME_SAMPLES, parse_config};
pub use decode::{AacDecoder, DECODER_DELAY, DecodeError};
#[cfg(any(test, feature = "test-util"))]
pub use rtp::packetize;
pub use rtp::{AacDepacketizer, AacFrame, AacPayloadError, AacStats};

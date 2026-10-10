//! The transcoder contract: turns one track's frames into a derived track
//! of another codec, once per connection and shared by every sink.
//!
//! The trait works in both directions: the AAC→Opus chain for viewers and
//! the Opus→G.711 chain for talk-back are two instances, not two
//! abstractions.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::codec::{Codec, CodecFamily};
use crate::track::{FrameSubscription, Track};

/// A running transcoder and the derived track it feeds. Dropping the
/// handle stops the transcoder.
#[derive(Debug)]
pub struct TrackHandle {
    /// The derived track.
    pub track: Arc<Track>,
    /// The delay the running conversion adds: the longest a packet leaves
    /// after the capture time its timestamp claims, for input that arrives
    /// on time. `tracks[].audio_delay_ms` reports it.
    pub delay: Duration,
    /// Cancelled to stop the transcoder task.
    pub stop: CancellationToken,
}

impl Drop for TrackHandle {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Why a transcoder could not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranscodeError {
    /// This transcoder does not do that conversion.
    #[error("no transcoder from {from} to {to}")]
    Unsupported {
        /// The input codec family.
        from: CodecFamily,
        /// The requested output family.
        to: CodecFamily,
    },
    /// The codec library refused the parameters (unsupported sample rate,
    /// channel count, configuration).
    #[error("transcoder failed to start: {0}")]
    Failed(String),
}

/// One conversion, registered at startup.
pub trait Transcoder: fmt::Debug + Send + Sync {
    /// The codec this transcoder would produce from `from` in family `to`,
    /// or `None` when it cannot. Pure; used by negotiation.
    fn derive(&self, from: &Codec, to: CodecFamily) -> Option<Codec>;

    /// Starts converting `input` (the source track's side branch) into
    /// `output`, whose codec is what [`Transcoder::derive`] returned. The
    /// transcoder publishes each side-branch frame of `output` before the
    /// packets it carries, with the capture time the packets' timestamps
    /// claim, so a sink maps a derived packet through
    /// [`Track::capture_time`]. It never closes `output`; the owner does.
    fn spawn(
        &self,
        input: FrameSubscription,
        from: &Codec,
        output: Arc<Track>,
    ) -> Result<TrackHandle, TranscodeError>;
}

/// Builds the talk-back transcoder for a device's frame duration: the
/// reverse chain (Opus or G.711 uplink to the device's G.711), whose frame
/// is a construction parameter since [`Transcoder::spawn`] has no slot for
/// it. Registered apart from the downlink transcoders
/// ([`Registries::uplink`](crate::registry::Registries::uplink)), so
/// negotiation never offers a viewer a talk-back conversion.
pub trait UplinkFactory: fmt::Debug + Send + Sync {
    /// The transcoder producing packets of `frame`
    /// ([`BackchannelHandle::frame`](crate::source::BackchannelHandle::frame));
    /// one outside the range it frames is clamped into it.
    fn transcoder(&self, frame: Duration) -> Arc<dyn Transcoder>;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::clock::{Clock as _, SystemClock};
    use crate::codec::Kind;
    use crate::track::{TrackId, TrackLimits};

    #[test]
    fn dropping_the_handle_stops_the_transcoder() {
        let stop = CancellationToken::new();
        let handle = TrackHandle {
            track: Arc::new(Track::new(
                TrackId::new(Kind::Audio, 1),
                Codec::Opus { channels: 1 },
                48_000,
                TrackLimits::default(),
                SystemClock.now(),
            )),
            delay: Duration::from_millis(78),
            stop: stop.clone(),
        };
        assert!(!stop.is_cancelled());
        drop(handle);
        assert!(stop.is_cancelled());
    }

    #[test]
    fn errors_name_the_conversion() {
        assert_eq!(
            TranscodeError::Unsupported {
                from: CodecFamily::AacLc,
                to: CodecFamily::Pcmu
            }
            .to_string(),
            "no transcoder from aac_lc to pcmu"
        );
        assert_eq!(
            TranscodeError::Failed("rate".into()).to_string(),
            "transcoder failed to start: rate"
        );
    }
}

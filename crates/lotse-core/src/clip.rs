//! The clip contract: what a container output implements to turn one
//! event clip's frames into the bytes of one file, and the policy a clip
//! runs under.
//!
//! A clip joins with the track's pre-roll ring and takes its frames with
//! reliable delivery: the worker's clip task drains the subscriptions into
//! a [`ReliableQueue`](crate::interleave::ReliableQueue), merges them in
//! capture order through an [`Interleaver`](crate::interleave::Interleaver)
//! and hands each frame to the [`ClipMuxer`] the registered
//! [`ClipMuxerFactory`] made for it. Core knows no container: the factory
//! is registered by the binary
//! ([`Registries::clip`](crate::registry::Registries::clip)), and a worker
//! without one runs no clip.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::codec::{Codec, CodecFamily, Kind};
use crate::media::MediaFrame;

/// Default of `limits.clip_queue_bytes`: 8 MiB of frames a clip holds
/// while its reader is slower than the camera.
pub const DEFAULT_CLIP_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// Default of the interleaver's hold: how long a frame waits for the other
/// track to pass its capture time. An AAC path that delivers a PES late
/// still lands in order within it.
pub const DEFAULT_MAX_SKEW: Duration = Duration::from_secs(1);

/// Default of a fragment's longest span: a fragment ends at every video
/// keyframe and at the latest this long after it began, so the reader
/// gets bytes continuously.
pub const DEFAULT_CLIP_FRAGMENT: Duration = Duration::from_secs(1);

/// The policy a clip runs under: its reliable delivery's bound, the
/// interleaver's hold and the container's fragment span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipPolicy {
    /// The most the clip's queue holds before it drops to the next video
    /// keyframe and reports the gap (`limits.clip_queue_bytes`).
    pub queue_bytes: usize,
    /// How long a frame waits for the other track to pass its capture
    /// time before it goes out regardless.
    pub max_skew: Duration,
    /// A fragment ends at the latest this long after it began.
    pub fragment: Duration,
}

impl Default for ClipPolicy {
    fn default() -> Self {
        Self {
            queue_bytes: DEFAULT_CLIP_QUEUE_BYTES,
            max_skew: DEFAULT_MAX_SKEW,
            fragment: DEFAULT_CLIP_FRAGMENT,
        }
    }
}

/// One track of a clip as its container declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipTrack {
    /// The codec, with the parameter sets or configuration the container's
    /// sample entry carries.
    pub codec: Codec,
    /// The track's clock rate: the container's timescale, so the camera's
    /// timestamps are the file's.
    pub clock_rate: u32,
}

/// Why a muxer could not write a clip.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClipError {
    /// The container cannot carry this codec, or the codec lacks what its
    /// sample entry needs (a parameter set not yet known).
    #[error("the clip container cannot carry {0}")]
    Unsupported(CodecFamily),
    /// A frame or a timestamp the container cannot represent.
    #[error("clip muxing failed: {0}")]
    Failed(String),
}

/// One container output, registered at startup behind its Cargo feature.
pub trait ClipMuxerFactory: fmt::Debug + Send + Sync {
    /// Whether the container can carry `codec` as the track has it; the
    /// clip task decides what becomes of an audio track it cannot.
    fn accepts(&self, codec: &Codec) -> bool;

    /// A muxer for one clip under `policy`.
    fn muxer(&self, policy: &ClipPolicy) -> Box<dyn ClipMuxer>;
}

/// One clip's container writer. Sans-IO: every call returns the bytes it
/// completed, in order, as slices the caller writes as they are (a
/// sample's payload is the frame's own, never copied); an empty list when
/// nothing is complete yet.
pub trait ClipMuxer: Send {
    /// The container's header for the clip's tracks: the video, and the
    /// audio when the clip has one.
    fn start(
        &mut self,
        video: &ClipTrack,
        audio: Option<&ClipTrack>,
    ) -> Result<Vec<Bytes>, ClipError>;

    /// Puts the clip's media time 0 at capture time `origin` instead of
    /// at its first frame's: a clip whose audio is transcoded moves the
    /// packets back by the transcode's delay and so starts that much
    /// before its first frame, where the first packets belong. Called
    /// after `start`, before the first `push`; ignored otherwise.
    fn set_origin(&mut self, origin: Instant);

    /// Takes the next frame of the `track` kind, in the order the
    /// interleaver hands them out; returns the fragment it completed, if
    /// any. The first video frame is a keyframe.
    fn push(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<Vec<Bytes>, ClipError>;

    /// Where the container put the latest frame of the `track` kind it
    /// took: its presentation time from the clip's media time 0; zero
    /// before the first. A container may place a frame later than its
    /// capture time (an epoch that would begin before the one ahead of it
    /// did), so the clip reports its gaps where the file has them by this.
    fn media_time(&self, track: Kind) -> Duration;

    /// Ends the clip: the last fragment, after which the file is complete.
    fn finish(&mut self) -> Result<Vec<Bytes>, ClipError>;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn the_default_policy_is_the_documented_limits() {
        assert_eq!(
            ClipPolicy::default(),
            ClipPolicy {
                queue_bytes: 8 * 1024 * 1024,
                max_skew: Duration::from_secs(1),
                fragment: Duration::from_secs(1),
            }
        );
    }

    #[test]
    fn errors_name_the_codec_or_the_failure() {
        assert_eq!(
            ClipError::Unsupported(CodecFamily::Pcmu).to_string(),
            "the clip container cannot carry pcmu"
        );
        assert_eq!(
            ClipError::Failed("timestamp".into()).to_string(),
            "clip muxing failed: timestamp"
        );
    }
}

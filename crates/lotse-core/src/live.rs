//! The live container contract: what a container output implements to turn a
//! track's live frames into an init segment and one fragment per video frame,
//! for a viewer that plays them as they come (live fMP4 over HTTP, and the
//! parts of LL-HLS).
//!
//! A live writer starts at a video keyframe and writes each video frame in a
//! fragment of its own, with the audio up to it, once the next video frame
//! arrives and tells how long it lasts. It never waits for more: a fragment
//! is complete the moment its frame's duration is known. After a hole (the
//! reader fell behind and the frames up to the next keyframe were dropped,
//! [`LiveMuxer::skip`], or the camera reconnected) it starts again at the next
//! video keyframe, which it places where the output so far ends (the video's
//! last frame lasting until the audio sent ends, if that is later), so the
//! decode and presentation times run on without a hole and a player buffers
//! no gap; the audio keeps its place beside the video by capture time. Core knows no container: the
//! factory is registered by the binary ([`Registries::live`]), and a worker
//! without one runs no live output.
//!
//! [`Registries::live`]: crate::registry::Registries::live

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::codec::{Codec, Kind};
use crate::media::MediaFrame;
use crate::recording::{RecordingError, RecordingTrack};

/// The start of a live output: its init segment and the MIME type of what it
/// writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveInit {
    /// The init segment, ahead of every fragment.
    pub bytes: Bytes,
    /// The MIME type with the codecs the fragments carry (RFC 6381 §3.1:
    /// `video/mp4; codecs="avc1.640028,mp4a.40.2"`), so a player can ask
    /// whether it plays them before it fetches a byte.
    pub mime: String,
}

/// One fragment of a live output, and what a playlist says of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveFragment {
    /// The fragment's bytes, in order: slices the caller writes as they are.
    pub bytes: Vec<Bytes>,
    /// Whether its video starts with a keyframe: a player can start decoding
    /// at it.
    pub independent: bool,
    /// The decode time of its video, from the output's media time 0; for a
    /// fragment of audio alone, where the video so far ends.
    pub decode_time: Duration,
    /// How long its video lasts; zero for a fragment of audio alone.
    pub duration: Duration,
}

impl LiveFragment {
    /// The bytes the fragment holds.
    pub fn len(&self) -> usize {
        self.bytes
            .iter()
            .map(Bytes::len)
            .fold(0_usize, usize::saturating_add)
    }

    /// Whether it holds no byte.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a frame handed to a live writer became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveStep {
    /// The frame waits for the next one of its track: nothing is complete.
    Held,
    /// The frame completed a fragment: the one before it, and the audio up
    /// to it.
    Fragment(LiveFragment),
    /// The frame was left out: no video keyframe started the output yet, or
    /// since its last hole.
    Dropped,
}

/// One live container output, registered at startup behind its Cargo feature.
pub trait LiveMuxerFactory: fmt::Debug + Send + Sync {
    /// Whether the container can carry `codec` as the track has it: a live
    /// output leaves out audio it cannot.
    fn accepts(&self, codec: &Codec) -> bool;

    /// A writer for one live output.
    fn muxer(&self) -> Box<dyn LiveMuxer>;
}

/// One live output's container writer. Sans-IO, as a recording's
/// ([`crate::recording::RecordingMuxer`]): every call returns the bytes it
/// completed as slices of the frames' own payloads.
pub trait LiveMuxer: Send {
    /// The init segment for the output's tracks: the video, and the audio
    /// when it has one.
    fn start(
        &mut self,
        video: &RecordingTrack,
        audio: Option<&RecordingTrack>,
    ) -> Result<LiveInit, RecordingError>;

    /// Takes the next frame of the `track` kind, in the order the frames
    /// arrive.
    fn push(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<LiveStep, RecordingError>;

    /// A hole: the caller left frames out. The frames held are finished
    /// as they are and returned, if any (the video's last lasting until the
    /// audio ends, if that is later), and every frame from here on is
    /// [`LiveStep::Dropped`] until the next video keyframe, which starts
    /// the output again where it ends.
    fn skip(&mut self) -> Result<Option<LiveFragment>, RecordingError>;
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
    fn a_fragment_s_length_is_its_slices_and_none_is_empty() {
        let mut fragment = LiveFragment {
            bytes: vec![Bytes::from_static(b"moof"), Bytes::from_static(b"mdat!")],
            independent: true,
            decode_time: Duration::ZERO,
            duration: Duration::from_millis(40),
        };
        assert_eq!(fragment.len(), 9);
        assert!(!fragment.is_empty());
        fragment.bytes = vec![Bytes::new()];
        assert_eq!(fragment.len(), 0);
        assert!(fragment.is_empty());
    }
}

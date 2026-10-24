//! Fragmented MP4 for event clips: the [`ClipMuxer`] that writes one clip's
//! frames, H.264 or H.265 video and optionally AAC-LC or Opus audio, as
//! one fragmented MP4 file, and the [`Factory`] the binary registers.
//!
//! Runs in a worker, inside a clip task, on frames the worker's tracks
//! already accepted. Sans-IO and pure: every call returns the bytes it
//! completed and the caller writes them; no I/O, no clock (the frames'
//! capture times are the only time), no logging (the clip task logs the
//! clip). Depends on `lotse-core` (the clip contract, frames, codecs),
//! `lotse-codec` (parameter sets, NAL units, Opus packet lengths) and
//! mp4-atom, which encodes the boxes; never on a source or output crate
//! or a process crate.
//!
//! The file: an init segment (`ftyp`, `moov` with one track per clip
//! track and `mvex`), then one movie fragment (`moof` and `mdat`) at a
//! time. A fragment ends before every video keyframe, before a frame that
//! begins a new epoch of its track, once the clip policy's fragment span
//! of decode time has passed since it began, and once its media data
//! reach [`MAX_FRAGMENT_BYTES`]; [`ClipMuxer::finish`] writes the last.
//! The file is playable up to its last complete fragment whenever it
//! ends. Sample payloads go out as slices of the frames' own bytes, never
//! copied.
//!
//! Standards: ISO/IEC 14496-12 (ISO base media file format: the boxes,
//! movie fragments, sample flags, composition offsets), ISO/IEC 14496-14
//! (MP4: the `mp4a` sample entry and its `esds`), ISO/IEC 14496-15 (NAL
//! unit structured video: `avc1`/`avcC`, `hvc1`/`hvcC`, length-prefixed
//! samples), ISO/IEC 14496-1 §7.2.6.6 (the decoder configuration
//! descriptor) and ISO/IEC 14496-3 §1.6.2.1 (`AudioSpecificConfig`), and
//! "Encapsulation of Opus in ISO Base Media File Format" v0.8.1 (`Opus`
//! and `dOps`). Each module names its clauses.

mod fragment;
mod init;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lotse_core::clip::{ClipError, ClipMuxer, ClipMuxerFactory, ClipPolicy, ClipTrack};
use lotse_core::{Codec, Kind, MediaFrame};

use crate::fragment::TrackWriter;
use crate::init::{AUDIO_TRACK_ID, VIDEO_TRACK_ID};

/// The largest frame a sample takes: far above any camera's frame
/// (`limits.max_frame_bytes` defaults to 4 MiB), and small enough that a
/// sample's size, a length added per NAL unit, fits its 32-bit field
/// (ISO/IEC 14496-12 §8.8.8, `sample_size`).
pub const MAX_SAMPLE_BYTES: usize = 256 * 1024 * 1024;

/// The media data after which a fragment ends early. One more sample of
/// each track may follow it, so the run's data offset, a signed 32-bit
/// count from the `moof` (ISO/IEC 14496-12 §8.8.8, `data_offset`), always
/// fits.
pub const MAX_FRAGMENT_BYTES: u64 = 1024 * 1024 * 1024;

/// An mp4-atom encoding failure: a field the sample entry cannot carry.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the shape `map_err` calls it with"
)]
pub(crate) fn encode_failed(err: mp4_atom::Error) -> ClipError {
    ClipError::Failed(format!("mp4 encoding: {err}"))
}

/// The fragmented MP4 container: registered by the binary as the clip
/// output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Factory;

impl ClipMuxerFactory for Factory {
    /// H.264 and H.265 with their parameter sets, AAC-LC with its
    /// configuration, mono or stereo Opus.
    fn accepts(&self, codec: &Codec) -> bool {
        init::carries(codec)
    }

    fn muxer(&self, policy: &ClipPolicy) -> Box<dyn ClipMuxer> {
        Box::new(Muxer::new(policy))
    }
}

/// The bounds a muxer keeps; [`MAX_SAMPLE_BYTES`] and
/// [`MAX_FRAGMENT_BYTES`] outside the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    /// The largest frame a sample takes.
    sample_bytes: usize,
    /// The media data after which a fragment ends.
    fragment_bytes: u64,
}

/// Where a muxer is in its clip.
#[derive(Debug)]
enum State {
    /// Before [`ClipMuxer::start`].
    Idle,
    /// Between the start and the finish.
    Running(Box<Clip>),
    /// After [`ClipMuxer::finish`], or a finish without a start.
    Finished,
}

/// The clip a running muxer writes.
#[derive(Debug)]
struct Clip {
    /// The video track.
    video: TrackWriter,
    /// The audio track, when the clip has one.
    audio: Option<TrackWriter>,
    /// The capture time of the clip's first frame: decode time 0.
    origin: Option<Instant>,
    /// The decode time of the frame the current fragment began with, on
    /// its track: the fragment's span counts from it. Decode times, not
    /// capture times: a track's never go back (see the [`fragment`]
    /// module), and inside an epoch they follow the timestamps, so a
    /// capture time a Sender Report put ahead and a later one corrected
    /// back, which the clip's interleaver takes, cannot hold the next cut
    /// until the capture times catch up.
    began: Option<Duration>,
    /// The sequence number of the latest fragment (ISO/IEC 14496-12
    /// §8.8.5): 0 before the first.
    sequence: u32,
}

impl Clip {
    /// A clip of `video` and `audio` before its first frame.
    fn new(video: &ClipTrack, audio: Option<&ClipTrack>) -> Self {
        Self {
            video: TrackWriter::new(VIDEO_TRACK_ID, Kind::Video, video),
            audio: audio.map(|audio| TrackWriter::new(AUDIO_TRACK_ID, Kind::Audio, audio)),
            origin: None,
            began: None,
            sequence: 0,
        }
    }

    /// Takes `frame` of the `kind` track; the fragment it completed, if
    /// any.
    fn push(
        &mut self,
        kind: Kind,
        frame: Arc<MediaFrame>,
        span: Duration,
        fragment_bytes: u64,
    ) -> Result<Vec<Bytes>, ClipError> {
        let origin = *self.origin.get_or_insert(frame.wallclock);
        let keyframe = frame.keyframe;
        let track = match kind {
            Kind::Video => &mut self.video,
            Kind::Audio => self.audio.as_mut().ok_or_else(|| {
                ClipError::Failed("an audio frame for a clip without audio".into())
            })?,
        };
        let anchored = track.push(frame, origin)?;
        let at = track.decode_time();
        let began = *self.began.get_or_insert(at);
        let ready = self
            .video
            .ready_bytes()
            .saturating_add(self.audio.as_ref().map_or(0, TrackWriter::ready_bytes));
        let cut = anchored
            || (kind == Kind::Video && keyframe)
            || at.saturating_sub(began) >= span
            || ready >= fragment_bytes;
        if !cut {
            return Ok(Vec::new());
        }
        let out = self.fragment()?;
        if !out.is_empty() {
            self.began = Some(at);
        }
        Ok(out)
    }

    /// The fragment of the samples ready, if any.
    fn fragment(&mut self) -> Result<Vec<Bytes>, ClipError> {
        let mut runs = vec![self.video.take_ready()];
        runs.extend(self.audio.as_mut().map(TrackWriter::take_ready));
        let sequence = self.sequence.wrapping_add(1);
        let out = fragment::fragment(sequence, &runs)?;
        if !out.is_empty() {
            self.sequence = sequence;
        }
        Ok(out)
    }

    /// Finishes every track's last sample and writes the last fragment.
    fn finish(&mut self) -> Result<Vec<Bytes>, ClipError> {
        self.video.close();
        if let Some(audio) = &mut self.audio {
            audio.close();
        }
        self.fragment()
    }
}

/// One clip's fragmented MP4 writer.
#[derive(Debug)]
pub struct Muxer {
    /// The longest a fragment spans.
    span: Duration,
    /// The bounds it keeps.
    limits: Limits,
    /// Where it is.
    state: State,
}

impl Muxer {
    /// A muxer whose fragments span at most `policy.fragment`.
    pub fn new(policy: &ClipPolicy) -> Self {
        Self {
            span: policy.fragment,
            limits: Limits {
                sample_bytes: MAX_SAMPLE_BYTES,
                fragment_bytes: MAX_FRAGMENT_BYTES,
            },
            state: State::Idle,
        }
    }

    /// The error of a call out of order.
    fn out_of_order(call: &str) -> ClipError {
        ClipError::Failed(format!("{call} out of order"))
    }
}

impl ClipMuxer for Muxer {
    fn start(
        &mut self,
        video: &ClipTrack,
        audio: Option<&ClipTrack>,
    ) -> Result<Vec<Bytes>, ClipError> {
        if !matches!(self.state, State::Idle) {
            return Err(Self::out_of_order("start"));
        }
        let init = init::init_segment(video, audio)?;
        self.state = State::Running(Box::new(Clip::new(video, audio)));
        Ok(vec![init])
    }

    fn push(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<Vec<Bytes>, ClipError> {
        let State::Running(clip) = &mut self.state else {
            return Err(Self::out_of_order("push"));
        };
        let bytes = frame.payload.len();
        if bytes > self.limits.sample_bytes {
            return Err(ClipError::Failed(format!(
                "a frame of {bytes} bytes is larger than a sample may be ({})",
                self.limits.sample_bytes
            )));
        }
        clip.push(track, frame, self.span, self.limits.fragment_bytes)
    }

    fn media_time(&self, track: Kind) -> Duration {
        let State::Running(clip) = &self.state else {
            return Duration::ZERO;
        };
        match track {
            Kind::Video => clip.video.media_time(),
            Kind::Audio => clip
                .audio
                .as_ref()
                .map_or(Duration::ZERO, TrackWriter::media_time),
        }
    }

    fn finish(&mut self) -> Result<Vec<Bytes>, ClipError> {
        let State::Running(mut clip) = std::mem::replace(&mut self.state, State::Finished) else {
            return Err(Self::out_of_order("finish"));
        };
        clip.finish()
    }
}

#[cfg(test)]
mod tests;

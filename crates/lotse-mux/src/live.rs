//! Live fragmented MP4: the [`LiveWriter`] that turns a stream's live frames
//! into an init segment and one movie fragment per video frame, for a
//! player that plays them as they come, and the [`LiveFactory`] the binary
//! registers.
//!
//! The boxes are a recording's (see [`crate::init`] and [`crate::fragment`]):
//! the same init segment and the same `moof`+`mdat` fragments, the samples'
//! timing and parameter sets alike. What differs is where a fragment ends
//! and where the timeline goes after a hole:
//!
//! - The output starts at a video keyframe; frames before it, video or
//!   audio, are left out ([`LiveStep::Dropped`]).
//! - Each video frame is held until the next one arrives, which gives its
//!   duration, as in a recording; then it goes out in a fragment of its own,
//!   with the audio finished up to then (ISO/IEC 14496-12 §8.8.4: a
//!   fragment may hold any number of samples, one included). So a fragment
//!   is out one frame interval after its frame arrived, never later. A
//!   fragment starting with a keyframe is [`LiveFragment::independent`]: its
//!   first sample is a sync sample (§8.8.3.1).
//! - The audio of a stream whose video stops goes out alone once it spans
//!   [`AUDIO_FRAGMENT_SPAN`] or holds [`AUDIO_FRAGMENT_BYTES`], so it is
//!   held for no longer and no more than that.
//! - The decode and the presentation times run on without a hole: after a
//!   hole the caller made ([`LiveMuxer::skip`]) or a reconnect (a video
//!   keyframe of another epoch), the next video keyframe starts a new
//!   epoch where the output so far ends, and the output's media time 0
//!   moves to the capture time that puts the keyframe there (on by the
//!   time left out, or back when the keyframe was captured before that),
//!   so the audio after it keeps its place beside the video by capture
//!   time. A player so never meets a gap in what it buffers. The output
//!   ends where the video's presentation ends: the last video frame
//!   before the hole lasts the frame before it's duration, as a
//!   recording's last frame does, or until the audio ends if that is
//!   later (audio that went out alone while the video stalled), the
//!   frame on screen while that audio plays. Reordered video is decoded
//!   past where it is presented: the keyframe is decoded where that
//!   decode ends, ahead of its presentation by a negative composition
//!   offset (ISO/IEC 14496-12 §8.8.8), as a recording's epoch is.
//! - Until the video started again, the audio is left out: after a skip,
//!   and for audio of a new epoch until the video's first keyframe after
//!   that epoch's first audio frame, whether the audio before was taken
//!   or left out. The audio's first epoch is the stream's own, whatever
//!   keyframe it comes after: a writer that saw no audio before cannot
//!   tell a reconnect's from it. Placed by the origin of then, it is
//!   still followed by the video, whose last frame lasts until it ends.
//!
//! Sans-IO and pure, as the recording muxer: no I/O, no clock (the frames'
//! capture times are the only time), no logging (the caller logs).

use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::live::{LiveFragment, LiveInit, LiveMuxer, LiveMuxerFactory, LiveStep};
use lotse_core::recording::{RecordingError, RecordingTrack};
use lotse_core::{Codec, Kind, MediaFrame};

use crate::fragment::{self, TrackWriter};
use crate::init::{self, AUDIO_TRACK_ID, VIDEO_TRACK_ID};
use crate::{MAX_SAMPLE_BYTES, out_of_order};

/// The longest a fragment of audio alone spans: the audio of a stream whose
/// video stopped goes out at least this often.
pub const AUDIO_FRAGMENT_SPAN: Duration = Duration::from_millis(500);

/// The most what the audio's samples hold before they go out alone, their
/// payloads and what describes them: a camera sending large audio frames
/// a tick apart cannot make one fragment hold more.
pub const AUDIO_FRAGMENT_BYTES: u64 = 1024 * 1024;

/// The live fragmented MP4 container: registered by the binary as the live
/// output's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiveFactory;

impl LiveMuxerFactory for LiveFactory {
    /// The recording's codecs: H.264 and H.265 with their parameter sets,
    /// AAC-LC with its configuration, mono or stereo Opus.
    fn accepts(&self, codec: &Codec) -> bool {
        init::carries(codec)
    }

    fn muxer(&self) -> Box<dyn LiveMuxer> {
        Box::new(LiveWriter::new())
    }
}

/// The bounds a live writer keeps; outside the tests [`MAX_SAMPLE_BYTES`],
/// [`AUDIO_FRAGMENT_SPAN`] and [`AUDIO_FRAGMENT_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    /// The largest frame a sample takes.
    sample_bytes: usize,
    /// The longest the audio's samples span before they go out alone.
    audio_span: Duration,
    /// The most the audio's samples hold before they go out alone.
    audio_bytes: u64,
}

/// One live output's tracks and where its timeline is.
#[derive(Debug)]
struct Live {
    /// The video track.
    video: TrackWriter,
    /// The audio track, when the output has one.
    audio: Option<TrackWriter>,
    /// The output's media time 0 as a capture time: the first keyframe's,
    /// moved at every start of the video after it ([`Live::start_at`]);
    /// `None` before the first.
    origin: Option<Instant>,
    /// Whether the output waits for a video keyframe: before the first,
    /// and after a skip.
    waiting: bool,
    /// The epoch of the video's frames since its latest keyframe started
    /// it.
    video_epoch: Option<u32>,
    /// The epoch of the latest audio frame, taken or left out; `None`
    /// before the first.
    audio_epoch: Option<u32>,
    /// How often the video started: at the first keyframe and after each
    /// hole.
    starts: u64,
    /// [`Live::starts`] when the audio's epoch began, 0 for its first: the
    /// audio is taken once the video started after that. Before, audio of
    /// a new epoch would be placed by an origin the video's next start
    /// moves.
    audio_since: u64,
    /// The sequence number of the latest fragment (ISO/IEC 14496-12
    /// §8.8.5): 0 before the first.
    sequence: u32,
}

impl Live {
    /// An output of `video` and `audio` before its first keyframe.
    fn new(video: &RecordingTrack, audio: Option<&RecordingTrack>) -> Self {
        Self {
            video: TrackWriter::new(VIDEO_TRACK_ID, Kind::Video, video),
            audio: audio.map(|audio| TrackWriter::new(AUDIO_TRACK_ID, Kind::Audio, audio)),
            origin: None,
            waiting: true,
            video_epoch: None,
            audio_epoch: None,
            starts: 0,
            audio_since: 0,
            sequence: 0,
        }
    }

    /// Ends both tracks' epochs here (see [`TrackWriter::break_epoch`]):
    /// the audio's, then the video's, whose last frame is presented until
    /// the audio ends, if that is later. The video's presentation so ends
    /// where the output does.
    fn break_epochs(&mut self) {
        let until = self.audio.as_mut().map_or(Duration::ZERO, |audio| {
            audio.break_epoch(Duration::ZERO);
            audio.presented_end()
        });
        self.video.break_epoch(until);
    }

    /// Takes a video frame.
    fn push_video(&mut self, frame: Arc<MediaFrame>) -> Result<LiveStep, RecordingError> {
        let new_epoch = self.video_epoch != Some(frame.epoch);
        if !(self.waiting || new_epoch) {
            // A started output has its origin.
            let origin = self.origin.unwrap_or(frame.wallclock);
            self.video.push(frame, origin)?;
            // The frame before it is finished now: its fragment, if any.
            return self.ready(true);
        }
        if !frame.keyframe {
            return Ok(LiveStep::Dropped);
        }
        if !self.waiting {
            // A keyframe of another epoch: the camera reconnected.
            self.break_epochs();
        }
        let origin = self.start_at(&frame);
        self.waiting = false;
        self.video_epoch = Some(frame.epoch);
        self.starts = self.starts.saturating_add(1);
        // The samples the break finished go out before the keyframe is
        // taken, which a fragment of its own carries once the next frame
        // comes.
        let step = self.ready(true)?;
        self.video.push(frame, origin)?;
        Ok(step)
    }

    /// The output's media time 0 for a keyframe that starts the video
    /// (again) at `frame`: its own capture time for the first; else the
    /// capture time that puts the keyframe where the output so far ends,
    /// the video's presentation after [`Live::break_epochs`]. That leaves
    /// the hole out of the timeline, or moves the origin back when the
    /// keyframe was captured before that end, so the audio captured after
    /// the keyframe follows it by as much. The video's decode may end
    /// later (reordered video), which its track's epoch takes up.
    fn start_at(&mut self, frame: &MediaFrame) -> Instant {
        let origin = match self.origin {
            None => frame.wallclock,
            Some(origin) => {
                let end = self.video.presented_end();
                // Only a capture time before the clock's own start has
                // none: the origin stays.
                frame.wallclock.checked_sub(end).unwrap_or(origin)
            }
        };
        self.origin = Some(origin);
        origin
    }

    /// Takes an audio frame; its samples go out alone once they reach
    /// `limits`.
    fn push_audio(
        &mut self,
        frame: Arc<MediaFrame>,
        limits: &Limits,
    ) -> Result<LiveStep, RecordingError> {
        let Some(audio) = self.audio.as_mut() else {
            return Err(RecordingError::Failed(
                "an audio frame for a live output without audio".into(),
            ));
        };
        if self.audio_epoch != Some(frame.epoch) {
            // The first epoch is the stream's own; a later one is a
            // reconnect's, whose video starts again after it.
            self.audio_since = self.audio_epoch.map_or(0, |_| self.starts);
            self.audio_epoch = Some(frame.epoch);
        }
        // The video's starts break the audio's epoch too: the audio after
        // one starts a new epoch on its track.
        let started = !self.waiting && self.audio_since < self.starts;
        let Some(origin) = self.origin.filter(|_| started) else {
            return Ok(LiveStep::Dropped);
        };
        audio.push(frame, origin)?;
        let full = audio.ready_bytes() >= limits.audio_bytes
            || audio
                .ready_span()
                .is_some_and(|(from, to)| to.saturating_sub(from) >= limits.audio_span);
        self.ready(full)
    }

    /// The fragment of the samples ready when `due`, if any; else the frame
    /// waits.
    fn ready(&mut self, due: bool) -> Result<LiveStep, RecordingError> {
        if !due {
            return Ok(LiveStep::Held);
        }
        Ok(self.fragment()?.map_or(LiveStep::Held, LiveStep::Fragment))
    }

    /// The fragment of the samples ready, if any.
    fn fragment(&mut self) -> Result<Option<LiveFragment>, RecordingError> {
        let independent = self.video.ready_starts_with_sync();
        let (decode_time, end) = self.video.ready_span().unwrap_or_else(|| {
            let end = self.video.decode_end();
            (end, end)
        });
        let mut runs = vec![self.video.take_ready()];
        runs.extend(self.audio.as_mut().map(TrackWriter::take_ready));
        let sequence = self.sequence.wrapping_add(1);
        let bytes = fragment::fragment(sequence, &runs)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        self.sequence = sequence;
        Ok(Some(LiveFragment {
            bytes,
            independent,
            decode_time,
            duration: end.saturating_sub(decode_time),
        }))
    }
}

/// One live output's fragmented MP4 writer.
#[derive(Debug)]
pub struct LiveWriter {
    /// The bounds it keeps.
    limits: Limits,
    /// The output, once started.
    live: Option<Box<Live>>,
}

impl Default for LiveWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveWriter {
    /// A writer with the documented bounds.
    pub const fn new() -> Self {
        Self::with_limits(Limits {
            sample_bytes: MAX_SAMPLE_BYTES,
            audio_span: AUDIO_FRAGMENT_SPAN,
            audio_bytes: AUDIO_FRAGMENT_BYTES,
        })
    }

    /// A writer that keeps `limits`.
    const fn with_limits(limits: Limits) -> Self {
        Self { limits, live: None }
    }
}

impl LiveMuxer for LiveWriter {
    fn start(
        &mut self,
        video: &RecordingTrack,
        audio: Option<&RecordingTrack>,
    ) -> Result<LiveInit, RecordingError> {
        if self.live.is_some() {
            return Err(out_of_order("start"));
        }
        let bytes = init::init_segment(video, audio)?;
        let codecs = init::codecs(&video.codec, audio.map(|audio| &audio.codec))?;
        self.live = Some(Box::new(Live::new(video, audio)));
        Ok(LiveInit {
            bytes,
            mime: format!("video/mp4; codecs=\"{codecs}\""),
        })
    }

    fn push(&mut self, track: Kind, frame: Arc<MediaFrame>) -> Result<LiveStep, RecordingError> {
        let Some(live) = self.live.as_mut() else {
            return Err(out_of_order("push"));
        };
        let bytes = frame.payload.len();
        if bytes > self.limits.sample_bytes {
            return Err(RecordingError::Failed(format!(
                "a frame of {bytes} bytes is larger than a sample may be ({})",
                self.limits.sample_bytes
            )));
        }
        match track {
            Kind::Video => live.push_video(frame),
            Kind::Audio => live.push_audio(frame, &self.limits),
        }
    }

    fn skip(&mut self) -> Result<Option<LiveFragment>, RecordingError> {
        let Some(live) = self.live.as_mut() else {
            return Err(out_of_order("skip"));
        };
        if live.waiting {
            return Ok(None);
        }
        live.break_epochs();
        live.waiting = true;
        live.fragment()
    }
}

#[cfg(test)]
mod tests;

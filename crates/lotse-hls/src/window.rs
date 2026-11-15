//! The live window: the Media Segments and Partial Segments of one live
//! output, built from its fragments as they come, and what a request for
//! one of them, or for the playlist, gets.
//!
//! # Parts and segments
//!
//! A fragment is one video frame (and the audio up to it) and is never split,
//! so a Partial Segment (draft-pantos-hls-rfc8216bis-22 §3.2) is a run of
//! whole fragments and a Media Segment the run of its parts (§3.2: "A Parent
//! Segment and its entire set of Partial Segments MUST contain the same set
//! of media samples"). The window starts at the first independent fragment
//! and drops the fragments before it.
//!
//! - A part closes as soon as one more fragment as long as the last would
//!   take it past the part limit, so it is published the moment its last
//!   frame is in, not when the next arrives; and a part closes before a
//!   fragment that would take it past the limit. A part so lasts at most
//!   the limit (§4.4.4.9: "MUST be less than or equal to the Part Target
//!   Duration"), unless one fragment alone is longer, and with regular
//!   frames it lasts as many whole frames as fit, which keeps it above 85 %
//!   of the limit (§4.4.4.9) for any frame interval below 15 % of it.
//! - A segment ends before an independent fragment once it lasts the
//!   segment target or longer, or falls short of it by no more than
//!   [`JITTER`] (a second of 30 frames of 90 kHz ticks sums to 10 ns short
//!   of one): every segment starts with a keyframe
//!   (§4.4.2.1, `EXT-X-INDEPENDENT-SEGMENTS`; §6.2.1: "divide the source
//!   media at points that support effective decode"), its last part closes
//!   with it (exempt from the 85 %, §4.4.4.9), and it lasts the target or
//!   more: one keyframe interval when keyframes are further apart than the
//!   target.
//! - A part is `INDEPENDENT=YES` when it holds an independent fragment
//!   (§4.4.4.9: "if the Partial Segment contains an independent frame"); the
//!   first part of every segment does.
//! - A fragment of audio alone lasts zero and joins the open part: it never
//!   closes one.
//!
//! The decode times of the fragments run on without a hole, so the playlist
//! needs no `EXT-X-DISCONTINUITY` (§6.2.1: timing and encoding changes are
//! what it signals; an encoding change starts a new output, so a new
//! window), and no `EXT-X-GAP`.
//!
//! # The targets a playlist holds to
//!
//! Nothing is published before the first segment is complete. Its parts and
//! its duration set the Part Target Duration and the Target Duration every
//! playlist after holds to (§6.2.1: "The value of the EXT-X-TARGETDURATION
//! tag in the Media Playlist MUST NOT change"; `EXT-X-PART-INF` is not among
//! what §6.2.1 lets a server change either):
//!
//! - The Target Duration is the first segment's duration rounded to the
//!   nearest second (round half up), at least 1 (§4.4.3.1: each EXTINF
//!   "when rounded to the nearest integer, MUST be less than or equal to the
//!   Target Duration"; "Its value MUST be at least 1").
//! - The Part Target Duration is the first segment's longest part plus
//!   [`JITTER`], rounded up to the millisecond; until then parts close at
//!   the configured part target plus [`JITTER`]. Frame durations differ by
//!   the nanoseconds of a timestamp's conversion (3000 ticks of 90 kHz are
//!   33 333 333.3 ns) and by a camera's clock: the measured target fits the
//!   frame interval (29.97 frames a second make 6-frame parts of 200.2 ms
//!   under a 200 ms target, advertised as 202 ms, not 5-frame parts of
//!   166.8 ms, 83 % of 200), and the millisecond above it keeps a part that
//!   is a few nanoseconds longer from closing a frame early.
//!
//! SPEC-DEVIATION (§6.2.1, "MUST NOT change"): when a later segment, after
//! rounding, lasts longer than the Target Duration (a camera's keyframe
//! interval grew), the Target Duration rises to it, and when a later part
//! lasts longer than the Part Target Duration (a single frame longer than
//! the whole target: the frame rate fell), the Part Target Duration rises
//! to it, as the first one was set. The alternative breaks §4.4.3.1's and
//! §4.4.4.9's upper bounds, which §4.4.3.1 says "can trigger playback
//! stalls", or cuts a segment without a keyframe. A lower frame rate can
//! also make parts shorter than 85 % of the Part Target Duration
//! (§4.4.4.9), and a camera whose frame durations jitter by more than
//! [`JITTER`] can too; a part is whole frames and cannot be stretched.
//!
//! # What the window holds
//!
//! The window has no wall clock: its clock is the media it took, the sum of
//! its fragments' durations, read after each push. A live writer sends a
//! fragment once the next frame tells how long it lasts, so at its end, and
//! the clock so runs with the camera's.
//!
//! The playlist lists the last [`Config::segments`] complete segments. A
//! complete segment's `EXT-X-PART` tags are listed, all of them, while its
//! end is within three Target Durations of the playlist's (its last closed
//! part's), and leave together at the push that takes it further, or with
//! the segment when it is delisted first. §6.2.2: "EXT-X-PART tags SHOULD
//! be removed from the Playlist after they are greater than three Target
//! Durations from the end of the Playlist". A client knows a part's Part
//! Index (§3.2: "the position of the Partial Segment within its Parent
//! Segment. The first Partial Segment has a Part Index of zero") only by
//! counting its parent's tags: hls.js 1.7.4 (`src/loader/m3u8-parser.ts`,
//! read 2026-11-15) numbers the `EXT-X-PART` tags after a segment's URI from
//! 0 and places the first at its parent's start, so a parent listed without
//! its first parts would have the rest misnumbered and mistimed.
//! SPEC-DEVIATION (§6.2.2, the SHOULD): a parent's first parts so keep their
//! tags up to one segment longer than three Target Durations from the end.
//! The open segment's parts are always listed.
//!
//! A delisted segment is still served (not listed) until the later of two
//! deadlines, both of §6.2.2, and then retired at the first push that takes
//! the clock to it:
//!
//! - "clients MUST be able to download the segment until the time at which
//!   it first appeared in the Playlist plus the segment's Availability
//!   Duration", which is "the duration of the segment plus the duration of
//!   the longest-duration Playlist distributed by the server containing that
//!   segment": the clock when it completed, plus its duration, plus the
//!   longest sum of the segments' durations (§4.1: "The duration of a Media
//!   Playlist is the sum of the durations of the Media Segments within it")
//!   of a playlist that listed it;
//! - "Clients MUST be able to download the Partial Segment for at least
//!   three Target Durations after the EXT-X-PART tag is removed from the
//!   Playlist": the clock when its part tags left, plus three Target
//!   Durations. A part is served as long as its segment.
//!
//! Segments of one Target Duration each are so served about one segment
//! past their delisting; segments of differing durations, or shorter than
//! the Target Duration, longer.
//!
//! Media past [`Config::max_bytes`] drops the oldest segments first, the
//! delisted ones, then the listed ones; the open segment is never dropped,
//! and a fragment that would make it hold more than the cap alone ends the
//! window ([`PushError::Overflow`]): a stream whose keyframes are that far
//! apart cannot be served as segments that start with one.
//!
//! SPEC-DEVIATION (§6.2.2, "MUST NOT remove a Media Segment ... if that
//! would produce a Playlist whose duration is less than three times the
//! Target Duration", and the deadlines above): the segment count and the
//! byte cap are hard bounds on the supervisor's memory; the count delists
//! a segment however short the playlist then is, and the cap drops one
//! before its deadline. The defaults keep about six Target Durations when
//! segments last one each, which they do when the keyframe interval is the
//! segment target or longer. And the deadlines are wall-clock times that
//! the window reads off its media: a source that sends media faster than
//! real time retires segments early by as much.
//!
//! The window is sans-IO and has no other clock: a blocked request
//! ([`Window::reload`], [`Window::get`]) is the caller's to hold, to wake
//! when [`Window::push`] publishes ([`Pushed::Published`]) and to time out.

mod playlist;

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;

use crate::name::Resource;
use crate::query::Blocking;

/// The part target a window closes parts at by default, until its first
/// segment measures the Part Target Duration: 200 ms, whole frames each (5
/// at 25 frames a second, 6 at 30, 3 at 15, 2 at 10).
///
/// Lower latency comes at the price of more requests: a client holds back
/// three of them (`PART-HOLD-BACK`, draft-pantos-hls-rfc8216bis-22
/// §4.4.3.8), 600 ms, and makes a blocking playlist request and a part
/// request per part, five a second. MediaMTX 1.21.3 defaults to the same
/// (`hlsPartDuration: 200ms` in its `mediamtx.yml`, read 2026-11-15). NOTE:
/// chosen by reasoning, not measured; the browser test (a later change)
/// measures the latency a browser plays at.
pub const DEFAULT_PART_TARGET: Duration = Duration::from_millis(200);

/// The segment target a window ends segments at by default: 1 s, so a
/// segment is one keyframe interval for the 1 to 2 s that the Low-Latency
/// profile recommends (draft-pantos-hls-rfc8216bis-22 Appendix B.1: "The
/// recommended GOP size is between one and two seconds") and longer ones,
/// and two or more intervals of shorter ones. Shorter segments make a
/// window hold less, and they shorten what follows from the Target
/// Duration: how long a blocked request may wait (§6.2.5.2) and how far
/// back part tags are listed (§6.2.2). Latency comes from the parts, not
/// the segments. MediaMTX 1.21.3 defaults to the same (`hlsSegmentDuration:
/// 1s`, read 2026-11-15).
pub const DEFAULT_SEGMENT_TARGET: Duration = Duration::from_secs(1);

/// The complete segments a playlist lists by default: 6. With segments of
/// one Target Duration each, a playlist of 6 Target Durations, at least the
/// 3 §6.2.2 asks of one, and one delisted segment still served (see the
/// module docs), so the window holds 7 segments and the open one; a part's
/// tag is listed for about 3 Target Durations and the part served for 3
/// more (§6.2.2) within those 7. MediaMTX 1.21.3 keeps 7 (`hlsSegmentCount:
/// 7`, read 2026-11-15).
pub const DEFAULT_SEGMENTS: usize = 6;

/// The media a window holds at most by default, accounted as
/// [`Window::bytes`] counts it: 32 MiB, the default window of 2 s segments
/// (7 and the open one, see [`DEFAULT_SEGMENTS`]) of a stream of up to
/// about 16 Mbit/s.
pub const DEFAULT_MAX_BYTES: usize = 32 * 1024 * 1024;

/// What a fragment costs the window beyond its bytes: 1 KiB, an upper bound
/// of what the window allocates for one fragment in the worst case, a
/// fragment that is its own part and its own segment (every fragment
/// independent under a zero segment target). On the 64-bit targets:
///
/// - its handle, a `Bytes` of 32 bytes, in its part's slices: a `Vec`
///   allocates room for 4 elements at its first push (`RawVec`'s minimum
///   non-zero capacity for elements of up to 1 KiB) and doubles when full,
///   so 4 handles, 128 bytes;
/// - its part, 56 bytes, in its segment's parts, 4 likewise: 224 bytes;
/// - its segment, 120 bytes, in the listed queue and, delisted, 136 bytes in
///   the delisted queue, each twice over: a `VecDeque` doubles when full
///   and never shrinks, so it holds up to twice the most segments it held,
///   which the cap bounds: 512 bytes;
/// - the shared header a `Bytes` of a `Vec` allocates when cloned (3 words,
///   24 bytes), and an allocator's header of 16 bytes on each of the 4
///   allocations it costs alone (its buffer, that header, its part's slices
///   and its segment's parts): 88 bytes.
///
/// 952 bytes in all (a test checks the sum against the types' sizes),
/// rounded up. A fragment of no byte so still counts, and the byte cap
/// bounds the memory a window takes however small the fragments a worker
/// sends are.
pub const FRAGMENT_OVERHEAD: usize = 1024;

/// What a part's duration may exceed its target by before it closes a frame
/// early, and a segment's may fall short of its target by and still be at
/// it: frame durations differ by rounding and a camera's clock.
pub const JITTER: Duration = Duration::from_millis(1);

/// The nanoseconds of a millisecond.
const NANOS_PER_MILLISECOND: u128 = 1_000_000;

/// One second: the Advance Part Limit is counted in seconds of parts below
/// it, in parts above (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
const ONE_SECOND: Duration = Duration::from_secs(1);

/// "three": the Advance Part Limit, in parts at a Part Target Duration of a
/// second or more, in seconds of parts below (draft-pantos-hls-rfc8216bis-22
/// §6.2.5.2).
const ADVANCE_PART_LIMIT: u64 = 3;

/// How far from the playlist's end, in Target Durations, a complete
/// segment's end is while its part tags are listed: "EXT-X-PART tags SHOULD
/// be removed from the Playlist after they are greater than three Target
/// Durations from the end of the Playlist" (draft-pantos-hls-rfc8216bis-22
/// §6.2.2).
const PART_TAG_TARGET_DURATIONS: u32 = 3;

/// How long, in Target Durations, a part is served after its tag left the
/// playlist: "at least three Target Durations after the EXT-X-PART tag is
/// removed from the Playlist" (draft-pantos-hls-rfc8216bis-22 §6.2.2).
const PART_SERVED_TARGET_DURATIONS: u32 = 3;

/// One fragment of a live output: its bytes, opaque here, and what a playlist
/// says of it.
///
/// The window's own type, not the worker's `LiveFragment`: the supervisor,
/// which holds the window, receives each fragment from the worker as one
/// buffer with what describes it and never parses camera bytes, and the
/// window needs no decode time, which runs on without a hole (the durations
/// add up to it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// The fragment's bytes (a `moof` and its `mdat`), served as they are.
    pub bytes: Bytes,
    /// Whether it starts with a video keyframe: a segment may start at it.
    pub independent: bool,
    /// How long its video lasts; zero for a fragment of audio alone.
    pub duration: Duration,
}

/// How a window cuts and bounds its segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The duration a part closes at until the first segment measures the
    /// Part Target Duration ([`DEFAULT_PART_TARGET`]); non-zero.
    pub part_target: Duration,
    /// The duration after which the next independent fragment starts a new
    /// segment ([`DEFAULT_SEGMENT_TARGET`]); zero starts one at every
    /// independent fragment.
    pub segment_target: Duration,
    /// The complete segments the playlist lists ([`DEFAULT_SEGMENTS`]);
    /// non-zero.
    pub segments: usize,
    /// The most media the window holds, as [`Window::bytes`] counts it
    /// without the init segment ([`DEFAULT_MAX_BYTES`]); non-zero.
    pub max_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            part_target: DEFAULT_PART_TARGET,
            segment_target: DEFAULT_SEGMENT_TARGET,
            segments: DEFAULT_SEGMENTS,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// A [`Config`] a window cannot run with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The part target is zero: every part would close at once.
    #[error("the part target is zero")]
    ZeroPartTarget,
    /// The playlist would list no segment.
    #[error("the window lists no segment")]
    NoSegments,
    /// The byte cap is zero: no fragment fits.
    #[error("the window's byte cap is zero")]
    ZeroMaxBytes,
}

/// Why a window takes no more fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    /// The open segment would hold more than the byte cap: the stream sends
    /// no keyframe for longer than the window can hold. The window takes no
    /// fragment from here on and still serves what it holds; the caller ends
    /// it.
    #[error("the open segment would hold more than the window's {max_bytes} bytes")]
    Overflow {
        /// The window's byte cap.
        max_bytes: usize,
    },
}

/// What a fragment pushed to a window became.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// Left out: no independent fragment started the window yet.
    Dropped,
    /// Held in the open part: nothing new to serve.
    Held,
    /// A part closed, or a segment with it: the playlist changed, and
    /// blocked requests may be served.
    Published,
}

/// What a playlist request gets now (draft-pantos-hls-rfc8216bis-22
/// §6.2.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reload {
    /// The playlist ([`Window::playlist`]), now.
    Ready,
    /// Nothing yet: ask again when a push publishes. §6.2.5.2: a server that
    /// cannot answer within three Target Durations SHOULD return Service
    /// Unavailable ([`Window::target_duration`]).
    Wait,
    /// Bad Request: the request asks for a segment or part too far ahead.
    BadRequest,
}

/// What a request for one of a window's resources gets now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The resource's bytes.
    Ready(Chunks),
    /// The part a playlist's `EXT-X-PRELOAD-HINT` names, not complete yet:
    /// ask again when a push publishes (draft-pantos-hls-rfc8216bis-22
    /// §4.4.5.3: "The server will hold onto the request ("block") until it
    /// can respond").
    Wait,
    /// Not held: out of the window, never made, or not hinted (§6.2.6: "The
    /// server SHOULD respond with "Not Found" ... to a request for a resource
    /// that it cannot find and that is not specified by an
    /// EXT-X-PRELOAD-HINT tag").
    NotFound,
}

/// A resource's bytes, as the slices the window holds: clones of its
/// buffers, never copies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chunks {
    /// The slices, in order.
    chunks: Vec<Bytes>,
    /// Their total length.
    len: usize,
}

impl Chunks {
    /// The bytes in all, for a `Content-Length`.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether it holds no byte.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The slices, in order.
    pub fn as_slice(&self) -> &[Bytes] {
        &self.chunks
    }

    /// The slices, in order, to write out.
    pub fn into_vec(self) -> Vec<Bytes> {
        self.chunks
    }

    /// Appends one slice.
    fn push(&mut self, chunk: Bytes) {
        self.len = self.len.saturating_add(chunk.len());
        self.chunks.push(chunk);
    }
}

impl From<Bytes> for Chunks {
    fn from(bytes: Bytes) -> Self {
        let mut chunks = Self::default();
        chunks.push(bytes);
        chunks
    }
}

/// A run of whole fragments: a Partial Segment once closed, the open part
/// before.
#[derive(Debug, Default)]
struct Part {
    /// Its fragments' bytes.
    chunks: Chunks,
    /// The sum of its fragments' durations.
    duration: Duration,
    /// Whether one of its fragments is independent.
    independent: bool,
}

impl Part {
    /// Appends a fragment.
    fn push(&mut self, fragment: Fragment) {
        self.chunks.push(fragment.bytes);
        self.duration = self.duration.saturating_add(fragment.duration);
        self.independent |= fragment.independent;
    }
}

/// A Media Segment: complete, or the open one, whose parts are the ones
/// closed so far.
#[derive(Debug)]
struct Segment {
    /// Its Media Sequence Number.
    msn: u64,
    /// Its closed parts, in order.
    parts: Vec<Part>,
    /// The sum of its closed parts' durations.
    duration: Duration,
    /// What it costs the window ([`FRAGMENT_OVERHEAD`]), its open part's
    /// fragments included.
    cost: usize,
    /// Where it starts on the window's clock: the clock before its first
    /// fragment.
    start: Duration,
    /// The window's clock when it completed and first appeared in the
    /// playlist; zero while open.
    appeared: Duration,
    /// The duration of the longest playlist that listed it, the sum of its
    /// segments' durations (draft-pantos-hls-rfc8216bis-22 §4.1); zero while
    /// open.
    longest: Duration,
    /// The window's clock when its part tags left the playlist; `None` while
    /// they are listed, and always for the open segment.
    untagged: Option<Duration>,
}

impl Segment {
    /// Where it ends on the window's clock: its start plus its closed parts.
    fn end(&self) -> Duration {
        self.start.saturating_add(self.duration)
    }

    /// The segment's bytes: its parts', in order.
    fn chunks(&self) -> Chunks {
        let mut chunks = Chunks::default();
        for chunk in self.parts.iter().flat_map(|part| part.chunks.as_slice()) {
            chunks.push(chunk.clone());
        }
        chunks
    }
}

/// The segment being built, and its part being built.
#[derive(Debug)]
struct Open {
    /// The segment, with the parts closed so far.
    segment: Segment,
    /// The fragments since the last part closed.
    pending: Part,
}

impl Open {
    /// An empty segment of `msn` that starts at `start` on the window's
    /// clock.
    fn new(msn: u64, start: Duration) -> Self {
        Self {
            segment: Segment {
                msn,
                parts: Vec::new(),
                duration: Duration::ZERO,
                cost: 0,
                start,
                appeared: Duration::ZERO,
                longest: Duration::ZERO,
                untagged: None,
            },
            pending: Part::default(),
        }
    }

    /// How long it lasts so far, its open part included.
    fn duration(&self) -> Duration {
        self.segment.duration.saturating_add(self.pending.duration)
    }

    /// Closes the open part, if it holds a fragment, and returns its
    /// duration.
    fn close_part(&mut self) -> Option<Duration> {
        if self.pending.chunks.as_slice().is_empty() {
            return None;
        }
        let part = std::mem::take(&mut self.pending);
        let duration = part.duration;
        self.segment.duration = self.segment.duration.saturating_add(duration);
        self.segment.parts.push(part);
        Some(duration)
    }
}

/// A segment delisted and still served (see the module docs).
#[derive(Debug)]
struct Delisted {
    /// The segment.
    segment: Segment,
    /// The window's clock at which it is retired (draft-pantos-hls-rfc8216bis-22
    /// §6.2.2): served while the clock is before it.
    until: Duration,
}

/// The targets a published playlist holds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Targets {
    /// The Target Duration, in seconds (draft-pantos-hls-rfc8216bis-22
    /// §4.4.3.1).
    target_duration: u64,
    /// The Part Target Duration (§4.4.3.7), whole milliseconds.
    part_target: Duration,
}

/// The LL-HLS window of one live output. See the module docs.
#[derive(Debug)]
pub struct Window {
    /// How it cuts and bounds segments.
    config: Config,
    /// The init segment, held apart from the media and never dropped.
    init: Bytes,
    /// The complete segments the playlist lists, oldest first, Media
    /// Sequence Numbers consecutive.
    listed: VecDeque<Segment>,
    /// The segments delisted and still served, in the order delisted.
    delisted: VecDeque<Delisted>,
    /// The window's clock: the durations of the fragments it took, summed
    /// (see the module docs).
    clock: Duration,
    /// The segment being built: `None` until an independent fragment starts
    /// the window, then always one.
    open: Option<Open>,
    /// How many segments completed: the Media Sequence Number of the open
    /// segment, or of the first before one is open.
    completed: u64,
    /// How many parts the last complete segment has, held or not.
    previous_parts: u64,
    /// The targets, once the first segment completed and the playlist is
    /// published.
    targets: Option<Targets>,
    /// What the media held costs, as [`Window::bytes`] counts it.
    held: usize,
    /// Whether a push overflowed: the window takes no more fragments.
    overflowed: bool,
}

impl Window {
    /// An empty window for the output whose init segment is `init`.
    pub fn new(config: Config, init: Bytes) -> Result<Self, ConfigError> {
        if config.part_target.is_zero() {
            return Err(ConfigError::ZeroPartTarget);
        }
        if config.segments == 0 {
            return Err(ConfigError::NoSegments);
        }
        if config.max_bytes == 0 {
            return Err(ConfigError::ZeroMaxBytes);
        }
        Ok(Self {
            config,
            init,
            listed: VecDeque::new(),
            delisted: VecDeque::new(),
            clock: Duration::ZERO,
            open: None,
            completed: 0,
            previous_parts: 0,
            targets: None,
            held: 0,
            overflowed: false,
        })
    }

    /// Takes the output's next fragment, in order.
    pub fn push(&mut self, fragment: Fragment) -> Result<Pushed, PushError> {
        let overflow = PushError::Overflow {
            max_bytes: self.config.max_bytes,
        };
        if self.overflowed {
            return Err(overflow);
        }
        let starts = match &self.open {
            None if !fragment.independent => return Ok(Pushed::Dropped),
            None => true,
            // A segment as long as its frames' rounded durations sum to:
            // within JITTER of the target is at it.
            Some(open) => {
                fragment.independent
                    && open.duration().saturating_add(JITTER) >= self.config.segment_target
            }
        };
        let cost = fragment.bytes.len().saturating_add(FRAGMENT_OVERHEAD);
        let joins = match &self.open {
            Some(open) if !starts => open.segment.cost,
            _ => 0,
        };
        if joins.saturating_add(cost) > self.config.max_bytes {
            self.overflowed = true;
            return Err(overflow);
        }

        let start = self.clock;
        self.clock = self.clock.saturating_add(fragment.duration);
        let completing = if starts { self.open.take() } else { None };
        let published = completing.is_some();
        if let Some(open) = completing {
            self.complete(open);
        }
        let limit = self.part_limit();
        let msn = self.completed;
        let open = self.open.get_or_insert_with(|| Open::new(msn, start));
        // Close the part before a fragment that would take it past the limit;
        // one of only audio, which lasts nothing, keeps it.
        let before = if !open.pending.duration.is_zero()
            && open.pending.duration.saturating_add(fragment.duration) > limit
        {
            open.close_part()
        } else {
            None
        };
        let duration = fragment.duration;
        open.pending.push(fragment);
        open.segment.cost = open.segment.cost.saturating_add(cost);
        // Close it now if one more fragment as long would.
        let after = if open.pending.duration.saturating_add(duration) > limit {
            open.close_part()
        } else {
            None
        };
        let end = open.segment.end();
        self.held = self.held.saturating_add(cost);
        // Only a part closed after its fragment can be longer than the limit:
        // the one fragment it holds is.
        if let Some(duration) = after {
            self.raise_part_target(duration);
        }
        self.untag(end);
        self.retire();
        // Drop the oldest segments past the cap, the delisted ones first; the
        // open one alone is within it (checked above).
        while self.held > self.config.max_bytes
            && let Some(gone) = self
                .delisted
                .pop_front()
                .map(|delisted| delisted.segment)
                .or_else(|| self.listed.pop_front())
        {
            self.held = self.held.saturating_sub(gone.cost);
        }
        Ok(if published || before.is_some() || after.is_some() {
            Pushed::Published
        } else {
            Pushed::Held
        })
    }

    /// Completes the open segment: closes its open part, sets or raises the
    /// targets, lists it, delists the oldest past the count, and records the
    /// playlist's duration against every segment it lists.
    fn complete(&mut self, mut open: Open) {
        // The open part is within the limit: the last fragment would have
        // closed it otherwise.
        open.close_part();
        let mut segment = open.segment;
        segment.appeared = self.clock;
        self.completed = self.completed.saturating_add(1);
        self.previous_parts = u64::try_from(segment.parts.len()).unwrap_or(u64::MAX);
        let rounded = rounded_seconds(segment.duration);
        if let Some(targets) = &mut self.targets {
            targets.target_duration = targets.target_duration.max(rounded);
        } else {
            let longest = segment
                .parts
                .iter()
                .map(|part| part.duration)
                .max()
                .unwrap_or_default();
            self.targets = Some(Targets {
                target_duration: rounded.max(1),
                part_target: part_target(longest),
            });
        }
        self.listed.push_back(segment);
        if self.listed.len() > self.config.segments
            && let Some(oldest) = self.listed.pop_front()
        {
            let until = self.deadline(&oldest);
            self.delisted.push_back(Delisted {
                segment: oldest,
                until,
            });
        }
        let duration = self.listed.iter().fold(Duration::ZERO, |sum, segment| {
            sum.saturating_add(segment.duration)
        });
        for segment in &mut self.listed {
            segment.longest = segment.longest.max(duration);
        }
    }

    /// The clock at which `segment`, delisted now, is retired
    /// (draft-pantos-hls-rfc8216bis-22 §6.2.2, see the module docs): the
    /// later of its Availability Duration past the time it appeared and
    /// three Target Durations past the time its part tags left, now if they
    /// leave with it.
    fn deadline(&self, segment: &Segment) -> Duration {
        let available = segment
            .appeared
            .saturating_add(segment.duration)
            .saturating_add(segment.longest);
        let parts = segment
            .untagged
            .unwrap_or(self.clock)
            .saturating_add(self.target_durations(PART_SERVED_TARGET_DURATIONS));
        available.max(parts)
    }

    /// `count` Target Durations; zero before the playlist is published.
    fn target_durations(&self, count: u32) -> Duration {
        self.target_duration()
            .unwrap_or_default()
            .saturating_mul(count)
    }

    /// Takes the part tags of the complete segments whose end is now more
    /// than three Target Durations from the playlist's `end` (its last closed
    /// part's) out of the playlist, all of a segment's together (see the
    /// module docs), oldest first, and records when.
    fn untag(&mut self, end: Duration) {
        let reach = self.target_durations(PART_TAG_TARGET_DURATIONS);
        let clock = self.clock;
        for segment in self
            .listed
            .iter_mut()
            .skip_while(|segment| segment.untagged.is_some())
        {
            if segment.end().saturating_add(reach) >= end {
                break;
            }
            segment.untagged = Some(clock);
        }
    }

    /// Retires the delisted segments whose deadline the clock reached.
    fn retire(&mut self) {
        let clock = self.clock;
        let mut freed = 0_usize;
        self.delisted.retain(|delisted| {
            let served = delisted.until > clock;
            if !served {
                freed = freed.saturating_add(delisted.segment.cost);
            }
            served
        });
        self.held = self.held.saturating_sub(freed);
    }

    /// Raises the published Part Target Duration to fit a part of `duration`
    /// (see the module docs' SPEC-DEVIATION).
    fn raise_part_target(&mut self, duration: Duration) {
        if let Some(targets) = &mut self.targets
            && duration > targets.part_target
        {
            targets.part_target = part_target(duration);
        }
    }

    /// The duration a part closes at: the published Part Target Duration, or
    /// the configured one plus [`JITTER`] before.
    fn part_limit(&self) -> Duration {
        self.targets.map_or_else(
            || self.config.part_target.saturating_add(JITTER),
            |targets| targets.part_target,
        )
    }

    /// The Part Target Duration of the playlist, or the configured part
    /// target before one is published: what the Advance Part Limit counts
    /// in (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
    fn part_target(&self) -> Duration {
        self.targets
            .map_or(self.config.part_target, |targets| targets.part_target)
    }

    /// How many parts the open segment has closed.
    fn open_parts(&self) -> u64 {
        self.open.as_ref().map_or(0, |open| {
            u64::try_from(open.segment.parts.len()).unwrap_or(u64::MAX)
        })
    }

    /// The init segment.
    pub fn init(&self) -> &Bytes {
        &self.init
    }

    /// What the window holds: its media, each fragment's bytes and
    /// [`FRAGMENT_OVERHEAD`], and the init segment. The supervisor counts it
    /// against its own cap.
    pub fn bytes(&self) -> usize {
        self.held.saturating_add(self.init.len())
    }

    /// The Target Duration of the playlist, once published: a blocked
    /// request that is not answered within three of them SHOULD get Service
    /// Unavailable (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
    pub fn target_duration(&self) -> Option<Duration> {
        self.targets
            .map(|targets| Duration::from_secs(targets.target_duration))
    }

    /// The part the playlist hints as the next (`EXT-X-PRELOAD-HINT`), as
    /// (Media Sequence Number, Part Index), once published.
    pub fn next_part(&self) -> Option<(u64, u64)> {
        self.targets.map(|_| (self.completed, self.open_parts()))
    }

    /// What a playlist request with `blocking` gets now
    /// (draft-pantos-hls-rfc8216bis-22 §6.2.5.2).
    ///
    /// The request is ready once the playlist holds what it asks for: the
    /// segment `M` or a later one; the part `N` of segment `M`, or a later
    /// one, where an `N` past the last part of a complete segment `M` asks
    /// for part 0 of the next ("MUST treat the request as one for Part Index
    /// 0 of the following Parent Segment"). A request for something no longer
    /// held is ready too ("even if it is no longer in the Playlist"). It is a
    /// Bad Request when `M` is past the last complete segment plus two, or
    /// when the part is further ahead of the last part than the Advance Part
    /// Limit: three seconds of parts below a Part Target Duration of a
    /// second, else three parts. How far ahead counts the parts that must
    /// still close at least, as if the open segment closed with the parts it
    /// has. Nothing is ready before the playlist is published.
    pub fn reload(&self, blocking: Blocking) -> Reload {
        let open = self.completed;
        let ahead = match blocking {
            Blocking::None => 0,
            Blocking::Segment { msn } if msn > open.saturating_add(1) => {
                return Reload::BadRequest;
            }
            Blocking::Segment { msn } => u64::from(msn >= open),
            Blocking::Part { msn, .. } if msn > open.saturating_add(1) => {
                return Reload::BadRequest;
            }
            Blocking::Part { msn, part } => {
                let parts = self.open_parts();
                if msn.saturating_add(1) < open
                    || (msn.saturating_add(1) == open && part < self.previous_parts)
                {
                    0
                } else if msn < open {
                    // Past the last part of a complete segment: part 0 of the open one.
                    1_u64.saturating_sub(parts)
                } else if msn == open {
                    part.saturating_add(1).saturating_sub(parts)
                } else {
                    part.saturating_add(1)
                }
            }
        };
        if self.too_far(ahead) {
            Reload::BadRequest
        } else if ahead == 0 && self.targets.is_some() {
            Reload::Ready
        } else {
            Reload::Wait
        }
    }

    /// Whether `ahead` parts are past the Advance Part Limit
    /// (draft-pantos-hls-rfc8216bis-22 §6.2.5.2): "three divided by the
    /// Part Target Duration if the Part Target Duration is less than one
    /// second, or three otherwise". That is three seconds of parts of the
    /// Part Target Duration or of a second, whichever is shorter, compared
    /// exactly: at a target of one second both readings give three.
    fn too_far(&self, ahead: u64) -> bool {
        let part = self.part_target().min(ONE_SECOND);
        u128::from(ahead).saturating_mul(part.as_nanos())
            > u128::from(ADVANCE_PART_LIMIT).saturating_mul(ONE_SECOND.as_nanos())
    }

    /// What a request for `resource` gets now.
    pub fn get(&self, resource: Resource) -> Lookup {
        let found = match resource {
            Resource::Init => Some(Chunks::from(self.init.clone())),
            Resource::Segment { msn } => self.segment(msn).map(Segment::chunks),
            Resource::Part { msn, index } => self.part(msn, index).map(|part| part.chunks.clone()),
        };
        match found {
            Some(chunks) => Lookup::Ready(chunks),
            None if matches!(resource, Resource::Part { msn, index }
                if self.next_part() == Some((msn, index))) =>
            {
                Lookup::Wait
            }
            None => Lookup::NotFound,
        }
    }

    /// The complete segment `msn`, if held.
    fn segment(&self, msn: u64) -> Option<&Segment> {
        if let Some(delisted) = self
            .delisted
            .iter()
            .find(|delisted| delisted.segment.msn == msn)
        {
            return Some(&delisted.segment);
        }
        let first = self.listed.front()?.msn;
        self.listed
            .get(usize::try_from(msn.checked_sub(first)?).ok()?)
    }

    /// The closed part `index` of segment `msn`, if held.
    fn part(&self, msn: u64, index: u64) -> Option<&Part> {
        let parts = match &self.open {
            Some(open) if open.segment.msn == msn => &open.segment.parts,
            _ => &self.segment(msn)?.parts,
        };
        parts.get(usize::try_from(index).ok()?)
    }
}

/// The Part Target Duration for a longest part of `longest`: plus [`JITTER`],
/// rounded up to the millisecond.
fn part_target(longest: Duration) -> Duration {
    let millis = longest
        .saturating_add(JITTER)
        .as_nanos()
        .div_ceil(NANOS_PER_MILLISECOND);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

/// `duration` in seconds, rounded to the nearest integer, half up
/// (draft-pantos-hls-rfc8216bis-22 §4.4.3.1).
fn rounded_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() >= 500_000_000))
}

#[cfg(test)]
mod tests;

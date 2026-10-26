//! Fragmented MP4 reading: an HLS stream's init segment (`EXT-X-MAP`,
//! RFC 8216 §4.3.2.5) into the layout of its tracks, then each media
//! segment into their units of media (see [`crate::media`]), as the
//! MPEG-TS demultiplexer hands them on.
//!
//! The boxes are read by mp4-atom; this module walks them. It implements
//! ISO/IEC 14496-12: the movie box (§8.2.1) and per track its header
//! (§8.3.2, `track_ID`), the media header's `timescale` (§8.4.2), the
//! handler (§8.4.3: `vide`, `soun`), the first sample entry of the sample
//! description (§8.5.2) and the edit list (§8.6.6); the track extends
//! box's defaults (§8.8.3); per media segment each movie fragment
//! (§8.8.4) with its track fragments: the header's base data offset,
//! `default-base-is-moof` and defaults (§8.8.7), the runs with their data
//! offset and per-sample duration, size and composition offset, signed
//! in version 1 (§8.8.8), the base media decode time (§8.8.12), and the
//! media data box the samples lie in (§8.1.1). RFC 8216 §3.3 requires a
//! `tfdt` in every track fragment of an HLS segment: one without is an
//! error. Sample entries: `avc1`/`avc3` with their `avcC` (ISO/IEC
//! 14496-15 §5.3.3), `hvc1`/`hev1` with their `hvcC` (§8.3.3), whose
//! parameter sets go into the [`Codec`] and NAL unit length size into
//! the conversion of each sample to Annex B (§5.3.2, §8.3.2); `mp4a` with
//! an MPEG-4 or MPEG-2 AAC object type (ISO/IEC 14496-1 §7.2.6.6.2,
//! `objectTypeIndication` 0x40, 0x66 to 0x68) and its
//! `AudioSpecificConfig` (ISO/IEC 14496-3 §1.6.2.1), decided as the
//! MPEG-TS path decides its ADTS configuration. Other sample entries are
//! declared [`Codec::Unsupported`] by their type, and tracks of other
//! handlers are not tracks.
//!
//! Times: a track's samples are timed on its media timeline, in its
//! `timescale`, from the fragment's `tfdt` plus the durations of the
//! samples before them, and every track's media timeline starts at the
//! same instant. The edit list moves a track's media timeline against
//! the presentation (ffmpeg 9.0.2's HLS muxer, observed 2026-10-08,
//! starts video 21 ms after the AAC priming with an empty edit): its
//! leading empty edits delay the track, and the first edit with media
//! skips its `media_time`; later edits and `media_rate` are not read
//! (fragments extend the last edit). Each unit's decode time goes onto
//! the shared 90 kHz program clock ([`TS_CLOCK_RATE`]), as MPEG-TS DTS
//! are, so the pacer paces every track on one base; its presentation
//! time (the decode time plus the composition offset) onto the track's
//! clock: 90 kHz for video, the sampling rate for AAC. Conversions round
//! down. Units of a segment are handed on in decode-time order across
//! tracks, as a multiplex interleaves them.
//!
//! One [`Reader`] reads one stream. An HLS variant with a separate audio
//! rendition (RFC 8216 §4.3.4.2.1) is two streams, each with its own init
//! segment: the caller runs one reader per stream on the same program
//! clock, joins their layouts (the rendition's tracks after the
//! variant's, its units' [`Unit::track`] offset by the variant's track
//! count) and merges their units by decode time; the two media timelines
//! start at the same instant as tracks of one stream do. A new init
//! segment is a new reader and a new [`Layout`].
//!
//! Bounds: a media segment whose movie fragments declare more than
//! [`MAX_SAMPLES`] samples in all is refused before mp4-atom reads any of
//! them (each declared sample may become an entry it allocates and a
//! unit, and an empty one is read without costing media data); a sample
//! larger than `max_frame_bytes`, empty,
//! outside every media data box (a segment cut short ends its last one)
//! or whose NAL units run past its end is dropped and counted; a segment
//! whose samples cover more bytes than its media data boxes hold is
//! refused, because they overlap (runs pointing at the same bytes would
//! have each copied again), so a segment's units hold at most its media
//! data, each NAL unit's length prefix replaced by a start code. Before
//! mp4-atom reads the movie box, or the first movie fragment of a
//! segment, the boxes it would read in it, or in each of the segment's
//! fragments, are walked as it reads them, each once (the walk of a
//! fragment counts its declared samples too): an item reference box
//! (ISO/IEC 14496-12 §8.11.12) among them whose references claim more
//! bytes than it holds is refused, as mp4-atom 0.16.2 counts them
//! unchecked (its `Iref::decode_body_ext`), and so are boxes, and the
//! descriptors of an `esds` (ISO/IEC 14496-1 §7.2.6.5), nested more than
//! [`MAX_DEPTH`] deep, as it reads each nested one on the stack. The walk
//! mirrors mp4-atom 0.16.2, which the workspace pins. Pure: no I/O, no
//! clock, no logging (mp4-atom's own `tracing` warnings name boxes it
//! does not know).

#[cfg(test)]
pub(crate) mod test_data;

use std::ops::Range;

use bytes::Bytes;
use lotse_codec::aac::parse_config;
use lotse_codec::h264::{length_prefixed_to_annex_b, parse_sps};
use lotse_codec::h265::nal::{PPS_NUT, SPS_NUT, VPS_NUT};
use lotse_core::{Codec, Kind};
use mp4_atom::{
    Atom as _, Avc1, Avc3, Avcc, Codec as SampleEntry, Decode as _, DecodeMaybe as _, Encode as _,
    Esds, FourCC, Hdlr, Header, Hev1, Hvc1, Hvcc, Iref, Meta, Moof, Moov, Traf, Trak, Trex,
};

use crate::media::{Layout, LayoutTrack, TS_CLOCK_RATE, Unit};
use crate::ts::clamp;

/// The most samples one media segment may declare, over all its movie
/// fragments: over an hour of 30 fps video with AAC at 48 kHz, where HLS
/// segments last seconds (RFC 8216 §4.3.3.1, `EXT-X-TARGETDURATION`).
/// Counted over the whole segment, as each sample may become a [`Unit`]
/// and many fragments of one-byte samples would otherwise make millions.
pub const MAX_SAMPLES: u64 = 1 << 18;

/// The deepest boxes may nest where mp4-atom reads them one inside
/// another in the movie box or a movie fragment, that box counted
/// (ISO/IEC 14496-12 §4.2: a box's body may hold boxes), and with them
/// the descriptors of an `esds` (ISO/IEC 14496-1 §7.2.6.5: descriptors
/// hold descriptors), each counted as a box: one bound for both, as
/// mp4-atom 0.16.2 reads each nested box and descriptor on the same
/// stack. Edit boxes nested 50 deep overflowed a thread's 2 MiB stack
/// (Rust's default, tokio's too) in a debug build, 800 deep in a release
/// build (observed 2026-10-24), which aborts the process. The deepest
/// that sample entries nest is 11: `moov`, `trak`, `mdia`, `minf`,
/// `stbl`, `stsd`, `mp4a`, QTFF's `wave`, `esds`, its `ES_Descriptor`
/// and that one's `DecoderConfigDescriptor` (whose `DecoderSpecificInfo`
/// mp4-atom reads as data); a `mebx`'s keys reach 9.
pub const MAX_DEPTH: usize = 16;

/// The movie box (ISO/IEC 14496-12 §8.2.1).
const MOOV: FourCC = FourCC::new(b"moov");

/// The movie fragment box (ISO/IEC 14496-12 §8.8.4).
const MOOF: FourCC = FourCC::new(b"moof");

/// The track fragment box (ISO/IEC 14496-12 §8.8.6).
const TRAF: FourCC = FourCC::new(b"traf");

/// The track fragment run box (ISO/IEC 14496-12 §8.8.8).
const TRUN: FourCC = FourCC::new(b"trun");

/// The media data box (ISO/IEC 14496-12 §8.1.1).
const MDAT: FourCC = FourCC::new(b"mdat");

/// The video handler (ISO/IEC 14496-12 §8.4.3, `handler_type`).
const VIDE: FourCC = FourCC::new(b"vide");

/// The audio handler (ISO/IEC 14496-12 §8.4.3, `handler_type`).
const SOUN: FourCC = FourCC::new(b"soun");

/// The `objectTypeIndication` values whose decoder specific information
/// is an `AudioSpecificConfig`: MPEG-4 audio (0x40) and MPEG-2 AAC Main,
/// LC and SSR (0x66 to 0x68) (ISO/IEC 14496-1 §7.2.6.6.2, Table 5).
const AAC_OBJECT_TYPES: [u8; 4] = [0x40, 0x66, 0x67, 0x68];

/// What the reader counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Fmp4Stats {
    /// Media segments read.
    pub segments: u64,
    /// Samples handed on as units.
    pub samples: u64,
    /// Samples dropped as larger than `max_frame_bytes`.
    pub dropped_oversize: u64,
    /// Samples dropped as empty: of size 0, or video samples whose NAL
    /// units are all empty.
    pub dropped_empty: u64,
    /// Samples dropped as not inside a media data box: past the end of a
    /// segment cut short, or placed wrong.
    pub dropped_outside: u64,
    /// Video samples dropped as their NAL units run past their end.
    pub dropped_malformed: u64,
    /// Track fragments of a track the init segment does not have.
    pub unknown_tracks: u64,
}

/// Why an init or media segment cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Fmp4Error {
    /// mp4-atom could not read a box: `what`, with its reason.
    #[error("the {what} cannot be read: {reason}")]
    Box {
        /// The box.
        what: &'static str,
        /// mp4-atom's reason.
        reason: String,
    },
    /// The init segment has no movie box (ISO/IEC 14496-12 §8.2.1).
    #[error("the init segment has no movie box")]
    NoMovie,
    /// A track that is read has a media timescale of zero (ISO/IEC
    /// 14496-12 §8.4.2.3: units per second).
    #[error("track {track} has a timescale of zero")]
    Timescale {
        /// Its `track_ID`.
        track: u32,
    },
    /// A track fragment without a base media decode time (RFC 8216 §3.3,
    /// ISO/IEC 14496-12 §8.8.12).
    #[error("a fragment of track {track} has no base media decode time")]
    NoDecodeTime {
        /// Its `track_ID`.
        track: u32,
    },
    /// A media segment's movie fragments declare more samples than
    /// [`MAX_SAMPLES`] in all.
    #[error("a media segment declares {count} samples, more than {MAX_SAMPLES}")]
    TooManySamples {
        /// The samples the runs of all its movie fragments declare.
        count: u64,
    },
    /// Boxes, or the descriptors of an `esds`, that mp4-atom reads one
    /// inside another nest more than [`MAX_DEPTH`] deep in the movie box
    /// or a movie fragment.
    #[error("the {what} nests boxes more than {MAX_DEPTH} deep")]
    TooDeep {
        /// The box.
        what: &'static str,
    },
    /// The samples of a media segment cover more bytes than its media
    /// data boxes hold: their runs overlap (ISO/IEC 14496-12 §8.8.8 lays
    /// a run's samples out one after the other).
    #[error(
        "the samples of a media segment cover more than its {media} bytes of media data: they overlap"
    )]
    OverlappingSamples {
        /// The bytes its media data boxes hold.
        media: usize,
    },
}

/// A box an mp4-atom error came from.
fn box_error(what: &'static str) -> impl FnOnce(mp4_atom::Error) -> Fmp4Error {
    move |err| Fmp4Error::Box {
        what,
        reason: err.to_string(),
    }
}

/// What a track's samples carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Content {
    /// H.264 or H.265, each NAL unit after its length in this many bytes.
    Video {
        /// The NAL unit length size (ISO/IEC 14496-15 §5.3.3.2,
        /// §8.3.3.2: `lengthSizeMinusOne` + 1).
        length_size: u8,
    },
    /// Raw AAC frames.
    Audio,
    /// Not read.
    Unsupported,
}

/// One track of the stream.
#[derive(Debug, Clone)]
struct Track {
    /// Its `track_ID`.
    id: u32,
    /// What its samples carry.
    content: Content,
    /// Its media timescale: units per second of its sample times.
    timescale: u32,
    /// The clock of its units' timestamps.
    clock_rate: u32,
    /// Where its media timeline lies against the presentation, in its
    /// timescale: added to every sample time (the edit list).
    shift: i128,
}

/// The defaults of a track's samples (ISO/IEC 14496-12 §8.8.3,
/// `TrackExtendsBox`), by `track_ID`.
#[derive(Debug, Clone, Copy, Default)]
struct Defaults {
    /// `default_sample_duration`.
    duration: u32,
    /// `default_sample_size`.
    size: u32,
}

/// The fragmented MP4 reader of one stream: its init segment's tracks,
/// then its media segments.
#[derive(Debug)]
pub struct Reader {
    /// The tracks, in the order of the layout.
    tracks: Vec<Track>,
    /// The layout handed on.
    layout: Layout,
    /// Each `trex`: `track_ID` and its defaults.
    defaults: Vec<(u32, Defaults)>,
    /// The sample size limit.
    max_frame_bytes: usize,
    /// Counters.
    stats: Fmp4Stats,
}

/// A media segment's bytes, where its media data boxes hold them, and how
/// much of them its samples may still cover.
#[derive(Debug)]
struct Media<'a> {
    /// The segment.
    bytes: &'a [u8],
    /// The body of each media data box, cut short where the segment ends:
    /// in order and disjoint, as top-level boxes follow one another
    /// (ISO/IEC 14496-12 §4.2).
    data: &'a [Range<usize>],
    /// The media data not yet covered by a sample.
    budget: Budget,
}

/// How many bytes of a media segment's media data its samples may still
/// cover: samples that do not overlap cover at most the media data once.
#[derive(Debug, Clone, Copy)]
struct Budget {
    /// The bytes the segment's media data boxes hold.
    media: usize,
    /// Those not yet covered by a sample.
    left: usize,
}

impl Budget {
    /// Covers `size` bytes with a sample.
    ///
    /// # Errors
    ///
    /// [`Fmp4Error::OverlappingSamples`] when the samples now cover more
    /// than the media data.
    fn cover(&mut self, size: usize) -> Result<(), Fmp4Error> {
        self.left = self
            .left
            .checked_sub(size)
            .ok_or(Fmp4Error::OverlappingSamples { media: self.media })?;
        Ok(())
    }
}

/// A box of a byte sequence, as its header places it.
#[derive(Debug, Clone, Copy)]
struct Placed<'a> {
    /// Its type.
    kind: FourCC,
    /// Where it begins.
    start: usize,
    /// Where its body begins.
    body_start: usize,
    /// Its body, cut short where the bytes end.
    body: &'a [u8],
}

/// The first box of some bytes as its header places it (ISO/IEC 14496-12
/// §4.2: `size`, `largesize`, 0 = to the end), its header read by
/// mp4-atom's own `Header` as it reads every box: the one reader of box
/// headers here.
#[derive(Debug, Clone, Copy)]
struct Head<'a> {
    /// Its type.
    kind: FourCC,
    /// The length of its header: where its body begins.
    len: usize,
    /// Whether its header gives its size: one of 0 runs to the end.
    sized: bool,
    /// Its body, cut short where the bytes end.
    body: &'a [u8],
    /// The bytes after it; `None` when its size runs past their end.
    after: Option<&'a [u8]>,
}

/// The [`Head`] of the first box of `data`; `None` for bytes too few for
/// a header (mp4-atom's `Header::decode_maybe`).
///
/// # Errors
///
/// mp4-atom's for a size below the header's own.
fn head(data: &[u8]) -> Result<Option<Head<'_>>, mp4_atom::Error> {
    let mut cursor = data;
    let Some(header) = Header::decode_maybe(&mut cursor)? else {
        return Ok(None);
    };
    let size = header.size.unwrap_or(cursor.len());
    let (body, after) = match cursor.split_at_checked(size) {
        Some((body, after)) => (body, Some(after)),
        None => (cursor, None),
    };
    Ok(Some(Head {
        kind: header.kind,
        len: data.len().saturating_sub(cursor.len()),
        sized: header.size.is_some(),
        body,
        after,
    }))
}

/// The boxes of `data` one after the other, each as its header places it
/// ([`head`]). Bytes too few for a header end the list; a box whose size
/// runs past the end is the last, its body cut short.
fn boxes(data: &[u8]) -> Result<Vec<Placed<'_>>, mp4_atom::Error> {
    let mut placed = Vec::new();
    let mut start = 0_usize;
    while let Some(rest) = data.get(start..).filter(|rest| !rest.is_empty()) {
        let Some(head) = head(rest)? else {
            break;
        };
        placed.push(Placed {
            kind: head.kind,
            start,
            body_start: start.saturating_add(head.len),
            body: head.body,
        });
        let Some(after) = head.after else {
            break;
        };
        start = data.len().saturating_sub(after.len());
    }
    Ok(placed)
}

/// The first box of `data` as mp4-atom 0.16.2 reads the boxes of a body
/// one after the other (its `Any::decode_maybe`): its [`Head`] and the
/// bytes after it. `None` where mp4-atom reads no further: bytes too few
/// for a header, a header it refuses or a size past the end of `data`.
fn next_box(data: &[u8]) -> Option<(Head<'_>, &[u8])> {
    let head = head(data).ok()??;
    Some((head, head.after?))
}

#[cfg(test)]
thread_local! {
    /// The steps the walks on this thread took: the box headers, item
    /// references and descriptors they read, for the test of their
    /// linearity.
    static STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A step of the walk: counted in `STEPS` in the tests, and nothing
/// elsewhere.
fn step() {
    #[cfg(test)]
    STEPS.with(|steps| steps.set(steps.get().saturating_add(1)));
}

/// Whether mp4-atom 0.16.2 counts past zero reading `body`, the body of
/// an item reference box (ISO/IEC 14496-12 §8.11.12.2): after the
/// version and flags, its `SingleItemTypeReferenceBox`es, each its size,
/// `reference_type`, `from_item_ID`, `reference_count` and that many
/// `to_item_ID`s, the IDs 16-bit in version 0 and 32-bit in version 1.
/// Each reference it reads is a step: at most one per 12 bytes of
/// `body`, and one more.
///
/// mp4-atom 0.16.2 (`Iref::decode_body_ext`, observed 2026-10-24, the
/// newest release) subtracts each reference's size from the bytes it has
/// left unchecked: a size past them panics where overflow checks are on
/// (debug builds, the fuzz targets) and wraps elsewhere, after which it
/// reads on until the body ends and refuses the box. This reads the body
/// as it does, every reference after its fields rather than after its
/// size, and stops where mp4-atom stops without counting past zero: at
/// another version, which it refuses, at a field the body is too short
/// for, and once the sizes add up to the body.
fn references_overrun(body: &[u8]) -> bool {
    let Some((&[version, ..], mut rest)) = body.split_first_chunk::<4>() else {
        return false;
    };
    // `reference_type` and `from_item_ID`, and the size of a `to_item_ID`.
    let (fields, id_size) = match version {
        0 => (6, 2_usize),
        1 => (8, 4_usize),
        _ => return false,
    };
    let mut left = rest.len();
    while left > 0 {
        step();
        let Some((size, after)) = rest.split_first_chunk::<4>() else {
            return false;
        };
        let size = usize::try_from(u32::from_be_bytes(*size)).unwrap_or(usize::MAX);
        let Some(still) = left.checked_sub(size) else {
            return true;
        };
        left = still;
        let Some((count, ids)) = after.get(fields..).and_then(<[u8]>::split_first_chunk::<2>)
        else {
            return false;
        };
        let ids_len = usize::from(u16::from_be_bytes(*count)).saturating_mul(id_size);
        let Some(next) = ids.get(ids_len..) else {
            return false;
        };
        rest = next;
    }
    false
}

/// A descriptor of an `esds` (ISO/IEC 14496-1 §7.2.6.5, §8.3.3: a tag,
/// its `sizeOfInstance` and its body) and the bytes after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Descriptor<'a> {
    /// Its tag.
    tag: u8,
    /// Its body.
    body: &'a [u8],
    /// The bytes after it.
    after: &'a [u8],
}

/// The first descriptor of `data` as mp4-atom 0.16.2 reads one (its
/// `Descriptor::decode`): its tag, its body and the bytes after it. The
/// size after the tag is ISO/IEC 14496-1 §8.3.3's `sizeOfInstance`: bytes
/// of seven bits each, most significant first, each but the last with
/// its top bit (`nextByte`) set; mp4-atom reads at most four, whatever
/// the top bit of the fourth. `None` where it reads no further: no tag,
/// no size, or a size past the end of `data`.
fn descriptor(data: &[u8]) -> Option<Descriptor<'_>> {
    let (&tag, mut rest) = data.split_first()?;
    let mut size = 0_u32;
    for _ in 0..4 {
        let (&byte, after) = rest.split_first()?;
        rest = after;
        size = size.wrapping_shl(7).saturating_add(u32::from(byte & 0x7f));
        if byte & 0x80 == 0 {
            break;
        }
    }
    rest.split_at_checked(usize::try_from(size).ok()?)
        .map(|(body, after)| Descriptor { tag, body, after })
}

/// The fields of an `ES_Descriptor` before the descriptors in it, as
/// mp4-atom 0.16.2 reads them (its `EsDescriptor::decode`): `ES_ID` and
/// the byte of flags and `streamPriority` (ISO/IEC 14496-1 §7.2.6.5.1);
/// it reads none of the optional fields the flags announce.
const ES_FIELDS: usize = 3;

/// The fields of a `DecoderConfigDescriptor` before the descriptors in
/// it (ISO/IEC 14496-1 §7.2.6.6.1): `objectTypeIndication`, the byte of
/// `streamType` and `upStream`, `bufferSizeDB`, `maxBitrate` and
/// `avgBitrate`.
const DECODER_CONFIG_FIELDS: usize = 13;

/// The QTFF sound sample description's `wave` box (Apple's QTFF,
/// "siDecompressionParam Atom"), which may hold an `mp4a`'s `esds`.
const WAVE: FourCC = FourCC::new(b"wave");

/// The keys of a `mebx` sample entry, whose type mp4-atom reads as such
/// only there.
const KEYS: FourCC = FourCC::new(b"keys");

/// Which boxes in a box's body mp4-atom 0.16.2 reads, and from where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Children {
    /// Every box after the body's first this many bytes, its own fields:
    /// each by its type, as a box of that type is read wherever it lies
    /// (its `Any`), item reference boxes included.
    After(usize),
    /// After the body's first this many bytes, one box read as one of a
    /// fixed type whatever its header's type, so not by its type: the
    /// handler of a meta box (`Meta::decode_body`, its `Hdlr::decode`)
    /// and the label of a `urim` (its `Uri::decode`); then every box by
    /// its type, as [`Children::After`].
    Labelled(usize),
    /// Only the meta boxes (ISO/IEC 14496-12 §8.10.1, the user data box:
    /// mp4-atom reads its other boxes as data, even of a type it knows).
    Meta,
    /// A `mebx` sample entry's: after its `SampleEntry` fields, its
    /// `keys` as [`Children::Keys`] (ISO/IEC 14496-12 §12.8, as mp4-atom
    /// cites it), every other box by its type.
    Mebx,
    /// Every box a key whose body holds boxes read by their type (the
    /// `keys` of a `mebx` sample entry).
    Keys,
    /// An `mp4a` sample entry's: after this many bytes, its fields, a
    /// `wave` as [`Children::Wave`], every other box by its type.
    Mp4a(usize),
    /// A `wave` in an `mp4a` (mp4-atom's `decode_wave`): only its `esds`
    /// boxes, each read as one; a box of size 0 is not read.
    Wave,
    /// A track fragment's in the box walked (ISO/IEC 14496-12 §8.8.6):
    /// every box by its type, the samples its runs declare counted.
    Runs,
}

/// The fields of every sample entry before its own (ISO/IEC 14496-12
/// §8.5.2.2, `SampleEntry`: six reserved bytes and
/// `data_reference_index`).
const ENTRY_FIELDS: usize = 8;

/// The fields of a visual sample entry before its boxes (ISO/IEC
/// 14496-12 §12.1.3.2, `VisualSampleEntry`, with `SampleEntry`'s).
const VISUAL_FIELDS: usize = 78;

/// The fields of an audio sample entry before its boxes (ISO/IEC
/// 14496-12 §12.2.3.2, `AudioSampleEntry`, with `SampleEntry`'s), and of
/// an AMR one (3GPP TS 26.244 §6.5, `AMRSampleEntry`).
const AUDIO_FIELDS: usize = 28;

/// The fields of a 3GPP timed text sample entry before its boxes (3GPP
/// TS 26.245 §5.16, `TextSampleEntry`, with `SampleEntry`'s).
const TEXT_FIELDS: usize = 38;

/// Where mp4-atom 0.16.2 reads the boxes of an audio sample entry's
/// `body`: after its fields, and the 16 more of a version 1 sound
/// description or the 36 more of version 2 (Apple's QTFF, "Sound sample
/// description", the version in bytes 8 and 9). `None` for
/// another version or a body too short for one: mp4-atom refuses them.
fn audio_fields(body: &[u8]) -> Option<usize> {
    match body.get(8..10)? {
        [0, 0] => Some(AUDIO_FIELDS),
        [0, 1] => Some(AUDIO_FIELDS.saturating_add(16)),
        [0, 2] => Some(AUDIO_FIELDS.saturating_add(36)),
        _ => None,
    }
}

/// Where the `count` null-terminated strings end that follow the
/// `SampleEntry` fields of a metadata sample entry's `body` (ISO/IEC
/// 14496-12 §12.3.3.2: `mett`, `metx`). mp4-atom 0.16.2 reads each to
/// its null or to the end of the body.
fn after_strings(body: &[u8], count: usize) -> usize {
    let mut at = ENTRY_FIELDS;
    for _ in 0..count {
        at = body
            .get(at..)
            .and_then(|rest| rest.iter().position(|&byte| byte == 0))
            .map_or(body.len(), |null| at.saturating_add(null).saturating_add(1));
    }
    at
}

/// Which boxes mp4-atom 0.16.2 reads in `body`, the body of a box of type
/// `kind` that it reads by its type; `None` where it reads the body as
/// fields and data alone. It dispatches by type, wherever a box lies:
/// these are its types that hold boxes (each named as mp4-atom names
/// it), each with the fields it reads first.
fn children(kind: FourCC, body: &[u8]) -> Option<Children> {
    use mp4_atom::{
        Ac3, Av01, Dinf, Eac3, Edts, Evte, Fl32, Fl64, Flac, Fpcm, In24, In32, Ipcm, Ipco, Iprp,
        Jpeg, Lpcm, Mdia, Mebx, Mett, Metx, Mfra, Minf, Mp3, Mp4a, Mvex, Opus, S16l, Samr, Sowt,
        Stbl, Stsd, Twos, Tx3g, Udta, Uncv, Urim, Vp08, Vp09, Wvtt,
    };
    match kind {
        Moov::KIND
        | Trak::KIND
        | Mdia::KIND
        | Minf::KIND
        | Stbl::KIND
        | Dinf::KIND
        | Edts::KIND
        | Mvex::KIND
        | Moof::KIND
        | Traf::KIND
        | Mfra::KIND
        | Iprp::KIND
        | Ipco::KIND => Some(Children::After(0)),
        // ISO/IEC 14496-12 §8.11.1: a full box; QTFF's is a box.
        Meta::KIND if body.get(4..8) == Some(Hdlr::KIND.as_ref()) => Some(Children::Labelled(0)),
        Meta::KIND => Some(Children::Labelled(4)),
        Udta::KIND => Some(Children::Meta),
        // ISO/IEC 14496-12 §8.5.2.2: version, flags and `entry_count`.
        Stsd::KIND => Some(Children::After(8)),
        Avc1::KIND
        | Avc3::KIND
        | Hev1::KIND
        | Hvc1::KIND
        | Vp08::KIND
        | Vp09::KIND
        | Av01::KIND
        | Jpeg::KIND
        | Uncv::KIND => Some(Children::After(VISUAL_FIELDS)),
        Mp4a::KIND => audio_fields(body).map(Children::Mp4a),
        Opus::KIND
        | Flac::KIND
        | Ac3::KIND
        | Eac3::KIND
        | Mp3::KIND
        | Sowt::KIND
        | Twos::KIND
        | Lpcm::KIND
        | Ipcm::KIND
        | Fpcm::KIND
        | In24::KIND
        | In32::KIND
        | Fl32::KIND
        | Fl64::KIND
        | S16l::KIND => audio_fields(body).map(Children::After),
        Samr::KIND => Some(Children::After(AUDIO_FIELDS)),
        Tx3g::KIND => Some(Children::After(TEXT_FIELDS)),
        Wvtt::KIND | Evte::KIND => Some(Children::After(ENTRY_FIELDS)),
        Urim::KIND => Some(Children::Labelled(ENTRY_FIELDS)),
        Mebx::KIND => Some(Children::Mebx),
        Mett::KIND => Some(Children::After(after_strings(body, 2))),
        Metx::KIND => Some(Children::After(after_strings(body, 3))),
        _ => None,
    }
}

/// A walk of the boxes mp4-atom 0.16.2 reads in the movie box or a movie
/// fragment, as it reads them.
#[derive(Debug)]
struct Walk {
    /// The box walked, as errors name it.
    what: &'static str,
    /// The samples the runs of the track fragments in it declare.
    samples: u64,
}

impl Walk {
    /// Walks the boxes mp4-atom reads in `body`, the body of a box that
    /// lies `depth` boxes deep, the outer one counted.
    ///
    /// # Errors
    ///
    /// [`Fmp4Error::TooDeep`] past [`MAX_DEPTH`], and those of
    /// [`Walk::child`].
    fn container(
        &mut self,
        body: &[u8],
        children: Children,
        depth: usize,
    ) -> Result<(), Fmp4Error> {
        if depth > MAX_DEPTH {
            return Err(Fmp4Error::TooDeep { what: self.what });
        }
        let (fields, labelled) = match children {
            Children::After(fields) | Children::Mp4a(fields) => (fields, false),
            Children::Labelled(fields) => (fields, true),
            Children::Mebx => (ENTRY_FIELDS, false),
            Children::Meta | Children::Keys | Children::Wave | Children::Runs => (0, false),
        };
        let mut rest = body.get(fields..).unwrap_or_default();
        if labelled {
            let Some((_label, after)) = next_box(rest) else {
                return Ok(());
            };
            step();
            rest = after;
        }
        let deeper = depth.saturating_add(1);
        while let Some((child, after)) = next_box(rest) {
            step();
            rest = after;
            match children {
                Children::Meta if child.kind == Meta::KIND => {
                    self.child(child.kind, child.body, depth)?;
                }
                Children::Mebx if child.kind == KEYS => {
                    self.container(child.body, Children::Keys, deeper)?;
                }
                Children::Keys => self.container(child.body, Children::After(0), deeper)?,
                Children::Mp4a(_) if child.kind == WAVE => {
                    self.container(child.body, Children::Wave, deeper)?;
                }
                Children::Wave if child.kind == Esds::KIND && child.sized => {
                    self.child(child.kind, child.body, depth)?;
                }
                Children::Meta | Children::Wave => {}
                Children::Runs => {
                    if child.kind == TRUN
                        && let Some(&[a, b, c, d]) = child.body.get(4..8)
                    {
                        self.samples = self
                            .samples
                            .saturating_add(u64::from(u32::from_be_bytes([a, b, c, d])));
                    }
                    self.child(child.kind, child.body, depth)?;
                }
                Children::After(_) | Children::Labelled(_) | Children::Mebx | Children::Mp4a(_) => {
                    self.child(child.kind, child.body, depth)?;
                }
            }
        }
        Ok(())
    }

    /// Walks a box of type `kind` with `body` that mp4-atom reads by its
    /// type in the body of a box `depth` boxes deep.
    ///
    /// # Errors
    ///
    /// mp4-atom's own error for an item reference box once its count
    /// wraps, an over decode of `iref` ([`references_overrun`]), and
    /// those of [`Walk::container`] and [`Walk::descriptors`].
    fn child(&mut self, kind: FourCC, body: &[u8], depth: usize) -> Result<(), Fmp4Error> {
        let deeper = depth.saturating_add(1);
        match kind {
            Iref::KIND if references_overrun(body) => Err(box_error(self.what)(
                mp4_atom::Error::OverDecode(Iref::KIND),
            )),
            // ISO/IEC 14496-14 §3.1.2: the `ES_Descriptor` after the
            // version and flags.
            Esds::KIND => self.descriptors(body.get(4..).unwrap_or_default(), deeper),
            // ISO/IEC 14496-12 §8.8.4: the track fragments of a movie
            // fragment, whose runs give its samples.
            TRAF if depth == 1 => self.container(body, Children::Runs, deeper),
            _ => match children(kind, body) {
                Some(children) => self.container(body, children, deeper),
                None => Ok(()),
            },
        }
    }

    /// Walks the descriptors mp4-atom reads in `data`, the body of an
    /// `esds` after its version and flags or of a descriptor, that lies
    /// `depth` deep, boxes and descriptors counted alike. mp4-atom 0.16.2
    /// reads an `ES_Descriptor` (tag 0x03) and a `DecoderConfigDescriptor`
    /// (0x04) wherever it finds one, and each reads the descriptors after
    /// its fields on the stack, as it reads boxes; it reads every other
    /// descriptor (a `DecoderSpecificInfo`, an `SLConfigDescriptor`, one
    /// it does not know) as data. ISO/IEC 14496-1 nests them three deep
    /// (§7.2.6.5.1: an `ES_Descriptor` holds a `DecoderConfigDescriptor`;
    /// §7.2.6.6.1: that holds its `DecoderSpecificInfo`).
    ///
    /// # Errors
    ///
    /// [`Fmp4Error::TooDeep`] past [`MAX_DEPTH`].
    fn descriptors(&mut self, mut data: &[u8], depth: usize) -> Result<(), Fmp4Error> {
        use mp4_atom::esds::{DecoderConfig, EsDescriptor};
        if depth > MAX_DEPTH {
            return Err(Fmp4Error::TooDeep { what: self.what });
        }
        while let Some(Descriptor { tag, body, after }) = descriptor(data) {
            step();
            data = after;
            let fields = match tag {
                EsDescriptor::TAG => ES_FIELDS,
                DecoderConfig::TAG => DECODER_CONFIG_FIELDS,
                _ => continue,
            };
            self.descriptors(
                body.get(fields..).unwrap_or_default(),
                depth.saturating_add(1),
            )?;
        }
        Ok(())
    }
}

/// Refuses `body`, the body of the movie box or a movie fragment (`what`
/// in errors), before mp4-atom 0.16.2 reads it, where it would count past
/// zero reading an item reference box ([`references_overrun`]) or read
/// boxes or descriptors nested deeper than [`MAX_DEPTH`]. It walks the
/// boxes mp4-atom reads, from box boundary to box boundary (ISO/IEC
/// 14496-12 §4.2) and past each box's own fields ([`children`]), and the
/// descriptors of each `esds` ([`Walk::descriptors`]), and no others:
/// bytes inside data, padding (§8.1.2, `free`) and boxes it reads as data
/// are not boxes. The walk is linear: it reads no byte of `body` more
/// than twice (a meta box's handler type is looked at first), and takes
/// at most one step, a box header, reference or descriptor read, per two
/// bytes of `body`. It returns the samples the runs (§8.8.8:
/// `sample_count` after the version and flags) of the track fragments in
/// `body` declare, summed: those of a movie fragment.
///
/// # Errors
///
/// [`Fmp4Error::Box`] with mp4-atom's own error for such an item
/// reference box once its count wraps, an over decode of `iref`, and
/// [`Fmp4Error::TooDeep`].
fn check_boxes(what: &'static str, body: &[u8]) -> Result<u64, Fmp4Error> {
    let mut walk = Walk { what, samples: 0 };
    walk.container(body, Children::After(0), 1)?;
    Ok(walk.samples)
}

/// The name of a sample entry lotse does not read: its type, in lower
/// case (ISO/IEC 14496-12 §8.5.2.2, the entry's box type).
fn entry_name(entry: &SampleEntry) -> String {
    let mut encoded = Vec::new();
    let kind: &[u8] = match entry {
        SampleEntry::Unknown(kind, _) => kind.as_ref(),
        known => {
            // mp4-atom names a known entry only by its variant: its box
            // type is where its encoding begins, after the size.
            let _encoded = known.encode(&mut encoded);
            encoded.get(4..8).unwrap_or_default()
        }
    };
    String::from_utf8_lossy(kind).trim().to_ascii_lowercase()
}

/// H.264 from its `avcC` (ISO/IEC 14496-15 §5.3.3): the first sequence
/// and picture parameter sets, the profile and level from the SPS.
fn h264(avcc: &Avcc) -> (Codec, Content) {
    let sps = avcc
        .sequence_parameter_sets
        .first()
        .map(|sps| Bytes::copy_from_slice(sps));
    let pps = avcc
        .picture_parameter_sets
        .first()
        .map(|pps| Bytes::copy_from_slice(pps));
    let profile_level_id = sps
        .as_deref()
        .and_then(|sps| parse_sps(sps).ok())
        .map(|info| info.profile_level_id);
    (
        Codec::H264 {
            profile_level_id,
            sps,
            pps,
        },
        Content::Video {
            length_size: avcc.length_size,
        },
    )
}

/// H.265 from its `hvcC` (ISO/IEC 14496-15 §8.3.3): the first video,
/// sequence and picture parameter set of its arrays.
fn h265(hvcc: &Hvcc) -> (Codec, Content) {
    let first = |nal_unit_type: u8| {
        hvcc.arrays
            .iter()
            .filter(|array| array.nal_unit_type == nal_unit_type)
            .find_map(|array| array.nalus.first())
            .map(|nal| Bytes::copy_from_slice(nal))
    };
    (
        Codec::H265 {
            vps: first(VPS_NUT),
            sps: first(SPS_NUT),
            pps: first(PPS_NUT),
        },
        Content::Video {
            length_size: hvcc.length_size_minus_one.saturating_add(1),
        },
    )
}

/// AAC from its `esds` (ISO/IEC 14496-1 §7.2.6.6, §7.2.6.7): the
/// `AudioSpecificConfig`, decided as an ADTS configuration is, with its
/// clock rate.
fn aac(esds: &Esds) -> (Codec, Content, u32) {
    let config = &esds.es_desc.dec_config;
    if !AAC_OBJECT_TYPES.contains(&config.object_type_indication) {
        return unsupported(Kind::Audio, "mp4a");
    }
    let Some(specific) = &config.dec_specific else {
        return unsupported(Kind::Audio, "aac");
    };
    match parse_config(&specific.raw) {
        Ok(parsed) => (
            Codec::AacLc {
                sample_rate: parsed.sample_rate,
                channels: parsed.channels,
                config: Bytes::copy_from_slice(&specific.raw),
            },
            Content::Audio,
            parsed.sample_rate,
        ),
        Err(err) => unsupported(Kind::Audio, err.codec_name()),
    }
}

/// A track that is not read: its codec, the 90 kHz clock MPEG-TS
/// declares such tracks with.
fn unsupported(kind: Kind, name: &str) -> (Codec, Content, u32) {
    (
        Codec::Unsupported {
            kind,
            name: name.to_owned(),
        },
        Content::Unsupported,
        TS_CLOCK_RATE,
    )
}

/// The shift of a track's media timeline from its edit list (ISO/IEC
/// 14496-12 §8.6.6), in its `timescale`: the leading empty edits
/// (`media_time` −1), whose durations are in the movie's
/// `movie_timescale`, less the `media_time` of the first edit with media.
fn shift(trak: &Trak, movie_timescale: u32, timescale: u32) -> i128 {
    let Some(elst) = trak.edts.as_ref().and_then(|edts| edts.elst.as_ref()) else {
        return 0;
    };
    let mut empty = 0_i128;
    let mut start = 0_i128;
    for entry in &elst.entries {
        if let Some(media_time) = entry.media_time {
            start = i128::from(media_time);
            break;
        }
        empty = empty.saturating_add(i128::from(entry.segment_duration));
    }
    let delay = empty
        .saturating_mul(i128::from(timescale))
        .checked_div(i128::from(movie_timescale))
        .unwrap_or_default();
    delay.saturating_sub(start)
}

/// A track of the movie and its layout entry; `None` for a track of
/// another handler, which is not a track here.
fn track(trak: &Trak, movie_timescale: u32) -> Result<Option<(Track, LayoutTrack)>, Fmp4Error> {
    let id = trak.tkhd.track_id;
    let kind = match trak.mdia.hdlr.handler {
        VIDE => Kind::Video,
        SOUN => Kind::Audio,
        _ => return Ok(None),
    };
    let entry = trak.mdia.minf.stbl.stsd.codecs.first();
    let (codec, content, clock_rate) = match (kind, entry) {
        (
            Kind::Video,
            Some(SampleEntry::Avc1(Avc1 { avcc, .. }) | SampleEntry::Avc3(Avc3 { avcc, .. })),
        ) => {
            let (codec, content) = h264(avcc);
            (codec, content, TS_CLOCK_RATE)
        }
        (
            Kind::Video,
            Some(SampleEntry::Hvc1(Hvc1 { hvcc, .. }) | SampleEntry::Hev1(Hev1 { hvcc, .. })),
        ) => {
            let (codec, content) = h265(hvcc);
            (codec, content, TS_CLOCK_RATE)
        }
        (Kind::Audio, Some(SampleEntry::Mp4a(mp4a))) => aac(&mp4a.esds),
        (kind, Some(other)) => unsupported(kind, &entry_name(other)),
        (kind, None) => unsupported(kind, "unknown"),
    };
    let timescale = trak.mdia.mdhd.timescale;
    if timescale == 0 && content != Content::Unsupported {
        return Err(Fmp4Error::Timescale { track: id });
    }
    let layout = LayoutTrack {
        id,
        stream_type: 0,
        kind,
        codec,
        clock_rate,
    };
    Ok(Some((
        Track {
            id,
            content,
            timescale,
            clock_rate,
            shift: shift(trak, movie_timescale, timescale),
        },
        layout,
    )))
}

/// `ticks` of `timescale` on a clock of `rate`, rounded down; the
/// timescale is not zero for a track that is read.
fn convert(ticks: i128, rate: u32, timescale: u32) -> i64 {
    clamp(
        ticks
            .saturating_mul(i128::from(rate))
            .checked_div_euclid(i128::from(timescale))
            .unwrap_or_default(),
    )
}

/// Where a track fragment's data begins (ISO/IEC 14496-12 §8.8.7.1): the
/// explicit base data offset, else the movie fragment's first byte with
/// `default-base-is-moof` or for the first track fragment, else the end
/// of the preceding track fragment's data.
fn base_offset(traf: &Traf, moof_start: usize, previous_end: Option<usize>) -> usize {
    if let Some(offset) = traf.tfhd.base_data_offset {
        return usize::try_from(offset).unwrap_or(usize::MAX);
    }
    if traf.tfhd.default_base_is_moof {
        return moof_start;
    }
    previous_end.unwrap_or(moof_start)
}

/// `base` moved by a run's signed `data_offset` (ISO/IEC 14496-12
/// §8.8.8.3); past either end of the address space, the run lies
/// nowhere.
fn offset(base: usize, by: i32) -> usize {
    let moved = i128::try_from(base)
        .unwrap_or(i128::MAX)
        .saturating_add(i128::from(by));
    usize::try_from(moved).unwrap_or(usize::MAX)
}

impl Reader {
    /// The reader of the stream whose init segment is `init` (RFC 8216
    /// §4.3.2.5), keeping samples up to `max_frame_bytes`
    /// (`limits.max_frame_bytes`).
    ///
    /// # Errors
    ///
    /// [`Fmp4Error::NoMovie`] without a movie box,
    /// [`Fmp4Error::Box`] when mp4-atom cannot read it,
    /// [`Fmp4Error::TooDeep`] for boxes in it nested too deep, and
    /// [`Fmp4Error::Timescale`] for a track to read with a timescale of
    /// zero.
    pub fn new(init: &[u8], max_frame_bytes: usize) -> Result<Self, Fmp4Error> {
        let placed = boxes(init).map_err(box_error("init segment"))?;
        let moov = placed
            .iter()
            .find(|placed| placed.kind == MOOV)
            .ok_or(Fmp4Error::NoMovie)?;
        check_boxes("movie box", moov.body)?;
        let mut bytes = init.get(moov.start..).unwrap_or_default();
        let moov = Moov::decode(&mut bytes).map_err(box_error("movie box"))?;
        let mut tracks = Vec::new();
        let mut layout = Vec::new();
        for trak in &moov.trak {
            if let Some((track, entry)) = track(trak, moov.mvhd.timescale)? {
                tracks.push(track);
                layout.push(entry);
            }
        }
        let defaults = moov
            .mvex
            .iter()
            .flat_map(|mvex| &mvex.trex)
            .map(|trex: &Trex| {
                (
                    trex.track_id,
                    Defaults {
                        duration: trex.default_sample_duration,
                        size: trex.default_sample_size,
                    },
                )
            })
            .collect();
        Ok(Self {
            tracks,
            layout: Layout {
                program_number: 0,
                tracks: layout,
            },
            defaults,
            max_frame_bytes,
            stats: Fmp4Stats::default(),
        })
    }

    /// The layout of the stream's tracks: [`Unit::track`] indexes it.
    #[must_use]
    pub const fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The counters.
    #[must_use]
    pub const fn stats(&self) -> Fmp4Stats {
        self.stats
    }

    /// Reads one media segment and appends its units to `out`, in decode
    /// time order. Samples that cannot be handed on are dropped and
    /// counted ([`Fmp4Stats`]).
    ///
    /// # Errors
    ///
    /// [`Fmp4Error::Box`] when mp4-atom cannot read a movie fragment
    /// (cut short included), [`Fmp4Error::TooDeep`] for boxes in one
    /// nested too deep, [`Fmp4Error::TooManySamples`],
    /// [`Fmp4Error::NoDecodeTime`] and [`Fmp4Error::OverlappingSamples`];
    /// nothing is appended then.
    pub fn read_segment(&mut self, segment: &[u8], out: &mut Vec<Unit>) -> Result<(), Fmp4Error> {
        let placed = boxes(segment).map_err(box_error("media segment"))?;
        let data: Vec<Range<usize>> = placed
            .iter()
            .filter(|placed| placed.kind == MDAT)
            .map(|mdat| mdat.body_start..mdat.body_start.saturating_add(mdat.body.len()))
            .collect();
        let media = data
            .iter()
            .map(|mdat| mdat.end.saturating_sub(mdat.start))
            .fold(0_usize, usize::saturating_add);
        let mut media = Media {
            bytes: segment,
            data: &data,
            budget: Budget { media, left: media },
        };
        let mut units = Vec::new();
        let mut stats = self.stats;
        let fragments: Vec<_> = placed.iter().filter(|placed| placed.kind == MOOF).collect();
        let mut count = 0_u64;
        for fragment in &fragments {
            count = count.saturating_add(check_boxes("movie fragment", fragment.body)?);
        }
        if count > MAX_SAMPLES {
            return Err(Fmp4Error::TooManySamples { count });
        }
        for fragment in fragments {
            let mut bytes = segment.get(fragment.start..).unwrap_or_default();
            let moof = Moof::decode(&mut bytes).map_err(box_error("movie fragment"))?;
            self.fragment(&moof, fragment.start, &mut media, &mut units, &mut stats)?;
        }
        units.sort_by_key(|unit| unit.decode_time);
        stats.segments = stats.segments.saturating_add(1);
        self.stats = stats;
        out.append(&mut units);
        Ok(())
    }

    /// The units of one movie fragment that begins at `moof_start` in
    /// `media`, its samples covered out of `media`'s budget.
    fn fragment(
        &self,
        moof: &Moof,
        moof_start: usize,
        media: &mut Media<'_>,
        units: &mut Vec<Unit>,
        stats: &mut Fmp4Stats,
    ) -> Result<(), Fmp4Error> {
        let mut previous_end = None;
        for traf in &moof.traf {
            let id = traf.tfhd.track_id;
            let index = self.tracks.iter().position(|track| track.id == id);
            if index.is_none() {
                stats.unknown_tracks = stats.unknown_tracks.saturating_add(1);
            }
            let tfdt = traf
                .tfdt
                .as_ref()
                .ok_or(Fmp4Error::NoDecodeTime { track: id })?;
            let trex = self
                .defaults
                .iter()
                .find(|(track, _)| *track == id)
                .map(|(_, defaults)| *defaults)
                .unwrap_or_default();
            let default_duration = traf.tfhd.default_sample_duration.unwrap_or(trex.duration);
            let default_size = traf.tfhd.default_sample_size.unwrap_or(trex.size);
            let track = index.and_then(|index| Some((index, self.tracks.get(index)?)));
            let mut decode = i128::from(tfdt.base_media_decode_time);
            let base = base_offset(traf, moof_start, previous_end);
            let mut position = base;
            for trun in &traf.trun {
                if let Some(by) = trun.data_offset {
                    position = offset(base, by);
                }
                for entry in &trun.entries {
                    let size = entry.size.unwrap_or(default_size);
                    let start = position;
                    position = position.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
                    let decode_ticks = decode;
                    decode = decode
                        .saturating_add(i128::from(entry.duration.unwrap_or(default_duration)));
                    let Some((index, track)) = track else {
                        continue;
                    };
                    let presentation =
                        decode_ticks.saturating_add(i128::from(entry.cts.unwrap_or(0)));
                    if let Some(payload) = self.payload(track, media, start..position, stats)? {
                        stats.samples = stats.samples.saturating_add(1);
                        units.push(Unit {
                            track: index,
                            decode_time: convert(
                                decode_ticks.saturating_add(track.shift),
                                TS_CLOCK_RATE,
                                track.timescale,
                            ),
                            ts: convert(
                                presentation.saturating_add(track.shift),
                                track.clock_rate,
                                track.timescale,
                            ),
                            payload,
                        });
                    }
                }
            }
            previous_end = Some(position);
        }
        Ok(())
    }

    /// The payload of `track`'s sample at `range` of `media`, covered out
    /// of `media`'s budget before it is copied, or `None` when it is
    /// dropped (counted in `stats`) or the track is not read.
    ///
    /// # Errors
    ///
    /// [`Fmp4Error::OverlappingSamples`] when the sample does not fit the
    /// budget.
    fn payload(
        &self,
        track: &Track,
        media: &mut Media<'_>,
        range: Range<usize>,
        stats: &mut Fmp4Stats,
    ) -> Result<Option<Bytes>, Fmp4Error> {
        let length_size = match track.content {
            Content::Unsupported => return Ok(None),
            Content::Video { length_size } => Some(length_size),
            Content::Audio => None,
        };
        let size = range.end.saturating_sub(range.start);
        if size == 0 {
            stats.dropped_empty = stats.dropped_empty.saturating_add(1);
            return Ok(None);
        }
        if size > self.max_frame_bytes {
            stats.dropped_oversize = stats.dropped_oversize.saturating_add(1);
            return Ok(None);
        }
        let inside = inside(media.data, &range);
        let bytes = media.bytes;
        let Some(sample) = bytes.get(range).filter(|_| inside) else {
            stats.dropped_outside = stats.dropped_outside.saturating_add(1);
            return Ok(None);
        };
        media.budget.cover(sample.len())?;
        let Some(length_size) = length_size else {
            return Ok(Some(Bytes::copy_from_slice(sample)));
        };
        let mut annex_b = Vec::with_capacity(sample.len());
        if length_prefixed_to_annex_b(sample, length_size, &mut annex_b).is_err() {
            stats.dropped_malformed = stats.dropped_malformed.saturating_add(1);
            return Ok(None);
        }
        // The conversion skips empty NAL units, so a sample of only those
        // holds no access unit.
        if annex_b.is_empty() {
            stats.dropped_empty = stats.dropped_empty.saturating_add(1);
            return Ok(None);
        }
        Ok(Some(Bytes::from(annex_b)))
    }
}

/// Whether `range` lies inside one of `data`, the bodies of a segment's
/// media data boxes in order and disjoint: inside the last that starts at
/// or before it, found by binary search, so a sample costs the log of the
/// boxes, however many empty ones a segment holds.
fn inside(data: &[Range<usize>], range: &Range<usize>) -> bool {
    let after = data.partition_point(|mdat| mdat.start <= range.start);
    after
        .checked_sub(1)
        .and_then(|last| data.get(last))
        .is_some_and(|mdat| range.end <= mdat.end)
}

#[cfg(test)]
mod tests;

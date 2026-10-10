//! What the HTTP source's container readers hand on: the layout of the
//! program, then its media one unit at a time, each with the time to
//! pace it at and the timestamp to publish it with.
//!
//! The layout names each track's kind, codec and clock rate, which
//! `TrackPublisher::declare` takes as they are. Video units are whole
//! access units in the Annex B byte stream (ISO/IEC 14496-10 Annex B,
//! ITU-T H.265 Annex B), the input of lotse-codec's `FramedNormalizer`;
//! audio units are raw AAC frames (ISO/IEC 14496-3 §4.4.2.1,
//! `raw_data_block`), what an RTSP camera's RFC 3640 units become on the
//! side branch.

use bytes::Bytes;
use lotse_core::{Codec, Kind};

/// The clock of MPEG-TS presentation and decoding time stamps, and of a
/// video track's timestamps: 90 kHz (ISO/IEC 13818-1 §2.4.3.7, `PTS`).
pub const TS_CLOCK_RATE: u32 = 90_000;

/// The tracks of the program, in the order the program map (MPEG-TS) or
/// the movie box (fragmented MP4) lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The program they belong to (ISO/IEC 13818-1 §2.4.4.3,
    /// `program_number`); 0 for fragmented MP4, which has no programs.
    pub program_number: u16,
    /// The tracks; [`Unit::track`] indexes them.
    pub tracks: Vec<LayoutTrack>,
}

/// One track of a [`Layout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutTrack {
    /// The packet identifier carrying it (ISO/IEC 13818-1 §2.4.4.8,
    /// `elementary_PID`), or its `track_ID` in fragmented MP4 (ISO/IEC
    /// 14496-12 §8.3.2).
    pub id: u32,
    /// Its `stream_type` (ISO/IEC 13818-1 Table 2-34); 0 for fragmented
    /// MP4, whose sample entry names the codec instead.
    pub stream_type: u8,
    /// Video or audio.
    pub kind: Kind,
    /// The codec. Video from MPEG-TS starts without parameter sets, which
    /// the normalizer finds in band; fragmented MP4 video carries those
    /// of its `avcC` or `hvcC` (ISO/IEC 14496-15 §5.3.3, §8.3.3), which
    /// seed the normalizers as an SDP's sets do. [`Codec::Unsupported`]
    /// for a stream that is not read, whose units never come.
    pub codec: Codec,
    /// The clock of its [`Unit::ts`]: [`TS_CLOCK_RATE`] for video and for
    /// an unsupported track, the sampling rate for AAC.
    pub clock_rate: u32,
}

/// One unit of media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    /// The index of its track in the current [`Layout`].
    pub track: usize,
    /// When to send it, on the program's 90 kHz clock: the decoding time
    /// (ISO/IEC 13818-1 §2.4.3.7, `DTS`, else the `PTS`), extended past
    /// the 33-bit wrap. Shared by every track of the program, so it paces
    /// them together; it may be negative.
    pub decode_time: i64,
    /// Its presentation time on the track's clock
    /// ([`LayoutTrack::clock_rate`]), extended past the 33-bit wrap: what
    /// the RTP timestamp and the frame's media time are taken from.
    pub ts: i64,
    /// One access unit in the Annex B byte stream (video) or one raw AAC
    /// frame (audio).
    pub payload: Bytes,
}

/// What a container reader hands on, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The program's tracks, before any of their units, and again
    /// whenever they change: a new program map, another AAC
    /// configuration. Units after it index the new layout.
    Layout(Layout),
    /// One unit of media.
    Unit(Unit),
}

//! MPEG-TS demultiplexing: a transport stream, as an HLS segment or a raw
//! stream over HTTP carries it, into the program's layout and its units
//! of media (see [`crate::media`]).
//!
//! Implements ISO/IEC 13818-1 (ITU-T H.222.0): the transport packet
//! (§2.4.3.2), whose sync byte the `align` module finds; the program association
//! (§2.4.4.3) and program map (§2.4.4.8) tables, through mpeg2ts-reader,
//! which also checks their CRC (Annex A) and acts on a table only when its
//! `version_number` changes; the continuity counter (§2.4.3.3), which
//! mpeg2ts-reader checks per elementary stream; the PES packet (§2.4.3.6)
//! with its PTS and DTS (§2.4.3.7), extended here past their 33-bit wrap
//! on one timeline for the whole program. Stream types (Table 2-34):
//! H.264 (0x1B, carried per §2.14), H.265 (0x24, §2.17) and AAC in ADTS
//! (0x0F, ISO/IEC 13818-7 §6.2) are demultiplexed; the other audio and
//! video types are declared [`Codec::Unsupported`] and not read; the rest
//! (private data, metadata, user private types) are not tracks.
//!
//! The first program the program association table lists is the one read:
//! HLS segments carry exactly one (RFC 8216 §3.2), and so do cameras. A
//! new program map with other streams is a new [`Layout`].
//!
//! Each video PES packet is taken as one access unit, handed on whole in
//! the Annex B byte stream for lotse-codec's `FramedNormalizer` and timed
//! by its PTS and DTS: the PTS of a PES packet times the first access
//! unit beginning in it (§2.4.3.7), and muxers write one per packet
//! (ffmpeg 9.0.2's MPEG-TS muxer, observed 2026-10-08, with
//! `PES_packet_length` 0, which §2.4.3.7 allows for video). A video PES
//! packet without a PTS is dropped: §2.4.3.7 lets a muxer leave it out
//! (a PTS at least every 0.7 s), but then its access unit has no time.
//! ADTS is split into raw AAC frames by lotse-codec's `AdtsSplitter`; a
//! PES packet's PTS times the first frame beginning in it (§2.4.3.7),
//! and the frames after it follow 1024 samples apart (ISO/IEC 14496-3
//! §4.4.1, `frameLengthFlag` 0, the only frame length ADTS has), so the
//! timestamps stay continuous when a PES PTS is rounded, and restart
//! from the PTS when it is more than half a frame away.
//!
//! The layout is handed on once every AAC track has had its first ADTS
//! header, which gives its sampling rate, the track's clock rate: until
//! then units are held, at most [`HOLD_TICKS`] of program time and
//! `max_frame_bytes` of payload, after which an AAC track still without
//! a header is declared [`Codec::Unsupported`] and its frames are dropped.
//!
//! The normalizers are not run here: the caller paces units at their
//! decode time and normalizes each video unit when it is sent, so the
//! codec update a new SPS brings reaches the track with that unit, as
//! the RTSP source does it. A PES packet ends when the next one on its
//! PID begins; [`Demuxer::flush`] ends the open ones where the input
//! ends, at the end of an HLS segment.
//!
//! Pure: no I/O, no clock, no logging. The caller logs the layouts and
//! reports the [`DemuxStats`]: each continuity error is at least one
//! transport packet lost, an `IngestCounters::count_lost` of one.
//! The program clock reference (§2.4.3.5) is not read: the caller's pacer
//! gives the program its time base.

mod align;
#[cfg(test)]
pub(crate) mod test_data;

use bytes::Bytes;
use lotse_codec::aac::{AdtsConfig, AdtsFrame, AdtsSplitter, FRAME_SAMPLES};
use lotse_core::{Codec, Kind};
use mpeg2ts_reader::demultiplex::{
    Demultiplex, DemuxContext, FilterChangeset, FilterRequest, NullPacketFilter, PacketFilter,
    PatPacketFilter, PmtPacketFilter,
};
use mpeg2ts_reader::packet::Packet;
use mpeg2ts_reader::pes::{
    ElementaryStreamConsumer, PesContents, PesError, PesHeader, PesPacketFilter, PtsDts,
};
use mpeg2ts_reader::psi::pat::PAT_PID;
use mpeg2ts_reader::psi::pmt::PmtSection;

use self::align::Aligner;
use crate::media::{Event, Layout, LayoutTrack, TS_CLOCK_RATE, Unit};

/// H.264 video (ISO/IEC 13818-1 Table 2-34, `stream_type` 0x1B).
const STREAM_H264: u8 = 0x1b;

/// H.265 video (ISO/IEC 13818-1 Table 2-34, `stream_type` 0x24).
const STREAM_H265: u8 = 0x24;

/// AAC with the ADTS transport syntax (ISO/IEC 13818-1 Table 2-34,
/// `stream_type` 0x0F).
const STREAM_ADTS: u8 = 0x0f;

/// The longest units are held for the first ADTS header of every AAC
/// track: two seconds of the 90 kHz program clock. Muxers interleave
/// audio and video far more tightly (ffmpeg's MPEG-TS muxer within its
/// default `max_delay` of 0.7 s).
pub const HOLD_TICKS: u64 = 2 * TS_CLOCK_RATE as u64;

/// The span of PTS and DTS: 33 bits (ISO/IEC 13818-1 §2.4.3.7).
const TIMESTAMP_WRAP: i64 = 1 << 33;

/// The samples of one AAC frame, as a signed count.
const FRAME: i128 = FRAME_SAMPLES as i128;

/// How far a PES PTS may lie from the frame count before the AAC
/// timestamps restart from it: half a frame, in samples. Rounding a PTS
/// to the 90 kHz clock moves it by a sample at most; a lost frame by a
/// whole one.
const REANCHOR_SAMPLES: i128 = FRAME / 2;

/// What the demultiplexer counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DemuxStats {
    /// Whole transport packets read.
    pub packets: u64,
    /// Bytes skipped looking for the sync byte.
    pub skipped_bytes: u64,
    /// Times a packet did not begin with the sync byte where one was due.
    pub sync_losses: u64,
    /// Continuity counter errors on a demultiplexed stream (ISO/IEC
    /// 13818-1 §2.4.3.3): each one is at least one packet lost.
    pub continuity_errors: u64,
    /// PES packets dropped as larger than `max_frame_bytes`.
    pub dropped_oversize: u64,
    /// PES packets dropped for a header that cannot be read.
    pub dropped_malformed: u64,
    /// Units dropped without a time: video without a PTS, AAC frames
    /// before the first PTS of their track.
    pub dropped_untimed: u64,
    /// PES packets dropped unfinished, their rest lost.
    pub dropped_incomplete: u64,
    /// Times the AAC timestamps restarted from a PES PTS that the frame
    /// count did not reach.
    pub audio_reanchors: u64,
}

/// The MPEG-TS demultiplexer of one stream.
pub struct Demuxer {
    /// Bytes to whole packets.
    aligner: Aligner,
    /// mpeg2ts-reader's packet dispatch, by PID.
    demux: Demultiplex<Ctx>,
    /// The program and its streams.
    ctx: Ctx,
}

impl std::fmt::Debug for Demuxer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Demuxer")
            .field("stats", &self.stats())
            .field("tracks", &self.ctx.tracks.len())
            .field("buffered", &self.buffered())
            .finish_non_exhaustive()
    }
}

impl Demuxer {
    /// A demultiplexer keeping PES packets up to `max_frame_bytes`
    /// (`limits.max_frame_bytes`).
    #[must_use]
    pub fn new(max_frame_bytes: usize) -> Self {
        let mut ctx = Ctx::new(max_frame_bytes);
        let demux = Demultiplex::new(&mut ctx);
        Self {
            aligner: Aligner::default(),
            demux,
            ctx,
        }
    }

    /// Takes the next bytes of the stream, in any pieces, and appends what
    /// they complete to `out`.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<Event>) {
        let Self {
            aligner,
            demux,
            ctx,
        } = self;
        aligner.push(data, &mut |packets| demux.push(ctx, packets));
        out.append(&mut ctx.events);
    }

    /// Ends the PES packets still open, as the end of the input ends them,
    /// and appends what they complete to `out`. Bytes of a packet not yet
    /// complete stay, and a PES packet whose rest still comes is dropped
    /// then.
    pub fn flush(&mut self, out: &mut Vec<Event>) {
        for index in 0..self.ctx.tracks.len() {
            self.ctx.finish(index);
        }
        out.append(&mut self.ctx.events);
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> DemuxStats {
        let align = self.aligner.stats();
        DemuxStats {
            packets: align.packets,
            skipped_bytes: align.skipped_bytes,
            sync_losses: align.sync_losses,
            ..self.ctx.stats
        }
    }

    /// Bytes held: a partial packet, open PES packets, units waiting for
    /// the layout. Each is bounded: fewer than three packets,
    /// `max_frame_bytes` per stream, `max_frame_bytes` plus one unit.
    #[must_use]
    pub fn buffered(&self) -> usize {
        let open: usize = self
            .ctx
            .tracks
            .iter()
            .filter_map(|track| track.pes.as_ref())
            .map(|pes| pes.data.len())
            .sum();
        self.aligner
            .buffered()
            .saturating_add(open)
            .saturating_add(self.ctx.held_bytes)
    }
}

/// What a stream of the program map is to the demultiplexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamClass {
    /// H.264, demultiplexed.
    H264,
    /// H.265, demultiplexed.
    H265,
    /// AAC in ADTS, demultiplexed.
    Adts,
    /// Audio or video of another codec: declared, not read.
    Unsupported(Kind, &'static str),
    /// Not a track.
    Other,
}

/// The class of a `stream_type` (ISO/IEC 13818-1 Table 2-34). The
/// unsupported codecs carry the names the API reports.
const fn classify(stream_type: u8) -> StreamClass {
    match stream_type {
        STREAM_H264 => StreamClass::H264,
        STREAM_H265 => StreamClass::H265,
        STREAM_ADTS => StreamClass::Adts,
        0x01 => StreamClass::Unsupported(Kind::Video, "mpeg1_video"),
        0x02 => StreamClass::Unsupported(Kind::Video, "mpeg2_video"),
        0x10 => StreamClass::Unsupported(Kind::Video, "mpeg4_visual"),
        0x42 => StreamClass::Unsupported(Kind::Video, "avs"),
        0x03 => StreamClass::Unsupported(Kind::Audio, "mpeg1_audio"),
        0x04 => StreamClass::Unsupported(Kind::Audio, "mpeg2_audio"),
        0x11 => StreamClass::Unsupported(Kind::Audio, "aac_latm"),
        0x1c => StreamClass::Unsupported(Kind::Audio, "mpeg4_audio"),
        _ => StreamClass::Other,
    }
}

/// A PES packet being collected.
#[derive(Debug)]
struct Pes {
    /// Its PTS and DTS, extended: `None` without a PTS.
    timing: Option<Timing>,
    /// Its payload so far, at most `max_frame_bytes`.
    data: Vec<u8>,
}

/// The presentation and decoding time of a PES packet on the program's
/// extended 90 kHz timeline.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// PTS.
    pts: i64,
    /// DTS, the PTS when absent (ISO/IEC 13818-1 §2.4.3.7).
    dts: i64,
}

/// Where an AAC track stands with its configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AudioConfig {
    /// No ADTS header yet; the layout waits.
    Waiting,
    /// The configuration the layout declares.
    Declared(AdtsConfig),
    /// The layout went out without one: frames are dropped.
    Absent,
}

/// The sample an AAC frame's timestamps count from.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    /// The frame's sequence.
    sequence: u64,
    /// Its timestamp, in samples.
    samples: i64,
}

impl Anchor {
    /// The timestamp of frame `sequence`, 1024 samples a frame from here.
    fn at(self, sequence: u64) -> i128 {
        let frames = i128::from(sequence).saturating_sub(i128::from(self.sequence));
        i128::from(self.samples).saturating_add(frames.saturating_mul(FRAME))
    }
}

/// An AAC track's state.
#[derive(Debug)]
struct Audio {
    /// ADTS to raw frames.
    splitter: AdtsSplitter,
    /// The configuration.
    config: AudioConfig,
    /// What timestamps count from; `None` before the first PTS and after
    /// a configuration change.
    anchor: Option<Anchor>,
}

/// What an AAC frame changes in the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    /// Nothing.
    None,
    /// Its track's first configuration.
    Declared,
    /// Another configuration than the declared one.
    Changed,
}

/// A raw AAC frame with its times: decode time, timestamp, payload.
type TimedFrame = (i64, i64, Bytes);

impl Audio {
    /// Takes one frame of the PES packet whose PTS (if any) times frame
    /// `first`: what it changes in the layout and, unless it is dropped,
    /// the frame with its times.
    fn accept(
        &mut self,
        frame: AdtsFrame,
        first: Option<u64>,
        pts: Option<i64>,
        stats: &mut DemuxStats,
    ) -> (Change, Option<TimedFrame>) {
        let change = match self.config {
            AudioConfig::Absent => return (Change::None, None),
            AudioConfig::Waiting => Change::Declared,
            AudioConfig::Declared(declared) if declared != frame.config => {
                self.anchor = None;
                Change::Changed
            }
            AudioConfig::Declared(_) => Change::None,
        };
        self.config = AudioConfig::Declared(frame.config);
        // An undecodable configuration is an unsupported track: no units.
        let Ok(aac) = frame.config.parsed else {
            return (change, None);
        };
        let rate = i128::from(aac.sample_rate);
        if first == Some(frame.sequence)
            && let Some(pts) = pts
        {
            let samples = i128::from(pts)
                .saturating_mul(rate)
                .div_euclid(i128::from(TS_CLOCK_RATE));
            let moved = self
                .anchor
                .map(|anchor| anchor.at(frame.sequence).abs_diff(samples));
            if moved.is_none_or(|moved| moved > REANCHOR_SAMPLES.unsigned_abs()) {
                if moved.is_some() {
                    stats.audio_reanchors = stats.audio_reanchors.saturating_add(1);
                }
                self.anchor = Some(Anchor {
                    sequence: frame.sequence,
                    samples: clamp(samples),
                });
            }
        }
        let Some(anchor) = self.anchor else {
            stats.dropped_untimed = stats.dropped_untimed.saturating_add(1);
            return (change, None);
        };
        let ts = anchor.at(frame.sequence);
        let decode_time = ts
            .saturating_mul(i128::from(TS_CLOCK_RATE))
            .div_euclid(rate);
        (change, Some((clamp(decode_time), clamp(ts), frame.payload)))
    }
}

/// `value` within the range of `i64`.
pub(crate) fn clamp(value: i128) -> i64 {
    i64::try_from(value.clamp(i128::from(i64::MIN), i128::from(i64::MAX))).unwrap_or_default()
}

/// What a track carries.
#[derive(Debug)]
enum Content {
    /// H.264 or H.265: its codec, without parameter sets yet.
    Video(Codec),
    /// AAC in ADTS.
    Audio(Audio),
    /// Not read.
    Unsupported(Kind, &'static str),
}

/// One track of the program.
#[derive(Debug)]
struct Track {
    /// Its PID.
    pid: u16,
    /// Its `stream_type`.
    stream_type: u8,
    /// What it carries.
    content: Content,
    /// The PES packet being collected.
    pes: Option<Pes>,
}

impl Track {
    /// The track of a stream the program map lists; `None` for a stream
    /// that is not a track.
    fn new(pid: u16, stream_type: u8, max_frame_bytes: usize) -> Option<Self> {
        let content = match classify(stream_type) {
            StreamClass::H264 => Content::Video(Codec::H264 {
                profile_level_id: None,
                sps: None,
                pps: None,
            }),
            StreamClass::H265 => Content::Video(Codec::H265 {
                vps: None,
                sps: None,
                pps: None,
            }),
            StreamClass::Adts => Content::Audio(Audio {
                splitter: AdtsSplitter::new(max_frame_bytes),
                config: AudioConfig::Waiting,
                anchor: None,
            }),
            StreamClass::Unsupported(kind, name) => Content::Unsupported(kind, name),
            StreamClass::Other => return None,
        };
        Some(Self {
            pid,
            stream_type,
            content,
            pes: None,
        })
    }

    /// Whether its PES packets are read.
    const fn demultiplexed(&self) -> bool {
        !matches!(self.content, Content::Unsupported(..))
    }

    /// Whether the layout waits for it.
    const fn waiting(&self) -> bool {
        matches!(
            self.content,
            Content::Audio(Audio {
                config: AudioConfig::Waiting,
                ..
            })
        )
    }

    /// Its entry in the layout.
    fn layout(&self) -> LayoutTrack {
        let (kind, codec, clock_rate) = match &self.content {
            Content::Video(codec) => (Kind::Video, codec.clone(), TS_CLOCK_RATE),
            Content::Audio(audio) => match audio.config {
                AudioConfig::Declared(config) => match config.parsed {
                    Ok(aac) => (
                        Kind::Audio,
                        Codec::AacLc {
                            sample_rate: aac.sample_rate,
                            channels: aac.channels,
                            config: Bytes::copy_from_slice(&config.audio_specific_config),
                        },
                        aac.sample_rate,
                    ),
                    Err(err) => unsupported(Kind::Audio, err.codec_name()),
                },
                AudioConfig::Waiting | AudioConfig::Absent => unsupported(Kind::Audio, "aac"),
            },
            Content::Unsupported(kind, name) => unsupported(*kind, name),
        };
        LayoutTrack {
            id: u32::from(self.pid),
            stream_type: self.stream_type,
            kind,
            codec,
            clock_rate,
        }
    }
}

/// The layout entry of a track that is not read: its kind, the codec
/// name, the 90 kHz clock of MPEG-TS time stamps.
fn unsupported(kind: Kind, name: &str) -> (Kind, Codec, u32) {
    (
        kind,
        Codec::Unsupported {
            kind,
            name: name.to_owned(),
        },
        TS_CLOCK_RATE,
    )
}

/// The packet filters mpeg2ts-reader dispatches each PID to.
enum Filter {
    /// The program association table (ISO/IEC 13818-1 §2.4.4.3).
    Pat(PatPacketFilter<Ctx>),
    /// The program map table of the program read (§2.4.4.8).
    Pmt(PmtPacketFilter<Ctx>),
    /// A demultiplexed stream's PES packets.
    Stream(PesPacketFilter<Ctx, StreamConsumer>),
    /// Anything else, ignored.
    Null(NullPacketFilter<Ctx>),
}

impl PacketFilter for Filter {
    type Ctx = Ctx;

    fn consume(&mut self, ctx: &mut Ctx, packet: &Packet<'_>) {
        match self {
            Self::Pat(filter) => filter.consume(ctx, packet),
            Self::Pmt(filter) => filter.consume(ctx, packet),
            Self::Stream(filter) => filter.consume(ctx, packet),
            Self::Null(filter) => filter.consume(ctx, packet),
        }
    }
}

/// The PES packets of one stream, handed to the context by track.
struct StreamConsumer {
    /// The index of the stream's track. Valid while the filter is: a
    /// program map that replaces the tracks replaces every filter.
    index: usize,
}

impl ElementaryStreamConsumer<Ctx> for StreamConsumer {
    fn start_stream(&mut self, ctx: &mut Ctx) {
        // A new filter for the PID, after a new version of the program
        // map with the same streams: it begins at a PES packet, so the
        // one still open ends here. Usually the version changes between
        // PES packets; if not, the packets dropped before this one are
        // missing from it.
        ctx.finish(self.index);
    }

    fn begin_packet(&mut self, ctx: &mut Ctx, header: PesHeader<'_>) {
        ctx.begin(self.index, &header);
    }

    fn continue_packet(&mut self, ctx: &mut Ctx, data: &[u8]) {
        ctx.append(self.index, data);
    }

    fn end_packet(&mut self, ctx: &mut Ctx) {
        ctx.finish(self.index);
    }

    fn continuity_error(&mut self, ctx: &mut Ctx) {
        ctx.stats.continuity_errors = ctx.stats.continuity_errors.saturating_add(1);
        ctx.cut(self.index);
    }
}

/// The demultiplexer's state: the program read, its tracks and what
/// they produced.
struct Ctx {
    /// Filter changes mpeg2ts-reader applies after a table.
    changeset: FilterChangeset<Filter>,
    /// The PES size limit.
    max_frame_bytes: usize,
    /// The program read, once the program association table named it.
    program: Option<u16>,
    /// The (PID, `stream_type`) of the tracks of the last program map.
    streams: Option<Vec<(u16, u8)>>,
    /// The tracks.
    tracks: Vec<Track>,
    /// Whether the layout of these tracks went out.
    ready: bool,
    /// Units waiting for the layout.
    held: Vec<Unit>,
    /// Their payload bytes.
    held_bytes: usize,
    /// The last extended timestamp, which the next one is extended near.
    last_time: Option<i64>,
    /// Events for the caller.
    events: Vec<Event>,
    /// Counters.
    stats: DemuxStats,
}

impl DemuxContext for Ctx {
    type F = Filter;

    fn filter_changeset(&mut self) -> &mut FilterChangeset<Filter> {
        &mut self.changeset
    }

    fn construct(&mut self, request: FilterRequest<'_, '_>) -> Filter {
        match request {
            FilterRequest::ByPid(PAT_PID) => Filter::Pat(PatPacketFilter::default()),
            FilterRequest::Pmt {
                pid,
                program_number,
            } if self.program.is_none_or(|program| program == program_number) => {
                self.program = Some(program_number);
                Filter::Pmt(PmtPacketFilter::new(pid, program_number))
            }
            FilterRequest::ByStream {
                pmt, stream_info, ..
            } => {
                self.program_map(pmt);
                let pid = u16::from(stream_info.elementary_pid());
                match self
                    .tracks
                    .iter()
                    .position(|track| track.pid == pid && track.demultiplexed())
                {
                    Some(index) => Filter::Stream(PesPacketFilter::new(StreamConsumer { index })),
                    None => Filter::Null(NullPacketFilter::default()),
                }
            }
            FilterRequest::ByPid(_) | FilterRequest::Pmt { .. } | FilterRequest::Nit { .. } => {
                Filter::Null(NullPacketFilter::default())
            }
        }
    }
}

/// What a PES header gives: its PTS and DTS, raw, and the payload after
/// it in the first transport packet.
struct RawHeader<'a> {
    /// PTS and DTS (the PTS again when only it is there); `None` without
    /// a PTS.
    times: Option<(u64, u64)>,
    /// The payload bytes.
    payload: &'a [u8],
}

/// Reads a PES header; `None` when it cannot be read or has the forbidden
/// `PTS_DTS_flags` `01` (ISO/IEC 13818-1 §2.4.3.7).
fn read_header<'a>(header: &PesHeader<'a>) -> Option<RawHeader<'a>> {
    let PesContents::Parsed(Some(parsed)) = header.contents() else {
        return None;
    };
    let times = match parsed.pts_dts() {
        Ok(PtsDts::PtsOnly(Ok(pts))) => Some((pts.value(), pts.value())),
        Ok(PtsDts::Both {
            pts: Ok(pts),
            dts: Ok(dts),
        }) => Some((pts.value(), dts.value())),
        Err(PesError::FieldNotPresent) => None,
        _ => return None,
    };
    Some(RawHeader {
        times,
        payload: parsed.payload(),
    })
}

impl Ctx {
    /// An empty context.
    fn new(max_frame_bytes: usize) -> Self {
        Self {
            changeset: FilterChangeset::default(),
            max_frame_bytes,
            program: None,
            streams: None,
            tracks: Vec::new(),
            ready: false,
            held: Vec::new(),
            held_bytes: 0,
            last_time: None,
            events: Vec::new(),
            stats: DemuxStats::default(),
        }
    }

    /// A program map of the program read: new tracks when its streams
    /// differ from the last one's. The PES packets open on the old ones
    /// end first; units held for a layout that never went out go with it.
    fn program_map(&mut self, pmt: &PmtSection<'_>) {
        let tracks: Vec<Track> = pmt
            .streams()
            .filter_map(|stream| {
                Track::new(
                    u16::from(stream.elementary_pid()),
                    u8::from(stream.stream_type()),
                    self.max_frame_bytes,
                )
            })
            .collect();
        let streams: Vec<(u16, u8)> = tracks
            .iter()
            .map(|track| (track.pid, track.stream_type))
            .collect();
        if self.streams.as_ref() == Some(&streams) {
            return;
        }
        for index in 0..self.tracks.len() {
            self.finish(index);
        }
        self.streams = Some(streams);
        self.tracks = tracks;
        self.ready = false;
        self.held.clear();
        self.held_bytes = 0;
        self.try_ready();
    }

    /// Hands the layout on, with the units held for it, once no track
    /// waits. Called only while it has not gone out: a track waits only
    /// until then.
    fn try_ready(&mut self) {
        if self.tracks.iter().any(Track::waiting) {
            return;
        }
        self.ready = true;
        self.events.push(Event::Layout(self.layout()));
        self.events.extend(self.held.drain(..).map(Event::Unit));
        self.held_bytes = 0;
    }

    /// The current layout.
    fn layout(&self) -> Layout {
        Layout {
            program_number: self.program.unwrap_or_default(),
            tracks: self.tracks.iter().map(Track::layout).collect(),
        }
    }

    /// Hands a unit on, or holds it while the layout waits; held too
    /// long, the layout goes out without the configurations still
    /// missing.
    fn emit(&mut self, unit: Unit) {
        if self.ready {
            self.events.push(Event::Unit(unit));
            return;
        }
        let span = self
            .held
            .first()
            .map_or(0, |first| first.decode_time.abs_diff(unit.decode_time));
        self.held_bytes = self.held_bytes.saturating_add(unit.payload.len());
        self.held.push(unit);
        if span > HOLD_TICKS || self.held_bytes > self.max_frame_bytes {
            for track in &mut self.tracks {
                if let Content::Audio(audio) = &mut track.content
                    && audio.config == AudioConfig::Waiting
                {
                    audio.config = AudioConfig::Absent;
                }
            }
            self.try_ready();
        }
    }

    /// Extends a 33-bit PTS or DTS onto the program's timeline: the value
    /// nearest the last one that matches it modulo 2^33.
    fn extend(&mut self, raw: u64) -> i64 {
        let raw = i64::try_from(raw).unwrap_or_default();
        let value = self.last_time.map_or(raw, |last| {
            let ahead = raw
                .wrapping_sub(last.rem_euclid(TIMESTAMP_WRAP))
                .rem_euclid(TIMESTAMP_WRAP);
            let step = if ahead >= TIMESTAMP_WRAP / 2 {
                ahead.wrapping_sub(TIMESTAMP_WRAP)
            } else {
                ahead
            };
            last.saturating_add(step)
        });
        self.last_time = Some(value);
        value
    }

    /// Drops the PES packet open on track `index`, its rest lost.
    fn cut(&mut self, index: usize) {
        if self
            .tracks
            .get_mut(index)
            .and_then(|track| track.pes.take())
            .is_some()
        {
            self.stats.dropped_incomplete = self.stats.dropped_incomplete.saturating_add(1);
        }
    }

    /// A PES packet begins on track `index`.
    fn begin(&mut self, index: usize, header: &PesHeader<'_>) {
        let Some(RawHeader { times, payload }) = read_header(header) else {
            self.stats.dropped_malformed = self.stats.dropped_malformed.saturating_add(1);
            return;
        };
        let timing = times.map(|(pts, dts)| Timing {
            pts: self.extend(pts),
            dts: self.extend(dts),
        });
        if let Some(track) = self.tracks.get_mut(index) {
            track.pes = Some(Pes {
                timing,
                data: Vec::new(),
            });
        }
        self.append(index, payload);
    }

    /// More payload of the PES packet open on track `index`, if one is;
    /// over the limit, the packet is dropped.
    fn append(&mut self, index: usize, data: &[u8]) {
        if let Some(track) = self.tracks.get_mut(index)
            && let Some(pes) = track.pes.as_mut()
        {
            if pes.data.len().saturating_add(data.len()) > self.max_frame_bytes {
                track.pes = None;
                self.stats.dropped_oversize = self.stats.dropped_oversize.saturating_add(1);
            } else {
                pes.data.extend_from_slice(data);
            }
        }
    }

    /// Hands on what the PES packet open on track `index` holds, if one
    /// is.
    fn finish(&mut self, index: usize) {
        let pes = self
            .tracks
            .get_mut(index)
            .and_then(|track| track.pes.take());
        let Some(pes) = pes else { return };
        let content = self.tracks.get_mut(index).map(|track| &mut track.content);
        let steps: Vec<(Change, Option<TimedFrame>)> = if let Some(Content::Audio(audio)) = content
        {
            let mut frames = Vec::new();
            let first = audio.splitter.push(&pes.data, &mut frames);
            let pts = pes.timing.map(|timing| timing.pts);
            frames
                .into_iter()
                .map(|frame| audio.accept(frame, first, pts, &mut self.stats))
                .collect()
        } else {
            let Some(timing) = pes.timing else {
                self.stats.dropped_untimed = self.stats.dropped_untimed.saturating_add(1);
                return;
            };
            self.emit(Unit {
                track: index,
                decode_time: timing.dts,
                ts: timing.pts,
                payload: Bytes::from(pes.data),
            });
            return;
        };
        for (change, timed) in steps {
            match change {
                Change::Declared => self.try_ready(),
                Change::Changed if self.ready => {
                    self.events.push(Event::Layout(self.layout()));
                }
                Change::Changed | Change::None => {}
            }
            if let Some((decode_time, ts, payload)) = timed {
                self.emit(Unit {
                    track: index,
                    decode_time,
                    ts,
                    payload,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;

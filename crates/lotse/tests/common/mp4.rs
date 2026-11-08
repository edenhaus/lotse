//! An event recording's file read back with mp4-atom, a reader of ISO/IEC
//! 14496-12 independent of lotse's muxer: its boxes in order, each track's
//! samples, and the checks every recording's video passes. Shared by the
//! recording tests of the RTSP and the WebRTC sources.

use mp4_atom::{Any, Codec as SampleEntry, Decode as _, Moof, Moov};

/// `sample_is_non_sync_sample` in a sample's flags (ISO/IEC 14496-12
/// §8.8.3.1).
pub(crate) const NON_SYNC: u32 = 0x0001_0000;

/// An IDR slice's NAL unit type (ISO/IEC 14496-10 Table 7-1).
pub(crate) const NAL_IDR: u8 = 5;

/// A recording's file as mp4-atom reads it: every top-level box, in order.
pub(crate) struct Mp4 {
    pub(crate) moov: Moov,
    /// Each fragment and where its `moof` starts in the file.
    pub(crate) fragments: Vec<(Moof, usize)>,
}

/// One sample read back.
#[derive(Debug, Clone)]
pub(crate) struct Sample {
    /// Decode time in the track's timescale.
    pub(crate) dts: u64,
    pub(crate) duration: u64,
    pub(crate) sync: bool,
    pub(crate) bytes: Vec<u8>,
}

/// Reads `file` box by box: `ftyp` first (ISO/IEC 14496-12 §4.3), then
/// `moov`, then a `moof` and an `mdat` per fragment, nothing left over.
pub(crate) fn parse(file: &[u8]) -> Mp4 {
    let mut rest = file;
    let mut boxes = Vec::new();
    while !rest.is_empty() {
        let start = file.len() - rest.len();
        boxes.push((Any::decode(&mut rest).expect("a box"), start));
    }
    let mut boxes = boxes.into_iter();
    let Some((Any::Ftyp(ftyp), 0)) = boxes.next() else {
        panic!("the file does not begin with ftyp");
    };
    assert_eq!(ftyp.major_brand, b"iso6".into());
    let Some((Any::Moov(movie), _)) = boxes.next() else {
        panic!("no moov after ftyp");
    };
    let mut fragments = Vec::new();
    while let Some((placed, start)) = boxes.next() {
        let Any::Moof(moof) = placed else {
            panic!("a {:?} where a moof belongs", placed.kind());
        };
        let Some((Any::Mdat(_), _)) = boxes.next() else {
            panic!("a moof without its mdat");
        };
        fragments.push((moof, start));
    }
    Mp4 {
        moov: movie,
        fragments,
    }
}

impl Mp4 {
    /// The track whose sample entry `pick` takes: its id and timescale.
    pub(crate) fn track(&self, pick: impl Fn(&SampleEntry) -> bool) -> Option<(u32, u64)> {
        self.moov
            .trak
            .iter()
            .find(|trak| trak.mdia.minf.stbl.stsd.codecs.iter().any(&pick))
            .map(|trak| (trak.tkhd.track_id, u64::from(trak.mdia.mdhd.timescale)))
    }

    /// The video track: `avc1`.
    pub(crate) fn video(&self) -> (u32, u64) {
        self.track(|entry| matches!(entry, SampleEntry::Avc1(_)))
            .expect("an avc1 track")
    }

    /// The audio track's sample entry and samples, if it has one.
    pub(crate) fn audio(&self, file: &[u8]) -> Option<(SampleEntry, u64, Vec<Sample>)> {
        let trak = self.moov.trak.iter().find(|trak| {
            trak.mdia
                .minf
                .stbl
                .stsd
                .codecs
                .iter()
                .any(|entry| matches!(entry, SampleEntry::Mp4a(_) | SampleEntry::Opus(_)))
        })?;
        let entry = trak.mdia.minf.stbl.stsd.codecs[0].clone();
        let samples = self.samples(file, trak.tkhd.track_id);
        Some((entry, u64::from(trak.mdia.mdhd.timescale), samples))
    }

    /// The samples of track `track_id`, in decode order.
    pub(crate) fn samples(&self, file: &[u8], track_id: u32) -> Vec<Sample> {
        let default_flags = self
            .moov
            .mvex
            .as_ref()
            .and_then(|mvex| mvex.trex.iter().find(|trex| trex.track_id == track_id))
            .map_or(0, |trex| trex.default_sample_flags);
        let mut out = Vec::new();
        for (moof, start) in &self.fragments {
            for traf in moof
                .traf
                .iter()
                .filter(|traf| traf.tfhd.track_id == track_id)
            {
                // ISO/IEC 14496-12 §8.8.7: offsets count from the moof.
                assert!(traf.tfhd.default_base_is_moof);
                let mut dts = traf.tfdt.as_ref().expect("a tfdt").base_media_decode_time;
                for trun in &traf.trun {
                    let offset = usize::try_from(trun.data_offset.expect("a data offset")).unwrap();
                    let mut at = start + offset;
                    for entry in &trun.samples {
                        let size = usize::try_from(entry.size.expect("a size")).unwrap();
                        let duration = u64::from(entry.duration.expect("a duration"));
                        let flags = entry
                            .flags
                            .or(traf.tfhd.default_sample_flags)
                            .unwrap_or(default_flags);
                        out.push(Sample {
                            dts,
                            duration,
                            sync: flags & NON_SYNC == 0,
                            bytes: file[at..at + size].to_vec(),
                        });
                        at += size;
                        dts += duration;
                    }
                }
            }
        }
        out
    }
}

/// The NAL unit types of a sample of 4-byte length-prefixed NAL units
/// (ISO/IEC 14496-15 §5.3.3.1, `lengthSizeMinusOne` 3).
pub(crate) fn nal_types(sample: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut rest = sample;
    while let Some((length, after)) = rest.split_first_chunk::<4>() {
        let length = usize::try_from(u32::from_be_bytes(*length)).unwrap();
        let (unit, next) = after.split_at(length);
        types.push(unit[0] & 0x1f);
        rest = next;
    }
    assert!(rest.is_empty(), "a sample ends inside a NAL unit's length");
    types
}

/// Milliseconds of `ticks` at `rate`, rounded down as the daemon's
/// recording times are.
pub(crate) fn ms(ticks: u64, rate: u64) -> u64 {
    ticks * 1_000 / rate
}

/// Where each sample after the first in `samples` begins later than the
/// one before it ended: the holes on the track's timeline, as the
/// decode times of the samples around them.
pub(crate) fn holes(samples: &[Sample]) -> Vec<(u64, u64)> {
    samples
        .windows(2)
        .filter(|pair| pair[1].dts > pair[0].dts + pair[0].duration)
        .map(|pair| (pair[0].dts, pair[1].dts))
        .collect()
}

/// A video track of `samples` starts at a keyframe with its IDR and has no
/// hole.
pub(crate) fn assert_starts_at_a_keyframe_without_holes(samples: &[Sample]) {
    let first = samples.first().expect("video samples");
    assert!(first.sync, "the first sample is a sync sample");
    assert!(
        nal_types(&first.bytes).contains(&NAL_IDR),
        "{:?}",
        nal_types(&first.bytes)
    );
    assert_eq!(holes(samples), [], "the video runs without a hole");
}

//! The init segment of a clip: the file type box and the movie box with
//! one track per clip track, and the movie extends box that announces the
//! fragments.
//!
//! Implements ISO/IEC 14496-12: `ftyp` (§4.3), `moov` with `mvhd`
//! (§8.2.2), per track `tkhd` (§8.3.2), `mdhd` (§8.4.2), `hdlr` (§8.4.3),
//! `vmhd`/`smhd` (§12.1.2, §12.2.2), `dinf`/`dref` (§8.7.1, §8.7.2) and
//! an `stbl` whose `stsd` (§8.5.2) holds the one sample entry and whose
//! sample tables (`stts`, `stsc`, `stsz`, `stco`) are empty, since every
//! sample is in a fragment; `mvex` with one `trex` per track (§8.8.1,
//! §8.8.3). The sample entries: `avc1` with its `avcC` (ISO/IEC 14496-15
//! §5.4.2.1, the record §5.3.3.1), `hvc1` with its `hvcC` (§8.4.1.1, the
//! record §8.3.3.1), `mp4a` with its `esds` (ISO/IEC 14496-14 §5.6, the
//! `DecoderConfigDescriptor` of ISO/IEC 14496-1 §7.2.6.6 around the
//! track's `AudioSpecificConfig`, ISO/IEC 14496-3 §1.6.2.1), and `Opus`
//! with its `dOps` ("Encapsulation of Opus in ISO Base Media File
//! Format", v0.8.1 §4.3.1 and §4.3.2).
//!
//! The parameter sets are in the sample entry; which of them the samples
//! keep is the fragments' business (see [`crate::fragment`]).

use bytes::Bytes;
use lotse_codec::h265::nal::{PPS_NUT, SPS_NUT, VPS_NUT};
use lotse_codec::{h264, h265};
use lotse_core::Codec;
use lotse_core::clip::{ClipError, ClipTrack};
use mp4_atom::esds::{DecoderConfig, DecoderSpecific, EsDescriptor, SLConfig};
use mp4_atom::{
    Audio, Avc1, Avcc, AvccExt, Codec as SampleEntry, Dinf, Dops, Dref, Encode as _, Esds,
    FixedPoint, FourCC, Ftyp, Hdlr, Hvc1, HvcCArray, Hvcc, Mdhd, Mdia, Minf, Moov, Mp4a, Mvex,
    Mvhd, Opus, Smhd, Stbl, Stco, Stsd, Tkhd, Trak, Trex, Url, Visual, Vmhd,
};

use crate::encode_failed;

/// The track ID of the video track (ISO/IEC 14496-12 §8.3.2, `track_ID`).
pub(crate) const VIDEO_TRACK_ID: u32 = 1;

/// The track ID of the audio track.
pub(crate) const AUDIO_TRACK_ID: u32 = 2;

/// The sample flags of a sync sample (ISO/IEC 14496-12 §8.8.3.1):
/// `sample_depends_on` 2 (it depends on no other sample),
/// `sample_is_non_sync_sample` 0.
pub(crate) const SYNC_SAMPLE: u32 = 0x0200_0000;

/// The sample flags of any other video sample (ISO/IEC 14496-12
/// §8.8.3.1): `sample_depends_on` 1, `sample_is_non_sync_sample` 1.
pub(crate) const NON_SYNC_SAMPLE: u32 = 0x0101_0000;

/// The bytes of a NAL unit's length in a sample: 4, `lengthSizeMinusOne`
/// 3 (ISO/IEC 14496-15 §5.3.3.1.2, §8.3.3.1.2), the size of the start
/// code it replaces.
pub(crate) const NAL_LENGTH_SIZE: u8 = 4;

/// The H.264 profiles whose `AVCDecoderConfigurationRecord` carries the
/// chroma format and bit depths (ISO/IEC 14496-15 §5.3.3.1.2).
const AVCC_EXT_PROFILES: [u8; 4] = [100, 110, 122, 144];

/// `objectTypeIndication` of MPEG-4 audio, AAC among it (ISO/IEC 14496-1
/// §7.2.6.6.2, Table 5).
const OBJECT_TYPE_MPEG4_AUDIO: u8 = 0x40;

/// `streamType` of an audio stream (ISO/IEC 14496-1 §7.2.6.6.2, Table 6).
const STREAM_TYPE_AUDIO: u8 = 0x05;

/// The Opus sample entry's `samplerate` and `dOps`' `InputSampleRate`:
/// Opus decodes at 48 kHz (Opus in ISOBMFF §4.3.1; RFC 7587 §4.1 carries
/// no other rate).
pub(crate) const OPUS_RATE: u32 = 48_000;

/// The most channels `ChannelMappingFamily` 0 describes (Opus in ISOBMFF
/// §4.3.2, RFC 7845 §5.1.1.1).
const OPUS_MAX_CHANNELS: u8 = 2;

/// Whether a clip track of `codec` gets a sample entry: the four codecs,
/// with the parameter sets or the configuration their entry carries.
pub(crate) fn carries(codec: &Codec) -> bool {
    match codec {
        Codec::H264 { sps, pps, .. } => sps.is_some() && pps.is_some(),
        Codec::H265 { vps, sps, pps } => vps.is_some() && sps.is_some() && pps.is_some(),
        Codec::AacLc { config, .. } => !config.is_empty(),
        Codec::Opus { channels } => (1..=OPUS_MAX_CHANNELS).contains(channels),
        _ => false,
    }
}

/// The init segment of a clip of `video` and, when it has one, `audio`:
/// `ftyp` and `moov`.
pub(crate) fn init_segment(
    video: &ClipTrack,
    audio: Option<&ClipTrack>,
) -> Result<Bytes, ClipError> {
    let (entry, (width, height)) = video_entry(&video.codec)?;
    let mut trak = vec![track(
        VIDEO_TRACK_ID,
        video.clock_rate,
        width,
        height,
        entry,
    )?];
    let mut trex = vec![extends(VIDEO_TRACK_ID, NON_SYNC_SAMPLE)];
    if let Some(audio) = audio {
        trak.push(track(
            AUDIO_TRACK_ID,
            audio.clock_rate,
            0,
            0,
            audio_entry(&audio.codec)?,
        )?);
        trex.push(extends(AUDIO_TRACK_ID, SYNC_SAMPLE));
    }
    let moov = Moov {
        // The movie timescale stays mp4-atom's 1000 (§8.2.2): the movie
        // header carries no duration (0, the fragments have it).
        mvhd: Mvhd {
            rate: FixedPoint::new(1, 0),
            volume: FixedPoint::new(1, 0),
            next_track_id: if audio.is_some() {
                AUDIO_TRACK_ID.saturating_add(1)
            } else {
                AUDIO_TRACK_ID
            },
            ..Mvhd::default()
        },
        mvex: Some(Mvex { mehd: None, trex }),
        trak,
        ..Moov::default()
    };
    // `iso6`: `tfdt` and `default-base-is-moof` need `iso5` or later
    // (ISO/IEC 14496-12 §8.8.12, §8.8.7, brands in Annex E).
    let ftyp = Ftyp {
        major_brand: FourCC::new(b"iso6"),
        minor_version: 0,
        compatible_brands: vec![FourCC::new(b"iso6"), FourCC::new(b"mp41")],
    };
    let mut out = Vec::new();
    ftyp.encode(&mut out).map_err(encode_failed)?;
    moov.encode(&mut out).map_err(encode_failed)?;
    Ok(Bytes::from(out))
}

/// The track extends box of a track whose samples have `flags` unless a
/// fragment says otherwise (ISO/IEC 14496-12 §8.8.3).
const fn extends(track_id: u32, flags: u32) -> Trex {
    Trex {
        track_id,
        default_sample_description_index: 1,
        default_sample_duration: 0,
        default_sample_size: 0,
        default_sample_flags: flags,
    }
}

/// A track of `width` × `height` (0 for audio) on a `clock_rate`
/// timescale, its one sample entry `entry`, its sample tables empty.
fn track(
    track_id: u32,
    clock_rate: u32,
    width: u16,
    height: u16,
    entry: SampleEntry,
) -> Result<Trak, ClipError> {
    if clock_rate == 0 {
        // §8.4.2: `timescale` counts units per second; 0 is none.
        return Err(ClipError::Failed(format!(
            "track {track_id} has a clock rate of 0"
        )));
    }
    let video = track_id == VIDEO_TRACK_ID;
    let (handler, name) = if video {
        (FourCC::new(b"vide"), "VideoHandler")
    } else {
        (FourCC::new(b"soun"), "SoundHandler")
    };
    Ok(Trak {
        tkhd: Tkhd {
            track_id,
            enabled: true,
            in_movie: true,
            volume: FixedPoint::new(u8::from(!video), 0),
            width: FixedPoint::new(width, 0),
            height: FixedPoint::new(height, 0),
            ..Tkhd::default()
        },
        mdia: Mdia {
            mdhd: Mdhd {
                timescale: clock_rate,
                language: "und".into(),
                ..Mdhd::default()
            },
            hdlr: Hdlr {
                handler,
                name: name.into(),
            },
            minf: Minf {
                vmhd: video.then(Vmhd::default),
                smhd: (!video).then(Smhd::default),
                dinf: Dinf {
                    dref: Dref {
                        urls: vec![Url::default()],
                    },
                },
                stbl: Stbl {
                    stsd: Stsd {
                        codecs: vec![entry],
                    },
                    stco: Some(Stco::default()),
                    ..Stbl::default()
                },
                ..Minf::default()
            },
        },
        ..Trak::default()
    })
}

/// The visual sample entry fields of a `width` × `height` picture
/// (ISO/IEC 14496-12 §12.1.3), which are 16 bits.
fn visual(width: u32, height: u32) -> Result<(Visual, (u16, u16)), ClipError> {
    let (Ok(w), Ok(h)) = (u16::try_from(width), u16::try_from(height)) else {
        return Err(ClipError::Failed(format!(
            "a picture of {width}x{height} does not fit a sample entry"
        )));
    };
    let visual = Visual {
        data_reference_index: 1,
        width: w,
        height: h,
        ..Visual::default()
    };
    Ok((visual, (w, h)))
}

/// The sample entry of the video track and its picture size.
fn video_entry(codec: &Codec) -> Result<(SampleEntry, (u16, u16)), ClipError> {
    match codec {
        Codec::H264 {
            sps: Some(sps),
            pps: Some(pps),
            ..
        } => avc1(sps, pps),
        Codec::H265 {
            vps: Some(vps),
            sps: Some(sps),
            pps: Some(pps),
        } => hvc1(vps, sps, pps),
        other => Err(ClipError::Unsupported(other.family())),
    }
}

/// `avc1` with the `avcC` of `sps` and `pps` (ISO/IEC 14496-15
/// §5.3.3.1, §5.4.2.1): profile, compatibility and level are the SPS's
/// three bytes after its header, the chroma format and bit depths follow
/// for the High profiles.
fn avc1(sps: &[u8], pps: &[u8]) -> Result<(SampleEntry, (u16, u16)), ClipError> {
    let info = h264::parse_sps(sps).map_err(|err| ClipError::Failed(format!("h264 sps: {err}")))?;
    let [profile, compatibility, level] = info.profile_level_id;
    let ext = AVCC_EXT_PROFILES.contains(&profile).then(|| AvccExt {
        chroma_format: info.chroma_format_idc,
        bit_depth_luma: info.bit_depth_luma,
        bit_depth_chroma: info.bit_depth_chroma,
        sequence_parameter_sets_ext: Vec::new(),
    });
    let (visual, size) = visual(info.width, info.height)?;
    let entry = Avc1 {
        visual,
        avcc: Avcc {
            configuration_version: 1,
            avc_profile_indication: profile,
            profile_compatibility: compatibility,
            avc_level_indication: level,
            length_size: NAL_LENGTH_SIZE,
            sequence_parameter_sets: vec![sps.to_vec()],
            picture_parameter_sets: vec![pps.to_vec()],
            ext,
        },
        ..Avc1::default()
    };
    Ok((entry.into(), size))
}

/// `hvc1` with the `hvcC` of `vps`, `sps` and `pps` (ISO/IEC 14496-15
/// §8.3.3.1, §8.4.1.1): the general profile, tier and level, the chroma
/// format, bit depths and temporal layers of the SPS, and one array per
/// parameter set type.
///
/// `array_completeness` is 1 for the parameter set arrays, as §8.4.1.1.2
/// requires of `hvc1`: the samples leave those sets out. `hvc1` rather
/// than `hev1` (whose sets may stay in-band) because Apple's HLS
/// authoring specification requires `hvc1` for HEVC.
fn hvc1(vps: &[u8], sps: &[u8], pps: &[u8]) -> Result<(SampleEntry, (u16, u16)), ClipError> {
    let info = h265::parse_sps(sps).map_err(|err| ClipError::Failed(format!("h265 sps: {err}")))?;
    let array = |nal_unit_type: u8, unit: &[u8]| HvcCArray {
        completeness: true,
        nal_unit_type,
        nalus: vec![unit.to_vec()],
    };
    let (visual, size) = visual(info.width, info.height)?;
    let entry = Hvc1 {
        visual,
        hvcc: Hvcc {
            configuration_version: 1,
            general_profile_space: info.profile_space,
            general_tier_flag: info.high_tier,
            general_profile_idc: info.profile_idc,
            general_profile_compatibility_flags: info.compatibility.to_be_bytes(),
            general_constraint_indicator_flags: info.constraint_flags,
            general_level_idc: info.level_idc,
            chroma_format_idc: info.chroma_format_idc,
            bit_depth_luma_minus8: info.bit_depth_luma.saturating_sub(8),
            bit_depth_chroma_minus8: info.bit_depth_chroma.saturating_sub(8),
            num_temporal_layers: info.sub_layers,
            temporal_id_nested: info.temporal_id_nesting,
            length_size_minus_one: NAL_LENGTH_SIZE.saturating_sub(1),
            arrays: vec![
                array(VPS_NUT, vps),
                array(SPS_NUT, sps),
                array(PPS_NUT, pps),
            ],
            ..Hvcc::default()
        },
        ..Hvc1::default()
    };
    Ok((entry.into(), size))
}

/// The audio sample entry fields (ISO/IEC 14496-12 §12.2.3) of
/// `channels` at `sample_rate`, 16 bits. The rate is a 16.16 number: a
/// rate above 65535 Hz is written as 0, as the timescale has it.
fn audio(channels: u8, sample_rate: u32) -> Audio {
    Audio {
        data_reference_index: 1,
        channel_count: u16::from(channels),
        sample_size: 16,
        sample_rate: FixedPoint::new(u16::try_from(sample_rate).unwrap_or(0), 0),
    }
}

/// The sample entry of the audio track.
fn audio_entry(codec: &Codec) -> Result<SampleEntry, ClipError> {
    match codec {
        Codec::AacLc {
            sample_rate,
            channels,
            config,
        } if !config.is_empty() => Ok(Mp4a {
            audio: audio(*channels, *sample_rate),
            esds: Esds {
                es_desc: EsDescriptor {
                    // The track identifies the stream in a file; the ES_ID
                    // stays 0.
                    es_id: 0,
                    dec_config: DecoderConfig {
                        object_type_indication: OBJECT_TYPE_MPEG4_AUDIO,
                        stream_type: STREAM_TYPE_AUDIO,
                        dec_specific: Some(DecoderSpecific {
                            raw: config.to_vec(),
                            ..DecoderSpecific::default()
                        }),
                        ..DecoderConfig::default()
                    },
                    sl_config: SLConfig {},
                },
            },
            btrt: None,
            taic: None,
        }
        .into()),
        // Opus in ISOBMFF §4.3.2: `PreSkip` 0, since RTP does not carry
        // the encoder's delay (RFC 7587 §4.1); `ChannelMappingFamily` 0,
        // mono or stereo.
        Codec::Opus { channels } if (1..=OPUS_MAX_CHANNELS).contains(channels) => Ok(Opus {
            audio: audio(*channels, OPUS_RATE),
            dops: Dops {
                output_channel_count: *channels,
                pre_skip: 0,
                input_sample_rate: OPUS_RATE,
                output_gain: 0,
            },
            btrt: None,
        }
        .into()),
        other => Err(ClipError::Unsupported(other.family())),
    }
}

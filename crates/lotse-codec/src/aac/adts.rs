//! AAC from framed sources: an ADTS byte stream, as MPEG-TS carries AAC
//! (stream type 0x0F, ISO/IEC 13818-1 Table 2-34), split into the raw AAC
//! frames the AAC-LC → Opus transcoder decodes.
//!
//! Implements ISO/IEC 13818-7 §6.2 (`adts_frame`): §6.2.1 (the fixed and
//! variable header, the 16-bit `crc_check` when `protection_absent` is 0)
//! and §6.2.2 (`frame_length` counts the header). adts-reader reads each
//! header; this module adds the buffering across pushes, the resync and
//! the `AudioSpecificConfig` (ISO/IEC 14496-3 §1.6.2.1) of the header,
//! which ISO/IEC 14496-3 §1.A.2.2.1 maps field by field: the audio object
//! type is `profile_ObjectType` plus one, then the sampling frequency
//! index and the channel configuration, then a `GASpecificConfig`
//! (§4.4.1) of 1024-sample frames with no core coder and no extension.
//! That config goes through [`parse_config`], so what is decodable is
//! decided in one place. HE-AAC in ADTS signals SBR implicitly only
//! (§1.6.5.1): its header reads as AAC-LC at the core rate, which the
//! decoder plays.
//!
//! The bytes may come in any pieces: a frame split across pushes is held
//! until its last byte arrives (at most one frame, 8191 bytes, plus one).
//! Bytes that do not begin a header are skipped and counted until a
//! syncword with layer `00` (§6.2.1) and a readable header follow; a header
//! found that way is believed only once the next one's syncword follows
//! it, as payload bytes can look like a syncword. A frame with more than
//! one `raw_data_block` (§6.2, `number_of_raw_data_blocks_in_frame`)
//! is dropped and counted: without CRC its blocks are delimited only by
//! their own syntax, and cameras and encoders write one block per frame.
//! The CRC is not checked: a damaged frame reaches the decoder, which
//! drops what it cannot decode.
//!
//! Each frame carries its sequence, in 1024-sample frames from the
//! stream's first, dropped frames included, so the caller times it from
//! a PES PTS: [`AdtsSplitter::push`] returns the sequence of the first
//! frame that begins in the bytes pushed, the access unit a PES packet's
//! PTS refers to (ISO/IEC 13818-1 §2.4.3.7).

use adts_reader::{AdtsHeader, AdtsHeaderError};
use bytes::Bytes;

use super::config::{AacConfig, ConfigError, parse_config};

/// The first byte of the syncword `0xFFF` (ISO/IEC 13818-7 §6.2.1).
const SYNC_BYTE: u8 = 0xff;

/// The bits of the second header byte that hold the syncword's last four
/// bits and `layer` (ISO/IEC 13818-7 §6.2.1).
const SYNC_MASK: u8 = 0xf6;

/// Those bits of an ADTS header: syncword ones, `layer` `00`. MPEG-1/2
/// audio layers I to III share the syncword with a non-zero layer.
const SYNC_BITS: u8 = 0xf0;

/// The longest `frame_length`, a 13-bit field (ISO/IEC 13818-7 §6.2.2).
pub const MAX_ADTS_FRAME: usize = 8191;

/// The `AudioSpecificConfig` an ADTS header stands for, and whether the
/// decoder takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdtsConfig {
    /// The `AudioSpecificConfig` (ISO/IEC 14496-3 §1.6.2.1) built from the
    /// header: object type, sampling frequency index, channel
    /// configuration and a `GASpecificConfig` of zeros.
    pub audio_specific_config: [u8; 2],
    /// [`parse_config`]'s verdict on it.
    pub parsed: Result<AacConfig, ConfigError>,
}

impl AdtsConfig {
    /// The config of a header's audio object type (`profile_ObjectType`
    /// plus one, ISO/IEC 14496-3 §1.A.2.2.1, which adts-reader adds),
    /// sampling frequency index and channel configuration.
    fn new(object_type: u8, frequency_index: u8, channels: u8) -> Self {
        // audioObjectType (5 bits), samplingFrequencyIndex (4),
        // channelConfiguration (4), frameLengthFlag, dependsOnCoreCoder,
        // extensionFlag (1 each, all 0): §1.6.2.1, §4.4.1.
        let word = u16::from(object_type) << 11
            | u16::from(frequency_index) << 7
            | u16::from(channels) << 3;
        let audio_specific_config = word.to_be_bytes();
        Self {
            audio_specific_config,
            parsed: parse_config(&audio_specific_config),
        }
    }
}

/// One raw AAC frame out of its ADTS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdtsFrame {
    /// Its place in the stream, in 1024-sample frames from the first
    /// header, dropped frames included: frame `n` plays 1024 × `n`
    /// samples after frame 0.
    pub sequence: u64,
    /// The `raw_data_block`, without header and CRC.
    pub payload: Bytes,
    /// The config its header announced.
    pub config: AdtsConfig,
}

/// What the splitter counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdtsStats {
    /// Frames emitted.
    pub frames: u64,
    /// Frames dropped as larger than the limit.
    pub dropped_oversize: u64,
    /// Frames dropped for carrying more than one `raw_data_block`.
    pub dropped_blocks: u64,
    /// Frames dropped as empty: a header and no `raw_data_block`.
    pub dropped_empty: u64,
    /// Bytes skipped looking for a header.
    pub skipped_bytes: u64,
    /// Headers announcing another config than the frame before.
    pub config_changes: u64,
}

/// What to do at a position of the buffer.
#[derive(Debug)]
enum Step<'a> {
    /// The bytes there may begin a frame that is not complete yet.
    Wait,
    /// No frame begins there.
    Skip,
    /// A frame begins there.
    Frame(AdtsHeader<'a>),
}

/// The ADTS splitter of one AAC track.
#[derive(Debug)]
pub struct AdtsSplitter {
    /// The largest raw frame kept (`limits.max_frame_bytes`).
    max_frame_bytes: usize,
    /// Bytes of a frame, or of a header, begun in an earlier push.
    pending: Vec<u8>,
    /// Whether the last bytes consumed were a frame, so the next header
    /// is believed without the syncword after it. True at the start.
    synced: bool,
    /// The sequence of the next frame.
    sequence: u64,
    /// The config of the last header.
    config: Option<AdtsConfig>,
    /// Counters.
    stats: AdtsStats,
}

/// Whether `bytes` begin with the syncword and layer `00`; `None` while
/// they are too short to tell.
fn starts_with_sync(bytes: &[u8]) -> Option<bool> {
    match bytes {
        [] | [SYNC_BYTE] => None,
        [first, second, ..] => Some(*first == SYNC_BYTE && second & SYNC_MASK == SYNC_BITS),
        [_] => Some(false),
    }
}

/// What the bytes at a position are; a header found out of sync must be
/// followed by the next syncword.
fn step(rest: &[u8], synced: bool) -> Step<'_> {
    match starts_with_sync(rest) {
        None => return Step::Wait,
        Some(false) => return Step::Skip,
        Some(true) => {}
    }
    let header = match AdtsHeader::from_bytes(rest) {
        Ok(header) => header,
        Err(AdtsHeaderError::NotEnoughData { .. }) => return Step::Wait,
        Err(_) => return Step::Skip,
    };
    let Some(after) = rest.get(usize::from(header.frame_length())..) else {
        return Step::Wait;
    };
    if synced {
        return Step::Frame(header);
    }
    match starts_with_sync(after) {
        None => Step::Wait,
        Some(false) => Step::Skip,
        Some(true) => Step::Frame(header),
    }
}

impl AdtsSplitter {
    /// A splitter keeping raw frames up to `max_frame_bytes`.
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self {
            max_frame_bytes,
            pending: Vec::new(),
            synced: true,
            sequence: 0,
            config: None,
            stats: AdtsStats {
                frames: 0,
                dropped_oversize: 0,
                dropped_blocks: 0,
                dropped_empty: 0,
                skipped_bytes: 0,
                config_changes: 0,
            },
        }
    }

    /// The counters.
    pub const fn stats(&self) -> AdtsStats {
        self.stats
    }

    /// The config of the last header, if one was read.
    pub const fn config(&self) -> Option<AdtsConfig> {
        self.config
    }

    /// Bytes held for a frame not complete yet: at most
    /// [`MAX_ADTS_FRAME`] plus one.
    pub const fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// Takes the next bytes of the stream and appends the frames they
    /// complete to `out`. Returns the sequence of the first frame that
    /// begins in `data` and ends by its end, if any: the frame a PES
    /// PTS on `data` times.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<AdtsFrame>) -> Option<u64> {
        let carried = self.pending.len();
        let mut buffer = std::mem::take(&mut self.pending);
        buffer.extend_from_slice(data);
        let mut position = 0_usize;
        let mut first = None;
        while let Some(rest) = buffer.get(position..) {
            match step(rest, self.synced) {
                Step::Wait => break,
                Step::Skip => {
                    self.synced = false;
                    self.stats.skipped_bytes = self.stats.skipped_bytes.saturating_add(1);
                    position = position.saturating_add(1);
                }
                Step::Frame(header) => {
                    if first.is_none() && position >= carried {
                        first = Some(self.sequence);
                    }
                    self.synced = true;
                    position = position.saturating_add(usize::from(header.frame_length()));
                    self.accept(&header, out);
                }
            }
        }
        buffer.drain(..position.min(buffer.len()));
        self.pending = buffer;
        first
    }

    /// Takes one complete frame: its config, its sequence, and the frame
    /// itself unless it is dropped.
    fn accept(&mut self, header: &AdtsHeader<'_>, out: &mut Vec<AdtsFrame>) {
        let config = AdtsConfig::new(
            u8::from(header.audio_object_type()),
            u8::from(header.sampling_frequency()),
            u8::from(header.channel_configuration()),
        );
        if self.config.is_some_and(|last| last != config) {
            self.stats.config_changes = self.stats.config_changes.saturating_add(1);
        }
        self.config = Some(config);
        let blocks = header.number_of_raw_data_blocks_in_frame();
        let sequence = self.sequence;
        self.sequence = sequence.wrapping_add(u64::from(blocks));
        if blocks > 1 {
            self.stats.dropped_blocks = self.stats.dropped_blocks.saturating_add(1);
            return;
        }
        // The frame is complete, so its payload is there.
        let payload = header.payload().unwrap_or_default();
        if payload.is_empty() {
            self.stats.dropped_empty = self.stats.dropped_empty.saturating_add(1);
            return;
        }
        if payload.len() > self.max_frame_bytes {
            self.stats.dropped_oversize = self.stats.dropped_oversize.saturating_add(1);
            return;
        }
        self.stats.frames = self.stats.frames.saturating_add(1);
        out.push(AdtsFrame {
            sequence,
            payload: Bytes::copy_from_slice(payload),
            config,
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::super::test_data::{
        CONFIG_16K_MONO, CONFIG_48K_MONO, SINE_16K_MONO, SINE_48K_MONO, frames,
    };
    use super::*;

    const LC: u8 = 1;
    const F16K: u8 = 8;
    const MONO: u8 = 1;
    const LIMIT: usize = 8192;

    /// An ADTS frame (ISO/IEC 13818-7 §6.2.1): MPEG-4, `profile`,
    /// `frequency` index, `channels`, a CRC of `0xabcd` if `crc`, and
    /// `blocks` raw data blocks around `payload`.
    fn adts(
        profile: u8,
        frequency: u8,
        channels: u8,
        crc: bool,
        blocks: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = if crc { 9 } else { 7 } + payload.len();
        let mut frame = vec![
            0xff,
            0xf0 | u8::from(!crc),
            profile << 6 | frequency << 2 | channels >> 2,
            (channels & 3) << 6 | u8::try_from((length >> 11) & 3).unwrap(),
            u8::try_from((length >> 3) & 0xff).unwrap(),
            u8::try_from(length & 7).unwrap() << 5 | 0x1f,
            0xfc | (blocks - 1),
        ];
        if crc {
            frame.extend_from_slice(&[0xab, 0xcd]);
        }
        frame.extend_from_slice(payload);
        frame
    }

    /// An AAC-LC 16 kHz mono frame without CRC around `payload`.
    fn lc(payload: &[u8]) -> Vec<u8> {
        adts(LC, F16K, MONO, false, 1, payload)
    }

    fn push(splitter: &mut AdtsSplitter, data: &[u8]) -> (Option<u64>, Vec<AdtsFrame>) {
        let mut out = Vec::new();
        let first = splitter.push(data, &mut out);
        (first, out)
    }

    fn payloads(out: &[AdtsFrame]) -> Vec<&[u8]> {
        out.iter().map(|f| f.payload.as_ref()).collect()
    }

    fn sequences(out: &[AdtsFrame]) -> Vec<u64> {
        out.iter().map(|f| f.sequence).collect()
    }

    #[test]
    fn iso13818_7_6_2_the_fixtures_split_into_their_raw_frames() {
        for (stream, config, rate) in [
            (SINE_16K_MONO, CONFIG_16K_MONO, 16_000),
            (SINE_48K_MONO, CONFIG_48K_MONO, 48_000),
        ] {
            let mut splitter = AdtsSplitter::new(LIMIT);
            let (first, out) = push(&mut splitter, stream);
            assert_eq!(first, Some(0));
            assert_eq!(payloads(&out), frames(stream));
            let count = out.len() as u64;
            assert_eq!(sequences(&out), (0..count).collect::<Vec<_>>());
            let expected = AdtsConfig {
                audio_specific_config: config,
                parsed: Ok(AacConfig {
                    sample_rate: rate,
                    channels: 1,
                }),
            };
            assert!(out.iter().all(|f| f.config == expected));
            assert_eq!(splitter.config(), Some(expected));
            assert_eq!(
                splitter.stats(),
                AdtsStats {
                    frames: count,
                    ..AdtsStats::default()
                }
            );
            assert_eq!(splitter.buffered(), 0);
        }
    }

    #[test]
    fn iso13818_7_6_2_frames_split_across_pushes_come_out_whole() {
        let whole = {
            let mut splitter = AdtsSplitter::new(LIMIT);
            push(&mut splitter, SINE_48K_MONO).1
        };
        for size in [1, 2, 7, 9, 100, 188] {
            let mut splitter = AdtsSplitter::new(LIMIT);
            let mut out = Vec::new();
            for chunk in SINE_48K_MONO.chunks(size) {
                let first = splitter.push(chunk, &mut out);
                if size == 1 {
                    // No frame begins and ends in one byte.
                    assert_eq!(first, None);
                }
                assert!(splitter.buffered() <= MAX_ADTS_FRAME + 1);
            }
            assert_eq!(out, whole, "pieces of {size}");
            assert_eq!(splitter.buffered(), 0);
        }
    }

    #[test]
    fn iso13818_1_2_4_3_7_push_names_the_first_frame_beginning_in_it() {
        let (a, b, c) = (lc(b"aaaa"), lc(b"bbbbbb"), lc(b"cc"));
        let mut splitter = AdtsSplitter::new(LIMIT);
        let mut data = a.clone();
        data.extend_from_slice(&b[..3]);
        let (first, out) = push(&mut splitter, &data);
        assert_eq!((first, payloads(&out)), (Some(0), vec![&b"aaaa"[..]]));
        assert_eq!(splitter.buffered(), 3);
        // B began in the push before; C is the first to begin here.
        let mut data = b[3..].to_vec();
        data.extend_from_slice(&c);
        let (first, out) = push(&mut splitter, &data);
        assert_eq!(first, Some(2));
        assert_eq!(payloads(&out), vec![&b"bbbbbb"[..], b"cc"]);
        assert_eq!(sequences(&out), vec![1, 2]);
        // A frame that begins but does not end names nothing yet.
        assert_eq!(push(&mut splitter, &a[..8]), (None, Vec::new()));
        assert_eq!(push(&mut splitter, &[]), (None, Vec::new()));
        let (first, out) = push(&mut splitter, &a[8..]);
        assert_eq!((first, sequences(&out)), (None, vec![3]));
    }

    #[test]
    fn iso13818_7_6_2_1_crc_protected_frames_lose_header_and_crc() {
        let mut data = adts(LC, F16K, MONO, true, 1, b"protected");
        data.extend(lc(b"plain"));
        let mut splitter = AdtsSplitter::new(LIMIT);
        let (_, out) = push(&mut splitter, &data);
        assert_eq!(payloads(&out), vec![&b"protected"[..], b"plain"]);
        assert_eq!(out[0].config.audio_specific_config, CONFIG_16K_MONO);
        // Protection is no part of the config.
        assert_eq!(splitter.stats().config_changes, 0);
        // A CRC header cut after its fixed seven bytes waits for the CRC.
        let mut splitter = AdtsSplitter::new(LIMIT);
        let frame = adts(LC, F16K, MONO, true, 1, b"x");
        assert_eq!(push(&mut splitter, &frame[..8]), (None, Vec::new()));
        assert_eq!(splitter.buffered(), 8);
        let (_, out) = push(&mut splitter, &frame[8..]);
        assert_eq!(payloads(&out), vec![&b"x"[..]]);
    }

    #[test]
    fn iso13818_7_6_2_2_a_truncated_frame_is_held_not_emitted() {
        let frame = lc(b"truncated");
        let mut splitter = AdtsSplitter::new(LIMIT);
        let cut = frame.len() - 1;
        assert_eq!(push(&mut splitter, &frame[..cut]), (None, Vec::new()));
        assert_eq!(splitter.buffered(), cut);
        assert_eq!(splitter.stats(), AdtsStats::default());
        let (_, out) = push(&mut splitter, &frame[cut..]);
        assert_eq!(payloads(&out), vec![&b"truncated"[..]]);
    }

    #[test]
    fn iso14496_3_1_a_2_2_1_the_header_names_the_object_type_and_layout() {
        let cases = [
            // profile_ObjectType 0, 2, 3: AAC Main, SSR, LTP.
            (0, F16K, MONO, Err(ConfigError::ObjectType(1))),
            (2, F16K, MONO, Err(ConfigError::ObjectType(3))),
            (3, F16K, MONO, Err(ConfigError::ObjectType(4))),
            // Channels from a program config element, 5.1.
            (LC, F16K, 0, Err(ConfigError::Channels(0))),
            (LC, F16K, 6, Err(ConfigError::Channels(6))),
            // Reserved frequency index (Table 1.18).
            (LC, 0xd, MONO, Err(ConfigError::Frequency)),
            (
                LC,
                3,
                2,
                Ok(AacConfig {
                    sample_rate: 48_000,
                    channels: 2,
                }),
            ),
        ];
        for (profile, frequency, channels, parsed) in cases {
            let mut splitter = AdtsSplitter::new(LIMIT);
            let (_, out) = push(
                &mut splitter,
                &adts(profile, frequency, channels, false, 1, b"x"),
            );
            // The frame goes out either way; its config says whether it decodes.
            assert_eq!(out.len(), 1);
            assert_eq!(
                out[0].config.parsed, parsed,
                "{profile} {frequency} {channels}"
            );
            assert_eq!(parse_config(&out[0].config.audio_specific_config), parsed);
        }
        // AAC-LC, 16 kHz, mono is the fixtures' config.
        assert_eq!(
            AdtsConfig::new(2, F16K, MONO).audio_specific_config,
            CONFIG_16K_MONO
        );
    }

    #[test]
    fn iso13818_7_6_2_1_a_new_config_is_counted_and_carried() {
        let mut data = SINE_16K_MONO.to_vec();
        data.extend_from_slice(SINE_48K_MONO);
        let mut splitter = AdtsSplitter::new(LIMIT);
        let (_, out) = push(&mut splitter, &data);
        assert_eq!(splitter.stats().config_changes, 1);
        let first = frames(SINE_16K_MONO).len();
        assert!(
            out[..first]
                .iter()
                .all(|f| f.config.audio_specific_config == CONFIG_16K_MONO)
        );
        assert!(
            out[first..]
                .iter()
                .all(|f| f.config.audio_specific_config == CONFIG_48K_MONO)
        );
        assert_eq!(
            splitter.config().map(|c| c.audio_specific_config),
            Some(CONFIG_48K_MONO)
        );
    }

    #[test]
    fn frames_over_the_limit_are_dropped_and_counted_in_sequence() {
        let mut data = lc(b"four");
        data.extend(lc(b"fives"));
        data.extend(lc(b"sixsix"));
        let mut splitter = AdtsSplitter::new(5);
        let (first, out) = push(&mut splitter, &data);
        assert_eq!(first, Some(0));
        // A frame of exactly the limit is kept.
        assert_eq!(payloads(&out), vec![&b"four"[..], b"fives"]);
        assert_eq!(splitter.stats().dropped_oversize, 1);
        assert_eq!(splitter.stats().frames, 2);
        let (_, out) = push(&mut splitter, &lc(b"next"));
        assert_eq!(sequences(&out), vec![3]);
    }

    #[test]
    fn iso13818_7_6_2_frames_of_several_raw_data_blocks_are_dropped_and_counted() {
        let mut data = adts(LC, F16K, MONO, false, 2, b"two blocks");
        data.extend(adts(LC, F16K, MONO, false, 4, b"four blocks"));
        data.extend(lc(b"one"));
        let mut splitter = AdtsSplitter::new(LIMIT);
        let (first, out) = push(&mut splitter, &data);
        // The dropped frames still take their 1024 samples each.
        assert_eq!(first, Some(0));
        assert_eq!(payloads(&out), vec![&b"one"[..]]);
        assert_eq!(sequences(&out), vec![6]);
        assert_eq!(splitter.stats().dropped_blocks, 2);
        assert_eq!(
            splitter.config().map(|c| c.audio_specific_config),
            Some(CONFIG_16K_MONO)
        );
    }

    #[test]
    fn iso13818_7_6_2_a_frame_without_a_raw_data_block_is_dropped() {
        let mut data = lc(b"");
        data.extend(lc(b"x"));
        let mut splitter = AdtsSplitter::new(LIMIT);
        let (_, out) = push(&mut splitter, &data);
        assert_eq!(sequences(&out), vec![1]);
        assert_eq!(splitter.stats().dropped_empty, 1);
    }

    #[test]
    fn iso13818_7_6_2_1_garbage_is_skipped_up_to_a_confirmed_header() {
        // Not a syncword, an MPEG-1 layer III header (layer 01), a lone
        // 0xFF: none begins a frame.
        let mut data = vec![0x00, 0x47, 0xff, 0xfb, 0x90, 0xff, 0x12];
        let skipped = data.len() as u64;
        let (a, b) = (lc(b"aaaa"), lc(b"bbbb"));
        data.extend_from_slice(&a);
        let mut splitter = AdtsSplitter::new(LIMIT);
        // Out of sync, A waits for the syncword after it.
        assert_eq!(push(&mut splitter, &data), (None, Vec::new()));
        assert_eq!(splitter.stats().skipped_bytes, skipped);
        assert_eq!(splitter.buffered(), a.len());
        assert_eq!(push(&mut splitter, &b[..1]), (None, Vec::new()));
        let (first, out) = push(&mut splitter, &b[1..]);
        assert_eq!(payloads(&out), vec![&b"aaaa"[..], b"bbbb"]);
        // A began in an earlier push, B here.
        assert_eq!(first, None);
        assert_eq!(sequences(&out), vec![0, 1]);
        assert_eq!(splitter.stats().skipped_bytes, skipped);
    }

    #[test]
    fn iso13818_7_6_2_1_a_header_not_followed_by_a_syncword_is_payload() {
        // A false header out of sync whose length lands on no syncword.
        let mut data = vec![0x00];
        data.extend(lc(b"fake"));
        data.push(0x00);
        let real = lc(b"real");
        data.extend_from_slice(&real);
        data.extend(lc(b"next"));
        let mut splitter = AdtsSplitter::new(LIMIT);
        let (_, out) = push(&mut splitter, &data);
        assert_eq!(payloads(&out), vec![&b"real"[..], b"next"]);
        assert_eq!(splitter.stats().skipped_bytes, 1 + 7 + 4 + 1);
        // In sync, the next header is believed without one after it.
        let (_, out) = push(&mut splitter, &lc(b"last"));
        assert_eq!(payloads(&out), vec![&b"last"[..]]);
        assert_eq!(splitter.buffered(), 0);
    }

    #[test]
    fn iso13818_7_6_2_unreadable_headers_are_skipped() {
        let good = lc(b"good");
        // frame_length 6, shorter than its header.
        let mut short = lc(b"");
        short[4] = 0;
        short[5] = (6 << 5) | 0x1f;
        // Sampling frequency index 0xf, the escape ADTS cannot use.
        let mut escaped = lc(b"esc");
        escaped[2] |= 0xf << 2;
        for bad in [short, escaped] {
            let mut data = bad.clone();
            data.extend_from_slice(&good);
            data.extend_from_slice(&good);
            let mut splitter = AdtsSplitter::new(LIMIT);
            let (_, out) = push(&mut splitter, &data);
            assert_eq!(payloads(&out), vec![&b"good"[..], b"good"], "{bad:02x?}");
            assert_eq!(splitter.stats().skipped_bytes, bad.len() as u64);
        }
    }

    #[test]
    fn a_lone_sync_byte_waits_and_any_other_byte_is_skipped() {
        let mut splitter = AdtsSplitter::new(LIMIT);
        assert_eq!(starts_with_sync(&[]), None);
        assert_eq!(starts_with_sync(&[0xff]), None);
        assert_eq!(starts_with_sync(&[0xfe]), Some(false));
        assert_eq!(starts_with_sync(&[0xff, 0xf1]), Some(true));
        assert_eq!(starts_with_sync(&[0xff, 0xf9]), Some(true));
        assert_eq!(starts_with_sync(&[0xfe, 0xf1]), Some(false));
        assert_eq!(starts_with_sync(&[0xff, 0xe1]), Some(false));
        push(&mut splitter, &[0x12]);
        assert_eq!(
            (splitter.stats().skipped_bytes, splitter.buffered()),
            (1, 0)
        );
        push(&mut splitter, &[0xff]);
        assert_eq!(
            (splitter.stats().skipped_bytes, splitter.buffered()),
            (1, 1)
        );
        let frame = lc(b"x");
        let (_, out) = push(&mut splitter, &frame[1..]);
        assert_eq!(payloads(&out), Vec::<&[u8]>::new());
        assert_eq!(splitter.buffered(), frame.len());
        assert!(format!("{splitter:?}").contains("AdtsSplitter"));
    }
}

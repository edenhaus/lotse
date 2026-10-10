//! Choosing what to play from parsed HLS playlists: the variant, its audio
//! rendition, the segment to start at, and which segments each reload adds.
//!
//! Pure: no I/O and no clock. The caller fetches, logs the choices and the
//! [`Event`]s with their reasons, and schedules reloads from the intervals
//! returned here.
//!
//! Implements RFC 8216 §4.3.4.2 (variant `BANDWIDTH`, `CODECS` and `AUDIO`),
//! §4.3.4.1.1 (the rendition a group defaults to), §4.3.5.2
//! (`EXT-X-START`), §6.3.2 (media sequence numbers), §4.3.3.3
//! (discontinuity sequence numbers), §6.3.3 (where a live client starts,
//! with a [`SPEC-DEVIATION`](start_index)) and §6.3.4 (reload intervals),
//! with the codec names of RFC 6381 §3.3, and skips `EXT-X-GAP` segments
//! (draft-pantos-hls-rfc8216bis §4.4.4.7).

use std::time::Duration;

use super::playlist::{AudioRendition, MediaPlaylist, MultivariantPlaylist, Segment, Variant};

/// The RFC 6381 §3.3 sample entry types of the video a variant may carry:
/// H.264 (`avc1`, `avc3`, ISO/IEC 14496-15 §5.4) and H.265 (`hvc1`,
/// `hev1`, ISO/IEC 14496-15 §8.4). A codec matches with or without its
/// dot-separated profile parameters.
const VIDEO_SAMPLE_ENTRIES: [&str; 4] = ["avc1", "avc3", "hvc1", "hev1"];

/// The one audio codec a variant may carry: AAC-LC, `mp4a` with object
/// type indication `40` (ISO/IEC 14496-3) and audio object type 2
/// (RFC 6381 §3.3). HE-AAC (`mp4a.40.5`, `mp4a.40.29`) is not played.
const AAC_LC: &str = "mp4a.40.2";

/// What [`choose_variant`] chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// The variant to play.
    pub variant: Variant,
    /// The audio rendition of its `AUDIO` group, when it names one that the
    /// playlist lists. Its `uri` is `None` when the audio is in the
    /// variant's own segments.
    pub audio: Option<AudioRendition>,
    /// Whether no playable variant fits the bandwidth cap, so the lowest
    /// one was taken instead.
    pub over_cap: bool,
}

impl Choice {
    /// The media playlist of a separate audio rendition, `None` when the
    /// variant has no audio group or its audio is muxed into its segments
    /// (RFC 8216 §4.3.4.1, `URI`).
    #[must_use]
    pub fn audio_playlist(&self) -> Option<&url::Url> {
        self.audio.as_ref().and_then(|audio| audio.uri.as_ref())
    }
}

/// Why no variant of a multivariant playlist can be played.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    /// No variant lists only codecs the daemon plays. No codec text is
    /// carried: it is playlist text a camera controls.
    #[error(
        "none of the {count} variants of the playlist has only codecs that can be played \
         (H.264, H.265, AAC-LC) (RFC 8216 §4.3.4.2, CODECS)"
    )]
    NoPlayableVariant {
        /// How many variants the playlist lists.
        count: usize,
    },
}

/// Chooses the variant to play: of those whose `CODECS` are all playable,
/// or that have no `CODECS` attribute (RFC 8216 §4.3.4.2 makes it a SHOULD,
/// so a client cannot rely on it), the one with the highest `BANDWIDTH` at
/// or below `max_bandwidth` (bits per second; `None` is uncapped). When
/// none fits under the cap, the playable one with the lowest `BANDWIDTH`
/// is taken, flagged [`Choice::over_cap`]: a stream above the cap beats no
/// stream. Ties go to the first in playlist order.
///
/// The audio rendition is the one of the variant's `AUDIO` group with
/// `DEFAULT=YES`, else the group's first (RFC 8216 §4.3.4.1.1).
///
/// # Errors
///
/// [`SelectError::NoPlayableVariant`] when no variant is playable.
pub fn choose_variant(
    playlist: &MultivariantPlaylist,
    max_bandwidth: Option<u64>,
) -> Result<Choice, SelectError> {
    let mut within: Option<&Variant> = None;
    let mut lowest: Option<&Variant> = None;
    for variant in playlist.variants.iter().filter(|variant| playable(variant)) {
        let fits = max_bandwidth.is_none_or(|max| variant.bandwidth <= max);
        if fits && within.is_none_or(|best| variant.bandwidth > best.bandwidth) {
            within = Some(variant);
        }
        if lowest.is_none_or(|low| variant.bandwidth < low.bandwidth) {
            lowest = Some(variant);
        }
    }
    let (variant, over_cap) = match (within, lowest) {
        (Some(variant), _) => (variant, false),
        (None, Some(variant)) => (variant, true),
        (None, None) => {
            return Err(SelectError::NoPlayableVariant {
                count: playlist.variants.len(),
            });
        }
    };
    let audio = variant
        .audio_group
        .as_deref()
        .and_then(|group| audio_rendition(&playlist.audio, group))
        .cloned();
    Ok(Choice {
        variant: variant.clone(),
        audio,
        over_cap,
    })
}

/// Whether every codec of a variant's `CODECS` list is one the daemon
/// plays; a variant without the attribute is taken to be playable.
fn playable(variant: &Variant) -> bool {
    variant
        .codecs
        .as_deref()
        .is_none_or(|codecs| codecs.split(',').map(str::trim).all(playable_codec))
}

/// Whether one RFC 6381 codec name is H.264, H.265 or AAC-LC: a video
/// sample entry type alone or followed by `.` and its parameters (§3.3),
/// or exactly `mp4a.40.2`.
fn playable_codec(codec: &str) -> bool {
    codec == AAC_LC
        || VIDEO_SAMPLE_ENTRIES.iter().any(|entry| {
            codec
                .strip_prefix(entry)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        })
}

/// The rendition of `group` to play: the one with `DEFAULT=YES`, else the
/// first of the group (RFC 8216 §4.3.4.1.1); `None` when the playlist
/// lists no rendition of that group.
fn audio_rendition<'a>(audio: &'a [AudioRendition], group: &str) -> Option<&'a AudioRendition> {
    let in_group = |rendition: &&AudioRendition| rendition.group_id == group;
    audio
        .iter()
        .filter(in_group)
        .find(|rendition| rendition.default)
        .or_else(|| audio.iter().find(in_group))
}

/// The index of the segment to start playing at, `None` for a playlist
/// without segments.
///
/// With `EXT-X-START` (RFC 8216 §4.3.5.2), the segment that contains its
/// `TIME-OFFSET`: from the start of the playlist when positive, from its
/// end when negative, clamped to the playlist when its magnitude exceeds
/// the playlist's duration.
/// SPEC-DEVIATION: `PRECISE=YES` is ignored; playback starts at the start
/// of that segment rather than at the offset, which shows at most one
/// segment of media earlier than the server asked and needs no decoding to
/// skip it.
///
/// Without it, a playlist with `EXT-X-ENDLIST` starts at its first segment,
/// as a recording plays from its start (§6.3.3 places no limit on it), and
/// a live playlist at its second-newest segment with media: segments marked
/// `EXT-X-GAP` (draft-pantos-hls-rfc8216bis §4.4.4.7), which a low-latency
/// server lists as placeholders before it has made enough segments, are
/// not counted; the newest one when only one has media, and `None` while
/// none has.
/// SPEC-DEVIATION: §6.3.3 says a live client SHOULD NOT start at a segment
/// that starts less than three target durations from the end. The
/// second-newest segment cuts the latency to one or two target durations,
/// for a camera viewed live; the newest segment would leave nothing
/// buffered when the next one is late.
#[must_use]
pub fn start_index(playlist: &MediaPlaylist) -> Option<usize> {
    if playlist.segments.is_empty() {
        return None;
    }
    match playlist.start {
        Some(start) => Some(offset_index(&playlist.segments, start.time_offset)),
        None if playlist.end_list => Some(0),
        None => {
            let mut with_media = playlist
                .segments
                .iter()
                .enumerate()
                .rev()
                .filter(|(_, segment)| !segment.gap)
                .map(|(index, _)| index);
            let newest = with_media.next()?;
            Some(with_media.next().unwrap_or(newest))
        }
    }
}

/// The index of the segment that contains `offset` seconds into the
/// segments (negative: before their end), clamped to them (RFC 8216
/// §4.3.5.2). `segments` is not empty.
fn offset_index(segments: &[Segment], offset: f64) -> usize {
    let total = segments.iter().fold(Duration::ZERO, |total, segment| {
        total.saturating_add(segment.duration)
    });
    // A magnitude too large for a `Duration` exceeds the playlist anyway.
    let magnitude = Duration::try_from_secs_f64(offset.abs()).unwrap_or(Duration::MAX);
    let position = if offset < 0.0 {
        total.saturating_sub(magnitude)
    } else {
        magnitude
    };
    let mut end = Duration::ZERO;
    for (index, segment) in segments.iter().enumerate() {
        end = end.saturating_add(segment.duration);
        if position < end {
            return index;
        }
    }
    // At or past the end: the last segment.
    segments.len().saturating_sub(1)
}

/// One segment to fetch, in the order [`Tracker::update`] yields them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// Its media sequence number (RFC 8216 §6.3.2).
    pub sequence: u64,
    /// Its discontinuity sequence number (RFC 8216 §4.3.3.3).
    pub discontinuity_sequence: u64,
    /// Whether it starts a new timeline: its discontinuity sequence number
    /// differs from the previous segment yielded, or segments were lost or
    /// the stream restarted before it ([`Event`]), or an `EXT-X-GAP`
    /// segment, never yielded, came between the two. The first segment
    /// yielded starts the first timeline and is not flagged.
    pub discontinuity: bool,
    /// The segment.
    pub segment: Segment,
}

/// Something a reload found besides new segments, for the caller to log;
/// the next segment yielded carries [`Fetch::discontinuity`] for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The playlist no longer lists the next segment: its media sequence
    /// moved past it, so `lost` segments were never fetched (RFC 8216
    /// §6.3.2), as when fetching falls behind the live edge.
    Gap {
        /// How many segments were skipped.
        lost: u64,
    },
    /// The playlist's media sequence went backwards, or it ends before the
    /// next segment: the stream restarted, and playback restarts at its
    /// live edge ([`start_index`]).
    Restart,
}

/// What one load of a media playlist adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// The segments to fetch, in order, each once over the tracker's life;
    /// never one marked `EXT-X-GAP`, whose URI "SHOULD NOT be loaded by
    /// clients" (draft-pantos-hls-rfc8216bis §4.4.4.7).
    pub segments: Vec<Fetch>,
    /// A gap or restart found, if any.
    pub event: Option<Event>,
    /// How long after this load began to start the next one (RFC 8216
    /// §6.3.4): the target duration after a playlist that changed, half of
    /// it after one that did not. `None` once the playlist has
    /// `EXT-X-ENDLIST` and every segment is yielded: it is never reloaded.
    pub reload_after: Option<Duration>,
}

/// What tells two loads of a media playlist apart (RFC 8216 §6.3.4,
/// "changed"): segments are only added at the end and removed at the
/// start, so a playlist that changed differs in its media sequence, its
/// length, its last segment or its end.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    /// `EXT-X-MEDIA-SEQUENCE`.
    media_sequence: u64,
    /// `EXT-X-DISCONTINUITY-SEQUENCE`.
    discontinuity_sequence: u64,
    /// How many segments it lists.
    len: usize,
    /// Its last segment's URI.
    last: Option<url::Url>,
    /// `EXT-X-ENDLIST`.
    end_list: bool,
}

impl Fingerprint {
    /// The fingerprint of one load.
    fn of(playlist: &MediaPlaylist) -> Self {
        Self {
            media_sequence: playlist.media_sequence,
            discontinuity_sequence: playlist.discontinuity_sequence,
            len: playlist.segments.len(),
            last: playlist.segments.last().map(|segment| segment.uri.clone()),
            end_list: playlist.end_list,
        }
    }
}

/// Follows one media playlist across reloads: which segment comes next by
/// media sequence number (RFC 8216 §6.3.2), the discontinuity sequence of
/// each (§4.3.3.3), and when to reload (§6.3.4).
///
/// Invariant: every segment is yielded once, in increasing media sequence
/// order, until a [`Event::Restart`] starts the order over.
#[derive(Debug, Clone, Default)]
pub struct Tracker {
    /// The media sequence number of the next segment to yield; `None`
    /// until a load with segments chose the start.
    next: Option<u64>,
    /// The discontinuity sequence number of the last segment yielded.
    last_discontinuity: Option<u64>,
    /// Whether the next segment yielded starts a new timeline after a gap
    /// or restart that yielded nothing yet.
    pending_discontinuity: bool,
    /// The previous load, to tell whether the playlist changed.
    previous: Option<Fingerprint>,
}

impl Tracker {
    /// A tracker that has seen no load.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes one load of the playlist and returns the segments it adds.
    ///
    /// The first load with segments starts at [`start_index`]. Later loads
    /// continue at the next media sequence number; a playlist that moved
    /// past it reports [`Event::Gap`] and continues at its first segment,
    /// one whose media sequence went backwards or that ends before it
    /// reports [`Event::Restart`] and starts over at [`start_index`].
    /// Segments numbered `u64::MAX` or more are never yielded.
    pub fn update(&mut self, playlist: &MediaPlaylist) -> Update {
        let fingerprint = Fingerprint::of(playlist);
        let changed = self.previous.as_ref() != Some(&fingerprint);
        let restarted = self
            .previous
            .as_ref()
            .is_some_and(|previous| playlist.media_sequence < previous.media_sequence);
        self.previous = Some(fingerprint);

        let numbered = numbered(playlist);
        let first = playlist.media_sequence;
        let end = first.saturating_add(u64::try_from(numbered.len()).unwrap_or(u64::MAX));
        let mut event = None;
        let next = match self.next {
            Some(next) if restarted || next > end => {
                event = Some(Event::Restart);
                start_sequence(playlist)
            }
            Some(next) if next < first => {
                event = Some(Event::Gap {
                    lost: first.saturating_sub(next),
                });
                Some(first)
            }
            Some(next) => Some(next),
            None => start_sequence(playlist),
        };
        if event.is_some() {
            self.pending_discontinuity = true;
        }
        self.next = next;

        let mut segments = Vec::new();
        if let Some(next) = next {
            let mut after = next;
            for (sequence, discontinuity_sequence, segment) in numbered {
                if sequence < next {
                    continue;
                }
                after = sequence.saturating_add(1);
                if segment.gap {
                    // Its media is missing, so the segment after it starts
                    // a new timeline, unless none was yielded before it.
                    self.pending_discontinuity |= self.last_discontinuity.is_some();
                    continue;
                }
                let discontinuity = self.pending_discontinuity
                    || self
                        .last_discontinuity
                        .is_some_and(|last| last != discontinuity_sequence);
                self.pending_discontinuity = false;
                self.last_discontinuity = Some(discontinuity_sequence);
                segments.push(Fetch {
                    sequence,
                    discontinuity_sequence,
                    discontinuity,
                    segment: segment.clone(),
                });
            }
            self.next = Some(after);
        }

        let finished = playlist.end_list && self.next.is_none_or(|next| next >= end);
        let reload_after = (!finished).then(|| {
            if changed {
                playlist.target_duration
            } else {
                playlist
                    .target_duration
                    .checked_div(2)
                    .unwrap_or(playlist.target_duration)
            }
        });
        Update {
            segments,
            event,
            reload_after,
        }
    }
}

/// The media sequence number to start at in `playlist` ([`start_index`]),
/// `None` when it has no segments.
fn start_sequence(playlist: &MediaPlaylist) -> Option<u64> {
    let index = u64::try_from(start_index(playlist)?).ok()?;
    playlist.media_sequence.checked_add(index)
}

/// The segments of `playlist` with their media sequence numbers (RFC 8216
/// §6.3.2: the first's is `EXT-X-MEDIA-SEQUENCE`, each next one's is one
/// more) and discontinuity sequence numbers (§4.3.3.3: the first's is
/// `EXT-X-DISCONTINUITY-SEQUENCE`, each `EXT-X-DISCONTINUITY` adds one).
/// A tag on the first segment counts too: a server removes a tag only with
/// its segment and then raises the discontinuity sequence (§6.2.2), so
/// counting it keeps a segment's number the same across reloads. Ends
/// before the media sequence number `u64::MAX`, whose successor, the next
/// to fetch after it, has no number.
fn numbered(playlist: &MediaPlaylist) -> Vec<(u64, u64, &Segment)> {
    let mut discontinuity_sequence = playlist.discontinuity_sequence;
    (0..)
        .map_while(|index| {
            playlist
                .media_sequence
                .checked_add(index)
                .filter(|sequence| *sequence < u64::MAX)
        })
        .zip(&playlist.segments)
        .map(|(sequence, segment)| {
            if segment.discontinuity {
                discontinuity_sequence = discontinuity_sequence.saturating_add(1);
            }
            (sequence, discontinuity_sequence, segment)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use url::Url;

    use super::*;
    use crate::hls::{Playlist, Start, parse};

    fn url(path: &str) -> Url {
        Url::parse(&format!("http://camera.example{path}")).unwrap()
    }

    fn variant(path: &str, bandwidth: u64, codecs: Option<&str>) -> Variant {
        Variant {
            uri: url(path),
            bandwidth,
            codecs: codecs.map(str::to_owned),
            audio_group: None,
        }
    }

    fn rendition(group: &str, name: &str, default: bool, uri: Option<&str>) -> AudioRendition {
        AudioRendition {
            group_id: group.to_owned(),
            name: name.to_owned(),
            default,
            uri: uri.map(url),
        }
    }

    fn multivariant(variants: Vec<Variant>) -> MultivariantPlaylist {
        MultivariantPlaylist {
            variants,
            audio: Vec::new(),
        }
    }

    fn chosen(playlist: &MultivariantPlaylist, max_bandwidth: Option<u64>) -> (String, bool) {
        let choice = choose_variant(playlist, max_bandwidth).unwrap();
        (choice.variant.uri.path().to_owned(), choice.over_cap)
    }

    fn segment(name: &str, seconds: u64, discontinuity: bool) -> Segment {
        Segment {
            uri: url(&format!("/{name}")),
            duration: Duration::from_secs(seconds),
            discontinuity,
            map: None,
            gap: false,
        }
    }

    /// A live playlist with a target duration of 2 whose segments, each
    /// two seconds, are numbered from `media_sequence`; a name starting
    /// with `!` carries `EXT-X-DISCONTINUITY`, one starting with `?`
    /// `EXT-X-GAP`.
    fn live(media_sequence: u64, discontinuity_sequence: u64, names: &[&str]) -> MediaPlaylist {
        MediaPlaylist {
            target_duration: Duration::from_secs(2),
            media_sequence,
            discontinuity_sequence,
            end_list: false,
            start: None,
            segments: names
                .iter()
                .map(|name| {
                    let (gap, name) = name.strip_prefix('?').map_or((false, *name), |n| (true, n));
                    let mut segment = match name.strip_prefix('!') {
                        Some(name) => segment(name, 2, true),
                        None => segment(name, 2, false),
                    };
                    segment.gap = gap;
                    segment
                })
                .collect(),
        }
    }

    fn ended(mut playlist: MediaPlaylist) -> MediaPlaylist {
        playlist.end_list = true;
        playlist
    }

    fn with_start(mut playlist: MediaPlaylist, time_offset: f64) -> MediaPlaylist {
        playlist.start = Some(Start {
            time_offset,
            precise: false,
        });
        playlist
    }

    /// The yielded segments as (media sequence, discontinuity sequence,
    /// discontinuity flag, segment name).
    fn yielded(update: &Update) -> Vec<(u64, u64, bool, String)> {
        update
            .segments
            .iter()
            .map(|fetch| {
                (
                    fetch.sequence,
                    fetch.discontinuity_sequence,
                    fetch.discontinuity,
                    fetch.segment.uri.path().trim_start_matches('/').to_owned(),
                )
            })
            .collect()
    }

    fn fetch(
        sequence: u64,
        discontinuity_sequence: u64,
        discontinuity: bool,
        name: &str,
    ) -> (u64, u64, bool, String) {
        (
            sequence,
            discontinuity_sequence,
            discontinuity,
            name.to_owned(),
        )
    }

    const TARGET: Option<Duration> = Some(Duration::from_secs(2));
    const HALF: Option<Duration> = Some(Duration::from_secs(1));

    // Variant choice.

    #[test]
    fn rfc8216_4_3_4_2_highest_bandwidth_with_playable_codecs() {
        let playlist = multivariant(vec![
            variant("/low", 1_000_000, Some("avc1.64001f,mp4a.40.2")),
            variant("/mid", 3_000_000, Some("hvc1.1.6.L93.B0")),
            variant("/high", 5_000_000, Some("avc1.640028,ac-3")),
        ]);
        assert_eq!(chosen(&playlist, None), ("/mid".to_owned(), false));
    }

    #[test]
    fn rfc8216_4_3_4_2_highest_bandwidth_within_the_cap() {
        let playlist = multivariant(vec![
            variant("/low", 1_000_000, None),
            variant("/mid", 3_000_000, None),
            variant("/high", 5_000_000, None),
        ]);
        assert_eq!(
            chosen(&playlist, Some(2_999_999)),
            ("/low".to_owned(), false)
        );
        assert_eq!(
            chosen(&playlist, Some(3_000_000)),
            ("/mid".to_owned(), false)
        );
        assert_eq!(
            chosen(&playlist, Some(u64::MAX)),
            ("/high".to_owned(), false)
        );
    }

    #[test]
    fn rfc8216_4_3_4_2_lowest_playable_variant_when_none_fits_the_cap() {
        let playlist = multivariant(vec![
            variant("/mid", 3_000_000, None),
            variant("/unplayable", 500_000, Some("mp4a.40.5")),
            variant("/low", 1_000_000, None),
            variant("/high", 5_000_000, None),
        ]);
        assert_eq!(chosen(&playlist, Some(999_999)), ("/low".to_owned(), true));
    }

    #[test]
    fn rfc8216_4_3_4_2_equal_bandwidth_goes_to_the_first_variant() {
        let playlist = multivariant(vec![
            variant("/first", 1_000_000, None),
            variant("/second", 1_000_000, None),
        ]);
        assert_eq!(chosen(&playlist, None), ("/first".to_owned(), false));
        assert_eq!(chosen(&playlist, Some(1)), ("/first".to_owned(), true));
    }

    #[test]
    fn rfc8216_4_3_4_2_variant_without_codecs_is_accepted() {
        let playlist = multivariant(vec![
            variant("/he-aac", 1_000_000, Some("avc1.64001f,mp4a.40.5")),
            variant("/unknown", 500_000, None),
        ]);
        assert_eq!(chosen(&playlist, None), ("/unknown".to_owned(), false));
    }

    #[test]
    fn rfc6381_3_3_playable_codec_names() {
        for codec in [
            "avc1",
            "avc1.64001f",
            "avc3.42e01e",
            "hvc1.1.6.L93.B0",
            "hev1.2.4.L120.B0",
            "mp4a.40.2",
        ] {
            assert!(playable_codec(codec), "{codec}");
        }
        for codec in [
            "",
            "avc",
            "avc1x",
            "AVC1.64001F",
            "mp4a.40.5",
            "mp4a.40.29",
            "mp4a.40.2.1",
            "mp4a",
            "ac-3",
            "Opus",
            "vp09.00.10.08",
        ] {
            assert!(!playable_codec(codec), "{codec}");
        }
    }

    #[test]
    fn rfc6381_3_2_codec_list_with_spaces_is_split() {
        let playlist = multivariant(vec![variant("/a", 1, Some("avc1.4d401f, mp4a.40.2"))]);
        assert_eq!(chosen(&playlist, None), ("/a".to_owned(), false));
    }

    #[test]
    fn rfc8216_4_3_4_2_no_playable_variant_is_an_error() {
        let playlist = multivariant(vec![
            variant("/a", 1, Some("mp4a.40.5")),
            variant("/b", 2, Some("")),
        ]);
        let error = choose_variant(&playlist, None).unwrap_err();
        assert_eq!(error, SelectError::NoPlayableVariant { count: 2 });
        assert_eq!(
            error.to_string(),
            "none of the 2 variants of the playlist has only codecs that can be played \
             (H.264, H.265, AAC-LC) (RFC 8216 §4.3.4.2, CODECS)"
        );
        assert_eq!(
            choose_variant(&multivariant(Vec::new()), Some(1)),
            Err(SelectError::NoPlayableVariant { count: 0 })
        );
    }

    // Audio rendition.

    fn with_audio(audio: Vec<AudioRendition>, group: Option<&str>) -> MultivariantPlaylist {
        let mut chosen = variant("/v", 1, None);
        chosen.audio_group = group.map(str::to_owned);
        MultivariantPlaylist {
            variants: vec![chosen],
            audio,
        }
    }

    #[test]
    fn rfc8216_4_3_4_1_1_default_rendition_of_the_group() {
        let playlist = with_audio(
            vec![
                rendition("other", "x", true, Some("/x.m3u8")),
                rendition("aac", "en", false, Some("/en.m3u8")),
                rendition("aac", "de", true, Some("/de.m3u8")),
            ],
            Some("aac"),
        );
        let choice = choose_variant(&playlist, None).unwrap();
        assert_eq!(choice.audio.as_ref().unwrap().name, "de");
        assert_eq!(choice.audio_playlist(), Some(&url("/de.m3u8")));
    }

    #[test]
    fn rfc8216_4_3_4_1_1_first_rendition_without_a_default() {
        let playlist = with_audio(
            vec![
                rendition("other", "x", true, Some("/x.m3u8")),
                rendition("aac", "en", false, Some("/en.m3u8")),
                rendition("aac", "de", false, Some("/de.m3u8")),
            ],
            Some("aac"),
        );
        let choice = choose_variant(&playlist, None).unwrap();
        assert_eq!(choice.audio.unwrap().name, "en");
    }

    #[test]
    fn rfc8216_4_3_4_1_rendition_without_uri_is_muxed() {
        let playlist = with_audio(vec![rendition("aac", "main", true, None)], Some("aac"));
        let choice = choose_variant(&playlist, None).unwrap();
        assert_eq!(choice.audio.as_ref().unwrap().name, "main");
        assert_eq!(choice.audio_playlist(), None);
    }

    #[test]
    fn rfc8216_4_3_4_2_no_audio_group_or_no_rendition_of_it() {
        let audio = vec![rendition("aac", "en", true, Some("/en.m3u8"))];
        let choice = choose_variant(&with_audio(audio.clone(), None), None).unwrap();
        assert_eq!(choice.audio, None);
        assert_eq!(choice.audio_playlist(), None);
        let choice = choose_variant(&with_audio(audio, Some("missing")), None).unwrap();
        assert_eq!(choice.audio, None);
    }

    #[test]
    fn rfc8216_4_3_4_parsed_multivariant_playlist() {
        let base = url("/live/index.m3u8");
        let text = "#EXTM3U\n\
            #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",NAME=\"main\",DEFAULT=YES,URI=\"audio.m3u8\"\n\
            #EXT-X-STREAM-INF:BANDWIDTH=900000,CODECS=\"avc1.64001f,mp4a.40.2\",AUDIO=\"a\"\n\
            low.m3u8\n\
            #EXT-X-STREAM-INF:BANDWIDTH=4000000,CODECS=\"avc1.640028,mp4a.40.2\",AUDIO=\"a\"\n\
            high.m3u8\n";
        let mut low = variant("/live/low.m3u8", 900_000, Some("avc1.64001f,mp4a.40.2"));
        low.audio_group = Some("a".to_owned());
        let mut high = variant("/live/high.m3u8", 4_000_000, Some("avc1.640028,mp4a.40.2"));
        high.audio_group = Some("a".to_owned());
        let playlist = MultivariantPlaylist {
            variants: vec![low.clone(), high],
            audio: vec![rendition("a", "main", true, Some("/live/audio.m3u8"))],
        };
        assert_eq!(
            parse(text.as_bytes(), &base),
            Ok(Playlist::Multivariant(playlist.clone()))
        );
        let choice = choose_variant(&playlist, Some(1_000_000)).unwrap();
        assert_eq!(choice.variant, low);
        assert_eq!(choice.audio_playlist(), Some(&url("/live/audio.m3u8")));
    }

    // Start segment.

    #[test]
    fn rfc8216_6_3_3_live_starts_at_the_second_newest_segment() {
        // SPEC-DEVIATION (§6.3.3): not three target durations from the end.
        assert_eq!(start_index(&live(0, 0, &["a", "b", "c", "d"])), Some(2));
        assert_eq!(start_index(&live(0, 0, &["a", "b"])), Some(0));
        assert_eq!(start_index(&live(0, 0, &["a"])), Some(0));
        assert_eq!(start_index(&live(0, 0, &[])), None);
    }

    #[test]
    fn rfc8216bis_4_4_4_7_live_starts_at_the_second_newest_segment_with_media() {
        assert_eq!(start_index(&live(0, 0, &["?a", "?b", "c"])), Some(2));
        assert_eq!(
            start_index(&live(0, 0, &["?a", "b", "?c", "d", "?e"])),
            Some(1)
        );
        assert_eq!(start_index(&live(0, 0, &["a", "?b", "c", "d"])), Some(2));
        assert_eq!(start_index(&live(0, 0, &["?a", "?b"])), None);
        // EXT-X-START and EXT-X-ENDLIST choose as before; the tracker skips
        // the gaps.
        assert_eq!(start_index(&ended(live(0, 0, &["?a", "b"]))), Some(0));
    }

    #[test]
    fn rfc8216bis_4_4_4_7_gap_segments_are_never_fetched_and_end_the_timeline() {
        let mut tracker = Tracker::new();
        let update = tracker.update(&live(0, 0, &["a", "b", "?c", "d"]));
        assert_eq!(
            yielded(&update),
            vec![fetch(1, 0, false, "b"), fetch(3, 0, true, "d")]
        );
        // A gap at the end flags the segment after it, in a later load.
        let update = tracker.update(&live(1, 0, &["b", "?c", "d", "?e"]));
        assert_eq!(yielded(&update), vec![]);
        assert_eq!(update.reload_after, TARGET);
        let update = tracker.update(&live(2, 0, &["?c", "d", "?e", "f"]));
        assert_eq!(yielded(&update), vec![fetch(5, 0, true, "f")]);
        assert_eq!(update.event, None);
        // Two gaps in a row are one break.
        let update = tracker.update(&live(4, 0, &["?e", "f", "?g", "?h", "i"]));
        assert_eq!(yielded(&update), vec![fetch(8, 0, true, "i")]);
    }

    #[test]
    fn rfc8216bis_4_4_4_7_gaps_before_the_first_segment_start_no_new_timeline() {
        let mut tracker = Tracker::new();
        let update = tracker.update(&with_start(live(0, 0, &["?a", "?b", "c", "d"]), 0.0));
        assert_eq!(
            yielded(&update),
            vec![fetch(2, 0, false, "c"), fetch(3, 0, false, "d")]
        );
    }

    #[test]
    fn rfc8216_6_3_3_endlist_starts_at_the_first_segment() {
        assert_eq!(start_index(&ended(live(0, 0, &["a", "b", "c"]))), Some(0));
        assert_eq!(start_index(&ended(live(0, 0, &[]))), None);
    }

    #[test]
    fn rfc8216_4_3_5_2_negative_offset_counts_from_the_end() {
        // Five two-second segments end at 2, 4, 6, 8 and 10 seconds.
        let playlist = live(0, 0, &["a", "b", "c", "d", "e"]);
        assert_eq!(start_index(&with_start(playlist.clone(), -3.0)), Some(3));
        assert_eq!(start_index(&with_start(playlist.clone(), -4.0)), Some(3));
        assert_eq!(start_index(&with_start(playlist.clone(), -4.5)), Some(2));
        assert_eq!(start_index(&with_start(playlist.clone(), -0.5)), Some(4));
        assert_eq!(start_index(&with_start(playlist.clone(), -10.0)), Some(0));
        assert_eq!(
            start_index(&with_start(playlist, f64::NEG_INFINITY)),
            Some(0)
        );
    }

    #[test]
    fn rfc8216_4_3_5_2_positive_offset_counts_from_the_start() {
        let playlist = live(0, 0, &["a", "b", "c", "d", "e"]);
        assert_eq!(start_index(&with_start(playlist.clone(), 0.0)), Some(0));
        assert_eq!(start_index(&with_start(playlist.clone(), 1.9)), Some(0));
        assert_eq!(start_index(&with_start(playlist.clone(), 4.0)), Some(2));
        assert_eq!(start_index(&with_start(playlist.clone(), 5.0)), Some(2));
        assert_eq!(start_index(&with_start(playlist, 9.9)), Some(4));
    }

    #[test]
    fn rfc8216_4_3_5_2_offset_beyond_the_playlist_is_clamped() {
        let playlist = live(0, 0, &["a", "b", "c", "d", "e"]);
        assert_eq!(start_index(&with_start(playlist.clone(), 10.0)), Some(4));
        assert_eq!(start_index(&with_start(playlist.clone(), 100.0)), Some(4));
        assert_eq!(start_index(&with_start(playlist.clone(), -100.0)), Some(0));
        assert_eq!(start_index(&with_start(playlist.clone(), 1e300)), Some(4));
        assert_eq!(start_index(&with_start(playlist, f64::NAN)), Some(4));
    }

    #[test]
    fn rfc8216_4_3_5_2_start_overrides_endlist() {
        let playlist = ended(live(0, 0, &["a", "b", "c"]));
        assert_eq!(start_index(&with_start(playlist, -1.0)), Some(2));
    }

    #[test]
    fn rfc8216_4_3_5_2_segments_of_different_durations() {
        let mut playlist = live(0, 0, &[]);
        playlist.segments = vec![
            segment("a", 6, false),
            segment("b", 1, false),
            segment("c", 1, false),
        ];
        assert_eq!(start_index(&with_start(playlist.clone(), -2.5)), Some(0));
        assert_eq!(start_index(&with_start(playlist.clone(), -2.0)), Some(1));
        assert_eq!(start_index(&with_start(playlist, 6.0)), Some(1));
    }

    // Reload state.

    #[test]
    fn rfc8216_6_3_2_first_load_yields_from_the_live_edge() {
        let mut tracker = Tracker::new();
        let update = tracker.update(&live(10, 0, &["a", "b", "c", "d"]));
        assert_eq!(
            yielded(&update),
            vec![fetch(12, 0, false, "c"), fetch(13, 0, false, "d")]
        );
        assert_eq!(update.event, None);
        assert_eq!(update.reload_after, TARGET);
    }

    #[test]
    fn rfc8216_6_3_4_unchanged_playlist_reloads_after_half_the_target_duration() {
        let mut tracker = Tracker::new();
        let playlist = live(10, 0, &["a", "b", "c", "d"]);
        tracker.update(&playlist);
        let update = tracker.update(&playlist);
        assert_eq!(yielded(&update), vec![]);
        assert_eq!(update.event, None);
        assert_eq!(update.reload_after, HALF);
    }

    #[test]
    fn rfc8216_6_3_4_any_change_reloads_after_the_target_duration() {
        let base = live(10, 0, &["a", "b"]);
        let mut changes = vec![
            live(10, 1, &["a", "b"]),
            live(10, 0, &["a", "x"]),
            ended(live(10, 0, &["a", "b"])),
        ];
        let mut longer = base.clone();
        longer.segments.push(segment("c", 2, false));
        changes.push(longer);
        for changed in changes {
            let mut tracker = Tracker::new();
            tracker.update(&base);
            let update = tracker.update(&changed);
            assert!(
                update.reload_after.is_none() || update.reload_after == TARGET,
                "{changed:?}"
            );
            assert_eq!(update.event, None, "{changed:?}");
        }
        let mut tracker = Tracker::new();
        tracker.update(&base);
        assert_eq!(
            tracker.update(&live(10, 1, &["a", "b"])).reload_after,
            TARGET
        );
    }

    #[test]
    fn rfc8216_6_3_2_reload_yields_the_new_segments() {
        let mut tracker = Tracker::new();
        tracker.update(&live(10, 0, &["a", "b", "c", "d"]));
        let update = tracker.update(&live(11, 0, &["b", "c", "d", "e", "f"]));
        assert_eq!(
            yielded(&update),
            vec![fetch(14, 0, false, "e"), fetch(15, 0, false, "f")]
        );
        assert_eq!(update.event, None);
        assert_eq!(update.reload_after, TARGET);
    }

    #[test]
    fn rfc8216_6_3_2_window_starting_at_the_next_segment_is_no_gap() {
        let mut tracker = Tracker::new();
        tracker.update(&live(10, 0, &["a", "b", "c", "d"]));
        let update = tracker.update(&live(14, 0, &["e", "f"]));
        assert_eq!(
            yielded(&update),
            vec![fetch(14, 0, false, "e"), fetch(15, 0, false, "f")]
        );
        assert_eq!(update.event, None);
    }

    #[test]
    fn rfc8216_6_3_2_empty_playlist_waits_for_segments() {
        let mut tracker = Tracker::new();
        let update = tracker.update(&live(0, 0, &[]));
        assert_eq!(yielded(&update), vec![]);
        assert_eq!(update.reload_after, TARGET);
        assert_eq!(tracker.update(&live(0, 0, &[])).reload_after, HALF);
        let update = tracker.update(&live(0, 0, &["a", "b", "c"]));
        assert_eq!(
            yielded(&update),
            vec![fetch(1, 0, false, "b"), fetch(2, 0, false, "c")]
        );
    }

    #[test]
    fn rfc8216_6_3_2_skipped_segments_are_a_gap() {
        let mut tracker = Tracker::new();
        tracker.update(&live(10, 0, &["a", "b", "c", "d"]));
        let update = tracker.update(&live(20, 0, &["u", "v", "w"]));
        assert_eq!(update.event, Some(Event::Gap { lost: 6 }));
        assert_eq!(
            yielded(&update),
            vec![
                fetch(20, 0, true, "u"),
                fetch(21, 0, false, "v"),
                fetch(22, 0, false, "w")
            ]
        );
    }

    #[test]
    fn rfc8216_6_3_2_gap_into_an_empty_playlist_flags_the_next_segment() {
        let mut tracker = Tracker::new();
        tracker.update(&live(10, 0, &["a", "b"]));
        let update = tracker.update(&live(20, 0, &[]));
        assert_eq!(update.event, Some(Event::Gap { lost: 8 }));
        assert_eq!(yielded(&update), vec![]);
        let update = tracker.update(&live(20, 0, &["u"]));
        assert_eq!(update.event, None);
        assert_eq!(yielded(&update), vec![fetch(20, 0, true, "u")]);
    }

    #[test]
    fn rfc8216_6_3_2_media_sequence_going_backwards_is_a_restart() {
        let mut tracker = Tracker::new();
        tracker.update(&live(10, 0, &["a", "b", "c", "d"]));
        // Long enough to reach past the old position: still a restart.
        let update = tracker.update(&live(
            0,
            0,
            &[
                "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p",
            ],
        ));
        assert_eq!(update.event, Some(Event::Restart));
        assert_eq!(
            yielded(&update),
            vec![fetch(14, 0, true, "o"), fetch(15, 0, false, "p")]
        );
        let update = tracker.update(&live(9, 0, &["x"]));
        assert_eq!(update.event, Some(Event::Restart));
        assert_eq!(yielded(&update), vec![fetch(9, 0, true, "x")]);
    }

    #[test]
    fn rfc8216_6_3_2_playlist_ending_before_the_next_segment_is_a_restart() {
        let mut tracker = Tracker::new();
        tracker.update(&live(10, 0, &["a", "b", "c", "d"]));
        let update = tracker.update(&live(11, 0, &["x", "y"]));
        assert_eq!(update.event, Some(Event::Restart));
        assert_eq!(
            yielded(&update),
            vec![fetch(11, 0, true, "x"), fetch(12, 0, false, "y")]
        );
    }

    #[test]
    fn rfc8216_6_3_2_restart_into_an_empty_playlist_starts_at_the_next_live_edge() {
        let mut tracker = Tracker::new();
        tracker.update(&live(10, 0, &["a", "b"]));
        let update = tracker.update(&live(0, 0, &[]));
        assert_eq!(update.event, Some(Event::Restart));
        assert_eq!(yielded(&update), vec![]);
        let update = tracker.update(&live(0, 0, &["a", "b", "c"]));
        assert_eq!(update.event, None);
        assert_eq!(
            yielded(&update),
            vec![fetch(1, 0, true, "b"), fetch(2, 0, false, "c")]
        );
    }

    #[test]
    fn rfc8216_4_3_3_3_discontinuity_sequence_across_reloads() {
        let mut tracker = Tracker::new();
        let update = tracker.update(&live(0, 5, &["a", "!b"]));
        assert_eq!(
            yielded(&update),
            vec![fetch(0, 5, false, "a"), fetch(1, 6, true, "b")]
        );
        // The tagged segment is first now and keeps its number.
        let update = tracker.update(&live(1, 5, &["!b", "c"]));
        assert_eq!(yielded(&update), vec![fetch(2, 6, false, "c")]);
        // Removing the tag with its segment raises the sequence (§6.2.2).
        let update = tracker.update(&live(2, 6, &["c", "d"]));
        assert_eq!(yielded(&update), vec![fetch(3, 6, false, "d")]);
    }

    #[test]
    fn rfc8216_4_3_3_3_discontinuity_sequence_change_without_a_tag_starts_a_timeline() {
        let mut tracker = Tracker::new();
        tracker.update(&live(0, 0, &["a"]));
        let update = tracker.update(&live(1, 3, &["b", "c"]));
        assert_eq!(
            yielded(&update),
            vec![fetch(1, 3, true, "b"), fetch(2, 3, false, "c")]
        );
    }

    #[test]
    fn rfc8216_4_3_3_4_endlist_yields_every_segment_and_ends() {
        let mut tracker = Tracker::new();
        let update = tracker.update(&ended(live(0, 0, &["a", "b", "c"])));
        assert_eq!(
            yielded(&update),
            vec![
                fetch(0, 0, false, "a"),
                fetch(1, 0, false, "b"),
                fetch(2, 0, false, "c")
            ]
        );
        assert_eq!(update.reload_after, None);
        let mut tracker = Tracker::new();
        assert_eq!(tracker.update(&ended(live(0, 0, &[]))).reload_after, None);
    }

    #[test]
    fn rfc8216_4_3_3_4_live_playlist_that_ends() {
        let mut tracker = Tracker::new();
        tracker.update(&live(0, 0, &["a", "b", "c"]));
        let update = tracker.update(&ended(live(0, 0, &["a", "b", "c", "d"])));
        assert_eq!(yielded(&update), vec![fetch(3, 0, false, "d")]);
        assert_eq!(update.reload_after, None);
    }

    #[test]
    fn rfc8216_4_3_5_2_endlist_with_start_yields_the_rest() {
        let mut tracker = Tracker::new();
        let update = tracker.update(&with_start(ended(live(0, 0, &["a", "b", "c"])), 2.0));
        assert_eq!(
            yielded(&update),
            vec![fetch(1, 0, false, "b"), fetch(2, 0, false, "c")]
        );
        assert_eq!(update.reload_after, None);
    }

    #[test]
    fn rfc8216_6_3_2_media_sequence_numbers_end_before_u64_max() {
        let mut tracker = Tracker::new();
        let playlist = ended(live(u64::MAX - 1, 0, &["a", "b", "c"]));
        let update = tracker.update(&playlist);
        assert_eq!(yielded(&update), vec![fetch(u64::MAX - 1, 0, false, "a")]);
        assert_eq!(update.reload_after, None);

        let mut tracker = Tracker::new();
        let playlist = live(u64::MAX - 1, 0, &["a", "b", "c"]);
        assert_eq!(yielded(&tracker.update(&playlist)), vec![]);
        assert_eq!(yielded(&tracker.update(&playlist)), vec![]);

        // The start's own number does not fit.
        let mut tracker = Tracker::new();
        let playlist = live(u64::MAX, 0, &["a", "b", "c"]);
        let update = tracker.update(&playlist);
        assert_eq!(yielded(&update), vec![]);
        assert_eq!(update.reload_after, TARGET);
    }

    #[test]
    fn rfc8216_6_3_4_reload_interval_follows_the_target_duration() {
        let mut playlist = live(0, 0, &["a"]);
        playlist.target_duration = Duration::from_secs(5);
        let mut tracker = Tracker::new();
        assert_eq!(
            tracker.update(&playlist).reload_after,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            tracker.update(&playlist).reload_after,
            Some(Duration::from_millis(2500))
        );
    }
}

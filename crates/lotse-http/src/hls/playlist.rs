//! Parsing an HLS playlist into what the source needs, on `m3u8-rs`.
//!
//! Implements RFC 8216 §4 as a client reads it: §4.3.1.1 (`#EXTM3U`),
//! §4.3.2 (media segment tags: `EXTINF`, `EXT-X-BYTERANGE`,
//! `EXT-X-DISCONTINUITY`, `EXT-X-KEY`, `EXT-X-MAP`), §4.3.3 (media playlist
//! tags), §4.3.4 (multivariant playlist tags: `EXT-X-MEDIA`,
//! `EXT-X-STREAM-INF`, `EXT-X-I-FRAME-STREAM-INF`) and §4.3.5.2
//! (`EXT-X-START`). Every URI is resolved against the playlist's URL
//! (RFC 3986 §5.2, §4.1 of RFC 8216) and must share its origin (RFC 6454
//! §4: scheme, host and port), because the worker may connect to the
//! playlist's host only. Fragments are dropped: they are never sent
//! (RFC 3986 §3.5).
//!
//! Refused rather than half-played: encryption, byte ranges and I-frame-only
//! playlists. The input is bounded ([`MAX_PLAYLIST_BYTES`]) and so are the
//! lists built from it.
//!
//! `m3u8-rs` 6.0.1 (read 2026-10-08) attaches an `EXT-X-KEY` and an
//! `EXT-X-MAP` to the next segment only, and turns `EXT-X-KEY:METHOD=NONE`
//! without an IV into an unknown tag; both are corrected here.

use std::time::Duration;

use m3u8_rs::{AlternativeMediaType, ExtTag, KeyMethod};
use url::Url;

/// The largest playlist accepted, in bytes. Not from the RFC: a live
/// playlist is a few kilobytes, and the bound keeps the parser's memory
/// proportional to it.
pub const MAX_PLAYLIST_BYTES: usize = 1 << 20;

/// The most segments a media playlist may list. Not from the RFC: an hour
/// of one-second segments, far more than a live playlist's window.
pub const MAX_SEGMENTS: usize = 10_000;

/// The most `EXT-X-STREAM-INF` and `EXT-X-I-FRAME-STREAM-INF` variants a
/// multivariant playlist may list. Not from the RFC.
pub const MAX_VARIANTS: usize = 128;

/// The most `EXT-X-MEDIA` renditions a multivariant playlist may list, of
/// every type. Not from the RFC.
pub const MAX_RENDITIONS: usize = 128;

/// The value of the one `EXT-X-KEY` attribute list a client can play: an
/// unencrypted segment, where other attributes MUST NOT be present
/// (RFC 8216 §4.3.2.4).
const KEY_METHOD_NONE: &str = "METHOD=NONE";

/// A parsed playlist: a multivariant playlist lists variants, a media
/// playlist lists segments (RFC 8216 §4).
#[derive(Debug, Clone, PartialEq)]
pub enum Playlist {
    /// A multivariant playlist (RFC 8216 §4.3.4).
    Multivariant(MultivariantPlaylist),
    /// A media playlist (RFC 8216 §4.3.3).
    Media(MediaPlaylist),
}

/// The variants and audio renditions of a multivariant playlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultivariantPlaylist {
    /// The `EXT-X-STREAM-INF` variants in playlist order; I-frame variants
    /// (§4.3.4.3) are left out, they carry no playable stream.
    pub variants: Vec<Variant>,
    /// The `EXT-X-MEDIA` renditions of `TYPE=AUDIO` in playlist order; the
    /// other types are left out.
    pub audio: Vec<AudioRendition>,
}

/// One `EXT-X-STREAM-INF` variant (RFC 8216 §4.3.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    /// Its media playlist, resolved and of the playlist's origin.
    pub uri: Url,
    /// The `BANDWIDTH` attribute: peak bits per second.
    pub bandwidth: u64,
    /// The `CODECS` attribute (RFC 6381 list), when present.
    pub codecs: Option<String>,
    /// The `AUDIO` attribute: the `GROUP-ID` of its audio renditions.
    pub audio_group: Option<String>,
}

/// One `EXT-X-MEDIA` rendition of `TYPE=AUDIO` (RFC 8216 §4.3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioRendition {
    /// The `GROUP-ID` attribute a variant's `AUDIO` attribute names.
    pub group_id: String,
    /// The `NAME` attribute, unique within the group.
    pub name: String,
    /// The `DEFAULT` attribute: `YES` makes it the group's choice.
    pub default: bool,
    /// Its media playlist; `None` when the audio is in the variant's own
    /// segments (§4.3.4.1, `URI`).
    pub uri: Option<Url>,
}

/// The segments of a media playlist and the tags that steer playback.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaPlaylist {
    /// `EXT-X-TARGETDURATION` (§4.3.3.1): no segment is longer, rounded;
    /// at least one second.
    pub target_duration: Duration,
    /// `EXT-X-MEDIA-SEQUENCE` (§4.3.3.2): the first segment's number.
    pub media_sequence: u64,
    /// `EXT-X-DISCONTINUITY-SEQUENCE` (§4.3.3.3).
    pub discontinuity_sequence: u64,
    /// `EXT-X-ENDLIST` (§4.3.3.4): no segment will be added.
    pub end_list: bool,
    /// `EXT-X-START` (§4.3.5.2), when present.
    pub start: Option<Start>,
    /// The segments in playlist order, at most [`MAX_SEGMENTS`].
    pub segments: Vec<Segment>,
}

/// One media segment (RFC 8216 §3, §4.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The segment, resolved and of the playlist's origin.
    pub uri: Url,
    /// `EXTINF` (§4.3.2.1): positive.
    pub duration: Duration,
    /// `EXT-X-DISCONTINUITY` (§4.3.2.3) before this segment.
    pub discontinuity: bool,
    /// The `EXT-X-MAP` (§4.3.2.5) in effect: the last one before this
    /// segment, resolved and of the playlist's origin.
    pub map: Option<Url>,
}

/// `EXT-X-START` (RFC 8216 §4.3.5.2): where to start playing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Start {
    /// `TIME-OFFSET` in seconds, finite: from the start of the playlist
    /// when positive, from its end when negative.
    pub time_offset: f64,
    /// `PRECISE=YES`: start at the offset itself rather than at the start
    /// of the segment that contains it.
    pub precise: bool,
}

/// Why a playlist is refused. No variant carries playlist text a camera
/// controls beyond an origin, so the messages are safe to show.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlaylistError {
    /// Longer than [`MAX_PLAYLIST_BYTES`].
    #[error("the playlist is {size} bytes, more than the {MAX_PLAYLIST_BYTES} accepted")]
    TooLarge {
        /// Its length.
        size: usize,
    },
    /// The first line is not `#EXTM3U` (a byte order mark included, §4.1).
    #[error(
        "the response is not an HLS playlist: it does not start with #EXTM3U (RFC 8216 §4.3.1.1)"
    )]
    MissingHeader,
    /// Not M3U8 from `offset` on, such as a line that is not UTF-8 (§4.1).
    #[error("the playlist is not valid M3U8 from byte {offset} on (RFC 8216 §4.1)")]
    Malformed {
        /// Where parsing stopped.
        offset: usize,
    },
    /// More entries of one kind than the bound allows.
    #[error("the playlist lists {count} {what}, more than the {limit} accepted")]
    TooMany {
        /// The kind: "segments", "variants" or "renditions".
        what: &'static str,
        /// How many it lists.
        count: usize,
        /// The bound.
        limit: usize,
    },
    /// A media playlist without `EXT-X-TARGETDURATION`, or with 0.
    #[error(
        "the media playlist has no EXT-X-TARGETDURATION of at least one second (RFC 8216 §4.3.3.1)"
    )]
    TargetDuration,
    /// An `EXT-X-I-FRAMES-ONLY` media playlist.
    #[error("the media playlist is I-frame only, for trick play (RFC 8216 §4.3.3.6)")]
    IFramesOnly,
    /// An `EXT-X-START` whose `TIME-OFFSET` is not a finite number.
    #[error("EXT-X-START has a TIME-OFFSET that is not a finite number (RFC 8216 §4.3.5.2)")]
    StartOffset,
    /// An encrypted segment: an `EXT-X-KEY` with a method other than
    /// `NONE`, or one that cannot be read.
    #[error(
        "segment {index} of the playlist is encrypted; encrypted HLS is not supported (RFC 8216 §4.3.2.4)"
    )]
    Encrypted {
        /// Its position in the playlist, from 0.
        index: usize,
    },
    /// A segment or its `EXT-X-MAP` addressed by byte range.
    #[error(
        "segment {index} of the playlist is a byte range; byte ranges are not supported (RFC 8216 §4.3.2.2)"
    )]
    ByteRange {
        /// Its position in the playlist, from 0.
        index: usize,
    },
    /// An `EXT-X-MAP` that cannot be read, such as one without a quoted
    /// `URI`.
    #[error(
        "the EXT-X-MAP before segment {index} of the playlist is unreadable (RFC 8216 §4.3.2.5)"
    )]
    Map {
        /// The position of the segment it precedes, from 0.
        index: usize,
    },
    /// A segment without a positive, finite `EXTINF`.
    #[error("segment {index} of the playlist has no positive EXTINF duration (RFC 8216 §4.3.2.1)")]
    SegmentDuration {
        /// Its position in the playlist, from 0.
        index: usize,
    },
    /// An entry whose URI is missing, such as an `EXT-X-STREAM-INF` that no
    /// URI line follows (§4.3.4.2).
    #[error("a {what} has no URI (RFC 8216 §4.3.4.2)")]
    MissingUri {
        /// The kind of entry.
        what: &'static str,
    },
    /// A URI that does not resolve against the playlist's URL.
    #[error("a {what} URI is not a valid URI reference: {error} (RFC 3986 §4.1)")]
    InvalidUri {
        /// The kind of entry.
        what: &'static str,
        /// Why it does not resolve.
        error: url::ParseError,
    },
    /// A URI of another origin than the playlist's.
    #[error(
        "a {what} URI points to {origin}, not to the playlist's origin; only same-origin URIs are followed"
    )]
    CrossOrigin {
        /// The kind of entry.
        what: &'static str,
        /// The other origin (RFC 6454 §6.2), without path, query or
        /// credentials.
        origin: String,
    },
}

/// Parses a playlist fetched from `base`, resolving its URIs against it.
///
/// Refuses what [`PlaylistError`] lists; a playlist that parses is bounded
/// and every URL in it shares `base`'s origin and has no fragment.
pub fn parse(bytes: &[u8], base: &Url) -> Result<Playlist, PlaylistError> {
    if bytes.len() > MAX_PLAYLIST_BYTES {
        return Err(PlaylistError::TooLarge { size: bytes.len() });
    }
    if !bytes.starts_with(b"#EXTM3U") {
        return Err(PlaylistError::MissingHeader);
    }
    let (rest, playlist) =
        m3u8_rs::parse_playlist(bytes).map_err(|_| PlaylistError::Malformed { offset: 0 })?;
    if !rest.is_empty() {
        return Err(PlaylistError::Malformed {
            offset: bytes.len().saturating_sub(rest.len()),
        });
    }
    match playlist {
        m3u8_rs::Playlist::MasterPlaylist(playlist) => {
            multivariant(playlist, base).map(Playlist::Multivariant)
        }
        m3u8_rs::Playlist::MediaPlaylist(playlist) => media(playlist, base).map(Playlist::Media),
    }
}

/// The playable variants and the audio renditions of a multivariant
/// playlist.
fn multivariant(
    playlist: m3u8_rs::MasterPlaylist,
    base: &Url,
) -> Result<MultivariantPlaylist, PlaylistError> {
    bound("variants", playlist.variants.len(), MAX_VARIANTS)?;
    bound("renditions", playlist.alternatives.len(), MAX_RENDITIONS)?;
    let variants = playlist
        .variants
        .into_iter()
        .filter(|variant| !variant.is_i_frame)
        .map(|variant| {
            Ok(Variant {
                uri: resolve(base, &variant.uri, "variant")?,
                bandwidth: variant.bandwidth,
                codecs: variant.codecs,
                audio_group: variant.audio,
            })
        })
        .collect::<Result<_, PlaylistError>>()?;
    let audio = playlist
        .alternatives
        .into_iter()
        .filter(|media| media.media_type == AlternativeMediaType::Audio)
        .map(|media| {
            Ok(AudioRendition {
                uri: media
                    .uri
                    .map(|uri| resolve(base, &uri, "audio rendition"))
                    .transpose()?,
                group_id: media.group_id,
                name: media.name,
                default: media.default,
            })
        })
        .collect::<Result<_, PlaylistError>>()?;
    Ok(MultivariantPlaylist { variants, audio })
}

/// The segments of a media playlist, with `EXT-X-MAP` carried forward to
/// every segment it applies to (§4.3.2.5).
fn media(playlist: m3u8_rs::MediaPlaylist, base: &Url) -> Result<MediaPlaylist, PlaylistError> {
    if playlist.i_frames_only {
        return Err(PlaylistError::IFramesOnly);
    }
    // m3u8-rs reads a missing or unreadable EXT-X-TARGETDURATION as 0.
    if playlist.target_duration == 0 {
        return Err(PlaylistError::TargetDuration);
    }
    bound("segments", playlist.segments.len(), MAX_SEGMENTS)?;
    let start = match playlist.start {
        Some(start) if start.time_offset.is_finite() => Some(Start {
            time_offset: start.time_offset,
            precise: start.precise == Some(true),
        }),
        Some(_) => return Err(PlaylistError::StartOffset),
        None => None,
    };
    let mut map = None;
    let mut segments = Vec::with_capacity(playlist.segments.len());
    for (index, segment) in playlist.segments.into_iter().enumerate() {
        if segment.byte_range.is_some() || has_tag(&segment.unknown_tags, "X-BYTERANGE") {
            return Err(PlaylistError::ByteRange { index });
        }
        if encrypted(&segment) {
            return Err(PlaylistError::Encrypted { index });
        }
        if has_tag(&segment.unknown_tags, "X-MAP") {
            return Err(PlaylistError::Map { index });
        }
        if let Some(segment_map) = segment.map {
            if segment_map.byte_range.is_some() {
                return Err(PlaylistError::ByteRange { index });
            }
            map = Some(resolve(base, &segment_map.uri, "EXT-X-MAP")?);
        }
        let duration = Duration::try_from_secs_f32(segment.duration)
            .ok()
            .filter(|duration| !duration.is_zero())
            .ok_or(PlaylistError::SegmentDuration { index })?;
        segments.push(Segment {
            uri: resolve(base, &segment.uri, "segment")?,
            duration,
            discontinuity: segment.discontinuity,
            map: map.clone(),
        });
    }
    Ok(MediaPlaylist {
        target_duration: Duration::from_secs(playlist.target_duration),
        media_sequence: playlist.media_sequence,
        discontinuity_sequence: playlist.discontinuity_sequence,
        end_list: playlist.end_list,
        start,
        segments,
    })
}

/// Whether an `EXT-X-KEY` before `segment` encrypts it: a key with a method
/// other than `NONE`, or one m3u8-rs could not read, unless it is exactly
/// `METHOD=NONE` (§4.3.2.4).
fn encrypted(segment: &m3u8_rs::MediaSegment) -> bool {
    segment
        .key
        .as_ref()
        .is_some_and(|key| key.method != KeyMethod::None)
        || segment
            .unknown_tags
            .iter()
            .any(|tag| tag.tag == "X-KEY" && tag.rest.as_deref() != Some(KEY_METHOD_NONE))
}

/// Whether the tags m3u8-rs could not read include `name` (without the
/// `#EXT-` prefix).
fn has_tag(tags: &[ExtTag], name: &str) -> bool {
    tags.iter().any(|tag| tag.tag == name)
}

/// Refuses more than `limit` entries of one kind.
fn bound(what: &'static str, count: usize, limit: usize) -> Result<(), PlaylistError> {
    if count > limit {
        return Err(PlaylistError::TooMany { what, count, limit });
    }
    Ok(())
}

/// Resolves `reference` against `base` (RFC 3986 §5.2), requires `base`'s
/// origin (RFC 6454 §5) and drops the fragment (RFC 3986 §3.5).
fn resolve(base: &Url, reference: &str, what: &'static str) -> Result<Url, PlaylistError> {
    if reference.is_empty() {
        return Err(PlaylistError::MissingUri { what });
    }
    let mut url = base
        .join(reference)
        .map_err(|error| PlaylistError::InvalidUri { what, error })?;
    if url.origin() != base.origin() {
        return Err(PlaylistError::CrossOrigin {
            what,
            origin: url.origin().ascii_serialization(),
        });
    }
    url.set_fragment(None);
    Ok(url)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    const BASE: &str = "http://camera.example:8080/live/index.m3u8";

    fn base() -> Url {
        Url::parse(BASE).unwrap()
    }

    fn url(path: &str) -> Url {
        Url::parse(&format!("http://camera.example:8080{path}")).unwrap()
    }

    fn parse_media(text: &str) -> MediaPlaylist {
        let Playlist::Media(playlist) = parse(text.as_bytes(), &base()).unwrap() else {
            panic!("not a media playlist");
        };
        playlist
    }

    fn parse_multivariant(text: &str) -> MultivariantPlaylist {
        let Playlist::Multivariant(playlist) = parse(text.as_bytes(), &base()).unwrap() else {
            panic!("not a multivariant playlist");
        };
        playlist
    }

    fn refused(text: &str) -> PlaylistError {
        parse(text.as_bytes(), &base()).unwrap_err()
    }

    /// A media playlist with a target duration of 2 and `body` after it.
    fn media_with(body: &str) -> String {
        format!("#EXTM3U\n#EXT-X-TARGETDURATION:2\n{body}")
    }

    #[test]
    fn rfc8216_4_3_3_live_media_playlist() {
        let playlist = parse_media(
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:4\n#EXT-X-MEDIA-SEQUENCE:120\n\
             #EXT-X-DISCONTINUITY-SEQUENCE:7\n#EXTINF:3.5,\nseg120.ts\n#EXT-X-DISCONTINUITY\n\
             #EXTINF:4,title\nseg121.ts?token=a#frag\n",
        );
        assert_eq!(
            playlist,
            MediaPlaylist {
                target_duration: Duration::from_secs(4),
                media_sequence: 120,
                discontinuity_sequence: 7,
                end_list: false,
                start: None,
                segments: vec![
                    Segment {
                        uri: url("/live/seg120.ts"),
                        duration: Duration::from_millis(3500),
                        discontinuity: false,
                        map: None,
                    },
                    Segment {
                        uri: url("/live/seg121.ts?token=a"),
                        duration: Duration::from_secs(4),
                        discontinuity: true,
                        map: None,
                    },
                ],
            }
        );
    }

    #[test]
    fn rfc8216_4_3_3_4_endlist() {
        let playlist = parse_media(&media_with("#EXTINF:2,\na.ts\n#EXT-X-ENDLIST\n"));
        assert!(playlist.end_list);
        assert_eq!(playlist.segments.len(), 1);
    }

    #[test]
    fn rfc8216_4_3_3_empty_live_playlist_parses() {
        let playlist = parse_media(&media_with(""));
        assert!(playlist.segments.is_empty());
        assert_eq!(playlist.media_sequence, 0);
    }

    #[test]
    fn rfc8216_4_3_5_2_start_offset_and_precise() {
        let playlist = parse_media(&media_with(
            "#EXT-X-START:TIME-OFFSET=-6.5,PRECISE=YES\n#EXTINF:2,\na.ts\n",
        ));
        assert_eq!(
            playlist.start,
            Some(Start {
                time_offset: -6.5,
                precise: true
            })
        );
        let playlist = parse_media(&media_with("#EXT-X-START:TIME-OFFSET=4\n"));
        assert_eq!(
            playlist.start,
            Some(Start {
                time_offset: 4.0,
                precise: false
            })
        );
    }

    #[test]
    fn rfc8216_4_3_5_2_non_finite_start_offset_is_refused() {
        for offset in ["inf", "NaN", "-inf"] {
            assert_eq!(
                refused(&media_with(&format!("#EXT-X-START:TIME-OFFSET={offset}\n"))),
                PlaylistError::StartOffset
            );
        }
    }

    #[test]
    fn rfc8216_4_3_2_5_map_applies_until_the_next_map() {
        let playlist = parse_media(&media_with(
            "#EXTINF:2,\nplain.ts\n#EXT-X-MAP:URI=\"init1.mp4\"\n#EXTINF:2,\na.m4s\n#EXTINF:2,\n\
             b.m4s\n#EXT-X-MAP:URI=\"/other/init2.mp4#x\"\n#EXTINF:2,\nc.m4s\n",
        ));
        let maps: Vec<_> = playlist.segments.iter().map(|s| s.map.clone()).collect();
        assert_eq!(
            maps,
            [
                None,
                Some(url("/live/init1.mp4")),
                Some(url("/live/init1.mp4")),
                Some(url("/other/init2.mp4")),
            ]
        );
    }

    #[test]
    fn rfc8216_4_3_2_5_unreadable_map_is_refused() {
        assert_eq!(
            refused(&media_with("#EXT-X-MAP:URI=init.mp4\n#EXTINF:2,\na.m4s\n")),
            PlaylistError::Map { index: 0 }
        );
    }

    #[test]
    fn rfc8216_4_3_2_5_map_byte_range_is_refused() {
        assert_eq!(
            refused(&media_with(
                "#EXTINF:2,\na.m4s\n#EXT-X-MAP:URI=\"init.mp4\",BYTERANGE=\"720@0\"\n#EXTINF:2,\nb.m4s\n"
            )),
            PlaylistError::ByteRange { index: 1 }
        );
    }

    #[test]
    fn rfc8216_4_3_1_1_missing_extm3u_is_refused() {
        assert_eq!(
            refused("#EXT-X-TARGETDURATION:2\n#EXTINF:2,\na.ts\n"),
            PlaylistError::MissingHeader
        );
        assert_eq!(refused("<html></html>"), PlaylistError::MissingHeader);
        assert_eq!(refused(""), PlaylistError::MissingHeader);
    }

    #[test]
    fn rfc8216_4_1_byte_order_mark_is_refused() {
        assert_eq!(
            refused("\u{feff}#EXTM3U\n#EXT-X-TARGETDURATION:2\n"),
            PlaylistError::MissingHeader
        );
    }

    #[test]
    fn rfc8216_4_1_non_utf8_line_is_refused_where_it_starts() {
        let mut bytes = media_with("#EXTINF:2,\n").into_bytes();
        let offset = bytes.len();
        bytes.extend_from_slice(b"\xffa.ts\n#EXTINF:2,\nb.ts\n");
        assert_eq!(
            parse(&bytes, &base()),
            Err(PlaylistError::Malformed { offset })
        );
    }

    #[test]
    fn rfc8216_4_1_lone_carriage_return_is_refused() {
        let text = media_with("#EXTINF:2,\na.ts\rb\n");
        let offset = text.find("a.ts").unwrap();
        assert_eq!(refused(&text), PlaylistError::Malformed { offset });
    }

    #[test]
    fn rfc8216_4_1_crlf_line_endings_parse() {
        let playlist = parse_media("#EXTM3U\r\n#EXT-X-TARGETDURATION:2\r\n#EXTINF:2,\r\na.ts\r\n");
        assert_eq!(playlist.segments.len(), 1);
        assert_eq!(playlist.segments[0].uri, url("/live/a.ts"));
    }

    #[test]
    fn playlist_over_one_mebibyte_is_refused() {
        let mut text = media_with("");
        text.push_str(&"#".repeat(MAX_PLAYLIST_BYTES - text.len() - 1));
        text.push('\n');
        assert_eq!(text.len(), MAX_PLAYLIST_BYTES);
        assert!(parse_media(&text).segments.is_empty());
        text.push('\n');
        assert_eq!(
            refused(&text),
            PlaylistError::TooLarge {
                size: MAX_PLAYLIST_BYTES + 1
            }
        );
    }

    #[test]
    fn rfc8216_4_3_3_1_missing_target_duration_is_refused() {
        assert_eq!(
            refused("#EXTM3U\n#EXTINF:2,\na.ts\n"),
            PlaylistError::TargetDuration
        );
        assert_eq!(
            refused("#EXTM3U\n#EXT-X-TARGETDURATION:0\n#EXTINF:2,\na.ts\n"),
            PlaylistError::TargetDuration
        );
        assert_eq!(
            refused("#EXTM3U\n#EXT-X-TARGETDURATION:two\n#EXTINF:2,\na.ts\n"),
            PlaylistError::TargetDuration
        );
    }

    #[test]
    fn rfc8216_4_3_3_1_target_duration_of_one_second_parses() {
        let playlist = parse_media("#EXTM3U\n#EXT-X-TARGETDURATION:1\n");
        assert_eq!(playlist.target_duration, Duration::from_secs(1));
    }

    #[test]
    fn rfc8216_4_3_3_6_i_frames_only_is_refused() {
        assert_eq!(
            refused(&media_with(
                "#EXT-X-I-FRAMES-ONLY\n#EXTINF:2,\n#EXT-X-BYTERANGE:100@0\na.ts\n"
            )),
            PlaylistError::IFramesOnly
        );
    }

    #[test]
    fn rfc8216_4_3_2_2_byte_range_is_refused() {
        assert_eq!(
            refused(&media_with(
                "#EXTINF:2,\na.ts\n#EXTINF:2,\n#EXT-X-BYTERANGE:1000@200\nall.ts\n"
            )),
            PlaylistError::ByteRange { index: 1 }
        );
        assert_eq!(
            refused(&media_with("#EXTINF:2,\n#EXT-X-BYTERANGE:lots\nall.ts\n")),
            PlaylistError::ByteRange { index: 0 }
        );
    }

    #[test]
    fn rfc8216_4_3_2_4_encrypted_segments_are_refused() {
        for key in [
            "#EXT-X-KEY:METHOD=AES-128,URI=\"key.bin\"",
            "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"key.bin\",IV=0x01",
            "#EXT-X-KEY:METHOD=SOMETHING-NEW",
            // No METHOD: unreadable, so taken as encrypted.
            "#EXT-X-KEY:URI=\"key.bin\"",
            // Attributes besides METHOD=NONE MUST NOT be present.
            "#EXT-X-KEY:METHOD=NONE,URI=\"key.bin\"",
        ] {
            assert_eq!(
                refused(&media_with(&format!(
                    "#EXTINF:2,\na.ts\n{key}\n#EXTINF:2,\nb.ts\n"
                ))),
                PlaylistError::Encrypted { index: 1 },
                "{key}"
            );
        }
    }

    #[test]
    fn rfc8216_4_3_2_4_method_none_is_unencrypted() {
        for key in ["#EXT-X-KEY:METHOD=NONE", "#EXT-X-KEY:METHOD=NONE,IV=0x01"] {
            let playlist = parse_media(&media_with(&format!("{key}\n#EXTINF:2,\na.ts\n")));
            assert_eq!(playlist.segments.len(), 1, "{key}");
        }
    }

    #[test]
    fn rfc8216_4_3_2_4_method_none_ends_encryption() {
        let playlist = parse_media(&media_with(
            "#EXT-X-KEY:METHOD=AES-128,URI=\"k\"\n#EXT-X-KEY:METHOD=NONE,IV=0x01\n#EXTINF:2,\na.ts\n",
        ));
        assert_eq!(playlist.segments.len(), 1);
    }

    #[test]
    fn rfc8216_4_3_2_4_key_after_the_last_segment_encrypts_nothing() {
        let playlist = parse_media(&media_with(
            "#EXTINF:2,\na.ts\n#EXT-X-KEY:METHOD=AES-128,URI=\"k\"\n",
        ));
        assert_eq!(playlist.segments.len(), 1);
    }

    #[test]
    fn rfc8216_4_3_2_1_invalid_extinf_is_refused() {
        for extinf in [
            // Missing.
            "",
            // Zero.
            "#EXTINF:0,\n",
            // Negative: m3u8-rs reads it as a comment, so it is missing.
            "#EXTINF:-2,\n",
            // Beyond f32: infinite.
            &format!("#EXTINF:{},\n", "9".repeat(40)),
        ] {
            assert_eq!(
                refused(&media_with(&format!("#EXTINF:2,\na.ts\n{extinf}b.ts\n"))),
                PlaylistError::SegmentDuration { index: 1 },
                "{extinf}"
            );
        }
    }

    #[test]
    fn segment_count_is_bounded() {
        let mut text = media_with(&"#EXTINF:1,\ns.ts\n".repeat(MAX_SEGMENTS));
        assert_eq!(parse_media(&text).segments.len(), MAX_SEGMENTS);
        text.push_str("#EXTINF:1,\ns.ts\n");
        assert_eq!(
            refused(&text),
            PlaylistError::TooMany {
                what: "segments",
                count: MAX_SEGMENTS + 1,
                limit: MAX_SEGMENTS
            }
        );
    }

    #[test]
    fn rfc8216_4_3_4_multivariant_playlist() {
        let playlist = parse_multivariant(
            "#EXTM3U\n\
             #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aac\",NAME=\"English\",DEFAULT=YES,URI=\"audio/en.m3u8\"\n\
             #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aac\",NAME=\"Muxed\"\n\
             #EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"subs\",NAME=\"English\",URI=\"subs/en.m3u8\"\n\
             #EXT-X-STREAM-INF:BANDWIDTH=2000000,CODECS=\"avc1.64001f,mp4a.40.2\",AUDIO=\"aac\"\n\
             hi/index.m3u8#frag\n\
             #EXT-X-I-FRAME-STREAM-INF:BANDWIDTH=90000,URI=\"iframes.m3u8\"\n\
             #EXT-X-STREAM-INF:BANDWIDTH=500000\n\
             /lo.m3u8\n",
        );
        assert_eq!(
            playlist,
            MultivariantPlaylist {
                variants: vec![
                    Variant {
                        uri: url("/live/hi/index.m3u8"),
                        bandwidth: 2_000_000,
                        codecs: Some("avc1.64001f,mp4a.40.2".to_owned()),
                        audio_group: Some("aac".to_owned()),
                    },
                    Variant {
                        uri: url("/lo.m3u8"),
                        bandwidth: 500_000,
                        codecs: None,
                        audio_group: None,
                    },
                ],
                audio: vec![
                    AudioRendition {
                        group_id: "aac".to_owned(),
                        name: "English".to_owned(),
                        default: true,
                        uri: Some(url("/live/audio/en.m3u8")),
                    },
                    AudioRendition {
                        group_id: "aac".to_owned(),
                        name: "Muxed".to_owned(),
                        default: false,
                        uri: None,
                    },
                ],
            }
        );
    }

    #[test]
    fn rfc8216_4_3_4_2_variant_without_uri_is_refused() {
        assert_eq!(
            refused("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1000\n"),
            PlaylistError::MissingUri { what: "variant" }
        );
    }

    #[test]
    fn variant_count_is_bounded() {
        let variant = "#EXT-X-STREAM-INF:BANDWIDTH=1000\nv.m3u8\n";
        let mut text = format!("#EXTM3U\n{}", variant.repeat(MAX_VARIANTS));
        assert_eq!(parse_multivariant(&text).variants.len(), MAX_VARIANTS);
        text.push_str(variant);
        assert_eq!(
            refused(&text),
            PlaylistError::TooMany {
                what: "variants",
                count: MAX_VARIANTS + 1,
                limit: MAX_VARIANTS
            }
        );
    }

    #[test]
    fn rendition_count_is_bounded() {
        let rendition = "#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",NAME=\"n\"\n";
        let mut text = format!("#EXTM3U\n{}", rendition.repeat(MAX_RENDITIONS));
        assert_eq!(parse_multivariant(&text).audio.len(), MAX_RENDITIONS);
        text.push_str(rendition);
        assert_eq!(
            refused(&text),
            PlaylistError::TooMany {
                what: "renditions",
                count: MAX_RENDITIONS + 1,
                limit: MAX_RENDITIONS
            }
        );
    }

    #[test]
    fn rfc6454_cross_origin_uris_are_refused() {
        for (reference, origin) in [
            ("http://cdn.example:8080/a.ts", "http://cdn.example:8080"),
            (
                "https://camera.example:8080/a.ts",
                "https://camera.example:8080",
            ),
            ("http://camera.example/a.ts", "http://camera.example"),
            ("//other.example/a.ts", "http://other.example"),
            ("data:video/mp2t,abc", "null"),
        ] {
            assert_eq!(
                refused(&media_with(&format!("#EXTINF:2,\n{reference}\n"))),
                PlaylistError::CrossOrigin {
                    what: "segment",
                    origin: origin.to_owned()
                },
                "{reference}"
            );
        }
    }

    #[test]
    fn rfc6454_cross_origin_error_names_no_credentials() {
        let error = refused(&media_with(
            "#EXTINF:2,\nhttp://user:secret@cdn.example/a.ts?k=v\n",
        ));
        assert_eq!(
            error.to_string(),
            "a segment URI points to http://cdn.example, not to the playlist's origin; only \
             same-origin URIs are followed"
        );
    }

    #[test]
    fn rfc3986_5_2_absolute_same_origin_uri_is_followed() {
        let playlist = parse_media(&media_with(
            "#EXTINF:2,\nhttp://CAMERA.example:8080/x/../a.ts\n",
        ));
        assert_eq!(playlist.segments[0].uri, url("/a.ts"));
    }

    #[test]
    fn rfc6454_cross_origin_map_and_renditions_are_refused() {
        assert_eq!(
            refused(&media_with(
                "#EXT-X-MAP:URI=\"https://cdn.example/init.mp4\"\n#EXTINF:2,\na.m4s\n"
            )),
            PlaylistError::CrossOrigin {
                what: "EXT-X-MAP",
                origin: "https://cdn.example".to_owned()
            }
        );
        assert_eq!(
            refused(
                "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",NAME=\"n\",URI=\"https://cdn.example/a.m3u8\"\n"
            ),
            PlaylistError::CrossOrigin {
                what: "audio rendition",
                origin: "https://cdn.example".to_owned()
            }
        );
        assert_eq!(
            refused("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\nhttps://cdn.example/v.m3u8\n"),
            PlaylistError::CrossOrigin {
                what: "variant",
                origin: "https://cdn.example".to_owned()
            }
        );
    }

    #[test]
    fn rfc3986_4_1_unresolvable_uri_is_refused() {
        assert_eq!(
            refused(&media_with("#EXTINF:2,\nhttp://[::1/a.ts\n")),
            PlaylistError::InvalidUri {
                what: "segment",
                error: url::ParseError::InvalidIpv6Address
            }
        );
    }

    #[test]
    fn errors_name_the_clause() {
        assert_eq!(
            PlaylistError::Encrypted { index: 3 }.to_string(),
            "segment 3 of the playlist is encrypted; encrypted HLS is not supported (RFC 8216 \
             §4.3.2.4)"
        );
    }
}

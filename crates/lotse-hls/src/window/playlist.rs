//! The window's Media Playlist (draft-pantos-hls-rfc8216bis-22 §4), one
//! rendition of a live presentation, rendered whole on every request.
//!
//! In order: `EXTM3U` (§4.4.1.1, the first line), `EXT-X-VERSION` (§4.4.1.2,
//! §8), `EXT-X-TARGETDURATION` (§4.4.3.1), `EXT-X-SERVER-CONTROL` (§4.4.3.8),
//! `EXT-X-PART-INF` (§4.4.3.7), `EXT-X-MEDIA-SEQUENCE` (§4.4.3.2, before the
//! first segment), `EXT-X-INDEPENDENT-SEGMENTS` (§4.4.2.1), `EXT-X-MAP`
//! (§4.4.4.5, before every part, as §4.4.4.9 requires of a tag that applies
//! to a Parent Segment), then each complete segment as its recent
//! `EXT-X-PART` tags (§4.4.4.9), its `EXTINF` (§4.4.4.1) and its URI, the
//! open segment's parts, and the `EXT-X-PRELOAD-HINT` of the next part
//! (§4.4.5.3; the Low-Latency profile, Appendix B.1, has a playlist with
//! parts carry one).
//!
//! Durations are decimal-floating-point seconds (§4.2) to the microsecond,
//! truncated: monotone, so a part no longer than the Part Target Duration
//! is not written longer, and an EXTINF is not written longer than its
//! segment, so it rounds to no more than the Target Duration; a microsecond
//! a segment keeps the accumulated error imperceptible (§4.4.4.1) for
//! days of segments.
//!
//! Left out: `EXT-X-PROGRAM-DATE-TIME`. SPEC-DEVIATION (Appendix B.1: "All
//! Media Playlists have EXT-X-PROGRAM-DATE-TIME tags", there to map segments
//! across renditions): the window has no wall clock and one rendition. Also
//! left out, being out of scope: Playlist Delta Updates (§6.2.5.1, no
//! `CAN-SKIP-UNTIL`, so `_HLS_skip` is ignored), `EXT-X-RENDITION-REPORT`
//! (§4.4.5.4; Appendix B.1 asks for one per other rendition, and there is
//! none), encryption (`EXT-X-KEY`), `EXT-X-DISCONTINUITY` and `EXT-X-GAP`
//! (the decode times run on without a hole), and `EXT-X-ENDLIST` (a live
//! output never ends its playlist; it goes away).

use std::fmt;
use std::time::Duration;

use super::{Targets, Window};
use crate::name::Resource;

/// The compatibility version: 6, for `EXT-X-MAP` in a playlist without
/// `EXT-X-I-FRAMES-ONLY` (draft-pantos-hls-rfc8216bis-22 §8; floating-point
/// `EXTINF` needs 3). The Low-Latency tags need none (§8 lists none of them),
/// and §6.2.1 says the version "SHOULD NOT be greater than what is
/// required".
const VERSION: u8 = 6;

/// `PART-HOLD-BACK` in Part Target Durations: "MUST be at least twice the
/// Part Target Duration. Its value SHOULD be at least three times"
/// (draft-pantos-hls-rfc8216bis-22 §4.4.3.8). Three: the SHOULD, the
/// lowest latency it allows.
const PART_HOLD_BACK_PARTS: u32 = 3;

/// How far from the playlist's end, in Target Durations, a part's tag is
/// listed: "EXT-X-PART tags SHOULD be removed from the Playlist after they
/// are greater than three Target Durations from the end of the Playlist"
/// (draft-pantos-hls-rfc8216bis-22 §6.2.2). A part is that far once its end
/// is.
const PART_TAG_TARGET_DURATIONS: u32 = 3;

impl Window {
    /// The Media Playlist as it is now, once the first segment completed;
    /// `None` before (the targets every playlist holds to are not known yet).
    pub fn playlist(&self) -> Option<String> {
        let targets = self.targets?;
        Some(
            Render {
                window: self,
                targets,
            }
            .to_string(),
        )
    }
}

/// A window's playlist, written out.
struct Render<'a> {
    /// The window.
    window: &'a Window,
    /// Its targets.
    targets: Targets,
}

impl fmt::Display for Render<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let window = self.window;
        let Targets {
            target_duration,
            part_target,
        } = self.targets;
        let media_sequence = window
            .listed
            .front()
            .map_or(window.completed, |segment| segment.msn);
        writeln!(f, "#EXTM3U")?;
        writeln!(f, "#EXT-X-VERSION:{VERSION}")?;
        writeln!(f, "#EXT-X-TARGETDURATION:{target_duration}")?;
        let hold_back = Seconds(part_target.saturating_mul(PART_HOLD_BACK_PARTS));
        write!(f, "#EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES,")?;
        writeln!(f, "PART-HOLD-BACK={hold_back}")?;
        writeln!(f, "#EXT-X-PART-INF:PART-TARGET={}", Seconds(part_target))?;
        writeln!(f, "#EXT-X-MEDIA-SEQUENCE:{media_sequence}")?;
        writeln!(f, "#EXT-X-INDEPENDENT-SEGMENTS")?;
        writeln!(f, "#EXT-X-MAP:URI=\"{}\"", Resource::Init)?;

        let open = window.open.as_ref().map(|open| &open.segment);
        let segments = || window.listed.iter().chain(open);
        let end = segments().fold(Duration::ZERO, |end, segment| {
            end.saturating_add(segment.duration)
        });
        let tags_from = end.saturating_sub(
            Duration::from_secs(target_duration).saturating_mul(PART_TAG_TARGET_DURATIONS),
        );
        let mut at = Duration::ZERO;
        for segment in segments() {
            for (index, part) in (0_u64..).zip(&segment.parts) {
                at = at.saturating_add(part.duration);
                if at >= tags_from {
                    let uri = Resource::Part {
                        msn: segment.msn,
                        index,
                    };
                    let independent = if part.independent {
                        "INDEPENDENT=YES,"
                    } else {
                        ""
                    };
                    let duration = Seconds(part.duration);
                    write!(f, "#EXT-X-PART:DURATION={duration},{independent}")?;
                    writeln!(f, "URI=\"{uri}\"")?;
                }
            }
            if Some(segment.msn) != open.map(|open| open.msn) {
                writeln!(f, "#EXTINF:{},", Seconds(segment.duration))?;
                writeln!(f, "{}", Resource::Segment { msn: segment.msn })?;
            }
        }
        let (msn, index) = (window.completed, window.open_parts());
        writeln!(
            f,
            "#EXT-X-PRELOAD-HINT:TYPE=PART,URI=\"{}\"",
            Resource::Part { msn, index }
        )
    }
}

/// A duration as decimal-floating-point seconds (draft-pantos-hls-rfc8216bis-22
/// §4.2), to the microsecond, truncated.
struct Seconds(Duration);

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:06}", self.0.as_secs(), self.0.subsec_micros())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn rfc8216bis_4_2_seconds_are_decimal_floating_point_to_the_microsecond_truncated() {
        assert_eq!(Seconds(Duration::ZERO).to_string(), "0.000000");
        assert_eq!(Seconds(Duration::from_millis(200)).to_string(), "0.200000");
        assert_eq!(
            Seconds(Duration::from_nanos(2_002_002_999)).to_string(),
            "2.002002"
        );
        assert_eq!(Seconds(Duration::from_secs(61)).to_string(), "61.000000");
    }
}

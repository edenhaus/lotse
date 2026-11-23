//! The names of a window's resources: the URIs its playlist gives them,
//! relative to the playlist's own (draft-pantos-hls-rfc8216bis-22 §4.1: a
//! relative URI resolves against the URI of the playlist that holds it), and
//! the strict parse of a requested name back to the resource.
//!
//! The scheme: [`INIT_NAME`] for the init segment (the `EXT-X-MAP`, §4.4.4.5),
//! `seg{msn}.m4s` for the Media Segment of a Media Sequence Number (§3,
//! §4.4.3.2) and `part{msn}.{index}.m4s` for its Partial Segment of a Part
//! Index (§3.2, §4.4.4.9), the numbers in decimal. A name a client sends is
//! untrusted: [`Resource::parse`] takes exactly what [`Resource`]'s `Display`
//! writes and nothing else, so every resource has one name and every name
//! one resource. A number has no sign, no leading zero (`seg01.m4s` would
//! alias `seg1.m4s`) and fits a `u64`; the work is linear in the name's
//! length, and nothing is allocated.

use std::fmt;

/// The init segment's name: the URI of the playlist's `EXT-X-MAP`
/// (draft-pantos-hls-rfc8216bis-22 §4.4.4.5).
pub const INIT_NAME: &str = "init.mp4";

/// The prefix of a Media Segment's name.
const SEGMENT_PREFIX: &str = "seg";

/// The prefix of a Partial Segment's name.
const PART_PREFIX: &str = "part";

/// The extension of a segment's and a part's name: each is fragmented MPEG-4
/// (draft-pantos-hls-rfc8216bis-22 §3.1.2), a movie fragment of its own.
const MEDIA_SUFFIX: &str = ".m4s";

/// One resource of a window, by what names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    /// The init segment (draft-pantos-hls-rfc8216bis-22 §3, the Media
    /// Initialization Section).
    Init,
    /// A Media Segment, by its Media Sequence Number (§3).
    Segment {
        /// Its Media Sequence Number.
        msn: u64,
    },
    /// A Partial Segment (§3.2), by its Parent Segment's Media Sequence
    /// Number and its Part Index.
    Part {
        /// Its Parent Segment's Media Sequence Number.
        msn: u64,
        /// Its Part Index: 0 for the first part of the segment.
        index: u64,
    },
}

impl Resource {
    /// The resource `name` names, the last segment of a request's path; `None`
    /// for anything [`Display`](fmt::Display) does not write exactly.
    pub fn parse(name: &str) -> Option<Self> {
        if name == INIT_NAME {
            return Some(Self::Init);
        }
        if let Some(msn) = name
            .strip_prefix(SEGMENT_PREFIX)
            .and_then(|rest| rest.strip_suffix(MEDIA_SUFFIX))
        {
            return number(msn).map(|msn| Self::Segment { msn });
        }
        let (msn, index) = name
            .strip_prefix(PART_PREFIX)?
            .strip_suffix(MEDIA_SUFFIX)?
            .split_once('.')?;
        Some(Self::Part {
            msn: number(msn)?,
            index: number(index)?,
        })
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => f.write_str(INIT_NAME),
            Self::Segment { msn } => write!(f, "{SEGMENT_PREFIX}{msn}{MEDIA_SUFFIX}"),
            Self::Part { msn, index } => write!(f, "{PART_PREFIX}{msn}.{index}{MEDIA_SUFFIX}"),
        }
    }
}

/// The number `digits` writes the way `Display` writes a `u64`: ASCII digits
/// only, no sign, no leading zero but in `0` itself; `None` otherwise or past
/// `u64::MAX` (which also bounds it to 20 digits).
fn number(digits: &str) -> Option<u64> {
    let canonical = !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && !(digits.len() > 1 && digits.starts_with('0'));
    // All digits: `parse` fails only on overflow.
    canonical.then(|| digits.parse().ok()).flatten()
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
    fn rfc8216bis_4_4_4_5_the_init_segment_is_init_mp4() {
        assert_eq!(Resource::Init.to_string(), "init.mp4");
        assert_eq!(Resource::parse("init.mp4"), Some(Resource::Init));
    }

    #[test]
    fn rfc8216bis_3_a_segment_is_named_by_its_media_sequence_number() {
        assert_eq!(Resource::Segment { msn: 42 }.to_string(), "seg42.m4s");
        assert_eq!(
            Resource::parse("seg42.m4s"),
            Some(Resource::Segment { msn: 42 })
        );
        assert_eq!(
            Resource::parse("seg0.m4s"),
            Some(Resource::Segment { msn: 0 })
        );
    }

    #[test]
    fn rfc8216bis_3_2_a_part_is_named_by_its_parent_s_msn_and_its_part_index() {
        let part = Resource::Part { msn: 7, index: 3 };
        assert_eq!(part.to_string(), "part7.3.m4s");
        assert_eq!(Resource::parse("part7.3.m4s"), Some(part));
        assert_eq!(
            Resource::parse("part0.0.m4s"),
            Some(Resource::Part { msn: 0, index: 0 })
        );
    }

    #[test]
    fn every_name_round_trips_at_the_limits() {
        for resource in [
            Resource::Init,
            Resource::Segment { msn: u64::MAX },
            Resource::Part {
                msn: u64::MAX,
                index: u64::MAX,
            },
            Resource::Part { msn: 10, index: 0 },
        ] {
            assert_eq!(Resource::parse(&resource.to_string()), Some(resource));
        }
    }

    #[test]
    fn a_name_that_is_not_written_exactly_is_refused() {
        for name in [
            "",
            "init.mp4 ",
            "Init.mp4",
            "init.m4s",
            "seg.m4s",
            "seg01.m4s",
            "seg00.m4s",
            "seg+1.m4s",
            "seg-1.m4s",
            "seg 1.m4s",
            "seg1.mp4",
            "seg1",
            "seg1.m4s/",
            "seg18446744073709551616.m4s",
            "seg99999999999999999999999.m4s",
            "seg١.m4s",
            "part1.m4s",
            "part1..m4s",
            "part.1.m4s",
            "part1.01.m4s",
            "part01.1.m4s",
            "part1.1.1.m4s",
            "part1.18446744073709551616.m4s",
            "part1.1.mp4",
            "../seg1.m4s",
            "Seg1.m4s",
        ] {
            assert_eq!(Resource::parse(name), None, "{name:?}");
        }
    }
}

//! The API version, which follows Semantic Versioning 2.0.0 and is separate
//! from the daemon's version.
//!
//! Until lotse 1.0 the API is not stable and its major version is 0. As
//! Cargo reads a 0.x version, a minor bump (0.1 to 0.2) is a breaking
//! change and a patch bump an additive one; from 1.0 on, the major marks a
//! breaking change and the minor an additive one. The WebSocket path
//! carries the major version.

/// The API version in `hello.api` and the schema bundle's `api`.
pub const API_VERSION: &str = "0.1.1";

/// [`API_VERSION`], parsed; a test keeps the two equal.
pub const CURRENT: ApiVersion = ApiVersion {
    major: 0,
    minor: 1,
    patch: 1,
};

/// The WebSocket path: `/v<major>/ws`; a test keeps it on [`CURRENT`]'s major.
pub const WS_PATH: &str = "/v0/ws";

/// A `MAJOR.MINOR.PATCH` version (Semantic Versioning 2.0.0 §2, without pre-release or
/// build metadata, which the API version never carries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVersion {
    /// Breaking changes from 1.0 on.
    pub major: u64,
    /// Breaking changes while the major is 0, additive ones after.
    pub minor: u64,
    /// Additive changes while the major is 0, fixes after.
    pub patch: u64,
}

impl ApiVersion {
    /// Parses `MAJOR.MINOR.PATCH`: three non-negative integers without
    /// leading zeros (Semantic Versioning 2.0.0 §2); anything else is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.');
        let version = Self {
            major: number(parts.next()?)?,
            minor: number(parts.next()?)?,
            patch: number(parts.next()?)?,
        };
        parts.next().is_none().then_some(version)
    }

    /// Whether a client built for `self` can use a daemon speaking
    /// `daemon`: the same major, the same minor while the major is 0 (a
    /// 0.x minor is breaking), and the daemon not older, so every command
    /// and field the client knows exists.
    pub fn accepts(self, daemon: Self) -> bool {
        daemon.major == self.major
            && (self.major != 0 || daemon.minor == self.minor)
            && daemon >= self
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One numeric identifier: ASCII digits, no leading zero unless it is `0`.
fn number(part: &str) -> Option<u64> {
    let digits = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let canonical = part == "0" || !part.starts_with('0');
    if digits && canonical {
        part.parse().ok()
    } else {
        None
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

    const fn v(major: u64, minor: u64, patch: u64) -> ApiVersion {
        ApiVersion {
            major,
            minor,
            patch,
        }
    }

    #[test]
    fn the_constants_agree_and_stay_below_1_0() {
        assert_eq!(ApiVersion::parse(API_VERSION), Some(CURRENT));
        assert_eq!(CURRENT.to_string(), API_VERSION);
        assert_eq!(WS_PATH, format!("/v{}/ws", CURRENT.major));
        // 0.1.1: two-way audio (`backchannel` in `session/get` and
        // `stream/get`, `talker_changed`, `backchannel/release`).
        assert_eq!(CURRENT, v(0, 1, 1), "unstable until lotse 1.0");
    }

    #[test]
    fn semver_2_0_0_section_2_versions_parse_and_others_do_not() {
        assert_eq!(ApiVersion::parse("0.1.0"), Some(v(0, 1, 0)));
        assert_eq!(ApiVersion::parse("10.20.30"), Some(v(10, 20, 30)));
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.x",
            "a.b.c",
            "1..3",
            "-1.2.3",
            "+1.2.3",
            "1.2.3-rc.1",
            "1.2.3+build",
            " 1.2.3",
            "1.2.3 ",
            "99999999999999999999.0.0",
        ] {
            assert_eq!(ApiVersion::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_0_x_client_accepts_the_same_minor_at_the_same_or_a_later_patch() {
        let client = v(0, 1, 2);
        assert!(client.accepts(v(0, 1, 2)));
        assert!(client.accepts(v(0, 1, 9)), "a later patch only adds");
        assert!(
            !client.accepts(v(0, 1, 1)),
            "an older daemon lacks what the client knows"
        );
        assert!(!client.accepts(v(0, 2, 2)), "a 0.x minor is breaking");
        assert!(!client.accepts(v(0, 0, 9)));
        assert!(!client.accepts(v(1, 1, 2)), "another major is breaking");
    }

    #[test]
    fn a_stable_client_accepts_the_same_major_at_the_same_or_a_later_minor() {
        let client = v(1, 2, 3);
        assert!(client.accepts(v(1, 2, 3)));
        assert!(client.accepts(v(1, 2, 4)));
        assert!(client.accepts(v(1, 5, 0)), "a later minor only adds");
        assert!(!client.accepts(v(1, 2, 2)));
        assert!(!client.accepts(v(1, 1, 9)));
        assert!(!client.accepts(v(2, 2, 3)));
        assert!(!client.accepts(v(0, 2, 3)));
    }
}

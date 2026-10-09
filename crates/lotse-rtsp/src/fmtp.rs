//! The one format parameter the source reads from the camera's SDP itself:
//! RFC 7798 §7.1 `sprop-max-don-diff` of an H.265 format, which says
//! whether its payloads carry decoding order numbers (DONL, DOND) that the
//! `lotse-codec` normalizers do not read.
//! retina 0.4.20 reads an H.265 `fmtp` for its own depacketizer, which the
//! source bypasses, and exposes only the parameter sets, so the raw SDP
//! of the `DESCRIBE` answer is scanned here.
//!
//! Implements RFC 8866 §5.14 (`m=` lines start a media description), §6.6
//! (`rtpmap`) and §6.15 (`fmtp`), and RFC 7798 §4.4.1 (DONL present when
//! `sprop-max-don-diff` is above 0 for any of the RTP streams) and §7.1
//! (`sprop-max-don-diff`, an integer from 0 to 32767, 0 when absent).

/// RFC 7798 §7.1: the name of the parameter. Media type parameter names
/// are case-insensitive (RFC 6838 §4.3).
const SPROP_MAX_DON_DIFF: &str = "sprop-max-don-diff";

/// RFC 7798 §7.1: "The value of sprop-max-don-diff MUST be an integer in
/// the range of 0 to 32767, inclusive."
const MAX_DON_DIFF: u16 = 32_767;

/// The encoding name of an H.265 format in an `rtpmap` (RFC 7798 §7.1),
/// compared without case as RFC 8866 §6.6 encoding names are.
const H265: &str = "H265";

/// An H.265 format declares a `sprop-max-don-diff` that is not an integer
/// from 0 to [`MAX_DON_DIFF`] (RFC 7798 §7.1), so whether its payloads
/// carry decoding order numbers is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MalformedDonDiff;

/// The largest `sprop-max-don-diff` of any H.265 format in `sdp`, 0 when
/// none declares one. RFC 7798 §4.4.1 makes DONL present in every stream
/// of an H.265 bitstream once any of its streams declares a value above
/// 0, and the camera's streams cannot be told apart from retina's list
/// with certainty, so every H.265 format counts. Lines are split as
/// sdp-types splits them (at LF, a trailing CR dropped); one that is not
/// UTF-8 or not an `m=`, `a=rtpmap:` or `a=fmtp:` line is skipped.
pub(crate) fn h265_max_don_diff(sdp: &[u8]) -> Result<u16, MalformedDonDiff> {
    let mut largest = 0;
    // The current media description's `rtpmap`s (payload type, encoding)
    // and `fmtp`s (payload type, parameters): payload type numbers are
    // mapped per media description (RFC 8866 §6.6).
    let mut rtpmaps: Vec<(&str, &str)> = Vec::new();
    let mut fmtps: Vec<(&str, &str)> = Vec::new();
    for line in sdp.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        if line.starts_with("m=") {
            largest = largest.max(section(&rtpmaps, &fmtps)?);
            rtpmaps.clear();
            fmtps.clear();
        } else if let Some((pt, value)) = line
            .strip_prefix("a=rtpmap:")
            .and_then(|value| value.split_once(' '))
        {
            rtpmaps.push((pt, value.split('/').next().unwrap_or_default().trim()));
        } else if let Some((pt, value)) = line
            .strip_prefix("a=fmtp:")
            .and_then(|value| value.split_once(' '))
        {
            fmtps.push((pt, value));
        }
    }
    Ok(largest.max(section(&rtpmaps, &fmtps)?))
}

/// The largest `sprop-max-don-diff` of the `fmtp`s of one media
/// description whose payload type its `rtpmap`s name H.265.
fn section(rtpmaps: &[(&str, &str)], fmtps: &[(&str, &str)]) -> Result<u16, MalformedDonDiff> {
    let mut largest = 0;
    for (pt, parameters) in fmtps {
        let h265 = rtpmaps
            .iter()
            .any(|(mapped, encoding)| mapped == pt && encoding.eq_ignore_ascii_case(H265));
        if h265 {
            largest = largest.max(max_don_diff(parameters)?);
        }
    }
    Ok(largest)
}

/// RFC 7798 §7.1 `sprop-max-don-diff` of one format's parameters
/// (`key=value` pairs separated by `;`), 0 when absent; the largest if the
/// camera repeats it.
fn max_don_diff(parameters: &str) -> Result<u16, MalformedDonDiff> {
    let mut largest = 0;
    for parameter in parameters.split(';') {
        let Some((key, value)) = parameter.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case(SPROP_MAX_DON_DIFF) {
            continue;
        }
        let diff = value
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|diff| *diff <= MAX_DON_DIFF)
            .ok_or(MalformedDonDiff)?;
        largest = largest.max(diff);
    }
    Ok(largest)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    /// An H.265 description with `extra` appended to its `fmtp`.
    fn h265(extra: &str) -> String {
        format!(
            "v=0\r\ns=-\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n\
             a=fmtp:96 profile-id=1;sprop-vps=QAE=;sprop-sps=QgE=;sprop-pps=RAE={extra}\r\n\
             a=control:track0\r\n"
        )
    }

    #[test]
    fn rfc7798_7_1_an_absent_sprop_max_don_diff_is_0() {
        assert_eq!(h265_max_don_diff(h265("").as_bytes()), Ok(0));
        assert_eq!(h265_max_don_diff(b""), Ok(0));
        // An fmtp without parameters, as Ubiquiti cameras send it.
        assert_eq!(
            h265_max_don_diff(b"m=video 0 RTP/AVP 96\na=rtpmap:96 H265/90000\na=fmtp:96\n"),
            Ok(0)
        );
    }

    #[test]
    fn rfc7798_7_1_sprop_max_don_diff_is_read_from_an_h265_fmtp() {
        for (extra, diff) in [
            (";sprop-max-don-diff=0", 0),
            (";sprop-max-don-diff=2;sprop-depack-buf-nalus=2", 2),
            ("; SPROP-MAX-DON-DIFF = 7 ", 7),
            (";sprop-max-don-diff=32767", 32_767),
            (";sprop-max-don-diff=3;sprop-max-don-diff=1", 3),
            (";sprop-max-don-diff=1;sprop-max-don-diff=3", 3),
            (";garbage;sprop-max-don-diff=4", 4),
        ] {
            assert_eq!(
                h265_max_don_diff(h265(extra).as_bytes()),
                Ok(diff),
                "{extra}"
            );
        }
        // LF line ends, lower-case encoding name.
        assert_eq!(
            h265_max_don_diff(
                b"m=video 0 RTP/AVP 96\na=rtpmap:96 h265/90000\na=fmtp:96 sprop-max-don-diff=5\n"
            ),
            Ok(5)
        );
    }

    #[test]
    fn rfc7798_7_1_a_sprop_max_don_diff_out_of_its_range_is_malformed() {
        for extra in [
            ";sprop-max-don-diff=",
            ";sprop-max-don-diff=abc",
            ";sprop-max-don-diff=-1",
            ";sprop-max-don-diff=32768",
            ";sprop-max-don-diff=65536",
            ";sprop-max-don-diff=1.5",
            ";sprop-max-don-diff=0;sprop-max-don-diff=x",
        ] {
            assert_eq!(
                h265_max_don_diff(h265(extra).as_bytes()),
                Err(MalformedDonDiff),
                "{extra}"
            );
        }
    }

    #[test]
    fn rfc7798_4_4_1_any_h265_format_of_the_description_counts() {
        // The H.265 format is the second description's; the first is
        // H.264 and its fmtp is not read.
        let sdp = "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
                   a=fmtp:96 sprop-max-don-diff=x\r\n\
                   m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n\
                   a=fmtp:96 sprop-max-don-diff=9\r\n\
                   m=audio 0 RTP/AVP 0\r\n";
        assert_eq!(h265_max_don_diff(sdp.as_bytes()), Ok(9));
        // A second payload type of one description.
        let sdp = "m=video 0 RTP/AVP 96 97\r\na=rtpmap:96 H264/90000\r\n\
                   a=rtpmap:97 H265/90000\r\na=fmtp:96 sprop-max-don-diff=x\r\n\
                   a=fmtp:97 sprop-max-don-diff=6\r\n";
        assert_eq!(h265_max_don_diff(sdp.as_bytes()), Ok(6));
        // The larger of two H.265 descriptions, either order.
        let two = |a: u16, b: u16| {
            format!(
                "m=video 0 RTP/AVP 96\na=rtpmap:96 H265/90000\na=fmtp:96 sprop-max-don-diff={a}\n\
                 m=video 0 RTP/AVP 96\na=rtpmap:96 H265/90000\na=fmtp:96 sprop-max-don-diff={b}\n"
            )
        };
        assert_eq!(h265_max_don_diff(two(8, 2).as_bytes()), Ok(8));
        assert_eq!(h265_max_don_diff(two(2, 8).as_bytes()), Ok(8));
        // A malformed value in the first description is found too.
        let sdp = "m=video 0 RTP/AVP 96\na=rtpmap:96 H265/90000\na=fmtp:96 sprop-max-don-diff=x\n\
                   m=audio 0 RTP/AVP 0\n";
        assert_eq!(h265_max_don_diff(sdp.as_bytes()), Err(MalformedDonDiff));
    }

    #[test]
    fn rfc8866_6_6_payload_types_map_per_media_description() {
        // The rtpmap naming 96 H.265 belongs to the first description;
        // the second's 96 has none and is not H.265.
        let sdp = "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n\
                   m=video 0 RTP/AVP 96\r\na=fmtp:96 sprop-max-don-diff=3\r\n";
        assert_eq!(h265_max_don_diff(sdp.as_bytes()), Ok(0));
        // An fmtp of another payload type, a non-UTF-8 line and lines
        // that are neither rtpmap nor fmtp are not read.
        let sdp = b"m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n\
                    a=fmtp:97 sprop-max-don-diff=3\r\n\
                    a=fmtp:96 \xff sprop-max-don-diff=3\r\na=rtpmap:96\r\n\
                    a=control:sprop-max-don-diff=3\r\n";
        assert_eq!(h265_max_don_diff(sdp), Ok(0));
    }
}

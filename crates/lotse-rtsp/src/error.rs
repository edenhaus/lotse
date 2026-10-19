//! How a retina error becomes a [`SourceError`]: the RTSP status and
//! method stay in the message, the kind follows what went wrong. The
//! message is scrubbed of the source URL's path and query, which retina
//! may echo, before it is cut: a path cut partway through no longer
//! matches the scrub.
//!
//! The camera's own text, which retina's messages quote (a header, an
//! SDP line), reaches the log and the API's error only through
//! `camera_text`: one line, no control characters, at most
//! `CAMERA_TEXT_BYTES`, ending in `CUT_MARK` where it was cut.
//!
//! RFC 2326 §7.1.1: 401 and 403 are the credential failures.

use lotse_core::source::SourceError;
use lotse_core::source_url::SourceUrl;

/// The most bytes of a camera's text an error message or a log line
/// carries: a header value or a reason is a sentence, and a camera's
/// message may be 64 KiB of anything.
pub(crate) const CAMERA_TEXT_BYTES: usize = 200;

/// A camera's `text` as an error or a log line carries it: on one line,
/// control characters replaced, cut to [`CAMERA_TEXT_BYTES`]; cut text
/// ends in [`CUT_MARK`](lotse_core::text::CUT_MARK) within them.
pub(crate) fn camera_text(text: &str) -> String {
    lotse_core::text::plain(text, CAMERA_TEXT_BYTES)
}

/// Classifies a retina error of the session for `url`. retina keeps its
/// variants private, so the status code (public) and the message text
/// (stable prefixes per variant) decide.
pub fn classify(error: &retina::Error, url: &SourceUrl) -> SourceError {
    classify_text(&error.to_string(), error.status_code(), url)
}

/// [`classify`] on a retina error's `text` and RTSP `status`: its first
/// line, scrubbed of `url` ([`RedactedUrl::scrub`]), then as
/// [`camera_text`], is the message. The kind follows the line as retina
/// wrote it: scrubbed, a query that happens to occur in a prefix (`t` in
/// `Timeout`) would change it.
///
/// [`RedactedUrl::scrub`]: lotse_core::secret::RedactedUrl::scrub
fn classify_text(text: &str, status: Option<u16>, url: &SourceUrl) -> SourceError {
    let line = first_line(text);
    let message = camera_text(&url.redacted().scrub(line));
    if let Some(status) = status {
        return match status {
            401 | 403 => SourceError::AuthFailed(message),
            _ => SourceError::Protocol(message),
        };
    }
    if line.starts_with("Unable to connect") {
        SourceError::Unreachable(message)
    } else if line.starts_with("Timeout") {
        SourceError::Timeout(message)
    } else if line.starts_with("Error reading from RTSP peer")
        || line.starts_with("Error writing to RTSP peer")
        || line.starts_with("Error receiving UDP packet")
    {
        SourceError::Ended(message)
    } else {
        SourceError::Protocol(message)
    }
}

/// retina appends connection and message context on further lines; the
/// first line is the error.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::text::CUT_MARK;

    use super::*;

    /// A source URL with nothing to scrub.
    fn cam() -> SourceUrl {
        SourceUrl::parse("rtsp://cam/").unwrap()
    }

    /// retina names the URL it was given in an `InvalidArgument`; the
    /// relay URL it is given carries the source URL's path and query,
    /// which the attempt's scrub removes.
    #[tokio::test]
    async fn a_url_retina_echoes_loses_its_path_and_query() {
        let url =
            SourceUrl::parse("rtsp://admin:pw5b1c@cam/camkey7f3a/live?token=tok9d2e").unwrap();
        let mut target = url.expose_url().clone();
        target.set_scheme("rtspx").unwrap();
        let err =
            retina::client::Session::describe(target, retina::client::SessionOptions::default())
                .await
                .err()
                .expect("retina refuses a scheme other than rtsp");
        assert!(
            err.to_string().contains("camkey7f3a"),
            "retina echoes: {err}"
        );
        assert_eq!(
            classify(&err, &url),
            SourceError::Protocol(
                "Invalid argument: Bad URL rtspx://cam/****?**** only scheme rtsp supported".into()
            )
        );
    }

    #[test]
    fn camera_text_is_one_line_of_at_most_200_bytes() {
        assert_eq!(camera_text("a\r\nb\u{1b}[2J"), "a  b\u{fffd}[2J");
        let long = "é".repeat(CAMERA_TEXT_BYTES);
        let room = CAMERA_TEXT_BYTES - CUT_MARK.len();
        let capped = camera_text(&long);
        assert_eq!(capped, format!("{}{CUT_MARK}", "é".repeat(room / 2)));
        assert_eq!(capped.len(), CAMERA_TEXT_BYTES - 1, "é does not fit whole");
        let capped = camera_text(&format!("x{long}"));
        assert_eq!(capped, format!("x{}{CUT_MARK}", "é".repeat((room - 1) / 2)));
        assert_eq!(capped.len(), CAMERA_TEXT_BYTES);
    }

    #[test]
    fn a_camera_s_text_in_retina_s_error_reaches_the_message_capped_on_one_line() {
        let quoted = format!("{:?}", format!("x\r\n{}", "y".repeat(64 * 1024)));
        let text = format!("Unparseable Session header {quoted}\n\nconn: 127.0.0.1:1");
        let err = classify_text(&text, None, &cam());
        assert!(
            matches!(&err, SourceError::Protocol(m) if m.len() == CAMERA_TEXT_BYTES
                && m.starts_with(r#"Unparseable Session header "x\r\nyyy"#)
                && m.ends_with(&format!("y{CUT_MARK}"))),
            "{err:?}"
        );
        assert_eq!(
            classify_text("401\u{1b}[2J\nmore", Some(401), &cam()),
            SourceError::AuthFailed("401\u{fffd}[2J".into())
        );
        assert!(matches!(
            classify_text("Unable to connect\r to x", None, &cam()),
            SourceError::Unreachable(m) if m == "Unable to connect  to x"
        ));
        assert!(matches!(
            classify_text("Timeout", None, &cam()),
            SourceError::Timeout(_)
        ));
        assert!(matches!(
            classify_text("Error receiving UDP packet", None, &cam()),
            SourceError::Ended(_)
        ));
        assert!(matches!(
            classify_text("x", Some(404), &cam()),
            SourceError::Protocol(_)
        ));
    }

    /// A camera that echoes the path without a scheme, where the message
    /// is cut: scrubbed after the cut, the path's first bytes would show.
    /// The scrubbed path's start fills the cap up to the cut mark.
    #[test]
    fn a_path_echoed_where_the_message_is_cut_is_scrubbed_before_the_cut() {
        let url = SourceUrl::parse("rtsp://cam/camkey7f3a/live?token=tok9d2e").unwrap();
        let lead = "x".repeat(CAMERA_TEXT_BYTES - 18 - CUT_MARK.len());
        let text = format!("Bad request {lead} /camkey7f3a/live?token=tok9d2e");
        let cut = format!("Bad request {lead} /****{CUT_MARK}");
        assert_eq!(cut.len(), CAMERA_TEXT_BYTES);
        assert_eq!(
            classify_text(&text, Some(400), &url),
            SourceError::Protocol(cut)
        );
    }

    /// A query that occurs in a kind's prefix is scrubbed out of the
    /// message, not out of the classification.
    #[test]
    fn a_query_echoed_in_a_kinds_prefix_keeps_the_kind() {
        let url = SourceUrl::parse("rtsp://cam/live?t").unwrap();
        assert_eq!(
            classify_text("Timeout", None, &url),
            SourceError::Timeout("Timeou****".into())
        );
        let url = SourceUrl::parse("rtsp://cam/live?connect").unwrap();
        assert_eq!(
            classify_text("Unable to connect to cam", None, &url),
            SourceError::Unreachable("Unable to **** to cam".into())
        );
        let url = SourceUrl::parse("rtsp://cam/live?Error").unwrap();
        assert_eq!(
            classify_text("Error reading from RTSP peer", None, &url),
            SourceError::Ended("**** reading from RTSP peer".into())
        );
    }

    #[test]
    fn first_lines_are_kept() {
        assert_eq!(first_line("Timeout\n\nconn: x"), "Timeout");
        assert_eq!(first_line(""), "");
    }
}

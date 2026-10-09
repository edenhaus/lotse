//! How a retina error becomes a [`SourceError`]: the RTSP status and
//! method stay in the message, the kind follows what went wrong.
//!
//! The camera's own text, which retina's messages quote (a header, an
//! SDP line), reaches the log and the API's error only through
//! `camera_text`: one line, no control characters, at most
//! `CAMERA_TEXT_BYTES`.
//!
//! RFC 2326 §7.1.1: 401 and 403 are the credential failures.

use lotse_core::source::SourceError;

/// The most bytes of a camera's text an error message or a log line
/// carries: a header value or a reason is a sentence, and a camera's
/// message may be 64 KiB of anything.
pub(crate) const CAMERA_TEXT_BYTES: usize = 200;

/// A camera's `text` as an error or a log line carries it: on one line,
/// control characters replaced, cut to [`CAMERA_TEXT_BYTES`].
pub(crate) fn camera_text(text: &str) -> String {
    lotse_core::text::plain(text, CAMERA_TEXT_BYTES)
}

/// Classifies a retina error. retina keeps its variants private, so the
/// status code (public) and the message text (stable prefixes per
/// variant) decide.
pub fn classify(error: &retina::Error) -> SourceError {
    classify_text(&error.to_string(), error.status_code())
}

/// [`classify`] on a retina error's `text` and RTSP `status`: its first
/// line, as [`camera_text`], is the message.
fn classify_text(text: &str, status: Option<u16>) -> SourceError {
    let message = camera_text(first_line(text));
    if let Some(status) = status {
        return match status {
            401 | 403 => SourceError::AuthFailed(message),
            _ => SourceError::Protocol(message),
        };
    }
    if message.starts_with("Unable to connect") {
        SourceError::Unreachable(message)
    } else if message.starts_with("Timeout") {
        SourceError::Timeout(message)
    } else if message.starts_with("Error reading from RTSP peer")
        || message.starts_with("Error writing to RTSP peer")
        || message.starts_with("Error receiving UDP packet")
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

    use super::*;

    #[test]
    fn camera_text_is_one_line_of_at_most_200_bytes() {
        assert_eq!(camera_text("a\r\nb\u{1b}[2J"), "a  b\u{fffd}[2J");
        let long = "é".repeat(CAMERA_TEXT_BYTES);
        assert_eq!(camera_text(&long).len(), CAMERA_TEXT_BYTES);
        assert_eq!(
            camera_text(&format!("x{long}")).len(),
            CAMERA_TEXT_BYTES - 1
        );
    }

    #[test]
    fn a_camera_s_text_in_retina_s_error_reaches_the_message_capped_on_one_line() {
        let quoted = format!("{:?}", format!("x\r\n{}", "y".repeat(64 * 1024)));
        let text = format!("Unparseable Session header {quoted}\n\nconn: 127.0.0.1:1");
        let err = classify_text(&text, None);
        assert!(
            matches!(&err, SourceError::Protocol(m) if m.len() == CAMERA_TEXT_BYTES
                && m.starts_with(r#"Unparseable Session header "x\r\nyyy"#)),
            "{err:?}"
        );
        assert_eq!(
            classify_text("401\u{1b}[2J\nmore", Some(401)),
            SourceError::AuthFailed("401\u{fffd}[2J".into())
        );
        assert!(matches!(
            classify_text("Unable to connect\r to x", None),
            SourceError::Unreachable(m) if m == "Unable to connect  to x"
        ));
        assert!(matches!(
            classify_text("Timeout", None),
            SourceError::Timeout(_)
        ));
        assert!(matches!(
            classify_text("Error receiving UDP packet", None),
            SourceError::Ended(_)
        ));
        assert!(matches!(
            classify_text("x", Some(404)),
            SourceError::Protocol(_)
        ));
    }

    #[test]
    fn first_lines_are_kept() {
        assert_eq!(first_line("Timeout\n\nconn: x"), "Timeout");
        assert_eq!(first_line(""), "");
    }
}

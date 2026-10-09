//! Text from outside the daemon on its way into a log line or an error
//! message: a camera's header or SDP value, a worker's message. [`plain`]
//! puts it on one line without control characters and caps it, so its
//! sender can neither forge log lines nor make a line or an API error
//! carry more than a sentence.

/// `text` on one line and cut to at most `max` bytes on a character
/// boundary: a tab, CR or LF becomes a space, any other control character
/// U+FFFD.
pub fn plain(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max));
    for c in text.chars() {
        let c = match c {
            '\t' | '\n' | '\r' => ' ',
            c if c.is_control() => char::REPLACEMENT_CHARACTER,
            c => c,
        };
        if out.len().saturating_add(c.len_utf8()) > max {
            break;
        }
        out.push(c);
    }
    out
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
    fn plain_text_is_capped_on_a_char_boundary_without_controls() {
        assert_eq!(plain("a sentence.", 512), "a sentence.");
        assert_eq!(plain("abc", 3), "abc", "at the cap");
        assert_eq!(plain("abcd", 3), "abc");
        assert_eq!(plain("aé", 2), "a", "é does not fit whole");
        assert_eq!(plain("aé", 3), "aé");
        assert_eq!(
            plain("ok\n2026-10-09 INFO forged\u{1b}[2J\t\r\0\u{85}\u{7f}", 64),
            "ok 2026-10-09 INFO forged\u{fffd}[2J  \u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(plain("a\0b", 3), "a", "a replacement takes three bytes");
        assert_eq!(plain("a\0b", 4), "a\u{fffd}");
        let long = "x".repeat(200 * 1024);
        assert_eq!(plain(&long, 512).len(), 512);
        assert_eq!(plain("", 0), "");
    }
}

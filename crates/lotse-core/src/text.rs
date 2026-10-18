//! Text from outside the daemon on its way into a log line or an error
//! message: a camera's header or SDP value, a worker's message. [`plain`]
//! puts it on one line without control characters and caps it, so its
//! sender can neither forge log lines nor make a line or an API error
//! carry more than a sentence. Text that was cut ends in [`CUT_MARK`], so
//! a reader can tell it from text that happened to be that short.

/// What ends text [`plain`] cut: ASCII, so it reads the same in any log
/// and in JSON.
pub const CUT_MARK: &str = "...";

/// `text` on one line and cut to at most `max` bytes on a character
/// boundary: a tab, CR or LF becomes a space, any other control character
/// U+FFFD. Cut text ends in [`CUT_MARK`] within the `max` bytes, unless
/// `max` leaves no room for it.
pub fn plain(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max));
    let mut cut = false;
    for c in text.chars() {
        let c = match c {
            '\t' | '\n' | '\r' => ' ',
            c if c.is_control() => char::REPLACEMENT_CHARACTER,
            c => c,
        };
        if out.len().saturating_add(c.len_utf8()) > max {
            cut = true;
            break;
        }
        out.push(c);
    }
    if cut && max >= CUT_MARK.len() {
        while out.len().saturating_add(CUT_MARK.len()) > max {
            out.pop();
        }
        out.push_str(CUT_MARK);
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
        assert_eq!(plain("abcd", 3), "...", "cut, the mark fills the cap");
        assert_eq!(plain("abcde", 4), "a...");
        assert_eq!(plain("abcd", 2), "ab", "no room for the mark");
        assert_eq!(plain("aé", 2), "a", "é does not fit whole");
        assert_eq!(plain("aé", 3), "aé");
        assert_eq!(
            plain("aééé", 6),
            "aé...",
            "the mark ends on a char boundary"
        );
        assert_eq!(plain("aééé", 5), "a...", "é makes room for the mark whole");
        assert_eq!(
            plain("ok\n2026-10-09 INFO forged\u{1b}[2J\t\r\0\u{85}\u{7f}", 64),
            "ok 2026-10-09 INFO forged\u{fffd}[2J  \u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(plain("a\0b", 3), "...", "a replacement takes three bytes");
        assert_eq!(plain("a\0b", 4), "a...");
        assert_eq!(plain("a\0", 4), "a\u{fffd}", "not cut: no mark");
        let long = "x".repeat(200 * 1024);
        let capped = plain(&long, 512);
        assert_eq!(capped.len(), 512);
        assert!(capped.ends_with(CUT_MARK), "{capped}");
        assert_eq!(plain("", 0), "");
    }
}

//! retina's log lines, as the daemon lets them out: throttled per call
//! site, scrubbed and capped, and without retina's spans.
//!
//! retina logs through `tracing`, and much of what it logs is the camera's
//! text: a `SETUP` answer's head (`{:#?}`), the whole SDP of a `DESCRIBE`
//! answer with a stream it cannot parse, a request the camera sent while
//! playing, the `RTP-Info` header. All of it is untrusted, however retina
//! formats it: uncapped, on many lines, and once per request or packet the
//! camera chooses to send. And retina names URLs in it: the URL of each
//! request (on its `rtsp_request` and `rtsp_teardown` spans, in `url`
//! fields), and the camera's own (`RTP-Info`, `a=control`, `Content-Base`).
//! The URL retina is given is the source URL with the address of the
//! crate's loopback relay for its host: the credentials are gone, but the
//! path and query stay, which may hold a camera key or a token and which
//! lotse logs only redacted (`lotse_core::secret::RedactedUrl`), and the
//! camera echoes them.
//!
//! So [`RetinaLog`] wraps the layer that writes the lines and stands
//! between it and every event of a `retina` target ([`is_retina`]):
//!
//! - each call site is throttled as the daemon throttles the `log` records
//!   of other crates ([`CallSites`]): the first event, then at most one
//!   per summary interval with the count;
//! - an event that passes is written as an event of its own, at its level,
//!   with the target [`TARGET`] (which no `retina` filter matches, so it
//!   is never taken for one of retina's) and the original target in its
//!   `retina` field; its message and every field value, `name=value`
//!   after it, go through [`retina_text`]: cut to its first line, which
//!   drops what retina dumps of the camera's protocol after a line break
//!   (the SDP, a request, a response head, buffered bytes) with whatever
//!   URLs it holds, relative ones too; each `rtsp://` and
//!   `rtsps://` URL cut to scheme, host and port ([`scrub_urls`]); then
//!   control characters replaced and capped like any camera text;
//! - the fields named `url`, `rtp_info` and `value` are dropped outright.
//!
//! retina's spans carry the request URL in their fields, which every event
//! inside them would print: [`no_retina_spans`], a global filter, keeps
//! them from being created. The events inside are logged as any other.
//!
//! The event written is handed to the wrapped layer directly, never
//! dispatched again: a dispatch from inside a dispatch reaches no
//! subscriber while any scoped one is set, and could loop otherwise.

use std::fmt::{self, Write as _};
use std::sync::Arc;

use lotse_core::clock::Clock;
use lotse_core::throttle::{CallSites, summary};
use tracing_core::callsite::{DefaultCallsite, Identifier};
use tracing_core::field::{Field, FieldSet, Value, Visit};
use tracing_core::metadata::Kind;
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::error::camera_text;

/// The target of the events [`RetinaLog`] writes for retina's: not a
/// `retina` one, so they are never taken for retina's own.
pub const TARGET: &str = "lotse_rtsp::retina";

/// The fields of an event written for one of retina's: the scrubbed text,
/// and the target retina logged it with.
const FIELDS: &[&str] = &["message", "retina"];

/// The fields of retina's events that are dropped outright: they hold a
/// URL (the request's) or a header that names one (`RTP-Info`), or one
/// [`scrub_urls`] cannot find: retina (edenhaus/retina `f65065f`,
/// `src/client/parse.rs`, read 2026-11-04) logs a `Content-Base` or
/// `Content-Location` header without a scheme, which it repaired, as
/// the `value` of its warning, path and query as the camera sent them.
/// The `value` of an invalid `fmtp` attribute, its one other, goes too.
const DROPPED: [&str; 3] = ["url", "rtp_info", "value"];

/// The schemes [`scrub_urls`] finds, lowercase; a URL's scheme is
/// case-insensitive (RFC 3986 §3.1).
const SCHEMES: [&str; 2] = ["rtsps://", "rtsp://"];

/// What [`scrub_urls`] puts for a URL's userinfo and for its path, query
/// and fragment, as `RedactedUrl` does.
const REDACTED: &str = "****";

/// The metadata and callsite of the events written at one level.
macro_rules! callsite {
    ($(#[$doc:meta])* $meta:ident, $callsite:ident, $level:expr) => {
        $(#[$doc])*
        static $meta: Metadata<'static> = Metadata::new(
            "retina",
            TARGET,
            $level,
            None,
            None,
            Some(module_path!()),
            FieldSet::new(FIELDS, Identifier(&$callsite)),
            Kind::EVENT,
        );
        $(#[$doc])*
        static $callsite: DefaultCallsite = DefaultCallsite::new(&$meta);
    };
}

callsite!(
    /// An `ERROR` event written for one of retina's.
    ERROR_META,
    ERROR_CALLSITE,
    Level::ERROR
);
callsite!(
    /// A `WARN` event written for one of retina's.
    WARN_META,
    WARN_CALLSITE,
    Level::WARN
);
callsite!(
    /// An `INFO` event written for one of retina's.
    INFO_META,
    INFO_CALLSITE,
    Level::INFO
);
callsite!(
    /// A `DEBUG` event written for one of retina's.
    DEBUG_META,
    DEBUG_CALLSITE,
    Level::DEBUG
);
callsite!(
    /// A `TRACE` event written for one of retina's.
    TRACE_META,
    TRACE_CALLSITE,
    Level::TRACE
);

/// The metadata of the events written at `level`.
fn metadata(level: Level) -> &'static Metadata<'static> {
    match level {
        Level::ERROR => &ERROR_META,
        Level::WARN => &WARN_META,
        Level::INFO => &INFO_META,
        Level::DEBUG => &DEBUG_META,
        _ => &TRACE_META,
    }
}

/// Whether `metadata` is retina's: its target is `retina` or within it.
pub fn is_retina(metadata: &Metadata<'_>) -> bool {
    let target = metadata.target();
    target == "retina" || target.starts_with("retina::")
}

/// The global filter that keeps retina's spans from being created: they
/// carry the request's URL, which every event inside would print. True
/// for everything else.
pub fn no_retina_spans(metadata: &Metadata<'_>) -> bool {
    !(metadata.is_span() && is_retina(metadata))
}

/// `text` with every `rtsp://` and `rtsps://` URL in it (the scheme in any
/// case) cut to its scheme, host and port: a userinfo becomes `****@`,
/// and whatever follows the host `/****`. A URL runs to the first
/// whitespace or control character, which no URL holds (RFC 3986 §2), so
/// whatever text follows it within that goes with the path: another
/// `RTP-Info` entry, a `;seq=`, the quote or bracket that closes a quoted
/// URL. Any other character is no sure end: an apostrophe is a
/// sub-delimiter (§2.2), and a URL as retina prints it may hold a `|` or
/// a `{` its writer left unescaped. Its authority ends at the first `/`,
/// `?` or `#` (§3.2), its host follows the last `@` before that, and its
/// host and port run as far as the characters they hold (§3.2.2, §3.2.3):
/// what follows them (a closing quote) goes with the path.
pub fn scrub_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((start, scheme_len)) = next_url(rest) {
        let (before, from) = rest.split_at_checked(start).unwrap_or((rest, ""));
        let (scheme, after) = from.split_at_checked(scheme_len).unwrap_or((from, ""));
        let end = after.find(ends_url).unwrap_or(after.len());
        let (url, tail) = after.split_at_checked(end).unwrap_or((after, ""));
        out.push_str(before);
        out.push_str(scheme);
        let path_at = url.find(['/', '?', '#']).unwrap_or(url.len());
        let (authority, path) = url.split_at_checked(path_at).unwrap_or((url, ""));
        let host = match authority.rsplit_once('@') {
            Some((_, host)) => {
                out.push_str(REDACTED);
                out.push('@');
                host
            }
            None => authority,
        };
        let host_end = host.find(|c| !in_host(c)).unwrap_or(host.len());
        let (host, after_host) = host.split_at_checked(host_end).unwrap_or((host, ""));
        out.push_str(host);
        if !path.is_empty() || !after_host.is_empty() {
            out.push('/');
            out.push_str(REDACTED);
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Where the first `rtsp://` or `rtsps://` in `text` starts, in any case,
/// and the length of that scheme with its `://`.
fn next_url(text: &str) -> Option<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    SCHEMES
        .iter()
        .filter_map(|scheme| lower.find(scheme).map(|at| (at, scheme.len())))
        .min()
}

/// Whether `c` ends a URL in text: whitespace or a control character,
/// which no URL holds (RFC 3986 §2).
fn ends_url(c: char) -> bool {
    c.is_whitespace() || c.is_control()
}

/// Whether `c` is one a host and its port hold: unreserved, a
/// sub-delimiter, a `%` of an escape (a reg-name, RFC 3986 §3.2.2), the
/// `[`, `]` and `:` of an IP literal, and the `:` before the port
/// (§3.2.3).
fn in_host(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.'
                | '_'
                | '~'
                | '%'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
                | ':'
                | '['
                | ']'
        )
}

/// The first line of `text`, to its first CR or LF. retina writes what it
/// dumps of the camera's protocol after a line break (edenhaus/retina
/// `f65065f`, read 2026-11-04: `Ignoring unparseable stream\nraw SDP:
/// {:#?}` in `src/client/parse.rs`, `Received RTSP request in Playing
/// state. Responding unimplemented.\n{:#?}` in `src/client/playing.rs`,
/// `buffered:\n{:#?}` in `src/rtsp/reader.rs`, and the `{:#?}` of a
/// response head, which starts its fields on the next line), and that text
/// holds URLs no scheme marks, such as a relative `a=control` (RFC 2326
/// §C.1.1), which [`scrub_urls`] cannot find: none of it is kept.
fn first_line(text: &str) -> &str {
    text.split(['\r', '\n']).next().unwrap_or_default()
}

/// retina's `text` as a log line carries it: its first line
/// (`first_line`), its URLs cut to scheme, host and port
/// ([`scrub_urls`]), then as any camera text (control characters
/// replaced, capped). The scrub comes before the cap, so a cut never
/// leaves part of a URL it would have removed.
pub fn retina_text(text: &str) -> String {
    camera_text(&scrub_urls(first_line(text)))
}

/// The text of one of retina's events: its message, then each field but
/// the [`DROPPED`] ones as ` name=value`, each through [`retina_text`].
#[derive(Debug, Default)]
struct Text {
    /// The message.
    message: String,
    /// The fields after it.
    fields: String,
}

impl Visit for Text {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record(field, &format!("{value:?}"));
    }
}

impl Text {
    /// Takes `value` of `field`.
    fn record(&mut self, field: &Field, value: &str) {
        let name = field.name();
        if name == "message" {
            self.message = retina_text(value);
        } else if !DROPPED.contains(&name) {
            let _infallible = write!(self.fields, " {name}={}", retina_text(value));
        }
    }
}

/// The layer that writes the log lines (`inner`), with retina's events
/// throttled, scrubbed and capped on their way to it (the module docs).
#[derive(Debug)]
pub struct RetinaLog<L> {
    /// The layer that writes the lines.
    inner: L,
    /// One throttle per call site of retina's.
    sites: CallSites<Identifier>,
}

impl<L> RetinaLog<L> {
    /// `inner` with retina's events throttled on `clock`.
    pub fn new(inner: L, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner,
            sites: CallSites::new(clock),
        }
    }
}

/// Hands `write` what of `event` reaches the lines: the event itself
/// when it is not retina's; for one of retina's, nothing while its
/// call site is throttled, else the event written for it (the module
/// docs), counted in `sites`. Apart from the wrapped layer, so none of
/// it is generic.
fn written(sites: &CallSites<Identifier>, event: &Event<'_>, write: &mut dyn FnMut(&Event<'_>)) {
    let original = event.metadata();
    if !is_retina(original) {
        write(event);
        return;
    }
    let Some(count) = sites.hit(original.callsite()) else {
        return;
    };
    let mut text = Text::default();
    event.record(&mut text);
    let line = format!("{}{}", text.message, text.fields);
    let line = if count > 1 {
        summary(&line, count)
    } else {
        line
    };
    let retina = tracing_core::field::display(original.target());
    let line = line.as_str();
    let (line, retina): (&dyn Value, &dyn Value) = (&line, &retina);
    let written = metadata(*original.level());
    let mut fields = written.fields().iter();
    if let (Some(message), Some(target)) = (fields.next(), fields.next()) {
        let values = [(&message, Some(line)), (&target, Some(retina))];
        let values = written.fields().value_set(&values);
        // In the current span, as retina's events are.
        write(&Event::new(written, &values));
    }
}

impl<S, L> Layer<S> for RetinaLog<L>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    L: Layer<S>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        self.inner.on_new_span(attrs, id, ctx);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        self.inner.on_record(id, values, ctx);
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        self.inner.on_enter(id, ctx);
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        self.inner.on_exit(id, ctx);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        self.inner.on_close(id, ctx);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        written(&self.sites, event, &mut |written| {
            self.inner.on_event(written, ctx.clone());
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::Mutex;

    use lotse_core::clock::FakeClock;
    use lotse_core::text::CUT_MARK;
    use lotse_core::throttle::SUMMARY_INTERVAL;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;
    use crate::error::CAMERA_TEXT_BYTES;

    #[test]
    fn rfc3986_3_2_a_url_keeps_its_scheme_host_and_port_and_loses_the_rest() {
        for (text, scrubbed) in [
            ("no url here", "no url here"),
            ("rtsp://cam", "rtsp://cam"),
            (
                "at rtsp://cam:554/camkey7f3a/live x",
                "at rtsp://cam:554/**** x",
            ),
            ("rtsp://cam/x?token=tok9d2e", "rtsp://cam/****"),
            ("rtsp://cam?token=tok9d2e", "rtsp://cam/****"),
            ("rtsp://cam#frag", "rtsp://cam/****"),
            // The authority ends at a `#`: an `@` after it is no userinfo's.
            ("rtsp://cam#note@secret", "rtsp://cam/****"),
            ("rtsp://cam:554#a@b/c", "rtsp://cam:554/****"),
            ("rtsp://admin:pw5b1c@cam/x", "rtsp://****@cam/****"),
            // The host follows the last `@` of the authority.
            ("rtsp://a@b:p@w@cam:8554", "rtsp://****@cam:8554"),
            ("RTSPS://[fe80::1]:322/x", "RTSPS://[fe80::1]:322/****"),
            ("rtsp://", "rtsp://"),
            // Two URLs, and the scheme of the earlier one wins.
            (
                "a rtsps://cam/x b rtsp://other:1/y",
                "a rtsps://cam/**** b rtsp://other:1/****",
            ),
            // `RTP-Info`: the rest of the header runs with the first path.
            (
                "url=rtsp://cam/s/track0;seq=1;rtptime=x,url=rtsp://cam/s/track1",
                "url=rtsp://cam/****",
            ),
            (
                "a=control:rtsp://cam/x\r\na=y",
                "a=control:rtsp://cam/****\r\na=y",
            ),
            (
                "rtsp://cam/x\u{1b}[0m tail",
                "rtsp://cam/****\u{1b}[0m tail",
            ),
        ] {
            assert_eq!(scrub_urls(text), scrubbed, "{text}");
        }
    }

    #[test]
    fn rfc3986_2_2_a_url_runs_past_apostrophes_and_quotes_to_whitespace() {
        for (text, scrubbed) in [
            // An apostrophe is a sub-delimiter: what follows it is the URL's.
            ("rtsp://cam/path'part?token=secret-token", "rtsp://cam/****"),
            ("'rtsp://cam/camkey7f3a' and", "'rtsp://cam/**** and"),
            ("'rtsp://cam' and", "'rtsp://cam' and"),
            // As `{:?}` quotes it, and across lines: the closing quote goes
            // with the path, and so would a secret after an escaped one.
            (
                "Request { url: \"rtsp://cam/camkey7f3a\" }\nCSeq: 5",
                "Request { url: \"rtsp://cam/**** }\nCSeq: 5",
            ),
            ("\"rtsp://cam/a\\\"tok9d2e\"", "\"rtsp://cam/****"),
            // A quote after the host: it and the rest go with the path.
            ("\"rtsp://cam\" }", "\"rtsp://cam/**** }"),
            ("\"rtsp://cam\"tok9d2e@x\"", "\"rtsp://****@x/****"),
            ("<rtsp://u:pw5b1c@cam>", "<rtsp://****@cam/****"),
            // Characters a URL should escape and its writer left as they
            // are end nothing.
            ("rtsp://cam/a|tok9d2e{b}^c`d", "rtsp://cam/****"),
            ("rtsp://cam/x?t=a\\tok9d2e", "rtsp://cam/****"),
            // A userinfo is wholly redacted, whatever it holds.
            ("rtsp://us\u{e4}r:pw5b1c@cam/x", "rtsp://****@cam/****"),
        ] {
            assert_eq!(scrub_urls(text), scrubbed, "{text}");
        }
    }

    #[test]
    fn retinas_text_is_scrubbed_before_it_is_capped() {
        // Cut first, the cap would keep the path's first bytes; scrubbed
        // first, the URL is short enough to stay whole.
        let lead = "x".repeat(CAMERA_TEXT_BYTES - 20);
        let text = format!("{lead} rtsp://cam/camkey7f3a/live?token=tok9d2e");
        assert_eq!(retina_text(&text), format!("{lead} rtsp://cam/****"));
        // Longer than the cap once scrubbed: cut and marked.
        let long = format!("{} {text}", "y".repeat(CAMERA_TEXT_BYTES));
        let line = retina_text(&long);
        assert_eq!(line.len(), CAMERA_TEXT_BYTES, "{line}");
        assert!(line.ends_with(CUT_MARK), "{line}");
        assert!(!line.contains("camkey"), "{line}");
        // Control characters within the line are replaced.
        assert_eq!(retina_text("a\tb\u{1b}[2J"), "a b\u{fffd}[2J");
    }

    /// What retina dumps of the camera's protocol after a line break is
    /// dropped, with the URLs it holds that no scheme marks: a relative
    /// `a=control` (RFC 2326 §C.1.1) early in an SDP would fit under the
    /// cap.
    #[test]
    fn rfc2326_c_1_1_retinas_dump_after_a_line_break_is_dropped_with_its_relative_urls() {
        let sdp = "\"v=0\\r\\na=control:/camkey7f3a/live?token=tok9d2e\\r\\n\"";
        for (text, line) in [
            (
                format!("Ignoring unparseable stream\nraw SDP: {sdp}"),
                "Ignoring unparseable stream",
            ),
            (
                format!("SETUP response: Head {{\r    sdp: {sdp}"),
                "SETUP response: Head {",
            ),
            (format!("\n{sdp}"), ""),
            ("one line".to_owned(), "one line"),
        ] {
            assert_eq!(retina_text(&text), line, "{text}");
        }
        assert_eq!(first_line("a\r\nb"), "a");
        assert_eq!(first_line(""), "");
    }

    #[test]
    fn retinas_targets_and_spans_are_told_apart() {
        // Spans have metadata only where a subscriber takes them.
        tracing::subscriber::with_default(tracing_subscriber::registry(), || {
            let request = tracing::info_span!(target: "retina::client", "rtsp_request");
            let root = tracing::info_span!(target: "retina", "rtsp_teardown");
            let lookalike = tracing::info_span!(target: "retinal", "x");
            let (request, root, lookalike) = (
                request.metadata().unwrap(),
                root.metadata().unwrap(),
                lookalike.metadata().unwrap(),
            );
            assert!(is_retina(request) && is_retina(root));
            assert!(!is_retina(lookalike));
            assert!(!no_retina_spans(request) && !no_retina_spans(root));
            assert!(no_retina_spans(lookalike));
        });
        // The events written for retina's are no retina events.
        assert_eq!(WARN_META.target(), TARGET);
        assert!(!is_retina(&WARN_META) && no_retina_spans(&WARN_META));
    }

    /// A log sink the test reads back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What `run` logs, as text and as JSON with the span list, through
    /// the layer counting on `clock`, with retina's spans filtered out.
    fn logged(clock: &Arc<FakeClock>, run: impl FnOnce()) -> (String, String) {
        let (mut text, json) = (Captured::default(), Captured::default());
        let (to_text, to_json) = (text.clone(), json.clone());
        let lines = tracing_subscriber::fmt::layer()
            .with_writer(move || to_text.clone())
            .with_ansi(false);
        let objects = tracing_subscriber::fmt::layer()
            .with_writer(move || to_json.clone())
            .json()
            .with_span_list(true);
        let subscriber = tracing_subscriber::registry()
            .with(filter_fn(no_retina_spans))
            .with(RetinaLog::new(lines, clock.clone()))
            .with(RetinaLog::new(objects, clock.clone()));
        tracing::subscriber::with_default(subscriber, run);
        std::io::Write::flush(&mut text).unwrap();
        let read =
            |captured: &Captured| String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        (read(&text), read(&json))
    }

    #[test]
    fn retinas_events_are_written_at_their_level_with_their_target_and_without_url_fields() {
        let clock = Arc::new(FakeClock::from_system());
        let (text, json) = logged(&clock, || {
            tracing::error!(target: "retina::a", "an error");
            tracing::warn!(
                target: "retina::client::parse",
                rtp_info = "url=rtsp://cam/camkey7f3a;rtptime=x",
                url = "rtsp://cam/camkey7f3a",
                error = %"bad\nrtsp://cam/camkey7f3a",
                "Unparseable rtptime in RTP-Info header"
            );
            // A `&str` field as it is, not quoted as `{:?}` would.
            tracing::info!(target: "retina", stream = 1, method = "DESCRIBE", "an info");
            tracing::debug!(target: "retina::b", "SETUP response: {:#?}", ("Transport", "x"));
            tracing::trace!(target: "retina::c", "a trace");
        });
        for (level, message) in [
            ("ERROR", "an error"),
            ("WARN", "Unparseable rtptime in RTP-Info header error=bad"),
            ("INFO", "an info stream=1 method=DESCRIBE"),
            // The `{:#?}` after its first line is dropped.
            ("DEBUG", "SETUP response: ( retina=retina::b"),
            ("TRACE", "a trace"),
        ] {
            assert!(
                text.lines()
                    .any(|line| line.contains(level) && line.contains(message)),
                "{level} {message}: {text}"
            );
        }
        assert_eq!(text.lines().count(), 5, "{text}");
        assert!(text.contains("retina=retina::client::parse"), "{text}");
        for logs in [&text, &json] {
            assert!(!logs.contains("camkey7f3a"), "{logs}");
            assert!(!logs.contains("rtptime=x"), "{logs}");
        }
        assert!(
            json.contains("\"retina\":\"retina::client::parse\""),
            "{json}"
        );
    }

    #[test]
    fn a_repaired_schemeless_content_base_is_logged_without_its_value() {
        // retina (edenhaus/retina `f65065f`, `src/client/parse.rs`, read
        // 2026-11-04) logs the header it repaired as it came, no scheme
        // for the scrub to find.
        let clock = Arc::new(FakeClock::from_system());
        let (text, json) = logged(&clock, || {
            let value = "cam.example/camkey7f3a?token=tok9d2e";
            let url = format!("rtsp://{value}");
            tracing::warn!(
                target: "retina::client::parse",
                header = %"Content-Base",
                value = ?value,
                %url,
                "repaired schemeless URL"
            );
        });
        assert!(
            text.contains("repaired schemeless URL header=Content-Base retina="),
            "{text}"
        );
        for logs in [&text, &json] {
            assert!(!logs.contains("camkey7f3a"), "{logs}");
            assert!(!logs.contains("tok9d2e"), "{logs}");
        }
    }

    #[test]
    fn a_retina_call_site_is_throttled_and_summarized_with_the_count() {
        let clock = Arc::new(FakeClock::from_system());
        let restart = || {
            tracing::warn!(target: "retina::client::playing", seq = 7, "sender restarted RTP sequence numbers");
        };
        let (text, _) = logged(&clock, || {
            for _ in 0..5 {
                restart();
            }
            clock.advance(SUMMARY_INTERVAL);
            restart();
        });
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(
            lines[0].ends_with(
                "sender restarted RTP sequence numbers seq=7 retina=retina::client::playing"
            ),
            "{text}"
        );
        assert!(
            lines[1].contains(
                "sender restarted RTP sequence numbers seq=7 (5 occurrences since the last line)"
            ),
            "{text}"
        );
    }

    /// A layer that records which of a span's calls reach it.
    #[derive(Clone, Default)]
    struct Calls(Arc<Mutex<Vec<&'static str>>>);

    impl Calls {
        fn push(&self, call: &'static str) {
            self.0.lock().unwrap().push(call);
        }
    }

    impl<S: Subscriber> Layer<S> for Calls {
        fn on_new_span(&self, _attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
            self.push("new");
        }

        fn on_record(&self, _id: &Id, _values: &Record<'_>, _ctx: Context<'_, S>) {
            self.push("record");
        }

        fn on_enter(&self, _id: &Id, _ctx: Context<'_, S>) {
            self.push("enter");
        }

        fn on_exit(&self, _id: &Id, _ctx: Context<'_, S>) {
            self.push("exit");
        }

        fn on_close(&self, _id: Id, _ctx: Context<'_, S>) {
            self.push("close");
        }
    }

    #[test]
    fn every_call_of_a_span_reaches_the_wrapped_layer() {
        let calls = Calls::default();
        let clock = Arc::new(FakeClock::from_system());
        let subscriber = tracing_subscriber::registry().with(RetinaLog::new(calls.clone(), clock));
        tracing::subscriber::with_default(subscriber, || {
            let attempt = tracing::info_span!("attempt", state = tracing::field::Empty);
            attempt.record("state", "playing");
            attempt.in_scope(|| {});
            drop(attempt);
        });
        assert_eq!(
            *calls.0.lock().unwrap(),
            ["new", "record", "enter", "exit", "close"]
        );
    }

    #[test]
    fn other_events_and_spans_pass_untouched_and_retinas_spans_are_never_created() {
        let clock = Arc::new(FakeClock::from_system());
        let (text, json) = logged(&clock, || {
            let attempt =
                tracing::info_span!("attempt", stream = "door", state = tracing::field::Empty);
            attempt.record("state", "playing");
            let attempt = attempt.entered();
            let request = tracing::info_span!(
                target: "retina::client::session_core",
                "rtsp_request",
                url = "rtsp://cam/camkey7f3a"
            );
            assert!(request.is_disabled());
            let _request = request.entered();
            tracing::warn!(target: "retina::client::parse", "inside");
            tracing::info!(url = "rtsp://cam/x", "lotse's own");
            drop(attempt);
        });
        assert!(
            text.contains("attempt{stream=\"door\" state=\"playing\"}"),
            "{text}"
        );
        assert!(text.contains("lotse's own url=\"rtsp://cam/x\""), "{text}");
        assert!(json.contains("\"state\":\"playing\""), "{json}");
        for logs in [&text, &json] {
            assert!(!logs.contains("rtsp_request"), "{logs}");
            assert!(!logs.contains("camkey7f3a"), "{logs}");
            assert!(logs.contains("inside"), "{logs}");
        }
    }
}

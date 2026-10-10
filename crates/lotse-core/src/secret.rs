//! [`Secret`]: a value whose `Debug` and `Display` print `****`, so camera
//! credentials cannot reach a log line, an API result or an error message by
//! accident; [`RedactedUrl`]: a URL that prints its origin only, because a
//! source URL's path and query carry secrets too (a camera key as a path
//! segment, a CDN or session token in the query).
//!
//! URL components follow RFC 3986 §3 as the `url` crate (WHATWG URL)
//! parses them.

use std::fmt;

use url::Url;

/// What a redacted secret prints as.
pub const REDACTED: &str = "****";

/// A value that never prints. Read it with [`Secret::expose_secret`], and only
/// where the value leaves the process toward its own source (an RTSP
/// `Authorization` header, a TURN allocation).
///
/// Equality and hashing see the real value, because the canonical source key
/// includes the credentials.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps `value`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The real value. The name is deliberately loud, so it stands out in review.
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Unwraps the real value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// A borrowed URL that prints redacted: `scheme://[****@]host[:port]`,
/// then `/****` when the path is anything but empty or `/`, `?****` when a
/// query is present and `#****` when a fragment is. Nothing decides which
/// part is secret: everything past the origin is. `Display` and `Debug`
/// print that form; the URL itself stays reachable through
/// [`RedactedUrl::expose_url`], for the protocol client only.
#[derive(Clone, Copy)]
pub struct RedactedUrl<'a> {
    /// The URL, secrets included.
    url: &'a Url,
    /// Whether to print `****@`: the URL had a userinfo, which may have
    /// been split off already (`SourceUrl` keeps it apart).
    userinfo: bool,
}

impl<'a> RedactedUrl<'a> {
    /// Wraps `url`; `****@` is printed when it has a user name or a
    /// password.
    pub fn new(url: &'a Url) -> Self {
        Self {
            url,
            userinfo: !url.username().is_empty() || url.password().is_some(),
        }
    }

    /// Wraps `url`, whose userinfo was split off: `****@` is printed when
    /// `userinfo` says it had one.
    pub(crate) const fn with_userinfo(url: &'a Url, userinfo: bool) -> Self {
        Self { url, userinfo }
    }

    /// The URL with its path and query. The name is deliberately loud, as
    /// [`Secret::expose_secret`]'s is.
    pub const fn expose_url(&self) -> &'a Url {
        self.url
    }

    /// `text` with every `scheme://` URL in it printed redacted, and every
    /// verbatim occurrence of this URL's path (unless empty or `/`) and
    /// query (unless empty) replaced by `****`: for messages of third-party
    /// libraries, which may echo the URL, or a URL built from it, that they
    /// were given.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        let mut scrubbed = redact_embedded_urls(text);
        let path = self.url.path();
        if !path.is_empty() && path != "/" {
            scrubbed = scrubbed.replace(path, REDACTED_PATH);
        }
        if let Some(query) = self.url.query().filter(|query| !query.is_empty()) {
            scrubbed = scrubbed.replace(query, REDACTED);
        }
        scrubbed
    }
}

/// What a path other than empty or `/` prints as.
const REDACTED_PATH: &str = "/****";

impl fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.url.scheme())?;
        if self.userinfo {
            write!(f, "{REDACTED}@")?;
        }
        f.write_str(self.url.host_str().unwrap_or_default())?;
        if let Some(port) = self.url.port() {
            write!(f, ":{port}")?;
        }
        match self.url.path() {
            "" | "/" => f.write_str(self.url.path())?,
            _ => f.write_str(REDACTED_PATH)?,
        }
        if self.url.query().is_some() {
            write!(f, "?{REDACTED}")?;
        }
        if self.url.fragment().is_some() {
            write!(f, "#{REDACTED}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Url").field(&self.to_string()).finish()
    }
}

/// Whether `c` may appear in a URI scheme (RFC 3986 §3.1).
const fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

/// Whether `c` ends a URL embedded in prose: white space, a quote or an
/// angle bracket (RFC 3986 Appendix C delimiters).
const fn ends_embedded_url(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`')
}

/// What follows the scheme of a URL with an authority (RFC 3986 §3).
const SEPARATOR: &str = "://";

/// `text` with every `scheme://…` in it replaced by its [`RedactedUrl`]
/// form, or by `scheme://****` when it does not parse. The URL runs from
/// its scheme (RFC 3986 §3.1) to the next white space, quote or angle
/// bracket, or the end.
fn redact_embedded_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(SEPARATOR) {
        let (before, from_separator) = rest.split_at_checked(at).unwrap_or((rest, ""));
        let scheme_start = before
            .char_indices()
            .rev()
            .take_while(|&(_, c)| is_scheme_char(c))
            .last()
            .map_or(before.len(), |(index, _)| index);
        let (prose, scheme) = before
            .split_at_checked(scheme_start)
            .unwrap_or((before, ""));
        let past = from_separator.get(SEPARATOR.len()..).unwrap_or_default();
        let end = past.find(ends_embedded_url).unwrap_or(past.len());
        let (tail, after) = past.split_at_checked(end).unwrap_or((past, ""));
        out.push_str(prose);
        if let Ok(url) = Url::parse(&format!("{scheme}{SEPARATOR}{tail}")) {
            out.push_str(&RedactedUrl::new(&url).to_string());
        } else {
            // Not a URL after all (no scheme, or one that does not parse):
            // what follows `://` is redacted anyway.
            out.push_str(scheme);
            out.push_str(SEPARATOR);
            out.push_str(REDACTED);
        }
        rest = after;
    }
    out.push_str(rest);
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
    fn debug_and_display_redact() {
        let secret = Secret::new(String::from("hunter2"));
        assert_eq!(format!("{secret:?}"), "Secret(****)");
        assert_eq!(format!("{secret}"), "****");
        assert_eq!(format!("{:?}", Some(&secret)), "Some(Secret(****))");
    }

    #[test]
    fn expose_and_into_inner_return_the_value() {
        let secret: Secret<&str> = "hunter2".into();
        assert_eq!(*secret.expose_secret(), "hunter2");
        assert_eq!(secret.into_inner(), "hunter2");
    }

    #[test]
    fn equality_sees_the_real_value() {
        assert_eq!(Secret::new(1), Secret::new(1));
        assert_ne!(Secret::new(1), Secret::new(2));
        assert_eq!(Secret::<u8>::default(), Secret::new(0));
    }

    fn redacted(input: &str) -> String {
        RedactedUrl::new(&Url::parse(input).unwrap()).to_string()
    }

    #[test]
    fn rfc3986_3_a_url_prints_its_origin_and_markers_only() {
        for (input, shown) in [
            ("rtsp://cam", "rtsp://cam"),
            ("rtsp://cam/", "rtsp://cam/"),
            ("rtsp://cam/a/b", "rtsp://cam/****"),
            ("rtsp://cam:554", "rtsp://cam:554"),
            ("rtsp://u:p@cam:554/a?b", "rtsp://****@cam:554/****?****"),
            ("rtsp://u@cam/", "rtsp://****@cam/"),
            ("rtsp://:p@cam", "rtsp://****@cam"),
            ("rtsp://cam?q", "rtsp://cam?****"),
            ("http://cam", "http://cam/"),
            ("http://cam/?", "http://cam/?****"),
            (
                "http://cam:8080/key/live/files/high/index.m3u8",
                "http://cam:8080/****",
            ),
            ("https://cam:443/key?token=t", "https://cam/****?****"),
            (
                "https://u:p@[2001:DB8::1]:8443/k?t",
                "https://****@[2001:db8::1]:8443/****?****",
            ),
            ("http://[::1]/", "http://[::1]/"),
            ("http://cam/a#frag", "http://cam/****#****"),
            ("http://cam/#frag", "http://cam/#****"),
            ("file:///etc/key", "file:///****"),
        ] {
            assert_eq!(redacted(input), shown, "{input}");
        }
    }

    #[test]
    fn debug_prints_the_redacted_form_and_expose_url_the_url() {
        let url = Url::parse("https://cam/key?token=t").unwrap();
        let shown = RedactedUrl::new(&url);
        assert_eq!(format!("{shown:?}"), "Url(\"https://cam/****?****\")");
        assert_eq!(
            format!("{:?}", Some(shown)),
            "Some(Url(\"https://cam/****?****\"))"
        );
        assert_eq!(shown.expose_url(), &url);
        let split = Url::parse("rtsp://cam/").unwrap();
        assert_eq!(
            RedactedUrl::with_userinfo(&split, true).to_string(),
            "rtsp://****@cam/"
        );
        assert_eq!(
            RedactedUrl::with_userinfo(&split, false).to_string(),
            "rtsp://cam/"
        );
    }

    #[test]
    fn scrub_redacts_embedded_urls_and_the_urls_path_and_query() {
        let url = Url::parse("rtsp://127.0.0.1:41000/KEY/live?token=TOK").unwrap();
        let shown = RedactedUrl::new(&url);
        for (text, scrubbed) in [
            ("nothing here", "nothing here"),
            (
                "unable to join base url rtsp://127.0.0.1:41000/KEY/live/?token=TOK with control url \"x\"",
                "unable to join base url rtsp://127.0.0.1:41000/****?**** with control url \"x\"",
            ),
            (
                "bad Content-Base \"rtsp://u:pw@other/KEY2/\": nope",
                "bad Content-Base \"rtsp://****@other/****\": nope",
            ),
            ("(see <http://cdn/x>)", "(see <http://cdn/****>)"),
            ("broken rtsp://[::1/KEY end", "broken rtsp://**** end"),
            ("odd 1x://KEY and ://KEY", "odd 1x://**** and ://****"),
            (
                "Url { path: \"/KEY/live/trackID=1\", query: Some(\"token=TOK\") }",
                "Url { path: \"/****/trackID=1\", query: Some(\"****\") }",
            ),
            ("\u{2192}rtsp://cam/KEY", "\u{2192}rtsp://cam/****"),
        ] {
            assert_eq!(shown.scrub(text), scrubbed, "{text}");
        }
    }

    #[test]
    fn scrub_leaves_a_trivial_path_and_an_empty_query_alone() {
        for input in ["rtsp://cam", "rtsp://cam/", "rtsp://cam/?"] {
            let url = Url::parse(input).unwrap();
            assert_eq!(
                RedactedUrl::new(&url).scrub("a / b ? c"),
                "a / b ? c",
                "{input}"
            );
        }
    }
}

//! [`SourceUrl`]: a parsed source URL whose credentials are a [`Secret`] and
//! whose equality is the canonical source key.
//!
//! Implements RFC 3986 §3 (components) through the `url` crate and §3.2.1
//! (percent-encoded userinfo) through `percent-encoding`. Which schemes are
//! accepted is the source registry's decision, not this type's: it only
//! requires an authority with a host and refuses a fragment.

use std::fmt;
use std::str::FromStr;

use percent_encoding::percent_decode_str;
use url::Url;

use crate::secret::{REDACTED, RedactedUrl, Secret};

/// The userinfo of a source URL. `Debug` prints `Credentials(****)`, and the
/// password is a [`Secret`] on its own, so neither reaches a log line.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Credentials {
    /// The percent-decoded user name; empty when the URL had only a password.
    username: String,
    /// The percent-decoded password, when the URL had one.
    password: Option<Secret<String>>,
}

impl Credentials {
    /// The user name, percent-decoded.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The password, percent-decoded, when the URL had one.
    pub fn password(&self) -> Option<&Secret<String>> {
        self.password.as_ref()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credentials({REDACTED})")
    }
}

/// Why a string is not a usable source URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceUrlError {
    /// The string is not a URL at all (RFC 3986 syntax).
    #[error("url does not parse: {0}")]
    Parse(#[from] url::ParseError),
    /// The URL has no host, so there is nothing to connect to.
    #[error("url has no host")]
    MissingHost,
    /// The URL carries a `#fragment`. Stream options belong in `options`,
    /// so a fragment meant to carry them fails loudly instead of being
    /// ignored.
    #[error("url has a fragment; stream options belong in `options`, not in the url")]
    Fragment,
    /// The userinfo is not valid UTF-8 after percent-decoding.
    #[error("credentials are not valid UTF-8 after percent-decoding")]
    CredentialsNotUtf8,
}

/// A source URL with its credentials split off.
///
/// Two values are equal exactly when they name the same upstream connection:
/// scheme, host (lowercased), port as written, path, query and credentials.
/// Streams whose URLs are equal share one `SourceConnection`; a different
/// port spelling, path or password is a different connection.
/// `Display` and `Debug` print the [`RedactedUrl`] form, the origin only
/// (`rtsp://****@host:554/****?****`): a path or query can carry a secret
/// as well as the userinfo can.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SourceUrl {
    /// The URL without its userinfo, as a protocol client needs it.
    url: Url,
    /// The userinfo, when the URL had one.
    credentials: Option<Credentials>,
}

impl SourceUrl {
    /// Parses `input`, splits off the userinfo and lowercases the host.
    pub fn parse(input: &str) -> Result<Self, SourceUrlError> {
        let mut url = Url::parse(input)?;
        if url.fragment().is_some() {
            return Err(SourceUrlError::Fragment);
        }
        let host = match url.host_str() {
            Some(host) if !host.is_empty() => host.to_ascii_lowercase(),
            _ => return Err(SourceUrlError::MissingHost),
        };

        let credentials = if url.username().is_empty() && url.password().is_none() {
            None
        } else {
            Some(Credentials {
                username: decode(url.username())?,
                password: url
                    .password()
                    .map(|password| decode(password).map(Secret::new))
                    .transpose()?,
            })
        };

        // `set_host` re-parses the lowercased host; it was a valid host before,
        // so this cannot fail. `set_username`/`set_password` fail only for URLs
        // without a host, which were rejected above.
        url.set_host(Some(&host))?;
        url.set_username("")
            .and_then(|()| url.set_password(None))
            .map_err(|()| SourceUrlError::MissingHost)?;

        Ok(Self { url, credentials })
    }

    /// The scheme, lowercased (`rtsp`, `rtsps`).
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// The host, lowercased; an IPv6 literal keeps its brackets.
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    /// The port as written in the URL. Protocol defaults are the source's
    /// business.
    pub fn port(&self) -> Option<u16> {
        self.url.port()
    }

    /// The URL with the userinfo removed, path and query included, for the
    /// protocol client only. The name is deliberately loud, as
    /// [`Secret::expose_secret`]'s is: what it returns must not be printed
    /// (print [`SourceUrl::redacted`]).
    pub const fn expose_url(&self) -> &Url {
        &self.url
    }

    /// The printable form, `****@` included when the URL had a userinfo.
    pub fn redacted(&self) -> RedactedUrl<'_> {
        RedactedUrl::with_userinfo(&self.url, self.credentials.is_some())
    }

    /// The credentials, when the URL had any.
    pub fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }
}

/// Percent-decodes one userinfo component (RFC 3986 §3.2.1).
fn decode(component: &str) -> Result<String, SourceUrlError> {
    percent_decode_str(component)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| SourceUrlError::CredentialsNotUtf8)
}

impl FromStr for SourceUrl {
    type Err = SourceUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for SourceUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.redacted(), f)
    }
}

impl fmt::Debug for SourceUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SourceUrl").field(&self.to_string()).finish()
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
    fn parses_every_component_rfc3986_3() {
        let url = SourceUrl::parse("rtsp://admin:hunter2@192.168.1.10:554/h264?ch=1").unwrap();
        assert_eq!(url.scheme(), "rtsp");
        assert_eq!(url.host(), "192.168.1.10");
        assert_eq!(url.port(), Some(554));
        assert_eq!(url.expose_url().path(), "/h264");
        assert_eq!(url.expose_url().query(), Some("ch=1"));
        let credentials = url.credentials().unwrap();
        assert_eq!(credentials.username(), "admin");
        assert_eq!(credentials.password().unwrap().expose_secret(), "hunter2");
    }

    #[test]
    fn display_and_debug_redact_the_userinfo_path_and_query() {
        let url = SourceUrl::parse("rtsp://admin:hunter2@Cam.local:554/h264?x=1").unwrap();
        assert_eq!(url.to_string(), "rtsp://****@cam.local:554/****?****");
        assert_eq!(url.redacted().to_string(), url.to_string());
        assert_eq!(
            format!("{url:?}"),
            "SourceUrl(\"rtsp://****@cam.local:554/****?****\")"
        );
        assert_eq!(
            format!("{:?}", url.credentials().unwrap()),
            "Credentials(****)"
        );
        let printed = format!("{url}{url:?}");
        for secret in ["hunter2", "admin", "h264", "x=1"] {
            assert!(!printed.contains(secret), "{secret} in {printed}");
        }
    }

    #[test]
    fn url_without_credentials_keeps_everything_else() {
        let url = SourceUrl::parse("rtsps://admin:hunter2@cam.local:322/main?a=b").unwrap();
        assert_eq!(url.expose_url().as_str(), "rtsps://cam.local:322/main?a=b");
    }

    #[test]
    fn a_url_without_userinfo_has_no_credentials() {
        let url = SourceUrl::parse("rtsp://cam.local/main").unwrap();
        assert!(url.credentials().is_none());
        assert_eq!(url.port(), None);
        assert_eq!(url.to_string(), "rtsp://cam.local/****");
    }

    #[test]
    fn decodes_percent_encoded_userinfo_rfc3986_3_2_1() {
        let url = SourceUrl::parse("rtsp://us%40er:p%40ss%2Fw@cam.local/").unwrap();
        let credentials = url.credentials().unwrap();
        assert_eq!(credentials.username(), "us@er");
        assert_eq!(credentials.password().unwrap().expose_secret(), "p@ss/w");
    }

    #[test]
    fn accepts_a_password_without_a_user_name() {
        let url = SourceUrl::parse("rtsp://:secret@cam.local/").unwrap();
        let credentials = url.credentials().unwrap();
        assert_eq!(credentials.username(), "");
        assert_eq!(credentials.password().unwrap().expose_secret(), "secret");
    }

    #[test]
    fn accepts_a_user_name_without_a_password() {
        let url = SourceUrl::parse("rtsp://admin@cam.local/").unwrap();
        let credentials = url.credentials().unwrap();
        assert_eq!(credentials.username(), "admin");
        assert!(credentials.password().is_none());
        assert_eq!(url.to_string(), "rtsp://****@cam.local/");
    }

    #[test]
    fn keeps_ipv6_literals_bracketed() {
        let url = SourceUrl::parse("rtsp://[FE80::1]:554/main").unwrap();
        assert_eq!(url.host(), "[fe80::1]");
        assert_eq!(url.to_string(), "rtsp://[fe80::1]:554/****");
    }

    #[test]
    fn rfc3986_3_every_component_past_the_origin_is_redacted() {
        for (input, shown) in [
            ("rtsp://cam.local", "rtsp://cam.local"),
            ("rtsp://cam.local/", "rtsp://cam.local/"),
            ("rtsp://u:p@cam.local", "rtsp://****@cam.local"),
            ("rtsp://u@cam.local:8554/", "rtsp://****@cam.local:8554/"),
            ("rtsp://cam.local?token=t", "rtsp://cam.local?****"),
            ("http://cam.local/?token=t", "http://cam.local/?****"),
            ("http://cam.local/?", "http://cam.local/?****"),
            (
                "https://cam.local:8443/key/live/files/high/index.m3u8?session=s",
                "https://cam.local:8443/****?****",
            ),
            (
                "https://cam.local:443/key/index.m3u8",
                "https://cam.local/****",
            ),
            ("http://cam.local", "http://cam.local/"),
            (
                "rtsp://:p@[FE80::1]:554/main?a=b",
                "rtsp://****@[fe80::1]:554/****?****",
            ),
        ] {
            let url = SourceUrl::parse(input).unwrap();
            assert_eq!(url.to_string(), shown, "{input}");
            assert_eq!(
                format!("{url:?}"),
                format!("SourceUrl({shown:?})"),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_a_missing_host() {
        assert_eq!(
            SourceUrl::parse("rtsp:///main").unwrap_err(),
            SourceUrlError::MissingHost
        );
        assert_eq!(
            SourceUrl::parse("rtsp:main").unwrap_err(),
            SourceUrlError::MissingHost
        );
    }

    #[test]
    fn rejects_a_fragment() {
        assert_eq!(
            SourceUrl::parse("rtsp://cam.local/main#audio=opus").unwrap_err(),
            SourceUrlError::Fragment
        );
    }

    #[test]
    fn rejects_non_utf8_credentials() {
        assert_eq!(
            SourceUrl::parse("rtsp://%ff:x@cam.local/").unwrap_err(),
            SourceUrlError::CredentialsNotUtf8
        );
        assert_eq!(
            SourceUrl::parse("rtsp://x:%ff@cam.local/").unwrap_err(),
            SourceUrlError::CredentialsNotUtf8
        );
    }

    #[test]
    fn rejects_what_is_not_a_url() {
        let err = SourceUrl::parse("not a url").unwrap_err();
        assert!(matches!(err, SourceUrlError::Parse(_)), "{err:?}");
        assert!(err.to_string().starts_with("url does not parse: "));
        assert_eq!(
            "rtsp://cam.local/".parse::<SourceUrl>().unwrap(),
            SourceUrl::parse("rtsp://cam.local/").unwrap()
        );
    }

    #[test]
    fn equality_is_the_canonical_key() {
        let a = SourceUrl::parse("rtsp://admin:one@CAM.local:554/main").unwrap();
        let same = SourceUrl::parse("rtsp://admin:one@cam.local:554/main").unwrap();
        let other_password = SourceUrl::parse("rtsp://admin:two@cam.local:554/main").unwrap();
        let other_path = SourceUrl::parse("rtsp://admin:one@cam.local:554/sub").unwrap();
        let default_port = SourceUrl::parse("rtsp://admin:one@cam.local/main").unwrap();
        assert_eq!(a, same);
        assert_ne!(a, other_password);
        assert_ne!(a, other_path);
        assert_ne!(a, default_port);
    }

    #[test]
    fn error_messages_are_stable() {
        assert_eq!(SourceUrlError::MissingHost.to_string(), "url has no host");
        assert_eq!(
            SourceUrlError::Fragment.to_string(),
            "url has a fragment; stream options belong in `options`, not in the url"
        );
        assert_eq!(
            SourceUrlError::CredentialsNotUtf8.to_string(),
            "credentials are not valid UTF-8 after percent-decoding"
        );
    }
}

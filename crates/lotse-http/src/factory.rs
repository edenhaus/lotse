//! The `http` and `https` schemes' factory: options checked, the source
//! built.

use lotse_core::source::{Direction, Source, SourceCapabilities, SourceConfigError, SourceFactory};
use lotse_core::source_url::SourceUrl;
use lotse_tls::{TlsTarget, Trust};

use crate::options::HttpOptions;
use crate::source::{HttpSource, PROTOCOL};

/// RFC 9110 §4.2.1: the default port of `http://`.
pub const DEFAULT_PORT: u16 = 80;

/// RFC 9110 §4.2.2: the default port of `https://`.
pub const DEFAULT_TLS_PORT: u16 = 443;

/// The factory. It holds nothing: an HTTP source connects to its server
/// directly, without a loopback relay.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpFactory;

/// The `https` target for `url` and `options`; `None` for `http`. The TLS
/// options are refused on `http`, and the pin and `insecure_tls` together.
fn tls_target(
    url: &SourceUrl,
    options: &HttpOptions,
) -> Result<Option<TlsTarget>, SourceConfigError> {
    let invalid = |message: &str| SourceConfigError::InvalidOptions {
        scheme: PROTOCOL,
        message: message.to_owned(),
    };
    let trust = match (options.tls_fingerprint, options.insecure_tls) {
        (Some(_), true) => return Err(invalid("set tls_fingerprint or insecure_tls, not both")),
        (Some(pin), false) => Trust::Pin(pin),
        (None, true) => Trust::Insecure,
        (None, false) => Trust::Roots,
    };
    if url.scheme() != "https" {
        return if trust == Trust::Roots {
            Ok(None)
        } else {
            Err(invalid(
                "tls_fingerprint and insecure_tls apply to https:// only",
            ))
        };
    }
    TlsTarget::new(url.host(), trust)
        .map(Some)
        .map_err(|message| SourceConfigError::InvalidUrl {
            scheme: PROTOCOL,
            message,
        })
}

impl SourceFactory for HttpFactory {
    fn schemes(&self) -> &'static [&'static str] {
        &["http", "https"]
    }

    /// Pulled; nothing goes back to the server, and a server that serves
    /// a playlist or a stream has no way to be asked for a keyframe.
    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            direction: Direction::Pull,
            backchannel: false,
            keyframe_request: false,
            snapshot_uri: false,
        }
    }

    fn default_port(&self, scheme: &str) -> Option<u16> {
        Some(if scheme == "https" {
            DEFAULT_TLS_PORT
        } else {
            DEFAULT_PORT
        })
    }

    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError> {
        let options =
            HttpOptions::parse(options).map_err(|err| SourceConfigError::InvalidOptions {
                scheme: PROTOCOL,
                message: err.to_string(),
            })?;
        let tls = tls_target(url, &options)?;
        Ok(Box::new(HttpSource::new(url.clone(), options, tls)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use lotse_core::source::KeyframeRequest;
    use serde_json::json;

    use super::*;

    const PIN: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn url(input: &str) -> SourceUrl {
        SourceUrl::parse(input).unwrap()
    }

    #[test]
    fn the_factory_serves_http_and_https_pulled_without_keyframe_requests() {
        let factory = HttpFactory;
        assert_eq!(factory.schemes(), ["http", "https"]);
        let capabilities = factory.capabilities();
        assert_eq!(capabilities.direction, Direction::Pull);
        assert!(!capabilities.backchannel);
        assert!(!capabilities.keyframe_request);
        assert!(!capabilities.snapshot_uri);
        for scheme in ["http", "https"] {
            assert!(!factory.loopback_relay(scheme), "{scheme}");
        }
    }

    #[test]
    fn rfc9110_4_2_1_http_defaults_to_port_80_and_4_2_2_https_to_443() {
        let factory = HttpFactory;
        assert_eq!(factory.default_port("http"), Some(80));
        assert_eq!(factory.default_port("https"), Some(443));
    }

    #[test]
    fn null_options_are_the_defaults_and_the_source_describes_itself_redacted() {
        let factory = HttpFactory;
        let url = url("http://user:pass@cam.local/live/index.m3u8");
        let source = factory.validate(&url, &serde_json::Value::Null).unwrap();
        let described = source.describe();
        assert_eq!(described.protocol, "http");
        assert_eq!(described.url, url);
        assert!(!described.url.to_string().contains("pass"));
        assert_eq!(described.options, HttpOptions::default().redacted());
        assert_eq!(
            source.connection_options(),
            HttpOptions::default().connection_key()
        );
        assert!(matches!(
            source.request_keyframe(),
            KeyframeRequest::Unsupported
        ));
        // `{}` and the defaults spelled out are the same connection.
        let spelled = factory
            .validate(&url, &json!({ "timeout_ms": 10_000 }))
            .unwrap();
        assert_eq!(spelled.connection_options(), source.connection_options());
        let capped = factory
            .validate(&url, &json!({ "max_bandwidth": 1_000_000 }))
            .unwrap();
        assert_eq!(capped.describe().options["max_bandwidth"], 1_000_000);
        assert_ne!(capped.connection_options(), source.connection_options());
        // Plain HTTP carries no TLS target.
        assert!(format!("{source:?}").contains("tls: None"), "{source:?}");
    }

    #[test]
    fn unknown_or_malformed_options_are_refused_at_put() {
        let factory = HttpFactory;
        let url = url("http://cam.local/");
        for options in [
            json!({ "nope": 1 }),
            json!({ "timeout_ms": "soon" }),
            json!({ "user_agent": "Client/1" }),
            json!([]),
        ] {
            let err = factory.validate(&url, &options).unwrap_err();
            assert!(
                matches!(
                    err,
                    SourceConfigError::InvalidOptions { scheme: "http", .. }
                ),
                "{options}: {err}"
            );
        }
    }

    #[test]
    fn rfc9110_4_2_2_the_tls_options_are_checked_at_put() {
        let factory = HttpFactory;
        let https = url("https://cam.local/s.m3u8");
        let http = url("http://cam.local/s.m3u8");
        for (options, trust) in [
            (json!({}), "Roots"),
            (json!({ "tls_fingerprint": PIN }), "Pin"),
            (json!({ "insecure_tls": true }), "Insecure"),
        ] {
            let source = factory.validate(&https, &options).unwrap();
            let debug = format!("{source:?}");
            assert!(debug.contains("server_name"), "{options}: {debug}");
            assert!(debug.contains(trust), "{options}: {debug}");
        }
        let both = json!({ "tls_fingerprint": PIN, "insecure_tls": true });
        let err = factory.validate(&https, &both).unwrap_err();
        assert!(
            matches!(err, SourceConfigError::InvalidOptions { .. })
                && err.to_string().contains("not both"),
            "{err}"
        );
        let err = factory
            .validate(&https, &json!({ "tls_fingerprint": "ab:cd" }))
            .unwrap_err();
        assert!(
            matches!(err, SourceConfigError::InvalidOptions { .. })
                && err.to_string().contains("64 hex digits"),
            "{err}"
        );
        for options in [
            json!({ "tls_fingerprint": PIN }),
            json!({ "insecure_tls": true }),
        ] {
            let err = factory.validate(&http, &options).unwrap_err();
            assert!(
                matches!(err, SourceConfigError::InvalidOptions { .. })
                    && err.to_string().contains("https:// only"),
                "{options}: {err}"
            );
        }
        assert!(
            factory
                .validate(&http, &json!({ "insecure_tls": false }))
                .is_ok()
        );
        let bad_host = url("https://a!b/");
        let err = factory.validate(&bad_host, &json!({})).unwrap_err();
        assert!(
            matches!(err, SourceConfigError::InvalidUrl { scheme: "http", .. })
                && err.to_string().contains("TLS server name"),
            "{err}"
        );
        // The same host over plain HTTP needs no server name.
        assert!(factory.validate(&url("http://a!b/"), &json!({})).is_ok());
    }
}

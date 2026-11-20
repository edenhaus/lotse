//! The `http` and `https` protocols' factory: options checked, the source
//! built.

use lotse_core::source::{Source, SourceCapabilities, SourceConfigError, SourceFactory};
use lotse_core::source_url::SourceUrl;
use lotse_tls::{TlsTarget, Trust};

use crate::options::{HttpOptions, HttpsOptions};
use crate::source::{HttpSource, PROTOCOL, TLS_PROTOCOL};

/// RFC 9110 §4.2.1: the default port of `http://`.
pub const DEFAULT_PORT: u16 = 80;

/// RFC 9110 §4.2.2: the default port of `https://`.
pub const DEFAULT_TLS_PORT: u16 = 443;

/// The factory. It holds nothing: an HTTP source connects to its server
/// directly.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpFactory;

/// `options` parsed as `protocol`'s, or why not.
fn parse<T: serde::de::DeserializeOwned>(
    protocol: &'static str,
    options: &serde_json::Value,
) -> Result<T, SourceConfigError> {
    serde_json::from_value(options.clone()).map_err(|err| SourceConfigError::InvalidOptions {
        protocol,
        message: err.to_string(),
    })
}

/// An `https` source's options as the source runs with them, and its TLS
/// target (RFC 9110 §4.2.2), whose pin and host are checked here.
fn https(
    url: &SourceUrl,
    options: HttpsOptions,
) -> Result<(HttpOptions, TlsTarget), SourceConfigError> {
    let HttpsOptions {
        timeout_ms,
        max_bandwidth,
        tls,
    } = options;
    let trust = Trust::try_from(&tls).map_err(|err| SourceConfigError::InvalidOptions {
        protocol: TLS_PROTOCOL,
        message: err.to_string(),
    })?;
    let target =
        TlsTarget::new(url.host(), trust).map_err(|message| SourceConfigError::InvalidUrl {
            protocol: TLS_PROTOCOL,
            message,
        })?;
    let options = HttpOptions {
        timeout_ms,
        max_bandwidth,
    };
    Ok((options, target))
}

impl SourceFactory for HttpFactory {
    fn protocols(&self) -> &'static [&'static str] {
        &[PROTOCOL, TLS_PROTOCOL]
    }

    /// Nothing goes back to the server: no backchannel.
    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities { backchannel: false }
    }

    fn default_port(&self, protocol: &str) -> Option<u16> {
        Some(if protocol == TLS_PROTOCOL {
            DEFAULT_TLS_PORT
        } else {
            DEFAULT_PORT
        })
    }

    /// `url`'s scheme picks the protocol, whose options `options` must
    /// be: the supervisor hands an `https` source's here only with an
    /// `https://` URL.
    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError> {
        let source = if url.scheme() == TLS_PROTOCOL {
            let (options, tls) = https(url, parse(TLS_PROTOCOL, options)?)?;
            HttpSource::new(url.clone(), options, Some(tls))
        } else {
            HttpSource::new(url.clone(), parse(PROTOCOL, options)?, None)
        };
        Ok(Box::new(source))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use serde_json::json;

    use super::*;

    const PIN: &str = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";

    fn url(input: &str) -> SourceUrl {
        SourceUrl::parse(input).unwrap()
    }

    #[test]
    fn the_factory_serves_http_and_https_without_a_backchannel() {
        let factory = HttpFactory;
        assert_eq!(factory.protocols(), ["http", "https"]);
        assert!(!factory.capabilities().backchannel);
    }

    #[test]
    fn rfc9110_4_2_1_http_defaults_to_port_80_and_4_2_2_https_to_443() {
        let factory = HttpFactory;
        assert_eq!(factory.default_port("http"), Some(80));
        assert_eq!(factory.default_port("https"), Some(443));
    }

    #[test]
    fn empty_options_are_the_defaults_and_the_source_describes_itself_redacted() {
        let factory = HttpFactory;
        let url = url("http://user:pass@cam.local/live/index.m3u8");
        let source = factory.validate(&url, &json!({})).unwrap();
        let described = source.describe();
        assert_eq!(described.protocol, "http");
        assert_eq!(described.url.as_ref(), Some(&url));
        assert!(!described.url.as_ref().unwrap().to_string().contains("pass"));
        assert_eq!(
            described.options,
            json!({ "timeout_ms": 10_000, "max_bandwidth": null })
        );
        assert_eq!(source.connection_options(), described.options);
        // `{}` and the defaults spelled out are the same connection.
        let spelled = factory
            .validate(
                &url,
                &json!({ "timeout_ms": 10_000, "max_bandwidth": null }),
            )
            .unwrap();
        assert_eq!(spelled.connection_options(), source.connection_options());
        for other in [
            json!({ "max_bandwidth": 1_000_000 }),
            json!({ "timeout_ms": 5_000 }),
        ] {
            let built = factory.validate(&url, &other).unwrap();
            assert_ne!(
                built.connection_options(),
                source.connection_options(),
                "{other}"
            );
        }
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
            json!({ "tls": "insecure" }),
            json!({ "max_bandwidth": -1 }),
        ] {
            let err = factory.validate(&url, &options).unwrap_err();
            assert!(
                matches!(
                    err,
                    SourceConfigError::InvalidOptions {
                        protocol: "http",
                        ..
                    }
                ),
                "{options}: {err}"
            );
        }
    }

    #[test]
    fn rfc9110_4_2_2_https_runs_with_the_trust_it_names() {
        let factory = HttpFactory;
        let https = url("https://cam.local/s.m3u8");
        let source = factory.validate(&https, &json!({})).unwrap();
        assert_eq!(source.describe().protocol, "https");
        assert_eq!(
            source.describe().options,
            json!({ "timeout_ms": 10_000, "max_bandwidth": null, "tls": "roots" })
        );
        for (options, trust, shown) in [
            (json!({}), "Roots", json!("roots")),
            (json!({ "tls": "insecure" }), "Insecure", json!("insecure")),
            (
                json!({ "tls": { "pin": PIN.replace(':', "") } }),
                "Pin",
                json!({ "pin": PIN.to_lowercase() }),
            ),
        ] {
            let built = factory.validate(&https, &options).unwrap();
            let debug = format!("{built:?}");
            assert!(debug.contains("server_name"), "{options}: {debug}");
            assert!(debug.contains(trust), "{options}: {debug}");
            // Every spelling of one pin is one key.
            assert_eq!(built.connection_options()["tls"], shown, "{options}");
        }
        // A refused pin is not repeated: a value pasted there can carry
        // credentials.
        let err = factory
            .validate(
                &https,
                &json!({ "tls": { "pin": "https://u:hunter2@cam/" } }),
            )
            .unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
        let err = factory
            .validate(&https, &json!({ "tls": { "pin": "ab:cd" } }))
            .unwrap_err();
        assert!(
            matches!(
                &err,
                SourceConfigError::InvalidOptions {
                    protocol: "https",
                    ..
                }
            ) && err.to_string().contains("64 hex digits"),
            "{err}"
        );
        let err = factory
            .validate(&https, &json!({ "tls": "none" }))
            .unwrap_err();
        assert!(
            matches!(
                err,
                SourceConfigError::InvalidOptions {
                    protocol: "https",
                    ..
                }
            ),
            "{err}"
        );
        let bad_host = url("https://a!b/");
        let err = factory.validate(&bad_host, &json!({})).unwrap_err();
        assert!(
            matches!(
                err,
                SourceConfigError::InvalidUrl {
                    protocol: "https",
                    ..
                }
            ) && err.to_string().contains("TLS server name"),
            "{err}"
        );
        // The same host over plain HTTP needs no server name.
        assert!(factory.validate(&url("http://a!b/"), &json!({})).is_ok());
    }
}

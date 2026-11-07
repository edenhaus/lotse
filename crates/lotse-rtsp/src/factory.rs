//! The `rtsp` and `rtsps` protocols' factory: options checked, the source
//! built.

use lotse_core::source::{Source, SourceCapabilities, SourceConfigError, SourceFactory};
use lotse_core::source_url::SourceUrl;
use lotse_tls::{TlsTarget, Trust};

use crate::options::{RtspOptions, RtspsOptions, Transport};
use crate::source::RtspSource;

/// The `rtsp` protocol (RFC 2326), also the name the source's tracks and
/// logs carry for both protocols.
pub const PROTOCOL: &str = "rtsp";

/// The `rtsps` protocol: RTSP over TLS (RFC 7826 §19.2).
pub const TLS_PROTOCOL: &str = "rtsps";

/// RFC 2326 §3.2: the default port of `rtsp://`.
pub const DEFAULT_PORT: u16 = 554;

/// RFC 7826 §4.2 and §19.2 (and the IANA service registry): the default
/// port of `rtsps://`. RFC 2326 predates the scheme; cameras use it with
/// RTSP 1.0.
pub const DEFAULT_TLS_PORT: u16 = 322;

/// Whether the RTSP source can send on the camera's ONVIF backchannel, as
/// [`SourceFactory::capabilities`] declares it: the worker offers talk-back
/// on this protocol's streams, and the daemon announces `two_way_audio`,
/// only when it is `true`. It is: the source probes the backchannel and
/// offers it, and a talker's claim opens it in a session of its own whose
/// packets go out through retina's send path ([`crate::backchannel`]).
pub const BACKCHANNEL: bool = true;

/// The factory: every source it builds dials the camera itself, on the
/// connect ports the worker is given ([`SourceFactory::default_port`]).
#[derive(Debug, Default)]
pub struct RtspFactory;

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

/// An `rtsps` source's options as the source runs with them: its media
/// interleaved on the TLS connection (RFC 7826 §19.2; over UDP it would
/// leave the TLS session as plain RTP, and SRTP is not supported), and
/// its TLS target, whose pin and host are checked here.
fn rtsps(
    url: &SourceUrl,
    options: RtspsOptions,
) -> Result<(RtspOptions, TlsTarget), SourceConfigError> {
    let RtspsOptions {
        backchannel,
        timeout_ms,
        user_agent,
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
    let options = RtspOptions {
        transport: Transport::Tcp,
        backchannel,
        timeout_ms,
        user_agent,
    };
    Ok((options, target))
}

impl SourceFactory for RtspFactory {
    fn protocols(&self) -> &'static [&'static str] {
        &[PROTOCOL, TLS_PROTOCOL]
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            backchannel: BACKCHANNEL,
        }
    }

    fn default_port(&self, protocol: &str) -> Option<u16> {
        Some(if protocol == TLS_PROTOCOL {
            DEFAULT_TLS_PORT
        } else {
            DEFAULT_PORT
        })
    }

    /// `url`'s scheme picks the protocol, whose options `options` must
    /// be: the supervisor hands an `rtsps` source's here only with an
    /// `rtsps://` URL.
    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError> {
        let source = if url.scheme() == TLS_PROTOCOL {
            let (options, tls) = rtsps(url, parse(TLS_PROTOCOL, options)?)?;
            RtspSource::new(url.clone(), options, Some(tls))
        } else {
            RtspSource::new(url.clone(), parse(PROTOCOL, options)?, None)
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

    #[test]
    fn the_factory_validates_the_rtsp_options() {
        let factory = RtspFactory;
        assert_eq!(factory.protocols(), ["rtsp", "rtsps"]);
        assert!(factory.capabilities().backchannel, "the ONVIF backchannel");
        let url = SourceUrl::parse("rtsp://user:pass@192.168.1.10/h264").unwrap();
        let source = factory.validate(&url, &json!({})).unwrap();
        let described = source.describe();
        assert_eq!(described.protocol, "rtsp");
        assert_eq!(described.url.as_ref(), Some(&url));
        assert_eq!(
            described.options,
            json!({ "transport": "tcp", "backchannel": false, "timeout_ms": 10_000, "user_agent": null })
        );
        assert_eq!(
            source.connection_options(),
            json!({ "transport": "tcp", "timeout_ms": 10_000, "user_agent": null })
        );
        // ONVIF Streaming Specification §5.3.1: the `Require` header only
        // for a stream that opted in, on the same connection either way.
        assert!(!source.wants_backchannel(), "opt-in");
        let talking = factory
            .validate(&url, &json!({ "backchannel": true }))
            .unwrap();
        assert!(talking.wants_backchannel());
        assert_eq!(talking.describe().options["backchannel"], true);
        assert_eq!(talking.connection_options(), source.connection_options());
        // Spelled out, the same camera session.
        let spelled = factory
            .validate(&url, &json!({ "timeout_ms": 10_000, "transport": "tcp" }))
            .unwrap();
        assert_eq!(spelled.connection_options(), source.connection_options());
        for other in [
            json!({ "transport": "udp" }),
            json!({ "timeout_ms": 5_000 }),
            json!({ "user_agent": "Client/2026.10 (lotse)" }),
        ] {
            let built = factory.validate(&url, &other).unwrap();
            assert_ne!(
                built.connection_options(),
                source.connection_options(),
                "{other}"
            );
        }
        for bad in [
            json!({ "nope": 1 }),
            json!({ "tls": "insecure" }),
            json!({ "user_agent": "lotse\r\nX: 1" }),
            json!({ "transport": "sctp" }),
        ] {
            let err = factory.validate(&url, &bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    SourceConfigError::InvalidOptions {
                        protocol: "rtsp",
                        ..
                    }
                ),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn rtsps_defaults_to_port_322_and_rtsp_to_554_rfc7826_4_2() {
        let factory = RtspFactory;
        assert_eq!(factory.default_port("rtsp"), Some(554));
        assert_eq!(factory.default_port("rtsps"), Some(322));
    }

    #[test]
    fn rfc7826_19_2_rtsps_runs_interleaved_with_the_trust_it_names() {
        let factory = RtspFactory;
        let rtsps = SourceUrl::parse("rtsps://cam.local/").unwrap();
        let source = factory.validate(&rtsps, &json!({})).unwrap();
        let described = source.describe();
        assert_eq!(described.protocol, "rtsps");
        assert_eq!(
            described.options,
            json!({ "backchannel": false, "timeout_ms": 10_000, "user_agent": null, "tls": "roots" })
        );
        assert!(
            format!("{source:?}").contains("transport: Tcp"),
            "{source:?}"
        );
        for (options, trust) in [
            (json!({ "tls": "insecure" }), json!("insecure")),
            (
                json!({ "tls": { "pin": PIN } }),
                json!({ "pin": PIN.to_lowercase() }),
            ),
            (
                json!({ "tls": { "pin": PIN.replace(':', "") } }),
                json!({ "pin": PIN.to_lowercase() }),
            ),
        ] {
            let built = factory.validate(&rtsps, &options).unwrap();
            assert_eq!(built.describe().options["tls"], trust, "{options}");
            // Every spelling of one pin is one key; each trust its own.
            assert_eq!(built.connection_options()["tls"], trust, "{options}");
            assert_ne!(built.connection_options(), source.connection_options());
        }
        let key = source.connection_options();
        assert!(key.get("backchannel").is_none(), "{key}");
        let err = factory
            .validate(&rtsps, &json!({ "tls": { "pin": "ab:cd" } }))
            .unwrap_err();
        assert!(
            matches!(
                &err,
                SourceConfigError::InvalidOptions {
                    protocol: "rtsps",
                    ..
                }
            ) && err.to_string().contains("64 hex digits"),
            "{err}"
        );
        // Its media never leaves the TLS session: no transport to choose.
        let err = factory
            .validate(&rtsps, &json!({ "transport": "udp" }))
            .unwrap_err();
        assert!(
            matches!(
                &err,
                SourceConfigError::InvalidOptions {
                    protocol: "rtsps",
                    ..
                }
            ) && err.to_string().contains("unknown field `transport`"),
            "{err}"
        );
        let bad_host = SourceUrl::parse("rtsps://a!b/").unwrap();
        let err = factory.validate(&bad_host, &json!({})).unwrap_err();
        assert!(
            matches!(
                err,
                SourceConfigError::InvalidUrl {
                    protocol: "rtsps",
                    ..
                }
            ) && err.to_string().contains("TLS server name"),
            "{err}"
        );
    }
}

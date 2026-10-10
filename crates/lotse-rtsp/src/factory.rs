//! The `rtsp` and `rtsps` schemes' factory: options checked, the source
//! built.

use std::net::TcpListener;
use std::sync::Arc;

use lotse_core::source::{Direction, Source, SourceCapabilities, SourceConfigError, SourceFactory};
use lotse_core::source_url::SourceUrl;
use lotse_tls::{TlsTarget, Trust};

use crate::options::{RtspOptions, Transport};
use crate::source::RtspSource;

/// The protocol name reported for every scheme of this factory.
pub const PROTOCOL: &str = "rtsp";

/// RFC 2326 §3.2: the default port of `rtsp://`.
pub const DEFAULT_PORT: u16 = 554;

/// RFC 7826 §4.2 and §19.2 (and the IANA service registry): the default
/// port of `rtsps://`. RFC 2326 predates the scheme; cameras use it with
/// RTSP 1.0.
pub const DEFAULT_TLS_PORT: u16 = 322;

/// The factory, with the loopback listener a sandboxed worker bound for
/// the `rtsps` relay before its sandbox, if any.
#[derive(Debug, Default)]
pub struct RtspFactory {
    /// The pre-bound relay listener; `None` binds one per attempt.
    relay: Option<Arc<TcpListener>>,
}

impl RtspFactory {
    /// A factory whose `rtsps` sources relay through `relay` when given
    /// ([`SourceFactory::loopback_relay`]).
    pub fn new(relay: Option<TcpListener>) -> Self {
        Self {
            relay: relay.map(Arc::new),
        }
    }
}

/// The `rtsps` target for `url` and `options`; `None` for `rtsp`. The TLS
/// options are refused on `rtsp`, and the pin and `insecure_tls` together.
fn tls_target(
    url: &SourceUrl,
    options: &RtspOptions,
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
    if url.scheme() != "rtsps" {
        return if trust == Trust::Roots {
            Ok(None)
        } else {
            Err(invalid(
                "tls_fingerprint and insecure_tls apply to rtsps:// only",
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

impl SourceFactory for RtspFactory {
    fn schemes(&self) -> &'static [&'static str] {
        &["rtsp", "rtsps"]
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            direction: Direction::Pull,
            backchannel: false,
            keyframe_request: false,
            snapshot_uri: false,
        }
    }

    fn default_port(&self, scheme: &str) -> Option<u16> {
        Some(if scheme == "rtsps" {
            DEFAULT_TLS_PORT
        } else {
            DEFAULT_PORT
        })
    }

    /// Both schemes: every connection reaches retina through the relay,
    /// which also sends the camera its receiver reports.
    fn loopback_relay(&self, _scheme: &str) -> bool {
        true
    }

    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError> {
        let options =
            RtspOptions::parse(options).map_err(|err| SourceConfigError::InvalidOptions {
                scheme: PROTOCOL,
                message: err.to_string(),
            })?;
        let tls = tls_target(url, &options)?;
        if tls.is_some() && options.transport == Transport::Udp {
            return Err(SourceConfigError::InvalidOptions {
                scheme: PROTOCOL,
                message: "transport udp is not available for rtsps://: the media would leave the TLS session as plain RTP (SRTP is not supported); use tcp".to_owned(),
            });
        }
        Ok(Box::new(RtspSource::new(
            url.clone(),
            options,
            tls,
            self.relay.clone(),
        )))
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

    const PIN: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn the_factory_validates_scheme_and_options() {
        let factory = RtspFactory::default();
        assert_eq!(factory.schemes(), ["rtsp", "rtsps"]);
        assert_eq!(factory.capabilities().direction, Direction::Pull);
        let url = SourceUrl::parse("rtsp://user:pass@192.168.1.10/h264").unwrap();
        let source = factory.validate(&url, &serde_json::Value::Null).unwrap();
        let described = source.describe();
        assert_eq!(described.protocol, "rtsp");
        assert_eq!(described.url, url);
        assert_eq!(described.options["transport"], "tcp");
        assert_eq!(
            source.connection_options(),
            RtspOptions::default().connection_key()
        );
        assert!(matches!(
            source.request_keyframe(),
            lotse_core::source::KeyframeRequest::Unsupported
        ));
        let udp = factory
            .validate(&url, &json!({ "transport": "udp" }))
            .unwrap();
        assert_eq!(udp.describe().options["transport"], "udp");
        assert_ne!(udp.connection_options(), source.connection_options());
        let err = factory.validate(&url, &json!({ "nope": 1 })).unwrap_err();
        assert!(
            matches!(err, SourceConfigError::InvalidOptions { .. }),
            "{err}"
        );
        // A user_agent retina would panic on is refused here, before a
        // worker builds a request with it.
        let err = factory
            .validate(&url, &json!({ "user_agent": "lotse\r\nX: 1" }))
            .unwrap_err();
        assert!(
            matches!(&err, SourceConfigError::InvalidOptions { message, .. } if message.contains("user_agent")),
            "{err}"
        );
        let agent = factory
            .validate(&url, &json!({ "user_agent": "Client/2026.10 (lotse)" }))
            .unwrap();
        assert_eq!(
            agent.describe().options["user_agent"],
            "Client/2026.10 (lotse)"
        );
    }

    #[test]
    fn rtsps_defaults_to_port_322_and_rtsp_to_554_rfc7826_4_2() {
        let factory = RtspFactory::default();
        assert_eq!(factory.default_port("rtsp"), Some(554));
        assert_eq!(factory.default_port("rtsps"), Some(322));
        assert!(factory.loopback_relay("rtsps"));
        assert!(
            factory.loopback_relay("rtsp"),
            "the receiver reports need the relay for rtsp too"
        );
    }

    #[test]
    fn rtsps_options_are_checked_at_put() {
        let factory = RtspFactory::new(None);
        let rtsps = SourceUrl::parse("rtsps://cam.local/").unwrap();
        let rtsp = SourceUrl::parse("rtsp://cam.local/").unwrap();
        for options in [
            json!({}),
            json!({ "tls_fingerprint": PIN }),
            json!({ "insecure_tls": true }),
        ] {
            assert!(factory.validate(&rtsps, &options).is_ok(), "{options}");
        }
        let both = json!({ "tls_fingerprint": PIN, "insecure_tls": true });
        let err = factory.validate(&rtsps, &both).unwrap_err();
        assert!(err.to_string().contains("not both"), "{err}");
        let err = factory
            .validate(&rtsps, &json!({ "tls_fingerprint": "ab:cd" }))
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
            let err = factory.validate(&rtsp, &options).unwrap_err();
            assert!(err.to_string().contains("rtsps:// only"), "{err}");
        }
        // RFC 7826 §19.2 protects the RTSP session; media over plain UDP
        // would leave it.
        let err = factory
            .validate(&rtsps, &json!({ "transport": "udp" }))
            .unwrap_err();
        assert!(
            matches!(err, SourceConfigError::InvalidOptions { .. })
                && err.to_string().contains("not available for rtsps://"),
            "{err}"
        );
        assert!(
            factory
                .validate(&rtsps, &json!({ "transport": "tcp" }))
                .is_ok()
        );
        let bad_host = SourceUrl::parse("rtsps://a!b/").unwrap();
        let err = factory.validate(&bad_host, &json!({})).unwrap_err();
        assert!(
            matches!(err, SourceConfigError::InvalidUrl { .. })
                && err.to_string().contains("TLS server name"),
            "{err}"
        );
    }
}

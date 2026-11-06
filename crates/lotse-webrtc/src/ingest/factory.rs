//! The `webrtc` scheme's factory: the URL and options checked, the source
//! built.

use lotse_core::source::{Source, SourceCapabilities, SourceConfigError, SourceFactory};
use lotse_core::source_url::SourceUrl;

use super::options::WebRtcOptions;
use super::source::WebRtcSource;

/// The scheme, which is also the protocol name the source reports.
pub const SCHEME: &str = "webrtc";

/// The factory of `webrtc://<label>` sources: the label (the camera's
/// entity id in the client, say `camera.front_door`) names the camera to
/// the client that relays its signaling; lotse never resolves it. Its
/// sources are signaled ([`SourceCapabilities::signaled`]) and offer no
/// backchannel (yet).
#[derive(Debug, Default, Clone, Copy)]
pub struct WebRtcSourceFactory;

/// Checks that `url` is a `webrtc://<label>` URL and nothing more: no
/// userinfo, no port, no path but an empty one or `/`, no query.
fn check_url(url: &SourceUrl) -> Result<(), SourceConfigError> {
    let invalid = |message: &str| {
        Err(SourceConfigError::InvalidUrl {
            scheme: SCHEME,
            message: format!("a webrtc:// URL names the camera's label only: {message}"),
        })
    };
    let inner = url.expose_url();
    if url.credentials().is_some() {
        return invalid("no userinfo");
    }
    if url.port().is_some() {
        return invalid("no port");
    }
    if !matches!(inner.path(), "" | "/") {
        return invalid("no path");
    }
    if inner.query().is_some() {
        return invalid("no query");
    }
    Ok(())
}

impl SourceFactory for WebRtcSourceFactory {
    fn schemes(&self) -> &'static [&'static str] {
        &[SCHEME]
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            backchannel: false,
            signaled: true,
        }
    }

    fn validate(
        &self,
        url: &SourceUrl,
        options: &serde_json::Value,
    ) -> Result<Box<dyn Source>, SourceConfigError> {
        check_url(url)?;
        let options =
            WebRtcOptions::parse(options).map_err(|err| SourceConfigError::InvalidOptions {
                scheme: SCHEME,
                message: err.to_string(),
            })?;
        Ok(Box::new(WebRtcSource::new(url.clone(), options)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use serde_json::json;

    use super::*;

    #[test]
    fn the_factory_takes_a_label_and_declares_a_signaled_source() {
        let factory = WebRtcSourceFactory;
        assert_eq!(factory.schemes(), ["webrtc"]);
        assert_eq!(
            factory.capabilities(),
            SourceCapabilities {
                backchannel: false,
                signaled: true,
            }
        );
        assert_eq!(factory.default_port("webrtc"), None);
        for spelled in ["webrtc://camera.front_door", "webrtc://Camera.Front_Door/"] {
            let url = SourceUrl::parse(spelled).unwrap();
            let source = factory.validate(&url, &serde_json::Value::Null).unwrap();
            let described = source.describe();
            assert_eq!(described.protocol, "webrtc");
            assert_eq!(described.url, url);
            assert_eq!(
                described.options,
                json!({ "data_channel": null, "audio": true })
            );
            assert_eq!(source.connection_options(), described.options);
            assert!(!source.wants_backchannel());
        }
        let url = SourceUrl::parse("webrtc://camera.nest").unwrap();
        let nest = factory
            .validate(&url, &json!({ "data_channel": "dataSendChannel" }))
            .unwrap();
        assert_eq!(
            nest.connection_options(),
            json!({ "data_channel": "dataSendChannel", "audio": true })
        );
        // Spelled differently, the same connection.
        let spelled_out = factory
            .validate(
                &url,
                &json!({ "data_channel": "dataSendChannel", "audio": true }),
            )
            .unwrap();
        assert_eq!(nest.connection_options(), spelled_out.connection_options());
    }

    #[test]
    fn rfc3986_3_a_webrtc_url_with_more_than_a_label_is_refused() {
        let factory = WebRtcSourceFactory;
        for (url, what) in [
            ("webrtc://user:secret@camera.front_door", "no userinfo"),
            ("webrtc://user@camera.front_door", "no userinfo"),
            ("webrtc://camera.front_door:8443", "no port"),
            ("webrtc://camera.front_door/stream", "no path"),
            ("webrtc://camera.front_door?token=1", "no query"),
            ("webrtc://camera.front_door/?token=1", "no query"),
        ] {
            let err = factory
                .validate(&SourceUrl::parse(url).unwrap(), &serde_json::Value::Null)
                .unwrap_err();
            assert_eq!(
                err,
                SourceConfigError::InvalidUrl {
                    scheme: "webrtc",
                    message: format!("a webrtc:// URL names the camera's label only: {what}"),
                },
                "{url}"
            );
        }
    }

    #[test]
    fn bad_options_are_refused_as_invalid_options() {
        let url = SourceUrl::parse("webrtc://camera.front_door").unwrap();
        let err = WebRtcSourceFactory
            .validate(&url, &json!({ "codec": "h264" }))
            .unwrap_err();
        assert!(
            matches!(&err, SourceConfigError::InvalidOptions { scheme: "webrtc", message } if message.contains("unknown field")),
            "{err}"
        );
    }
}

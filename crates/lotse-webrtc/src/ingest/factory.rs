//! The `webrtc` signaled protocol's factory: the options checked, the
//! source built.

use lotse_core::source::{SignaledSourceFactory, Source, SourceConfigError};

use super::options::WebRtcOptions;
use super::source::WebRtcSource;

/// The protocol's name: what `stream/put` names a WebRTC camera by
/// (`{"protocol": "webrtc"}`) and what its sources report.
pub const PROTOCOL: &str = "webrtc";

/// The factory of WebRTC camera sources. A camera has no address lotse
/// could connect to: the control-API client relays its signaling, and
/// the stream the source belongs to is its identity, so the factory takes
/// its options only. Its sources offer no backchannel (yet).
#[derive(Debug, Default, Clone, Copy)]
pub struct WebRtcSourceFactory;

impl SignaledSourceFactory for WebRtcSourceFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn validate(&self, options: &serde_json::Value) -> Result<Box<dyn Source>, SourceConfigError> {
        let options: WebRtcOptions = serde_json::from_value(options.clone()).map_err(|err| {
            SourceConfigError::InvalidOptions {
                protocol: PROTOCOL,
                message: err.to_string(),
            }
        })?;
        Ok(Box::new(WebRtcSource::new(options)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use serde_json::json;

    use super::*;

    #[test]
    fn the_factory_names_its_protocol_and_builds_a_source_without_an_address() {
        let factory = WebRtcSourceFactory;
        assert_eq!(factory.protocol(), "webrtc");
        let source = factory.validate(&json!({})).unwrap();
        let described = source.describe();
        assert_eq!(described.protocol, "webrtc");
        assert_eq!(described.url, None, "no address");
        assert_eq!(
            described.options,
            json!({ "data_channel": null, "audio": true })
        );
        assert_eq!(source.connection_options(), described.options);
        assert!(!source.wants_backchannel());
        let nest = factory
            .validate(&json!({ "data_channel": "dataSendChannel" }))
            .unwrap();
        assert_eq!(
            nest.connection_options(),
            json!({ "data_channel": "dataSendChannel", "audio": true })
        );
        // Spelled differently, the same connection.
        let spelled_out = factory
            .validate(&json!({ "data_channel": "dataSendChannel", "audio": true }))
            .unwrap();
        assert_eq!(nest.connection_options(), spelled_out.connection_options());
    }

    #[test]
    fn bad_options_are_refused_as_invalid_options() {
        let err = WebRtcSourceFactory
            .validate(&json!({ "codec": "h264" }))
            .unwrap_err();
        assert!(
            matches!(&err, SourceConfigError::InvalidOptions { protocol: "webrtc", message } if message.contains("unknown field")),
            "{err}"
        );
    }
}

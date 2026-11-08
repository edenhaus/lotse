//! The options a `webrtc` source runs with: [`WebRtcOptions`], declared as
//! the API's `stream/put` variant in `lotse_api_types::source`, which also
//! checks them (unknown fields, a data channel label that is empty, too
//! long or carries a control character, RFC 8832 §5.1).

pub use lotse_api_types::source::{MAX_LABEL_CHARS, WebRtcOptions};

/// `options` with every default applied: what `stream/get` reports
/// (nothing here is secret) and the options half of the connection key,
/// since each one changes the offer.
pub fn normalized(options: &WebRtcOptions) -> serde_json::Value {
    serde_json::json!(options)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use serde_json::json;

    use super::*;

    #[test]
    fn rfc8832_5_1_the_options_normalize_with_every_default() {
        let parsed: WebRtcOptions = serde_json::from_value(json!({})).unwrap();
        assert_eq!(
            normalized(&parsed),
            json!({ "data_channel": null, "audio": true })
        );
        let nest = WebRtcOptions {
            data_channel: Some("dataSendChannel".into()),
            audio: false,
        };
        assert_eq!(
            normalized(&nest),
            json!({ "data_channel": "dataSendChannel", "audio": false })
        );
        assert_eq!(MAX_LABEL_CHARS, 64);
    }
}

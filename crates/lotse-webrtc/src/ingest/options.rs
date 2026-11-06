//! The `options` of a `webrtc://` source as `stream/put` carries them.
//! Unknown fields are rejected, so a typo fails at `stream/put`, and so
//! does a data channel label that is empty, too long or carries a control
//! character.

use serde::{Deserialize, Deserializer, Serialize};

/// The longest `data_channel` label accepted, in characters. Not from a
/// spec (RFC 8832 §5.1 allows up to 65535 bytes); the label the cameras'
/// integrations ask for is a short name (Nest's `dataSendChannel`).
pub const MAX_LABEL_CHARS: usize = 64;

/// Whether `label` can be the data channel's label: 1 to
/// [`MAX_LABEL_CHARS`] characters, none of them a control character, so
/// it prints and logs as one line.
fn is_valid_label(label: &str) -> bool {
    let chars = label.chars().count();
    (1..=MAX_LABEL_CHARS).contains(&chars) && !label.chars().any(char::is_control)
}

/// Deserializes `data_channel`, refusing a label [`is_valid_label`]
/// rejects.
fn deserialize_label<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        Some(label) if !is_valid_label(&label) => Err(serde::de::Error::custom(format!(
            "data_channel must be 1 to {MAX_LABEL_CHARS} printable characters, not {label:?}"
        ))),
        other => Ok(other),
    }
}

/// The default of [`WebRtcOptions::audio`]: the camera's audio is offered
/// for.
const fn audio_default() -> bool {
    true
}

/// The typed options of a `webrtc://` source. Every field changes the
/// offer, so every field is part of the connection key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRtcOptions {
    /// The label of a data channel to offer beside the media (RFC 8831,
    /// RFC 8832), as the camera's integration asks for one: Nest refuses
    /// an offer without an `application` m-line and wants
    /// `dataSendChannel`. `None` (the default) offers none.
    #[serde(default, deserialize_with = "deserialize_label")]
    pub data_channel: Option<String>,
    /// Offer to receive the camera's audio (default `true`); `false`
    /// offers video only.
    #[serde(default = "audio_default")]
    pub audio: bool,
}

impl Default for WebRtcOptions {
    fn default() -> Self {
        Self {
            data_channel: None,
            audio: audio_default(),
        }
    }
}

impl WebRtcOptions {
    /// Parses `stream/put`'s untyped `options`: `null` is the defaults,
    /// an object is checked field by field, anything else is refused.
    ///
    /// # Errors
    ///
    /// What is wrong with them, for `invalid_request`.
    pub fn parse(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        match value {
            serde_json::Value::Null => Ok(Self::default()),
            serde_json::Value::Object(_) => serde_json::from_value(value.clone()),
            other => Err(serde::de::Error::custom(format!(
                "options must be an object, not {other}"
            ))),
        }
    }

    /// The options normalized, every default applied: what `stream/get`
    /// reports (nothing here is secret) and the options half of the
    /// connection key, since each one changes the offer.
    pub fn normalized(&self) -> serde_json::Value {
        serde_json::json!({
            "data_channel": self.data_channel,
            "audio": self.audio,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use serde_json::json;

    use super::*;

    #[test]
    fn null_and_empty_options_are_the_defaults() {
        for options in [serde_json::Value::Null, json!({})] {
            let parsed = WebRtcOptions::parse(&options).unwrap();
            assert_eq!(parsed, WebRtcOptions::default());
            assert!(parsed.audio);
            assert_eq!(parsed.data_channel, None);
            assert_eq!(
                parsed.normalized(),
                json!({ "data_channel": null, "audio": true })
            );
        }
    }

    #[test]
    fn rfc8832_5_1_a_data_channel_label_and_audio_off_are_taken() {
        let parsed =
            WebRtcOptions::parse(&json!({ "data_channel": "dataSendChannel", "audio": false }))
                .unwrap();
        assert_eq!(parsed.data_channel.as_deref(), Some("dataSendChannel"));
        assert!(!parsed.audio);
        assert_eq!(
            parsed.normalized(),
            json!({ "data_channel": "dataSendChannel", "audio": false })
        );
        let longest = "é".repeat(MAX_LABEL_CHARS);
        let parsed = WebRtcOptions::parse(&json!({ "data_channel": longest })).unwrap();
        assert_eq!(parsed.data_channel, Some(longest));
        // `null` spelled out is no data channel.
        let parsed = WebRtcOptions::parse(&json!({ "data_channel": null })).unwrap();
        assert_eq!(parsed.data_channel, None);
    }

    #[test]
    fn bad_labels_unknown_fields_and_non_objects_are_refused() {
        for label in [
            String::new(),
            "x".repeat(MAX_LABEL_CHARS + 1),
            "data\nchannel".to_owned(),
            "\u{7f}".to_owned(),
        ] {
            let err = WebRtcOptions::parse(&json!({ "data_channel": label })).unwrap_err();
            assert!(
                err.to_string()
                    .contains("data_channel must be 1 to 64 printable characters"),
                "{label:?}: {err}"
            );
        }
        let err = WebRtcOptions::parse(&json!({ "data_channel": 7 })).unwrap_err();
        assert!(err.to_string().contains("invalid type"), "{err}");
        let err = WebRtcOptions::parse(&json!({ "backchannel": true })).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        let err = WebRtcOptions::parse(&json!({ "audio": "yes" })).unwrap_err();
        assert!(err.to_string().contains("invalid type"), "{err}");
        let err = WebRtcOptions::parse(&json!([1])).unwrap_err();
        assert_eq!(err.to_string(), "options must be an object, not [1]");
    }
}

//! The `options` of an `rtsp://` or `rtsps://` source as `stream/put`
//! carries them.
//! Unknown fields are rejected, so a typo fails at `stream/put`, and so
//! does a `tls_fingerprint` that is not a SHA-256 in hex or a `user_agent`
//! that is not a header field value (RFC 7230 §3.2, RFC 2326 §12.41).

use serde::{Deserialize, Deserializer, Serialize};

use lotse_tls::Fingerprint;

/// The read deadline default, in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// The `User-Agent` the daemon announces.
pub const DEFAULT_USER_AGENT: &str = concat!("lotse/", env!("CARGO_PKG_VERSION"));

/// The longest `user_agent` accepted, in bytes: far above any product
/// token a camera logs, and small enough that a request header stays
/// short. Not from a spec; RFC 7230 §3.2.5 leaves the limit to the
/// implementation.
pub const MAX_USER_AGENT_LEN: usize = 256;

/// Whether `value` can be sent as the `User-Agent` header: RFC 2326
/// §12.41 makes it `1*(product | comment)`, so it is non-empty, and
/// RFC 7230 §3.2 makes it a `field-value` without `obs-text`, which retina
/// also refuses: `VCHAR` at both ends, `VCHAR`, `SP` or `HTAB` between,
/// so no CR, LF, NUL or other control byte, no surrounding whitespace and
/// nothing outside ASCII. At most [`MAX_USER_AGENT_LEN`] bytes.
fn is_valid_user_agent(value: &str) -> bool {
    let vchar = |b: &u8| matches!(b, 0x21..=0x7E);
    let inner = |b: &u8| vchar(b) || matches!(b, b' ' | b'\t');
    let bytes = value.as_bytes();
    bytes.len() <= MAX_USER_AGENT_LEN
        && bytes.first().is_some_and(vchar)
        && bytes.last().is_some_and(vchar)
        && bytes.iter().all(inner)
}

/// Deserializes `user_agent`, refusing a value [`is_valid_user_agent`]
/// rejects, so it fails at `stream/put` as `invalid_request` instead of
/// when the worker builds its first request: retina 0.4 unwraps the
/// header value there, and the panic aborts the worker on every attempt.
fn deserialize_user_agent<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        Some(text) if !is_valid_user_agent(&text) => Err(serde::de::Error::custom(format!(
            "user_agent must be 1 to {MAX_USER_AGENT_LEN} printable ASCII characters, with spaces or tabs only between them (RFC 7230 §3.2), not {text:?}"
        ))),
        other => Ok(other),
    }
}

/// How RTP reaches the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Interleaved over the RTSP connection; the default.
    #[default]
    Tcp,
    /// Separate UDP ports; opt-in from M3 for wired cameras.
    Udp,
}

/// Whether to ask the camera's ONVIF service for keyframes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnvifKeyframe {
    /// Probe the device service once per connection and use it if there.
    #[default]
    Auto,
    /// Never.
    Off,
}

/// The ONVIF endpoint a client can pass, so no probing is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnvifEndpoint {
    /// The device or media service URL.
    pub url: String,
    /// The media profile the stream belongs to.
    pub profile_token: String,
}

/// The typed options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RtspOptions {
    /// `tcp` (default) or `udp`.
    pub transport: Transport,
    /// Request the ONVIF backchannel if offered (M4).
    pub backchannel: bool,
    /// Keyframe requests through ONVIF.
    pub onvif_keyframe: OnvifKeyframe,
    /// The ONVIF endpoint, when known.
    pub onvif: Option<OnvifEndpoint>,
    /// SHA-256 pin of the camera's leaf certificate for `rtsps`: replaces
    /// the check against the embedded roots and the host name.
    pub tls_fingerprint: Option<Fingerprint>,
    /// Accept any certificate for `rtsps`; warned about on every
    /// connection. Exclusive with `tls_fingerprint`.
    pub insecure_tls: bool,
    /// The read deadline.
    pub timeout_ms: u64,
    /// The `User-Agent` to send instead of the default; a valid header
    /// field value, checked on parse.
    #[serde(deserialize_with = "deserialize_user_agent")]
    pub user_agent: Option<String>,
}

impl Default for RtspOptions {
    fn default() -> Self {
        Self {
            transport: Transport::Tcp,
            backchannel: true,
            onvif_keyframe: OnvifKeyframe::Auto,
            onvif: None,
            tls_fingerprint: None,
            insecure_tls: false,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            user_agent: None,
        }
    }
}

impl RtspOptions {
    /// Parses the untyped options of `stream/put`; `null` means defaults,
    /// anything but an object is an error.
    pub fn parse(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        match value {
            serde_json::Value::Null => Ok(Self::default()),
            serde_json::Value::Object(_) => serde_json::from_value(value.clone()),
            other => Err(serde::de::Error::custom(format!(
                "options must be an object, not {other}"
            ))),
        }
    }

    /// The options as `stream/get` reports them: nothing here is secret
    /// (a certificate fingerprint is public).
    pub fn redacted(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// The options half of the connection key:
    /// every field with its default applied, so `{}` and the defaults
    /// spelled out are one key, minus `backchannel`, which is deliberately
    /// not in the key so enabling talk-back never opens a second camera
    /// session.
    pub fn connection_key(&self) -> serde_json::Value {
        let mut key = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(fields) = key.as_object_mut() {
            let _backchannel = fields.remove("backchannel");
        }
        key
    }

    /// The `User-Agent` to send.
    pub fn user_agent(&self) -> &str {
        self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT)
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
    fn options_default_parse_strictly_and_report_themselves() {
        let defaults = RtspOptions::parse(&serde_json::Value::Null).unwrap();
        assert_eq!(defaults, RtspOptions::default());
        assert_eq!(defaults.timeout_ms, 10_000);
        assert!(defaults.backchannel);
        assert_eq!(defaults.user_agent(), DEFAULT_USER_AGENT);
        assert_eq!(RtspOptions::parse(&json!({})).unwrap(), defaults);
        let full = RtspOptions::parse(&json!({
            "transport": "udp", "backchannel": false, "onvif_keyframe": "off",
            "onvif": { "url": "http://cam/onvif/device_service", "profile_token": "p0" },
            "tls_fingerprint": PIN, "insecure_tls": true, "timeout_ms": 5000,
            "user_agent": "test/1"
        }))
        .unwrap();
        assert_eq!(full.transport, Transport::Udp);
        assert_eq!(full.onvif_keyframe, OnvifKeyframe::Off);
        assert_eq!(full.onvif.as_ref().unwrap().profile_token, "p0");
        assert_eq!(full.user_agent(), "test/1");
        assert_eq!(full.redacted()["timeout_ms"], 5000);
        assert_eq!(full.redacted()["tls_fingerprint"], PIN.to_lowercase());
        let err = RtspOptions::parse(&json!({ "tls_fingerprint": "ab:cd" })).unwrap_err();
        assert!(err.to_string().contains("64 hex digits"), "{err}");
        assert!(RtspOptions::parse(&json!({ "transports": "tcp" })).is_err());
        assert!(RtspOptions::parse(&json!({ "transport": "sctp" })).is_err());
        assert!(RtspOptions::parse(&json!({ "onvif": { "url": "x" } })).is_err());
        assert!(RtspOptions::parse(&json!([])).is_err());
    }

    #[test]
    fn a_user_agent_is_a_field_value_rfc7230_3_2_and_rfc2326_12_41() {
        let parse = |agent: serde_json::Value| RtspOptions::parse(&json!({ "user_agent": agent }));
        let longest = "a".repeat(MAX_USER_AGENT_LEN);
        for good in [
            "a",
            "~",
            "!",
            "lotse/1.0 (Linux; x86_64)",
            "a\tb",
            "a  b",
            longest.as_str(),
        ] {
            assert_eq!(parse(json!(good)).unwrap().user_agent(), good, "{good:?}");
        }
        assert_eq!(
            parse(serde_json::Value::Null).unwrap().user_agent(),
            DEFAULT_USER_AGENT
        );
        let too_long = "a".repeat(MAX_USER_AGENT_LEN + 1);
        for bad in [
            "",
            " ",
            "\t",
            " lotse",
            "lotse ",
            "\tlotse",
            "lotse\t",
            "lotse\r\nX-Injected: 1",
            "lotse\n",
            "lo\rtse",
            "lo\0tse",
            "lo\x7ftse",
            "lo\x01tse",
            "\x7f",
            "\u{e9}lotse",
            "lotse\u{e9}",
            "lo\u{e9}tse",
            too_long.as_str(),
        ] {
            let err = parse(json!(bad)).unwrap_err();
            assert!(
                err.to_string().contains("user_agent must be 1 to 256"),
                "{bad:?}: {err}"
            );
        }
        assert!(parse(json!(7)).is_err());
    }

    #[test]
    fn the_connection_key_applies_defaults_and_leaves_out_the_backchannel() {
        let key = |value: serde_json::Value| RtspOptions::parse(&value).unwrap().connection_key();
        let defaults = key(serde_json::Value::Null);
        assert_eq!(defaults["timeout_ms"], 10_000);
        assert_eq!(defaults["transport"], "tcp");
        assert!(defaults.get("backchannel").is_none(), "{defaults}");
        // Spelled out, reordered or with only the backchannel changed: the
        // same camera session.
        for same in [
            json!({}),
            json!({ "timeout_ms": 10_000, "transport": "tcp" }),
            json!({ "transport": "tcp", "timeout_ms": 10_000, "insecure_tls": false }),
            json!({ "backchannel": false }),
        ] {
            assert_eq!(key(same.clone()), defaults, "{same}");
        }
        for other in [
            json!({ "timeout_ms": 5_000 }),
            json!({ "user_agent": "test/1" }),
            json!({ "transport": "udp" }),
            json!({ "tls_fingerprint": PIN }),
            json!({ "insecure_tls": true }),
        ] {
            assert_ne!(key(other.clone()), defaults, "{other}");
        }
        // Every spelling of one pin is one key.
        assert_eq!(
            key(json!({ "tls_fingerprint": PIN })),
            key(json!({ "tls_fingerprint": PIN.replace(':', "").to_lowercase() }))
        );
        assert_eq!(
            key(json!({ "tls_fingerprint": PIN }))["tls_fingerprint"],
            PIN.to_lowercase()
        );
    }
}

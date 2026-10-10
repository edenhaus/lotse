//! The `options` of an `http://` or `https://` source as `stream/put`
//! carries them. Unknown fields are rejected, so a typo fails at
//! `stream/put`, and so does a `tls_fingerprint` that is not a SHA-256 in
//! hex. Which scheme may carry the TLS options is the factory's check.

use std::time::Duration;

use lotse_tls::Fingerprint;
use serde::{Deserialize, Serialize};

/// The default of `timeout_ms`, in milliseconds: as the RTSP source's.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// The typed options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpOptions {
    /// How long each connect, each answer and each wait for body bytes
    /// may take, in milliseconds.
    pub timeout_ms: u64,
    /// The highest variant `BANDWIDTH` (RFC 8216 §4.3.4.2, bits per
    /// second) to play from a multivariant playlist; `None` is uncapped.
    pub max_bandwidth: Option<u64>,
    /// SHA-256 pin of the server's leaf certificate for `https`: replaces
    /// the check against the embedded roots and the host name.
    pub tls_fingerprint: Option<Fingerprint>,
    /// Accept any certificate for `https`; warned about on every
    /// connection. Exclusive with `tls_fingerprint`.
    pub insecure_tls: bool,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_bandwidth: None,
            tls_fingerprint: None,
            insecure_tls: false,
        }
    }
}

impl HttpOptions {
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

    /// The options half of the connection key: every field with its
    /// default applied, so `{}` and the defaults spelled out are one key.
    /// Every option changes what is received, so none is left out.
    pub fn connection_key(&self) -> serde_json::Value {
        self.redacted()
    }

    /// The connect, answer and body deadline.
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
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
        let defaults = HttpOptions::parse(&serde_json::Value::Null).unwrap();
        assert_eq!(defaults, HttpOptions::default());
        assert_eq!(defaults.timeout_ms, 10_000);
        assert_eq!(defaults.timeout(), Duration::from_secs(10));
        assert_eq!(defaults.max_bandwidth, None);
        assert!(!defaults.insecure_tls);
        assert_eq!(HttpOptions::parse(&json!({})).unwrap(), defaults);
        let full = HttpOptions::parse(&json!({
            "timeout_ms": 5000, "max_bandwidth": 2_000_000,
            "tls_fingerprint": PIN, "insecure_tls": true
        }))
        .unwrap();
        assert_eq!(full.timeout(), Duration::from_secs(5));
        assert_eq!(full.max_bandwidth, Some(2_000_000));
        assert!(full.insecure_tls);
        assert_eq!(full.redacted()["timeout_ms"], 5000);
        assert_eq!(full.redacted()["tls_fingerprint"], PIN.to_lowercase());
        let err = HttpOptions::parse(&json!({ "tls_fingerprint": "ab:cd" })).unwrap_err();
        assert!(err.to_string().contains("64 hex digits"), "{err}");
        assert!(HttpOptions::parse(&json!({ "timeout": 5 })).is_err());
        assert!(HttpOptions::parse(&json!({ "max_bandwidth": -1 })).is_err());
        let err = HttpOptions::parse(&json!([])).unwrap_err();
        assert!(err.to_string().contains("must be an object"), "{err}");
    }

    #[test]
    fn the_connection_key_applies_defaults_and_keeps_every_option() {
        let key = |value: serde_json::Value| HttpOptions::parse(&value).unwrap().connection_key();
        let defaults = key(serde_json::Value::Null);
        assert_eq!(defaults["timeout_ms"], 10_000);
        for same in [
            json!({}),
            json!({ "timeout_ms": 10_000, "insecure_tls": false }),
            json!({ "max_bandwidth": null }),
        ] {
            assert_eq!(key(same.clone()), defaults, "{same}");
        }
        for other in [
            json!({ "timeout_ms": 5_000 }),
            json!({ "max_bandwidth": 1 }),
            json!({ "tls_fingerprint": PIN }),
            json!({ "insecure_tls": true }),
        ] {
            assert_ne!(key(other.clone()), defaults, "{other}");
        }
        assert_eq!(
            key(json!({ "tls_fingerprint": PIN })),
            key(json!({ "tls_fingerprint": PIN.replace(':', "").to_lowercase() }))
        );
    }
}

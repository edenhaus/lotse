//! The sources of `stream/put`, each named by its `protocol` and carrying
//! that protocol's own fields beside it, and the same shape `stream/get`
//! reports them in (the URL redacted).
//!
//! A URL protocol's name is its URL's scheme: `rtsp` and `rtsps` (RFC 2326,
//! RFC 7826 §19.2), `http` and `https` (RFC 9110 §4.2.1, §4.2.2; HLS, RFC
//! 8216, or MPEG-TS over them). `webrtc` is a camera whose signaling the
//! client relays (RFC 8829): it has no URL, and its stream is its identity.
//! Every protocol's fields are declared once, here: the `stream/put`
//! variant (`RtspSource`) and the options its factory parses
//! (`RtspOptions`, the same fields without the `url`) come from one
//! declaration (the `url_sources!` macro). Unknown fields are refused,
//! so a typo fails at `stream/put`, as do a `user_agent` that is no header
//! field value (RFC 7230 §3.2, RFC 2326 §12.41) and a data channel label
//! that is empty, too long or carries a control character. A `tls` pin's
//! shape is checked by the factory, which parses it.

use std::fmt;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

#[cfg(feature = "schema")]
use crate::limits::{MAX_PIN_CHARS, MAX_URL_CHARS};

/// The default of every `timeout_ms`, in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// The longest `user_agent` accepted, in bytes: far above any product
/// token a camera logs, and small enough that a request header stays
/// short. Not from a spec; RFC 7230 §3.2.5 leaves the limit to the
/// implementation.
pub const MAX_USER_AGENT_LEN: usize = 256;

/// The longest `data_channel` label accepted, in characters. Not from a
/// spec (RFC 8832 §5.1 allows up to 65535 bytes); the label the cameras'
/// integrations ask for is a short name (Nest's `dataSendChannel`).
pub const MAX_LABEL_CHARS: usize = 64;

/// [`DEFAULT_TIMEOUT_MS`], as serde's `default` takes it.
const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

/// `true`, as serde's `default` takes it: the default of
/// [`WebRtcOptions::audio`].
const fn default_true() -> bool {
    true
}

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
/// when the worker builds its first request: retina (0.4, and the 0.5
/// prototype pinned at `f65065f`) unwraps the header value there, and the
/// panic aborts the worker on every attempt.
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

/// `url` as `scheme://****` when it starts with a scheme (RFC 3986 §3.1:
/// a letter, then letters, digits, `+`, `-` and `.`) and `://`, else
/// `****`: the redacted form of a URL not parsed yet. A parsed source URL
/// prints its origin too (`lotse_core::secret::RedactedUrl`).
fn redact_unparsed(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, _))
            if scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            format!("{scheme}://****")
        }
        _ => "****".to_owned(),
    }
}

/// How an `rtsp` source's RTP reaches the daemon (RFC 2326 §10.12,
/// §12.39).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Interleaved over the RTSP connection (RFC 2326 §10.12); the
    /// default.
    #[default]
    Tcp,
    /// Separate UDP ports, for wired cameras.
    Udp,
}

/// Whom an `rtsps` or `https` source's TLS connection trusts: `"roots"`
/// (the default), `"insecure"`, or `{"pin": "<SHA-256 fingerprint>"}`.
/// RFC 7826 §19.2 and RFC 9110 §4.3.4 take the server's identity from
/// RFC 2818 §3.1, which `roots` checks. In every mode the handshake
/// signature is verified with the presented certificate's key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TlsTrust {
    /// The chain must end in an embedded root and the certificate must
    /// name the URL's host (RFC 2818 §3.1, RFC 6125).
    #[default]
    Roots,
    /// Any certificate; warned about on every connection.
    Insecure,
    /// Exactly the certificate with this SHA-256 fingerprint: 64 hex
    /// digits, upper or lower case, optionally with a colon between each
    /// pair (what `openssl x509 -fingerprint -sha256` prints). Chain,
    /// validity period and host name are not checked: a self-signed
    /// camera certificate rarely names the host it is reached by.
    Pin(#[cfg_attr(feature = "schema", schemars(length(max = MAX_PIN_CHARS)))] String),
}

impl TlsTrust {
    /// The pin, when it is one.
    pub fn pin(&self) -> Option<&str> {
        match self {
            Self::Pin(pin) => Some(pin),
            Self::Roots | Self::Insecure => None,
        }
    }
}

/// Declares the sources of one family of URL protocols (`rtsp` and
/// `rtsps`; `http` and `https`) from one list of fields each: the
/// family's `shared` fields, then each protocol's own. For each protocol
/// it declares the `stream/put` variant `$source` (the `url`, then the
/// fields) and `$options`, the same fields without the `url`, which the
/// protocol's factory parses from the options the supervisor hands it.
/// One declaration, so the two cannot drift: same names, types, defaults,
/// checks and documentation. `$source`'s `Debug` prints the URL's scheme
/// only: it is not parsed yet, so where its userinfo, path and query end
/// is not known, and any of them can carry a secret.
macro_rules! url_sources {
    (
        shared $shared:tt
        $(
            $(#[$doc:meta])*
            $protocol:literal => $source:ident, $options:ident $own:tt
        )+
    ) => {
        $(
            url_sources!(@join $(#[$doc])* $protocol => $source, $options $shared $own);
        )+
    };
    (@join
        $(#[$doc:meta])*
        $protocol:literal => $source:ident, $options:ident
        { $($shared:tt)* } { $($own:tt)* }
    ) => {
        url_sources!(@declare $(#[$doc])* $protocol => $source, $options { $($shared)* $($own)* });
    };
    (@declare
        $(#[$doc:meta])*
        $protocol:literal => $source:ident, $options:ident {
            $( $(#[$field_meta:meta])* pub $field:ident : $type:ty, )*
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "schema", derive(JsonSchema))]
        #[serde(deny_unknown_fields)]
        pub struct $source {
            #[doc = concat!(
                "The source URL, a `", $protocol, "://` one, credentials in its userinfo; ",
                "redacted everywhere it is reported, `stream/get` included."
            )]
            #[cfg_attr(feature = "schema", schemars(length(max = MAX_URL_CHARS)))]
            pub url: String,
            $( $(#[$field_meta])* pub $field: $type, )*
        }

        #[doc = concat!(
            "The fields of a `", $protocol, "` source but its `url`, as its factory parses ",
            "them: declared with [`", stringify!($source), "`]'s."
        )]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $options {
            $( $(#[$field_meta])* pub $field: $type, )*
        }

        /// Prints the URL's scheme only, and every other field.
        impl fmt::Debug for $source {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($source))
                    .field("url", &redact_unparsed(&self.url))
                    $( .field(stringify!($field), &self.$field) )*
                    .finish()
            }
        }
    };
}

url_sources! {
    shared {
        /// Ask the camera for its ONVIF backchannel, two-way audio's path
        /// to its speaker. Once the stream's session plays, a `DESCRIBE`
        /// with `Require: www.onvif.org/ver20/backchannel` (ONVIF Streaming
        /// Specification §5.3.1) on a connection of its own asks whether
        /// the camera has one, on every connect; a talker's claim opens it
        /// in a session of its own and its release closes it, so the
        /// camera's backchannel is free whenever nobody talks, and the
        /// session that plays the stream never carries the header. Off by
        /// default: the client knows which cameras talk back and opts a
        /// stream in, so a camera without one never sees the header. It
        /// does not tell connections apart: the connection a stream shares
        /// asks iff one of its streams does. Opting in or out never
        /// restarts the connection: an opt-in probes at once while the
        /// stream plays (else at its next connect), and an offer that
        /// requests talk-back meanwhile waits for the probe; the last
        /// opt-out drops what the probe found and frees the backchannel
        /// from its talker. A talk-back request the backchannel cannot
        /// serve is answered without it, with a `backchannel_declined`
        /// warning.
        #[serde(default)]
        pub backchannel: bool,
        /// The read deadline, in milliseconds.
        #[serde(default = "default_timeout_ms")]
        pub timeout_ms: u64,
        /// The `User-Agent` to send instead of the daemon's: 1 to 256
        /// printable ASCII characters, spaces or tabs only between them
        /// (RFC 7230 §3.2, RFC 2326 §12.41); `null`, the default, sends
        /// the daemon's.
        #[serde(default, deserialize_with = "deserialize_user_agent")]
        pub user_agent: Option<String>,
    }
    /// An `rtsp` source: an RTSP camera (RFC 2326), `rtsp://` URL.
    "rtsp" => RtspSource, RtspOptions {
        /// `tcp`, the default, interleaves RTP on the RTSP connection;
        /// `udp` takes it on ports of its own.
        #[serde(default)]
        pub transport: Transport,
    }
    /// An `rtsps` source: an RTSP camera over TLS (RFC 7826 §19.2),
    /// `rtsps://` URL. Its media is interleaved on the TLS connection,
    /// always: over UDP it would leave the TLS session as plain RTP (SRTP
    /// is not supported), so it has no `transport`.
    "rtsps" => RtspsSource, RtspsOptions {
        /// Whom the TLS connection trusts.
        #[serde(default)]
        pub tls: TlsTrust,
    }
}

url_sources! {
    shared {
        /// How long each connect, each answer and each wait for body
        /// bytes may take, in milliseconds.
        #[serde(default = "default_timeout_ms")]
        pub timeout_ms: u64,
        /// The highest variant `BANDWIDTH` (RFC 8216 §4.3.4.2, bits per
        /// second) to play from a multivariant playlist; `null`, the
        /// default, is uncapped.
        #[serde(default)]
        pub max_bandwidth: Option<u64>,
    }
    /// An `http` source: an HLS playlist (RFC 8216) or an MPEG-TS stream,
    /// `http://` URL.
    "http" => HttpSource, HttpOptions {}
    /// An `https` source: an HLS playlist or an MPEG-TS stream over TLS
    /// (RFC 9110 §4.2.2), `https://` URL.
    "https" => HttpsSource, HttpsOptions {
        /// Whom the TLS connection trusts.
        #[serde(default)]
        pub tls: TlsTrust,
    }
}

/// A `webrtc` source: a WebRTC camera whose signaling the client relays
/// (RFC 8829), so it has no URL and its stream is its identity; its
/// connection attempts offer through `signaling/subscribe`. Every field
/// changes the offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct WebRtcOptions {
    /// The label of a data channel to offer beside the media (RFC 8831,
    /// RFC 8832), as the camera's integration asks for one: Nest refuses
    /// an offer without an `application` m-line and wants
    /// `dataSendChannel`. 1 to 64 characters, none a control character;
    /// `null`, the default, offers none.
    #[serde(default, deserialize_with = "deserialize_label")]
    pub data_channel: Option<String>,
    /// Offer to receive the camera's audio (default `true`); `false`
    /// offers video only.
    #[serde(default = "default_true")]
    pub audio: bool,
}

/// The fake source of `lotse_core::test_util` (`fake://` URLs), in
/// builds with the `test-util` feature only: its options are whatever the
/// fake factory checks.
#[cfg(feature = "test-util")]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeSource {
    /// The `fake://` URL.
    pub url: String,
    /// The fake factory's options.
    #[serde(flatten)]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// Prints the URL's scheme only and the options' names.
#[cfg(feature = "test-util")]
impl fmt::Debug for FakeSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSource")
            .field("url", &redact_unparsed(&self.url))
            .field("options", &self.options.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The signaled fake source of `lotse_core::test_util`, in builds with the
/// `test-util` feature only.
#[cfg(feature = "test-util")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeSignaledSource {
    /// The fake factory's options.
    #[serde(flatten)]
    pub options: serde_json::Map<String, serde_json::Value>,
}

/// One entry of `stream/put`'s `sources`, named by its `protocol`, with
/// the protocol's own fields beside it; `stream/get` reports each source
/// in the same shape, defaults filled in and the URL redacted. A URL
/// protocol's `url` has the protocol's name as its scheme. The protocols
/// a build registered are `info.protocols`; one this build left out is
/// refused with `protocol_unsupported`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum SourceSpec {
    /// An RTSP camera.
    #[cfg_attr(feature = "schema", schemars(title = "RtspSource"))]
    Rtsp(RtspSource),
    /// An RTSP camera over TLS.
    #[cfg_attr(feature = "schema", schemars(title = "RtspsSource"))]
    Rtsps(RtspsSource),
    /// HLS or MPEG-TS over HTTP.
    #[cfg_attr(feature = "schema", schemars(title = "HttpSource"))]
    Http(HttpSource),
    /// HLS or MPEG-TS over HTTPS.
    #[cfg_attr(feature = "schema", schemars(title = "HttpsSource"))]
    Https(HttpsSource),
    /// A WebRTC camera whose signaling the client relays.
    #[cfg_attr(feature = "schema", schemars(title = "WebrtcSource"))]
    Webrtc(WebRtcOptions),
    /// The fake source, `test-util` builds only; never in the schema.
    #[cfg(feature = "test-util")]
    #[cfg_attr(feature = "schema", schemars(skip))]
    Fake(FakeSource),
    /// The signaled fake source, `test-util` builds only; never in the
    /// schema.
    #[cfg(feature = "test-util")]
    #[cfg_attr(feature = "schema", schemars(skip))]
    #[serde(rename = "fake-signaled")]
    FakeSignaled(FakeSignaledSource),
}

impl SourceSpec {
    /// The protocol's name, the `protocol` tag: for a URL protocol also
    /// its URL's scheme.
    pub const fn protocol(&self) -> &'static str {
        match self {
            Self::Rtsp(_) => "rtsp",
            Self::Rtsps(_) => "rtsps",
            Self::Http(_) => "http",
            Self::Https(_) => "https",
            Self::Webrtc(_) => "webrtc",
            #[cfg(feature = "test-util")]
            Self::Fake(_) => "fake",
            #[cfg(feature = "test-util")]
            Self::FakeSignaled(_) => "fake-signaled",
        }
    }

    /// The URL of a source lotse connects to; `None` for one whose
    /// signaling the client relays.
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Rtsp(source) => Some(&source.url),
            Self::Rtsps(source) => Some(&source.url),
            Self::Http(source) => Some(&source.url),
            Self::Https(source) => Some(&source.url),
            Self::Webrtc(_) => None,
            #[cfg(feature = "test-util")]
            Self::Fake(source) => Some(&source.url),
            #[cfg(feature = "test-util")]
            Self::FakeSignaled(_) => None,
        }
    }

    /// The same source with `url` in place of its URL (a redacted one,
    /// as `stream/get` reports it); a source without one is unchanged.
    #[must_use]
    pub fn with_url(self, url: String) -> Self {
        match self {
            Self::Rtsp(source) => Self::Rtsp(RtspSource { url, ..source }),
            Self::Rtsps(source) => Self::Rtsps(RtspsSource { url, ..source }),
            Self::Http(source) => Self::Http(HttpSource { url, ..source }),
            Self::Https(source) => Self::Https(HttpsSource { url, ..source }),
            #[cfg(feature = "test-util")]
            Self::Fake(source) => Self::Fake(FakeSource { url, ..source }),
            Self::Webrtc(source) => Self::Webrtc(source),
            #[cfg(feature = "test-util")]
            Self::FakeSignaled(source) => Self::FakeSignaled(source),
        }
    }

    /// The trust of a TLS protocol's source; `None` for the others.
    pub const fn tls(&self) -> Option<&TlsTrust> {
        match self {
            Self::Rtsps(source) => Some(&source.tls),
            Self::Https(source) => Some(&source.tls),
            _ => None,
        }
    }

    /// Every field but `protocol` and `url`, defaults filled in: the
    /// options the protocol's factory parses (`RtspOptions` for `rtsp`).
    pub fn options(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut fields = serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        let _protocol = fields.remove("protocol");
        let _url = fields.remove("url");
        fields
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};

    use super::*;

    const PIN: &str = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";

    fn spec(value: Value) -> SourceSpec {
        serde_json::from_value(value).unwrap()
    }

    fn refusal(value: Value) -> String {
        serde_json::from_value::<SourceSpec>(value)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn every_protocol_takes_its_own_fields_with_their_defaults() {
        for (given, protocol, url, filled) in [
            (
                json!({ "protocol": "rtsp", "url": "rtsp://cam/s1" }),
                "rtsp",
                Some("rtsp://cam/s1"),
                json!({ "transport": "tcp", "backchannel": false, "timeout_ms": 10_000, "user_agent": null }),
            ),
            (
                json!({ "protocol": "rtsps", "url": "rtsps://cam/s1" }),
                "rtsps",
                Some("rtsps://cam/s1"),
                json!({ "tls": "roots", "backchannel": false, "timeout_ms": 10_000, "user_agent": null }),
            ),
            (
                json!({ "protocol": "http", "url": "http://cam/live.m3u8" }),
                "http",
                Some("http://cam/live.m3u8"),
                json!({ "timeout_ms": 10_000, "max_bandwidth": null }),
            ),
            (
                json!({ "protocol": "https", "url": "https://cam/live.m3u8" }),
                "https",
                Some("https://cam/live.m3u8"),
                json!({ "timeout_ms": 10_000, "max_bandwidth": null, "tls": "roots" }),
            ),
            (
                json!({ "protocol": "webrtc" }),
                "webrtc",
                None,
                json!({ "data_channel": null, "audio": true }),
            ),
        ] {
            let parsed = spec(given.clone());
            assert_eq!(parsed.protocol(), protocol, "{given}");
            assert_eq!(parsed.url(), url, "{given}");
            assert_eq!(Value::Object(parsed.options()), filled, "{given}");
            // The wire form names the protocol and fills in every default,
            // and reads back the same.
            let wire = serde_json::to_value(&parsed).unwrap();
            assert_eq!(wire["protocol"], protocol);
            assert_eq!(wire.get("url").and_then(Value::as_str), url);
            assert_eq!(spec(wire), parsed);
        }
    }

    #[test]
    fn every_field_is_kept_and_u64_survives() {
        let rtsp = spec(json!({
            "protocol": "rtsp", "url": "rtsp://u:p@cam/s1", "transport": "udp",
            "backchannel": true, "timeout_ms": u64::MAX, "user_agent": "test/1"
        }));
        assert_eq!(
            Value::Object(rtsp.options()),
            json!({ "transport": "udp", "backchannel": true, "timeout_ms": u64::MAX, "user_agent": "test/1" })
        );
        let rtsps = spec(json!({
            "protocol": "rtsps", "url": "rtsps://cam/s1", "tls": { "pin": PIN }, "backchannel": true
        }));
        assert_eq!(rtsps.tls(), Some(&TlsTrust::Pin(PIN.into())));
        assert_eq!(rtsps.tls().and_then(TlsTrust::pin), Some(PIN));
        let https = spec(json!({
            "protocol": "https", "url": "https://cam/", "tls": "insecure", "max_bandwidth": 4_000_000
        }));
        assert_eq!(https.tls(), Some(&TlsTrust::Insecure));
        assert_eq!(TlsTrust::Insecure.pin(), None);
        assert_eq!(TlsTrust::Roots.pin(), None);
        assert_eq!(https.options()["max_bandwidth"], 4_000_000);
        for no_tls in [
            json!({ "protocol": "rtsp", "url": "rtsp://cam/" }),
            json!({ "protocol": "http", "url": "http://cam/" }),
            json!({ "protocol": "webrtc" }),
        ] {
            assert_eq!(spec(no_tls.clone()).tls(), None, "{no_tls}");
        }
        let webrtc = spec(
            json!({ "protocol": "webrtc", "data_channel": "dataSendChannel", "audio": false }),
        );
        assert_eq!(
            Value::Object(webrtc.options()),
            json!({ "data_channel": "dataSendChannel", "audio": false })
        );
    }

    /// The options a factory parses are the variant's fields without the
    /// `url`: what `options()` hands it parses as its options type, and
    /// serializes back to the same.
    fn options_round_trip<T: DeserializeOwned + Serialize>(given: &Value) {
        let options = Value::Object(spec(given.clone()).options());
        let parsed: T = serde_json::from_value(options.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), options, "{given}");
    }

    #[test]
    fn a_variants_options_are_its_factorys_options() {
        options_round_trip::<RtspOptions>(
            &json!({ "protocol": "rtsp", "url": "rtsp://cam/", "transport": "udp" }),
        );
        options_round_trip::<RtspsOptions>(
            &json!({ "protocol": "rtsps", "url": "rtsps://cam/", "tls": { "pin": PIN } }),
        );
        options_round_trip::<HttpOptions>(
            &json!({ "protocol": "http", "url": "http://cam/", "max_bandwidth": 1 }),
        );
        options_round_trip::<HttpsOptions>(
            &json!({ "protocol": "https", "url": "https://cam/", "tls": "insecure" }),
        );
        options_round_trip::<WebRtcOptions>(&json!({ "protocol": "webrtc", "audio": false }));
        // The options alone take no `url` and default as the variant does.
        let err =
            serde_json::from_value::<RtspOptions>(json!({ "url": "rtsp://cam/" })).unwrap_err();
        assert!(err.to_string().starts_with("unknown field `url`"), "{err}");
        let defaults: HttpsOptions = serde_json::from_value(json!({})).unwrap();
        assert_eq!(
            defaults,
            HttpsOptions {
                timeout_ms: DEFAULT_TIMEOUT_MS,
                max_bandwidth: None,
                tls: TlsTrust::Roots
            }
        );
    }

    #[test]
    fn a_source_is_refused_saying_what_is_wrong() {
        for (value, says) in [
            (json!({ "url": "rtsp://cam/" }), "missing field `protocol`"),
            (
                json!({ "protocol": "rtmp", "url": "rtmp://cam/" }),
                "unknown variant `rtmp`, expected one of `rtsp`, `rtsps`, `http`, `https`, `webrtc`",
            ),
            (json!({ "protocol": "rtsp" }), "missing field `url`"),
            (
                json!({ "protocol": "rtsps", "url": "rtsps://cam/", "transport": "udp" }),
                "unknown field `transport`",
            ),
            (
                json!({ "protocol": "rtsp", "url": "rtsp://cam/", "tls": "insecure" }),
                "unknown field `tls`",
            ),
            (
                json!({ "protocol": "http", "url": "http://cam/", "user_agent": "x" }),
                "unknown field `user_agent`",
            ),
            (
                json!({ "protocol": "webrtc", "url": "webrtc://cam/" }),
                "unknown field `url`",
            ),
            (
                json!({ "protocol": "rtsp", "url": "rtsp://cam/", "options": {} }),
                "unknown field `options`",
            ),
            (
                json!({ "protocol": "rtsp", "url": "rtsp://cam/", "transport": "sctp" }),
                "unknown variant `sctp`",
            ),
            (
                json!({ "protocol": "https", "url": "https://cam/", "tls": "pin" }),
                "invalid type: unit variant, expected newtype variant",
            ),
            (
                json!({ "protocol": "https", "url": "https://cam/", "tls": { "ca": "x" } }),
                "unknown variant `ca`",
            ),
            (
                json!({ "protocol": "http", "url": "http://cam/", "max_bandwidth": -1 }),
                "invalid value: integer `-1`",
            ),
            (
                json!({ "protocol": "webrtc", "audio": "yes" }),
                "invalid type: string \"yes\", expected a boolean",
            ),
            (json!({ "protocol": null }), "invalid type: null"),
            (
                json!({ "protocol": "rtsp", "url": null }),
                "invalid type: null",
            ),
        ] {
            let err = refusal(value.clone());
            assert!(err.starts_with(says), "{value}: {err}");
        }
    }

    #[test]
    fn a_user_agent_is_a_field_value_rfc7230_3_2_and_rfc2326_12_41() {
        let parse = |agent: Value| {
            serde_json::from_value::<SourceSpec>(
                json!({ "protocol": "rtsp", "url": "rtsp://cam/", "user_agent": agent }),
            )
        };
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
            assert_eq!(
                parse(json!(good)).unwrap().options()["user_agent"],
                good,
                "{good:?}"
            );
        }
        assert!(parse(Value::Null).unwrap().options()["user_agent"].is_null());
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
        // rtsps checks it the same way.
        let err =
            refusal(json!({ "protocol": "rtsps", "url": "rtsps://cam/", "user_agent": "a\n" }));
        assert!(err.contains("user_agent must be 1 to 256"), "{err}");
    }

    #[test]
    fn rfc8832_5_1_a_data_channel_label_is_1_to_64_printable_characters() {
        let longest = "é".repeat(MAX_LABEL_CHARS);
        let parsed = spec(json!({ "protocol": "webrtc", "data_channel": longest }));
        assert_eq!(parsed.options()["data_channel"], longest.as_str());
        // `null` spelled out is no data channel.
        let parsed = spec(json!({ "protocol": "webrtc", "data_channel": null }));
        assert!(parsed.options()["data_channel"].is_null());
        for label in [
            String::new(),
            "x".repeat(MAX_LABEL_CHARS + 1),
            "data\nchannel".to_owned(),
            "\u{7f}".to_owned(),
        ] {
            let err = refusal(json!({ "protocol": "webrtc", "data_channel": label }));
            assert!(
                err.contains("data_channel must be 1 to 64 printable characters"),
                "{label:?}: {err}"
            );
        }
        let err = refusal(json!({ "protocol": "webrtc", "data_channel": 7 }));
        assert!(err.contains("invalid type"), "{err}");
    }

    #[test]
    fn with_url_replaces_a_url_and_leaves_a_signaled_source_as_it_is() {
        for given in [
            json!({ "protocol": "rtsp", "url": "rtsp://u:p@cam/s1" }),
            json!({ "protocol": "rtsps", "url": "rtsps://u:p@cam/s1" }),
            json!({ "protocol": "http", "url": "http://u:p@cam/s1" }),
            json!({ "protocol": "https", "url": "https://u:p@cam/s1" }),
        ] {
            let parsed = spec(given.clone());
            let options = parsed.options();
            let shown = parsed.with_url("x://****@cam/****".into());
            assert_eq!(shown.url(), Some("x://****@cam/****"), "{given}");
            assert_eq!(shown.options(), options, "{given}");
            assert_eq!(shown.protocol(), given["protocol"], "{given}");
        }
        let webrtc = spec(json!({ "protocol": "webrtc", "audio": false }));
        assert_eq!(webrtc.clone().with_url("x://".into()), webrtc);
    }

    #[test]
    fn rfc3986_s3_1_debug_prints_a_source_urls_scheme_only() {
        let parsed = spec(json!({
            "protocol": "rtsp", "url": "rtsp://admin:hunter2@cam.local:554/h264?x=1",
            "user_agent": "test/1"
        }));
        assert_eq!(
            format!("{parsed:?}"),
            r#"Rtsp(RtspSource { url: "rtsp://****", backchannel: false, timeout_ms: 10000, user_agent: Some("test/1"), transport: Tcp })"#
        );
        // The command that carries it prints it the same way.
        let put = crate::parse_command(
            r#"{"id":1,"type":"stream/put","stream_id":"a","sources":[{"protocol":"rtsp","url":"rtsp://u:hunter2@c/"}]}"#,
        )
        .unwrap();
        let debug = format!("{put:?}");
        assert!(
            debug.contains(r#""rtsp://****""#) && !debug.contains("hunter2"),
            "{debug}"
        );
        // The wire form keeps the credentials a client sends.
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["url"],
            "rtsp://admin:hunter2@cam.local:554/h264?x=1"
        );
        for (given, shown) in [
            (
                json!({ "protocol": "rtsps", "url": "rtsps://u:p@cam/", "tls": { "pin": "ab" } }),
                r#"Rtsps(RtspsSource { url: "rtsps://****", backchannel: false, timeout_ms: 10000, user_agent: None, tls: Pin("ab") })"#,
            ),
            (
                json!({ "protocol": "http", "url": "http://u:p@cam/" }),
                r#"Http(HttpSource { url: "http://****", timeout_ms: 10000, max_bandwidth: None })"#,
            ),
            (
                json!({ "protocol": "https", "url": "https://u:p@cam/" }),
                r#"Https(HttpsSource { url: "https://****", timeout_ms: 10000, max_bandwidth: None, tls: Roots })"#,
            ),
            (
                json!({ "protocol": "webrtc" }),
                "Webrtc(WebRtcOptions { data_channel: None, audio: true })",
            ),
        ] {
            assert_eq!(format!("{:?}", spec(given)), shown);
        }
        for (url, shown) in [
            ("rtsp://cam.local/key?token=t", "rtsp://****"),
            ("https://u:pa/ss?w#rd@cam/", "https://****"),
            ("svc+x-1.2://cam", "svc+x-1.2://****"),
            ("rtsp://", "rtsp://****"),
            ("u:p@cam/key", "****"),
            ("://cam/key", "****"),
            ("1rtsp://cam/key", "****"),
            ("x@y://cam/key", "****"),
            ("rt sp://cam/key", "****"),
            ("", "****"),
        ] {
            assert_eq!(redact_unparsed(url), shown, "{url}");
        }
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn the_fake_sources_take_any_options_and_print_their_names_only() {
        let fake = spec(json!({ "protocol": "fake", "url": "fake://u:p@h/", "crash": true }));
        assert_eq!(
            (fake.protocol(), fake.url()),
            ("fake", Some("fake://u:p@h/"))
        );
        assert_eq!(Value::Object(fake.options()), json!({ "crash": true }));
        assert_eq!(
            format!("{fake:?}"),
            r#"Fake(FakeSource { url: "fake://****", options: ["crash"] })"#
        );
        assert_eq!(fake.tls(), None);
        let shown = fake.with_url("fake://h/".into());
        assert_eq!(
            serde_json::to_value(&shown).unwrap(),
            json!({ "protocol": "fake", "url": "fake://h/", "crash": true })
        );
        let signaled = spec(json!({ "protocol": "fake-signaled" }));
        assert_eq!(
            (signaled.protocol(), signaled.url()),
            ("fake-signaled", None)
        );
        assert!(signaled.options().is_empty());
        assert_eq!(signaled.clone().with_url("x://".into()), signaled);
    }
}

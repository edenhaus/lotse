//! The options an `rtsp` or `rtsps` source runs with: [`RtspOptions`], the
//! `rtsp` source's fields but its URL, declared with the API's `stream/put`
//! variant in `lotse_api_types::source`, which also checks them (unknown
//! fields, a `user_agent` that is no header field value, RFC 7230 §3.2,
//! RFC 2326 §12.41). An `rtsps` source's ([`RtspsOptions`]) become the
//! same, interleaved over TCP, beside its TLS target
//! ([`crate::RtspFactory`]).

pub use lotse_api_types::source::{MAX_USER_AGENT_LEN, RtspOptions, RtspsOptions, Transport};

/// The `User-Agent` the daemon announces.
pub const DEFAULT_USER_AGENT: &str = concat!("lotse/", env!("CARGO_PKG_VERSION"));

/// The `User-Agent` to send: the source's `user_agent`, else
/// [`DEFAULT_USER_AGENT`].
pub fn user_agent(options: &RtspOptions) -> &str {
    options.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT)
}

/// The options of `{}`: every default.
#[cfg(test)]
pub(crate) fn defaults() -> RtspOptions {
    serde_json::from_value(serde_json::json!({})).unwrap()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn the_user_agent_is_the_sources_or_the_daemons() {
        let defaults = defaults();
        assert_eq!(defaults.timeout_ms, 10_000);
        assert_eq!(defaults.transport, Transport::Tcp);
        assert!(!defaults.backchannel, "opt-in");
        assert_eq!(user_agent(&defaults), DEFAULT_USER_AGENT);
        assert!(DEFAULT_USER_AGENT.starts_with("lotse/"));
        let agent = RtspOptions {
            user_agent: Some("test/1".into()),
            ..defaults
        };
        assert_eq!(user_agent(&agent), "test/1");
    }
}

//! The options an `http` or `https` source runs with: [`HttpOptions`], the
//! `http` source's fields but its URL, declared with the API's `stream/put`
//! variant in `lotse_api_types::source`, which also checks them (unknown
//! fields, wrong types). An `https` source's ([`HttpsOptions`]) become the
//! same beside its TLS target ([`crate::HttpFactory`]).

use std::time::Duration;

pub use lotse_api_types::source::{HttpOptions, HttpsOptions};

/// The connect, answer and body deadline of `options` (`timeout_ms`).
pub const fn timeout(options: &HttpOptions) -> Duration {
    Duration::from_millis(options.timeout_ms)
}

/// The options of `{}`: every default.
#[cfg(test)]
pub(crate) fn defaults() -> HttpOptions {
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
    fn the_timeout_is_timeout_ms() {
        let defaults = defaults();
        assert_eq!(defaults.max_bandwidth, None);
        assert_eq!(timeout(&defaults), Duration::from_secs(10));
        let short = HttpOptions {
            timeout_ms: 5_000,
            ..defaults
        };
        assert_eq!(timeout(&short), Duration::from_secs(5));
    }
}

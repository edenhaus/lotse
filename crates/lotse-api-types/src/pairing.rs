//! The result of `pairing/create`: a one-time code that enrolls one client
//! of the control TLS listener.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What `pairing/create` answers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairingCreateResult {
    /// The code to paste into the client, `LOTSE1-<server pin>-<secret>`:
    /// the SHA-256 of the daemon's certificate and a 128-bit secret, each
    /// as lowercase hex. A secret: show it to the user, never log it.
    pub code: String,
    /// How long the code stays valid, in milliseconds.
    pub expires_in_ms: u64,
}

/// Redacts the code. `Serialize` is the wire form the client is sent, so
/// it keeps it; a serialized result is never logged.
impl fmt::Debug for PairingCreateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCreateResult")
            .field("code", &"****")
            .field("expires_in_ms", &self.expires_in_ms)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_docs_in_private_items, reason = "test code")]

    use super::*;

    #[test]
    fn debug_redacts_the_code_and_the_wire_form_keeps_it() {
        let code = "LOTSE1-00-0123456789abcdef0123456789abcdef";
        let result = PairingCreateResult {
            code: code.to_owned(),
            expires_in_ms: 600_000,
        };
        let debug = format!("{result:?}");
        assert!(!debug.contains("0123456789abcdef"), "{debug}");
        assert!(debug.contains("600000"), "{debug}");
        let wire = serde_json::to_string(&result).unwrap();
        assert!(wire.contains(code), "{wire}");
    }
}

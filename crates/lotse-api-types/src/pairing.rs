//! The result of `pairing/create`: a one-time code that enrolls one client
//! of the control TLS listener.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What `pairing/create` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairingCreateResult {
    /// The code to paste into the client, `LOTSE1-<server pin>-<secret>`:
    /// the SHA-256 of the daemon's certificate and a 128-bit secret, each
    /// as lowercase hex. A secret: show it to the user, never log it.
    pub code: String,
    /// How long the code stays valid, in milliseconds.
    pub expires_in_ms: u64,
}

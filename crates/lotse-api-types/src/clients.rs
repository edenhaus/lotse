//! The result of `clients/list`: who may connect to the control TLS
//! listener.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One client certificate the control TLS listener lets in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ControlClient {
    /// The SHA-256 of the client's certificate, as lowercase hex pairs
    /// joined by colons.
    pub pin: String,
    /// The pin comes from the configuration (`--control-clients`), which
    /// `clients/remove` cannot change; otherwise it was enrolled by pairing.
    pub fixed: bool,
    /// A control connection authenticated with this pin is open.
    pub connected: bool,
}

/// `clients/list`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ClientList {
    /// Every allowed pin, ordered by pin.
    pub clients: Vec<ControlClient>,
}

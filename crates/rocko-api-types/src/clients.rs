//! The result of `clients/list`: who may connect to the control TLS
//! listener, and with which role.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What a client certificate's pin may do on the control TLS listener. The
/// role is rocko's, kept with the pin; nothing in the certificate says it,
/// since a client makes its own certificate and its contents prove
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClientRole {
    /// The whole control API: the WebSocket, recordings' bytes and
    /// `GET /v0/metrics`. Pairing enrolls this role only.
    Control,
    /// `GET /v0/metrics` and nothing else: every other route is refused
    /// with 403.
    Metrics,
}

impl ClientRole {
    /// The role's name, as the API and the enrolled pins file write it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Metrics => "metrics",
        }
    }

    /// The role named `text`, exactly as [`Self::as_str`] writes it.
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Control, Self::Metrics]
            .into_iter()
            .find(|role| role.as_str() == text)
    }
}

/// One client certificate the control TLS listener lets in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ControlClient {
    /// The SHA-256 of the client's certificate, as lowercase hex pairs
    /// joined by colons.
    pub pin: String,
    /// The pin comes from the configuration (`--control-clients`,
    /// `--metrics-clients`), which `clients/remove` cannot change;
    /// otherwise it was enrolled by pairing or `clients/add`.
    pub fixed: bool,
    /// What the pin may do.
    pub role: ClientRole,
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[test]
    fn a_role_is_named_in_snake_case_and_parses_back_exactly() {
        for (role, name) in [
            (ClientRole::Control, "control"),
            (ClientRole::Metrics, "metrics"),
        ] {
            assert_eq!(role.as_str(), name);
            assert_eq!(ClientRole::parse(name), Some(role));
            assert_eq!(serde_json::to_value(role).unwrap(), name);
        }
        for refused in ["", "Control", "metric", "control "] {
            assert_eq!(ClientRole::parse(refused), None, "{refused:?}");
        }
    }
}

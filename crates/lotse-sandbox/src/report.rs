//! What `info.sandbox` reports: each hardening layer's status, so a
//! client can warn the user when the host kernel lacks one.

use serde::{Deserialize, Serialize};

use crate::Mode;

/// The status of one layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerStatus {
    /// Applied and active.
    Enforced,
    /// The kernel or platform does not offer it.
    Unavailable,
    /// The sandbox mode is `off`.
    Off,
}

impl LayerStatus {
    /// The API name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Unavailable => "unavailable",
            Self::Off => "off",
        }
    }
}

/// The Landlock layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandlockReport {
    /// Filesystem rules (ABI 1, Linux 5.13).
    pub fs: LayerStatus,
    /// TCP connect and bind rules (ABI 4, Linux 6.7).
    pub net: LayerStatus,
    /// The highest Landlock ABI the kernel supports; zero without Landlock.
    pub abi: u32,
}

/// The whole report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxReport {
    /// The `sandbox` setting.
    pub mode: Mode,
    /// The real uid after the drop.
    pub uid: u32,
    /// The real gid after the drop.
    pub gid: u32,
    /// `PR_SET_NO_NEW_PRIVS` is set.
    pub no_new_privs: bool,
    /// The seccomp allowlist.
    pub seccomp: LayerStatus,
    /// The Landlock layers.
    pub landlock: LandlockReport,
    /// Why layers are unavailable or only partly enforced, for the logs and
    /// a client's warning.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl SandboxReport {
    /// The report of a process running with `sandbox = off`.
    pub const fn off(uid: u32, gid: u32) -> Self {
        Self {
            mode: Mode::Off,
            uid,
            gid,
            no_new_privs: false,
            seccomp: LayerStatus::Off,
            landlock: LandlockReport {
                fs: LayerStatus::Off,
                net: LayerStatus::Off,
                abi: 0,
            },
            notes: Vec::new(),
        }
    }

    /// The layers that are unavailable, by API name.
    pub fn missing_layers(&self) -> Vec<&'static str> {
        [
            ("seccomp", self.seccomp),
            ("landlock.fs", self.landlock.fs),
            ("landlock.net", self.landlock.net),
        ]
        .into_iter()
        .filter(|(_, status)| *status == LayerStatus::Unavailable)
        .map(|(name, _)| name)
        .collect()
    }
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
    fn serializes_in_the_shape_of_info_sandbox() {
        let report = SandboxReport {
            mode: Mode::On,
            uid: 65534,
            gid: 65534,
            no_new_privs: true,
            seccomp: LayerStatus::Enforced,
            landlock: LandlockReport {
                fs: LayerStatus::Enforced,
                net: LayerStatus::Unavailable,
                abi: 3,
            },
            notes: Vec::new(),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "mode": "on", "uid": 65534, "gid": 65534, "no_new_privs": true,
                "seccomp": "enforced",
                "landlock": { "fs": "enforced", "net": "unavailable", "abi": 3 }
            })
        );
        assert_eq!(
            serde_json::from_value::<SandboxReport>(json).unwrap(),
            report
        );
        assert_eq!(report.missing_layers(), ["landlock.net"]);
        for status in [
            LayerStatus::Enforced,
            LayerStatus::Unavailable,
            LayerStatus::Off,
        ] {
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                serde_json::json!(status.name()),
                "the API name is the serialized one"
            );
        }
        assert_eq!(LayerStatus::Enforced.name(), "enforced");
        assert_eq!(LayerStatus::Unavailable.name(), "unavailable");
        assert_eq!(LayerStatus::Off.name(), "off");
    }

    #[test]
    fn notes_appear_only_when_present() {
        let mut report = SandboxReport::off(1, 2);
        assert!(!serde_json::to_string(&report).unwrap().contains("notes"));
        report
            .notes
            .push("landlock: not supported by this kernel".into());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"notes\":[\"landlock: not supported by this kernel\"]"));
    }
}

//! Who may own what the daemon keeps private before its privilege drop:
//! the control socket's directory, the data directory and the control
//! identity in it.
//!
//! The daemon started as some uid, and, started as root, drops to another
//! one after binding (`--user`). Each of these must belong to the uid it
//! started as, or, started as root only, to the uid it drops to. The
//! second case is the one a container image needs: its directories belong
//! to the account the daemon runs as, so a start as that account needs no
//! capability at all, and a start as root drops to the same account and
//! finds them its own.
//!
//! Accepting the drop target's directories widens nothing. Root reaches
//! any directory anyway, so the owner check never kept root out; it keeps
//! out a directory someone else could have planted or could still change.
//! A directory of the drop target belongs to the account the daemon runs
//! as for the rest of its life: what that account could put there, it
//! could do as the daemon. Any other owner is still refused, and the mode
//! rules are the same for every owner. A daemon that does not start as
//! root drops to nobody, so its own uid stays the only owner it accepts.

use std::fmt;

/// The uids that may own a directory (or a file in one) the daemon
/// checks before its privilege drop: [`Self::starting`] always, and
/// [`Self::drop_to`] only when [`Self::starting`] is root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owners {
    /// The uid the daemon started as.
    pub starting: u32,
    /// The uid it drops to after binding when started as root; ignored
    /// for any other start, which drops to nobody.
    pub drop_to: u32,
}

impl Owners {
    /// A start as `starting` that drops to `drop_to` if `starting` is root.
    pub const fn new(starting: u32, drop_to: u32) -> Self {
        Self { starting, drop_to }
    }

    /// Only `uid`: a process that drops to nobody, or a tool that reads as
    /// the account it runs as.
    pub const fn only(uid: u32) -> Self {
        Self::new(uid, uid)
    }

    /// Whether `uid` may own the directory or file: the starting uid, or,
    /// when that is root, the uid the daemon drops to.
    pub const fn accepts(self, uid: u32) -> bool {
        uid == self.starting || (self.starting == 0 && uid == self.drop_to)
    }
}

/// The accepted uids, for an error's message: `1000`, or `0 or 65532`.
impl fmt::Display for Owners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.starting == 0 && self.drop_to != 0 {
            write!(f, "{} or {}", self.starting, self.drop_to)
        } else {
            write!(f, "{}", self.starting)
        }
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
    fn a_start_as_root_accepts_root_and_the_uid_it_drops_to() {
        let owners = Owners {
            starting: 0,
            drop_to: 65532,
        };
        assert!(owners.accepts(0));
        assert!(owners.accepts(65532));
        assert!(!owners.accepts(65534));
        assert!(!owners.accepts(1000));
        assert_eq!(owners.to_string(), "0 or 65532");
    }

    #[test]
    fn any_other_start_accepts_its_own_uid_alone() {
        let owners = Owners {
            starting: 65532,
            drop_to: 1000,
        };
        assert!(owners.accepts(65532));
        assert!(!owners.accepts(1000), "drops to nobody, so no drop target");
        assert!(!owners.accepts(0), "root is no owner of a non-root start");
        assert_eq!(owners.to_string(), "65532");
        assert_eq!(
            Owners::only(1000),
            Owners {
                starting: 1000,
                drop_to: 1000
            }
        );
        assert_eq!(Owners::only(1000).to_string(), "1000");
    }

    #[test]
    fn root_that_drops_to_root_shows_one_owner() {
        let owners = Owners::only(0);
        assert!(owners.accepts(0));
        assert!(!owners.accepts(1));
        assert_eq!(owners.to_string(), "0");
    }
}

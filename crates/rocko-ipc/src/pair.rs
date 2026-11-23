//! The one place both channels create their socketpair, close-on-exec
//! from the moment the descriptors exist.
//!
//! Workers are spawned from runtime threads at any time, and `exec`
//! closes only descriptors marked `FD_CLOEXEC`, so a descriptor that
//! lacks the flag even briefly is inherited by whichever worker is
//! spawned meanwhile: the supervisor's end of a sibling's channel among
//! them. On Linux the kernel sets the flag as it creates the pair
//! (`socket(2)` `SOCK_CLOEXEC`, Linux 2.6.27, which `socketpair(2)`
//! accepts in its type argument); rustix passes the flag through and sets
//! nothing itself. macOS, a development platform only, has no
//! `SOCK_CLOEXEC`, so the flag is set by `fcntl(2)` `F_SETFD` right after,
//! which is not atomic with the creation.

use std::io;
use std::os::fd::OwnedFd;

use rustix::net::{AddressFamily, SocketFlags, SocketType};

/// A connected `AF_UNIX` pair of `kind`, both ends close-on-exec.
pub(crate) fn unix_pair(kind: SocketType) -> io::Result<(OwnedFd, OwnedFd)> {
    let (a, b) = rustix::net::socketpair(AddressFamily::UNIX, kind, pair_flags(), None)?;
    #[cfg(not(target_os = "linux"))]
    {
        rustix::io::fcntl_setfd(&a, rustix::io::FdFlags::CLOEXEC)?;
        rustix::io::fcntl_setfd(&b, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok((a, b))
}

/// The `socketpair` flags: `SOCK_CLOEXEC` on Linux, none elsewhere (see
/// the module). One function for both, so the mutation tests, which run on
/// Linux, never mutate a variant that is not built.
const fn pair_flags() -> SocketFlags {
    #[cfg(target_os = "linux")]
    {
        SocketFlags::CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        SocketFlags::empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use rustix::io::FdFlags;

    use super::*;

    #[test]
    fn both_ends_of_either_kind_are_close_on_exec_socket_2_sock_cloexec() {
        for kind in [SocketType::STREAM, SocketType::DGRAM] {
            let (a, b) = unix_pair(kind).unwrap();
            for fd in [&a, &b] {
                assert!(
                    rustix::io::fcntl_getfd(fd)
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_asks_the_kernel_for_the_flag_at_creation() {
        assert_eq!(pair_flags(), SocketFlags::CLOEXEC);
    }
}

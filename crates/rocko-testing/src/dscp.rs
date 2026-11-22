//! The DSCP a datagram arrived with, for the marking tests (RFC 8837 §5).
//!
//! Linux only: reading the `IP_TOS` and `IPV6_TCLASS` control messages
//! takes `recvmsg(2)` with a control buffer, which safe Rust gets from nix
//! there; the coverage host is Linux, and on macOS the marking tests only
//! send.

use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd};

use nix::sys::socket::{
    AddressFamily, ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage, getsockname,
    recvmsg, setsockopt, sockopt,
};

/// Asks the UDP socket `socket` to report the TOS byte (IPv4) or traffic
/// class (IPv6) of every datagram it receives.
pub fn report_marks(socket: &impl AsFd) -> nix::Result<()> {
    let local = getsockname::<SockaddrStorage>(socket.as_fd().as_raw_fd())?;
    if local.family() == Some(AddressFamily::Inet) {
        setsockopt(socket, sockopt::IpRecvTos, &true)
    } else {
        setsockopt(socket, sockopt::Ipv6RecvTClass, &true)
    }
}

/// The next datagram on `socket` (which [`report_marks`] set up), where it
/// came from, and the DSCP it carried: the TOS byte or traffic class
/// shifted past its two ECN bits.
pub fn recv_marked(socket: &impl AsFd) -> nix::Result<(Vec<u8>, Option<SocketAddr>, Option<u8>)> {
    let mut buf = vec![0_u8; 2048];
    let mut control = nix::cmsg_space!(libc::c_int);
    let mut iov = [IoSliceMut::new(&mut buf)];
    let message = recvmsg::<SockaddrStorage>(
        socket.as_fd().as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )?;
    let len = message.bytes;
    let from = message.address.and_then(|address| {
        address
            .as_sockaddr_in()
            .map(|v4| SocketAddr::V4((*v4).into()))
            .or_else(|| {
                address
                    .as_sockaddr_in6()
                    .map(|v6| SocketAddr::V6((*v6).into()))
            })
    });
    let mut dscp = None;
    for cmsg in message.cmsgs()? {
        match cmsg {
            ControlMessageOwned::Ipv4Tos(tos) => dscp = Some(tos >> 2),
            ControlMessageOwned::Ipv6TClass(class) => {
                dscp = u8::try_from(class).ok().map(|class| class >> 2);
            }
            _ => {}
        }
    }
    buf.truncate(len);
    Ok((buf, from, dscp))
}

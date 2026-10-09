//! The shared WebRTC UDP socket and the ICE-TCP listener, bound in the
//! main thread before the privilege drop.
//!
//! One dual-stack socket, fixed port, buffers requested at 4 MiB but
//! capped by the kernel (the effective sizes are reported), DSCP AF41
//! (RFC 8837 §5 for video) for both families of a dual-stack socket; the
//! workers mark the audio track's packets EF per datagram. The demux sets
//! it up for `quinn-udp` when its receive thread starts (non-blocking,
//! destination addresses, GRO), and the thread waits with a short timeout
//! so it can notice a stop.
//!
//! The host addresses, the local side of every host candidate
//! (RFC 8445 §5.1.1.1), are found when it is bound, before the sandbox
//! (the `hosts` module).

use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use super::hosts;

/// The socket buffer size asked for; the kernel caps it at
/// `net.core.rmem_max` / `wmem_max` without `CAP_NET_ADMIN`.
pub const REQUESTED_BUFFER: usize = 4 << 20;

/// DSCP AF41 (RFC 2597) as a TOS byte: video, per RFC 8837 §5.
pub const DSCP_AF41_TOS: u32 = 34 << 2;

/// How long the receive thread blocks before it checks for a stop.
pub const RECV_TIMEOUT: Duration = Duration::from_millis(250);

/// The listen backlog of the ICE-TCP listener.
const TCP_BACKLOG: i32 = 64;

/// The bound UDP socket and what the kernel granted.
#[derive(Debug)]
pub struct BoundUdp {
    /// The socket, shared by the receive thread and every worker.
    pub socket: Arc<UdpSocket>,
    /// Where it is bound.
    pub local: SocketAddr,
    /// The receive buffer the kernel granted.
    pub recv_buffer: usize,
    /// The send buffer the kernel granted.
    pub send_buffer: usize,
    /// An IPv6 socket that accepts IPv4 too.
    pub dual_stack: bool,
    /// The addresses datagrams arrive on, the default-route one of each
    /// family first: the host candidates' addresses.
    pub hosts: Vec<SocketAddr>,
}

/// Binds the shared UDP socket.
pub fn bind_udp(addr: SocketAddr) -> io::Result<BoundUdp> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    // Best effort: a kernel that refuses keeps the socket IPv6-only.
    let dual_stack =
        addr.is_ipv6() && socket.set_only_v6(false).is_ok() && !socket.only_v6().unwrap_or(true);
    tune(&socket, addr.is_ipv6());
    socket.bind(&addr.into())?;
    socket.set_read_timeout(Some(RECV_TIMEOUT))?;
    let local = socket
        .local_addr()?
        .as_socket()
        .ok_or(io::ErrorKind::AddrNotAvailable)?;
    let recv_buffer = socket.recv_buffer_size().unwrap_or(0);
    let send_buffer = socket.send_buffer_size().unwrap_or(0);
    // An empty list means sessions answer without a host candidate; the
    // `ready` event shows it too.
    let hosts = hosts::host_addresses(local, dual_stack, &hosts::probe, &hosts::interfaces);
    tracing::info!(
        %local,
        dual_stack,
        recv_buffer,
        send_buffer,
        requested = REQUESTED_BUFFER,
        hosts = ?hosts,
        "webrtc udp socket bound"
    );
    Ok(BoundUdp {
        socket: Arc::new(socket.into()),
        local,
        recv_buffer,
        send_buffer,
        dual_stack,
        hosts,
    })
}

/// Asks for the buffers and the DSCP mark, best effort: what the kernel
/// refuses is logged, and the socket works without it.
fn tune(socket: &Socket, ipv6: bool) {
    if let Err(err) = socket.set_recv_buffer_size(REQUESTED_BUFFER) {
        tracing::debug!(error = %err, "udp receive buffer not raised");
    }
    if let Err(err) = socket.set_send_buffer_size(REQUESTED_BUFFER) {
        tracing::debug!(error = %err, "udp send buffer not raised");
    }
    // A dual-stack socket sends IPv4 by `IP_TOS`, not by its traffic
    // class (Linux, measured 2026-10-03: unmarked without it); macOS
    // refuses `IP_TOS` on an IPv6 socket, so there IPv4 goes unmarked.
    let marked = if ipv6 {
        socket
            .set_tclass_v6(DSCP_AF41_TOS)
            .and_then(|()| socket.set_tos_v4(DSCP_AF41_TOS))
    } else {
        socket.set_tos_v4(DSCP_AF41_TOS)
    };
    if let Err(err) = marked {
        tracing::debug!(error = %err, "dscp not set on the udp socket");
    }
}

/// Binds the ICE-TCP listener, non-blocking for the runtime.
pub fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        let _best_effort = socket.set_only_v6(false);
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(TCP_BACKLOG)?;
    socket.set_nonblocking(true)?;
    let local = socket.local_addr()?.as_socket();
    tracing::info!(local = ?local, "ice-tcp listener bound");
    Ok(socket.into())
}

#[cfg(test)]
pub(crate) mod test_support {
    //! The shared socket as the tests of this crate bind it.

    use std::net::{Ipv6Addr, SocketAddr};

    use super::{BoundUdp, bind_udp};

    /// Binds the shared socket dual-stack on an ephemeral port that no
    /// IPv4 socket holds, for a test that sends IPv4 to it.
    ///
    /// macOS picks an IPv6 socket's ephemeral port among the IPv6 sockets'
    /// ports only (observed 2026-10-06): `[::]:0` can land on a port another
    /// process holds on `127.0.0.1`, which then receives every IPv4
    /// datagram sent to that port, and a test waiting for one fails under
    /// a full workspace run, whose parallel tests hold such ports. A bind
    /// by number refuses that port, and once the dual-stack socket holds it
    /// no IPv4 socket can take it, so this asks for an ephemeral port and
    /// binds it again by number until the kernel does not refuse.
    pub(crate) fn bind_dual_stack() -> BoundUdp {
        (0..100)
            .find_map(|_| {
                let port = bind_udp("[::]:0".parse().ok()?).ok()?.local.port();
                bind_udp(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)).ok()
            })
            .expect("a dual-stack port no IPv4 socket holds")
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::net::Ipv6Addr;

    use super::test_support::bind_dual_stack;
    use super::*;

    /// What `bind_dual_stack` relies on: a dual-stack bind by number
    /// refuses a port an IPv4 socket holds, on macOS too, where the
    /// ephemeral choice of `[::]:0` does not.
    #[test]
    fn a_dual_stack_bind_by_number_refuses_a_port_an_ipv4_socket_holds() {
        let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = v4.local_addr().unwrap().port();
        let err = bind_udp(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        let bound = bind_dual_stack();
        assert!(bound.dual_stack);
        let v4 = UdpSocket::bind(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            bound.local.port(),
        ));
        assert_eq!(v4.unwrap_err().kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn the_udp_socket_is_dual_stack_with_reported_buffers() {
        let bound = bind_dual_stack();
        assert!(bound.dual_stack);
        assert!(bound.local.port() > 0);
        assert!(bound.recv_buffer > 0 && bound.send_buffer > 0);
        // An IPv4 sender reaches the dual-stack socket.
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = SocketAddr::new("127.0.0.1".parse().unwrap(), bound.local.port());
        sender.send_to(b"ping", target).unwrap();
        let mut buf = [0_u8; 16];
        let (n, from) = bound.socket.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from.port(), sender.local_addr().unwrap().port());
        // A timeout, not a hang, when nothing arrives.
        let err = bound.socket.recv_from(&mut buf).unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        let v4 = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(!v4.dual_stack);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rfc8837_5_video_leaves_af41_to_either_family_from_the_dual_stack_socket() {
        use lotse_testing::dscp::{recv_marked, report_marks};
        let dual = bind_udp("[::]:0".parse().unwrap()).unwrap();
        let v4 = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        for (sender, to, target) in [
            (&dual.socket, "127.0.0.1:0", "::ffff:127.0.0.1"),
            (&dual.socket, "[::1]:0", "::1"),
            (&v4.socket, "127.0.0.1:0", "127.0.0.1"),
        ] {
            let receiver = UdpSocket::bind(to).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            report_marks(&receiver).unwrap();
            let port = receiver.local_addr().unwrap().port();
            let target = SocketAddr::new(target.parse().unwrap(), port);
            sender.send_to(b"video", target).unwrap();
            let (payload, _, dscp) = recv_marked(&receiver).unwrap();
            assert_eq!((&payload[..], dscp), (&b"video"[..], Some(34)), "{target}");
        }
    }

    #[test]
    fn what_the_kernel_refuses_is_logged_and_the_socket_kept() {
        let captured = crate::test_support::Captured::default();
        let _logs = captured.install();
        for ipv6 in [false, true] {
            // Not a socket: every option is refused.
            let file = std::fs::File::open("/dev/null").unwrap();
            tune(&Socket::from(std::os::fd::OwnedFd::from(file)), ipv6);
        }
        assert_eq!(captured.lines("udp receive buffer not raised").len(), 2);
        assert_eq!(captured.lines("udp send buffer not raised").len(), 2);
        assert_eq!(captured.lines("dscp not set on the udp socket").len(), 2);
    }

    #[test]
    fn the_tcp_listener_binds_non_blocking() {
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(listener.local_addr().unwrap().port() > 0);
        let err = listener.accept().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        let v6 = bind_tcp("[::1]:0".parse().unwrap()).unwrap();
        assert!(v6.local_addr().unwrap().is_ipv6());
    }
}

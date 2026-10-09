//! The datagram channel from the supervisor's demux to a worker: one
//! `SOCK_SEQPACKET` socketpair per worker, each message one uplink UDP
//! datagram with the addresses it travelled between, so a session can feed
//! it to its engine as if it had read the socket itself.
//!
//! Media travels here only the other way, and only for a relay candidate
//! on a TCP TURN allocation, whose connection the supervisor owns: the
//! worker sends the padded `ChannelData` frame with the relayed address as
//! the source and the server as the destination. Otherwise workers send on
//! the shared UDP socket. The frame is fixed-width so the demux writes it
//! without allocating: source and destination as
//! `[family:1][address:16][port:2]`, then the payload.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::OwnedFd;

use rustix::net::SocketType;

/// The largest UDP payload (RFC 768: a 16-bit length).
pub const MAX_DATAGRAM_PAYLOAD: usize = 65_535;

/// One encoded address: family, sixteen address bytes, port.
const ADDR_LEN: usize = 19;

/// The fixed part of the frame header: two addresses; the session's
/// local ufrag (one length byte, then the bytes) comes first.
pub const HEADER_LEN: usize = 2 * ADDR_LEN;

/// The longest ufrag carried (RFC 8445 §5.4 allows up to 256 characters;
/// the supervisor generates far shorter ones).
pub const MAX_UFRAG_LEN: usize = 255;

/// Why a frame is not a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramError {
    /// Shorter than the header.
    #[error("datagram frame is {0} bytes, shorter than the header")]
    Truncated(usize),
    /// An address family byte that is neither 4 nor 6.
    #[error("address family {0} is neither 4 nor 6")]
    BadFamily(u8),
    /// The ufrag is not UTF-8.
    #[error("ufrag is not utf-8")]
    BadUfrag,
}

/// The socket type of the pair: `SOCK_SEQPACKET` on Linux, which keeps
/// message boundaries and reports the peer's end; macOS (development only)
/// has no Unix `SEQPACKET`, so it uses `SOCK_DGRAM`, which keeps the
/// boundaries too.
#[cfg(target_os = "linux")]
const PAIR_TYPE: SocketType = SocketType::SEQPACKET;
/// See the Linux definition.
#[cfg(not(target_os = "linux"))]
const PAIR_TYPE: SocketType = SocketType::DGRAM;

/// A message-boundary-keeping socketpair: the supervisor's end and the
/// worker's, both close-on-exec from creation, so no worker spawned later
/// inherits either.
pub fn datagram_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    crate::pair::unix_pair(PAIR_TYPE)
}

/// Appends one address.
fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Reads one address.
fn get_addr(bytes: &[u8]) -> Result<SocketAddr, DatagramError> {
    let family = bytes
        .first()
        .copied()
        .ok_or(DatagramError::Truncated(bytes.len()))?;
    let address = bytes
        .get(1..17)
        .ok_or(DatagramError::Truncated(bytes.len()))?;
    let port = bytes
        .get(17..19)
        .and_then(|p| <[u8; 2]>::try_from(p).ok())
        .map(u16::from_be_bytes)
        .ok_or(DatagramError::Truncated(bytes.len()))?;
    let ip = match family {
        4 => {
            let octets: [u8; 4] = address
                .get(..4)
                .and_then(|o| <[u8; 4]>::try_from(o).ok())
                .ok_or(DatagramError::Truncated(bytes.len()))?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        6 => {
            let octets: [u8; 16] =
                <[u8; 16]>::try_from(address).map_err(|_| DatagramError::Truncated(bytes.len()))?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        other => return Err(DatagramError::BadFamily(other)),
    };
    Ok(SocketAddr::new(ip, port))
}

/// One decoded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// The session the demux routed it to, by local ufrag.
    pub ufrag: &'a str,
    /// Where it came from.
    pub source: SocketAddr,
    /// The local address it arrived on.
    pub destination: SocketAddr,
    /// The UDP payload.
    pub payload: &'a [u8],
}

/// Writes the frame for `payload` travelling from `source` to
/// `destination` for the session `ufrag` into `out`, which is cleared
/// first. A ufrag longer than [`MAX_UFRAG_LEN`] is cut.
pub fn encode(
    ufrag: &str,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    out.clear();
    let ufrag = ufrag.as_bytes();
    let ufrag = ufrag.get(..ufrag.len().min(MAX_UFRAG_LEN)).unwrap_or(&[]);
    out.reserve(
        HEADER_LEN
            .saturating_add(1)
            .saturating_add(ufrag.len())
            .saturating_add(payload.len()),
    );
    out.push(u8::try_from(ufrag.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(ufrag);
    put_addr(out, source);
    put_addr(out, destination);
    out.extend_from_slice(payload);
}

/// Reads a frame back.
pub fn decode(frame: &[u8]) -> Result<Datagram<'_>, DatagramError> {
    let (&ufrag_len, rest) = frame
        .split_first()
        .ok_or(DatagramError::Truncated(frame.len()))?;
    let (ufrag, rest) = rest
        .split_at_checked(usize::from(ufrag_len))
        .ok_or(DatagramError::Truncated(frame.len()))?;
    let ufrag = std::str::from_utf8(ufrag).map_err(|_| DatagramError::BadUfrag)?;
    let (header, payload) = rest
        .split_at_checked(HEADER_LEN)
        .ok_or(DatagramError::Truncated(frame.len()))?;
    let (source, destination) = header
        .split_at_checked(ADDR_LEN)
        .ok_or(DatagramError::Truncated(frame.len()))?;
    Ok(Datagram {
        ufrag,
        source: get_addr(source)?,
        destination: get_addr(destination)?,
        payload,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::os::fd::AsFd as _;

    use super::*;

    #[test]
    fn frames_round_trip_for_both_families() {
        let v4: SocketAddr = "192.0.2.10:18556".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        let mut out = Vec::new();
        encode("abcd", v6, v4, b"hello", &mut out);
        assert_eq!(out.len(), 1 + 4 + HEADER_LEN + 5);
        let frame = decode(&out).unwrap();
        assert_eq!(
            (frame.ufrag, frame.source, frame.destination, frame.payload),
            ("abcd", v6, v4, &b"hello"[..])
        );
        encode("", v4, v6, &[], &mut out);
        let frame = decode(&out).unwrap();
        assert_eq!(
            (frame.ufrag, frame.source, frame.destination, frame.payload),
            ("", v4, v6, &[][..])
        );
        let long = "u".repeat(300);
        encode(&long, v4, v4, b"x", &mut out);
        assert_eq!(decode(&out).unwrap().ufrag.len(), MAX_UFRAG_LEN);
    }

    #[test]
    fn broken_frames_are_errors() {
        assert_eq!(decode(&[0; 10]), Err(DatagramError::Truncated(10)));
        assert_eq!(decode(&[]), Err(DatagramError::Truncated(0)));
        assert_eq!(decode(&[9]), Err(DatagramError::Truncated(1)));
        let mut out = Vec::new();
        let v4: SocketAddr = "127.0.0.1:1".parse().unwrap();
        encode("ab", v4, v4, b"x", &mut out);
        out[3] = 9;
        assert_eq!(decode(&out), Err(DatagramError::BadFamily(9)));
        out[1] = 0xff;
        assert_eq!(decode(&out), Err(DatagramError::BadUfrag));
        assert_eq!(get_addr(&[4, 1, 2]), Err(DatagramError::Truncated(3)));
        assert_eq!(get_addr(&[]), Err(DatagramError::Truncated(0)));
        assert_eq!(
            DatagramError::BadFamily(9).to_string(),
            "address family 9 is neither 4 nor 6"
        );
    }

    #[test]
    fn both_ends_are_close_on_exec_from_creation_socket_2_sock_cloexec() {
        // IPC-10: a worker spawned later must not inherit either end.
        let (ours, theirs) = datagram_pair().unwrap();
        for fd in [&ours, &theirs] {
            assert!(
                rustix::io::fcntl_getfd(fd)
                    .unwrap()
                    .contains(rustix::io::FdFlags::CLOEXEC)
            );
        }
    }

    #[test]
    fn the_pair_carries_message_boundaries() {
        let (ours, theirs) = datagram_pair().unwrap();
        let mut frame = Vec::new();
        let addr: SocketAddr = "127.0.0.1:5".parse().unwrap();
        encode("s", addr, addr, b"one", &mut frame);
        rustix::net::send(ours.as_fd(), &frame, rustix::net::SendFlags::empty()).unwrap();
        encode("s", addr, addr, b"two", &mut frame);
        rustix::net::send(ours.as_fd(), &frame, rustix::net::SendFlags::empty()).unwrap();
        let mut buf = vec![0_u8; 1500];
        let (n, _) =
            rustix::net::recv(theirs.as_fd(), &mut buf, rustix::net::RecvFlags::empty()).unwrap();
        assert_eq!(decode(&buf[..n]).unwrap().payload, b"one");
        let (n, _) =
            rustix::net::recv(theirs.as_fd(), &mut buf, rustix::net::RecvFlags::empty()).unwrap();
        assert_eq!(decode(&buf[..n]).unwrap().payload, b"two");
    }
}

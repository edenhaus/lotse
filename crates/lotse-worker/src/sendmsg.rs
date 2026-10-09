//! The worker's sends on the shared socket, with what a datagram carries
//! besides its destination as control messages on its one `sendmsg(2)`,
//! so sessions on other threads sending on the same socket at the same
//! time keep theirs:
//!
//! - DSCP: the socket carries AF41 for video, set by the supervisor, and
//!   an RTP packet of the audio track leaves marked EF, per RFC 8837 §5
//!   (Table 1, the "High" column): `IP_TOS` towards an IPv4 address,
//!   IPv4-mapped ones on the dual-stack socket included (Linux `ip(7)`, as
//!   an `int`; XNU takes it too), and `IPV6_TCLASS` towards IPv6 (RFC 3542
//!   §6.5). Both measured on 2026-10-03, Linux 7.0 and macOS 27: the
//!   kernel marks the datagram with the message's value and the socket's
//!   mark is left alone.
//! - The source address: a datagram leaves from the local address of the
//!   candidate the engine sends it from rather than the one the kernel
//!   would route from, so on a multi-homed host the browser sees the
//!   5-tuple it checked (RFC 8445 §7.2.5.2.1). `IP_PKTINFO` with
//!   `ipi_spec_dst` set towards IPv4, IPv4-mapped included (Linux
//!   `ip(7)`, observed behavior; XNU reads it too), and `IPV6_PKTINFO`
//!   with `ipi6_addr` set towards IPv6 (RFC 3542 §6.1), the interface
//!   index 0 both times, so the route still picks the interface. An
//!   address that is not the host's fails the send.
//!
//! Both messages are of the destination's family, so they share one
//! buffer when both apply. They are laid out here because libc's `CMSG_*`
//! helpers are `unsafe`: a `cmsghdr` (length, level, type) and the value,
//! padded to `CMSG_SPACE`. The length field is the header less its two
//! `int`s: a `size_t` on Linux (musl's `socklen_t` and padding on a
//! little-endian 64-bit target are the same bytes), a `socklen_t` on
//! macOS; both align the data as their `CMSG_ALIGN` does.

#[cfg(target_endian = "big")]
compile_error!(
    "the control message's length is written little-endian; lotse targets x86-64 and aarch64"
);

use std::io::{self, IoSlice};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use libc::c_int;
use socket2::{MsgHdr, SockAddr, SockRef};

/// DSCP EF (RFC 3246) as a TOS byte: audio, per RFC 8837 §5.
pub(crate) const DSCP_EF_TOS: c_int = 46 << 2;

/// `CMSG_ALIGN`'s unit: `size_t` on Linux (glibc and musl), 32 bits on
/// macOS (`__DARWIN_ALIGN32`).
#[cfg(target_os = "linux")]
const ALIGN: usize = size_of::<usize>();
/// `CMSG_ALIGN`'s unit: `size_t` on Linux (glibc and musl), 32 bits on
/// macOS (`__DARWIN_ALIGN32`).
#[cfg(not(target_os = "linux"))]
const ALIGN: usize = 4;

/// `sizeof(struct cmsghdr)`.
const HEADER: usize = size_of::<libc::cmsghdr>();

/// The width of `cmsg_len`: what the header holds besides level and type.
const LEN_FIELD: usize = HEADER.saturating_sub(2 * size_of::<c_int>());

/// Where a message's value starts, `CMSG_DATA`.
const DATA: usize = HEADER.next_multiple_of(ALIGN);

/// `sizeof(struct in_pktinfo)`: the interface index, `ipi_spec_dst` and
/// `ipi_addr`, 12 bytes on Linux and macOS alike.
const IN_PKTINFO: usize = size_of::<libc::in_pktinfo>();

/// `sizeof(struct in6_pktinfo)`: `ipi6_addr`, then the interface index
/// (RFC 3542 §6.1).
const IN6_PKTINFO: usize = size_of::<libc::in6_pktinfo>();

/// Where `ipi_spec_dst` starts in an `in_pktinfo`: after the index.
const SPEC_DST: usize = size_of::<c_int>();

/// `CMSG_LEN(n)`: the header and a value of `n` bytes.
const fn cmsg_len(n: usize) -> usize {
    DATA.saturating_add(n)
}

/// `CMSG_SPACE(n)`: a message with a value of `n` bytes, padded.
const fn cmsg_space(n: usize) -> usize {
    cmsg_len(n).next_multiple_of(ALIGN)
}

/// The buffer's length: a DSCP mark and the larger source address, an
/// `in6_pktinfo` (20 bytes against an `in_pktinfo`'s 12).
const CAPACITY: usize = cmsg_space(size_of::<c_int>()).saturating_add(cmsg_space(IN6_PKTINFO));

/// Copies `bytes` into `buf` from `at`, as far as `buf` goes.
fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    for (dst, src) in buf.iter_mut().skip(at).zip(bytes) {
        *dst = *src;
    }
}

/// The control messages of one datagram, laid out one after the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Control {
    /// The messages, then zeros.
    buf: [u8; CAPACITY],
    /// How much of `buf` they take.
    len: usize,
}

impl Control {
    /// No message.
    const fn new() -> Self {
        Self {
            buf: [0; CAPACITY],
            len: 0,
        }
    }

    /// Appends the message `name` at `level` carrying `value`; the
    /// callers append at most one mark and one address, which
    /// [`CAPACITY`] holds.
    fn push(&mut self, level: c_int, name: c_int, value: &[u8]) {
        let at = self.len;
        put(
            &mut self.buf,
            at,
            cmsg_len(value.len())
                .to_le_bytes()
                .get(..LEN_FIELD)
                .unwrap_or_default(),
        );
        let level_at = at.saturating_add(LEN_FIELD);
        put(&mut self.buf, level_at, &level.to_ne_bytes());
        put(
            &mut self.buf,
            level_at.saturating_add(size_of::<c_int>()),
            &name.to_ne_bytes(),
        );
        put(&mut self.buf, at.saturating_add(DATA), value);
        self.len = at.saturating_add(cmsg_space(value.len()));
    }

    /// The messages.
    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }
}

/// An `in_pktinfo` naming `ip` as the source (`ipi_spec_dst`), the
/// interface index and `ipi_addr` zero.
fn in_pktinfo(ip: Ipv4Addr) -> [u8; IN_PKTINFO] {
    let mut info = [0; IN_PKTINFO];
    put(&mut info, SPEC_DST, &ip.octets());
    info
}

/// An `in6_pktinfo` naming `ip` as the source (`ipi6_addr`), the
/// interface index zero (RFC 3542 §6.1).
fn in6_pktinfo(ip: Ipv6Addr) -> [u8; IN6_PKTINFO] {
    let mut info = [0; IN6_PKTINFO];
    put(&mut info, 0, &ip.octets());
    info
}

/// The control messages for a datagram to `target`: marked `tos`, and
/// leaving from `source` when it is of the target's family (an
/// IPv4-mapped one counting as IPv4); a source of the other family is
/// left to the kernel.
fn control(target: SocketAddr, tos: Option<c_int>, source: Option<IpAddr>) -> Control {
    let v4 = target.ip().to_canonical().is_ipv4();
    let mut control = Control::new();
    if let Some(tos) = tos {
        if v4 {
            control.push(libc::IPPROTO_IP, libc::IP_TOS, &tos.to_ne_bytes());
        } else {
            control.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tos.to_ne_bytes());
        }
    }
    match source.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V4(ip)) if v4 => {
            control.push(libc::IPPROTO_IP, libc::IP_PKTINFO, &in_pktinfo(ip));
        }
        Some(IpAddr::V6(ip)) if !v4 => {
            control.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6_pktinfo(ip));
        }
        _ => {}
    }
    control
}

/// Sends `payload` to `target` from `socket`: marked EF when it is the
/// audio track's and with the socket's own mark otherwise, and from
/// `source` when given, else from where the kernel routes.
pub(crate) fn send_to(
    socket: &UdpSocket,
    payload: &[u8],
    target: SocketAddr,
    audio: bool,
    source: Option<IpAddr>,
) -> io::Result<usize> {
    if !audio && source.is_none() {
        return socket.send_to(payload, target);
    }
    let control = control(target, audio.then_some(DSCP_EF_TOS), source);
    let address = SockAddr::from(target);
    let buffers = [IoSlice::new(payload)];
    let message = MsgHdr::new()
        .with_addr(&address)
        .with_buffers(&buffers)
        .with_control(control.bytes());
    SockRef::from(socket).sendmsg(&message, 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    /// The `int` at `at`.
    fn int(buf: &[u8], at: usize) -> c_int {
        c_int::from_ne_bytes(buf[at..at + size_of::<c_int>()].try_into().unwrap())
    }

    /// The `cmsg_len` of the message at `at`.
    fn length(buf: &[u8], at: usize) -> usize {
        let mut len = [0_u8; size_of::<usize>()];
        len[..LEN_FIELD].copy_from_slice(&buf[at..at + LEN_FIELD]);
        usize::from_le_bytes(len)
    }

    /// The length, level, type and value of the message at `at`.
    fn message(buf: &[u8], at: usize) -> (usize, c_int, c_int, &[u8]) {
        let len = length(buf, at);
        (
            len,
            int(buf, at + LEN_FIELD),
            int(buf, at + LEN_FIELD + 4),
            &buf[at + DATA..at + len],
        )
    }

    #[test]
    fn the_control_message_is_laid_out_as_cmsg_len_and_cmsg_space() {
        // RFC 3542 §20.3 by hand: header, then the aligned value.
        #[cfg(target_os = "linux")]
        assert_eq!(
            (HEADER, LEN_FIELD, DATA, cmsg_len(4), cmsg_space(4)),
            (16, 8, 16, 20, 24)
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            (HEADER, LEN_FIELD, DATA, cmsg_len(4), cmsg_space(4)),
            (12, 4, 12, 16, 16)
        );
        assert_eq!((IN_PKTINFO, IN6_PKTINFO), (12, 20));
        assert_eq!(CAPACITY, cmsg_space(4) + cmsg_space(20));
        let v4 = control("192.0.2.1:9".parse().unwrap(), Some(0xb8), None);
        let mapped = control("[::ffff:192.0.2.1]:9".parse().unwrap(), Some(0xb8), None);
        let v6 = control("[2001:db8::1]:9".parse().unwrap(), Some(0xb8), None);
        assert_eq!(v4, mapped, "IPv4-mapped is IPv4 on the wire");
        assert_eq!(v4.bytes().len(), cmsg_space(4));
        let tos = 0xb8_i32.to_ne_bytes();
        assert_eq!(
            message(v4.bytes(), 0),
            (cmsg_len(4), libc::IPPROTO_IP, libc::IP_TOS, &tos[..])
        );
        assert_eq!(
            message(v6.bytes(), 0),
            (cmsg_len(4), libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tos[..])
        );
        assert!(
            v4.bytes()[cmsg_len(4)..].iter().all(|b| *b == 0),
            "padding is zero"
        );
        assert_eq!(DSCP_EF_TOS, 0xb8, "EF is DSCP 46");
        assert!(
            control("192.0.2.1:9".parse().unwrap(), None, None)
                .bytes()
                .is_empty()
        );
    }

    #[test]
    fn ip_pktinfo_names_the_source_in_ipi_spec_dst() {
        // Linux ip(7) `IP_PKTINFO` on send, observed behavior: the index
        // and `ipi_addr` zero, `ipi_spec_dst` the source.
        let source: IpAddr = "192.0.2.7".parse().unwrap();
        let v4 = control("198.51.100.1:9".parse().unwrap(), None, Some(source));
        let mapped = control(
            "[::ffff:198.51.100.1]:9".parse().unwrap(),
            None,
            Some("::ffff:192.0.2.7".parse().unwrap()),
        );
        assert_eq!(v4, mapped, "IPv4-mapped is IPv4 on the wire");
        assert_eq!(v4.bytes().len(), cmsg_space(IN_PKTINFO));
        assert_eq!(
            message(v4.bytes(), 0),
            (
                cmsg_len(IN_PKTINFO),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &[0, 0, 0, 0, 192, 0, 2, 7, 0, 0, 0, 0][..]
            )
        );
    }

    #[test]
    fn rfc3542_6_1_ipv6_pktinfo_names_the_source_in_ipi6_addr() {
        let v6 = control(
            "[2001:db8::1]:9".parse().unwrap(),
            None,
            Some("2001:db8::7".parse().unwrap()),
        );
        assert_eq!(v6.bytes().len(), cmsg_space(IN6_PKTINFO));
        let mut info = [0_u8; 20];
        info[..16].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            message(v6.bytes(), 0),
            (
                cmsg_len(IN6_PKTINFO),
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                &info[..]
            )
        );
    }

    #[test]
    fn the_mark_and_the_source_share_one_buffer() {
        let tos = 0xb8_i32.to_ne_bytes();
        let v4 = control(
            "198.51.100.1:9".parse().unwrap(),
            Some(0xb8),
            Some("192.0.2.7".parse().unwrap()),
        );
        assert_eq!(v4.bytes().len(), cmsg_space(4) + cmsg_space(IN_PKTINFO));
        assert_eq!(
            message(v4.bytes(), 0),
            (cmsg_len(4), libc::IPPROTO_IP, libc::IP_TOS, &tos[..])
        );
        assert_eq!(
            message(v4.bytes(), cmsg_space(4)),
            (
                cmsg_len(IN_PKTINFO),
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &in_pktinfo(Ipv4Addr::new(192, 0, 2, 7))[..]
            )
        );
        let v6 = control(
            "[2001:db8::1]:9".parse().unwrap(),
            Some(0xb8),
            Some("2001:db8::7".parse().unwrap()),
        );
        assert_eq!(v6.bytes().len(), CAPACITY, "the largest pair fits");
        assert_eq!(
            message(v6.bytes(), 0),
            (cmsg_len(4), libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tos[..])
        );
        assert_eq!(
            message(v6.bytes(), cmsg_space(4)),
            (
                cmsg_len(IN6_PKTINFO),
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                &in6_pktinfo("2001:db8::7".parse().unwrap())[..]
            )
        );
    }

    #[test]
    fn a_source_of_the_other_family_is_left_to_the_kernel() {
        let to_v4 = control(
            "198.51.100.1:9".parse().unwrap(),
            None,
            Some("2001:db8::7".parse().unwrap()),
        );
        let to_v6 = control(
            "[2001:db8::1]:9".parse().unwrap(),
            Some(0xb8),
            Some("192.0.2.7".parse().unwrap()),
        );
        assert!(to_v4.bytes().is_empty());
        assert_eq!(to_v6.bytes().len(), cmsg_space(4), "the mark alone");
    }

    /// A sender bound to `bind` marked AF41 like the supervisor's socket
    /// (dual-stack when IPv6), and a receiver bound to `to`.
    fn rig(bind: &str, to: &str) -> (UdpSocket, UdpSocket) {
        let bind: SocketAddr = bind.parse().unwrap();
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(bind),
            socket2::Type::DGRAM,
            None,
        )
        .unwrap();
        if bind.is_ipv6() {
            socket.set_only_v6(false).unwrap();
            socket.set_tclass_v6(34 << 2).unwrap();
        }
        // macOS refuses `IP_TOS` on an IPv6 socket.
        socket.set_tos_v4(34 << 2).ok();
        socket.bind(&bind.into()).unwrap();
        let receiver = UdpSocket::bind(to).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        (socket.into(), receiver)
    }

    /// The payload, source and DSCP of the next datagram on `receiver`,
    /// which `report` set up; the DSCP is read on Linux only.
    #[cfg(target_os = "linux")]
    fn received(receiver: &UdpSocket) -> (Vec<u8>, SocketAddr, Option<u8>) {
        let (payload, from, dscp) = lotse_testing::dscp::recv_marked(receiver).unwrap();
        (payload, from.unwrap(), dscp)
    }

    #[cfg(target_os = "linux")]
    fn report(receiver: &UdpSocket) {
        lotse_testing::dscp::report_marks(receiver).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    fn received(receiver: &UdpSocket) -> (Vec<u8>, SocketAddr, Option<u8>) {
        let mut buf = [0_u8; 64];
        let (n, from) = receiver.recv_from(&mut buf).unwrap();
        (buf[..n].to_vec(), from, None)
    }

    #[cfg(not(target_os = "linux"))]
    fn report(_receiver: &UdpSocket) {}

    /// The EF and AF41 marks the tests read: macOS marks too (measured),
    /// but the test reads marks on Linux only.
    #[cfg(target_os = "linux")]
    const MARKS: (Option<u8>, Option<u8>) = (Some(46), Some(34));
    #[cfg(not(target_os = "linux"))]
    const MARKS: (Option<u8>, Option<u8>) = (None, None);

    /// A local address besides 127.0.0.1: Linux routes all of
    /// 127.0.0.0/8 to `lo`, so a datagram to 127.0.0.1 would not leave
    /// from 127.0.0.2 unasked; macOS has 127.0.0.1 alone.
    #[cfg(target_os = "linux")]
    const SECOND: &str = "127.0.0.2";
    #[cfg(not(target_os = "linux"))]
    const SECOND: &str = "127.0.0.1";

    /// `to` with an IPv4 address IPv4-mapped when `mapped`.
    fn target(to: SocketAddr, mapped: bool) -> SocketAddr {
        match to {
            SocketAddr::V4(v4) if mapped => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            _ => to,
        }
    }

    #[test]
    fn rfc8837_5_audio_leaves_ef_and_the_rest_the_sockets_af41() {
        // IPv4, IPv6, and IPv4-mapped from the dual-stack socket; with and
        // without a source address.
        for (bind, to, mapped, source) in [
            ("127.0.0.1:0", "127.0.0.1:0", false, None),
            ("[::]:0", "[::1]:0", false, None),
            ("[::]:0", "127.0.0.1:0", true, None),
            ("0.0.0.0:0", "127.0.0.1:0", false, Some("127.0.0.1")),
            ("[::]:0", "[::1]:0", false, Some("::1")),
            ("[::]:0", "127.0.0.1:0", true, Some("127.0.0.1")),
        ] {
            let (sender, receiver) = rig(bind, to);
            report(&receiver);
            let target_addr = target(receiver.local_addr().unwrap(), mapped);
            let source = source.map(|ip| ip.parse().unwrap());
            assert_eq!(
                send_to(&sender, b"audio", target_addr, true, source).unwrap(),
                5
            );
            assert_eq!(
                send_to(&sender, b"video", target_addr, false, source).unwrap(),
                5
            );
            let (audio, _, audio_dscp) = received(&receiver);
            let (video, _, video_dscp) = received(&receiver);
            assert_eq!((&audio[..], &video[..]), (&b"audio"[..], &b"video"[..]));
            assert_eq!(
                (audio_dscp, video_dscp),
                MARKS,
                "EF, AF41 to {target_addr} from {source:?}"
            );
        }
    }

    #[test]
    fn rfc8445_7_2_5_2_1_a_datagram_leaves_from_the_named_source() {
        // IPv6 loopback has `::1` alone on both platforms.
        for (bind, to, mapped, source, audio) in [
            ("0.0.0.0:0", "127.0.0.1:0", false, SECOND, false),
            ("0.0.0.0:0", "127.0.0.1:0", false, SECOND, true),
            ("[::]:0", "127.0.0.1:0", true, SECOND, false),
            ("[::]:0", "127.0.0.1:0", true, SECOND, true),
            ("[::]:0", "[::1]:0", false, "::1", false),
            ("[::]:0", "[::1]:0", false, "::1", true),
        ] {
            let (sender, receiver) = rig(bind, to);
            report(&receiver);
            let port = sender.local_addr().unwrap().port();
            let target_addr = target(receiver.local_addr().unwrap(), mapped);
            let source: IpAddr = source.parse().unwrap();
            send_to(&sender, b"x", target_addr, audio, Some(source)).unwrap();
            let (payload, from, _) = received(&receiver);
            assert_eq!(
                (&payload[..], from),
                (&b"x"[..], SocketAddr::new(source, port)),
                "to {target_addr}, audio {audio}"
            );
        }
    }

    #[test]
    fn a_source_the_host_does_not_have_fails_the_send() {
        // The kernel honors the message: an address of no interface is
        // refused rather than replaced by the routed one.
        for (bind, to, mapped, source) in [
            ("0.0.0.0:0", "127.0.0.1:0", false, "192.0.2.7"),
            ("[::]:0", "127.0.0.1:0", true, "192.0.2.7"),
            ("[::]:0", "[::1]:0", false, "2001:db8::7"),
        ] {
            let (sender, receiver) = rig(bind, to);
            let target_addr = target(receiver.local_addr().unwrap(), mapped);
            let sent = send_to(
                &sender,
                b"x",
                target_addr,
                false,
                Some(source.parse().unwrap()),
            );
            assert!(sent.is_err(), "from {source} to {target_addr}: {sent:?}");
        }
    }

    #[test]
    fn put_stops_at_the_buffer_end() {
        let mut buf = [0_u8; 3];
        put(&mut buf, 1, &[7, 8, 9]);
        assert_eq!(buf, [0, 7, 8]);
        put(&mut buf, 5, &[1]);
        assert_eq!(buf, [0, 7, 8]);
    }
}

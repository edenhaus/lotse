//! Advertised addresses (`webrtc.advertise`): the addresses a NAT in front
//! of the daemon forwards to its host addresses, such as a container
//! bridge network's published ports, told to every viewer's browser as
//! server-reflexive candidates in place of the host candidates it cannot
//! reach.
//!
//! Like the STUN-learned candidates of [`crate::gather`], only the browser
//! is told: its checks to an advertised address arrive at the host base
//! through the NAT, so the worker's ICE agent needs no candidate of its
//! own and keeps its host bases. With at least one address advertised,
//! the worker's host candidates are no longer told to the browser, in its
//! trickled candidates or in the answer's `a=candidate` lines, so the
//! addresses behind the NAT stay inside it and the browser spends no
//! checks on them; relay and server-reflexive candidates still pass.
//! For the same reason the related address of every server-reflexive
//! candidate told to the browser, advertised or STUN-learned, is withheld
//! then ([`Advertisement::related`]), and a session tells each
//! server-reflexive transport address once ([`srflx_address`]).
//!
//! Implements RFC 8445 §5.1.1.2 (a server-reflexive candidate and its
//! base), §5.1.1.3 (its foundation), §5.1.2.1 (its priority, a local
//! preference unique per candidate) and §5.1.3 (a candidate equal to a
//! host candidate is redundant), RFC 6544 §4.2 (the local preference of a
//! TCP candidate) and §4.5 (`tcptype`), and RFC 8839 §5.1 (the `candidate`
//! attribute, which the host filter reads, and its related address,
//! withheld for privacy as `0.0.0.0` or `::` at port 9).
//!
//! SPEC-DEVIATION: RFC 8445 §5.1.1.2 has an agent learn a server-reflexive
//! candidate from a STUN server; these are configured instead, because the
//! NAT of a container's bridge network maps the published ports to the
//! host addresses whatever a STUN server would see, and a deployment
//! without one must still be reachable. They behave as §5.1.1.2's do: a
//! transport address on the NAT's public side, its base a host address
//! (whose address the candidate withholds, RFC 8839 §5.1).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::gather::{COMPONENT, LOCAL_PREFERENCE, SRFLX_TYPE_PREFERENCE};

/// The most addresses `webrtc.advertise` takes: each one is a UDP and an
/// ICE-TCP candidate in every answer, and a NAT has few public sides.
pub const MAX_ADVERTISED: usize = 8;

/// The direction preference of a passive server-reflexive TCP candidate
/// (RFC 6544 §4.2: 2 for passive among the server-reflexive ones).
const TCP_DIRECTION_PREFERENCE: u32 = 2;

/// The highest other-preference of a TCP candidate (RFC 6544 §4.2: 0 to
/// 8191).
const TCP_OTHER_PREFERENCE: u32 = 8_191;

/// The port of a withheld related address (RFC 8839 §5.1: "the port to
/// '9'" when an agent does not reveal it, for privacy).
const WITHHELD_PORT: u16 = 9;

/// One entry of `webrtc.advertise`: an IP address, and the port the NAT
/// forwards to the front door's when it differs. No hostname, so nothing
/// is resolved when an offer comes. Always usable: canonical (an
/// IPv4-mapped IPv6 address is the IPv4 one), neither unspecified,
/// multicast nor broadcast, and never port 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvertisedAddress {
    /// The address, canonical.
    ip: IpAddr,
    /// The port for both the UDP and the ICE-TCP candidate; without it,
    /// each takes its own listener's port.
    port: Option<u16>,
}

/// Why a string or an address is not an [`AdvertisedAddress`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdvertiseError {
    /// Neither `IP` nor `IP:PORT`.
    #[error(
        "advertised address must be IP or IP:PORT ([IPv6]:PORT), not {0:?}; hostnames are not resolved"
    )]
    Syntax(String),
    /// An address no browser can send to.
    #[error("advertised address {address} is {reason}, which no browser can reach")]
    Unreachable {
        /// The address as given, canonical.
        address: String,
        /// `unspecified`, `multicast` or `broadcast`.
        reason: &'static str,
    },
    /// Port 0, which no NAT forwards.
    #[error("advertised address {0} has port 0")]
    PortZero(String),
}

impl AdvertisedAddress {
    /// `ip`, canonical, with `port`; refused when no browser could reach
    /// it.
    pub fn new(ip: IpAddr, port: Option<u16>) -> Result<Self, AdvertiseError> {
        let address = Self {
            ip: ip.to_canonical(),
            port,
        };
        let unreachable = if address.ip.is_unspecified() {
            Some("unspecified")
        } else if address.ip.is_multicast() {
            Some("multicast")
        } else if matches!(address.ip, IpAddr::V4(v4) if v4.is_broadcast()) {
            Some("broadcast")
        } else {
            None
        };
        if let Some(reason) = unreachable {
            return Err(AdvertiseError::Unreachable {
                address: address.to_string(),
                reason,
            });
        }
        if port == Some(0) {
            return Err(AdvertiseError::PortZero(address.to_string()));
        }
        Ok(address)
    }

    /// The address.
    pub const fn ip(self) -> IpAddr {
        self.ip
    }

    /// The port, if one was given.
    pub const fn port(self) -> Option<u16> {
        self.port
    }
}

impl fmt::Display for AdvertisedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}", SocketAddr::new(self.ip, port)),
            None => write!(f, "{}", self.ip),
        }
    }
}

impl FromStr for AdvertisedAddress {
    type Err = AdvertiseError;

    /// `IP`, `IP:PORT`, `[IPv6]` or `[IPv6]:PORT`, surrounding whitespace
    /// ignored.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim();
        let (ip, port) = if let Ok(addr) = text.parse::<SocketAddr>() {
            (addr.ip(), Some(addr.port()))
        } else if let Ok(ip) = text.parse::<IpAddr>() {
            (ip, None)
        } else if let Some(ip) = text
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
        {
            (IpAddr::V6(ip), None)
        } else {
            return Err(AdvertiseError::Syntax(s.to_owned()));
        };
        Self::new(ip, port)
    }
}

/// The transport of a candidate (RFC 8839 §5.1 `transport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    /// UDP, on the shared socket.
    Udp,
    /// Passive ICE-TCP, on the listener (RFC 6544).
    Tcp,
}

impl Protocol {
    /// The name in a `candidate` attribute and in the logs.
    const fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// What the advertised addresses make of every session, worked out once
/// from the front door's host addresses: the candidates told to the
/// browser, and which of the worker's host candidates it is still told.
/// The default advertises nothing and hides nothing.
#[derive(Debug, Default)]
pub(crate) struct Advertisement {
    /// The `candidate` attribute values, each entry's UDP one, then its
    /// TCP one.
    lines: Vec<String>,
    /// An address is advertised: the worker's host candidates are hidden
    /// from the browser, but for those in [`Self::kept`].
    active: bool,
    /// Host candidates an advertised address equals (RFC 8445 §5.1.3): the
    /// host candidate stands for it, so the browser is told that one.
    kept: Vec<(Protocol, SocketAddr)>,
}

impl Advertisement {
    /// The candidates of `advertised` on the UDP host addresses `hosts`
    /// and the passive ICE-TCP ones `tcp_hosts` (none with the listener
    /// off). Logs each decision once, at startup.
    pub(crate) fn new(
        advertised: &[AdvertisedAddress],
        hosts: &[SocketAddr],
        tcp_hosts: &[SocketAddr],
    ) -> Self {
        let mut advertisement = Self {
            active: !advertised.is_empty(),
            ..Self::default()
        };
        for (index, address) in advertised.iter().enumerate() {
            advertisement.add(index, *address, Protocol::Udp, hosts);
            if !tcp_hosts.is_empty() {
                advertisement.add(index, *address, Protocol::Tcp, tcp_hosts);
            }
        }
        if advertisement.active {
            tracing::info!(
                advertised = advertised.len(),
                candidates = advertisement.lines.len(),
                hosts_kept = advertisement.kept.len(),
                "advertised addresses told to browsers; the worker's host candidates hidden from them"
            );
        }
        advertisement
    }

    /// Adds `address`'s candidate over `protocol`, whose base is the first
    /// of `bases` of its family, at the base's port unless it names one;
    /// skipped without a base of its family, and kept as the host
    /// candidate it equals (RFC 8445 §5.1.3).
    fn add(
        &mut self,
        index: usize,
        address: AdvertisedAddress,
        protocol: Protocol,
        bases: &[SocketAddr],
    ) {
        let transport = protocol.name();
        let Some(base) = bases
            .iter()
            .find(|base| base.is_ipv4() == address.ip.is_ipv4())
        else {
            tracing::warn!(
                %address,
                transport,
                "advertised address skipped: no host address of its family to be its base"
            );
            return;
        };
        let mapped = SocketAddr::new(address.ip, address.port.unwrap_or_else(|| base.port()));
        if bases.contains(&mapped) {
            tracing::info!(
                %address,
                transport,
                "advertised address is a host candidate; the browser is told that one (RFC 8445 §5.1.3)"
            );
            self.kept.push((protocol, mapped));
            return;
        }
        let line = candidate_line(index, protocol, mapped);
        tracing::info!(%address, transport, candidate = line, "advertised candidate");
        self.lines.push(line);
    }

    /// The candidates told to every browser.
    pub(crate) fn lines(&self) -> &[String] {
        &self.lines
    }

    /// The related address of a server-reflexive candidate at `mapped`
    /// whose base is `base` (RFC 8839 §5.1): the base, unless an address
    /// is advertised; then withheld, as §5.1 allows for privacy, so that
    /// no candidate the browser is told names an address behind the NAT.
    pub(crate) fn related(&self, mapped: SocketAddr, base: SocketAddr) -> SocketAddr {
        if self.active { withheld(mapped) } else { base }
    }

    /// Whether the browser is told the worker's candidate `candidate` (a
    /// `candidate` attribute value): always without an advertised address;
    /// with one, unless it is a host candidate other than those kept. A
    /// line that does not parse is hidden then, as it could be a host one.
    pub(crate) fn shows(&self, candidate: &str) -> bool {
        if !self.active {
            return true;
        }
        match parse_candidate(candidate) {
            Some((_, _, kind)) if !kind.eq_ignore_ascii_case("host") => true,
            Some((protocol, addr, _)) => self.kept.contains(&(protocol, addr)),
            None => false,
        }
    }

    /// `sdp` without the `a=candidate` lines [`Self::shows`] hides, line
    /// endings kept, and how many it hid. It also loses any
    /// `a=end-of-candidates`: the advertised candidates trickle after the
    /// answer, and after the indication a browser takes no more of a
    /// section's candidates (RFC 8838 §8.2, §13), so the session's own
    /// end-of-candidates follows them instead. The worker's engine writes
    /// none (str0m 0.25, observed 2026-11-10), but its answer is untrusted.
    pub(crate) fn filter_sdp(&self, sdp: String) -> (String, usize) {
        if !self.active {
            return (sdp, 0);
        }
        let mut hidden = 0_usize;
        let kept = sdp
            .split_inclusive('\n')
            .filter(|line| {
                let Some(attribute) = line.trim_end().strip_prefix("a=") else {
                    return true;
                };
                if attribute == "end-of-candidates" {
                    return false;
                }
                let shown = attribute
                    .strip_prefix("candidate:")
                    .is_none_or(|_| self.shows(attribute));
                if !shown {
                    hidden = hidden.saturating_add(1);
                }
                shown
            })
            .collect();
        (kept, hidden)
    }
}

/// The `candidate` attribute value (RFC 8839 §5.1) of advertised address
/// `index` at `mapped` over `protocol`, its base withheld ([`withheld`]):
/// foundation `au`
/// or `at` and the index, which no STUN-learned (`s`), relay or host one
/// (the engine's, hexadecimal) shares (RFC 8445 §5.1.1.3); type
/// preference that of a server-reflexive candidate (§5.1.2.2), local
/// preference unique per entry (§5.1.2.1): for UDP below the STUN-learned
/// one's, for TCP RFC 6544 §4.2's passive server-reflexive one, so a UDP
/// candidate always comes first; a TCP one is passive (RFC 6544 §4.5, its
/// `tcptype` after `raddr` and `rport`).
fn candidate_line(index: usize, protocol: Protocol, mapped: SocketAddr) -> String {
    let entry = u32::try_from(index).unwrap_or(u32::MAX);
    let (foundation, local_preference, tcptype) = match protocol {
        Protocol::Udp => (
            "au",
            LOCAL_PREFERENCE.saturating_sub(1).saturating_sub(entry),
            "",
        ),
        Protocol::Tcp => (
            "at",
            (TCP_DIRECTION_PREFERENCE << 13)
                .saturating_add(TCP_OTHER_PREFERENCE.saturating_sub(entry)),
            " tcptype passive",
        ),
    };
    // (2^24)·type preference + (2^8)·local preference + (256 − component)
    let priority = (SRFLX_TYPE_PREFERENCE << 24)
        .saturating_add(local_preference.saturating_mul(256))
        .saturating_add(256 - COMPONENT);
    let related = withheld(mapped);
    format!(
        "candidate:{foundation}{index} {COMPONENT} {} {priority} {} {} typ srflx raddr {} rport {}{tcptype}",
        protocol.name(),
        mapped.ip(),
        mapped.port(),
        related.ip(),
        related.port()
    )
}

/// The related address that reveals nothing for a candidate at
/// `candidate` (RFC 8839 §5.1): `0.0.0.0` for an IPv4 candidate, `::` for
/// an IPv6 one, at port 9.
const fn withheld(candidate: SocketAddr) -> SocketAddr {
    let ip = match candidate {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, WITHHELD_PORT)
}

/// The transport and transport address of a server-reflexive candidate
/// line, which a session tells the browser once: a second candidate at
/// the same one, with the same base, is redundant (RFC 8445 §5.1.3).
/// `None` for another type or a malformed line.
pub(crate) fn srflx_address(candidate: &str) -> Option<(Protocol, SocketAddr)> {
    parse_candidate(candidate)
        .filter(|(_, _, kind)| kind.eq_ignore_ascii_case("srflx"))
        .map(|(protocol, addr, _)| (protocol, addr))
}

/// The transport, transport address (canonical) and type of a `candidate`
/// attribute value (RFC 8839 §5.1: `candidate:` foundation, component,
/// transport, priority, address, port, `typ`, type); `None` for another
/// transport or a malformed line.
fn parse_candidate(candidate: &str) -> Option<(Protocol, SocketAddr, &str)> {
    let mut fields = candidate
        .strip_prefix("candidate:")?
        .split_ascii_whitespace();
    let transport = fields.nth(2)?;
    let protocol = if transport.eq_ignore_ascii_case("udp") {
        Protocol::Udp
    } else if transport.eq_ignore_ascii_case("tcp") {
        Protocol::Tcp
    } else {
        return None;
    };
    let ip: IpAddr = fields.nth(1)?.parse().ok()?;
    let port: u16 = fields.next()?.parse().ok()?;
    let ("typ", kind) = (fields.next()?, fields.next()?) else {
        return None;
    };
    Some((protocol, SocketAddr::new(ip.to_canonical(), port), kind))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;
    use crate::test_support::Captured;

    fn addr(text: &str) -> AdvertisedAddress {
        text.parse().unwrap()
    }

    fn sockets(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|text| text.parse().unwrap()).collect()
    }

    #[test]
    fn advertised_addresses_are_ip_or_ip_and_port_and_reachable() {
        let parsed = |text: &str| {
            text.parse::<AdvertisedAddress>()
                .map(|a| (a.ip(), a.port()))
        };
        assert_eq!(
            parsed("203.0.113.7"),
            Ok(("203.0.113.7".parse().unwrap(), None))
        );
        assert_eq!(
            parsed(" 203.0.113.7:40000 "),
            Ok(("203.0.113.7".parse().unwrap(), Some(40_000)))
        );
        assert_eq!(
            parsed("2001:db8::7"),
            Ok(("2001:db8::7".parse().unwrap(), None))
        );
        assert_eq!(
            parsed("[2001:db8::7]"),
            Ok(("2001:db8::7".parse().unwrap(), None))
        );
        assert_eq!(
            parsed("[2001:db8::7]:5"),
            Ok(("2001:db8::7".parse().unwrap(), Some(5)))
        );
        // Canonical: an IPv4-mapped address is the IPv4 one.
        assert_eq!(
            parsed("[::ffff:203.0.113.7]:5"),
            Ok(("203.0.113.7".parse().unwrap(), Some(5)))
        );
        for bad in [
            "",
            "cam.example",
            "cam.example:5",
            "[2001:db8::7",
            "1.2.3.4:x",
            "1.2.3.4:70000",
        ] {
            assert_eq!(
                parsed(bad),
                Err(AdvertiseError::Syntax(bad.to_owned())),
                "{bad:?}"
            );
        }
        for (bad, address, reason) in [
            ("0.0.0.0", "0.0.0.0", "unspecified"),
            ("[::]:5", "[::]:5", "unspecified"),
            ("::ffff:0.0.0.0", "0.0.0.0", "unspecified"),
            ("224.0.0.1", "224.0.0.1", "multicast"),
            ("ff02::1", "ff02::1", "multicast"),
            ("255.255.255.255:5", "255.255.255.255:5", "broadcast"),
        ] {
            assert_eq!(
                parsed(bad),
                Err(AdvertiseError::Unreachable {
                    address: address.to_owned(),
                    reason
                }),
                "{bad:?}"
            );
        }
        assert_eq!(
            parsed("203.0.113.7:0"),
            Err(AdvertiseError::PortZero("203.0.113.7:0".into()))
        );
        // A unicast address that is neither, at any port, is fine.
        assert!(parsed("192.0.2.255").is_ok());
    }

    #[test]
    fn advertised_addresses_print_as_given_and_errors_name_them() {
        assert_eq!(addr("203.0.113.7").to_string(), "203.0.113.7");
        assert_eq!(addr("203.0.113.7:5").to_string(), "203.0.113.7:5");
        assert_eq!(addr("[2001:db8::7]").to_string(), "2001:db8::7");
        assert_eq!(addr("[2001:db8::7]:5").to_string(), "[2001:db8::7]:5");
        assert_eq!(
            "cam.example"
                .parse::<AdvertisedAddress>()
                .unwrap_err()
                .to_string(),
            "advertised address must be IP or IP:PORT ([IPv6]:PORT), not \"cam.example\"; hostnames are not resolved"
        );
        assert_eq!(
            "[::]:5"
                .parse::<AdvertisedAddress>()
                .unwrap_err()
                .to_string(),
            "advertised address [::]:5 is unspecified, which no browser can reach"
        );
        assert_eq!(
            "192.0.2.1:0"
                .parse::<AdvertisedAddress>()
                .unwrap_err()
                .to_string(),
            "advertised address 192.0.2.1:0 has port 0"
        );
    }

    #[test]
    fn advertised_candidates_carry_rfc_8445_5_1_2_1_and_rfc_6544_4_2_priorities_and_withhold_their_base_rfc_8839_5_1()
     {
        // (2^24)·100 + (2^8)·(65535 − 1 − index) + 255
        assert_eq!(
            candidate_line(0, Protocol::Udp, "203.0.113.7:18556".parse().unwrap()),
            "candidate:au0 1 udp 1694498559 203.0.113.7 18556 typ srflx raddr 0.0.0.0 rport 9"
        );
        assert_eq!(
            candidate_line(1, Protocol::Udp, "203.0.113.8:5".parse().unwrap()),
            "candidate:au1 1 udp 1694498303 203.0.113.8 5 typ srflx raddr 0.0.0.0 rport 9"
        );
        // (2^24)·100 + (2^8)·((2^13)·2 + 8191 − index) + 255
        assert_eq!(
            candidate_line(0, Protocol::Tcp, "203.0.113.7:18557".parse().unwrap()),
            "candidate:at0 1 tcp 1684013055 203.0.113.7 18557 typ srflx raddr 0.0.0.0 rport 9 tcptype passive"
        );
        assert_eq!(
            candidate_line(2, Protocol::Tcp, "[2001:db8::7]:5".parse().unwrap()),
            "candidate:at2 1 tcp 1684012543 2001:db8::7 5 typ srflx raddr :: rport 9 tcptype passive"
        );
    }

    #[test]
    fn each_address_is_a_udp_and_a_tcp_candidate_on_a_base_of_its_family() {
        let captured = Captured::default();
        let _logs = captured.install();
        let hosts = sockets(&["172.17.0.2:18556", "[fd00::2]:18556"]);
        let tcp_hosts = sockets(&["172.17.0.2:18557"]);
        let advertisement = Advertisement::new(
            &[addr("203.0.113.7"), addr("[2001:db8::7]:40000")],
            &hosts,
            &tcp_hosts,
        );
        assert_eq!(
            advertisement.lines(),
            [
                "candidate:au0 1 udp 1694498559 203.0.113.7 18556 typ srflx raddr 0.0.0.0 rport 9",
                "candidate:at0 1 tcp 1684013055 203.0.113.7 18557 typ srflx raddr 0.0.0.0 rport 9 tcptype passive",
                "candidate:au1 1 udp 1694498303 2001:db8::7 40000 typ srflx raddr :: rport 9",
            ]
        );
        // No IPv6 TCP base: that candidate is skipped, with a warning.
        let skipped = captured.lines("no host address of its family");
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(
            skipped[0].contains("WARN") && skipped[0].contains("transport=\"tcp\""),
            "{skipped:?}"
        );
        assert_eq!(captured.lines("advertised candidate").len(), 3);
        let summary = captured.lines("advertised addresses told to browsers");
        assert_eq!(summary.len(), 1, "{summary:?}");
        assert!(
            summary[0].contains("advertised=2") && summary[0].contains("candidates=3"),
            "{summary:?}"
        );
        // The listener off: UDP only.
        let udp_only = Advertisement::new(&[addr("203.0.113.7")], &hosts, &[]);
        assert_eq!(udp_only.lines().len(), 1);
        assert!(udp_only.lines()[0].contains(" udp "));
    }

    #[test]
    fn nothing_advertised_shows_every_candidate_and_logs_nothing() {
        let captured = Captured::default();
        let _logs = captured.install();
        let none = Advertisement::new(&[], &sockets(&["172.17.0.2:18556"]), &[]);
        assert_eq!(none.lines(), Vec::<String>::new());
        assert!(none.shows("candidate:1 1 udp 2130706431 172.17.0.2 18556 typ host"));
        assert!(none.shows("garbage"));
        let sdp = "v=0\r\na=candidate:1 1 udp 1 172.17.0.2 18556 typ host\r\n".to_owned();
        assert_eq!(none.filter_sdp(sdp.clone()), (sdp, 0));
        assert_eq!(captured.lines("advertised"), Vec::<String>::new());
    }

    #[test]
    fn rfc_8445_5_1_3_an_address_equal_to_a_host_candidate_is_that_candidate() {
        let hosts = sockets(&["192.168.1.2:18556"]);
        let tcp_hosts = sockets(&["192.168.1.2:18557"]);
        // Without a port it equals the UDP and the TCP host candidate;
        // with the UDP port, only the UDP one.
        let same = Advertisement::new(&[addr("192.168.1.2")], &hosts, &tcp_hosts);
        assert_eq!(same.lines(), Vec::<String>::new());
        assert!(same.shows("candidate:1 1 udp 2130706431 192.168.1.2 18556 typ host"));
        assert!(
            same.shows("candidate:2 1 tcp 1518280447 192.168.1.2 18557 typ host tcptype passive")
        );
        // Compared canonical.
        assert!(same.shows("candidate:1 1 udp 1 ::ffff:192.168.1.2 18556 typ host"));
        let udp = Advertisement::new(&[addr("192.168.1.2:18556")], &hosts, &tcp_hosts);
        assert_eq!(udp.lines().len(), 1);
        assert!(udp.lines()[0].contains("tcp 1684013055 192.168.1.2 18556 typ srflx"));
        assert!(udp.shows("candidate:1 1 udp 2130706431 192.168.1.2 18556 typ host"));
        assert!(
            !udp.shows("candidate:2 1 tcp 1518280447 192.168.1.2 18557 typ host tcptype passive")
        );
        // The same address over the other transport is not kept.
        assert!(!udp.shows("candidate:3 1 tcp 1 192.168.1.2 18556 typ host tcptype passive"));
    }

    #[test]
    fn with_an_address_advertised_host_candidates_are_hidden_and_the_rest_shown() {
        let advertisement = Advertisement::new(
            &[addr("203.0.113.7")],
            &sockets(&["172.17.0.2:18556"]),
            &sockets(&["172.17.0.2:18557"]),
        );
        for hidden in [
            "candidate:1 1 udp 2130706431 172.17.0.2 18556 typ host",
            "candidate:1 1 UDP 2130706431 172.17.0.2 18556 typ HOST",
            "candidate:2 1 tcp 1518280447 172.17.0.2 18557 typ host tcptype passive",
            "candidate:3 1 udp 2130706431 ::ffff:172.17.0.2 18556 typ host",
            // What does not parse could be a host candidate.
            "candidate:4 1 sctp 1 172.17.0.2 18556 typ srflx",
            "candidate:5 1 udp 1 not-an-ip 18556 typ srflx",
            "candidate:6 1 udp 1 172.17.0.2 port typ srflx",
            "candidate:7 1 udp 1 172.17.0.2 18556 type srflx",
            "candidate:8 1 udp 1 172.17.0.2 18556 typ",
            "candidate:9 1 udp 1 172.17.0.2",
            "1 1 udp 1 172.17.0.2 18556 typ srflx",
        ] {
            assert!(!advertisement.shows(hidden), "{hidden}");
        }
        for shown in [
            "candidate:r1 1 udp 16777215 198.51.100.1 49152 typ relay raddr 172.17.0.2 rport 18556",
            "candidate:s0 1 udp 1694498815 203.0.113.7 18556 typ srflx raddr 0.0.0.0 rport 9",
        ] {
            assert!(advertisement.shows(shown), "{shown}");
        }
    }

    #[test]
    fn rfc_8839_5_1_the_related_address_is_withheld_only_with_an_address_advertised() {
        let base: SocketAddr = "172.17.0.2:18556".parse().unwrap();
        let none = Advertisement::default();
        assert_eq!(none.related("203.0.113.9:4".parse().unwrap(), base), base);
        let active = Advertisement::new(&[addr("203.0.113.7")], &[base], &[]);
        assert_eq!(
            active.related("203.0.113.9:4".parse().unwrap(), base),
            "0.0.0.0:9".parse().unwrap()
        );
        assert_eq!(
            active.related("[2001:db8::9]:4".parse().unwrap(), base),
            "[::]:9".parse().unwrap()
        );
    }

    #[test]
    fn srflx_addresses_are_read_from_server_reflexive_lines_only() {
        assert_eq!(
            srflx_address(
                "candidate:s0 1 UDP 1 ::ffff:203.0.113.7 40000 typ SRFLX raddr 0.0.0.0 rport 9"
            ),
            Some((Protocol::Udp, "203.0.113.7:40000".parse().unwrap()))
        );
        assert_eq!(
            srflx_address(
                "candidate:at0 1 tcp 1 203.0.113.7 18557 typ srflx raddr 0.0.0.0 rport 9 tcptype passive"
            ),
            Some((Protocol::Tcp, "203.0.113.7:18557".parse().unwrap()))
        );
        for other in [
            "candidate:r1 1 udp 1 198.51.100.1 49152 typ relay raddr 0.0.0.0 rport 0",
            "candidate:1 1 udp 1 172.17.0.2 18556 typ host",
            "candidate:s0",
        ] {
            assert_eq!(srflx_address(other), None, "{other}");
        }
    }

    #[test]
    fn the_answer_loses_its_hidden_candidate_lines_and_end_of_candidates_rfc_8838_8_2() {
        let advertisement =
            Advertisement::new(&[addr("203.0.113.7")], &sockets(&["172.17.0.2:18556"]), &[]);
        let sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\n\
                   a=mid:0\r\n\
                   a=candidate:1 1 udp 2130706431 172.17.0.2 18556 typ host\r\n\
                   a=candidate:2 1 tcp 1518280447 172.17.0.2 18557 typ host tcptype passive\r\n\
                   a=candidate:r1 1 udp 16777215 198.51.100.1 49152 typ relay raddr 0.0.0.0 rport 0\r\n\
                   a=candidates-are-not-these\r\n\
                   a=end-of-candidates\r\n\
                   a=end-of-candidates-not\r\n\
                   a=end-of-candidates";
        let (filtered, hidden) = advertisement.filter_sdp(sdp.to_owned());
        assert_eq!(hidden, 2);
        assert_eq!(
            filtered,
            "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\n\
             a=mid:0\r\n\
             a=candidate:r1 1 udp 16777215 198.51.100.1 49152 typ relay raddr 0.0.0.0 rport 0\r\n\
             a=candidates-are-not-these\r\n\
             a=end-of-candidates-not\r\n"
        );
    }
}

//! The host addresses, the local side of every host candidate
//! (RFC 8445 §5.1.1.1), found in the main thread before the sandbox.
//!
//! An explicitly bound address is the one host address, used as given.
//! For an unspecified bind, every address of every interface that is up
//! is one (`getifaddrs(3)`), of the families the socket accepts, except
//! (each skip logged with its reason):
//!
//! - loopback interfaces and addresses (RFC 8445 §5.1.1.1, MUST NOT);
//! - link-local addresses, whose IPv6 scope id a candidate cannot carry
//!   (and which §5.1.1.1 forbids next to a temporary address);
//! - IPv6 site-local and IPv4-compatible addresses (§5.1.1.1, MUST NOT)
//!   and IPv4-mapped ones (SHOULD NOT; lotse speaks IPv4);
//! - Docker's interfaces, by name: `docker0`, user-defined bridges `br-*`,
//!   container ends `veth*` and `hassio`, a network some deployments
//!   create (observed 2026-09), which no viewer can reach. Docker's address pools overlap
//!   home LANs, so the address cannot tell;
//! - all but one IPv6 address per interface and /64 prefix (the prefix of
//!   every interface identifier, RFC 4291 §2.5.1): §5.1.1.1 forbids a
//!   trackable address next to a temporary one (RFC 8981) on the same
//!   interface and prefix, and `getifaddrs(3)` does not say which one is
//!   temporary. The default-route address is kept where it is one of
//!   them, which is the temporary one whenever the kernel prefers
//!   temporaries (RFC 6724 §5, rule 7); else the first listed.
//!
//! The address the kernel routes from by default, learned per family by
//! connecting a probe socket to a documentation address (RFC 5737,
//! RFC 3849) without sending anything, comes first: str0m ranks a family's
//! host candidates in the order they are added, so it gets the highest
//! local preference. Should the enumeration fail, the probed addresses
//! alone are offered, Docker's default networks then recognized by
//! address.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

/// The IPv4 probe target: TEST-NET-1 (RFC 5737 §3), never answered.
pub(super) const PROBE_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);

/// The IPv6 probe target: the documentation prefix (RFC 3849).
pub(super) const PROBE_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
    9,
);

/// One address of a network interface, as `getifaddrs(3)` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InterfaceAddress {
    /// The interface's name, `eth0` or `docker0`.
    pub(super) name: String,
    /// The address.
    pub(super) ip: IpAddr,
    /// The interface is up (`IFF_UP`).
    pub(super) up: bool,
    /// The interface is a loopback one (`IFF_LOOPBACK`).
    pub(super) loopback: bool,
}

/// Every IPv4 and IPv6 address of every interface, in the order
/// `getifaddrs(3)` lists them; the link-layer entries are left out.
pub(super) fn interfaces() -> io::Result<Vec<InterfaceAddress>> {
    let listed = getifaddrs().map_err(io::Error::from)?;
    Ok(listed
        .filter_map(|entry| {
            let address = entry.address?;
            let ip = match address.as_sockaddr_in() {
                Some(v4) => IpAddr::V4(v4.ip()),
                None => IpAddr::V6(address.as_sockaddr_in6()?.ip()),
            };
            Some(InterfaceAddress {
                name: entry.interface_name,
                ip,
                up: entry.flags.contains(InterfaceFlags::IFF_UP),
                loopback: entry.flags.contains(InterfaceFlags::IFF_LOOPBACK),
            })
        })
        .collect())
}

/// The source address the kernel would use towards `target`: a connected
/// UDP socket sends nothing until asked to.
pub(super) fn probe(target: SocketAddr) -> Option<IpAddr> {
    let any: SocketAddr = match target {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(any).ok()?;
    socket.connect(target).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// The host addresses of a socket bound at `local`, accepting IPv4 too
/// when `dual_stack`: `local` itself when it names an address, otherwise
/// the offered addresses `interfaces` lists, the ones `probe` finds the
/// default route from first ([module docs](self)).
pub(super) fn host_addresses(
    local: SocketAddr,
    dual_stack: bool,
    probe: impl Fn(SocketAddr) -> Option<IpAddr>,
    interfaces: impl FnOnce() -> io::Result<Vec<InterfaceAddress>>,
) -> Vec<SocketAddr> {
    if !local.ip().is_unspecified() {
        return vec![SocketAddr::new(local.ip().to_canonical(), local.port())];
    }
    let targets: &[SocketAddr] = match local {
        SocketAddr::V4(_) => &[PROBE_V4],
        SocketAddr::V6(_) if dual_stack => &[PROBE_V4, PROBE_V6],
        SocketAddr::V6(_) => &[PROBE_V6],
    };
    let defaults: Vec<IpAddr> = targets
        .iter()
        .filter_map(|target| probe(*target))
        .map(|ip| ip.to_canonical())
        .collect();
    let ips = match interfaces() {
        Ok(listed) => offered(listed, &defaults, |ip| {
            targets
                .iter()
                .any(|target| target.is_ipv4() == ip.is_ipv4())
        }),
        Err(err) => {
            tracing::warn!(
                error = %err,
                "interfaces not enumerated; offering the default-route addresses alone"
            );
            defaults.into_iter().filter(|ip| usable(*ip)).collect()
        }
    };
    ips.into_iter()
        .map(|ip| SocketAddr::new(ip, local.port()))
        .collect()
}

/// The addresses of `listed` that are offered, of the families `accepts`
/// takes, each once: the default-route ones among them first, in the
/// order of `defaults`, then the rest as listed.
fn offered(
    listed: Vec<InterfaceAddress>,
    defaults: &[IpAddr],
    accepts: impl Fn(IpAddr) -> bool,
) -> Vec<IpAddr> {
    let mut kept: Vec<InterfaceAddress> = Vec::new();
    for address in listed {
        if !accepts(address.ip) {
            continue;
        }
        if let Some(reason) = excluded(&address) {
            tracing::debug!(
                interface = address.name,
                ip = %address.ip,
                reason,
                "interface address not offered"
            );
            continue;
        }
        match kept.iter().position(|other| same_prefix(other, &address)) {
            None => kept.push(address),
            Some(at) => {
                if let Some(slot) = kept.get_mut(at)
                    && defaults.contains(&address.ip)
                {
                    tracing::debug!(
                        interface = address.name,
                        ip = %slot.ip,
                        reason = "the default-route address shares its interface and prefix",
                        "interface address not offered"
                    );
                    *slot = address;
                } else {
                    tracing::debug!(
                        interface = address.name,
                        ip = %address.ip,
                        reason = "another address shares its interface and prefix",
                        "interface address not offered"
                    );
                }
            }
        }
    }
    // An address listed on two interfaces is offered once.
    let mut hosts: Vec<IpAddr> = defaults
        .iter()
        .copied()
        .filter(|ip| kept.iter().any(|address| address.ip == *ip))
        .collect();
    for address in kept {
        if !hosts.contains(&address.ip) {
            hosts.push(address.ip);
        }
    }
    hosts
}

/// Why an interface address is not offered; `None` when it is.
fn excluded(address: &InterfaceAddress) -> Option<&'static str> {
    if !address.up {
        Some("interface down")
    } else if address.loopback {
        Some("loopback interface")
    } else if docker_interface(&address.name) {
        Some("docker network")
    } else {
        unusable(address.ip)
    }
}

/// Docker's interfaces, which no viewer can reach (observed 2026-09): the
/// default bridge, user-defined bridges, the host ends of containers'
/// links and the `hassio` network some deployments create.
fn docker_interface(name: &str) -> bool {
    name == "docker0" || name == "hassio" || name.starts_with("br-") || name.starts_with("veth")
}

/// Two IPv6 addresses on one interface in one /64 prefix (RFC 4291
/// §2.5.1), of which RFC 8445 §5.1.1.1 lets only the temporary one be a
/// candidate.
fn same_prefix(a: &InterfaceAddress, b: &InterfaceAddress) -> bool {
    match (a.ip, b.ip) {
        (IpAddr::V6(x), IpAddr::V6(y)) => {
            a.name == b.name && x.octets().get(..8) == y.octets().get(..8)
        }
        _ => false,
    }
}

/// Why `ip` is never a host candidate unasked, on whatever interface:
/// loopback and unspecified addresses, link-local ones (`169.254/16`,
/// `fe80::/10`), and IPv6 site-local (`fec0::/10`), IPv4-compatible
/// (`::/96`) and IPv4-mapped (`::ffff:0:0/96`, a SHOULD NOT) ones
/// (RFC 8445 §5.1.1.1); `None` when it may be one.
fn unusable(ip: IpAddr) -> Option<&'static str> {
    match ip {
        _ if ip.is_loopback() => Some("loopback"),
        _ if ip.is_unspecified() => Some("unspecified"),
        IpAddr::V4(v4) if v4.is_link_local() => Some("link-local"),
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) if v6.is_unicast_link_local() => Some("link-local"),
        IpAddr::V6(v6) => match v6.segments() {
            [first, ..] if first & 0xffc0 == 0xfec0 => Some("site-local"),
            [0, 0, 0, 0, 0, 0, _, _] => Some("ipv4-compatible"),
            [0, 0, 0, 0, 0, 0xffff, _, _] => Some("ipv4-mapped"),
            _ => None,
        },
    }
}

/// Docker networks no viewer can reach, recognized by address where the
/// interfaces are unknown: Docker's default bridge `docker0`
/// (`172.17.0.0/16`) and the `hassio` network some deployments
/// create (`172.30.32.0/23`), both observed 2026-09.
const DOCKER_NETWORKS: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(172, 17, 0, 0), 16),
    (Ipv4Addr::new(172, 30, 32, 0), 23),
];

/// Whether `ip` lies in `network`/`prefix`.
fn in_network(ip: Ipv4Addr, (network, prefix): (Ipv4Addr, u8)) -> bool {
    let mask = u32::MAX
        .checked_shl(32_u32.saturating_sub(u32::from(prefix)))
        .unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
}

/// Whether a probed address may be a host candidate when the interfaces
/// are unknown: not [`unusable`] and not on a [`DOCKER_NETWORKS`] one.
fn usable(ip: IpAddr) -> bool {
    unusable(ip).is_none()
        && match ip {
            IpAddr::V4(v4) => !DOCKER_NETWORKS.iter().any(|net| in_network(v4, *net)),
            IpAddr::V6(_) => true,
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

    fn at(name: &str, ip: &str) -> InterfaceAddress {
        InterfaceAddress {
            name: name.into(),
            ip: ip.parse().unwrap(),
            up: true,
            loopback: false,
        }
    }

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    /// A multi-homed host: a LAN with IPv6, a camera VLAN, and everything
    /// that must not be offered.
    fn host() -> Vec<InterfaceAddress> {
        vec![
            InterfaceAddress {
                loopback: true,
                ..at("lo", "127.0.0.1")
            },
            InterfaceAddress {
                loopback: true,
                ..at("lo", "::1")
            },
            at("eth0", "192.168.1.2"),
            at("eth0", "2001:db8:1:1::2"),
            at("eth0", "fe80::2"),
            at("eth0", "2001:db8:1:1::abcd"),
            at("eth0", "fd00:1::2"),
            at("eth1", "10.0.5.2"),
            at("eth1", "10.0.5.3"),
            at("eth1", "2001:db8:1:1::5"),
            at("docker0", "172.17.0.1"),
            at("br-3f2a", "192.168.200.1"),
            at("veth12ab", "fe80::99"),
            at("hassio", "172.30.32.1"),
            at("wlan0", "169.254.3.3"),
            InterfaceAddress {
                up: false,
                ..at("eth2", "10.9.9.9")
            },
            at("tun0", "fec0::1"),
            at("tun0", "::10.1.2.3"),
            at("eth9", "192.168.1.2"),
        ]
    }

    fn route(target: SocketAddr) -> IpAddr {
        match target {
            SocketAddr::V4(_) => "10.0.5.3".parse().unwrap(),
            SocketAddr::V6(_) => "2001:db8:1:1::abcd".parse().unwrap(),
        }
    }

    #[test]
    fn rfc8445_5_1_1_1_every_interface_but_the_excluded_default_route_first() {
        let routed = |target| Some(route(target));
        let hosts = host_addresses("[::]:18556".parse().unwrap(), true, routed, || Ok(host()));
        assert_eq!(
            hosts,
            addrs(&[
                // The default route of each family, then the rest as listed.
                "10.0.5.3:18556",
                "[2001:db8:1:1::abcd]:18556",
                "192.168.1.2:18556",
                "[fd00:1::2]:18556",
                "10.0.5.2:18556",
                // Another interface in the same prefix keeps its own.
                "[2001:db8:1:1::5]:18556",
            ])
        );
        // The families the socket accepts.
        assert_eq!(
            host_addresses("[::]:7".parse().unwrap(), false, routed, || Ok(host())),
            addrs(&[
                "[2001:db8:1:1::abcd]:7",
                "[fd00:1::2]:7",
                "[2001:db8:1:1::5]:7"
            ])
        );
        assert_eq!(
            host_addresses("0.0.0.0:7".parse().unwrap(), true, routed, || Ok(host())),
            addrs(&["10.0.5.3:7", "192.168.1.2:7", "10.0.5.2:7"])
        );
    }

    #[test]
    fn rfc8445_5_1_1_1_one_ipv6_address_per_interface_and_prefix() {
        // Without a default route the first listed of a prefix stays.
        assert_eq!(
            host_addresses("[::]:7".parse().unwrap(), false, |_| None, || Ok(host())),
            addrs(&[
                "[2001:db8:1:1::2]:7",
                "[fd00:1::2]:7",
                "[2001:db8:1:1::5]:7"
            ])
        );
        // A default route elsewhere leaves the prefix's first in place.
        let elsewhere = |_| Some("2001:db8:9::1".parse().unwrap());
        assert_eq!(
            host_addresses("[::]:7".parse().unwrap(), false, elsewhere, || Ok(host())),
            addrs(&[
                "[2001:db8:1:1::2]:7",
                "[fd00:1::2]:7",
                "[2001:db8:1:1::5]:7"
            ])
        );
        // IPv4 addresses share no such limit; IPv6 in another /64 neither.
        let a = at("eth0", "2001:db8:1:1::1");
        assert!(!same_prefix(&a, &at("eth0", "2001:db8:1:2::1")));
        assert!(!same_prefix(&a, &at("eth1", "2001:db8:1:1::1")));
        assert!(same_prefix(&a, &at("eth0", "2001:db8:1:1:ffff::1")));
        assert!(!same_prefix(
            &at("eth0", "10.0.0.1"),
            &at("eth0", "10.0.0.2")
        ));
        assert!(!same_prefix(&a, &at("eth0", "10.0.0.2")));
    }

    #[test]
    fn a_probed_address_that_is_not_offered_is_not_preferred() {
        let docker = |_| Some("172.17.0.1".parse().unwrap());
        assert_eq!(
            host_addresses("0.0.0.0:7".parse().unwrap(), false, docker, || Ok(host())),
            addrs(&["192.168.1.2:7", "10.0.5.2:7", "10.0.5.3:7"])
        );
    }

    #[test]
    fn each_exclusion_names_its_reason() {
        let cases = [
            (
                InterfaceAddress {
                    up: false,
                    ..at("eth0", "10.0.0.1")
                },
                Some("interface down"),
            ),
            (
                InterfaceAddress {
                    loopback: true,
                    ..at("lo", "10.0.0.1")
                },
                Some("loopback interface"),
            ),
            (at("docker0", "10.0.0.1"), Some("docker network")),
            (at("hassio", "10.0.0.1"), Some("docker network")),
            (at("br-0123abcd", "10.0.0.1"), Some("docker network")),
            (at("veth0", "10.0.0.1"), Some("docker network")),
            (at("eth0", "127.0.0.2"), Some("loopback")),
            (at("eth0", "::1"), Some("loopback")),
            (at("eth0", "0.0.0.0"), Some("unspecified")),
            (at("eth0", "::"), Some("unspecified")),
            (at("eth0", "169.254.0.1"), Some("link-local")),
            (at("eth0", "fe80::1"), Some("link-local")),
            (at("eth0", "fec0::1"), Some("site-local")),
            (at("eth0", "feff::1"), Some("site-local")),
            (at("eth0", "::192.0.2.1"), Some("ipv4-compatible")),
            (at("eth0", "10.0.0.1"), None),
            (at("br0", "10.0.0.1"), None),
            (at("docker1", "10.0.0.1"), None),
            (at("eth0", "172.17.0.2"), None),
            (at("eth0", "fe00::1"), None),
            (at("eth0", "fd00::1"), None),
            (at("eth0", "2001:db8::1"), None),
            (at("eth0", "::1:0:0:0:1"), None),
            (at("eth0", "::ffff:192.0.2.1"), Some("ipv4-mapped")),
            (at("eth0", "::fffe:192.0.2.1"), None),
        ];
        for (address, reason) in cases {
            assert_eq!(excluded(&address), reason, "{address:?}");
        }
    }

    #[test]
    fn host_addresses_are_the_bound_address_or_the_probed_usable_ones_unenumerated() {
        // The interfaces do not change an explicit bind.
        let unasked = || Ok(host());
        let explicit = host_addresses("127.0.0.1:5".parse().unwrap(), false, |_| None, unasked);
        assert_eq!(explicit, addrs(&["127.0.0.1:5"]));
        // A v4-mapped bind is reported as the IPv4 address it is.
        let mapped = host_addresses(
            "[::ffff:192.0.2.7]:5".parse().unwrap(),
            true,
            |_| None,
            unasked,
        );
        assert_eq!(mapped, addrs(&["192.0.2.7:5"]));
        // An explicit bind is used as given, Docker network or not.
        assert_eq!(
            host_addresses("172.17.0.2:5".parse().unwrap(), false, |_| None, unasked),
            addrs(&["172.17.0.2:5"])
        );
        let failed = || Err(io::Error::other("no interfaces"));
        let routed = |target: SocketAddr| {
            Some(match target {
                SocketAddr::V4(_) => "192.168.1.2".parse().unwrap(),
                SocketAddr::V6(_) => "2001:db8::2".parse().unwrap(),
            })
        };
        assert_eq!(
            host_addresses("[::]:18556".parse().unwrap(), true, routed, failed),
            addrs(&["192.168.1.2:18556", "[2001:db8::2]:18556"])
        );
        assert_eq!(
            host_addresses("[::]:18556".parse().unwrap(), false, routed, failed),
            addrs(&["[2001:db8::2]:18556"])
        );
        assert_eq!(
            host_addresses("0.0.0.0:18556".parse().unwrap(), true, routed, failed),
            addrs(&["192.168.1.2:18556"])
        );
        // No route, or only unusable addresses: nothing.
        assert!(host_addresses("[::]:1".parse().unwrap(), true, |_| None, failed).is_empty());
        for unusable in [
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "::",
            "172.17.0.1",
            "172.17.255.255",
            "172.30.32.1",
            "172.30.33.254",
        ] {
            let ip: IpAddr = unusable.parse().unwrap();
            assert!(!usable(ip), "{unusable}");
            assert!(
                host_addresses("[::]:1".parse().unwrap(), true, |_| Some(ip), failed).is_empty()
            );
        }
        for fine in [
            "10.0.0.1",
            "2001:db8::1",
            "172.16.255.255",
            "172.18.0.1",
            "172.30.31.255",
            "172.30.34.1",
            "192.168.1.2",
        ] {
            assert!(usable(fine.parse().unwrap()), "{fine}");
        }
        // A /0 network holds everything.
        assert!(in_network(
            "1.2.3.4".parse().unwrap(),
            ("9.9.9.9".parse().unwrap(), 0)
        ));
    }

    #[test]
    fn the_interfaces_include_the_loopback_one_up() {
        let listed = interfaces().unwrap();
        let lo = listed
            .iter()
            .find(|address| address.ip == IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("127.0.0.1 on an interface");
        assert!(lo.up && lo.loopback, "{lo:?}");
        assert!(lo.name.starts_with("lo"), "{lo:?}");
        // No link-layer entry comes through as an address.
        assert!(listed.iter().all(|address| !address.ip.is_unspecified()));
    }

    #[test]
    fn the_probe_names_the_routed_source_address() {
        // Loopback always routes, from loopback.
        assert_eq!(
            probe("127.0.0.1:9".parse().unwrap()),
            Some("127.0.0.1".parse().unwrap())
        );
        // Whatever the host's routes, a probe never yields an unspecified
        // address, and the documentation targets are never answered.
        for target in [PROBE_V4, PROBE_V6] {
            assert!(probe(target).is_none_or(|ip| !ip.is_unspecified()));
        }
    }
}

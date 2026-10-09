//! Host resolution for a source connection. The supervisor resolves camera
//! hosts because workers have no DNS.
//! IP literals need no lookup; names go through the platform resolver on
//! the runtime's blocking pool (`getaddrinfo(3)`, which reads
//! `/etc/resolv.conf` and `/etc/hosts`, both kept readable by the
//! supervisor's Landlock rules). No mDNS: `.local` names are the
//! client's to resolve.

use std::net::{IpAddr, SocketAddr};

/// Resolves `host`, as a source URL spells it (an IPv6 literal keeps its
/// brackets), to the addresses to try in order, with `port` applied.
pub(crate) async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    if let Some(ip) = literal(host) {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| format!("{host}: {err}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host}: no addresses"));
    }
    Ok(addrs)
}

/// The address `host` names, when it is a literal.
fn literal(host: &str) -> Option<IpAddr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse().ok()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use super::*;

    #[tokio::test]
    async fn literals_resolve_without_a_lookup_and_names_go_through_the_resolver() {
        assert_eq!(
            resolve("192.168.1.10", 554).await.unwrap(),
            ["192.168.1.10:554".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            resolve("[::1]", 8554).await.unwrap(),
            ["[::1]:8554".parse::<SocketAddr>().unwrap()]
        );
        assert!(literal("cam").is_none());
        let localhost = resolve("localhost", 1).await.unwrap();
        assert!(
            localhost
                .iter()
                .all(|addr| addr.ip().is_loopback() && addr.port() == 1),
            "{localhost:?}"
        );
        let err = resolve("", 1).await.unwrap_err();
        assert!(err.starts_with(':'), "{err}");
    }
}

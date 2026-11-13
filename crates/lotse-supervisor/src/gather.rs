//! Gathering for one session: the `stun:` servers of the offer's
//! `ice_servers`, a Binding from the shared socket to each, and the
//! `srflx` candidate the mapped address becomes; and the `turn:` and
//! `turns:` servers, a lease on each one's shared allocation over UDP, TCP
//! or TLS over TCP, whose relayed address the worker's agent takes as a
//! relay candidate.
//!
//! Implements RFC 7064 §3.1 (the `stun:` URI: host and optional port,
//! default 3478), RFC 7065 §3.1 (the `turn:` and `turns:` URIs: host,
//! optional port, default 3478 and 5349, and optional transport; a
//! `turns:` URI over UDP asks for DTLS, RFC 7350, which is not supported),
//! RFC 8489 §6.2.3 (a `turns:` server proves the URI's host name to the
//! embedded roots), RFC 8445 §5.1.1.2 (a
//! server-reflexive candidate and its base), §5.1.2.1 (its priority),
//! §5.1.1.3 (its foundation) and §5.1.3 (a candidate equal to its base is
//! redundant and dropped), and RFC 8839 §5.1 (the `candidate` attribute).
//! The worker's ICE agent needs no srflx candidate of its own: the
//! browser's checks to it arrive at the host address through the NAT, so
//! only the browser is told. A relay candidate is the agent's own: it
//! sends from it, so the worker makes its line.

use std::net::SocketAddr;
use std::time::Duration;

use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::session::{IceServer, SessionEvent, WarningCode};
use lotse_core::secret::Secret;
use lotse_tls::{TlsTarget, Trust};

use crate::net::allocation::Transport;
use crate::net::credential::Credentials;
use crate::net::stun_client::StunClient;
use crate::net::turn_client::{Lease, TurnClient, Via};

/// How long end-of-candidates waits for the gathers after the offer.
pub(crate) const GATHER_DEADLINE: Duration = Duration::from_secs(2);

/// STUN servers asked per session; more add no candidate a viewer needs.
pub(crate) const MAX_STUN_SERVERS: usize = 4;

/// TURN servers asked per session; each is one shared allocation.
pub(crate) const MAX_TURN_SERVERS: usize = 4;

/// Warnings an offer's `ice_servers` yield; the rest are logged. The
/// session's queue must hold them with its `session` event before them
/// and a `closed` event after, so an offer closed at once never loses
/// its close.
pub(crate) const MAX_WARNINGS: usize = 4;

/// The default port of a `stun:` and a `turn:` URI (RFC 7064 §3.1, RFC
/// 7065 §3.1, RFC 8489 §18.6).
const STUN_PORT: u16 = 3478;

/// The default port of a `turns:` URI (RFC 7065 §3.1, RFC 8489 §18.6).
const TURNS_PORT: u16 = 5349;

/// The type preference of a server-reflexive candidate (RFC 8445
/// §5.1.2.2 recommends 100).
pub(crate) const SRFLX_TYPE_PREFERENCE: u32 = 100;

/// The local preference of the one base per family (RFC 8445 §5.1.2.1:
/// 65535 when there is a single one).
pub(crate) const LOCAL_PREFERENCE: u32 = 65_535;

/// The RTP component; rtcp-mux leaves only this one (RFC 5761).
pub(crate) const COMPONENT: u32 = 1;

/// A `stun:` server as its URI names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StunServer {
    /// The host, an IPv6 literal with its brackets.
    pub(crate) host: String,
    /// The port.
    pub(crate) port: u16,
}

/// A `turn:` or `turns:` server as its URI names it, with its entry's
/// long-term credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TurnServer {
    /// The host and port.
    pub(crate) server: StunServer,
    /// How it is reached (RFC 7065 §3.1); over TLS, the host as the name
    /// its certificate must carry, checked against the embedded roots.
    pub(crate) via: Via,
    /// The entry's username and credential.
    pub(crate) credentials: Credentials,
}

/// What `ice_servers` asks of a session.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct IcePlan {
    /// Warnings for entries not supported yet, at most [`MAX_WARNINGS`].
    pub(crate) warnings: Vec<SessionEvent>,
    /// The STUN servers to gather from, at most [`MAX_STUN_SERVERS`].
    pub(crate) stun: Vec<StunServer>,
    /// The TURN servers to allocate on, at most [`MAX_TURN_SERVERS`].
    pub(crate) turn: Vec<TurnServer>,
}

/// Checks `ice_servers`: only `stun:`, `turn:` and `turns:` URIs (RFC 7064,
/// RFC 7065). A `turns:` URI is TLS over TCP, its host a TLS server name
/// (RFC 8489 §6.2.3); one with `?transport=udp` asks for DTLS (RFC 7350),
/// which is not supported, and yields a `turn_unsupported` warning, the
/// first [`MAX_WARNINGS`] of them. A `turn:` or `turns:` entry without a
/// username and credential is skipped: TURN asks for the long-term
/// credential (RFC 8656 §5), and browsers refuse such an entry (W3C WebRTC
/// 1.0 §4.2.1). A server over TCP or TLS is skipped when the list names
/// its host and port over UDP too: all relay over UDP to the peer (§7.1),
/// so the UDP allocation is enough, and what a session sends through a
/// stream passes through the supervisor, which owns the connection.
pub(crate) fn plan(servers: &[IceServer]) -> Result<IcePlan, ApiError> {
    let mut plan = IcePlan::default();
    for (entry, url) in servers
        .iter()
        .flat_map(|server| server.urls.iter().map(move |url| (server, url)))
    {
        let (scheme, rest) = url.split_once(':').unwrap_or(("", ""));
        match scheme.to_ascii_lowercase().as_str() {
            "stun" => {
                let server = parse_stun(rest).ok_or_else(|| {
                    ApiError::new(ErrorCode::InvalidRequest, "not a stun: URI (RFC 7064)")
                        .with_detail("url", url.as_str())
                })?;
                if plan.stun.len() < MAX_STUN_SERVERS {
                    plan.stun.push(server);
                } else {
                    tracing::debug!(url, "stun server beyond the per-session limit ignored");
                }
            }
            scheme @ ("turn" | "turns") => {
                let tls = scheme == "turns";
                let default_port = if tls { TURNS_PORT } else { STUN_PORT };
                let (server, query) = parse_turn(rest, default_port).ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::InvalidRequest,
                        format!("not a {scheme}: URI (RFC 7065)"),
                    )
                    .with_detail("url", url.as_str())
                })?;
                let via = match (tls, query) {
                    (false, TransportQuery::Tcp) => Via::Tcp,
                    (false, TransportQuery::Udp | TransportQuery::None) => Via::Udp,
                    (true, TransportQuery::Udp) => {
                        warn_unsupported(&mut plan, url);
                        continue;
                    }
                    (true, TransportQuery::Tcp | TransportQuery::None) => {
                        Via::Tls(TlsTarget::new(&server.host, Trust::Roots).map_err(|err| {
                            ApiError::new(ErrorCode::InvalidRequest, err)
                                .with_detail("url", url.as_str())
                        })?)
                    }
                };
                let (Some(username), Some(password)) = (&entry.username, &entry.credential) else {
                    tracing::info!(url, "turn server without username and credential ignored");
                    continue;
                };
                let turn = TurnServer {
                    server,
                    via,
                    credentials: Credentials {
                        username: username.clone(),
                        password: Secret::new(password.clone()),
                    },
                };
                if plan.turn.contains(&turn) {
                    tracing::debug!(url, "turn server named twice");
                } else {
                    plan.turn.push(turn);
                }
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "ice_servers urls must be stun:, turn: or turns:",
                )
                .with_detail("url", url.as_str()));
            }
        }
    }
    let udp: Vec<StunServer> = plan
        .turn
        .iter()
        .filter(|turn| turn.via == Via::Udp)
        .map(|turn| turn.server.clone())
        .collect();
    plan.turn.retain(|turn| {
        let transport = turn.via.transport();
        let redundant =
            transport.is_stream() && udp.iter().any(|other| same_server(other, &turn.server));
        if redundant {
            let transport = transport.name();
            tracing::debug!(
                host = turn.server.host,
                port = turn.server.port,
                transport,
                "turn server over a stream named over udp too; the udp allocation relays"
            );
        }
        !redundant
    });
    let kept = plan.turn.len().min(MAX_TURN_SERVERS);
    for ignored in plan.turn.drain(kept..) {
        tracing::debug!(
            host = ignored.server.host,
            "turn server beyond the per-session limit ignored"
        );
    }
    Ok(plan)
}

/// Warns of a `turns:` URI over UDP, DTLS (RFC 7350), which is not
/// supported: a `turn_unsupported` warning while fewer than
/// [`MAX_WARNINGS`] were given, else a log line.
fn warn_unsupported(plan: &mut IcePlan, url: &str) {
    if plan.warnings.len() < MAX_WARNINGS {
        plan.warnings.push(SessionEvent::Warning {
            code: WarningCode::TurnUnsupported,
            message: format!("{url} ignored: TURN over DTLS is not supported"),
            reason: None,
            status: None,
        });
    } else {
        tracing::debug!(
            url,
            "turns: server over dtls beyond the warning limit ignored"
        );
    }
}

/// Whether two URIs name one server: the host ignoring ASCII case (RFC
/// 3986 §6.2.2.1) and the port.
fn same_server(one: &StunServer, other: &StunServer) -> bool {
    one.port == other.port && one.host.eq_ignore_ascii_case(&other.host)
}

/// The `?transport=` query of a `turn:` or `turns:` URI (RFC 7065 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportQuery {
    /// None: UDP for `turn:`, TCP for `turns:`.
    None,
    /// `udp`: DTLS for `turns:` (RFC 7350).
    Udp,
    /// `tcp`.
    Tcp,
}

/// The server after `turn:` or `turns:` and the transport it asks for
/// (RFC 7065 §3.1: `host [ ":" port ] [ "?transport=" transport ]`,
/// transport `udp` or `tcp`), `default_port` when it names none. Another
/// transport, or another query, fails.
fn parse_turn(rest: &str, default_port: u16) -> Option<(StunServer, TransportQuery)> {
    let (address, transport) = match rest.split_once('?') {
        None => (rest, TransportQuery::None),
        Some((address, query)) => match query.to_ascii_lowercase().as_str() {
            "transport=udp" => (address, TransportQuery::Udp),
            "transport=tcp" => (address, TransportQuery::Tcp),
            _ => return None,
        },
    };
    parse_host(address, default_port).map(|server| (server, transport))
}

/// The host and port after `stun:` (RFC 7064 §3.1: `host [ ":" port ]`).
/// User info, a path or a query fail the host or port syntax.
fn parse_stun(rest: &str) -> Option<StunServer> {
    parse_host(rest, STUN_PORT)
}

/// `host [ ":" port ]` of a `stun:`, `turn:` or `turns:` URI (RFC 7064
/// §3.1, RFC 7065 §3.1), `default_port` when it names none.
fn parse_host(rest: &str, default_port: u16) -> Option<StunServer> {
    let (host, port) = match rest.rsplit_once(':') {
        // An IPv6 literal without a port ends in its bracket.
        Some((host, port)) if !port.contains(']') => (host, Some(port)),
        _ => (rest, None),
    };
    let bracketed = host.starts_with('[');
    let valid_host = if bracketed {
        host.strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .is_some_and(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok())
    } else {
        !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    };
    let port = match port {
        Some(port) => port.parse().ok().filter(|port| *port != 0)?,
        None => default_port,
    };
    valid_host.then(|| StunServer {
        host: host.to_owned(),
        port,
    })
}

/// The `candidate` attribute value of a server-reflexive candidate
/// (RFC 8839 §5.1), with the RFC 8445 §5.1.2.1 priority and `related` as
/// its related address: its base, or the withheld one §5.1 allows
/// ([`Advertisement::related`](crate::advertise::Advertisement::related)).
pub(crate) fn srflx_candidate(
    foundation: usize,
    mapped: SocketAddr,
    related: SocketAddr,
) -> String {
    let priority = (SRFLX_TYPE_PREFERENCE << 24) | (LOCAL_PREFERENCE << 8) | (256 - COMPONENT);
    format!(
        "candidate:s{foundation} {COMPONENT} udp {priority} {} {} typ srflx raddr {} rport {}",
        mapped.ip(),
        mapped.port(),
        related.ip(),
        related.port()
    )
}

/// Resolves `server` to an address the shared socket reaches from one of
/// `hosts`: the first of a family a host address has, in canonical form,
/// with that host address.
async fn reach(server: &StunServer, hosts: &[SocketAddr]) -> Option<(SocketAddr, SocketAddr)> {
    let addrs = match crate::resolve::resolve(&server.host, server.port).await {
        Ok(addrs) => addrs,
        Err(error) => {
            tracing::warn!(host = server.host, error, "ice server not resolved");
            return None;
        }
    };
    let reached = addrs.iter().find_map(|addr| {
        let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
        hosts
            .iter()
            .find(|host| host.is_ipv4() == addr.is_ipv4())
            .map(|base| (addr, *base))
    });
    if reached.is_none() {
        tracing::debug!(
            host = server.host,
            "no host address of the ice server's family"
        );
    }
    reached
}

/// Gathers from one server: resolves it, sends from the host address of
/// the family it resolves to, and returns the mapped address with its
/// base; `None` when that fails or the candidate is redundant (no NAT).
/// `hosts` are of `generation`, whose mapping the client asks for
/// (RFC 8445 §5.1.1.2: the candidate is relative to its base).
pub(crate) async fn gather(
    client: &StunClient,
    server: &StunServer,
    hosts: &[SocketAddr],
    generation: u64,
) -> Option<(SocketAddr, SocketAddr)> {
    let (target, base) = reach(server, hosts).await?;
    let mapped = client.reflexive(target, generation).await.ok()?;
    if mapped == base {
        tracing::debug!(%mapped, "server-reflexive address equals its base; redundant");
        return None;
    }
    Some((mapped, base))
}

/// A lease on a TURN server's allocation, for one session's relay
/// candidate.
#[derive(Debug)]
pub(crate) struct Relayed {
    /// The lease.
    pub(crate) lease: Lease,
    /// The server, as resolved.
    pub(crate) server: SocketAddr,
    /// The transport to it; on a stream (TCP or TLS) what the session
    /// sends goes through the supervisor.
    pub(crate) transport: Transport,
    /// The host address the allocation's traffic leaves from.
    pub(crate) local: SocketAddr,
}

/// Leases the allocation on `server` over its transport (made with its
/// credential if there is none yet), reached from the host address of the
/// family it resolves to; `None` when that fails. `hosts` are of
/// `generation`, which a TCP or TLS allocation must have been connected on
/// (RFC 8656 §5: an allocation is bound to its 5-tuple).
pub(crate) async fn relay(
    client: &TurnClient,
    server: &TurnServer,
    hosts: &[SocketAddr],
    generation: u64,
) -> Option<Relayed> {
    let (target, local) = reach(&server.server, hosts).await?;
    match client
        .lease(target, &server.via, generation, &server.credentials)
        .await
    {
        Ok(lease) => Some(Relayed {
            lease,
            server: target,
            transport: server.via.transport(),
            local,
        }),
        Err(err) => {
            tracing::warn!(server = %target, error = %err, "turn allocation failed");
            None
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

    use std::net::UdpSocket;
    use std::sync::Arc;

    use lotse_core::clock::SystemClock;
    use serde_json::json;

    use super::*;
    use crate::net::demux::Demux;
    use crate::net::stun::{self, Builder, Class, METHOD_BINDING};
    use crate::net::stun_client::StunClientConfig;

    fn servers(urls: &[&str]) -> Vec<IceServer> {
        vec![serde_json::from_value(json!({ "urls": urls })).unwrap()]
    }

    #[test]
    fn stun_uris_parse_per_rfc_7064_3_1() {
        let parse = |rest: &str| parse_stun(rest).map(|s| (s.host, s.port));
        assert_eq!(parse("stun.example"), Some(("stun.example".into(), 3478)));
        assert_eq!(parse("stun.example:80"), Some(("stun.example".into(), 80)));
        assert_eq!(parse("192.0.2.1:19302"), Some(("192.0.2.1".into(), 19302)));
        assert_eq!(parse("[2001:db8::1]"), Some(("[2001:db8::1]".into(), 3478)));
        assert_eq!(parse("[2001:db8::1]:5"), Some(("[2001:db8::1]".into(), 5)));
        for bad in [
            "",
            "host:",
            "host:0",
            "host:99999",
            "host:x",
            "user@host",
            "host/path",
            "host?x",
            "[not-v6]",
            "[2001:db8::1",
            "ho st",
            ":80",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn plans_keep_stun_servers_warn_on_turns_over_dtls_and_refuse_the_rest() {
        let plan = plan(&servers(&[
            "stun:a",
            "STUN:b:1",
            "turn:t",
            "turns:t:5349",
            "turns:t:5349?transport=udp",
        ]))
        .unwrap();
        assert_eq!(
            plan.stun,
            [
                StunServer {
                    host: "a".into(),
                    port: 3478
                },
                StunServer {
                    host: "b".into(),
                    port: 1
                }
            ]
        );
        assert_eq!(plan.warnings.len(), 1);
        let many: Vec<String> = (0..6)
            .map(|n| format!("turns:t{n}?transport=UDP"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let warnings = super::plan(&servers(&many)).unwrap().warnings;
        assert_eq!(warnings.len(), MAX_WARNINGS);
        assert_eq!(
            warnings[MAX_WARNINGS - 1],
            SessionEvent::Warning {
                code: WarningCode::TurnUnsupported,
                message: format!(
                    "turns:t{}?transport=UDP ignored: TURN over DTLS is not supported",
                    MAX_WARNINGS - 1
                ),
                reason: None,
                status: None,
            }
        );
        let many: Vec<String> = (0..6).map(|n| format!("stun:s{n}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            super::plan(&servers(&many)).unwrap().stun.len(),
            MAX_STUN_SERVERS
        );
        for bad in ["http://x/", "stun:", "stun:a/b", "nocolon"] {
            let err = super::plan(&servers(&[bad])).unwrap_err();
            assert_eq!(
                (err.code, &err.details["url"]),
                (ErrorCode::InvalidRequest, &json!(bad))
            );
        }
        assert_eq!(super::plan(&[]).unwrap(), IcePlan::default());
    }

    #[test]
    fn turn_uris_parse_per_rfc_7065_3_1() {
        let parse = |rest: &str| parse_turn(rest, STUN_PORT).map(|(s, q)| (s.host, s.port, q));
        assert_eq!(
            parse("turn.example"),
            Some(("turn.example".into(), 3478, TransportQuery::None))
        );
        assert_eq!(
            parse("turn.example:80?transport=udp"),
            Some(("turn.example".into(), 80, TransportQuery::Udp))
        );
        assert_eq!(
            parse("[2001:db8::1]:443?transport=TCP"),
            Some(("[2001:db8::1]".into(), 443, TransportQuery::Tcp))
        );
        // `turns:` defaults to 5349.
        assert_eq!(
            parse_turn("turn.example", TURNS_PORT).map(|(s, _)| s.port),
            Some(5349)
        );
        for bad in [
            "",
            "host?transport=sctp",
            "host?x=1",
            "host:0?transport=udp",
            "user@host",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn plans_keep_turn_servers_with_credentials_over_udp_and_tcp_rfc_7065() {
        let entry = |urls: &[&str], credential: Option<&str>| -> IceServer {
            serde_json::from_value(json!({
                "urls": urls, "username": credential.map(|_| "ha"), "credential": credential
            }))
            .unwrap()
        };
        let named = |plan: &IcePlan| -> Vec<(String, u16, Transport)> {
            plan.turn
                .iter()
                .map(|t| (t.server.host.clone(), t.server.port, t.via.transport()))
                .collect()
        };
        let plan = plan(&[
            entry(
                &[
                    "turn:t2?transport=tcp",
                    "turn:t1",
                    "TURN:t1:3478",
                    "turn:T1:3478?transport=tcp",
                    "turn:t1:443?transport=tcp",
                    "turn:t2:3478?transport=tcp",
                ],
                Some("pw"),
            ),
            entry(&["turn:t3"], None),
        ])
        .unwrap();
        // Named twice is one server; TCP to a server named over UDP too is
        // left to the UDP one, whatever the order; no credential, no
        // server; no warning.
        assert_eq!(
            named(&plan),
            [
                ("t2".to_owned(), 3478, Transport::Tcp),
                ("t1".to_owned(), 3478, Transport::Udp),
                ("t1".to_owned(), 443, Transport::Tcp),
            ]
        );
        assert_eq!(plan.turn[0].credentials.username, "ha");
        assert_eq!(plan.turn[0].credentials.password.expose_secret(), "pw");
        assert_eq!(plan.warnings, []);
        // The limit counts what is left.
        let mut many: Vec<String> = (0..6).map(|n| format!("turn:t{n}?transport=tcp")).collect();
        many.extend((0..3).map(|n| format!("turn:t{n}")));
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let plan = super::plan(&[entry(&many, Some("pw"))]).unwrap();
        assert_eq!(
            named(&plan),
            [
                ("t3".to_owned(), 3478, Transport::Tcp),
                ("t4".to_owned(), 3478, Transport::Tcp),
                ("t5".to_owned(), 3478, Transport::Tcp),
                ("t0".to_owned(), 3478, Transport::Udp),
            ]
        );
        let err = super::plan(&[entry(&["turn:t?transport=sctp"], Some("pw"))]).unwrap_err();
        assert_eq!(
            (err.code, &err.details["url"]),
            (ErrorCode::InvalidRequest, &json!("turn:t?transport=sctp"))
        );
    }

    #[test]
    fn plans_keep_turns_servers_over_tls_to_the_embedded_roots_rfc_8489_6_2_3() {
        let entry = |urls: &[&str], credential: Option<&str>| -> IceServer {
            serde_json::from_value(json!({
                "urls": urls, "username": credential.map(|_| "ha"), "credential": credential
            }))
            .unwrap()
        };
        let plan = plan(&[
            entry(
                &[
                    "turns:t1",
                    "TURNS:t1:5349?transport=tcp",
                    "turns:t2:443?transport=TCP",
                    "turns:[2001:db8::1]",
                    // Named over UDP at its port too: the UDP allocation
                    // relays.
                    "turns:t3:443",
                    "turn:t3:443",
                ],
                Some("pw"),
            ),
            entry(&["turns:t4"], None),
        ])
        .unwrap();
        let tls = |host: &str| Via::Tls(TlsTarget::new(host, Trust::Roots).unwrap());
        let reached: Vec<(String, u16, Via)> = plan
            .turn
            .iter()
            .map(|t| (t.server.host.clone(), t.server.port, t.via.clone()))
            .collect();
        // Named twice is one server, the default port 5349; no credential,
        // no server; no warning.
        assert_eq!(
            reached,
            [
                ("t1".to_owned(), 5349, tls("t1")),
                ("t2".to_owned(), 443, tls("t2")),
                ("[2001:db8::1]".to_owned(), 5349, tls("[2001:db8::1]")),
                ("t3".to_owned(), 443, Via::Udp),
            ]
        );
        assert_eq!(plan.turn[0].credentials.username, "ha");
        assert_eq!(plan.warnings, []);
        // A host that is no TLS server name, and another transport, fail.
        for bad in ["turns:a..b", "turns:-t", "turns:t?transport=sctp"] {
            let err = super::plan(&[entry(&[bad], Some("pw"))]).unwrap_err();
            assert_eq!(
                (err.code, &err.details["url"]),
                (ErrorCode::InvalidRequest, &json!(bad)),
                "{bad}"
            );
        }
        let err = super::plan(&[entry(&["turns:t:0"], Some("pw"))]).unwrap_err();
        assert_eq!(err.message, "not a turns: URI (RFC 7065)");
    }

    #[test]
    fn srflx_candidates_carry_the_rfc_8445_5_1_2_1_priority_and_their_base() {
        let line = srflx_candidate(
            2,
            "203.0.113.7:40000".parse().unwrap(),
            "192.168.1.2:18556".parse().unwrap(),
        );
        // (2^24)·100 + (2^8)·65535 + (256 − 1)
        assert_eq!(
            line,
            "candidate:s2 1 udp 1694498815 203.0.113.7 40000 typ srflx raddr 192.168.1.2 rport 18556"
        );
    }

    /// A STUN server on loopback that answers every request with `mapped`.
    fn server(mapped: SocketAddr) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let request = stun::parse(&buf[..n]).unwrap();
                let reply = Builder::new(Class::Success, METHOD_BINDING, request.transaction_id)
                    .xor_mapped_address(mapped)
                    .build();
                let _sent = socket.send_to(&reply, from);
            }
        });
        addr
    }

    fn client() -> (Arc<StunClient>, Demux, SocketAddr) {
        let bound = crate::net::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = bound.local;
        let demux = Demux::start(
            Arc::clone(&bound.socket),
            local,
            vec![local],
            Arc::new(SystemClock),
        )
        .unwrap();
        let client = StunClient::new(
            bound.socket,
            demux.responses(),
            Arc::new(SystemClock),
            StunClientConfig {
                rto: Duration::from_millis(50),
                retries: 1,
                cache: Duration::from_secs(60),
            },
        );
        (Arc::new(client), demux, local)
    }

    #[tokio::test]
    async fn gathering_yields_srflx_only_behind_a_nat() {
        let (client, demux, local) = client();
        let natted = server("203.0.113.7:40000".parse().unwrap());
        let open = server(local);
        let stun = |addr: SocketAddr| StunServer {
            host: addr.ip().to_string(),
            port: addr.port(),
        };
        assert_eq!(
            gather(&client, &stun(natted), &[local], 0).await,
            Some(("203.0.113.7:40000".parse().unwrap(), local))
        );
        // RFC 8445 §5.1.3: mapped == base is redundant.
        assert_eq!(gather(&client, &stun(open), &[local], 0).await, None);
        // No host of the server's family, an unresolvable name, silence.
        let v6 = StunServer {
            host: "[::1]".into(),
            port: 3478,
        };
        assert_eq!(gather(&client, &v6, &[local], 0).await, None);
        let unresolvable = StunServer {
            host: "stun.invalid".into(),
            port: 3478,
        };
        assert_eq!(gather(&client, &unresolvable, &[local], 0).await, None);
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            gather(&client, &stun(silent.local_addr().unwrap()), &[local], 0).await,
            None
        );

        demux.stop();
    }
}

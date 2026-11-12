//! Gathering for one session: the `stun:` servers of the offer's
//! `ice_servers`, a Binding from the shared socket to each, and the
//! `srflx` candidate the mapped address becomes; and the `turn:` servers,
//! a lease on each one's shared allocation over UDP or TCP, whose relayed
//! address the worker's agent takes as a relay candidate. Every STUN
//! server is asked at once; the TURN servers wait in a queue
//! ([`RelayQueue`]) behind [`TURN_IN_FLIGHT`] attempts, a UDP server with
//! its TCP twin one entry ([`relay_entry`]).
//!
//! Implements RFC 7064 §3.1 (the `stun:` URI: host and optional port,
//! default 3478), RFC 7065 §3.1 (the `turn:` URI: host, optional port,
//! default 3478, and optional transport), RFC 8445 §5.1.1.2 (a
//! server-reflexive candidate and its base), §5.1.2.1 (its priority),
//! §5.1.1.3 (its foundation) and §5.1.3 (a candidate equal to its base is
//! redundant and dropped), and RFC 8839 §5.1 (the `candidate` attribute).
//! The worker's ICE agent needs no srflx candidate of its own: the
//! browser's checks to it arrive at the host address through the NAT, so
//! only the browser is told. A relay candidate is the agent's own: it
//! sends from it, so the worker makes its line.

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::time::Duration;

use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use lotse_api_types::error::{ApiError, ErrorCode};
use lotse_api_types::session::{IceServer, SessionEvent, WarningCode};
use lotse_core::clock::Clock;
use lotse_core::secret::Secret;
use lotse_core::task::BoxFuture;

use crate::net::allocation::Transport;
use crate::net::credential::Credentials;
use crate::net::stun_client::StunClient;
use crate::net::turn_client::{Lease, TurnClient};

/// How long end-of-candidates waits for the gathers after the offer.
///
/// No specification sets it: RFC 8838 §13 has end-of-candidates follow
/// the last candidate and names no time, so 4 s is our choice. It bounds
/// only how long end-of-candidates waits for slow or silent servers; it
/// goes out earlier as soon as no gather is in flight or queued. 4 s
/// covers four tries of a Binding to a silent STUN server (RFC 8489
/// §6.2.1: an RTO of 500 ms, doubling, sends at 0, 0.5, 1.5 and 3.5 s) and
/// a TURN allocation's two round trips (the 401 challenge, then the
/// request with the long-term credential: RFC 8656 §7.2, RFC 8489 §9.2)
/// with room for retransmissions and for the next server in line after a
/// fast failure. Waiting longer only delays a failing session's `failed`.
pub(crate) const GATHER_DEADLINE: Duration = Duration::from_secs(4);

/// STUN servers asked per session, all at once; the rest are ignored.
///
/// A STUN server is asked in parallel with the others rather than queued:
/// its failure is usually silence (UDP, no answer), so a queue that moves
/// on only when an attempt fails would leave a silent server holding its
/// place until the deadline and never ask the ones behind it. Eight is a
/// chosen bound, not a specification's: twice the four STUN servers the
/// client sends by default, with room for servers of its user's own. It
/// is cheap: a Binding costs one packet and its retransmissions and no
/// state on the server, the [`StunClient`] caches each server's answer
/// for 5 min, and identical mappings are told once (RFC 8445 §5.1.3). And
/// it bounds what one offer makes the daemon send, whose list may name
/// [`MAX_ICE_SERVERS`](lotse_api_types::limits::MAX_ICE_SERVERS) ×
/// [`MAX_ICE_URLS`](lotse_api_types::limits::MAX_ICE_URLS) URLs. A server
/// named twice takes one place.
pub(crate) const MAX_STUN_SERVERS: usize = 8;

/// TURN entries of a session in flight at once: an entry that ends
/// without a lease makes room for the next in line, one that yields a
/// lease does not, so a session holds at most this many relay candidates.
/// An entry is a server with its TCP twin, if any ([`TurnEntry`]): it
/// takes one place while either of its attempts runs.
///
/// TURN is queued, unlike STUN: an allocation is state and quota on the
/// server, and a TURN failure is mostly fast (an error response, a TCP
/// connection refused or reset), so the next server in line still runs
/// within [`GATHER_DEADLINE`].
pub(crate) const TURN_IN_FLIGHT: usize = 4;

/// TURN entries per session in all, a UDP server and its TCP twin one;
/// the servers beyond it are ignored. Twice [`TURN_IN_FLIGHT`]: when the
/// first four fail fast, four more still run, and a list longer than that
/// (it may name
/// [`MAX_ICE_SERVERS`](lotse_api_types::limits::MAX_ICE_SERVERS) ×
/// [`MAX_ICE_URLS`](lotse_api_types::limits::MAX_ICE_URLS) URLs) is no
/// reason to let one offer open more allocations.
pub(crate) const MAX_TURN_ATTEMPTS: usize = 8;

/// How long a UDP attempt whose server has a TCP twin goes without any
/// answer from the server before the twin starts alongside it.
///
/// A network that blocks UDP to the server mostly drops it silently, and
/// the UDP attempt then fails only at its own timeout (RFC 8489 §6.2.1:
/// 39.5 s), long after [`GATHER_DEADLINE`]; so the twin does not wait for
/// that failure. No specification sets the delay: it is our choice, after
/// the idea of RFC 8305's connection attempt delay (an analogy, not what
/// is implemented). By 1 s the Allocate went out twice (§6.2.1: an RTO of
/// 500 ms, sends at 0 and 0.5 s), and any answer, the 401 challenge
/// included (RFC 8656 §7.2, RFC 8489 §9.2), proves the UDP path, so the
/// twin then waits for that attempt to fail. A second leaves the twin's
/// connection and its two round trips room within [`GATHER_DEADLINE`].
pub(crate) const TWIN_DELAY: Duration = Duration::from_secs(1);

/// Warnings an offer's `ice_servers` yield; the rest are logged. The
/// session's queue must hold them with its `session` event before them
/// and a `closed` event after, so an offer closed at once never loses
/// its close.
pub(crate) const MAX_WARNINGS: usize = 4;

/// The default port of a `stun:` and a `turn:` URI (RFC 7064 §3.1, RFC
/// 7065 §3.1, RFC 8489 §18.6).
const STUN_PORT: u16 = 3478;

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

/// A `turn:` server as its URI names it, with its entry's long-term
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TurnServer {
    /// The host and port.
    pub(crate) server: StunServer,
    /// The transport to it (RFC 7065 §3.1).
    pub(crate) transport: Transport,
    /// The entry's username and credential.
    pub(crate) credentials: Credentials,
}

/// A TURN server to allocate on, with the same server over TCP to try
/// when this one, over UDP, is silent or fails ([`relay_entry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TurnEntry {
    /// The server.
    pub(crate) server: TurnServer,
    /// Its TCP twin, started alongside it once the server has not
    /// answered over UDP within [`TWIN_DELAY`], else once this attempt
    /// failed; only a UDP server has one.
    pub(crate) twin: Option<TurnServer>,
}

/// What `ice_servers` asks of a session.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct IcePlan {
    /// Warnings for entries not supported yet, at most [`MAX_WARNINGS`].
    pub(crate) warnings: Vec<SessionEvent>,
    /// The STUN servers to gather from, at most [`MAX_STUN_SERVERS`].
    pub(crate) stun: Vec<StunServer>,
    /// The TURN servers to allocate on, in list order, at most
    /// [`MAX_TURN_ATTEMPTS`].
    pub(crate) turn: Vec<TurnEntry>,
}

/// Checks `ice_servers`: only `stun:`, `turn:` and `turns:` URIs (RFC 7064,
/// RFC 7065). `turns:` is not supported until M6 and yields a
/// `turn_unsupported` warning, the first [`MAX_WARNINGS`] of them. A
/// `turn:` entry without a username and credential is skipped: TURN asks
/// for the long-term credential (RFC 8656 §5), and browsers refuse such an
/// entry (W3C WebRTC 1.0 §4.2.1). A `turn:` over TCP whose host and port
/// the list names over UDP too is that UDP server's twin, whatever their
/// order: both relay over UDP to the peer (§7.1), so the UDP allocation is
/// enough when it works, and what a session sends through a TCP one
/// passes through the supervisor, which owns the connection; but a
/// network that blocks UDP to the server still reaches it over TCP. The
/// twin starts only when the server is silent over UDP or that attempt
/// failed ([`relay_entry`]). A UDP server has one twin, the first such
/// TCP entry; a second is ignored. A TCP entry without a UDP twin is an
/// ordinary entry. A server named twice is one (a STUN one by host,
/// ignoring ASCII case, and port). The servers keep their list order,
/// the first [`MAX_STUN_SERVERS`] STUN and [`MAX_TURN_ATTEMPTS`] TURN
/// entries (a UDP server and its twin one).
pub(crate) fn plan(servers: &[IceServer]) -> Result<IcePlan, ApiError> {
    let mut plan = IcePlan::default();
    let mut turns: Vec<TurnServer> = Vec::new();
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
                if plan.stun.iter().any(|other| same_server(other, &server)) {
                    tracing::debug!(url, "stun server named twice");
                } else if plan.stun.len() < MAX_STUN_SERVERS {
                    plan.stun.push(server);
                } else {
                    tracing::debug!(url, "stun server beyond the per-session limit ignored");
                }
            }
            "turn" => {
                let (server, tcp) = parse_turn(rest).ok_or_else(|| {
                    ApiError::new(ErrorCode::InvalidRequest, "not a turn: URI (RFC 7065)")
                        .with_detail("url", url.as_str())
                })?;
                let (Some(username), Some(password)) = (&entry.username, &entry.credential) else {
                    tracing::info!(url, "turn server without username and credential ignored");
                    continue;
                };
                let turn = TurnServer {
                    server,
                    transport: if tcp { Transport::Tcp } else { Transport::Udp },
                    credentials: Credentials {
                        username: username.clone(),
                        password: Secret::new(password.clone()),
                    },
                };
                if turns.contains(&turn) {
                    tracing::debug!(url, "turn server named twice");
                } else {
                    turns.push(turn);
                }
            }
            "turns" if plan.warnings.len() < MAX_WARNINGS => {
                plan.warnings.push(SessionEvent::Warning {
                    code: WarningCode::TurnUnsupported,
                    message: format!("{url} ignored: TURN over TLS is not supported yet"),
                    reason: None,
                    status: None,
                });
            }
            "turns" => {
                tracing::debug!(url, "turns: server beyond the warning limit ignored");
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
    plan.turn = turn_entries(turns);
    Ok(plan)
}

/// `turns` in list order as entries, each TCP server whose host and port
/// a UDP one names too as the twin of the first such UDP server that has
/// none yet; at most [`MAX_TURN_ATTEMPTS`] entries.
fn turn_entries(turns: Vec<TurnServer>) -> Vec<TurnEntry> {
    let udp: Vec<StunServer> = turns
        .iter()
        .filter(|turn| turn.transport == Transport::Udp)
        .map(|turn| turn.server.clone())
        .collect();
    let (twins, plain): (Vec<TurnServer>, Vec<TurnServer>) = turns.into_iter().partition(|turn| {
        turn.transport == Transport::Tcp && udp.iter().any(|other| same_server(other, &turn.server))
    });
    let mut entries: Vec<TurnEntry> = plain
        .into_iter()
        .map(|server| TurnEntry { server, twin: None })
        .collect();
    // A twin's host and port are named over UDP, so every entry naming
    // them is over UDP: a TCP one would be a twin itself.
    for twin in twins {
        let free = entries
            .iter_mut()
            .find(|entry| entry.twin.is_none() && same_server(&entry.server.server, &twin.server));
        if let Some(entry) = free {
            tracing::debug!(
                host = twin.server.host,
                port = twin.server.port,
                "turn server over tcp named over udp too; tried when the udp one is silent or fails"
            );
            entry.twin = Some(twin);
        } else {
            tracing::debug!(
                host = twin.server.host,
                port = twin.server.port,
                "turn server over tcp whose udp server has a twin already ignored"
            );
        }
    }
    let kept = entries.len().min(MAX_TURN_ATTEMPTS);
    for ignored in entries.drain(kept..) {
        tracing::debug!(
            host = ignored.server.server.host,
            "turn server beyond the per-session limit ignored"
        );
    }
    entries
}

/// The order a session's TURN entries start in: [`TURN_IN_FLIGHT`] at
/// first, then the next in list order each time one ends without a lease;
/// at most [`MAX_TURN_ATTEMPTS`] in all. An entry is a server with its TCP
/// twin, if any: it holds one place in flight and one of the total while
/// either of its attempts runs, and its twin needs none of its own
/// ([`relay_entry`]). An entry that yields a lease starts none: its place
/// stays taken by the relay candidate. The policy alone, without sockets;
/// [`relay_all`] runs it.
#[derive(Debug)]
pub(crate) struct RelayQueue {
    /// The entries not started yet, in list order.
    waiting: VecDeque<TurnEntry>,
    /// The entries started, at most [`MAX_TURN_ATTEMPTS`].
    started: usize,
}

impl RelayQueue {
    /// A queue of `entries`, none started.
    pub(crate) fn new(entries: Vec<TurnEntry>) -> Self {
        Self {
            waiting: entries.into(),
            started: 0,
        }
    }

    /// The entries to start at once, at most [`TURN_IN_FLIGHT`].
    pub(crate) fn first(&mut self) -> Vec<TurnEntry> {
        let mut first = Vec::new();
        while first.len() < TURN_IN_FLIGHT
            && let Some(entry) = self.next()
        {
            first.push(entry);
        }
        first
    }

    /// An entry ended without a lease, its twin's attempt included: the
    /// entry to start in its place, if one is left within the limit.
    pub(crate) fn failed(&mut self) -> Option<TurnEntry> {
        self.next()
    }

    /// The next entry in line; none once [`MAX_TURN_ATTEMPTS`] started.
    fn next(&mut self) -> Option<TurnEntry> {
        if self.started >= MAX_TURN_ATTEMPTS {
            if !self.waiting.is_empty() {
                tracing::debug!(
                    limit = MAX_TURN_ATTEMPTS,
                    "turn attempt limit reached; the servers left are ignored"
                );
                self.waiting.clear();
            }
            return None;
        }
        let next = self.waiting.pop_front()?;
        self.started = self.started.saturating_add(1);
        Some(next)
    }
}

/// Whether two URIs name one server: the host ignoring ASCII case (RFC
/// 3986 §6.2.2.1) and the port.
fn same_server(one: &StunServer, other: &StunServer) -> bool {
    one.port == other.port && one.host.eq_ignore_ascii_case(&other.host)
}

/// The server after `turn:` and whether it asks for TCP (RFC 7065 §3.1:
/// `host [ ":" port ] [ "?transport=" transport ]`, transport `udp` or
/// `tcp`, UDP when absent). Another transport, or another query, fails.
fn parse_turn(rest: &str) -> Option<(StunServer, bool)> {
    let (address, tcp) = match rest.split_once('?') {
        None => (rest, false),
        Some((address, query)) => match query.to_ascii_lowercase().as_str() {
            "transport=udp" => (address, false),
            "transport=tcp" => (address, true),
            _ => return None,
        },
    };
    parse_stun(address).map(|server| (server, tcp))
}

/// The host and port after `stun:` (RFC 7064 §3.1: `host [ ":" port ]`).
/// User info, a path or a query fail the host or port syntax.
fn parse_stun(rest: &str) -> Option<StunServer> {
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
        None => STUN_PORT,
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
pub(crate) async fn gather(
    client: &StunClient,
    server: &StunServer,
    hosts: &[SocketAddr],
) -> Option<(SocketAddr, SocketAddr)> {
    let (target, base) = reach(server, hosts).await?;
    let mapped = client.reflexive(target).await.ok()?;
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
    /// The transport to it.
    pub(crate) transport: Transport,
    /// The host address the allocation's traffic leaves from.
    pub(crate) local: SocketAddr,
}

/// Leases the allocation on `server` at `target`, as resolved, over its
/// transport (made with its credential if there is none yet), its traffic
/// leaving from the host address `local`; `None` when that fails.
async fn lease(
    client: &TurnClient,
    server: &TurnServer,
    target: SocketAddr,
    local: SocketAddr,
) -> Option<Relayed> {
    match client
        .lease(target, server.transport, &server.credentials)
        .await
    {
        Ok(lease) => Some(Relayed {
            lease,
            server: target,
            transport: server.transport,
            local,
        }),
        Err(err) => {
            tracing::warn!(server = %target, transport = ?server.transport, error = %err, "turn allocation failed");
            None
        }
    }
}

/// `relayed` when it is a lease, else what `other`, the entry's other
/// attempt, yields.
async fn or_other(
    relayed: Option<Relayed>,
    other: impl Future<Output = Option<Relayed>>,
) -> Option<Relayed> {
    if relayed.is_some() {
        return relayed;
    }
    tracing::debug!("turn attempt failed; its twin's attempt decides the entry");
    other.await
}

/// One entry's attempts, reached from the host address of the family its
/// server resolves to: a lease on its server, and for a UDP server with a
/// TCP twin, on the twin at the same address. The twin starts alongside
/// the UDP attempt once [`TWIN_DELAY`] passed on `clock` without any
/// answer from the server over UDP ([`TurnClient::answered`]); when the
/// server answered, or the UDP attempt failed sooner, it starts once that
/// attempt failed. The first lease is the entry's: the other attempt is
/// dropped with this future, and a lease its allocation grants it, read
/// or not, is released at once (nobody holds it). `None` when no attempt
/// yields one.
pub(crate) async fn relay_entry(
    client: &TurnClient,
    clock: &dyn Clock,
    entry: TurnEntry,
    hosts: &[SocketAddr],
) -> Option<Relayed> {
    let TurnEntry { server, twin } = entry;
    let (target, local) = reach(&server.server, hosts).await?;
    let Some(twin) = twin else {
        return lease(client, &server, target, local).await;
    };
    let mut first = pin!(lease(client, &server, target, local));
    let second = pin!(lease(client, &twin, target, local));
    let silent = tokio::select! {
        relayed = &mut first => return or_other(relayed, second).await,
        () = clock.sleep(TWIN_DELAY) => !client.answered(target, Transport::Udp),
    };
    if !silent {
        tracing::debug!(server = %target, "turn server answered over udp; its tcp twin waits for that attempt to fail");
        let relayed = first.await;
        return or_other(relayed, second).await;
    }
    tracing::debug!(server = %target, delay = ?TWIN_DELAY, "no answer from the turn server over udp; its tcp twin started alongside");
    match select(first, second).await {
        Either::Left((relayed, other)) | Either::Right((relayed, other)) => {
            or_other(relayed, other).await
        }
    }
}

/// Runs a session's TURN entries in [`RelayQueue`]'s order, each by
/// [`relay_entry`] on `clock` and reached from `hosts`, and hands each
/// lease to `leased` as it comes, until `deadline` (the session's
/// [`GATHER_DEADLINE`]) passes. `false` once no entry is running or left
/// to start, `true` when the deadline passed first and cut the queue
/// short: the attempts still running then are dropped. The deadline is
/// looked at first: once it passed, a lease that is ready at the same
/// time is dropped with its attempt, and so released (nobody holds it),
/// never handed to `leased`. Dropping it drops the attempts running.
pub(crate) async fn relay_all(
    client: &TurnClient,
    clock: &dyn Clock,
    entries: Vec<TurnEntry>,
    hosts: &[SocketAddr],
    mut deadline: BoxFuture<'static, ()>,
    leased: &mut (dyn FnMut(Relayed) + Send),
) -> bool {
    let mut queue = RelayQueue::new(entries);
    let attempt = |entry: TurnEntry| async move {
        let host = entry.server.server.host.clone();
        (relay_entry(client, clock, entry, hosts).await, host)
    };
    let mut running: FuturesUnordered<_> = queue.first().into_iter().map(attempt).collect();
    loop {
        let next = tokio::select! {
            biased;
            () = &mut deadline => return true,
            next = running.next() => next,
        };
        let Some((relayed, failed)) = next else {
            return false;
        };
        if let Some(relayed) = relayed {
            leased(relayed);
        } else if let Some(next) = queue.failed() {
            tracing::debug!(
                failed,
                next = next.server.server.host,
                "turn server failed; the next in line tried"
            );
            running.push(attempt(next));
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use lotse_core::clock::{FakeClock, SystemClock};
    use lotse_testing::fake_turn::{ALLOCATE, FakeTurn, FakeTurnServer};
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
    fn plans_keep_stun_servers_warn_on_turns_and_refuse_the_rest() {
        let plan = plan(&servers(&["stun:a", "STUN:b:1", "turn:t", "turns:t:5349"])).unwrap();
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
        let many: Vec<String> = (0..6).map(|n| format!("turns:t{n}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let warnings = super::plan(&servers(&many)).unwrap().warnings;
        assert_eq!(warnings.len(), MAX_WARNINGS);
        assert_eq!(
            warnings[MAX_WARNINGS - 1],
            SessionEvent::Warning {
                code: WarningCode::TurnUnsupported,
                message: format!(
                    "turns:t{} ignored: TURN over TLS is not supported yet",
                    MAX_WARNINGS - 1
                ),
                reason: None,
                status: None,
            }
        );
        // Up to the limit, in list order; a server named twice (the host
        // ignoring ASCII case, RFC 3986 §6.2.2.1) takes one place.
        let mut many: Vec<String> = vec!["stun:s0".into(), "stun:S0:3478".into()];
        many.extend((1..=MAX_STUN_SERVERS).map(|n| format!("stun:s{n}")));
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let kept: Vec<String> = super::plan(&servers(&many))
            .unwrap()
            .stun
            .into_iter()
            .map(|server| server.host)
            .collect();
        let expected: Vec<String> = (0..MAX_STUN_SERVERS).map(|n| format!("s{n}")).collect();
        assert_eq!(kept, expected);
        assert_eq!(
            super::plan(&servers(&["stun:s", "stun:s:1"]))
                .unwrap()
                .stun
                .len(),
            2,
            "another port is another server"
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
        let parse = |rest: &str| parse_turn(rest).map(|(s, tcp)| (s.host, s.port, tcp));
        assert_eq!(
            parse("turn.example"),
            Some(("turn.example".into(), 3478, false))
        );
        assert_eq!(
            parse("turn.example:80?transport=udp"),
            Some(("turn.example".into(), 80, false))
        );
        assert_eq!(
            parse("[2001:db8::1]:443?transport=TCP"),
            Some(("[2001:db8::1]".into(), 443, true))
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

    fn turn_entry(urls: &[&str], credential: Option<&str>) -> IceServer {
        serde_json::from_value(json!({
            "urls": urls, "username": credential.map(|_| "ha"), "credential": credential
        }))
        .unwrap()
    }

    /// Each entry's server and twin as host, port and transport.
    fn named(plan: &IcePlan) -> Vec<(String, u16, Transport, Option<Transport>)> {
        plan.turn
            .iter()
            .map(|entry| {
                (
                    entry.server.server.host.clone(),
                    entry.server.server.port,
                    entry.server.transport,
                    entry.twin.as_ref().map(|twin| {
                        assert!(same_server(&twin.server, &entry.server.server));
                        twin.transport
                    }),
                )
            })
            .collect()
    }

    #[test]
    fn plans_keep_turn_servers_with_credentials_over_udp_and_tcp_rfc_7065() {
        let plan = plan(&[
            turn_entry(
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
            turn_entry(&["turn:t3"], None),
        ])
        .unwrap();
        // Named twice is one server; TCP to a server named over UDP too is
        // the UDP one's twin, whatever the order; TCP without a UDP
        // twin is a server of its own; no credential, no server; no
        // warning.
        assert_eq!(
            named(&plan),
            [
                ("t2".to_owned(), 3478, Transport::Tcp, None),
                ("t1".to_owned(), 3478, Transport::Udp, Some(Transport::Tcp)),
                ("t1".to_owned(), 443, Transport::Tcp, None),
            ]
        );
        assert_eq!(plan.turn[0].server.credentials.username, "ha");
        assert_eq!(
            plan.turn[0].server.credentials.password.expose_secret(),
            "pw"
        );
        assert_eq!(plan.warnings, []);
        // A UDP server has one twin: a second TCP twin, with another
        // credential, is ignored; another UDP server of the same host and
        // port takes it.
        let plan = super::plan(&[
            turn_entry(&["turn:t1", "turn:t1?transport=tcp"], Some("pw")),
            turn_entry(&["turn:t1?transport=tcp"], Some("other")),
        ])
        .unwrap();
        assert_eq!(
            named(&plan),
            [("t1".to_owned(), 3478, Transport::Udp, Some(Transport::Tcp))]
        );
        assert_eq!(
            plan.turn[0]
                .twin
                .as_ref()
                .unwrap()
                .credentials
                .password
                .expose_secret(),
            "pw"
        );
        let plan = super::plan(&[
            turn_entry(&["turn:t1", "turn:t1?transport=tcp"], Some("pw")),
            turn_entry(&["turn:t1?transport=tcp", "turn:t1"], Some("other")),
        ])
        .unwrap();
        assert_eq!(
            named(&plan),
            [
                ("t1".to_owned(), 3478, Transport::Udp, Some(Transport::Tcp)),
                ("t1".to_owned(), 3478, Transport::Udp, Some(Transport::Tcp)),
            ]
        );
        // The limit counts entries, a UDP server with its twin one, in
        // list order.
        let mut many: Vec<String> = (0..10)
            .map(|n| format!("turn:t{n}?transport=tcp"))
            .collect();
        many.extend((0..3).map(|n| format!("turn:t{n}")));
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let plan = super::plan(&[turn_entry(&many, Some("pw"))]).unwrap();
        let mut expected: Vec<(String, u16, Transport, Option<Transport>)> = (3..10)
            .map(|n| (format!("t{n}"), 3478, Transport::Tcp, None))
            .collect();
        expected.push(("t0".to_owned(), 3478, Transport::Udp, Some(Transport::Tcp)));
        assert_eq!(expected.len(), MAX_TURN_ATTEMPTS);
        assert_eq!(named(&plan), expected);
        let err = super::plan(&[turn_entry(&["turn:t?transport=sctp"], Some("pw"))]).unwrap_err();
        assert_eq!(
            (err.code, &err.details["url"]),
            (ErrorCode::InvalidRequest, &json!("turn:t?transport=sctp"))
        );
    }

    /// A TURN server named `host`, over TCP when `tcp`.
    fn turn(host: &str, tcp: bool) -> TurnServer {
        TurnServer {
            server: StunServer {
                host: host.into(),
                port: STUN_PORT,
            },
            transport: if tcp { Transport::Tcp } else { Transport::Udp },
            credentials: Credentials {
                username: "ha".into(),
                password: Secret::new("pw".into()),
            },
        }
    }

    /// Entries `t0`, `t1`, … over UDP, each with its TCP twin when
    /// `twinned`.
    fn queue(count: usize, twinned: bool) -> RelayQueue {
        RelayQueue::new(
            (0..count)
                .map(|n| TurnEntry {
                    server: turn(&format!("t{n}"), false),
                    twin: twinned.then(|| turn(&format!("t{n}"), true)),
                })
                .collect(),
        )
    }

    /// An entry's host and whether it is over TCP.
    fn which(entry: Option<TurnEntry>) -> Option<(String, bool)> {
        entry.map(|entry| {
            (
                entry.server.server.host,
                entry.server.transport == Transport::Tcp,
            )
        })
    }

    fn hosts(entries: Vec<TurnEntry>) -> Vec<String> {
        entries
            .into_iter()
            .map(|entry| entry.server.server.host)
            .collect()
    }

    #[test]
    fn four_turn_attempts_run_at_once_and_each_failure_starts_the_next_in_list_order() {
        let mut queue = queue(10, false);
        assert_eq!(hosts(queue.first()), ["t0", "t1", "t2", "t3"]);
        for n in 4..MAX_TURN_ATTEMPTS {
            assert_eq!(which(queue.failed()), Some((format!("t{n}"), false)));
        }
        // The total limit: the rest are never tried.
        assert_eq!(which(queue.failed()), None);
        assert_eq!(which(queue.failed()), None);
        assert!(queue.waiting.is_empty());
    }

    #[test]
    fn a_turn_attempt_that_succeeds_starts_none_and_a_short_queue_runs_dry() {
        let mut queue = queue(6, false);
        assert_eq!(hosts(queue.first()), ["t0", "t1", "t2", "t3"]);
        // t0 and t1 yield leases and start nothing; t2 and t3 fail.
        assert_eq!(which(queue.failed()), Some(("t4".into(), false)));
        assert_eq!(which(queue.failed()), Some(("t5".into(), false)));
        assert_eq!(which(queue.failed()), None);
        assert_eq!(which(queue.failed()), None);
        let mut short = self::queue(2, false);
        assert_eq!(hosts(short.first()), ["t0", "t1"]);
        assert_eq!(which(short.failed()), None);
        assert_eq!(RelayQueue::new(Vec::new()).first(), []);
    }

    #[test]
    fn a_udp_server_and_its_tcp_twin_take_one_place_and_count_once_rfc_7065_3_1() {
        let mut queue = queue(10, true);
        let first = queue.first();
        assert_eq!(hosts(first.clone()), ["t0", "t1", "t2", "t3"]);
        // Each entry carries its twin: the queue never starts one alone.
        assert!(first.iter().all(|entry| entry.twin.is_some()));
        // Each entry that ends without a lease, its twin's attempt
        // included, makes room for the next: all eight entries run.
        for n in 4..MAX_TURN_ATTEMPTS {
            let next = queue.failed().unwrap();
            assert_eq!(next.server.server.host, format!("t{n}"));
            assert_eq!(next.server.transport, Transport::Udp);
            assert_eq!(next.twin.unwrap().transport, Transport::Tcp);
        }
        assert_eq!(which(queue.failed()), None);
        assert!(queue.waiting.is_empty());
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
            gather(&client, &stun(natted), &[local]).await,
            Some(("203.0.113.7:40000".parse().unwrap(), local))
        );
        // RFC 8445 §5.1.3: mapped == base is redundant.
        assert_eq!(gather(&client, &stun(open), &[local]).await, None);
        // No host of the server's family, an unresolvable name, silence.
        let v6 = StunServer {
            host: "[::1]".into(),
            port: 3478,
        };
        assert_eq!(gather(&client, &v6, &[local]).await, None);
        let unresolvable = StunServer {
            host: "stun.invalid".into(),
            port: 3478,
        };
        assert_eq!(gather(&client, &unresolvable, &[local]).await, None);
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            gather(&client, &stun(silent.local_addr().unwrap()), &[local]).await,
            None
        );

        demux.stop();
    }

    /// A TURN client on a loopback socket, its timers on `clock`, with its
    /// demux and the socket's address.
    fn turn_client(clock: &Arc<FakeClock>) -> (TurnClient, Demux, SocketAddr) {
        let bound = crate::net::udp::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = bound.local;
        let demux = Demux::start(
            Arc::clone(&bound.socket),
            local,
            vec![local],
            Arc::new(SystemClock),
        )
        .unwrap();
        let client = TurnClient::new(
            bound.socket,
            &demux,
            clock.clone(),
            crate::net::allocation::AllocationConfig::default(),
        );
        (client, demux, local)
    }

    /// A fake TURN server knowing user `ha` with password `pw`.
    fn fake_turn() -> Arc<FakeTurn> {
        let turn = Arc::new(FakeTurn::new(
            Arc::new(SystemClock),
            "lotse.test",
            Duration::from_secs(600),
        ));
        turn.add_user("ha", "pw");
        turn
    }

    /// What a loopback UDP TURN server does with the requests it reads.
    enum Udp {
        /// Answers none.
        Silent,
        /// Answers only the first, as `turn` does.
        First(Arc<FakeTurn>),
        /// Answers each, as `turn` does.
        Each(Arc<FakeTurn>),
    }

    /// A UDP socket on `port` of loopback doing `udp`; the datagrams it
    /// read.
    fn udp_server(port: u16, udp: Udp) -> Arc<AtomicUsize> {
        let socket = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        let read = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&read);
        std::thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let seen = count.fetch_add(1, Ordering::SeqCst);
                let turn = match &udp {
                    Udp::First(turn) if seen == 0 => turn,
                    Udp::Each(turn) => turn,
                    Udp::Silent | Udp::First(_) => continue,
                };
                if let Some(reply) = turn.handle(from, false, &buf[..n]) {
                    let _sent = socket.send_to(&reply, from);
                }
            }
        });
        read
    }

    /// A TCP listener on loopback that closes each connection at once,
    /// with a UDP socket on its port doing `udp`: a UDP server and its
    /// TCP twin. The port, the datagrams read and the connections taken.
    fn twin_ports(udp: Udp) -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                count.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        (port, udp_server(port, udp), accepted)
    }

    /// An entry for the server on `port` of loopback over UDP, with its
    /// TCP twin, signing as `ha` with `password`.
    fn twinned(port: u16, password: &str) -> TurnEntry {
        let server = |tcp: bool| TurnServer {
            server: StunServer {
                host: "127.0.0.1".into(),
                port,
            },
            transport: if tcp { Transport::Tcp } else { Transport::Udp },
            credentials: Credentials {
                username: "ha".into(),
                password: Secret::new(password.into()),
            },
        };
        TurnEntry {
            server: server(false),
            twin: Some(server(true)),
        }
    }

    /// Polls `done` on real time for up to five seconds.
    async fn eventually(mut done: impl FnMut() -> bool) {
        let mut tries = 0;
        while !done() {
            assert!(tries < 1_000, "condition not reached");
            tries += 1;
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
    }

    /// Runs `relay_all` on `entries`, with no deadline, while `test` runs,
    /// moving `clock` by `step` every 5 ms of real time once `test` is
    /// done, until both end; the leases it yielded.
    async fn run_relays(
        client: &TurnClient,
        clock: &FakeClock,
        entries: Vec<TurnEntry>,
        hosts: &[SocketAddr],
        test: impl Future<Output = ()>,
        step: Duration,
    ) -> Vec<Relayed> {
        let mut leases = Vec::new();
        {
            let mut push = |relayed| leases.push(relayed);
            let never = Box::pin(std::future::pending());
            let mut relays = pin!(relay_all(client, clock, entries, hosts, never, &mut push));
            let mut test = pin!(test);
            let mut tested = false;
            let ended = async {
                loop {
                    tokio::select! {
                        cut = &mut relays => {
                            assert!(!cut, "no deadline cut the queue short");
                            break;
                        }
                        () = &mut test, if !tested => tested = true,
                        () = SystemClock.sleep(Duration::from_millis(5)), if tested => {
                            clock.advance(step);
                        }
                    }
                }
                assert!(tested, "the queue ended before the test");
            };
            tokio::select! {
                () = ended => {}
                () = SystemClock.sleep(Duration::from_secs(10)) => panic!("the queue hung"),
            }
        }
        leases
    }

    #[tokio::test]
    async fn a_lease_ready_just_as_the_gather_deadline_passes_is_released_not_handed_over_rfc_8656_8()
     {
        let clock = Arc::new(FakeClock::from_system());
        let (client, demux, local) = turn_client(&clock);
        let turn = fake_turn();
        let server = FakeTurnServer::start(Arc::clone(&turn)).await.unwrap();
        let entry = TurnEntry {
            twin: None,
            ..twinned(server.udp_addr().port(), "pw")
        };
        let mut leases = Vec::new();
        {
            let mut push = |relayed| leases.push(relayed);
            let deadline = clock.sleep(GATHER_DEADLINE);
            let hosts = [local];
            let mut relays = pin!(relay_all(
                &client,
                clock.as_ref(),
                vec![entry],
                &hosts,
                deadline,
                &mut push
            ));
            // Polled until the server granted the allocation, and no more:
            // its lease reaches the client and waits there, unread.
            let mut polls = 0;
            while turn.allocations().is_empty() {
                assert!(polls < 1_000, "no allocation granted");
                polls += 1;
                let poll =
                    std::future::poll_fn(|cx| std::task::Poll::Ready(relays.as_mut().poll(cx)))
                        .await;
                assert!(poll.is_pending());
                SystemClock.sleep(Duration::from_millis(5)).await;
            }
            SystemClock.sleep(Duration::from_millis(100)).await;
            // The deadline passes with the lease ready: the deadline wins,
            // every time.
            clock.advance(GATHER_DEADLINE);
            assert!(relays.await, "the deadline cut the queue short");
        }
        assert!(leases.is_empty(), "a lease handed over after the deadline");
        // Nobody holds the lease: released, and with it the allocation.
        eventually(|| turn.allocations().is_empty()).await;
        demux.stop();
    }

    #[tokio::test]
    async fn eight_twinned_turn_servers_failing_fast_are_all_tried_with_their_twins_rfc_7065_3_1() {
        let clock = Arc::new(FakeClock::from_system());
        let (client, demux, local) = turn_client(&clock);
        // Each refuses the credential over UDP and closes the connection
        // over TCP: both attempts of each entry fail at once, on a clock
        // that stands still.
        let turn = fake_turn();
        let pairs: Vec<_> = (0..10)
            .map(|_| twin_ports(Udp::Each(Arc::clone(&turn))))
            .collect();
        let entries = pairs
            .iter()
            .map(|(port, _, _)| twinned(*port, "wrong"))
            .collect();
        let leases = run_relays(&client, &clock, entries, &[local], async {}, Duration::ZERO).await;
        assert!(leases.is_empty());
        let tried: Vec<(bool, usize)> = pairs
            .iter()
            .map(|(_, read, accepted)| {
                (
                    read.load(Ordering::SeqCst) > 0,
                    accepted.load(Ordering::SeqCst),
                )
            })
            .collect();
        let mut expected = vec![(true, 1); MAX_TURN_ATTEMPTS];
        expected.extend([(false, 0); 2]);
        assert_eq!(tried, expected);
        demux.stop();
    }

    #[tokio::test]
    async fn a_udp_turn_server_that_answers_only_its_challenge_keeps_its_twin_waiting_rfc_8656_7_2()
    {
        let clock = Arc::new(FakeClock::from_system());
        let (client, demux, local) = turn_client(&clock);
        let turn = fake_turn();
        let server = FakeTurnServer::start(Arc::clone(&turn)).await.unwrap();
        // The 401 comes over UDP, then nothing: the path carries UDP, and
        // the twin waits for that attempt to fail.
        let address = server.tcp_addr();
        let read = udp_server(address.port(), Udp::First(Arc::clone(&turn)));
        let test = async {
            eventually(|| client.answered(address, Transport::Udp)).await;
            clock.advance(TWIN_DELAY);
            SystemClock.sleep(Duration::from_millis(100)).await;
            assert_eq!(server.tcp_clients(), [], "the twin waits");
        };
        // The UDP attempt times out (RFC 8489 §6.2.1: 39.5 s), and only then
        // does the twin run.
        let leases = run_relays(
            &client,
            &clock,
            vec![twinned(address.port(), "pw")],
            &[local],
            test,
            Duration::from_millis(500),
        )
        .await;
        assert!(read.load(Ordering::SeqCst) > 1, "retransmitted");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].transport, Transport::Tcp);
        assert_eq!(leases[0].server, address);
        demux.stop();
    }

    #[tokio::test]
    async fn a_udp_turn_server_that_answers_needs_no_twin_rfc_8656_7_2() {
        let clock = Arc::new(FakeClock::from_system());
        let (client, demux, local) = turn_client(&clock);
        let turn = fake_turn();
        let server = FakeTurnServer::start(Arc::clone(&turn)).await.unwrap();
        let address = server.udp_addr();
        let leases = run_relays(
            &client,
            &clock,
            vec![twinned(address.port(), "pw")],
            &[local],
            async {},
            Duration::ZERO,
        )
        .await;
        assert_eq!(leases.len(), 1);
        assert_eq!(
            (leases[0].transport, leases[0].server),
            (Transport::Udp, address)
        );
        assert!(turn.requests().iter().all(|request| !request.tcp));
        demux.stop();
    }

    #[tokio::test]
    async fn a_silent_udp_turn_server_whose_twin_fails_too_yields_nothing_rfc_8489_6_2_1() {
        let clock = Arc::new(FakeClock::from_system());
        let (client, demux, local) = turn_client(&clock);
        let (port, read, accepted) = twin_ports(Udp::Silent);
        let test = async {
            eventually(|| read.load(Ordering::SeqCst) > 0).await;
            clock.advance(TWIN_DELAY);
            // The twin fails at once; the silent UDP attempt goes on.
            eventually(|| accepted.load(Ordering::SeqCst) == 1).await;
        };
        let leases = run_relays(
            &client,
            &clock,
            vec![twinned(port, "pw")],
            &[local],
            test,
            Duration::from_millis(500),
        )
        .await;
        assert!(leases.is_empty());
        assert!(read.load(Ordering::SeqCst) > 1, "retransmitted");
        demux.stop();
    }

    #[tokio::test]
    async fn when_both_twins_yield_a_lease_the_later_one_is_released_rfc_8656_8() {
        let clock = Arc::new(FakeClock::from_system());
        let (client, demux, local) = turn_client(&clock);
        let turn = fake_turn();
        let server = FakeTurnServer::start(Arc::clone(&turn)).await.unwrap();
        // UDP to the server is held up at first, then gets through: a
        // relay on the TCP twin's port, opened later.
        let address = server.tcp_addr();
        let relay = UdpSocket::bind(address).unwrap();
        let open = Arc::new(AtomicBool::new(false));
        let opened = Arc::clone(&open);
        let read = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&read);
        let to = server.udp_addr();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let mut client = None;
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                if from == to {
                    if let Some(client) = client {
                        let _sent = relay.send_to(&buf[..n], client);
                    }
                } else {
                    client = Some(from);
                    count.fetch_add(1, Ordering::SeqCst);
                    if opened.load(Ordering::SeqCst) {
                        let _sent = relay.send_to(&buf[..n], to);
                    }
                }
            }
        });
        let test = async {
            // The twin starts alongside the silent UDP attempt and yields
            // the entry's lease.
            eventually(|| read.load(Ordering::SeqCst) > 0).await;
            clock.advance(TWIN_DELAY);
        };
        let leases = run_relays(
            &client,
            &clock,
            vec![twinned(address.port(), "pw")],
            &[local],
            test,
            Duration::ZERO,
        )
        .await;
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].transport, Transport::Tcp);
        // The UDP allocation is granted later, to nobody: released, and
        // with its last lease gone, deleted.
        open.store(true, Ordering::SeqCst);
        let allocate = |tcp: bool| {
            turn.requests().iter().any(|request| {
                request.method == ALLOCATE && request.error.is_none() && request.tcp == tcp
            })
        };
        for _ in 0..1_000 {
            if allocate(false) && turn.allocations().len() == 1 {
                break;
            }
            clock.advance(Duration::from_millis(500));
            SystemClock.sleep(Duration::from_millis(5)).await;
        }
        assert!(allocate(false) && allocate(true), "both yielded a lease");
        let allocations = turn.allocations();
        assert_eq!(allocations.len(), 1);
        assert!(allocations[0].tcp);
        assert_eq!(allocations[0].relayed, leases[0].lease.relayed());
        demux.stop();
    }
}

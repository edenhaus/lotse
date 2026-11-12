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

use crate::host_cache::HostSnapshot;
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
/// entries (a UDP server and its twin one); a list that names more is
/// told in one warning per kind ([`warn_beyond_limit`]).
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
                } else {
                    plan.stun.push(server);
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
    warn_beyond_limit("stun", MAX_STUN_SERVERS, plan.stun.len());
    let kept = plan.stun.len().min(MAX_STUN_SERVERS);
    for ignored in plan.stun.drain(kept..) {
        tracing::debug!(
            host = ignored.host,
            port = ignored.port,
            "stun server beyond the per-session limit ignored"
        );
    }
    plan.turn = turn_entries(turns);
    Ok(plan)
}

/// Logs one warning when an offer listed more `kind` servers than a
/// session asks, `listed` counting the usable ones after those named
/// twice: a reached limit is a warning, as it drops what the client
/// asked for. Each server dropped is logged at `debug` beside it. One
/// line per offer and kind, so the client's offers bound how often it is
/// logged and it needs no rate limit of its own.
fn warn_beyond_limit(kind: &'static str, limit: usize, listed: usize) {
    let ignored = listed.saturating_sub(limit);
    if ignored > 0 {
        tracing::warn!(
            kind,
            limit,
            listed,
            ignored,
            "ice servers beyond the per-session limit ignored"
        );
    }
}

/// `turns` in list order as entries, each TCP server whose host and port
/// a UDP one names too as the twin of the first such UDP server that has
/// none yet; at most [`MAX_TURN_ATTEMPTS`] entries, with one warning when
/// the list had more ([`warn_beyond_limit`]).
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
    warn_beyond_limit("turn", MAX_TURN_ATTEMPTS, entries.len());
    let kept = entries.len().min(MAX_TURN_ATTEMPTS);
    for ignored in entries.drain(kept..) {
        tracing::debug!(
            host = ignored.server.server.host,
            port = ignored.server.server.port,
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
    /// The transport to it.
    pub(crate) transport: Transport,
    /// The host address the allocation's traffic leaves from.
    pub(crate) local: SocketAddr,
}

/// Leases the allocation on `server` at `target`, as resolved, over its
/// transport (made with its credential if there is none yet), its traffic
/// leaving from the host address `local` of `generation`, which a TCP
/// allocation must have been connected on (RFC 8656 §5: an allocation is
/// bound to its 5-tuple); `None` when that fails.
async fn lease(
    client: &TurnClient,
    server: &TurnServer,
    target: SocketAddr,
    local: SocketAddr,
    generation: u64,
) -> Option<Relayed> {
    match client
        .lease(target, server.transport, generation, &server.credentials)
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

/// One entry's attempts, reached from the host address among `hosts`, of
/// `generation`, of the family its server resolves to: a lease on its
/// server, and for a UDP server with a
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
    generation: u64,
) -> Option<Relayed> {
    let TurnEntry { server, twin } = entry;
    let (target, local) = reach(&server.server, hosts).await?;
    let Some(twin) = twin else {
        return lease(client, &server, target, local, generation).await;
    };
    let mut first = pin!(lease(client, &server, target, local, generation));
    let second = pin!(lease(client, &twin, target, local, generation));
    let silent = tokio::select! {
        relayed = &mut first => return or_other(relayed, second).await,
        () = clock.sleep(TWIN_DELAY) => !client.answered(target, Transport::Udp, generation),
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
/// [`relay_entry`] on `clock` and reached from the session's `hosts`
/// (their addresses, of their generation), and hands each
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
    hosts: &HostSnapshot,
    mut deadline: BoxFuture<'static, ()>,
    leased: &mut (dyn FnMut(Relayed) + Send),
) -> bool {
    let mut queue = RelayQueue::new(entries);
    let attempt = |entry: TurnEntry| async move {
        let host = entry.server.server.host.clone();
        let relayed = relay_entry(client, clock, entry, &hosts.hosts, hosts.generation).await;
        (relayed, host)
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
mod tests;

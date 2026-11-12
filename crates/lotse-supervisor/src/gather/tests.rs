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

/// The STUN URLs `stun:s<n>` and an entry of the TURN URLs `turn:t<n>`
/// for `n` below the counts, `t0` with its TCP twin, each list with
/// its last server named twice.
fn listed(stun: usize, turn: usize) -> Vec<IceServer> {
    let mut stun: Vec<String> = (0..stun).map(|n| format!("stun:s{n}")).collect();
    stun.push(stun.last().unwrap().to_uppercase());
    let mut turn: Vec<String> = (0..turn).map(|n| format!("turn:t{n}")).collect();
    turn.push(turn.last().unwrap().clone());
    turn.push("turn:t0?transport=tcp".into());
    let stun: Vec<&str> = stun.iter().map(String::as_str).collect();
    let turn: Vec<&str> = turn.iter().map(String::as_str).collect();
    let mut listed = servers(&stun);
    listed.push(turn_entry(&turn, Some("pw")));
    listed
}

#[test]
fn an_offer_over_a_server_limit_warns_once_per_kind_and_one_at_it_not_at_all() {
    let captured = crate::test_support::Captured::default();
    let _logs = captured.install();
    let warning = "ice servers beyond the per-session limit ignored";
    // At the limits, a server named twice taking one place: no warning.
    let plan = plan(&listed(MAX_STUN_SERVERS, MAX_TURN_ATTEMPTS)).unwrap();
    assert_eq!(
        (plan.stun.len(), plan.turn.len()),
        (MAX_STUN_SERVERS, MAX_TURN_ATTEMPTS)
    );
    assert_eq!(captured.lines(warning), Vec::<String>::new());
    // Over them: one warning per kind with the limit and the servers
    // listed and ignored, each ignored server at debug.
    let plan = super::plan(&listed(MAX_STUN_SERVERS + 3, MAX_TURN_ATTEMPTS + 2)).unwrap();
    assert_eq!(
        (plan.stun.len(), plan.turn.len()),
        (MAX_STUN_SERVERS, MAX_TURN_ATTEMPTS)
    );
    let lines = captured.lines(warning);
    assert!(lines.iter().all(|line| line.contains(" WARN ")));
    let fields: Vec<&str> = lines
        .iter()
        .map(|line| line.split_once("limit ignored ").unwrap().1)
        .collect();
    assert_eq!(
        fields,
        [
            format!(
                "kind=\"stun\" limit={MAX_STUN_SERVERS} listed={} ignored=3",
                MAX_STUN_SERVERS + 3
            ),
            format!(
                "kind=\"turn\" limit={MAX_TURN_ATTEMPTS} listed={} ignored=2",
                MAX_TURN_ATTEMPTS + 2
            ),
        ]
    );
    let stun = captured.lines("stun server beyond the per-session limit ignored");
    let turn = captured.lines("turn server beyond the per-session limit ignored");
    assert_eq!((stun.len(), turn.len()), (3, 2));
    assert!(stun[0].contains(&format!("host=\"s{MAX_STUN_SERVERS}\" port=3478")));
    assert!(turn[0].contains(&format!("host=\"t{MAX_TURN_ATTEMPTS}\" port=3478")));
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

/// What `relay_all` hands over, pushed onto `leases`. One closure for
/// every test, so a test that expects nothing handed over leaves no
/// closure of its own that never runs (llvm-cov counts one as missed).
fn collect(leases: &mut Vec<Relayed>) -> impl FnMut(Relayed) + Send + '_ {
    move |relayed| leases.push(relayed)
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
        let mut push = collect(&mut leases);
        let never = Box::pin(std::future::pending());
        let hosts = HostSnapshot {
            hosts: hosts.to_vec(),
            ..HostSnapshot::default()
        };
        let mut relays = pin!(relay_all(client, clock, entries, &hosts, never, &mut push));
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
async fn a_lease_ready_just_as_the_gather_deadline_passes_is_released_not_handed_over_rfc_8656_8() {
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
        let mut push = collect(&mut leases);
        let deadline = clock.sleep(GATHER_DEADLINE);
        let hosts = HostSnapshot {
            hosts: vec![local],
            ..HostSnapshot::default()
        };
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
                std::future::poll_fn(|cx| std::task::Poll::Ready(relays.as_mut().poll(cx))).await;
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
async fn a_udp_turn_server_that_answers_only_its_challenge_keeps_its_twin_waiting_rfc_8656_7_2() {
    let clock = Arc::new(FakeClock::from_system());
    let (client, demux, local) = turn_client(&clock);
    let turn = fake_turn();
    let server = FakeTurnServer::start(Arc::clone(&turn)).await.unwrap();
    // The 401 comes over UDP, then nothing: the path carries UDP, and
    // the twin waits for that attempt to fail.
    let address = server.tcp_addr();
    let read = udp_server(address.port(), Udp::First(Arc::clone(&turn)));
    let test = async {
        eventually(|| client.answered(address, Transport::Udp, 0)).await;
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
async fn a_session_joining_while_its_udp_allocation_is_deleted_unanswered_starts_its_twin_rfc_8656_8_1()
 {
    let clock = Arc::new(FakeClock::from_system());
    let start = clock.now();
    let (client, demux, local) = turn_client(&clock);
    let turn = fake_turn();
    let server = FakeTurnServer::start(Arc::clone(&turn)).await.unwrap();
    // The UDP server on the TCP twin's port answers an allocation, then
    // goes silent: its deletion stays unanswered.
    let address = server.tcp_addr();
    let udp = fake_turn();
    let _read = udp_server(address.port(), Udp::Each(Arc::clone(&udp)));
    let entry = twinned(address.port(), "pw");
    let credentials = entry.server.credentials.clone();
    let earlier = client
        .lease(address, Transport::Udp, 0, &credentials)
        .await
        .unwrap();
    assert!(client.answered(address, Transport::Udp, 0));
    udp.drop_requests(usize::MAX);
    drop(earlier);
    eventually(|| udp.dropped() == 1).await;
    // The deleting allocation's answers do not count.
    assert!(!client.answered(address, Transport::Udp, 0));
    // The joining session's UDP attempt waits for the deletion; its
    // twin starts after TWIN_DELAY and yields the lease while the
    // clock stands there, well within the gather deadline.
    let test = async {
        SystemClock.sleep(Duration::from_millis(50)).await;
        clock.advance(TWIN_DELAY);
    };
    let leases = run_relays(&client, &clock, vec![entry], &[local], test, Duration::ZERO).await;
    assert_eq!(leases.len(), 1);
    assert_eq!(
        (leases[0].transport, leases[0].server),
        (Transport::Tcp, address)
    );
    assert!(clock.now().duration_since(start) < GATHER_DEADLINE);
    // The deletion never got through: the UDP server still holds it.
    assert_eq!(udp.allocations().len(), 1);
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

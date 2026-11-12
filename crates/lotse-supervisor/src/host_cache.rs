//! The host addresses sessions answer with (RFC 8445 §5.1.1.1), and what
//! follows from them, re-read when a `webrtc/offer` finds them older than
//! [`MAX_AGE`]: an address the host gains after the daemon started (a new
//! DHCP lease, an interface such as a VPN's coming up later) reaches the
//! next session without a restart.
//!
//! What follows from the host addresses is one [`HostSnapshot`], taken
//! whole: the passive ICE-TCP candidates' addresses, the advertised
//! addresses' candidates and host filter ([`Advertisement`]), the bases
//! STUN and TURN gathering pick from, and the addresses a signaled source
//! gathers on. A session keeps the snapshot of its offer for its whole
//! life: a running session is never told of new addresses (no ICE
//! restart); when its pair dies, the client opens a new session, which
//! gets the current ones.
//!
//! Each snapshot carries a generation, one more at each change of the
//! list, so what was learned from the host addresses of before is not
//! handed to a session on the new ones: the STUN client asks a server
//! again rather than reuse a mapping (a server-reflexive candidate is
//! relative to its base, RFC 8445 §5.1.1.2), and a new session's lease
//! on a TCP allocation comes from one connected on the new addresses (an
//! allocation is bound to its 5-tuple, RFC 8656 §5).
//!
//! The re-read is `getifaddrs(3)` (a netlink dump on Linux) and two
//! probe sockets that send nothing (the `net::hosts` module), which the
//! supervisor's sandbox allows: its seccomp filter takes any socket family
//! and Landlock restricts only TCP. An explicitly bound address is the one
//! host address whatever the interfaces say, so it is never re-read.
//!
//! Why each interface address is left out is logged at debug only when
//! the list is new: at startup (`net::udp`) and when a re-read finds a
//! different one, after the line saying it changed. A re-read that finds
//! the same list drops them: it changed nothing a session sees, the
//! decisions behind the list were logged with it, and repeating them at
//! every offer, up to once per [`MAX_AGE`], only buries the lines that
//! say something.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use lotse_core::clock::Clock;

use crate::advertise::{AdvertisedAddress, Advertisement};
use crate::net::hosts::{self, Exclusion, HostRead, InterfaceAddress};

/// How old the host addresses may be when an offer takes them: 2 s. A
/// burst of offers (a dashboard opening a dozen cameras at once) reads
/// them once, and a change reaches every offer made 2 s after it, sooner
/// than a client notices its session's pair died and opens a new one.
/// A read is cheap (one netlink dump and two sockets that send nothing),
/// so the bound is about bursts, not cost.
pub(crate) const MAX_AGE: Duration = Duration::from_secs(2);

/// The probe of the default route's source address towards a target
/// (`net::hosts::probe`, or a test's).
type Probe = dyn Fn(SocketAddr) -> Option<IpAddr> + Send + Sync;

/// The enumeration of the interfaces' addresses (`net::hosts::interfaces`,
/// or a test's).
type Interfaces = dyn Fn() -> io::Result<Vec<InterfaceAddress>> + Send + Sync;

/// How the front door's host addresses are read again: the shared UDP
/// socket's bound address and family, the ICE-TCP listener's address, the
/// probe and enumeration to read them with, and whether the read at
/// startup failed to enumerate the interfaces. Only the supervisor makes
/// one; the binary passes it through.
#[derive(Clone)]
pub struct HostScan {
    /// Where the shared UDP socket is bound; an address other than the
    /// unspecified one is never re-read.
    local: SocketAddr,
    /// The UDP socket takes IPv4 too.
    dual_stack: bool,
    /// Where the ICE-TCP listener is bound; `None` with it off.
    tcp_listener: Option<SocketAddr>,
    /// Finds the default route's source address.
    probe: Arc<Probe>,
    /// Lists the interfaces' addresses.
    interfaces: Arc<Interfaces>,
    /// The read at startup (`net::udp`) failed to enumerate the
    /// interfaces and warned so: the first re-read that fails too does
    /// not warn again, and the first that succeeds says the failure ended.
    startup_failed: bool,
}

impl HostScan {
    /// A scan of the system's interfaces for the UDP socket bound at
    /// `local` (taking IPv4 too when `dual_stack`) and the ICE-TCP listener
    /// at `tcp_listener`, whose enumeration at startup failed when
    /// `startup_failed`.
    pub(crate) fn system(
        local: SocketAddr,
        dual_stack: bool,
        tcp_listener: Option<SocketAddr>,
        startup_failed: bool,
    ) -> Self {
        Self {
            startup_failed,
            ..Self::new(
                local,
                dual_stack,
                tcp_listener,
                Arc::new(hosts::probe),
                Arc::new(hosts::interfaces),
            )
        }
    }

    /// A scan with its own `probe` and `interfaces`, whose enumeration at
    /// startup succeeded: the seam the tests change the interfaces
    /// through.
    pub(crate) fn new(
        local: SocketAddr,
        dual_stack: bool,
        tcp_listener: Option<SocketAddr>,
        probe: Arc<Probe>,
        interfaces: Arc<Interfaces>,
    ) -> Self {
        Self {
            local,
            dual_stack,
            tcp_listener,
            probe,
            interfaces,
            startup_failed: false,
        }
    }

    /// Whether the interfaces decide the host addresses: the socket is
    /// bound to the unspecified address.
    fn rereads(&self) -> bool {
        self.local.ip().is_unspecified()
    }

    /// The host addresses now, with the ones left out and why the
    /// interfaces were not enumerated if they were not, and the ICE-TCP
    /// addresses that follow from them. Logs nothing.
    fn read(&self) -> (HostRead, Vec<SocketAddr>) {
        let read = hosts::read_host_addresses(
            self.local,
            self.dual_stack,
            self.probe.as_ref(),
            self.interfaces.as_ref(),
        );
        let tcp_hosts = crate::tcp_hosts(&read.hosts, self.tcp_listener);
        (read, tcp_hosts)
    }
}

impl fmt::Debug for HostScan {
    /// The addresses and the startup failure; the probe and the
    /// enumeration are code.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostScan")
            .field("local", &self.local)
            .field("dual_stack", &self.dual_stack)
            .field("tcp_listener", &self.tcp_listener)
            .field("startup_failed", &self.startup_failed)
            .finish_non_exhaustive()
    }
}

/// The host addresses at one moment and everything derived from them,
/// which a session takes whole at its offer.
#[derive(Debug, Default)]
pub(crate) struct HostSnapshot {
    /// The host candidates' addresses, the default-route one of each
    /// family first.
    pub(crate) hosts: Vec<SocketAddr>,
    /// The passive ICE-TCP host candidates' addresses; empty with the
    /// listener off.
    pub(crate) tcp_hosts: Vec<SocketAddr>,
    /// What `webrtc.advertise` makes of a session on these addresses.
    pub(crate) advertisement: Arc<Advertisement>,
    /// The addresses of [`Self::hosts`], each once: where a signaled
    /// source gathers its candidates.
    pub(crate) local_addrs: Vec<IpAddr>,
    /// Which list of host addresses this is: 0 for the one found at
    /// startup, one more at each change ([module docs](self)).
    pub(crate) generation: u64,
}

impl HostSnapshot {
    /// The snapshot of `hosts` and `tcp_hosts`, with `advertised` worked
    /// out on them, of generation 0.
    pub(crate) fn new(
        hosts: Vec<SocketAddr>,
        tcp_hosts: Vec<SocketAddr>,
        advertised: &[AdvertisedAddress],
    ) -> Self {
        let mut local_addrs: Vec<IpAddr> = Vec::new();
        for ip in hosts.iter().map(SocketAddr::ip) {
            if !local_addrs.contains(&ip) {
                local_addrs.push(ip);
            }
        }
        Self {
            advertisement: Arc::new(Advertisement::new(advertised, &hosts, &tcp_hosts)),
            hosts,
            tcp_hosts,
            local_addrs,
            generation: 0,
        }
    }
}

/// What re-reads the host addresses: the scan, the advertised addresses
/// to work out again on a change, and the clock that ages them.
#[derive(Debug)]
struct Rescan {
    /// Reads the host addresses.
    scan: HostScan,
    /// `webrtc.advertise`.
    advertised: Vec<AdvertisedAddress>,
    /// The injected clock.
    clock: Arc<dyn Clock>,
}

/// The snapshot sessions take and when it was last read.
#[derive(Debug, Default)]
struct Cached {
    /// The current snapshot.
    snapshot: Arc<HostSnapshot>,
    /// When the host addresses were last read; `None` before the first
    /// read, which the default only is.
    read: Option<Instant>,
    /// The last read failed to enumerate the interfaces, the one at
    /// startup included: a failure is logged as a warning when it starts
    /// (by `net::hosts` at startup) and as information when it ends, in
    /// between at debug, so a lasting one does not repeat at every offer.
    failing: bool,
}

/// The host addresses sessions answer with: the [`HostSnapshot`] of the
/// last read, read again by [`Self::current`] once older than
/// [`MAX_AGE`]. Without a [`Rescan`] (an explicit bind, or no front door)
/// the snapshot never changes. The default is an empty, fixed one.
#[derive(Debug, Default)]
pub(crate) struct HostCache {
    /// How to re-read; `None` when the snapshot is fixed.
    rescan: Option<Rescan>,
    /// The snapshot; its lock is held while re-reading, so concurrent
    /// offers wait for one read instead of each doing their own. Nothing
    /// takes another lock while holding it.
    cached: Mutex<Cached>,
}

impl HostCache {
    /// A cache holding `snapshot`, read just now, re-read by `scan` with
    /// `advertised` worked out on each change, aged on `clock`; fixed
    /// without a scan or when the scan's socket is bound to one address.
    /// A scan whose startup read failed to enumerate the interfaces starts
    /// it failing, so the warning already logged is not repeated.
    pub(crate) fn new(
        snapshot: HostSnapshot,
        scan: Option<HostScan>,
        advertised: &[AdvertisedAddress],
        clock: &Arc<dyn Clock>,
    ) -> Self {
        let rescan = scan.filter(HostScan::rereads).map(|scan| Rescan {
            scan,
            advertised: advertised.to_vec(),
            clock: Arc::clone(clock),
        });
        let read = rescan.as_ref().map(|rescan| rescan.clock.now());
        let failing = rescan
            .as_ref()
            .is_some_and(|rescan| rescan.scan.startup_failed);
        Self {
            rescan,
            cached: Mutex::new(Cached {
                snapshot: Arc::new(snapshot),
                read,
                failing,
            }),
        }
    }

    /// The cached state; a poisoned lock is still usable, a panicking
    /// holder leaves a whole snapshot behind.
    fn lock(&self) -> MutexGuard<'_, Cached> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The last snapshot, never re-read: for what is not an offer.
    pub(crate) fn latest(&self) -> Arc<HostSnapshot> {
        Arc::clone(&self.lock().snapshot)
    }

    /// The snapshot for a new session: the last one, re-read first when it
    /// is [`MAX_AGE`] old or older. A changed list is logged once, with
    /// the addresses before and after and then why each interface address
    /// is left out, and replaces the snapshot with one of the next
    /// generation; the sessions holding the old one keep it. An unchanged
    /// list logs no exclusion and keeps the generation
    /// ([module docs](self)).
    pub(crate) fn current(&self) -> Arc<HostSnapshot> {
        let Some(rescan) = &self.rescan else {
            return self.latest();
        };
        let now = rescan.clock.now();
        let mut cached = self.lock();
        if cached
            .read
            .is_some_and(|read| now.saturating_duration_since(read) < MAX_AGE)
        {
            return Arc::clone(&cached.snapshot);
        }
        cached.read = Some(now);
        let (
            HostRead {
                hosts,
                exclusions,
                failure,
            },
            tcp_hosts,
        ) = rescan.scan.read();
        let failed = failure.is_some();
        match (failure, cached.failing) {
            (Some(err), false) => tracing::warn!(
                error = %err,
                "interfaces not enumerated at an offer; offering the default-route addresses alone until they are"
            ),
            (Some(err), true) => tracing::debug!(
                error = %err,
                "interfaces still not enumerated; offering the default-route addresses alone"
            ),
            (None, true) => tracing::info!("interfaces enumerated again"),
            (None, false) => {}
        }
        cached.failing = failed;
        if hosts == cached.snapshot.hosts {
            return Arc::clone(&cached.snapshot);
        }
        tracing::info!(
            before = cached.snapshot.hosts.len(),
            after = hosts.len(),
            previous = ?cached.snapshot.hosts,
            hosts = ?hosts,
            tcp_hosts = ?tcp_hosts,
            "host addresses changed; new sessions offer these, running ones keep theirs"
        );
        exclusions.iter().for_each(Exclusion::log);
        let mut snapshot = HostSnapshot::new(hosts, tcp_hosts, &rescan.advertised);
        snapshot.generation = cached.snapshot.generation.wrapping_add(1);
        let snapshot = Arc::new(snapshot);
        cached.snapshot = Arc::clone(&snapshot);
        snapshot
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A host whose interfaces a test changes.

    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::HostScan;
    use crate::net::hosts::InterfaceAddress;

    /// The interfaces a [`HostScan`] of [`Self::scan`] lists, changed by
    /// [`Self::set`] or failed by [`Self::fail`], and how often they were
    /// listed.
    #[derive(Debug, Default)]
    pub(crate) struct Interfaces {
        /// The addresses listed, or `None` to fail.
        listed: Mutex<Option<Vec<InterfaceAddress>>>,
        /// How many times they were listed.
        reads: AtomicUsize,
    }

    impl Interfaces {
        /// Interfaces `eth0` with each of `ips`, all up.
        pub(crate) fn with(ips: &[&str]) -> Arc<Self> {
            let interfaces = Arc::new(Self::default());
            interfaces.set(ips);
            interfaces
        }

        /// From now on, `eth0` with each of `ips`.
        pub(crate) fn set(&self, ips: &[&str]) {
            *self.listed.lock().unwrap() = Some(
                ips.iter()
                    .map(|ip| InterfaceAddress {
                        name: "eth0".into(),
                        ip: ip.parse().unwrap(),
                        up: true,
                        loopback: false,
                    })
                    .collect(),
            );
        }

        /// From now on, the enumeration fails.
        pub(crate) fn fail(&self) {
            *self.listed.lock().unwrap() = None;
        }

        /// How many times the interfaces were listed.
        pub(crate) fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }

        /// A scan of these interfaces for a UDP socket at `local`, dual
        /// stack, and the ICE-TCP listener at `tcp`, with no default route
        /// and `192.0.2.99` as the default route's when they fail.
        pub(crate) fn scan(self: &Arc<Self>, local: &str, tcp: Option<&str>) -> HostScan {
            let interfaces = Arc::clone(self);
            HostScan::new(
                local.parse().unwrap(),
                true,
                tcp.map(|tcp| tcp.parse().unwrap()),
                Arc::new(|target: SocketAddr| {
                    target.is_ipv4().then(|| IpAddr::from([192, 0, 2, 99]))
                }),
                Arc::new(move || {
                    interfaces.reads.fetch_add(1, Ordering::SeqCst);
                    interfaces
                        .listed
                        .lock()
                        .unwrap()
                        .clone()
                        .ok_or_else(|| io::Error::other("netlink refused"))
                }),
            )
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

    use lotse_core::clock::FakeClock;

    use super::test_support::Interfaces;
    use super::*;
    use crate::test_support::Captured;

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    fn cache(
        scan: HostScan,
        advertised: &[AdvertisedAddress],
        clock: &Arc<FakeClock>,
    ) -> HostCache {
        let clock: Arc<dyn Clock> = Arc::<FakeClock>::clone(clock);
        let (read, tcp_hosts) = scan.read();
        // As the front door: the startup read's failure goes with the scan.
        let mut scan = scan;
        scan.startup_failed = read.failure.is_some();
        HostCache::new(
            HostSnapshot::new(read.hosts, tcp_hosts, advertised),
            Some(scan),
            advertised,
            &clock,
        )
    }

    #[test]
    fn a_snapshot_lists_each_host_address_once_for_a_signaled_source() {
        let snapshot = HostSnapshot::new(
            addrs(&["192.0.2.1:1", "192.0.2.1:2", "[2001:db8::1]:1"]),
            Vec::new(),
            &[],
        );
        assert_eq!(
            snapshot.local_addrs,
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        assert_eq!(HostSnapshot::default().local_addrs, Vec::<IpAddr>::new());
    }

    #[test]
    fn the_scan_shows_its_addresses_not_its_code() {
        let scan = Interfaces::with(&[]).scan("[::]:18556", Some("[::]:18557"));
        assert_eq!(
            format!("{scan:?}"),
            "HostScan { local: [::]:18556, dual_stack: true, tcp_listener: Some([::]:18557), startup_failed: false, .. }"
        );
        // The system's scan reads the system's interfaces.
        let system = HostScan::system("0.0.0.0:0".parse().unwrap(), false, None, true);
        assert!(system.startup_failed);
        let (read, tcp_hosts) = system.read();
        assert!(read.failure.is_none(), "{:?}", read.failure);
        assert!(
            read.hosts
                .iter()
                .all(|host| host.is_ipv4() && host.port() == 0)
        );
        assert!(tcp_hosts.is_empty(), "listener off");
    }

    #[test]
    fn rfc8445_5_1_1_1_an_offer_rereads_host_addresses_older_than_the_max_age() {
        assert_eq!(MAX_AGE, Duration::from_secs(2));
        let captured = Captured::default();
        let _logs = captured.install();
        let interfaces = Interfaces::with(&["192.0.2.1"]);
        let clock = Arc::new(FakeClock::default());
        let advertised = ["2001:db8:f::7".parse().unwrap()];
        let hosts = cache(
            interfaces.scan("[::]:18556", Some("[::]:18557")),
            &advertised,
            &clock,
        );
        assert_eq!(interfaces.reads(), 1, "the first read");
        let first = hosts.current();
        assert_eq!(first.hosts, addrs(&["192.0.2.1:18556"]));
        assert_eq!(first.generation, 0);
        // No IPv6 host address to be the advertised one's base.
        assert_eq!(first.advertisement.lines(), Vec::<String>::new());
        // A change within the max age is not seen yet.
        interfaces.set(&["192.0.2.1", "2001:db8:1::2"]);
        clock.advance(MAX_AGE.checked_sub(Duration::from_millis(1)).unwrap());
        assert!(Arc::ptr_eq(&hosts.current(), &first));
        assert_eq!(interfaces.reads(), 1, "within the max age, no read");
        // At the max age it is, and everything derived follows.
        clock.advance(Duration::from_millis(1));
        let second = hosts.current();
        assert_eq!(interfaces.reads(), 2);
        assert_eq!(
            second.hosts,
            addrs(&["192.0.2.1:18556", "[2001:db8:1::2]:18556"])
        );
        assert_eq!(
            second.tcp_hosts,
            addrs(&["192.0.2.1:18557", "[2001:db8:1::2]:18557"])
        );
        assert_eq!(
            second.local_addrs,
            [
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8:1::2".parse().unwrap()
            ]
        );
        assert_eq!(second.advertisement.lines().len(), 2, "UDP and TCP");
        assert_eq!(second.generation, 1, "a change is a new generation");
        assert!(Arc::ptr_eq(&hosts.latest(), &second));
        // A session that took the first keeps it.
        assert_eq!(first.hosts, addrs(&["192.0.2.1:18556"]));
        let changed = captured.lines("host addresses changed");
        assert_eq!(changed.len(), 1, "{changed:?}");
        assert!(
            changed[0].contains("before=1 after=2")
                && changed[0].contains("previous=[192.0.2.1:18556]")
                && changed[0].contains("hosts=[192.0.2.1:18556, [2001:db8:1::2]:18556]"),
            "{changed:?}"
        );
        // Unchanged: the same snapshot, nothing logged.
        clock.advance(MAX_AGE);
        assert!(Arc::ptr_eq(&hosts.current(), &second));
        assert_eq!(interfaces.reads(), 3);
        assert_eq!(hosts.latest().generation, 1, "the same generation");
        assert_eq!(captured.lines("host addresses changed").len(), 1);
        // `latest` never reads.
        clock.advance(MAX_AGE);
        let _latest = hosts.latest();
        assert_eq!(interfaces.reads(), 3);
    }

    #[test]
    fn only_a_changed_list_logs_why_addresses_are_left_out() {
        let captured = Captured::default();
        let _logs = captured.install();
        let interfaces = Interfaces::with(&["192.0.2.1", "fe80::1"]);
        let clock = Arc::new(FakeClock::default());
        let hosts = cache(interfaces.scan("[::]:7", None), &[], &clock);
        let excluded = || captured.lines("interface address not offered");
        // The same list again: nothing new, so nothing about exclusions.
        for _ in 0..3 {
            clock.advance(MAX_AGE);
            assert_eq!(hosts.current().hosts, addrs(&["192.0.2.1:7"]));
        }
        assert_eq!(interfaces.reads(), 4);
        assert_eq!(excluded(), Vec::<String>::new());
        // A changed list logs them once, after the change.
        interfaces.set(&["192.0.2.1", "fe80::1", "2001:db8:1::2"]);
        clock.advance(MAX_AGE);
        assert_eq!(
            hosts.current().hosts,
            addrs(&["192.0.2.1:7", "[2001:db8:1::2]:7"])
        );
        let logged = excluded();
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(
            logged[0].contains("DEBUG")
                && logged[0].contains("ip=fe80::1")
                && logged[0].contains("reason=\"link-local\""),
            "{logged:?}"
        );
        let all = captured.lines("");
        let changed = all
            .iter()
            .position(|line| line.contains("host addresses changed"))
            .unwrap();
        assert!(all[changed + 1].contains("interface address not offered"));
        // Unchanged again: still once.
        clock.advance(MAX_AGE);
        let _same = hosts.current();
        assert_eq!(interfaces.reads(), 6);
        assert_eq!(excluded().len(), 1);
    }

    #[test]
    fn a_failing_enumeration_warns_once_and_says_when_it_ends() {
        let captured = Captured::default();
        let _logs = captured.install();
        let interfaces = Interfaces::with(&["192.0.2.1"]);
        let clock = Arc::new(FakeClock::default());
        let hosts = cache(interfaces.scan("0.0.0.0:7", None), &[], &clock);
        interfaces.fail();
        for _ in 0..3 {
            clock.advance(MAX_AGE);
            // The default-route address alone.
            assert_eq!(hosts.current().hosts, addrs(&["192.0.2.99:7"]));
        }
        assert_eq!(interfaces.reads(), 4);
        let warned = captured.lines("WARN");
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(
            warned[0].contains("interfaces not enumerated at an offer")
                && warned[0].contains("netlink refused"),
            "{warned:?}"
        );
        assert_eq!(captured.lines("interfaces still not enumerated").len(), 2);
        assert_eq!(captured.lines("host addresses changed").len(), 1);
        interfaces.set(&["192.0.2.1"]);
        clock.advance(MAX_AGE);
        assert_eq!(hosts.current().hosts, addrs(&["192.0.2.1:7"]));
        clock.advance(MAX_AGE);
        let _same = hosts.current();
        let ended = captured.lines("interfaces enumerated again");
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert!(ended[0].contains("INFO"), "{ended:?}");
        // A new failure warns again.
        interfaces.fail();
        clock.advance(MAX_AGE);
        let _fallback = hosts.current();
        assert_eq!(captured.lines("WARN").len(), 2);
    }

    #[test]
    fn a_failure_at_startup_is_not_warned_again_and_its_end_is_said() {
        let captured = Captured::default();
        let _logs = captured.install();
        let interfaces = Interfaces::with(&[]);
        interfaces.fail();
        let clock = Arc::new(FakeClock::default());
        let hosts = cache(interfaces.scan("0.0.0.0:7", None), &[], &clock);
        // Startup warned (`net::hosts`); the first re-read failing too
        // only says so at debug.
        clock.advance(MAX_AGE);
        assert_eq!(hosts.current().hosts, addrs(&["192.0.2.99:7"]));
        assert_eq!(captured.lines("WARN"), Vec::<String>::new());
        let lasting = captured.lines("interfaces still not enumerated");
        assert_eq!(lasting.len(), 1, "{lasting:?}");
        assert!(lasting[0].contains("DEBUG"), "{lasting:?}");
        // A cache whose startup read failed says when a re-read succeeds,
        // its first one included.
        let hosts = cache(interfaces.scan("0.0.0.0:7", None), &[], &clock);
        interfaces.set(&["192.0.2.1"]);
        clock.advance(MAX_AGE);
        assert_eq!(hosts.current().hosts, addrs(&["192.0.2.1:7"]));
        let ended = captured.lines("interfaces enumerated again");
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert!(ended[0].contains("INFO"), "{ended:?}");
        assert_eq!(captured.lines("WARN"), Vec::<String>::new());
    }

    #[test]
    fn an_explicit_bind_or_no_scan_is_never_reread() {
        let interfaces = Interfaces::with(&["192.0.2.1"]);
        let clock = Arc::new(FakeClock::default());
        let hosts = cache(interfaces.scan("192.0.2.1:7", None), &[], &clock);
        // Not even a read that would give the bound address back.
        assert!(hosts.rescan.is_none(), "{hosts:?}");
        assert!(
            cache(interfaces.scan("[::]:7", None), &[], &clock)
                .rescan
                .is_some()
        );
        let reads = interfaces.reads();
        interfaces.set(&["192.0.2.2"]);
        for _ in 0..3 {
            clock.advance(MAX_AGE);
            assert_eq!(hosts.current().hosts, addrs(&["192.0.2.1:7"]));
        }
        assert_eq!(interfaces.reads(), reads, "the interfaces are not asked");
        let fixed = HostCache::default();
        assert_eq!(fixed.current().hosts, Vec::<SocketAddr>::new());
        assert!(Arc::ptr_eq(&fixed.current(), &fixed.latest()));
    }
}

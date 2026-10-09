//! Process memory as the kernel reports it: `Rss` and `Pss` of
//! `/proc/<pid>/smaps_rollup` (proc(5), Linux 4.14), for `metrics/get` and
//! `stream/get`.
//!
//! The supervisor reads its own through `/proc/self`, which its Landlock
//! rules keep readable. A worker is not dumpable, so the kernel closes its
//! `/proc/<pid>/smaps_rollup` to every other process without
//! `CAP_SYS_PTRACE` (the `PTRACE_MODE_READ` check of ptrace(2)); the worker
//! opens its own before its sandbox and hands the descriptor over with
//! `Ready`, and the supervisor reads through it. The access check runs at
//! open, and each read makes the kernel walk the worker's mappings anew, so
//! the figures are the kernel's, never the worker's word.
//!
//! That walk takes as long as the process has mappings, and a compromised
//! worker can map many, so a read never runs on a runtime thread or under
//! the registry lock: [`MemoryProbe::sample`] reads on the blocking pool,
//! one read per probe at a time, and serves the figures again for
//! [`FRESH`] after.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lotse_core::task::spawn_blocking_named;

/// Where the supervisor's own figures come from; there is no `/proc` on
/// macOS.
pub(crate) const OWN: &str = "/proc/self/smaps_rollup";

/// The most of `smaps_rollup` read: the file is about 1 KiB, a header line
/// and some twenty `Key: value kB` lines.
const MAX_LEN: usize = 4096;

/// How long a read's figures are served again before the next read: the
/// workers' counters arrive once a second too, so a caller polling faster
/// learns nothing new, and the kernel walks a process's mappings at most
/// once per period however often `stream/get` and `metrics/get` are asked.
pub const FRESH: Duration = Duration::from_secs(1);

/// One process's memory; `None` where the figure is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Memory {
    /// Resident set size, bytes.
    pub rss_bytes: Option<u64>,
    /// Proportional set size, bytes.
    pub pss_bytes: Option<u64>,
}

/// An open `smaps_rollup`, read again by [`MemoryProbe::sample`] once its
/// last figures are older than [`FRESH`]. Clones share the descriptor and
/// the figures; two probes are equal when they share them.
#[derive(Debug, Clone)]
pub struct MemoryProbe(Arc<Rollup>);

/// What the clones of one probe share.
#[derive(Debug)]
struct Rollup {
    /// The open `smaps_rollup`.
    file: File,
    /// The last figures and when, on the injected clock, they were read;
    /// held across a read, so one probe reads once at a time and a caller
    /// arriving meanwhile gets that read's figures.
    last: tokio::sync::Mutex<Option<(Instant, Memory)>>,
}

impl Rollup {
    /// A probe's shared part on `file`, not read yet.
    fn new(file: File) -> Arc<Self> {
        Arc::new(Self {
            file,
            last: tokio::sync::Mutex::new(None),
        })
    }
}

impl PartialEq for MemoryProbe {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for MemoryProbe {}

impl MemoryProbe {
    /// A probe on a descriptor a worker handed over with `Ready`.
    pub fn from_fd(fd: OwnedFd) -> Self {
        Self(Rollup::new(File::from(fd)))
    }

    /// A probe on the `smaps_rollup` at `path` ([`OWN`]); `None` where
    /// it does not open.
    pub(crate) fn open(path: &str) -> Option<Self> {
        File::open(path).ok().map(|file| Self(Rollup::new(file)))
    }

    /// The figures at `now`: those of the last read when it is younger than
    /// [`FRESH`], otherwise a new read on the blocking pool, awaited without
    /// holding a runtime thread. Callers hold no lock across it.
    pub async fn sample(&self, now: Instant) -> Memory {
        let mut last = self.0.last.lock().await;
        if let Some((at, memory)) = *last
            && now.saturating_duration_since(at) < FRESH
        {
            return memory;
        }
        let probe = self.clone();
        // The read never panics (`panic = "abort"`), so the join fails only
        // when the runtime is shutting down: unknown figures then.
        let memory = spawn_blocking_named("memory.read", move || probe.read())
            .await
            .unwrap_or_default();
        *last = Some((now, memory));
        memory
    }

    /// The figures now, blocking while the kernel walks the mappings; only
    /// [`MemoryProbe::sample`] calls it, on the blocking pool. A failed read
    /// (the process is gone: `ESRCH`) gives unknown figures.
    fn read(&self) -> Memory {
        let mut buf = [0_u8; MAX_LEN];
        let mut filled = 0_usize;
        // A seq_file read at offset 0 starts the walk anew (pread(2) on
        // proc files); later chunks continue where the last one ended.
        while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            match self
                .0
                .file
                .read_at(rest, u64::try_from(filled).unwrap_or(u64::MAX))
            {
                Ok(0) => break,
                Ok(n) => filled = filled.saturating_add(n),
                Err(err) => {
                    tracing::debug!(error = %err, "smaps_rollup unreadable");
                    return Memory::default();
                }
            }
        }
        parse(buf.get(..filled).unwrap_or_default())
    }
}

/// The `Rss:` and `Pss:` lines of `smaps_rollup`, in kB (proc(5)); other
/// lines (`Pss_Anon:` and the rest) and malformed values are skipped.
fn parse(text: &[u8]) -> Memory {
    let mut memory = Memory::default();
    for line in String::from_utf8_lossy(text).lines() {
        let mut fields = line.split_ascii_whitespace();
        let slot = match fields.next() {
            Some("Rss:") => &mut memory.rss_bytes,
            Some("Pss:") => &mut memory.pss_bytes,
            _ => continue,
        };
        *slot = fields
            .next()
            .and_then(|kb| kb.parse::<u64>().ok())
            .and_then(|kb| kb.checked_mul(1024));
    }
    memory
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::io::Write as _;
    use std::sync::atomic::{AtomicU32, Ordering};

    use lotse_core::clock::{Clock as _, FakeClock};

    use super::*;

    /// `smaps_rollup` of a worker, as Linux 6.8 writes it.
    const ROLLUP: &str = "\
55d6c7a5e000-7ffd3d1f1000 ---p 00000000 00:00 0                          [rollup]
Rss:                3392 kB
Pss:                 616 kB
Pss_Dirty:           404 kB
Pss_Anon:            404 kB
Pss_File:            212 kB
Pss_Shmem:             0 kB
Shared_Clean:       2788 kB
Private_Dirty:       404 kB
Anonymous:           404 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
";

    fn probe(contents: &[u8]) -> MemoryProbe {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "lotse-smaps-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        File::create(&path).unwrap().write_all(contents).unwrap();
        let probe = MemoryProbe::open(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        probe
    }

    #[test]
    fn rss_and_pss_are_read_in_bytes_from_the_rollup() {
        assert_eq!(
            parse(ROLLUP.as_bytes()),
            Memory {
                rss_bytes: Some(3392 * 1024),
                pss_bytes: Some(616 * 1024),
            }
        );
    }

    #[test]
    fn malformed_and_missing_values_are_unknown() {
        assert_eq!(parse(b""), Memory::default());
        assert_eq!(
            parse(b"Rss: lots kB\nPss:\nPss_Anon: 4 kB\n"),
            Memory::default()
        );
        assert_eq!(
            parse(format!("Rss: {} kB\nPss: 1 kB\n", u64::MAX).as_bytes()),
            Memory {
                rss_bytes: None,
                pss_bytes: Some(1024),
            }
        );
    }

    #[test]
    fn a_probe_reads_its_file_again_each_time_and_its_clones_are_equal() {
        let rollup = probe(ROLLUP.as_bytes());
        let first = rollup.read();
        assert_eq!(first.pss_bytes, Some(616 * 1024));
        assert_eq!(rollup.read(), first, "read from offset 0 again");
        assert_eq!(rollup.clone(), rollup);
        assert_ne!(probe(b"Rss: 1 kB\n"), rollup);
    }

    #[test]
    fn a_rollup_past_the_buffer_is_cut_and_a_failed_read_is_unknown() {
        let mut long = ROLLUP.to_owned();
        while long.len() < MAX_LEN * 2 {
            long.push_str("Locked:                0 kB\n");
        }
        assert_eq!(probe(long.as_bytes()).read().rss_bytes, Some(3392 * 1024));
        // A directory opens but does not read.
        let dir = File::open(std::env::temp_dir()).unwrap();
        assert_eq!(
            MemoryProbe::from_fd(OwnedFd::from(dir)).read(),
            Memory::default()
        );
    }

    #[tokio::test]
    async fn a_sample_is_served_again_until_it_is_a_second_old_then_read_anew() {
        let path = std::env::temp_dir().join(format!("lotse-smaps-fresh-{}", std::process::id()));
        File::create(&path)
            .unwrap()
            .write_all(b"Pss: 1 kB\n")
            .unwrap();
        let rollup = MemoryProbe::open(path.to_str().unwrap()).unwrap();
        // Ten seconds on, so the clock can also go back.
        let start = FakeClock::from_system().now() + 10 * FRESH;
        assert_eq!(rollup.sample(start).await.pss_bytes, Some(1024));
        // The same file, rewritten: only a new read sees it.
        File::create(&path)
            .unwrap()
            .write_all(b"Pss: 2 kB\n")
            .unwrap();
        let almost = start + Duration::from_millis(999);
        assert_eq!(rollup.sample(almost).await.pss_bytes, Some(1024));
        assert_eq!(
            rollup.clone().sample(almost).await.pss_bytes,
            Some(1024),
            "clones share the figures"
        );
        // A clock that went back reads nothing new either.
        assert_eq!(
            rollup
                .sample(start.checked_sub(FRESH).unwrap())
                .await
                .pss_bytes,
            Some(1024)
        );
        let stale = start + FRESH;
        assert_eq!(rollup.sample(stale).await.pss_bytes, Some(2048));
        File::create(&path)
            .unwrap()
            .write_all(b"Pss: 3 kB\n")
            .unwrap();
        assert_eq!(
            rollup
                .sample(stale + Duration::from_millis(999))
                .await
                .pss_bytes,
            Some(2048),
            "fresh from the last read, not the first"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_path_that_does_not_open_has_no_probe() {
        assert!(MemoryProbe::open("/nonexistent/smaps_rollup").is_none());
        assert_eq!(MemoryProbe::open(OWN).is_some(), cfg!(target_os = "linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_own_probe_reads_the_supervisor_s_memory() {
        let memory = MemoryProbe::open(OWN).unwrap().read();
        assert!(memory.pss_bytes.unwrap() > 0, "{memory:?}");
        assert!(memory.rss_bytes >= memory.pss_bytes, "{memory:?}");
    }
}

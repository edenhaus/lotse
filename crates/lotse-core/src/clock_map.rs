//! The clock mapper: from a track's RTP timestamps to the daemon's
//! monotonic clock, one per source connection, never per source.
//!
//! Without Sender Reports every track of a connection maps by arrival on
//! one shared base, so the daemon introduces no skew of its own. With them
//! (RFC 3550 §6.4.1), each track fits the camera's NTP time against its RTP
//! clock by least squares over a 30 s window, and one NTP-to-local offset,
//! the smallest arrival-minus-NTP of the connection's reports, puts every
//! track on the same local base: the camera's capture clock decides A/V
//! sync. Every update is slew-limited, so one bad report moves the mapping
//! by at most [`MAX_SLEW`]. A report that contradicts the fit by more than
//! [`MAX_RESIDUAL`] is rejected, and a camera that keeps contradicting it
//! (an NTP step) re-anchors the whole connection, all tracks together.
//! A camera chooses how often it reports, so the lines of rejections,
//! re-anchors and syncs are rate-limited per track ([`Throttle`]).
//!
//! Each report also leaves its track's mapping error, which the skew
//! watchdog ([`crate::skew`]) judges across audio and video: from the
//! reports' own NTP and RTP times, never from their arrival.
//!
//! The arithmetic is exact integer arithmetic on `i128`: NTP time in
//! nanoseconds, RTP time in ticks, slopes as fractions. Anything that would
//! overflow is treated as no mapping, and the arrival is used.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use crate::codec::Kind;
use crate::skew::SkewWatchdog;
use crate::source::{ClockReport, SyncHint};
use crate::throttle::Throttle;
use crate::track::TrackId;

/// The window of Sender Reports a fit and the offset are computed over.
pub const FIT_WINDOW: Duration = Duration::from_secs(30);

/// How far one report may move a track's mapping or the connection's
/// offset.
pub const MAX_SLEW: Duration = Duration::from_millis(5);

/// A report further than this from the fit's prediction contradicts it
/// and is rejected. A camera stamps NTP and RTP time of a report together
/// (RFC 3550 §6.4.1), so an honest report is off by clock drift only.
pub const MAX_RESIDUAL: Duration = Duration::from_millis(100);

/// Consecutive contradicting reports on one track that re-anchor the
/// connection: the camera's NTP clock stepped.
pub const MAX_CONTRADICTIONS: u32 = 3;

/// At most this many reports per track in the window; the oldest go first.
const FIT_POINTS: usize = 32;

/// At most this many reports in the offset window, all tracks together.
const OFFSET_POINTS: usize = 64;

/// A fitted rate further than this from the declared clock rate, in parts
/// per million, is not believed, and the declared rate is used. Camera
/// clocks are off by hundreds of ppm at most.
const MAX_RATE_PPM: i128 = 10_000;

/// Nanoseconds per second.
const NANOS_PER_SEC: i128 = 1_000_000_000;

/// How a track's timestamps are mapped, as `tracks[].sync` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncMode {
    /// By arrival time on the connection's shared base.
    Arrival,
    /// From the camera's Sender Reports.
    SenderReports,
}

impl SyncMode {
    /// The API name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Arrival => "arrival",
            Self::SenderReports => "sender_reports",
        }
    }
}

/// `to - from` on the 32-bit RTP clock, signed (RFC 3550 §5.1: timestamps
/// wrap).
pub(crate) const fn ticks_between(from: u32, to: u32) -> i32 {
    i32::from_ne_bytes(to.wrapping_sub(from).to_ne_bytes())
}

/// Moves `from` toward `to` by at most [`MAX_SLEW`].
fn slew(from: i64, to: i64) -> i64 {
    let max = i64::try_from(MAX_SLEW.as_nanos()).unwrap_or(i64::MAX);
    from.saturating_add(to.saturating_sub(from).clamp(max.saturating_neg(), max))
}

/// A Sender Report kept for the fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Report {
    /// The RTP timestamp.
    rtp: u32,
    /// The NTP time in nanoseconds since the connection's NTP base.
    ntp: i64,
    /// When it arrived.
    arrival: Instant,
}

/// A linear map from a track's RTP clock to NTP nanoseconds: `ntp_ref` at
/// `rtp_ref`, and `num / den` nanoseconds per tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fit {
    /// The RTP timestamp the map is anchored at.
    rtp_ref: u32,
    /// Its NTP time, nanoseconds since the connection's base.
    ntp_ref: i64,
    /// The slope's numerator.
    num: i128,
    /// The slope's denominator; positive.
    den: i128,
}

impl Fit {
    /// The declared clock rate anchored at `report`.
    fn nominal(report: Report, clock_rate: u32) -> Self {
        Self {
            rtp_ref: report.rtp,
            ntp_ref: report.ntp,
            num: NANOS_PER_SEC,
            den: i128::from(clock_rate),
        }
    }

    /// The least-squares line through `reports`, anchored at `newest`'s
    /// timestamp; `None` without two distinct timestamps, or on overflow.
    fn least_squares(reports: &[Report], newest: Report) -> Option<Self> {
        let n = i128::try_from(reports.len()).ok()?;
        let (mut sx, mut sy, mut sxx, mut sxy) = (0_i128, 0_i128, 0_i128, 0_i128);
        for report in reports {
            let x = i128::from(ticks_between(newest.rtp, report.rtp));
            let y = i128::from(report.ntp).checked_sub(i128::from(newest.ntp))?;
            sx = sx.checked_add(x)?;
            sy = sy.checked_add(y)?;
            sxx = sxx.checked_add(x.checked_mul(x)?)?;
            sxy = sxy.checked_add(x.checked_mul(y)?)?;
        }
        let den = n.checked_mul(sxx)?.checked_sub(sx.checked_mul(sx)?)?;
        if den <= 0 {
            return None;
        }
        let num = n.checked_mul(sxy)?.checked_sub(sx.checked_mul(sy)?)?;
        // The intercept at x = 0: (Σy·den − num·Σx) / (n·den).
        let intercept = sy
            .checked_mul(den)?
            .checked_sub(num.checked_mul(sx)?)?
            .checked_div(n.checked_mul(den)?)?;
        let ntp_ref = i64::try_from(i128::from(newest.ntp).checked_add(intercept)?).ok()?;
        Some(Self {
            rtp_ref: newest.rtp,
            ntp_ref,
            num,
            den,
        })
    }

    /// Whether the slope is within [`MAX_RATE_PPM`] of `clock_rate` ticks
    /// per second.
    fn plausible(&self, clock_rate: u32) -> bool {
        // num / den ≈ 1e9 / rate  ⇔  |num·rate − 1e9·den| ≤ 1e9·den·ppm / 1e6
        let deviation = || {
            let nominal = NANOS_PER_SEC.checked_mul(self.den)?;
            let diff = self
                .num
                .checked_mul(i128::from(clock_rate))?
                .checked_sub(nominal)?;
            Some(diff.checked_mul(1_000_000)?.checked_abs()? <= nominal.checked_mul(MAX_RATE_PPM)?)
        };
        deviation().unwrap_or(false)
    }

    /// The NTP time of `rtp`.
    fn at(&self, rtp: u32) -> Option<i64> {
        let dx = i128::from(ticks_between(self.rtp_ref, rtp));
        let delta = dx.checked_mul(self.num)?.checked_div(self.den)?;
        i64::try_from(i128::from(self.ntp_ref).checked_add(delta)?).ok()
    }
}

/// What the mapper knows about one track.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrackClock {
    /// The last hint and when it arrived.
    last_hint: Option<(SyncHint, Instant)>,
    /// Hints seen so far.
    hints: u64,
    /// Sender Reports rejected as contradicting the fit.
    rejected: u64,
    /// Consecutive reports that contradicted the fit.
    contradictions: u32,
    /// The accepted Sender Reports in the window, oldest first.
    reports: Vec<Report>,
    /// The mapping, once a report was accepted; `None` maps by arrival.
    fit: Option<Fit>,
    /// The newest report's NTP time minus the mapping's for its RTP
    /// timestamp, in nanoseconds, after the report was applied (the whole
    /// residual for a rejected one): how far the mapping trails what the
    /// camera says now. `None` without a mapping.
    error: Option<i64>,
    /// Rate-limits the line of a rejected report: a camera sends reports
    /// at whatever rate it likes. Kept across re-anchors.
    rejections: Throttle,
    /// Rate-limits the line of a re-anchor, which a camera contradicting
    /// every report causes on every [`MAX_CONTRADICTIONS`]th.
    reanchors: Throttle,
    /// Rate-limits the line of the track's first accepted report, which
    /// each re-anchor makes again.
    syncs: Throttle,
}

/// The mapper's state, swapped as a whole so readers never lock.
#[derive(Debug, Clone, Default)]
struct State {
    /// Per-track knowledge.
    tracks: BTreeMap<TrackId, TrackClock>,
    /// The NTP timestamp and arrival of the connection's first accepted
    /// report: the zeros of its NTP and local nanoseconds.
    base: Option<(u64, Instant)>,
    /// Arrival minus NTP, in nanoseconds on those bases, of the reports in
    /// the window, all tracks together, oldest first.
    offsets: Vec<(Instant, i64)>,
    /// The offset in use, slewed toward the window's minimum.
    offset: Option<i64>,
    /// Judges the skew the mapping errors add up to; outlives re-anchors
    /// and epochs.
    watchdog: SkewWatchdog,
}

impl State {
    /// Nanoseconds from `base` to `ntp`, a 32.32 fixed-point NTP timestamp
    /// (RFC 3550 §4); signed, so an era wrap costs nothing. At most ±2³¹ s
    /// apart, which fits.
    fn ntp_nanos(base: u64, ntp: u64) -> i64 {
        let diff = i128::from(i64::from_ne_bytes(ntp.wrapping_sub(base).to_ne_bytes()));
        let nanos = diff
            .saturating_mul(NANOS_PER_SEC)
            .checked_shr(32)
            .unwrap_or(0);
        i64::try_from(nanos).unwrap_or(i64::MAX)
    }

    /// An accepted, contradicting or ignored Sender Report of `id`.
    fn sender_report(
        &mut self,
        id: TrackId,
        clock_rate: u32,
        ntp: u64,
        rtp: u32,
        arrival: Instant,
    ) {
        if clock_rate == 0 {
            tracing::debug!(track = %id, "sender report on a track without a clock rate; ignored");
            return;
        }
        let (base_ntp, base_arrival) = *self.base.get_or_insert((ntp, arrival));
        let ntp_ns = Self::ntp_nanos(base_ntp, ntp);
        let report = Report {
            rtp,
            ntp: ntp_ns,
            arrival,
        };
        let track = self.tracks.entry(id).or_default();
        if let Some(predicted) = track.fit.and_then(|fit| fit.at(rtp)) {
            let residual = Duration::from_nanos(ntp_ns.abs_diff(predicted));
            if residual > MAX_RESIDUAL {
                track.error = Some(ntp_ns.saturating_sub(predicted));
                track.rejected = track.rejected.saturating_add(1);
                track.contradictions = track.contradictions.saturating_add(1);
                if track.contradictions < MAX_CONTRADICTIONS {
                    if let Some(count) = track.rejections.hit(arrival) {
                        tracing::warn!(
                            track = %id,
                            residual_ms = residual.as_millis(),
                            count,
                            "sender report contradicts the clock fit; rejected"
                        );
                    }
                    return;
                }
                if let Some(count) = track.reanchors.hit(arrival) {
                    tracing::warn!(
                        track = %id,
                        residual_ms = residual.as_millis(),
                        reports = track.contradictions,
                        count,
                        "sender reports keep contradicting the clock fit; re-anchoring the connection"
                    );
                }
                self.reanchor();
                self.sender_report(id, clock_rate, ntp, rtp, arrival);
                return;
            }
        }
        track.contradictions = 0;
        track.reports.push(report);
        track
            .reports
            .retain(|r| arrival.saturating_duration_since(r.arrival) <= FIT_WINDOW);
        if track.reports.len() > FIT_POINTS {
            track.reports.remove(0);
        }
        let fitted = Fit::least_squares(&track.reports, report);
        let target = match fitted {
            Some(fit) if fit.plausible(clock_rate) => fit,
            Some(_) => {
                tracing::debug!(track = %id, clock_rate, "fitted clock rate implausible; the declared rate is used");
                Fit::nominal(report, clock_rate)
            }
            None => Fit::nominal(report, clock_rate),
        };
        let previous = track.fit.and_then(|fit| fit.at(rtp));
        if previous.is_none()
            && let Some(count) = track.syncs.hit(arrival)
        {
            tracing::info!(track = %id, count, "track synced from sender reports");
        }
        let ntp_ref = previous.map_or(target.ntp_ref, |from| slew(from, target.ntp_ref));
        track.fit = Some(Fit { ntp_ref, ..target });
        // Both fits are anchored at this report's timestamp.
        track.error = Some(ntp_ns.saturating_sub(ntp_ref));
        self.offset_report(base_arrival, report);
    }

    /// Adds `report` to the offset window and slews the offset toward the
    /// window's minimum.
    fn offset_report(&mut self, base_arrival: Instant, report: Report) {
        let since_base = report.arrival.saturating_duration_since(base_arrival);
        let local = i64::try_from(since_base.as_nanos()).unwrap_or(i64::MAX);
        let offset = local.saturating_sub(report.ntp);
        self.offsets.push((report.arrival, offset));
        self.offsets
            .retain(|(at, _)| report.arrival.saturating_duration_since(*at) <= FIT_WINDOW);
        if self.offsets.len() > OFFSET_POINTS {
            self.offsets.remove(0);
        }
        // The report just added is in the window, so there is a minimum.
        let target = self.offsets.iter().map(|(_, o)| *o).min().unwrap_or(offset);
        self.offset = Some(self.offset.map_or(target, |from| slew(from, target)));
    }

    /// Forgets every report and fit: the connection maps by arrival until
    /// the next reports.
    fn reanchor(&mut self) {
        for track in self.tracks.values_mut() {
            track.reports.clear();
            track.fit = None;
            track.error = None;
            track.contradictions = 0;
        }
        self.base = None;
        self.offsets.clear();
        self.offset = None;
    }

    /// How far audio leads video on the local base, in nanoseconds
    /// (negative: trails), from the tracks' mapping errors: audio and video
    /// captured at one camera instant land the difference of their errors
    /// apart, since every track adds the same offset. The pair furthest
    /// apart when there are more; `None` unless an audio and a video track
    /// both have a mapping.
    fn audio_lead(&self) -> Option<i64> {
        let errors = |kind: Kind| {
            self.tracks
                .iter()
                .filter(move |(id, _)| id.kind() == kind)
                .filter_map(|(_, clock)| clock.error)
        };
        errors(Kind::Audio)
            .flat_map(|audio| errors(Kind::Video).map(move |video| audio.saturating_sub(video)))
            .max_by_key(|lead| lead.unsigned_abs())
    }

    /// The capture time of `rtp` on `track` from its Sender Reports.
    fn capture_time(&self, track: TrackId, rtp: u32) -> Option<Instant> {
        let ntp = self.tracks.get(&track)?.fit?.at(rtp)?;
        let local = ntp.checked_add(self.offset?)?;
        let (_, base) = self.base?;
        let magnitude = Duration::from_nanos(local.unsigned_abs());
        if local >= 0 {
            base.checked_add(magnitude)
        } else {
            base.checked_sub(magnitude)
        }
    }
}

/// The per-connection clock mapper.
#[derive(Debug, Default)]
pub struct ClockMapper {
    /// The state.
    state: ArcSwap<State>,
    /// Serializes writers (the runner's hints, the source's resets), so
    /// none is lost; readers never take it.
    write: Mutex<()>,
}

impl ClockMapper {
    /// A mapper that has seen no hints.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a hint from the source; a Sender Report updates the track's
    /// fit and the connection's offset.
    pub fn ingest(&self, report: ClockReport) {
        let _writing = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = State::clone(&self.state.load());
        let track = state.tracks.entry(report.track).or_default();
        track.last_hint = Some((report.hint, report.arrival));
        track.hints = track.hints.saturating_add(1);
        // Per report, which a camera sends at any rate: `trace`.
        tracing::trace!(track = %report.track, hint = ?report.hint, "sync hint");
        match report.hint {
            SyncHint::RtcpSenderReport { ntp, rtp_ts } => {
                state.sender_report(report.track, report.clock_rate, ntp, rtp_ts, report.arrival);
                let lead = state.audio_lead();
                state.watchdog.observe(report.arrival, lead);
            }
            // MPEG-TS arrives with the HTTP and exec sources (M6).
            SyncHint::Pcr { .. } => {}
        }
        self.state.store(Arc::new(state));
    }

    /// Forgets every fit, for a new RTP timeline: a new connection or a
    /// timestamp discontinuity. Every track maps by arrival until its next
    /// Sender Report; the hint counters stay. It is the epoch boundary the
    /// skew watchdog's re-anchor waits for.
    pub fn reset(&self) {
        let _writing = self.write.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.state.load();
        // No base, no fit: nothing to forget, and no skew, so no re-anchor
        // waits either (an occurrence needs both tracks mapped).
        if current.base.is_none() {
            return;
        }
        let mut state = State::clone(&current);
        state.reanchor();
        state.watchdog.epoch_boundary();
        tracing::debug!("clock mapping reset for a new timeline");
        self.state.store(Arc::new(state));
    }

    /// The capture time of the item with `rtp_ts` that arrived at
    /// `arrival`: from the track's Sender Reports when it has them,
    /// otherwise the arrival itself, on the connection's shared base.
    pub fn map(&self, track: TrackId, rtp_ts: u32, arrival: Instant) -> Instant {
        self.state
            .load()
            .capture_time(track, rtp_ts)
            .unwrap_or(arrival)
    }

    /// How `track` is mapped now.
    pub fn mode(&self, track: TrackId) -> SyncMode {
        let synced = self
            .state
            .load()
            .tracks
            .get(&track)
            .is_some_and(|clock| clock.fit.is_some());
        if synced {
            SyncMode::SenderReports
        } else {
            SyncMode::Arrival
        }
    }

    /// Hints seen for `track`.
    pub fn hints_seen(&self, track: TrackId) -> u64 {
        self.state
            .load()
            .tracks
            .get(&track)
            .map_or(0, |clock| clock.hints)
    }

    /// Whether the skew watchdog withdrew audio: the stream's sessions stop
    /// writing it, for as long as this mapper's source runs.
    pub fn audio_withdrawn(&self) -> bool {
        self.state.load().watchdog.withdrawn()
    }

    /// Sender Reports of `track` rejected as contradicting its fit.
    pub fn hints_rejected(&self, track: TrackId) -> u64 {
        self.state
            .load()
            .tracks
            .get(&track)
            .map_or(0, |clock| clock.rejected)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use tracing::Level;

    use super::*;
    use crate::clock::{Clock as _, FakeClock, SystemClock};
    use crate::test_logs::Logs;

    const V0: TrackId = TrackId::new(Kind::Video, 0);
    const A0: TrackId = TrackId::new(Kind::Audio, 0);

    /// An NTP timestamp (32.32) `ms` milliseconds after an arbitrary start.
    fn ntp(ms: i64) -> u64 {
        let start: u64 = 3_900_000_000 << 32;
        let frac = (i128::from(ms) << 32) / 1_000;
        start.wrapping_add_signed(i64::try_from(frac).unwrap())
    }

    fn sr(
        track: TrackId,
        clock_rate: u32,
        ntp_ms: i64,
        rtp_ts: u32,
        arrival: Instant,
    ) -> ClockReport {
        ClockReport {
            track,
            clock_rate,
            hint: SyncHint::RtcpSenderReport {
                ntp: ntp(ntp_ms),
                rtp_ts,
            },
            arrival,
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The distance between two instants in microseconds, signed.
    fn micros(a: Instant, b: Instant) -> i128 {
        if a >= b {
            i128::try_from((a - b).as_micros()).unwrap()
        } else {
            -i128::try_from((b - a).as_micros()).unwrap()
        }
    }

    #[test]
    fn arrival_mode_maps_to_the_arrival_and_counts_hints() {
        let mapper = ClockMapper::new();
        let now = SystemClock.now();
        assert_eq!(mapper.map(V0, 90_000, now), now);
        assert_eq!(mapper.mode(V0), SyncMode::Arrival);
        assert_eq!(mapper.hints_seen(V0), 0);
        assert_eq!(mapper.hints_rejected(V0), 0);
        mapper.ingest(ClockReport {
            track: V0,
            clock_rate: 90_000,
            hint: SyncHint::Pcr { pcr: 27_000_000 },
            arrival: now,
        });
        assert_eq!(mapper.hints_seen(V0), 1);
        assert_eq!(mapper.hints_seen(A0), 0);
        assert_eq!(mapper.mode(V0), SyncMode::Arrival, "a PCR maps nothing yet");
        assert_eq!(mapper.map(V0, 1, now + ms(3)), now + ms(3));
        assert_eq!(SyncMode::SenderReports.name(), "sender_reports");
        assert_eq!(SyncMode::Arrival.name(), "arrival");
        assert!(format!("{mapper:?}").contains("hints: 1"));
    }

    #[test]
    fn rfc3550_6_4_1_one_sender_report_maps_at_the_declared_rate() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now() + Duration::from_secs(10);
        mapper.ingest(sr(V0, 90_000, 0, 1_000, t0));
        assert_eq!(mapper.mode(V0), SyncMode::SenderReports);
        assert_eq!(mapper.hints_seen(V0), 1);
        // The report's own instant maps to its arrival (the offset's zero),
        // later and earlier timestamps at 90 kHz, whatever their arrival.
        let late = t0 + Duration::from_secs(9);
        assert_eq!(mapper.map(V0, 1_000, late), t0);
        assert_eq!(
            mapper.map(V0, 1_000 + 90_000, late),
            t0 + Duration::from_secs(1)
        );
        assert_eq!(
            mapper.map(V0, 1_000_u32.wrapping_sub(45_000), late),
            t0.checked_sub(ms(500)).unwrap()
        );
        // Another track without reports still maps by arrival.
        assert_eq!(mapper.map(A0, 1_000, late), late);
        assert_eq!(mapper.mode(A0), SyncMode::Arrival);
    }

    #[test]
    fn rfc3550_5_1_timestamps_wrap_across_the_mapping() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.ingest(sr(V0, 90_000, 0, u32::MAX - 44_999, t0));
        assert_eq!(mapper.map(V0, 45_000, t0), t0 + Duration::from_secs(1));
    }

    #[test]
    fn audio_and_video_of_one_instant_map_to_one_capture_time() {
        // The camera's clock decides sync: the audio report arrives 30 ms
        // later than the video one would have, but the offset is shared.
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.ingest(sr(V0, 90_000, 0, 0, t0));
        mapper.ingest(sr(A0, 8_000, 1_000, 8_000, t0 + ms(1_030)));
        let video = mapper.map(V0, 90_000 * 2, t0);
        let audio = mapper.map(A0, 8_000 * 2, t0);
        assert_eq!(video, audio);
        assert_eq!(video, t0 + Duration::from_secs(2));
    }

    #[test]
    fn the_regression_follows_a_camera_clock_off_its_declared_rate() {
        // A 90 kHz clock running 400 ppm fast; a report every 5 s.
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        let rate = 90_036_u32;
        for i in 0..6_u32 {
            let at = u64::from(i) * 5_000;
            mapper.ingest(sr(
                V0,
                90_000,
                i64::from(i) * 5_000,
                i * 5 * rate,
                t0 + ms(at),
            ));
        }
        // 2 s past the last report: the declared rate would be 0.8 ms off.
        let rtp = 25 * rate + 2 * rate;
        let truth = t0 + Duration::from_secs(27);
        let error = micros(mapper.map(V0, rtp, truth), truth);
        assert!(error.abs() <= 20, "error {error} µs");
        let state = mapper.state.load();
        assert_eq!(state.tracks[&V0].reports.len(), 6);
    }

    #[test]
    fn rfc3550_6_4_1_sweep_mapping_error_and_av_offset_stay_bounded() {
        // Every combination of camera clock error, report interval, where
        // the RTP clock wraps and reports delayed by jitter: once the
        // offset has converged, both tracks map within 100 µs of the true
        // capture time, and so within 200 µs of each other.
        let jitter_ms = [7, 0, 13, 4, 19, 0, 2, 11, 5, 0];
        for ppm in [-900_i64, -300, 0, 250, 800] {
            for interval_ms in [1_000_i64, 5_000] {
                for start in [0_u32, u32::MAX - 100_000, 1 << 31] {
                    let mapper = ClockMapper::new();
                    let t0 = SystemClock.now();
                    let rtp = |rate: i64, t_ms: i64| {
                        let ticks = t_ms * rate * (1_000_000 + ppm) / 1_000_000_000;
                        start.wrapping_add(u32::try_from(ticks).unwrap())
                    };
                    let at = |t_ms: i64| t0 + ms(u64::try_from(t_ms).unwrap());
                    for (i, jitter) in jitter_ms.iter().enumerate() {
                        let t = i64::try_from(i).unwrap() * interval_ms;
                        let arrival = at(t) + ms(*jitter);
                        mapper.ingest(sr(V0, 90_000, t, rtp(90_000, t), arrival));
                        mapper.ingest(sr(A0, 48_000, t, rtp(48_000, t), arrival + ms(3)));
                    }
                    let t = 10 * interval_ms + 1_234;
                    let video = mapper.map(V0, rtp(90_000, t), t0);
                    let audio = mapper.map(A0, rtp(48_000, t), t0);
                    let case = format!("{ppm} ppm, every {interval_ms} ms, from {start}");
                    assert!(micros(video, at(t)).abs() <= 100, "video {case}");
                    assert!(micros(audio, at(t)).abs() <= 100, "audio {case}");
                    assert_eq!(
                        mapper.hints_rejected(V0) + mapper.hints_rejected(A0),
                        0,
                        "{case}"
                    );
                }
            }
        }
    }

    #[test]
    fn one_bad_report_moves_the_mapping_by_the_slew_limit_only() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.ingest(sr(V0, 90_000, 0, 0, t0));
        mapper.ingest(sr(V0, 90_000, 5_000, 450_000, t0 + ms(5_000)));
        let before = mapper.map(V0, 900_000, t0);
        // 50 ms off: within the residual bound, so accepted, but slewed.
        // Its arrival agrees with it, so the offset stays.
        mapper.ingest(sr(V0, 90_000, 10_050, 900_000, t0 + ms(10_050)));
        let after = mapper.map(V0, 900_000, t0);
        assert_eq!(micros(after, before), 5_000);
        assert_eq!(mapper.hints_rejected(V0), 0);
    }

    #[test]
    fn the_offset_is_the_smallest_transit_and_moves_by_the_slew_limit() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        // The first report was delayed by 20 ms on the way.
        mapper.ingest(sr(V0, 90_000, 0, 0, t0 + ms(20)));
        assert_eq!(mapper.map(V0, 0, t0), t0 + ms(20));
        mapper.ingest(sr(V0, 90_000, 1_000, 90_000, t0 + ms(1_000)));
        assert_eq!(
            mapper.map(V0, 0, t0),
            t0 + ms(15),
            "5 ms toward the better transit"
        );
        mapper.ingest(sr(V0, 90_000, 2_000, 180_000, t0 + ms(2_000)));
        mapper.ingest(sr(V0, 90_000, 3_000, 270_000, t0 + ms(3_000)));
        mapper.ingest(sr(V0, 90_000, 4_000, 360_000, t0 + ms(4_000)));
        assert_eq!(mapper.map(V0, 0, t0), t0, "converged, and no further");
        // Reports older than the window leave it.
        mapper.ingest(sr(V0, 90_000, 40_000, 3_600_000, t0 + ms(40_000)));
        let state = mapper.state.load();
        assert_eq!(state.offsets.len(), 1);
        assert_eq!(state.tracks[&V0].reports.len(), 1);
    }

    #[test]
    fn the_windows_keep_a_bounded_number_of_reports() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        for i in 0..40_u32 {
            let at = t0 + ms(u64::from(i) * 100);
            mapper.ingest(sr(V0, 90_000, i64::from(i) * 100, i * 9_000, at));
            mapper.ingest(sr(A0, 8_000, i64::from(i) * 100, i * 800, at));
        }
        let state = mapper.state.load();
        assert_eq!(state.tracks[&V0].reports.len(), FIT_POINTS);
        assert_eq!(state.tracks[&A0].reports.len(), FIT_POINTS);
        assert_eq!(state.offsets.len(), OFFSET_POINTS);
        assert_eq!(
            state.tracks[&V0].reports[0].rtp,
            8 * 9_000,
            "oldest dropped"
        );
    }

    #[test]
    fn a_lying_report_is_rejected_and_repeated_contradiction_reanchors() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.ingest(sr(V0, 90_000, 0, 0, t0));
        mapper.ingest(sr(A0, 8_000, 0, 0, t0));
        let before = mapper.map(V0, 90_000, t0);
        // The camera's NTP clock steps by an hour.
        let step = 3_600_000;
        mapper.ingest(sr(V0, 90_000, step + 1_000, 90_000, t0 + ms(1_000)));
        mapper.ingest(sr(V0, 90_000, step + 2_000, 180_000, t0 + ms(2_000)));
        assert_eq!(mapper.hints_rejected(V0), 2);
        assert_eq!(
            mapper.map(V0, 90_000, t0),
            before,
            "rejected reports change nothing"
        );
        assert_eq!(mapper.mode(V0), SyncMode::SenderReports);
        // The third re-anchors every track of the connection on it.
        let arrival = t0 + ms(3_000);
        mapper.ingest(sr(V0, 90_000, step + 3_000, 270_000, arrival));
        assert_eq!(mapper.hints_rejected(V0), 3);
        assert_eq!(mapper.map(V0, 270_000, t0), arrival);
        assert_eq!(
            mapper.mode(A0),
            SyncMode::Arrival,
            "audio waits for its next report"
        );
        assert_eq!(mapper.map(A0, 8_000, t0 + ms(7)), t0 + ms(7));
        // An honest report after that resets the count.
        mapper.ingest(sr(V0, 90_000, step + 4_000, 360_000, t0 + ms(4_000)));
        assert_eq!(mapper.state.load().tracks[&V0].contradictions, 0);
    }

    #[test]
    fn rfc3550_6_4_1_a_camera_contradicting_every_report_logs_each_line_once_per_interval() {
        let (logs, _guard) = Logs::capture();
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        // Thirty reports in under a second, each an hour after the last by
        // its NTP time: two in three rejected, every third re-anchoring the
        // connection and syncing the track again; then two more over an
        // interval later.
        for i in 0..32_u32 {
            let arrival = if i < 30 {
                t0 + ms(u64::from(i) * 30)
            } else {
                t0 + crate::throttle::SUMMARY_INTERVAL + ms(1_000 + u64::from(i - 30) * 30)
            };
            mapper.ingest(sr(V0, 90_000, i64::from(i) * 3_600_000, i * 90, arrival));
        }
        assert_eq!(mapper.hints_rejected(V0), 31);
        let counts = |level, message| -> Vec<String> {
            logs.lines(level, message)
                .into_iter()
                .map(|line| line.fields.rsplit(' ').next().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            counts(
                Level::WARN,
                "sender report contradicts the clock fit; rejected"
            ),
            ["count=1", "count=20"]
        );
        assert_eq!(
            counts(
                Level::WARN,
                "sender reports keep contradicting the clock fit; re-anchoring the connection"
            ),
            ["count=1", "count=9"]
        );
        assert_eq!(
            counts(Level::INFO, "track synced from sender reports"),
            ["count=1", "count=10"]
        );
        assert_eq!(
            logs.count(Level::TRACE, "sync hint"),
            32,
            "per report: trace"
        );
    }

    #[test]
    fn a_report_at_the_residual_bound_is_accepted() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.ingest(sr(V0, 90_000, 0, 0, t0));
        // Exactly 100 ms off the 1025 ms the fit predicts; multiples of
        // 125 ms are exact in 32.32 NTP fixed point.
        mapper.ingest(sr(V0, 90_000, 1_125, 92_250, t0 + ms(1_125)));
        assert_eq!(
            State::ntp_nanos(ntp(0), ntp(1_125)) - 1_025_000_000,
            i64::try_from(MAX_RESIDUAL.as_nanos()).unwrap()
        );
        assert_eq!(mapper.hints_rejected(V0), 0);
        assert_eq!(mapper.state.load().tracks[&V0].reports.len(), 2);
    }

    #[test]
    fn an_implausible_fitted_rate_falls_back_to_the_declared_rate() {
        // 9000 ticks in 50 ms is 180 kHz: within the residual bound, but no
        // 90 kHz camera runs at twice its rate.
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.ingest(sr(V0, 90_000, 0, 0, t0));
        mapper.ingest(sr(V0, 90_000, 50, 9_000, t0 + ms(50)));
        let a = mapper.map(V0, 9_000, t0);
        let b = mapper.map(V0, 99_000, t0);
        assert_eq!(b - a, Duration::from_secs(1), "the declared 90 kHz");
    }

    #[test]
    fn a_reset_maps_by_arrival_until_the_next_report() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.reset();
        assert!(mapper.state.load().base.is_none(), "nothing to forget");
        mapper.ingest(sr(V0, 90_000, 0, 0, t0));
        mapper.ingest(sr(A0, 8_000, 0, 0, t0));
        mapper.reset();
        assert_eq!(mapper.mode(V0), SyncMode::Arrival);
        assert_eq!(mapper.mode(A0), SyncMode::Arrival);
        assert_eq!(mapper.map(V0, 90_000, t0 + ms(5)), t0 + ms(5));
        assert_eq!(mapper.hints_seen(V0), 1, "the counters stay");
        // The new timeline's first report anchors afresh, whatever the old
        // fit would have predicted.
        mapper.ingest(sr(V0, 90_000, 60_000, 7_777, t0 + ms(100)));
        assert_eq!(mapper.hints_rejected(V0), 0);
        assert_eq!(mapper.map(V0, 7_777, t0), t0 + ms(100));
    }

    #[test]
    fn a_track_without_a_clock_rate_is_not_mapped() {
        let mapper = ClockMapper::new();
        let t0 = SystemClock.now();
        mapper.ingest(sr(V0, 0, 0, 0, t0));
        assert_eq!(mapper.mode(V0), SyncMode::Arrival);
        assert_eq!(mapper.hints_seen(V0), 1);
        assert!(mapper.state.load().base.is_none());
    }

    #[test]
    fn fits_and_slopes_follow_exact_arithmetic() {
        let t0 = SystemClock.now();
        let report = |rtp, ntp| Report {
            rtp,
            ntp,
            arrival: t0,
        };
        // One point, or points on one timestamp, have no slope.
        assert!(Fit::least_squares(&[report(0, 0)], report(0, 0)).is_none());
        assert!(Fit::least_squares(&[report(5, 0), report(5, 1)], report(5, 1)).is_none());
        // An exact line: 1 ms per 90 ticks, anchored at the newest.
        let points = [report(0, 0), report(90, 1_000_000), report(180, 2_000_000)];
        let fit = Fit::least_squares(&points, points[2]).unwrap();
        assert_eq!((fit.rtp_ref, fit.ntp_ref), (180, 2_000_000));
        assert_eq!(fit.at(270), Some(3_000_000));
        assert_eq!(fit.at(0), Some(0));
        assert!(fit.plausible(90_000));
        assert!(!fit.plausible(45_000));
        assert!(!fit.plausible(0));
        // 1 % off is the edge of belief.
        let edge = Fit {
            num: 101 * NANOS_PER_SEC,
            den: 100 * 90_000,
            ..fit
        };
        assert!(edge.plausible(90_000));
        let beyond = Fit {
            num: 10_101 * NANOS_PER_SEC,
            den: 10_000 * 90_000,
            ..fit
        };
        assert!(!beyond.plausible(90_000));
        let backwards = Fit {
            num: -NANOS_PER_SEC,
            ..fit
        };
        assert!(!backwards.plausible(90_000));
        // Overflow is no mapping, never a panic.
        let huge = Fit {
            num: i128::MAX,
            ..fit
        };
        assert_eq!(huge.at(181), None);
        assert!(!huge.plausible(90_000));
        let far = Fit {
            ntp_ref: i64::MAX,
            num: 1,
            den: 1,
            ..fit
        };
        assert_eq!(far.at(181), None);
        // A line whose intercept lies beyond the NTP range.
        let overflowing = [
            report(0, i64::MAX),
            report(1, i64::MAX),
            report(2, i64::MIN),
        ];
        assert!(Fit::least_squares(&overflowing, overflowing[0]).is_none());
        assert_eq!(slew(0, i64::MAX), 5_000_000);
        assert_eq!(slew(0, -3), -3);
        assert_eq!(State::ntp_nanos(ntp(0), ntp(1_500)), 1_500_000_000);
        assert_eq!(State::ntp_nanos(ntp(1_500), ntp(0)), -1_500_000_000);
        // Half the NTP range either way, the most a signed difference holds.
        assert_eq!(State::ntp_nanos(0, 1 << 63), -(1 << 31) * 1_000_000_000);
        assert_eq!(ticks_between(u32::MAX, 1), 2);
        assert_eq!(ticks_between(1, u32::MAX), -2);
    }

    // The skew watchdog on the mapper's own measurement.

    /// A camera's Sender Reports for `rounds` rounds of 250 ms from `t0`:
    /// audio's (8 kHz) at the start of each round, video's (90 kHz) 150 ms
    /// later, each arriving on time. Video claims the truth; audio claims
    /// `extra(k)` ms more in round `k`.
    fn camera(mapper: &ClockMapper, t0: Instant, rounds: u32, extra: impl Fn(u32) -> i64) {
        for k in 0..rounds {
            let at = u64::from(k) * 250;
            let truth = i64::from(k) * 250;
            mapper.ingest(sr(A0, 8_000, truth + extra(k), k * 2_000, t0 + ms(at)));
            mapper.ingest(sr(
                V0,
                90_000,
                truth + 150,
                (k * 250 + 150) * 90,
                t0 + ms(at + 150),
            ));
        }
    }

    /// Audio claims that keep its mapping error at `drift_ms` from round 1
    /// until round `recover` (never, if `None`), then at zero. They run
    /// 5 ms a round ahead of the truth, 2 %: an implausible rate, so the
    /// mapping follows each report at the declared rate, by the 5 ms slew
    /// limit, and trails the camera by exactly the step it took in round 1.
    fn drift(drift_ms: i64, recover: Option<u32>) -> impl Fn(u32) -> i64 {
        move |k| {
            let drifting = k >= 1 && recover.is_none_or(|recover| k < recover);
            i64::from(k) * 5 + if drifting { drift_ms } else { 0 }
        }
    }

    fn error_ms(mapper: &ClockMapper, track: TrackId) -> f64 {
        let nanos = mapper.state.load().tracks[&track].error.unwrap();
        #[expect(clippy::cast_precision_loss, reason = "a test's readable unit")]
        let millis = nanos as f64 / 1e6;
        millis
    }

    #[test]
    fn skew_watchdog_sr_drift_of_39_ms_sustained_for_a_minute_is_tolerated() {
        let mapper = ClockMapper::new();
        camera(&mapper, FakeClock::default().now(), 240, drift(39, None));
        assert!((error_ms(&mapper, A0) - 39.0).abs() < 0.001);
        assert!(error_ms(&mapper, V0).abs() < 0.001);
        assert_eq!(mapper.state.load().watchdog, SkewWatchdog::default());
    }

    #[test]
    fn skew_watchdog_sr_drift_of_41_ms_sustained_5_s_marks_a_re_anchor() {
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        // Round 21's audio report is 5 s after round 1's.
        camera(&mapper, t0, 21, drift(41, None));
        assert_eq!(mapper.state.load().watchdog.occurrences(), 0);
        mapper.ingest(sr(A0, 8_000, 21 * 255 + 41, 21 * 2_000, t0 + ms(5_250)));
        let state = mapper.state.load();
        assert_eq!(state.watchdog.occurrences(), 1);
        assert!(state.watchdog.reanchor_pending());
        assert!(!mapper.audio_withdrawn());
        // The mapping puts audio 41 ms before the camera's claim: it leads.
        let lead = state.audio_lead().unwrap();
        assert!((lead - 41_000_000).abs() < 1_000, "{lead}");
        // It never jumps inside an epoch: the mapping still trails by 41 ms.
        assert!((error_ms(&mapper, A0) - 41.0).abs() < 0.001);
        assert_eq!(mapper.mode(A0), SyncMode::SenderReports);
    }

    #[test]
    fn skew_watchdog_sr_drift_of_41_ms_for_4_9_s_is_tolerated() {
        // The last report that still sees it is video's of round 20, 4.9 s
        // after round 1's audio; round 21's audio is back on its mapping.
        let mapper = ClockMapper::new();
        camera(&mapper, FakeClock::default().now(), 40, drift(41, Some(21)));
        assert!(error_ms(&mapper, A0).abs() < 0.001);
        assert_eq!(mapper.state.load().watchdog, SkewWatchdog::default());
    }

    #[test]
    fn skew_watchdog_ignores_arrival_jitter_with_consistent_sender_reports() {
        // Ten minutes of a camera 300 ppm fast, one report a second per
        // track, each delayed by up to 480 ms, audio's by 250 ms more in
        // odd minutes: the offset moves, the mapping errors do not.
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        let rtp = |rate: u64, t_ms: u64| {
            u32::try_from(t_ms * rate * 1_000_300 / 1_000_000_000 % (1 << 32)).unwrap()
        };
        let mut seed = 0x2545_f491_u64;
        let mut jitter = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ms(seed % 481)
        };
        for second in 0..600_u64 {
            let t = second * 1_000;
            let audio_late = if (second / 60) % 2 == 1 {
                ms(250)
            } else {
                ms(0)
            };
            let truth = i64::try_from(t).unwrap();
            mapper.ingest(sr(V0, 90_000, truth, rtp(90_000, t), t0 + ms(t) + jitter()));
            mapper.ingest(sr(
                A0,
                16_000,
                truth + 500,
                rtp(16_000, t + 500),
                t0 + ms(t + 500) + jitter() + audio_late,
            ));
            assert_eq!(
                mapper.state.load().watchdog,
                SkewWatchdog::default(),
                "second {second}"
            );
        }
        // What is left is the rounding of the RTP timestamps to ticks.
        assert!(error_ms(&mapper, A0).abs() < 0.1);
        assert!(error_ms(&mapper, V0).abs() < 0.1);
        assert_eq!(mapper.hints_rejected(A0) + mapper.hints_rejected(V0), 0);
    }

    #[test]
    fn skew_watchdog_contradictory_sender_reports_of_one_track_mark_a_re_anchor() {
        // A report every 5 s per track; from 20 s on, audio's claim 150 ms
        // more than its fit allows while video's still agree.
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        for k in 0..6_u32 {
            let t = i64::from(k) * 5_000;
            let at = t0 + ms(u64::from(k) * 5_000);
            let audio = if k >= 4 { t + 150 } else { t };
            mapper.ingest(sr(A0, 8_000, audio, k * 40_000, at));
            mapper.ingest(sr(
                V0,
                90_000,
                t + 2_500,
                (k * 5_000 + 2_500) * 90,
                at + ms(2_500),
            ));
        }
        assert_eq!(mapper.hints_rejected(A0), 2);
        assert!((error_ms(&mapper, A0) - 150.0).abs() < 0.001);
        let state = mapper.state.load();
        assert_eq!(state.watchdog.occurrences(), 1, "the second, 5 s on");
        assert!(state.watchdog.reanchor_pending());
    }

    #[test]
    fn skew_watchdog_an_ntp_step_on_every_track_is_no_skew() {
        // The camera's one NTP clock steps by 150 ms: audio's report says
        // so first, video's 2.5 s later, and the two agree again.
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        for k in 0..8_u32 {
            let t = i64::from(k) * 5_000;
            let step = if k >= 4 { 150 } else { 0 };
            let at = t0 + ms(u64::from(k) * 5_000);
            mapper.ingest(sr(A0, 8_000, t + step, k * 40_000, at));
            mapper.ingest(sr(
                V0,
                90_000,
                t + 2_500 + step,
                (k * 5_000 + 2_500) * 90,
                at + ms(2_500),
            ));
        }
        assert_eq!(mapper.state.load().watchdog, SkewWatchdog::default());
        assert!(
            mapper.hints_rejected(A0) >= 3,
            "the mapper re-anchored on the step"
        );
    }

    #[test]
    fn skew_watchdog_re_anchor_waits_for_the_epoch_boundary() {
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        camera(&mapper, t0, 30, drift(60, None));
        assert!(mapper.state.load().watchdog.reanchor_pending());
        // More reports in the epoch move the mapping by the slew limit
        // only; the camera's claim keeps 60 ms ahead of it.
        assert!((error_ms(&mapper, A0) - 60.0).abs() < 0.001);
        // The boundary applies it: the new timeline maps afresh.
        mapper.reset();
        let state = mapper.state.load();
        assert!(!state.watchdog.reanchor_pending());
        assert_eq!(state.watchdog.occurrences(), 1);
        assert_eq!(mapper.mode(A0), SyncMode::Arrival);
        assert!(state.tracks[&A0].error.is_none());
        camera(&mapper, t0 + Duration::from_mins(1), 4, drift(0, None));
        assert!(error_ms(&mapper, A0).abs() < 0.001);
    }

    /// One occurrence on a new timeline from `at`: 60 ms of drift for the
    /// 5 s it takes, then the timeline ends (a camera reboot).
    fn episode(mapper: &ClockMapper, at: Instant) {
        camera(mapper, at, 22, drift(60, None));
        mapper.reset();
    }

    #[test]
    fn skew_watchdog_three_occurrences_within_10_minutes_withdraw_audio() {
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        episode(&mapper, t0);
        episode(&mapper, t0 + Duration::from_mins(4));
        assert!(!mapper.audio_withdrawn());
        episode(&mapper, t0 + Duration::from_mins(9));
        assert!(mapper.audio_withdrawn());
        assert_eq!(mapper.state.load().watchdog.occurrences(), 3);
    }

    #[test]
    fn skew_watchdog_three_occurrences_spread_over_11_minutes_keep_audio() {
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        for minute in [0, 5, 11] {
            episode(&mapper, t0 + Duration::from_secs(minute * 60 + 30));
        }
        assert!(!mapper.audio_withdrawn());
        assert_eq!(mapper.state.load().watchdog.occurrences(), 2);
    }

    #[test]
    fn skew_watchdog_a_camera_whose_audio_clock_runs_2_percent_fast_loses_audio() {
        // Audio's reports claim 1020 ms for every second of its 8 kHz
        // clock: the mapping falls behind, its reports are rejected, the
        // mapper re-anchors on them, and it starts over. Each round of
        // that is an occurrence; the third, within a minute, withdraws.
        let mapper = ClockMapper::new();
        let t0 = FakeClock::default().now();
        let mut withdrawn_at = None;
        for k in 0..60_u32 {
            let t = i64::from(k) * 1_000;
            let at = t0 + ms(u64::from(k) * 1_000);
            mapper.ingest(sr(V0, 90_000, t, k * 90_000, at));
            mapper.ingest(sr(A0, 8_000, t * 102 / 100, k * 8_000, at));
            if withdrawn_at.is_none() && mapper.audio_withdrawn() {
                withdrawn_at = Some(k);
            }
        }
        let withdrawn_at = withdrawn_at.expect("audio withdrawn");
        assert!((20..40).contains(&withdrawn_at), "after {withdrawn_at} s");
    }
}

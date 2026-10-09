//! RTCP Receiver Reports to the camera, one RTP session per stream
//! (RFC 3550 §6.4.2), from statistics the relay keeps on what the camera
//! sends.
//!
//! retina 0.4.20 sends no RTCP at all (its own documentation of
//! `Transport::Udp` says so), while RFC 3550 §6 says the reception
//! feedback "SHOULD be used in all environments". retina speaks plain RTSP
//! to the loopback relay,
//! which owns the camera's side and sees every RTP and RTCP packet first,
//! so the relay reports: over TCP on the stream's RTCP channel between
//! whole requests (RFC 2326 §10.12), over UDP from the stream's RTCP port
//! to the camera's (RFC 3550 §11).
//!
//! Per stream this keeps, sans I/O and with every time passed in:
//!
//! - the sequence state of RFC 3550 §A.1 (`MAX_DROPOUT`, `MAX_MISORDER`,
//!   `MIN_SEQUENTIAL` probation), and from it the extended highest
//!   sequence number, the cumulative loss and the fraction lost of §A.3;
//! - the interarrival jitter of §A.8, in RTP timestamp units of the
//!   stream's clock rate, which the source hands over in `SETUP` order
//!   ([`SetupRates`]);
//! - the middle 32 bits of the NTP timestamp of the camera's last Sender
//!   Report on the stream's RTCP channel and when it arrived, for LSR and
//!   DLSR (§6.4.1).
//!
//! Each report is a compound packet (§6.1): an RR with one report block
//! (§6.4.2), or none when no RTP arrived since the last report (§6.4: an
//! empty RR still heads the packet), then an SDES with our CNAME
//! (§6.5.1). Our SSRC (§8.1) and CNAME (RFC 7022 §4.2, 96 bits) are
//! random per attempt, and so is the interval (§6.2, §6.3.1, §A.7): the
//! deterministic interval is the 5 s minimum, 2.5 s for the first report
//! after the stream's first packet, drawn from [0.5, 1.5) times it and
//! divided by e − 3/2. The bandwidth term would exceed the minimum only
//! below about 6.4 kbit/s of session bandwidth (two members, one sender,
//! a ~100-byte average RTCP packet, 5 % of the bandwidth), which no
//! camera stream lotse takes comes near, and cameras seldom announce a
//! bandwidth (`b=AS`) to compute it from.

use std::collections::VecDeque;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// RFC 3550 §A.1 `MAX_DROPOUT`: a jump ahead of at most this many is
/// taken as loss.
const MAX_DROPOUT: u16 = 3000;

/// RFC 3550 §A.1 `MAX_MISORDER`: a packet at most this many behind the
/// highest is reordered or a duplicate.
const MAX_MISORDER: u16 = 100;

/// RFC 3550 §A.1 `MIN_SEQUENTIAL`: sequential packets a new source needs
/// before it counts.
const MIN_SEQUENTIAL: u8 = 2;

/// RFC 3550 §A.1 `RTP_SEQ_MOD`.
const RTP_SEQ_MOD: u32 = 1 << 16;

/// RFC 3550 §6.2: the minimum report interval, 5 s.
const MIN_INTERVAL: Duration = Duration::from_secs(5);

/// RFC 3550 §6.2: the minimum halved for the first report.
const FIRST_MIN_INTERVAL: Duration = Duration::from_millis(2500);

/// RFC 3550 §6.3.1: e − 3/2, in millionths, which the randomized interval
/// is divided by.
const COMPENSATION_MILLIONTHS: u128 = 1_218_282;

/// RFC 3550 §6.4.1: packet type SR.
const PT_SR: u8 = 200;

/// RFC 3550 §6.4.2: packet type RR.
const PT_RR: u8 = 201;

/// RFC 3550 §6.5: packet type SDES.
const PT_SDES: u8 = 202;

/// RFC 3550 §6.5.1: the CNAME item.
const SDES_CNAME: u8 = 1;

/// The first bytes of an interleaved frame or datagram the statistics
/// read: an RTP header's sequence number, timestamp and SSRC (12 bytes,
/// §5.1), an SR's NTP timestamp (bytes 8 to 15, §6.4.1).
pub(crate) const HEAD: usize = 16;

/// The clock rates of the streams the source sets up, in the order of its
/// `SETUP` requests: the relay takes the next one at each successful
/// `SETUP` answer, which retina waits for before it asks for the next
/// stream. Shared between the source, which pushes before it asks, and
/// the relay.
#[derive(Debug, Default)]
pub(crate) struct SetupRates(Mutex<VecDeque<u32>>);

impl SetupRates {
    /// The clock rate of the stream about to be set up.
    pub(crate) fn push(&self, rate: u32) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(rate);
    }

    /// The clock rate of the stream whose `SETUP` was answered.
    fn pop(&self) -> Option<u32> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }
}

/// The sequence state of one source, RFC 3550 §A.1's `source` structure.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sequence {
    /// The highest sequence number seen.
    max_seq: u16,
    /// Sequence number cycles, shifted (a multiple of `RTP_SEQ_MOD`).
    cycles: u32,
    /// The first sequence number counted.
    base_seq: u32,
    /// The last "bad" sequence number plus one.
    bad_seq: u32,
    /// Sequential packets still needed before the source counts.
    probation: u8,
    /// Packets received.
    received: u32,
    /// `expected` at the last report.
    expected_prior: u32,
    /// `received` at the last report.
    received_prior: u32,
}

impl Sequence {
    /// A new source at its first packet `seq`, on probation (§A.1).
    fn new(seq: u16) -> Self {
        let mut sequence = Self {
            max_seq: 0,
            cycles: 0,
            base_seq: 0,
            bad_seq: 0,
            probation: MIN_SEQUENTIAL,
            received: 0,
            expected_prior: 0,
            received_prior: 0,
        };
        sequence.init(seq);
        sequence.max_seq = seq.wrapping_sub(1);
        sequence
    }

    /// §A.1 `init_seq`.
    fn init(&mut self, seq: u16) {
        self.base_seq = u32::from(seq);
        self.max_seq = seq;
        self.bad_seq = RTP_SEQ_MOD.wrapping_add(1);
        self.cycles = 0;
        self.received = 0;
        self.received_prior = 0;
        self.expected_prior = 0;
    }

    /// §A.1 `update_seq`: whether the packet counts.
    fn update(&mut self, seq: u16) -> bool {
        let udelta = seq.wrapping_sub(self.max_seq);
        if self.probation > 0 {
            if seq == self.max_seq.wrapping_add(1) {
                self.probation = self.probation.saturating_sub(1);
                self.max_seq = seq;
                if self.probation == 0 {
                    self.init(seq);
                    self.received = self.received.wrapping_add(1);
                    return true;
                }
            } else {
                self.probation = MIN_SEQUENTIAL.saturating_sub(1);
                self.max_seq = seq;
            }
            return false;
        }
        if udelta < MAX_DROPOUT {
            // In order, with a permissible gap.
            if seq < self.max_seq {
                self.cycles = self.cycles.wrapping_add(RTP_SEQ_MOD);
            }
            self.max_seq = seq;
        } else if u32::from(udelta) <= RTP_SEQ_MOD.saturating_sub(u32::from(MAX_MISORDER)) {
            // A very large jump: two sequential packets mean the sender
            // restarted without telling.
            if u32::from(seq) == self.bad_seq {
                self.init(seq);
            } else {
                self.bad_seq = u32::from(seq.wrapping_add(1));
                return false;
            }
        }
        // Else a duplicate or reordered packet, counted as received.
        self.received = self.received.wrapping_add(1);
        true
    }

    /// §A.3: the fraction lost since the last report, the cumulative loss
    /// clamped to 24 signed bits, and the extended highest sequence
    /// number; the interval starts over.
    fn block(&mut self) -> (u8, i32, u32) {
        let extended_max = self.cycles.wrapping_add(u32::from(self.max_seq));
        let expected = extended_max.wrapping_sub(self.base_seq).wrapping_add(1);
        let lost = i64::from(expected)
            .saturating_sub(i64::from(self.received))
            .clamp(-0x80_0000, 0x7f_ffff);
        let expected_interval = expected.wrapping_sub(self.expected_prior);
        self.expected_prior = expected;
        let received_interval = self.received.wrapping_sub(self.received_prior);
        self.received_prior = self.received;
        let lost_interval =
            i64::from(expected_interval).saturating_sub(i64::from(received_interval));
        let fraction = if lost_interval <= 0 {
            0
        } else {
            lost_interval
                .saturating_mul(256)
                .checked_div(i64::from(expected_interval))
                .and_then(|fraction| u8::try_from(fraction).ok())
                .unwrap_or(u8::MAX)
        };
        (
            fraction,
            i32::try_from(lost).unwrap_or_default(),
            extended_max,
        )
    }
}

/// `elapsed` in ticks of a `rate` Hz clock, modulo 2^32 as RTP timestamps
/// are.
fn ticks(elapsed: Duration, rate: u32) -> u32 {
    let ticks = elapsed
        .as_nanos()
        .saturating_mul(u128::from(rate))
        .checked_div(1_000_000_000)
        .unwrap_or_default();
    u32::try_from(ticks & u128::from(u32::MAX)).unwrap_or_default()
}

/// The interarrival jitter of one source (RFC 3550 §6.4.1, §A.8), in
/// timestamp units of the stream's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Jitter {
    /// The arrival the arrival times count from.
    epoch: Instant,
    /// The last packet's relative transit time.
    transit: Option<u32>,
    /// The jitter estimate times 16, as §A.8 keeps it in integers.
    scaled: u32,
}

impl Jitter {
    /// Takes one packet with RTP timestamp `ts` that arrived at `now` on a
    /// `rate` Hz clock: J += (|D| − J) / 16.
    fn update(&mut self, ts: u32, now: Instant, rate: u32) {
        let arrival = ticks(now.saturating_duration_since(self.epoch), rate);
        let transit = arrival.wrapping_sub(ts);
        if let Some(last) = self.transit.replace(transit) {
            let d = transit.wrapping_sub(last).cast_signed().unsigned_abs();
            let decay = self.scaled.saturating_add(8).checked_shr(4).unwrap_or(0);
            self.scaled = self.scaled.saturating_add(d).saturating_sub(decay);
        }
    }

    /// The value the report carries.
    fn value(&self) -> u32 {
        self.scaled.checked_shr(4).unwrap_or(0)
    }
}

/// What one stream heard from its synchronization source.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Heard {
    /// The source's SSRC.
    ssrc: u32,
    /// Its sequence state.
    sequence: Sequence,
    /// Its jitter.
    jitter: Jitter,
}

/// One stream: an RTP session on an interleaved channel pair.
#[derive(Debug)]
struct Reception {
    /// The RTP channel (even); RTCP is on the next one.
    channel: u8,
    /// The RTP clock rate, when the source handed one over.
    rate: Option<u32>,
    /// The source, from its first RTP packet.
    heard: Option<Heard>,
    /// A packet counted since the last report.
    fresh: bool,
    /// The last Sender Report: the middle 32 bits of its NTP timestamp,
    /// and when it arrived.
    last_sr: Option<(u32, Instant)>,
    /// When the next report is due, from the first RTP packet on.
    next: Option<Instant>,
}

impl Reception {
    /// One RTP packet (RFC 3550 §5.1) that arrived at `now`, by its first
    /// bytes; a new SSRC starts the statistics over.
    fn rtp(&mut self, head: &[u8], now: Instant) {
        let fields = (
            head.first(),
            head.get(2..4).and_then(|b| <[u8; 2]>::try_from(b).ok()),
            head.get(4..8).and_then(|b| <[u8; 4]>::try_from(b).ok()),
            head.get(8..12).and_then(|b| <[u8; 4]>::try_from(b).ok()),
        );
        let (Some(&first), Some(seq), Some(ts), Some(ssrc)) = fields else {
            return;
        };
        if first >> 6 != 2 {
            return;
        }
        let (seq, ts, ssrc) = (
            u16::from_be_bytes(seq),
            u32::from_be_bytes(ts),
            u32::from_be_bytes(ssrc),
        );
        let source = match &mut self.heard {
            Some(known) if known.ssrc == ssrc => known,
            other => {
                if other.is_some() {
                    tracing::debug!(
                        channel = self.channel,
                        ssrc,
                        "rtsp rtcp: a new synchronization source; its statistics start over"
                    );
                }
                other.insert(Heard {
                    ssrc,
                    sequence: Sequence::new(seq),
                    jitter: Jitter {
                        epoch: now,
                        transit: None,
                        scaled: 0,
                    },
                })
            }
        };
        if source.sequence.update(seq) {
            self.fresh = true;
            if let Some(rate) = self.rate {
                source.jitter.update(ts, now, rate);
            }
        }
    }

    /// One RTCP compound packet (RFC 3550 §6.1) on the stream's RTCP
    /// channel that arrived at `now`: a Sender Report first is kept for
    /// LSR and DLSR, whatever SSRC it names, since the camera reads LSR
    /// against the reports it sent.
    fn rtcp(&mut self, head: &[u8], now: Instant) {
        let sr = head.first().is_some_and(|first| first >> 6 == 2) && head.get(1) == Some(&PT_SR);
        let middle = head.get(10..14).and_then(|b| <[u8; 4]>::try_from(b).ok());
        if let (true, Some(middle)) = (sr, middle) {
            self.last_sr = Some((u32::from_be_bytes(middle), now));
        }
    }

    /// The report block (RFC 3550 §6.4.1) appended to `out`, when RTP
    /// arrived since the last report.
    fn block(&mut self, now: Instant, out: &mut Vec<u8>) -> bool {
        let Some(heard) = self.heard.as_mut().filter(|_| self.fresh) else {
            return false;
        };
        self.fresh = false;
        let (fraction, lost, extended_max) = heard.sequence.block();
        let (lsr, dlsr) = self.last_sr.map_or((0, 0), |(lsr, at)| {
            // In units of 1/65536 s.
            let delay = now
                .saturating_duration_since(at)
                .as_nanos()
                .saturating_mul(65_536)
                .checked_div(1_000_000_000)
                .unwrap_or_default();
            (lsr, u32::try_from(delay).unwrap_or(u32::MAX))
        });
        out.extend_from_slice(&heard.ssrc.to_be_bytes());
        out.push(fraction);
        out.extend_from_slice(lost.to_be_bytes().get(1..).unwrap_or_default());
        out.extend_from_slice(&extended_max.to_be_bytes());
        out.extend_from_slice(&heard.jitter.value().to_be_bytes());
        out.extend_from_slice(&lsr.to_be_bytes());
        out.extend_from_slice(&dlsr.to_be_bytes());
        tracing::trace!(
            channel = self.channel,
            ssrc = heard.ssrc,
            fraction,
            lost,
            extended_max,
            jitter = heard.jitter.value(),
            lsr,
            dlsr,
            "rtsp rtcp: report block"
        );
        true
    }
}

/// One compound RTCP packet for a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    /// The stream's RTP channel; the report goes on the next one.
    pub(crate) channel: u8,
    /// The compound packet: RR, then SDES.
    pub(crate) packet: Vec<u8>,
}

impl Report {
    /// Appends the report as an interleaved frame on the stream's RTCP
    /// channel (RFC 2326 §10.12) to `out`.
    pub(crate) fn interleave(&self, out: &mut Vec<u8>) {
        let len = u16::try_from(self.packet.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&[b'$', self.channel | 1]);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.packet);
    }
}

/// The random choices of one attempt: our SSRC (RFC 3550 §8.1), our CNAME
/// (RFC 7022 §4.2) and the state the report intervals are drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Seed {
    /// Our SSRC.
    pub(crate) ssrc: u32,
    /// The CNAME's 96 random bits.
    pub(crate) cname: [u8; 12],
    /// The interval draws' state.
    pub(crate) draws: u64,
}

impl Seed {
    /// Fresh choices: `SipHash` outputs under std's `RandomState`, whose
    /// keys come from the operating system's random source, so the
    /// worker needs no generator of its own.
    pub(crate) fn random() -> Self {
        let draw = || RandomState::new().build_hasher().finish();
        let (first, second, third) = (draw(), draw(), draw());
        let mut cname = [0_u8; 12];
        let bytes = first.to_be_bytes().into_iter().chain(second.to_be_bytes());
        for (slot, byte) in cname.iter_mut().zip(bytes) {
            *slot = byte;
        }
        Self {
            ssrc: u32::try_from(second & u64::from(u32::MAX)).unwrap_or_default(),
            cname,
            draws: third,
        }
    }
}

/// The receiver side of every stream of one attempt: statistics, the
/// schedule and the packets.
#[derive(Debug)]
pub(crate) struct ReceiverReports {
    /// Our SSRC, the "SSRC of packet sender".
    ssrc: u32,
    /// The SDES chunk with our CNAME, padded (RFC 3550 §6.5).
    sdes: Vec<u8>,
    /// The interval draws' state (`SplitMix64`).
    draws: u64,
    /// The clock rates the source hands over.
    rates: std::sync::Arc<SetupRates>,
    /// The streams set up so far.
    streams: Vec<Reception>,
}

impl ReceiverReports {
    /// Reports for one attempt, with `seed`'s choices and the clock rates
    /// from `rates`.
    pub(crate) fn new(rates: std::sync::Arc<SetupRates>, seed: Seed) -> Self {
        let cname: String = seed
            .cname
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect();
        // SDES (§6.5): header, one chunk with our SSRC, the CNAME item,
        // the end-of-list item and padding to 32 bits.
        let mut chunk = seed.ssrc.to_be_bytes().to_vec();
        chunk.extend_from_slice(&[SDES_CNAME, u8::try_from(cname.len()).unwrap_or(0)]);
        chunk.extend_from_slice(cname.as_bytes());
        chunk.push(0);
        while !chunk.len().is_multiple_of(4) {
            chunk.push(0);
        }
        let words = u16::try_from(chunk.len() / 4).unwrap_or(0);
        let mut sdes = vec![0x81, PT_SDES];
        sdes.extend_from_slice(&words.to_be_bytes());
        sdes.extend_from_slice(&chunk);
        Self {
            ssrc: seed.ssrc,
            sdes,
            draws: seed.draws,
            rates,
            streams: Vec::new(),
        }
    }

    /// A `SETUP` was answered with the RTP channel `channel` (even, as
    /// retina assigns them): the stream reports from its first packet on,
    /// with the next clock rate the source handed over.
    pub(crate) fn set_up(&mut self, channel: u8) {
        if channel & 1 == 1 {
            tracing::debug!(
                channel,
                "rtsp rtcp: an odd RTP channel, which retina refuses; no reports"
            );
            return;
        }
        let rate = self.rates.pop();
        tracing::debug!(
            channel,
            rate,
            "rtsp rtcp: stream set up; receiver reports from its first packet"
        );
        self.streams.retain(|stream| stream.channel != channel);
        self.streams.push(Reception {
            channel,
            rate,
            heard: None,
            fresh: false,
            last_sr: None,
            next: None,
        });
    }

    /// One frame or datagram on `channel` (RTP on the even channel of a
    /// stream, RTCP on the odd one) that arrived at `now`, by its first
    /// [`HEAD`] bytes or fewer; `true` when it moved the next report
    /// earlier (a stream's first packet).
    pub(crate) fn packet(&mut self, channel: u8, head: &[u8], now: Instant) -> bool {
        let rtp_channel = channel & !1;
        let Some(stream) = self.streams.iter_mut().find(|s| s.channel == rtp_channel) else {
            return false;
        };
        if channel & 1 == 1 {
            stream.rtcp(head, now);
            return false;
        }
        stream.rtp(head, now);
        if stream.next.is_some() || stream.heard.is_none() {
            return false;
        }
        let wait = interval(&mut self.draws, true);
        tracing::debug!(
            channel = stream.channel,
            ?wait,
            "rtsp rtcp: first RTP packet; first receiver report scheduled"
        );
        stream.next = now.checked_add(wait);
        true
    }

    /// When the next report is due, if any is scheduled.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.streams.iter().filter_map(|stream| stream.next).min()
    }

    /// The reports due at `now`, each stream's next one scheduled.
    pub(crate) fn take_due(&mut self, now: Instant) -> Vec<Report> {
        let mut reports = Vec::new();
        for stream in &mut self.streams {
            if stream.next.is_none_or(|next| next > now) {
                continue;
            }
            let wait = interval(&mut self.draws, false);
            let ours = self.ssrc;
            stream.next = now.checked_add(wait);
            let mut blocks = Vec::new();
            let count = u8::from(stream.block(now, &mut blocks));
            let words = u16::from(count).saturating_mul(6).saturating_add(1);
            let mut packet = vec![0x80 | count, PT_RR];
            packet.extend_from_slice(&words.to_be_bytes());
            packet.extend_from_slice(&ours.to_be_bytes());
            packet.extend_from_slice(&blocks);
            packet.extend_from_slice(&self.sdes);
            tracing::trace!(
                channel = stream.channel,
                blocks = count,
                ?wait,
                "rtsp rtcp: receiver report"
            );
            reports.push(Report {
                channel: stream.channel,
                packet,
            });
        }
        reports
    }
}

/// The next draw of `SplitMix64` from `state`.
const fn split_mix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The next report interval (RFC 3550 §6.2, §6.3.1, §A.7): the minimum
/// (halved for the `initial` report), times a draw from [0.5, 1.5),
/// divided by e − 3/2.
fn interval(draws: &mut u64, initial: bool) -> Duration {
    let minimum = if initial {
        FIRST_MIN_INTERVAL
    } else {
        MIN_INTERVAL
    };
    let millionths = u128::from(split_mix(draws) % 1_000_000).saturating_add(500_000);
    let nanos = minimum
        .as_nanos()
        .saturating_mul(millionths)
        .checked_div(COMPENSATION_MILLIONTHS)
        .unwrap_or_default();
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::Arc;

    use lotse_core::clock::{Clock as _, FakeClock};

    use super::*;

    const SEED: Seed = Seed {
        ssrc: 0xfeed_beef,
        cname: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xff],
        draws: 7,
    };

    fn rtp(seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 96];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&ts.to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet
    }

    /// An SR's first 16 bytes with NTP `ntp`.
    fn sr(ntp: u64) -> Vec<u8> {
        let mut packet = vec![0x80, PT_SR, 0, 6, 0, 0, 0, 1];
        packet.extend_from_slice(&ntp.to_be_bytes());
        packet
    }

    /// The fields of a report's one block: (SSRC, fraction, cumulative,
    /// extended max, jitter, LSR, DLSR).
    fn fields(packet: &[u8]) -> (u32, u8, i32, u32, u32, u32, u32) {
        assert_eq!(packet[0], 0x81);
        assert_eq!(packet[1], PT_RR);
        let word = |at: usize| u32::from_be_bytes(packet[at..at + 4].try_into().unwrap());
        let lost = i32::from_be_bytes([
            if packet[13] & 0x80 == 0 { 0 } else { 0xff },
            packet[13],
            packet[14],
            packet[15],
        ]);
        (
            word(8),
            packet[12],
            lost,
            word(16),
            word(20),
            word(24),
            word(28),
        )
    }

    fn reports(rates: &[u32]) -> ReceiverReports {
        let shared = Arc::new(SetupRates::default());
        for rate in rates {
            shared.push(*rate);
        }
        ReceiverReports::new(shared, SEED)
    }

    #[test]
    fn rfc3550_a_1_a_new_source_counts_after_two_sequential_packets() {
        let mut sequence = Sequence::new(10);
        assert!(!sequence.update(10));
        assert!(sequence.update(11));
        assert_eq!((sequence.base_seq, sequence.received), (11, 1));
        // Out of sequence on probation starts the probation over.
        let mut sequence = Sequence::new(10);
        assert!(!sequence.update(10));
        let mut other = Sequence::new(10);
        assert!(!other.update(20));
        assert_eq!((other.probation, other.max_seq), (1, 20));
        assert!(other.update(21));
        assert_eq!(other.base_seq, 21);
        assert!(sequence.update(11));
    }

    #[test]
    fn rfc3550_a_1_wrap_gap_jump_and_restart() {
        let mut sequence = Sequence::new(0xfffe);
        sequence.update(0xfffe);
        assert!(sequence.update(0xffff));
        // Wraps: a cycle.
        assert!(sequence.update(0));
        assert_eq!(sequence.cycles, RTP_SEQ_MOD);
        // A gap below MAX_DROPOUT is loss.
        assert!(sequence.update(10));
        // A duplicate and a reordered packet count as received.
        assert!(sequence.update(10));
        assert!(sequence.update(5));
        assert_eq!(sequence.max_seq, 10);
        // A large jump is not taken, unless the next one follows it.
        assert!(!sequence.update(20_000));
        assert_eq!(sequence.bad_seq, 20_001);
        assert!(sequence.update(20_001));
        assert_eq!((sequence.base_seq, sequence.received), (20_001, 1));
        // The boundaries: MAX_DROPOUT - 1 ahead is a gap, MAX_MISORDER
        // behind is reordered, one more is a jump.
        assert!(sequence.update(20_001 + MAX_DROPOUT - 1));
        let max = sequence.max_seq;
        assert!(sequence.update(max - MAX_MISORDER + 1));
        assert_eq!(sequence.max_seq, max);
        let mut edge = sequence.clone();
        assert!(!edge.update(max.wrapping_add(MAX_DROPOUT)));
        assert!(!sequence.update(max - MAX_MISORDER));
        assert_eq!(sequence.bad_seq, u32::from(max - MAX_MISORDER + 1));
    }

    #[test]
    fn rfc3550_a_3_loss_fraction_and_extended_highest() {
        let mut sequence = Sequence::new(0xfff0);
        sequence.update(0xfff0);
        sequence.update(0xfff1);
        // 0xfff1..=0x000e expected (30), 26 received: 4 lost.
        for seq in 0xfff2_u16..=0xffff {
            sequence.update(seq);
        }
        for seq in [0_u16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14] {
            sequence.update(seq);
        }
        let (fraction, lost, extended) = sequence.block();
        assert_eq!(extended, RTP_SEQ_MOD + 14);
        assert_eq!(lost, 4);
        // 4 × 256 / 30.
        assert_eq!(fraction, 34);
        // Nothing new: nothing lost in the interval.
        assert_eq!(sequence.block(), (0, 4, RTP_SEQ_MOD + 14));
        // Duplicates make the interval's loss negative: fraction 0, the
        // cumulative count goes down.
        sequence.update(14);
        sequence.update(14);
        sequence.update(15);
        assert_eq!(sequence.block(), (0, 2, RTP_SEQ_MOD + 15));
        // All of the interval lost: 255.
        let mut lossy = Sequence::new(0);
        lossy.update(0);
        lossy.update(1);
        lossy.block();
        lossy.max_seq = 101;
        assert_eq!(lossy.block().0, 255);
        // The 24-bit clamp.
        lossy.received = 0;
        lossy.base_seq = 0;
        lossy.cycles = 0x0100_0000;
        assert_eq!(lossy.block().1, 0x7f_ffff);
        lossy.received = 0x0100_0000;
        lossy.cycles = 0;
        assert_eq!(lossy.block().1, -0x80_0000);
    }

    #[test]
    fn rfc3550_a_8_jitter_follows_the_transit_differences() {
        let at = FakeClock::from_system().now();
        let mut jitter = Jitter {
            epoch: at,
            transit: None,
            scaled: 0,
        };
        // 90 kHz, packets every 10 ms stamped 900 apart: no jitter.
        for n in 0..10_u32 {
            jitter.update(
                n * 900,
                at + Duration::from_millis(u64::from(n) * 10),
                90_000,
            );
        }
        assert_eq!(jitter.value(), 0);
        // One packet 10 ms late (900 ticks): J = 900/16 rounded down.
        jitter.update(9_000, at + Duration::from_millis(110), 90_000);
        assert_eq!(jitter.scaled, 900);
        assert_eq!(jitter.value(), 56);
        // Back on time: |D| = 900 again, J += 900 - (900 + 8) / 16.
        jitter.update(9_900, at + Duration::from_millis(110), 90_000);
        assert_eq!(jitter.scaled, 900 + 900 - 56);
        // Early is as far from on time as late.
        let mut early = Jitter {
            epoch: at,
            transit: Some(0),
            scaled: 0,
        };
        early.update(900, at, 90_000);
        assert_eq!(early.scaled, 900);
        assert_eq!(ticks(Duration::from_secs(1), 48_000), 48_000);
        assert_eq!(ticks(Duration::from_secs(1 << 20), 90_000), 4_177_526_784);
    }

    /// RFC 3550 §6.5: one chunk, our SSRC, a CNAME of 24 hex digits,
    /// padded.
    fn check_sdes(sdes: &[u8]) {
        assert_eq!(&sdes[..4], &[0x81, PT_SDES, 0, 8]);
        assert_eq!(&sdes[4..8], &0xfeed_beef_u32.to_be_bytes());
        assert_eq!((sdes[8], sdes[9]), (SDES_CNAME, 24));
        assert_eq!(&sdes[10..34], b"000102030405060708090aff");
        assert_eq!(&sdes[34..], &[0, 0]);
    }

    #[test]
    fn rfc3550_6_4_2_a_report_has_our_ssrc_one_block_and_the_sdes_cname() {
        let clock = FakeClock::from_system();
        let start = clock.now();
        let mut reports = reports(&[90_000]);
        reports.set_up(0);
        assert_eq!(reports.due(), None, "nothing before the first packet");
        // The SR's NTP is 0x0000_1234_5678_9abc: LSR its middle 32 bits.
        assert!(!reports.packet(1, &sr(0x0000_1234_5678_9abc), start));
        assert!(reports.packet(0, &rtp(1, 0, 0xabcd), start));
        assert!(!reports.packet(0, &rtp(2, 900, 0xabcd), start + Duration::from_millis(10)));
        // Lost: 3; seq 4 a frame late.
        assert!(!reports.packet(0, &rtp(4, 2_700, 0xabcd), start + Duration::from_millis(40)));
        let due = reports.due().unwrap();
        let first = due - start;
        assert!(
            first >= Duration::from_millis(1026) && first < Duration::from_millis(3079),
            "{first:?}"
        );
        assert!(
            reports
                .take_due(due.checked_sub(Duration::from_millis(1)).unwrap())
                .is_empty()
        );
        let sent = reports.take_due(due);
        assert_eq!(sent.len(), 1);
        let report = &sent[0];
        assert_eq!(report.channel, 0);
        let packet = &report.packet;
        assert_eq!(packet.len(), 32 + 36);
        assert_eq!(&packet[2..4], &[0, 7]);
        assert_eq!(&packet[4..8], &0xfeed_beef_u32.to_be_bytes());
        let (ssrc, fraction, lost, extended, jitter, lsr, dlsr) = fields(packet);
        assert_eq!((ssrc, lost, extended), (0xabcd, 1, 4));
        // 256 / 3.
        assert_eq!(fraction, 85);
        // |D| = 900 once: 900 / 16.
        assert_eq!(jitter, 56);
        assert_eq!(lsr, 0x1234_5678);
        let expected_dlsr =
            u32::try_from((due - start).as_nanos() * 65_536 / 1_000_000_000).unwrap();
        assert_eq!(dlsr, expected_dlsr);
        check_sdes(&packet[32..]);
        // The next one 5 s on average, an empty RR when nothing arrived.
        let next = reports.due().unwrap() - due;
        assert!(
            next >= Duration::from_millis(2052) && next < Duration::from_millis(6157),
            "{next:?}"
        );
        let later = reports.take_due(reports.due().unwrap());
        assert_eq!(&later[0].packet[..4], &[0x80, PT_RR, 0, 1]);
        assert_eq!(later[0].packet.len(), 8 + 36);
    }

    #[test]
    fn rfc2326_10_12_a_report_goes_on_the_streams_rtcp_channel() {
        let report = Report {
            channel: 2,
            packet: vec![1, 2, 3],
        };
        let mut out = vec![9];
        report.interleave(&mut out);
        assert_eq!(out, [9, b'$', 3, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn streams_report_on_their_own_schedule_and_skip_what_they_cannot_read() {
        let at = FakeClock::from_system().now();
        // The second stream's rate is missing: no jitter, still reports.
        let mut reports = reports(&[90_000]);
        reports.set_up(0);
        reports.set_up(2);
        // Odd channels are no RTP channel; unknown channels are ignored.
        reports.set_up(3);
        assert!(!reports.packet(4, &rtp(1, 0, 1), at));
        assert!(!reports.packet(5, &sr(1), at));
        // Short, non-version-2 and non-SR packets change nothing.
        assert!(!reports.packet(2, &rtp(1, 0, 1)[..11], at));
        assert!(!reports.packet(2, &[0x40; 12], at));
        assert!(!reports.packet(3, &sr(1)[..13], at));
        let mut rr = sr(1);
        rr[1] = PT_RR;
        assert!(!reports.packet(3, &rr, at));
        rr[1] = PT_SR;
        rr[0] = 0x40;
        assert!(!reports.packet(3, &rr, at));
        assert_eq!(reports.due(), None);
        reports.packet(2, &rtp(1, 0, 1), at);
        reports.packet(2, &rtp(2, 0, 1), at + Duration::from_millis(500));
        let audio_due = reports.due().unwrap();
        reports.packet(0, &rtp(1, 0, 7), at + Duration::from_secs(4));
        assert_eq!(reports.due(), Some(audio_due));
        let sent = reports.take_due(audio_due);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].channel, 2);
        let (_, _, _, _, jitter, lsr, dlsr) = fields(&sent[0].packet);
        assert_eq!((jitter, lsr, dlsr), (0, 0, 0));
        // A new SSRC starts the statistics over.
        let mut again = reports.streams[1].heard.clone().unwrap();
        reports.packet(2, &rtp(500, 0, 9), at + Duration::from_secs(1));
        assert_eq!(reports.streams[1].heard.as_ref().unwrap().ssrc, 9);
        assert!(again.sequence.update(3));
        // A stream set up again on its channel starts over too.
        reports.set_up(2);
        assert_eq!(reports.streams.len(), 2);
        assert!(reports.streams[1].heard.is_none());
    }

    #[test]
    fn rfc3550_6_3_1_intervals_spread_over_half_to_one_and_a_half_times_compensated() {
        let mut draws = 1;
        let (mut low, mut high) = (Duration::MAX, Duration::ZERO);
        for _ in 0..10_000 {
            let wait = interval(&mut draws, false);
            low = low.min(wait);
            high = high.max(wait);
        }
        // 5 s × [0.5, 1.5) / 1.21828: [2.052, 6.157) s, well spread.
        assert!(
            low >= Duration::from_millis(2052) && low < Duration::from_millis(2100),
            "{low:?}"
        );
        assert!(
            high < Duration::from_millis(6157) && high > Duration::from_millis(6100),
            "{high:?}"
        );
        let first = interval(&mut draws, true);
        assert!(first >= Duration::from_millis(1026) && first < Duration::from_millis(3079));
        // SplitMix64's reference output for state 0.
        assert_eq!(split_mix(&mut 0), 0xe220_a839_7b1d_cdaf);
    }

    #[test]
    fn rfc3550_8_1_every_attempt_draws_its_own_ssrc_and_cname() {
        let (a, b) = (Seed::random(), Seed::random());
        assert_ne!(a, b);
        // Each part of the seed is drawn (a 2^-32 chance of a false alarm).
        assert_ne!(a.ssrc, b.ssrc);
        assert_ne!(a.cname, [0; 12]);
        let rates = Arc::new(SetupRates::default());
        assert!(format!("{:?}", ReceiverReports::new(rates, a)).starts_with("ReceiverReports"));
    }
}

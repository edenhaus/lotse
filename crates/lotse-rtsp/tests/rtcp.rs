//! The RTSP source's RTCP Receiver Reports (RFC 3550 §6.4.2) against the
//! fake camera of `lotse-testing`, which records the RTCP a client sends:
//! over TCP on each stream's interleaved RTCP channel (RFC 2326 §10.12)
//! and with `transport: "udp"` from each stream's RTCP port, with the
//! loss, jitter, LSR and DLSR of §6.4.1 and the interval of §6.2 and
//! §6.3.1, all on the injected clock, which the test moves one frame at a
//! time.

#![allow(
    clippy::missing_docs_in_private_items,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the helpers outside #[test] functions panic on harness failures"
)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lotse_core::clock::{Clock, FakeClock, SystemClock};
use lotse_core::source::{ResolvedPeer, SourceFactory as _};
use lotse_core::source_url::SourceUrl;
use lotse_rtsp::RtspFactory;
use lotse_testing::fake_camera::{CameraAudio, CameraUdp, ClientRtcp, SSRC, Stats};
use lotse_testing::{CameraConfig, FakeCamera, Harness};
use serde_json::json;

/// Frames per second of the camera: the clock moves one frame at a time.
const FPS: u32 = 30;

/// One report block, as RFC 3550 §6.4.1 lays it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block {
    ssrc: u32,
    fraction: u8,
    lost: i32,
    extended_max: u32,
    jitter: u32,
    lsr: u32,
    dlsr: u32,
}

/// A recorded compound packet read as RR then SDES: our SSRC and the
/// block, if it has one.
fn read_rr(rtcp: &ClientRtcp) -> (u32, Option<Block>) {
    let p = &rtcp.packet;
    assert_eq!(p[0] >> 6, 2, "version 2: {p:?}");
    assert_eq!(p[1], 201, "an RR first (RFC 3550 §6.1): {p:?}");
    let count = p[0] & 0x1f;
    let words = usize::from(u16::from_be_bytes([p[2], p[3]]));
    let rr_len = (words + 1) * 4;
    assert_eq!(rr_len, 8 + 24 * usize::from(count));
    // An SDES with a CNAME follows (RFC 3550 §6.5.1).
    assert_eq!(p[rr_len + 1], 202, "SDES second: {p:?}");
    assert_eq!(p[rr_len + 8], 1, "the CNAME item");
    let word = |at: usize| u32::from_be_bytes(p[at..at + 4].try_into().unwrap());
    let ours = word(4);
    assert_eq!(word(rr_len + 4), ours, "the SDES chunk is ours");
    let block = (count == 1).then(|| Block {
        ssrc: word(8),
        fraction: p[12],
        lost: i32::from_be_bytes([
            if p[13] & 0x80 == 0 { 0 } else { 0xff },
            p[13],
            p[14],
            p[15],
        ]),
        extended_max: word(16),
        jitter: word(20),
        lsr: word(24),
        dlsr: word(28),
    });
    (ours, block)
}

/// The middle 32 bits of the NTP timestamp of `wall` (RFC 3550 §4).
fn ntp_middle(wall: SystemTime) -> u32 {
    let since = wall.duration_since(UNIX_EPOCH).unwrap();
    let secs = since.as_secs() + 2_208_988_800;
    let frac = u64::from(since.subsec_nanos()) * 65_536 / 1_000_000_000;
    u32::try_from(((secs & 0xffff) << 16) | frac).unwrap()
}

/// A camera and a source on a fake clock; `transport` is `"tcp"` or
/// `"udp"`.
struct Rig {
    clock: Arc<FakeClock>,
    camera: FakeCamera,
    harness: Harness,
    /// When the camera answered `PLAY`, on the fake clock.
    playing_at: Option<Instant>,
}

impl Rig {
    async fn start(config: CameraConfig, transport: &str) -> Self {
        let clock = Arc::new(FakeClock::from_system());
        let time: Arc<dyn Clock> = Arc::<FakeClock>::clone(&clock);
        let camera = FakeCamera::start(config, Arc::clone(&time))
            .await
            .expect("camera binds");
        let source = RtspFactory::default()
            .validate(
                &SourceUrl::parse(&camera.url()).unwrap(),
                &json!({ "transport": transport }),
            )
            .expect("valid source");
        let peer = ResolvedPeer {
            host: "127.0.0.1".into(),
            addrs: vec![camera.addr()],
        };
        let harness = Harness::start(source.as_ref(), peer, time);
        Self {
            clock,
            camera,
            harness,
            playing_at: None,
        }
    }

    /// Waits, up to 5 s of real time, for the camera to see `PLAY`, then
    /// moves the clock a frame at a time, with a moment of real time for
    /// the camera and the relay after each, until `done` holds for the
    /// recorded RTCP, or fails after `limit` of fake time.
    async fn run_until(
        &mut self,
        limit: Duration,
        done: impl Fn(&[ClientRtcp]) -> bool,
    ) -> Vec<ClientRtcp> {
        let frame = Duration::from_secs(1) / FPS;
        for _ in 0..2500 {
            if self.playing_at.is_some() {
                break;
            }
            if Stats::get(&self.camera.stats().plays) > 0 {
                self.playing_at = Some(self.clock.now());
            }
            SystemClock.sleep(Duration::from_millis(2)).await;
        }
        assert!(self.playing_at.is_some(), "no PLAY within 5 s");
        let start = self.clock.now();
        loop {
            let rtcp = self.camera.stats().rtcp_received();
            if done(&rtcp) {
                return rtcp;
            }
            assert!(
                self.clock.now() - start < limit,
                "not within {limit:?}: {rtcp:?}"
            );
            self.clock.advance(frame);
            SystemClock.sleep(Duration::from_millis(3)).await;
        }
    }

    async fn stop(self) {
        self.harness.cancel();
        let _exit = self.harness.finish().await;
        self.camera.stop().await;
    }
}

/// The reports with a block, of the stream whose RTCP channel is
/// `channel`.
fn reports_on(rtcp: &[ClientRtcp], channel: u8) -> Vec<(ClientRtcp, Block)> {
    rtcp.iter()
        .filter(|r| r.channel == Some(channel) && r.packet.len() > 8)
        .filter_map(|r| read_rr(r).1.map(|block| (r.clone(), block)))
        .collect()
}

/// LSR and DLSR name the Sender Report the camera sent that long before
/// the report arrived (RFC 3550 §6.4.1), within one frame on the fake
/// clock.
fn check_lsr(clock: &FakeClock, rtcp: &ClientRtcp, block: Block) {
    assert_ne!(block.lsr, 0, "the camera sends an SR a second: {block:?}");
    let arrived = clock.wall_now() - (clock.now() - rtcp.at);
    let delay = Duration::from_nanos(u64::from(block.dlsr) * 1_000_000_000 / 65_536);
    assert!(
        delay < Duration::from_millis(1100),
        "an SR a second: {delay:?}"
    );
    let sent = ntp_middle(arrived - delay);
    let off = sent.wrapping_sub(block.lsr).cast_signed().unsigned_abs();
    // One frame is 2185 units of 1/65536 s.
    assert!(off < 2_200, "LSR {:#x} vs {sent:#x}: {block:?}", block.lsr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3550_6_4_2_over_tcp_receiver_reports_reach_the_camera_on_each_rtcp_channel() {
    let config = CameraConfig {
        fps: FPS,
        audio: Some(CameraAudio::Pcmu),
        ..CameraConfig::default()
    };
    let mut rig = Rig::start(config, "tcp").await;
    let rtcp = rig
        .run_until(Duration::from_secs(20), |rtcp| {
            reports_on(rtcp, 1).len() >= 2 && !reports_on(rtcp, 3).is_empty()
        })
        .await;
    assert!(rtcp.iter().all(|r| !r.udp));
    let video = reports_on(&rtcp, 1);
    let (first, block) = &video[0];
    // RFC 3550 §6.2, §6.3.1: the first within 2.5 s × [0.5, 1.5) / (e −
    // 3/2) of the first packet, which came at PLAY, a frame late at most.
    let after = first.at - rig.playing_at.expect("played");
    assert!(
        after >= Duration::from_millis(1026) && after < Duration::from_millis(3079 + 70),
        "{after:?}"
    );
    assert_eq!(block.ssrc, SSRC);
    assert_eq!(
        (block.fraction, block.lost),
        (0, 0),
        "nothing lost over TCP"
    );
    assert!(block.extended_max > 30, "{block:?}");
    // The clock moved one frame a frame: arrival and RTP time agree to
    // the tick, and the jitter stays at most 1 (RFC 3550 §A.8).
    assert!(block.jitter <= 1, "{block:?}");
    check_lsr(&rig.clock, first, *block);
    // The next 5 s × [0.5, 1.5) / (e − 3/2) later, with more counted.
    let (second, next) = &video[1];
    let gap = second.at - first.at;
    assert!(
        gap >= Duration::from_millis(2052) && gap < Duration::from_millis(6157 + 70),
        "{gap:?}"
    );
    assert!(next.extended_max > block.extended_max);
    check_lsr(&rig.clock, second, *next);
    // The audio stream reports on its own channel, for its own source, from
    // the same sender (one SSRC and CNAME per attempt).
    let (audio_rtcp, audio) = &reports_on(&rtcp, 3)[0];
    assert_eq!(audio.ssrc, lotse_testing::fake_camera::AUDIO_SSRC);
    assert_eq!(read_rr(audio_rtcp).0, read_rr(first).0);
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rfc3550_6_4_2_over_udp_receiver_reports_count_the_loss_from_the_rtcp_port() {
    let config = CameraConfig {
        fps: FPS,
        udp: CameraUdp {
            drop_every: Some(10),
            ..CameraUdp::default()
        },
        ..CameraConfig::default()
    };
    let mut rig = Rig::start(config, "udp").await;
    let rtcp = rig
        .run_until(Duration::from_secs(20), |rtcp| {
            reports_on(rtcp, 1).len() >= 2
        })
        .await;
    assert!(rtcp.iter().all(|r| r.udp));
    let video = reports_on(&rtcp, 1);
    let (first, block) = &video[0];
    assert_eq!(block.ssrc, SSRC);
    // Every tenth RTP datagram never arrives: a tenth of each interval,
    // 25 or 26 of 256, and the cumulative count grows.
    let (_, next) = &video[1];
    for b in [block, next] {
        assert!((20..=32).contains(&b.fraction), "{b:?}");
    }
    assert!(
        block.lost > 0 && next.lost > block.lost,
        "{block:?} {next:?}"
    );
    check_lsr(&rig.clock, first, *block);
    rig.stop().await;
}

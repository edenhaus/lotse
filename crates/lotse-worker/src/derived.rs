//! The derived tracks of one connection: the output of a transcoder,
//! started when the first session needs it, shared by every session that
//! negotiates it, stopped when the last one leaves.
//!
//! Invariants, all kept under one lock:
//!
//! - negotiation and leasing are one step ([`DerivedTracks::pick`]), so a
//!   session that negotiates an existing derived track (which counts as
//!   native, 03)
//!   always gets it running, however sessions open and close around it;
//! - a derived track exists exactly while a [`Lease`] on it does: the last
//!   lease dropped stops the transcoder and closes the track, and the next
//!   session derives a new one (the same id, a fresh track);
//! - at most one derived track per source track and codec, because an
//!   existing one always wins negotiation over a new transcode.
//!
//! The derived tracks live here, beside the connection's `TrackSet`, not in
//! it: the source runner watches every track in the set for stalls and
//! starts its epochs, and a derived track's activity and epochs are its
//! transcoder's. A source reconnect needs nothing here: the transcoder
//! sees the source's new epoch on its input, re-anchors and starts one on
//! the derived track. A reconnect that changed the source's codec (the
//! camera was reconfigured) restarts the transcoder on the new
//! configuration in a new epoch ([`DerivedTracks::refresh`]), or closes
//! the derived track when the new codec cannot be transcoded, and its
//! sessions continue with video.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use lotse_core::clock::Clock;
use lotse_core::codec::{Codec, Kind};
use lotse_core::negotiate::{NegotiationError, TrackInfo, TrackPlan, negotiate};
use lotse_core::output::TrackRequest;
use lotse_core::source::TrackSet;
use lotse_core::track::{Track, TrackId};
use lotse_core::transcode::{TrackHandle, TranscodeError, Transcoder};
use tokio::sync::watch;

/// One running derived track.
#[derive(Debug)]
struct Entry {
    /// The running transcoder and its output track (`handle.track`).
    handle: TrackHandle,
    /// The native track it transcodes.
    source: Arc<Track>,
    /// The source's codec the transcoder runs on.
    input: Arc<Codec>,
    /// The transcoder, to restart it after a codec change.
    transcoder: Arc<dyn Transcoder>,
    /// The sessions holding it; never zero while the entry exists.
    leases: usize,
}

/// A derived track as `stream/get` reports it.
#[derive(Debug, Clone)]
pub(crate) struct DerivedInfo {
    /// The derived track.
    pub(crate) track: Arc<Track>,
    /// The native track it is transcoded from.
    pub(crate) from: TrackId,
    /// The delay its transcoder adds (`audio_delay_ms`).
    pub(crate) delay: Duration,
}

/// A negotiated track, with the lease that keeps its transcoder running
/// when it is a derived one.
#[derive(Debug)]
pub(crate) struct PickedTrack {
    /// The track to subscribe to.
    pub(crate) track: Arc<Track>,
    /// `Some` exactly for a derived track.
    pub(crate) lease: Option<Lease>,
}

/// One session's hold on a derived track. Dropping the last one stops the
/// transcoder and closes the track.
#[derive(Debug)]
pub(crate) struct Lease {
    /// The registry it came from.
    owner: Arc<DerivedTracks>,
    /// The derived track held.
    track: Arc<Track>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.owner.release(&self.track);
    }
}

/// The derived tracks of one connection, next to its native `TrackSet`.
#[derive(Debug)]
pub(crate) struct DerivedTracks {
    /// The connection's native tracks.
    set: Arc<TrackSet>,
    /// The registered transcoders, in the order negotiation tries them.
    transcoders: Vec<Arc<dyn Transcoder>>,
    /// Times a new derived track's activity from its creation.
    clock: Arc<dyn Clock>,
    /// The running derived tracks.
    entries: Mutex<Vec<Entry>>,
    /// Bumped whenever a derived track appears, goes or is restarted, so
    /// the worker reports the tracks again.
    changes: watch::Sender<()>,
}

impl DerivedTracks {
    /// No derived tracks yet on `set`, from `transcoders`.
    pub(crate) fn new(
        set: Arc<TrackSet>,
        transcoders: Vec<Arc<dyn Transcoder>>,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        let (changes, _none_yet) = watch::channel(());
        Arc::new(Self {
            set,
            transcoders,
            clock,
            entries: Mutex::new(Vec::new()),
            changes,
        })
    }

    /// The connection's native tracks.
    pub(crate) const fn tracks(&self) -> &Arc<TrackSet> {
        &self.set
    }

    /// Changes from now on: a derived track appeared, went or restarted.
    pub(crate) fn changes(&self) -> watch::Receiver<()> {
        self.changes.subscribe()
    }

    /// The running derived tracks.
    pub(crate) fn derived(&self) -> Vec<DerivedInfo> {
        self.lock()
            .iter()
            .map(|entry| DerivedInfo {
                track: Arc::clone(&entry.handle.track),
                from: entry.source.id(),
                delay: entry.handle.delay,
            })
            .collect()
    }

    /// The entries; a poisoned lock is still usable, since every update
    /// leaves the list consistent before it can panic.
    fn lock(&self) -> MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Negotiates `requests` against the native and the running derived
    /// tracks and the transcoders,
    /// one result per request in order: a derived track picked is leased,
    /// and started first when it is not running. A transcoder that fails
    /// to start leaves the request unmet (`CodecUnsupported`).
    pub(crate) fn pick(
        self: &Arc<Self>,
        requests: &[TrackRequest],
    ) -> Vec<Result<PickedTrack, NegotiationError>> {
        let mut entries = self.lock();
        let natives = self.set.tracks();
        let infos: Vec<TrackInfo> = natives
            .iter()
            .map(|track| TrackInfo {
                id: track.id(),
                codec: track.codec(),
                derived_from: None,
            })
            .chain(entries.iter().map(|entry| TrackInfo {
                id: entry.handle.track.id(),
                codec: entry.handle.track.codec(),
                derived_from: Some(entry.source.id()),
            }))
            .collect();
        let plans = negotiate(requests, &infos, &self.transcoders);
        let mut picked = Vec::with_capacity(plans.len());
        for (request, plan) in requests.iter().zip(plans) {
            picked.push(match plan {
                TrackPlan::Native { track } => self.native(&mut entries, &natives, track),
                TrackPlan::Derived {
                    from,
                    to,
                    transcoder,
                } => self.start(&mut entries, &natives, request, from, to, transcoder),
                TrackPlan::Unavailable(err) => Err(err),
            });
        }
        drop(entries);
        picked
    }

    /// A native track, or a running derived one, which is leased.
    fn native(
        self: &Arc<Self>,
        entries: &mut [Entry],
        natives: &[Arc<Track>],
        id: TrackId,
    ) -> Result<PickedTrack, NegotiationError> {
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.handle.track.id() == id)
        {
            entry.leases = entry.leases.saturating_add(1);
            tracing::debug!(track = %id, leases = entry.leases, "derived track shared");
            return Ok(self.lease(&entry.handle.track));
        }
        // Negotiation only names tracks it was given, so the lookup finds it.
        natives
            .iter()
            .find(|track| track.id() == id)
            .map(|track| PickedTrack {
                track: Arc::clone(track),
                lease: None,
            })
            .ok_or_else(|| NegotiationError::NoTrack { kind: id.kind() })
    }

    /// Starts a transcoder from the native track `from` to `to` and leases
    /// the new derived track.
    #[expect(
        clippy::too_many_arguments,
        reason = "the plan's parts and the locked state; a struct would only rename them"
    )]
    fn start(
        self: &Arc<Self>,
        entries: &mut Vec<Entry>,
        natives: &[Arc<Track>],
        request: &TrackRequest,
        from: TrackId,
        to: Codec,
        transcoder: usize,
    ) -> Result<PickedTrack, NegotiationError> {
        // Negotiation only names tracks and transcoders it was given.
        let source = natives
            .iter()
            .find(|track| track.id() == from)
            .ok_or_else(|| NegotiationError::NoTrack { kind: from.kind() })?;
        let transcoder = self
            .transcoders
            .get(transcoder)
            .ok_or_else(|| NegotiationError::NoTrack { kind: from.kind() })?;
        let input = source.codec();
        let id = next_id(natives, entries, to.kind());
        let codec = to.name().to_owned();
        let handle = to
            .rtp_clock_rate()
            .ok_or_else(|| TranscodeError::Failed(format!("{codec} has no RTP clock rate")))
            .and_then(|clock_rate| {
                let output = Track::new(id, to, clock_rate, source.limits(), self.clock.now());
                transcoder.spawn(source.subscribe_frames(), &input, Arc::new(output))
            });
        let handle = match handle {
            Ok(handle) => handle,
            Err(err) => {
                tracing::warn!(from = %from, codec, error = %err, "transcoder did not start; the request goes unmet");
                return Err(NegotiationError::CodecUnsupported {
                    kind: request.kind,
                    accepted: request.accept.clone(),
                    native: input.family(),
                });
            }
        };
        let delay_ms = handle.delay.as_millis();
        tracing::info!(track = %id, from = %from, codec, delay_ms, "derived track started");
        let picked = self.lease(&handle.track);
        entries.push(Entry {
            handle,
            source: Arc::clone(source),
            input,
            transcoder: Arc::clone(transcoder),
            leases: 1,
        });
        self.changes.send_replace(());
        Ok(picked)
    }

    /// A lease on `track`, already counted in its entry.
    fn lease(self: &Arc<Self>, track: &Arc<Track>) -> PickedTrack {
        PickedTrack {
            track: Arc::clone(track),
            lease: Some(Lease {
                owner: Arc::clone(self),
                track: Arc::clone(track),
            }),
        }
    }

    /// One lease on `track` ended; the last stops it.
    fn release(&self, track: &Arc<Track>) {
        let mut entries = self.lock();
        let Some(index) = entries
            .iter()
            .position(|entry| Arc::ptr_eq(&entry.handle.track, track))
        else {
            // Closed already by a codec change.
            return;
        };
        let leases = entries.get_mut(index).map_or(0, |entry| {
            entry.leases = entry.leases.saturating_sub(1);
            entry.leases
        });
        if leases > 0 {
            tracing::debug!(track = %track.id(), leases, "derived track released");
            return;
        }
        let entry = entries.swap_remove(index);
        drop(entries);
        self.stop(entry, "last_session_left");
    }

    /// Stops `entry`'s transcoder and closes its track: its sessions'
    /// audio subscriptions end.
    fn stop(&self, entry: Entry, reason: &'static str) {
        entry.handle.track.close();
        tracing::info!(track = %entry.handle.track.id(), reason, "derived track stopped");
        // Dropping the handle cancels the transcoder.
        drop(entry);
        self.changes.send_replace(());
    }

    /// After a reconnect: a derived track whose source codec changed is
    /// restarted on the new one, or stopped when the transcoder cannot take
    /// it. Frames of the new configuration that reached the old chain in
    /// between decode badly or not at all, which it handles like loss.
    pub(crate) fn refresh(&self) {
        let mut entries = self.lock();
        let mut stopped = Vec::new();
        for mut entry in std::mem::take(&mut *entries) {
            let input = entry.source.codec();
            if input == entry.input {
                entries.push(entry);
                continue;
            }
            let track = entry.handle.track.id();
            let codec = input.name().to_owned();
            match restart(&mut entry, input) {
                Ok(()) => {
                    tracing::info!(%track, codec, "source codec changed; transcoder restarted");
                    entries.push(entry);
                    self.changes.send_replace(());
                }
                Err(err) => {
                    let error = err.to_string();
                    tracing::warn!(%track, codec, error, "new source codec cannot be transcoded");
                    stopped.push(entry);
                }
            }
        }
        drop(entries);
        for entry in stopped {
            self.stop(entry, "source_codec_changed");
        }
    }
}

/// Restarts `entry`'s transcoder on the source's new codec `input`, in a
/// new epoch of the derived track: the new chain's timestamps start from
/// the new configuration.
fn restart(entry: &mut Entry, input: Arc<Codec>) -> Result<(), TranscodeError> {
    let track = Arc::clone(&entry.handle.track);
    let family = track.codec().family();
    let to =
        entry
            .transcoder
            .derive(&input, family)
            .ok_or_else(|| TranscodeError::Unsupported {
                from: input.family(),
                to: family,
            })?;
    entry.handle.stop.cancel();
    track.set_codec(to);
    track.start_epoch();
    entry.handle = entry
        .transcoder
        .spawn(entry.source.subscribe_frames(), &input, track)?;
    entry.input = input;
    Ok(())
}

/// The first id of `kind` no native or derived track has: `a1` beside a
/// native `a0`.
fn next_id(natives: &[Arc<Track>], entries: &[Entry], kind: Kind) -> TrackId {
    let taken = |id: TrackId| {
        natives.iter().any(|track| track.id() == id)
            || entries.iter().any(|entry| entry.handle.track.id() == id)
    };
    (0..=u8::MAX)
        .map(|index| TrackId::new(kind, index))
        .find(|id| !taken(*id))
        .unwrap_or_else(|| TrackId::new(kind, u8::MAX))
}

/// A transcoder for tests: AAC-LC to Opus, counting its starts, optionally
/// refusing them, forwarding each input frame as one derived frame and
/// packet at 48 kHz whose capture time is [`fake::SHIFT`] before the input
/// frame's.
#[cfg(test)]
pub(crate) mod fake {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::missing_docs_in_private_items,
        reason = "test code"
    )]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use lotse_core::codec::CodecFamily;
    use lotse_core::media::{MediaFrame, MediaPacket, MediaTime, RtpHeaderFields};
    use lotse_core::task::spawn_named;
    use lotse_core::test_util::FakeTranscoder;
    use lotse_core::track::FrameSubscription;
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// How much earlier than its input frame a derived frame is captured.
    pub(crate) const SHIFT: Duration = Duration::from_millis(64);

    /// The delay its handles report.
    pub(crate) const DELAY: Duration = Duration::from_millis(88);

    #[derive(Debug, Default)]
    pub(crate) struct Forwarding {
        pub(crate) refuse: bool,
        /// Derive a codec without an RTP clock rate, which no track can
        /// carry.
        pub(crate) clockless: bool,
        pub(crate) started: AtomicUsize,
        pub(crate) stops: Mutex<Vec<CancellationToken>>,
    }

    impl Forwarding {
        pub(crate) fn started(&self) -> usize {
            self.started.load(Ordering::SeqCst)
        }

        /// Whether the `n`th transcoder started (from 0) was stopped.
        pub(crate) fn stopped(&self, n: usize) -> bool {
            self.stops.lock().unwrap()[n].is_cancelled()
        }
    }

    impl Transcoder for Forwarding {
        fn derive(&self, from: &Codec, to: CodecFamily) -> Option<Codec> {
            let derived = FakeTranscoder::aac_to_opus().derive(from, to)?;
            Some(if self.clockless {
                Codec::Unsupported {
                    kind: Kind::Audio,
                    name: "clockless".into(),
                }
            } else {
                derived
            })
        }

        fn spawn(
            &self,
            mut input: FrameSubscription,
            from: &Codec,
            output: Arc<Track>,
        ) -> Result<TrackHandle, TranscodeError> {
            assert_eq!(from.family(), CodecFamily::AacLc);
            if self.refuse {
                return Err(TranscodeError::Failed("refused".into()));
            }
            self.started.fetch_add(1, Ordering::SeqCst);
            let stop = CancellationToken::new();
            self.stops.lock().unwrap().push(stop.clone());
            let track = Arc::clone(&output);
            let cancelled = stop.clone();
            let _task = spawn_named("test.transcode", async move {
                let mut seq = 0_u16;
                while let Some(Ok(frame)) = cancelled.run_until_cancelled(input.recv()).await {
                    let ts = frame.ts.ticks() * 3;
                    track.publish_frame(MediaFrame {
                        ts: MediaTime::from_ticks(ts),
                        wallclock: frame.wallclock.checked_sub(SHIFT).unwrap(),
                        ..(*frame).clone()
                    });
                    track.publish_packet(MediaPacket {
                        arrival: frame.wallclock,
                        rtp: RtpHeaderFields {
                            pt: 111,
                            seq,
                            ts: u32::try_from(ts).unwrap(),
                            marker: false,
                            ssrc: 3,
                        },
                        frame_start: true,
                        keyframe_start: false,
                        epoch: 0,
                        lateness: Duration::ZERO,
                        payload: Arc::from(&frame.payload[..]),
                    });
                    seq = seq.wrapping_add(1);
                }
            });
            Ok(TrackHandle {
                track: output,
                delay: DELAY,
                stop,
            })
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
    use lotse_core::codec::CodecFamily;
    use lotse_core::test_util::fake_aac;
    use lotse_core::track::{TrackLimits, Unit};

    use super::fake::{DELAY, Forwarding};
    use super::*;

    const V0: TrackId = TrackId::new(Kind::Video, 0);
    const A0: TrackId = TrackId::new(Kind::Audio, 0);
    const A1: TrackId = TrackId::new(Kind::Audio, 1);

    fn h264() -> Codec {
        Codec::H264 {
            profile_level_id: None,
            sps: None,
            pps: None,
        }
    }

    /// A connection with H.264 video and `audio`, and its derived tracks
    /// from `transcoder`.
    fn connection(audio: Codec, transcoder: &Arc<Forwarding>) -> Arc<DerivedTracks> {
        let clock = Arc::new(FakeClock::default());
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        declare(&set, audio);
        let transcoder: Arc<dyn Transcoder> = transcoder.clone();
        DerivedTracks::new(set, vec![transcoder], clock)
    }

    /// Declares the connection's tracks, as a (re)connecting source does.
    fn declare(set: &Arc<TrackSet>, audio: Codec) {
        let mut publisher = set.publisher();
        let rate = audio.rtp_clock_rate().unwrap_or(8_000);
        publisher.declare(Kind::Video, h264(), 90_000);
        publisher.declare(Kind::Audio, audio, rate);
        publisher.ready();
    }

    /// What a WebRTC session asks for.
    fn requests(audio: bool) -> Vec<TrackRequest> {
        let mut requests = vec![TrackRequest {
            kind: Kind::Video,
            accept: vec![CodecFamily::H264],
            unit: Unit::Packets,
            required: true,
        }];
        if audio {
            requests.push(TrackRequest {
                kind: Kind::Audio,
                accept: vec![CodecFamily::Opus, CodecFamily::Pcmu],
                unit: Unit::Packets,
                required: false,
            });
        }
        requests
    }

    /// One session's picks: video and audio.
    fn open(derived: &Arc<DerivedTracks>) -> (PickedTrack, PickedTrack) {
        let mut picks = derived.pick(&requests(true)).into_iter();
        (
            picks.next().unwrap().unwrap(),
            picks.next().unwrap().unwrap(),
        )
    }

    #[tokio::test]
    async fn two_sessions_share_one_transcoder_and_the_last_to_leave_stops_it() {
        let transcoder = Arc::new(Forwarding::default());
        let derived = connection(fake_aac(), &transcoder);
        let mut changes = derived.changes();
        let (video, first) = open(&derived);
        assert_eq!((video.track.id(), video.lease.is_none()), (V0, true));
        assert_eq!(first.track.id(), A1, "derived beside the native a0");
        assert_eq!(*first.track.codec(), Codec::Opus { channels: 1 });
        assert_eq!(first.track.clock_rate(), 48_000);
        assert!(first.lease.is_some());
        assert!(changes.has_changed().unwrap(), "reported");
        changes.mark_unchanged();

        let (_, second) = open(&derived);
        assert!(Arc::ptr_eq(&first.track, &second.track), "shared");
        assert_eq!(transcoder.started(), 1, "one transcoder");
        assert!(!changes.has_changed().unwrap());
        let reported = derived.derived();
        assert_eq!(reported.len(), 1);
        assert_eq!(
            (reported[0].track.id(), reported[0].from, reported[0].delay),
            (A1, A0, DELAY)
        );

        drop(first);
        assert!(!transcoder.stopped(0), "one session still listens");
        assert!(!second.track.is_closed());
        let track = Arc::clone(&second.track);
        drop(second);
        assert!(transcoder.stopped(0), "the last one left");
        assert!(track.is_closed());
        assert!(derived.derived().is_empty());
        assert!(changes.has_changed().unwrap(), "reported");

        // The next session derives afresh, under the same id.
        let (_, again) = open(&derived);
        assert_eq!(again.track.id(), A1);
        assert!(!Arc::ptr_eq(&again.track, &track));
        assert_eq!(transcoder.started(), 2);
    }

    #[tokio::test]
    async fn native_audio_and_video_only_sessions_start_nothing() {
        let transcoder = Arc::new(Forwarding::default());
        let pcmu = connection(Codec::Pcmu, &transcoder);
        let (_, audio) = open(&pcmu);
        assert_eq!((audio.track.id(), audio.lease.is_none()), (A0, true));
        let aac = connection(fake_aac(), &transcoder);
        let picks = aac.pick(&requests(false));
        assert_eq!(picks.len(), 1, "audio off: no audio request");
        assert_eq!(transcoder.started(), 0);
        assert!(aac.derived().is_empty());
    }

    #[tokio::test]
    async fn a_reconnect_keeps_the_derived_track_and_its_transcoder() {
        let transcoder = Arc::new(Forwarding::default());
        let derived = connection(fake_aac(), &transcoder);
        let (_, audio) = open(&derived);
        let changes = derived.changes();
        // The runner's reconnect: a new epoch, the same tracks declared.
        derived.tracks().start_epoch();
        declare(derived.tracks(), fake_aac());
        derived.refresh();
        assert_eq!(transcoder.started(), 1);
        assert!(!transcoder.stopped(0));
        assert!(!audio.track.is_closed());
        assert_eq!(audio.track.epoch(), 0, "epochs are the transcoder's");
        assert!(!changes.has_changed().unwrap());
    }

    #[tokio::test]
    async fn a_reconnect_with_a_new_audio_config_restarts_the_transcoder_in_a_new_epoch() {
        let transcoder = Arc::new(Forwarding::default());
        let derived = connection(fake_aac(), &transcoder);
        let (_, audio) = open(&derived);
        let changes = derived.changes();
        let config = variant!(fake_aac(), Codec::AacLc { config, .. } => config);
        let stereo = Codec::AacLc {
            sample_rate: 16_000,
            channels: 2,
            config,
        };
        declare(derived.tracks(), stereo);
        derived.refresh();
        assert_eq!(transcoder.started(), 2);
        assert!(transcoder.stopped(0), "the old chain");
        assert!(!transcoder.stopped(1));
        assert_eq!(*audio.track.codec(), Codec::Opus { channels: 2 });
        assert_eq!(audio.track.epoch(), 1);
        assert!(changes.has_changed().unwrap());
        drop(audio);
        assert!(transcoder.stopped(1), "the lease holds the new chain");
    }

    #[tokio::test]
    async fn a_reconnect_to_a_codec_the_transcoder_cannot_take_closes_the_derived_track() {
        let transcoder = Arc::new(Forwarding::default());
        let derived = connection(fake_aac(), &transcoder);
        let (_, audio) = open(&derived);
        let (_, other) = open(&derived);
        declare(derived.tracks(), Codec::Pcmu);
        derived.refresh();
        assert!(transcoder.stopped(0));
        assert!(audio.track.is_closed(), "its sessions continue with video");
        assert!(derived.derived().is_empty());
        drop(audio);
        drop(other);
        // New sessions cut the new codec through.
        let (_, native) = open(&derived);
        assert_eq!((native.track.id(), native.lease.is_none()), (A0, true));
        assert_eq!(transcoder.started(), 1);
    }

    #[tokio::test]
    async fn a_transcoder_that_does_not_start_leaves_audio_unmet() {
        let transcoder = Arc::new(Forwarding {
            refuse: true,
            ..Forwarding::default()
        });
        let derived = connection(fake_aac(), &transcoder);
        let picks = derived.pick(&requests(true));
        assert!(picks[0].is_ok(), "video plays");
        let err = variant!(&picks[1], Err(err) => err);
        assert_eq!(err.code(), "audio_codec_unsupported");
        assert_eq!(
            err.to_string(),
            "sink accepts [Opus, Pcmu]; stream audio is aac_lc"
        );
        assert!(derived.derived().is_empty());
    }

    #[tokio::test]
    async fn a_derived_codec_without_a_clock_rate_is_unmet() {
        let clock = Arc::new(FakeClock::default());
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        declare(&set, fake_aac());
        let clockless = Arc::new(Forwarding {
            clockless: true,
            ..Forwarding::default()
        });
        let derived = DerivedTracks::new(set, vec![clockless.clone()], clock);
        let picks = derived.pick(&requests(true));
        assert!(matches!(
            picks[1],
            Err(NegotiationError::CodecUnsupported {
                kind: Kind::Audio,
                ..
            })
        ));
        assert!(derived.derived().is_empty());
        assert_eq!(clockless.started(), 0, "no track to start it on");
    }

    #[tokio::test]
    async fn unmet_requests_pass_through_with_their_code() {
        let transcoder = Arc::new(Forwarding::default());
        let unsupported = Codec::Unsupported {
            kind: Kind::Audio,
            name: "aac_he".into(),
        };
        let derived = connection(unsupported, &transcoder);
        let picks = derived.pick(&requests(true));
        let err = variant!(&picks[1], Err(err) => err);
        assert_eq!(err.code(), "audio_codec_unsupported");
        assert_eq!(transcoder.started(), 0);
    }

    #[test]
    fn derived_ids_take_the_first_free_index_of_their_kind() {
        let clock = FakeClock::default();
        let set = TrackSet::new(TrackLimits::default(), clock.now());
        declare(&set, Codec::Pcmu);
        let natives = set.tracks();
        assert_eq!(next_id(&natives, &[], Kind::Audio), A1);
        assert_eq!(
            next_id(&natives, &[], Kind::Video),
            TrackId::new(Kind::Video, 1)
        );
        assert_eq!(next_id(&[], &[], Kind::Audio), A0);
        let derived = Arc::new(Track::new(
            A1,
            Codec::Opus { channels: 1 },
            48_000,
            TrackLimits::default(),
            clock.now(),
        ));
        let entry = Entry {
            handle: TrackHandle {
                track: derived,
                delay: DELAY,
                stop: tokio_util::sync::CancellationToken::new(),
            },
            source: Arc::clone(&natives[1]),
            input: natives[1].codec(),
            transcoder: Arc::new(Forwarding::default()),
            leases: 1,
        };
        assert_eq!(
            next_id(&natives, &[entry], Kind::Audio),
            TrackId::new(Kind::Audio, 2),
            "past a derived a1 too"
        );
        // Every index taken: the last, which a track set never reaches.
        let full: Vec<Arc<Track>> = (0..=u8::MAX)
            .map(|index| {
                let id = TrackId::new(Kind::Audio, index);
                Arc::new(Track::new(
                    id,
                    Codec::Pcmu,
                    8_000,
                    TrackLimits::default(),
                    clock.now(),
                ))
            })
            .collect();
        assert_eq!(
            next_id(&full, &[], Kind::Audio),
            TrackId::new(Kind::Audio, u8::MAX)
        );
    }

    /// Negotiation names only tracks and transcoders it was given; a plan
    /// that names others is unmet rather than a panic.
    #[tokio::test]
    async fn a_plan_naming_an_unknown_track_or_transcoder_is_unmet() {
        let transcoder = Arc::new(Forwarding::default());
        let derived = connection(fake_aac(), &transcoder);
        let no_audio = |result: Result<PickedTrack, NegotiationError>| {
            matches!(result, Err(NegotiationError::NoTrack { kind: Kind::Audio }))
        };
        assert!(no_audio(derived.native(&mut [], &[], A0)));
        let request = &requests(true)[1];
        let opus = Codec::Opus { channels: 1 };
        let natives = derived.tracks().tracks();
        let mut entries = Vec::new();
        assert!(no_audio(derived.start(
            &mut entries,
            &[],
            request,
            A0,
            opus.clone(),
            0
        )));
        assert!(no_audio(derived.start(
            &mut entries,
            &natives,
            request,
            A0,
            opus,
            1
        )));
        assert!(entries.is_empty());
        assert_eq!(transcoder.started(), 0);
    }
}

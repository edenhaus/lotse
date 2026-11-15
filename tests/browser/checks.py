"""What decides the browser test: the checks on what the test page measured.

The page (`crates/lotse-testing/src/browser/page.html`) measures what a viewer would see and hear
and takes two `getStats()` snapshots, at the first frame plus nothing and after the play time;
everything here is a pure function of that result and of the stream the camera sends, so the
rules are written once for every browser.

Two kinds of numbers:

- gated: what a viewer sees and hears (frames shown, the white flash in the pixels, the beep in
  WebAudio, the picture size, the connection, trickle ICE both ways) and the `getStats()` fields
  that Chrome, Firefox and Safari all report (MDN browser-compat-data, checked 2026-10-06):
  `inbound-rtp` `packetsReceived`, `packetsLost`, `framesDecoded`, `jitterBufferDelay`,
  `jitterBufferEmittedCount`, `audioLevel`, `totalAudioEnergy`, and `candidate-pair` `state` and
  `nominated` (W3C webrtc-stats, Candidate Recommendation Draft 2025-09-25: §8.4 and §8.5
  `inbound-rtp`, §8.19
  `candidate-pair`); and video's `totalProcessingDelay`, which MDN lists for Chrome and Firefox
  only but WebKit reports as well (`RTCStatsReport.idl` since libwebrtc M115 in June 2023, WebKit
  main at 6ae9a398d5, observed 2026-10-07);
- diagnostics: fields only some browsers report, recorded as "not reported" when missing, never a
  failure; the capture time of the frames shown, where the browser reports `captureTimestamp`
  (W3C webrtc-extensions; Chrome); and the A/V skew, reported against EBU R37 but not gated,
  because the WebAudio tap's own delay is not calibrated.

A case with a disruption (`harness.CASES`: a keyframe request, a camera reconnect, a worker
crash) plays two windows; the checks take the one after the recovery, check that the disruption
happened as the case says (`disruption_failures`), and report the skew of the window before it
too.

An MSE case (`harness.Case.player` `mse`) plays the stream as live fMP4 through the browser's
Media Source Extensions beside the WebRTC session, which is checked as in any case. Of the MSE
player only that it plays is gated (`mse_checks`): its frames advance, it shows the flashes, it
reports no error and stalls no longer than `MSE_STALL_MS`, and the daemon's output carries the
camera's audio where the container can (AAC, Opus) and leaves it out with `audio_omitted` where it
cannot (PCMU). Its latency is a report, never a gate (`latency`): glass to glass, the WebRTC
frames' capture to render (from `captureTimestamp`, as `capture_times`), and each MSE flash that
much plus how much later it was shown than the same second's WebRTC flash; without capture times,
the difference alone. So is what the browser's MSE says it plays (`isTypeSupported`) and whether
the MSE element's sound was heard.

An LL-HLS case (`player` `llhls`) does the same with an LL-HLS session played by hls.js (or the
browser's own HLS where hls.js has no MSE) in place of the MSE player: gated alike
(`llhls_checks`), no fatal hls.js error among them, and its latency reported alike, beside
hls.js's own estimate of it and its target, the playlist's `PART-HOLD-BACK`.
"""

from __future__ import annotations

import itertools
import math
import re
from dataclasses import asdict, dataclass
from statistics import median
from typing import Any

type Json = Any
"""A value decoded from JSON."""

NOT_REPORTED = "not reported"
"""A diagnostic the browser does not report."""

FIRST_FRAME_MS = 5_000.0
"""The first frame within 5 s of the offer: warm from the GOP cache it takes tens of ms."""

RATE_SHARE = 0.9
"""Frames decoded and packets received over the play time: at least this share of what the camera
sends. A browser that keeps up decodes them all (Chrome: 601 of 603 in 20 s); 10 %
leaves room for a busy runner, and a stall of 2 s in 20 still fails."""

FRAMES_SHOWN_SHARE = 0.8
"""Frames shown (`requestVideoFrameCallback`) over the play time: at least this share of what the
camera sends. Presentation follows the compositor as well as the decoder: headless Chrome showed
591-598 of 600 in 20 s, and once 256 of 300 in 10 s while it decoded all of them."""

FLASH_SHARE = 0.8
"""Flashes seen: at least this share of the seconds played (the first may fall before the start)."""

MAX_LOSS = 0.001
"""Packets lost: at most 0.1 % of those expected, per kind. Loopback loses none; one in a thousand
leaves room for a full socket buffer on a busy runner, not for a lossy path."""

JITTER_BUFFER_MS = {"video": 150.0, "audio": 250.0}
"""The mean jitter-buffer delay over the play time (`jitterBufferDelay / jitterBufferEmittedCount`,
webrtc-stats §8.5), per kind. Video's latency budget is 20-100 ms with decode; on loopback Chrome
holds 11 ms. Audio is held for lip-sync to the video and its own jitter: 52 ms measured in Chrome,
189-285 ms in browsers playing a transcoded AAC camera before the transcoder paced its packets and
33-34 ms since. Above these the latency budget is spent."""

SAFARI_AUDIO_JITTER_BUFFER_MS = 500.0
"""Safari's bound on the mean audio jitter-buffer delay, in place of `JITTER_BUFFER_MS`'s. The first
session of a run, the `join` case, held 405-435 ms of PCMU in Safari 26.6.2 and 27.2 on CI's macOS
runner in each of the six nightly runs from 2026-10-20 to 2026-11-07 that played it, with NetEq's
own target at 172 ms and the excess drained by accelerating (`removedSamplesForAcceleration`);
the later sessions of the same run, each against a daemon and camera started afresh exactly as
the first, held 120-190 ms. That first session also took 360-410 ms to its first frame against
50-80 ms for the others, and Chrome holds 42-62 ms in every case: Safari starting cold, not the
stream (observed 2026-11-08)."""

BEYOND_JITTER_BUFFER_FRAMES = 1.0
"""The mean video processing delay beyond the jitter buffer (`totalProcessingDelay /
framesDecoded` less the mean jitter-buffer delay, webrtc-stats §8.5): what a frame waits for and
spends in the decoder after it leaves the buffer, at most this many of the camera's frame
intervals (33 ms at 30 fps). A decoder that takes longer per frame cannot keep up with the camera
and queues frames; Chrome takes 1-2 ms for the 640x480 stream."""

NTP_UNIX_OFFSET_MS = 2_208_988_800_000
"""The Unix epoch on the NTP timescale, in ms (RFC 868: 70 years and 17 leap days). Chrome reports
`captureTimestamp` as the NTP time the abs-capture-time extension carries, in ms
(`RTCRtpSource::CaptureTimestamp`, `UQ32x32ToInt64Ms`; Chromium
`third_party/blink/renderer/platform/peerconnection/rtc_rtp_source.cc` at 9c77146d35, observed
2026-10-07); the other times are the page's wall clock, the Unix epoch's."""

VIDEO_RTP_TICKS_PER_MS = 90
"""The video RTP clock (RFC 6184 §8.2.1: 90 kHz), in ticks per ms."""

ABS_CAPTURE_TIME = "http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time"
"""The abs-capture-time header extension's URI (webrtc.org experiments, observed 2026-10-07)."""

LUMA_DARK = 64.0
"""A frame darker than this is black (the camera sends luma 16)."""

LUMA_BRIGHT = 192.0
"""A frame brighter than this is white (the camera sends luma 235)."""

BEEP_PEAK = 0.1
"""The beep's peak in WebAudio must exceed this (it is sent at 0.25, -12 dBFS)."""

ENERGY_SHARE = 0.5
"""`totalAudioEnergy` over the play time: at least half of the beep's own energy, a sine's
(peak / sqrt 2)^2 for 100 ms a second (webrtc-stats §8.5: the integral of audioLevel^2 over
time). A browser that takes audioLevel from the peak, not the RMS, reports twice that."""

PAIR_WITHIN_MS = 400.0
"""A beep belongs to a flash within this distance; the marks are a second apart."""

SYNC_SETTLE_MS = 3_000.0
"""Flashes of the first 3 s after the first frame are left out of the A/V sync: the browser is
still settling its lip-sync."""

EBU_R37_LEAD_MS = -40.0
"""EBU R37 (2007): sound may lead the picture by at most 40 ms at the viewer."""

EBU_R37_LAG_MS = 60.0
"""EBU R37 (2007): sound may lag the picture by at most 60 ms."""

TWO_ELEMENTS_FRAMES_SHOWN_SHARE = 0.6
"""Frames shown over the play time by each element of an MSE or LL-HLS case, the WebRTC one and the
other player's:
at least this share of what the camera sends, in place of `FRAMES_SHOWN_SHARE`, so each picture
moves on at the camera's pace, not in slow motion; that the other one never stops is
`MSE_STALL_MS`'s and the flashes' to check. Headless Chrome skips more frames of each element
when two play on one page, every frame decoded: 432-500 of 600 from WebRTC beside 468-506 from
MSE, against 521 from WebRTC alone, on a busy 4-core host (Chrome 153, 2026-11-15)."""

MSE_STALL_MS = 2_000.0
"""The longest the MSE or LL-HLS element may show no new frame within the play time: a player that
waits for data longer than this has stalled (the camera sends a frame every 33 ms)."""

MSE_PAIR_WITHIN_MS = 500.0
"""An MSE or LL-HLS flash is the same second's as the WebRTC flash nearest to where its distance
from the end of its element's buffer puts it, within this; the flashes are a second apart."""

LATENCY_PERCENTILE = 0.9
"""The high percentile of the latencies the report gives beside the median."""


@dataclass(frozen=True, kw_only=True)
class Stream:
    """What the synthetic camera sends (`lotse_testing::browser::STREAM`, from its `Ready` line)."""

    width: int
    height: int
    fps: int
    flash_frames: int
    audio_codec: str
    audio_packets_per_second: int
    beep_hz: int
    beep_packets: int
    beep_peak_milli: int

    @classmethod
    def from_json(cls, value: Json) -> Stream:
        """The stream of `lotse-browser`'s `Ready` line."""
        return cls(**{name: value[name] for name in cls.__dataclass_fields__})

    def beep_energy_per_second(self) -> float:
        """The beep's energy a second: a sine's mean square over its share of the second."""
        peak = self.beep_peak_milli / 1000
        beep_seconds = self.beep_packets / self.audio_packets_per_second
        return (peak / math.sqrt(2)) ** 2 * beep_seconds


def parse_duration(text: str) -> float:
    """Seconds of a duration such as `20s`, `500ms`, `2m`; a bare number is seconds."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s|m)?", text.strip())
    if match is None:
        msg = f"{text!r} is not a duration (20s, 500ms, 2m)"
        raise ValueError(msg)
    value = float(match.group(1))
    return value * {"ms": 0.001, "s": 1.0, "m": 60.0, None: 1.0}[match.group(2)]


def inbound(snapshot: Json, kind: str) -> dict[str, Json]:
    """The `inbound-rtp` stats of `kind` in a snapshot; empty when there are none."""
    for stats in (snapshot or {}).get("stats", []):
        if stats.get("type") == "inbound-rtp" and stats.get("kind") == kind:
            return dict(stats)
    return {}


def _number(stats: dict[str, Json], name: str) -> float | None:
    """The field `name` when it is a number."""
    value = stats.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _delta(start: dict[str, Json], end: dict[str, Json], name: str) -> float | None:
    """How much a counter grew between the snapshots; `None` when either lacks it.

    No stats object at the start (`{}`) counts from zero: the kind's first packet came after the
    snapshot, as a transcoded track's can, which starts with the session.
    """
    before = 0.0 if not start else _number(start, name)
    after = _number(end, name)
    if before is None or after is None:
        return None
    return after - before


def _mean_ms(total: float | None, count: float | None) -> float | None:
    """A total in seconds over a count, in ms; `None` without both or with no count."""
    if total is None or not count:
        return None
    return total / count * 1000


@dataclass(frozen=True, kw_only=True)
class AvSync:
    """The A/V sync from the marks.

    Each skew is a beep's time minus its flash's, positive when the sound comes after the picture.
    """

    flashes: int
    pairs: int
    median_ms: float | None
    min_ms: float | None
    max_ms: float | None
    skews_ms: list[float]
    browser_estimate_ms: float | None
    within_ebu_r37: bool | None


def av_sync(
    flashes: list[float], beeps: list[float], since: float, browser_estimate_ms: float | None
) -> AvSync:
    """Pairs each flash shown from `since` (ms) with the nearest beep within `PAIR_WITHIN_MS`."""
    counted = [at for at in flashes if at >= since]
    skews = []
    for flash in counted:
        near = [beep - flash for beep in beeps if abs(beep - flash) <= PAIR_WITHIN_MS]
        if near:
            skews.append(min(near, key=abs))
    middle = median(skews) if skews else None
    return AvSync(
        flashes=len(counted),
        pairs=len(skews),
        median_ms=middle,
        min_ms=min(skews, default=None),
        max_ms=max(skews, default=None),
        skews_ms=skews,
        browser_estimate_ms=browser_estimate_ms,
        within_ebu_r37=None if middle is None else EBU_R37_LEAD_MS <= middle <= EBU_R37_LAG_MS,
    )


@dataclass(frozen=True, kw_only=True)
class Verdict:
    """The checks' outcome: what was measured, the diagnostics, and every failed check."""

    measured: dict[str, Json]
    diagnostics: dict[str, Json]
    av_sync: AvSync
    failures: list[str]
    av_sync_before: AvSync | None = None
    """With a disruption, the A/V sync of the window before it."""
    mse: dict[str, Json] | None = None
    """In an MSE case, the MSE player's report (`mse_checks`)."""
    llhls: dict[str, Json] | None = None
    """In an LL-HLS case, the LL-HLS player's report (`llhls_checks`)."""
    latency: dict[str, Json] | None = None
    """In an MSE or LL-HLS case, WebRTC's and that player's glass-to-glass latency (`latency`); a
    report."""

    def as_json(self) -> dict[str, Json]:
        """The verdict for the report."""
        return asdict(self)


def _pair(snapshot: Json) -> dict[str, Json] | None:
    """The nominated, succeeded candidate pair of a snapshot (webrtc-stats §8.19)."""
    for stats in (snapshot or {}).get("stats", []):
        if (
            stats.get("type") == "candidate-pair"
            and stats.get("nominated") is True
            and stats.get("state") == "succeeded"
        ):
            return dict(stats)
    return None


def _shown(value: Json) -> Json:
    """A diagnostic's value, or `NOT_REPORTED`."""
    return NOT_REPORTED if value is None else value


def diagnostics(page: Json) -> dict[str, Json]:
    """What some browsers report and others do not: recorded, never a failure."""
    stats = page.get("stats") or {}
    start, end = stats.get("start"), stats.get("end")
    video_start, video = inbound(start, "video"), inbound(end, "video")
    audio_start, audio = inbound(start, "audio"), inbound(end, "audio")
    by_id = {s.get("id"): s for s in (end or {}).get("stats", [])}
    transport: dict[str, Json] = next(
        (s for s in by_id.values() if s.get("type") == "transport"), {}
    )
    selected = transport.get("selectedCandidatePairId")
    pair = (by_id.get(selected) if selected else None) or _pair(end) or {}

    def codec(stats: dict[str, Json]) -> Json:
        codec_id = stats.get("codecId")
        return (by_id.get(codec_id) or {}).get("mimeType") if codec_id else None

    def per_frame(name: str) -> Json:
        return _mean_ms(
            _delta(video_start, video, name), _delta(video_start, video, "framesDecoded")
        )

    def target(start: dict[str, Json], end: dict[str, Json]) -> Json:
        return _mean_ms(
            _delta(start, end, "jitterBufferTargetDelay"),
            _delta(start, end, "jitterBufferEmittedCount"),
        )

    video_playout = _number(video, "estimatedPlayoutTimestamp")
    audio_playout = _number(audio, "estimatedPlayoutTimestamp")
    rtt = _number(pair, "currentRoundTripTime")
    values = {
        "video": {
            "codec": codec(video),
            "frame_width": video.get("frameWidth"),
            "frame_height": video.get("frameHeight"),
            "frames_per_second": video.get("framesPerSecond"),
            "processing_delay_ms": per_frame("totalProcessingDelay"),
            "decode_ms": per_frame("totalDecodeTime"),
            "jitter_buffer_target_ms": target(video_start, video),
            "decoder": video.get("decoderImplementation"),
            "frames_dropped": video.get("framesDropped"),
            "key_frames_decoded": video.get("keyFramesDecoded"),
            "nacks": video.get("nackCount"),
            "plis": video.get("pliCount"),
            "estimated_playout_timestamp": video_playout,
        },
        "audio": {
            "codec": codec(audio),
            "jitter_buffer_target_ms": target(audio_start, audio),
            "concealed_samples": audio.get("concealedSamples"),
            "total_samples_received": audio.get("totalSamplesReceived"),
            "estimated_playout_timestamp": audio_playout,
        },
        "transport_selected_candidate_pair": transport.get("selectedCandidatePairId"),
        "round_trip_ms": None if rtt is None else rtt * 1000,
        "offer_codecs": page.get("offer_codecs"),
        "ice_states": page.get("ice", {}).get("states"),
        "decoded_video_frame_callback": page.get("video", {}).get("frame_callback"),
        "capture_time": capture_times(page),
        "daemon_tracks": (page.get("stream_end") or {}).get("tracks"),
        "disruption": disruption(page),
    }
    return {
        key: {k: _shown(v) for k, v in value.items()} if isinstance(value, dict) else _shown(value)
        for key, value in values.items()
    }


def disruption(page: Json) -> dict[str, Json] | None:
    """What the disruption did and how long the recovery took, from the page; a diagnostic.

    The PLIs the browser sent from the end of the first window to the end of the second
    (`pliCount`, webrtc-stats §8.5; Chrome and Safari report it, Firefox does not, per MDN's
    browser-compat-data, checked 2026-10-07), the mean jitter-buffer delays of the first window, the
    stream's reconnects and worker restarts before and after (`stream/get`), the reason the
    server closed the session, and the times from the disruption to the recovery and, after a
    crash, from the new offer to its first frame, in ms.
    """
    done = page.get("disruption")
    if not isinstance(done, dict):
        return None
    window = (page.get("before") or {}).get("stats") or {}
    before_end = inbound(window.get("end"), "video")
    # The request leaves after the snapshot at the end of the first window, its RTCP a moment
    # later: count to the end of the second.
    plis = _delta(before_end, inbound((page.get("stats") or {}).get("end"), "video"), "pliCount")
    buffers = {}
    for kind in ("video", "audio"):
        first, last = inbound(window.get("start"), kind), inbound(window.get("end"), kind)
        buffers[f"before_{kind}_jitter_buffer_ms"] = _mean_ms(
            _delta(first, last, "jitterBufferDelay"),
            _delta(first, last, "jitterBufferEmittedCount"),
        )
    at, recovered = done.get("at"), done.get("recovered")
    before, after = done.get("before") or {}, done.get("after") or {}
    return {
        "mode": done.get("mode"),
        "keyframe_request": done.get("keyframe_request"),
        "plis_sent": plis,
        "reconnects": [before.get("reconnects"), after.get("reconnects")],
        "worker_restarts": [before.get("restarts"), after.get("restarts")],
        "closed": done.get("closed"),
        "recovery_ms": recovered - at
        if isinstance(at, int | float) and isinstance(recovered, int | float)
        else None,
        "time_to_first_frame_ms": done.get("time_to_first_frame_ms"),
        **buffers,
    }


def disruption_failures(page: Json, disrupt: str | None) -> list[str]:
    """Whether the disruption the case asks for happened, each failure as a sentence."""
    done = page.get("disruption")
    if disrupt is None:
        return [] if done is None else [f"no disruption asked, but the page did {done}"]
    if not isinstance(done, dict) or done.get("mode") != disrupt:
        return [f"a {disrupt} disruption (the page did {done})"]
    if not isinstance(done.get("recovered"), int | float):
        return [f"a recovery after the {disrupt}"]
    before, after = done.get("before") or {}, done.get("after") or {}
    match disrupt:
        case "pli":
            ok = done.get("keyframe_request") == "sent"
            failure = "the page's keyframe request sent"
        case "reconnect":
            ok = _grew(before.get("reconnects"), after.get("reconnects"))
            failure = (
                f"the stream reconnected ({before.get('reconnects')} to {after.get('reconnects')})"
            )
        case "crash":
            closed = done.get("closed")
            ok = (
                isinstance(closed, str)
                and closed.startswith("worker_crashed")
                and _grew(before.get("restarts"), after.get("restarts"))
            )
            failure = (
                f"the session closed with worker_crashed and the worker restarted (closed "
                f"{closed!r}, restarts {before.get('restarts')} to {after.get('restarts')})"
            )
        case _:
            ok, failure = False, f"a known disruption, not {disrupt!r}"
    return [] if ok else [failure]


def _grew(before: Json, after: Json) -> bool:
    """Whether a counter of the stream grew."""
    return isinstance(before, int) and isinstance(after, int) and after > before


def transcoded(page: Json) -> bool:
    """Whether the daemon played the camera's AAC as Opus: an Opus track derived from AAC."""
    tracks = (page.get("stream_end") or {}).get("tracks") or []
    by_id = {track.get("id"): track for track in tracks if isinstance(track, dict)}
    return any(
        track.get("codec") == "opus"
        and (by_id.get(track.get("derived_from")) or {}).get("codec") == "aac_lc"
        for track in by_id.values()
    )


def _rtp_ms(later: Json, earlier: Json) -> float:
    """How far `later` is from `earlier` on the 32-bit video RTP clock, in ms, either way."""
    if not isinstance(later, int) or not isinstance(earlier, int):
        return 0.0
    ticks = (later - earlier) % (1 << 32)
    if ticks >= 1 << 31:
        ticks -= 1 << 32
    return ticks / VIDEO_RTP_TICKS_PER_MS


def _median_of(values: list[float]) -> float | None:
    """The median, or `None` without values."""
    return median(values) if values else None


def _capture_to_render(sample: Json) -> tuple[float, float] | None:
    """A capture sample's frame shown, on the wall clock, and its capture-to-render time, in ms.

    `None` without its capture time or its time shown. See `capture_times`.
    """
    if not isinstance(sample, dict):
        return None
    capture, shown = sample.get("capture"), sample.get("shown")
    if not isinstance(capture, int | float) or not isinstance(shown, int | float):
        return None
    frame = (
        capture - NTP_UNIX_OFFSET_MS + _rtp_ms(sample.get("frame_rtp"), sample.get("source_rtp"))
    )
    return shown, shown - frame


def capture_times(page: Json) -> dict[str, Json]:
    """Where the frames shown spent their time, from their capture time; a diagnostic.

    Each sample is a frame the page presented over the play time, with the video receiver's
    synchronization source as it was then (the page): its `captureTimestamp` is the capture time
    of the last frame delivered to the track, carried by the abs-capture-time extension or
    interpolated by RTP timestamp (webrtc-extensions), which the frame's own RTP timestamp moves to
    the frame shown. The daemon puts the capture time on the host's wall clock and the page's
    times are on it too, so the differences hold where both run on one host, as in the test; the
    sender's offset (`senderCaptureTimeOffset`) is recorded, not applied. The medians, in ms:

    - capture to receive: the daemon and the network (the frame's last packet, `receiveTime`);
    - receive to render: the browser's whole share, jitter buffer, decode and render
      (`expectedDisplayTime`);
    - capture to render: all of it from the moment the daemon took the frame in;
    - capture to delivery: to the frame's delivery to the track, the synchronization source's
      own `timestamp`.
    """
    samples = [s for s in (page.get("video") or {}).get("capture") or [] if isinstance(s, dict)]
    to_receive, to_render, receive_to_render, to_delivery = [], [], [], []
    for sample in samples:
        capture = sample.get("capture")
        if not isinstance(capture, int | float):
            continue
        source = capture - NTP_UNIX_OFFSET_MS
        frame = source + _rtp_ms(sample.get("frame_rtp"), sample.get("source_rtp"))
        shown, received, delivered = (sample.get(k) for k in ("shown", "received", "delivered"))
        if isinstance(shown, int | float):
            to_render.append(shown - frame)
        if isinstance(received, int | float):
            to_receive.append(received - frame)
            if isinstance(shown, int | float):
                receive_to_render.append(shown - received)
        if isinstance(delivered, int | float):
            to_delivery.append(delivered - source)
    offsets = [s.get("offset") for s in samples if isinstance(s.get("offset"), int | float)]
    answered = page.get("answer_extensions") or {}
    return {
        "asked": page.get("capture_time"),
        "negotiated": {
            kind: any(line.endswith(ABS_CAPTURE_TIME) for line in lines)
            for kind, lines in answered.items()
        },
        "frames": len(samples),
        "frames_without": (page.get("video") or {}).get("no_capture_time", 0),
        "capture_to_receive_ms": _median_of(to_receive),
        "receive_to_render_ms": _median_of(receive_to_render),
        "capture_to_render_ms": _median_of(to_render),
        "capture_to_delivery_ms": _median_of(to_delivery),
        "sender_capture_time_offset_ms": offsets[-1] if offsets else None,
    }


def _percentile(values: list[float], share: float) -> float | None:
    """The nearest-rank percentile `share` of `values`; `None` without values."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(math.ceil(share * len(ordered)), 1)
    return ordered[rank - 1]


def _spread(values: list[float]) -> dict[str, Json]:
    """The median and the `LATENCY_PERCENTILE` of `values`, and how many there are."""
    return {
        "median": _median_of(values),
        "p90": _percentile(values, LATENCY_PERCENTILE),
        "count": len(values),
    }


def _window(page: Json) -> tuple[float, float]:
    """The play window the checks take, on the page's clock, in ms: its two stats snapshots."""
    stats = page.get("stats") or {}
    start, end = stats.get("start") or {}, stats.get("end") or {}
    return float(start.get("at", 0.0)), float(end.get("at", math.inf))


@dataclass(frozen=True, kw_only=True)
class Player:
    """A player the page runs beside the WebRTC session, as its checks and report name it."""

    key: str
    """Its part of the page's result, and the prefix of its measurements (`mse`, `llhls`)."""
    label: str
    """Its name in a sentence."""
    output: str
    """What the daemon serves it, in a sentence."""
    close: str
    """The command that ends that output."""


MSE = Player(key="mse", label="MSE", output="the live output", close="live/close")
"""Live fMP4 through the browser's Media Source Extensions (`live/create`)."""

LLHLS = Player(key="llhls", label="LL-HLS", output="the LL-HLS session", close="hls/close")
"""LL-HLS through hls.js, or the browser's own HLS (`hls/create`)."""

PLAYERS = {player.key: player for player in (MSE, LLHLS)}
"""Each player by its key."""


def _player_flashes(page: Json, player: Player) -> list[dict[str, Json]]:
    """The flashes `player`'s element showed within the play window."""
    low, high = _window(page)
    flashes = ((page.get(player.key) or {}).get("video") or {}).get("flashes") or []
    return [
        f
        for f in flashes
        if isinstance(f, dict) and isinstance(f.get("at"), int | float) and low <= f["at"] <= high
    ]


def latency(page: Json, stream: Stream, player: Player = MSE) -> dict[str, Json]:
    """Glass-to-glass latency of WebRTC and of `player`, side by side on one page; a report.

    WebRTC's is each frame's capture to render (`capture_times`), over the frames the page sampled:
    from the moment the daemon took the frame in, the capture time it stamps, so the camera's own
    encoder and MediaMTX are not in it, for either path.
    Each flash `player` showed within the play window is paired with the WebRTC flash of the same
    second: the one nearest to where the flash's distance from the end of its buffer
    (`behind_ms`) and the one frame the output holds each frame put it, within
    `MSE_PAIR_WITHIN_MS`, since the flashes are a second apart and the player's picture is later
    than WebRTC's by some fraction of one or more. An LL-HLS part reaches the buffer whole, a part
    after its first frame, and the buffer's end is then that part's end, so the two cancel. Its
    latency is that WebRTC flash's capture to render plus how much later the player's flash was
    shown. Without `captureTimestamp` (Firefox and Safari do not report it), only the difference.
    """
    clock = page.get("clock") or {}
    origin = (clock.get("time_origin") or 0.0) + (clock.get("t0") or 0.0)
    samples = [
        timed
        for timed in map(_capture_to_render, (page.get("video") or {}).get("capture") or [])
        if timed
    ]
    by_shown = dict(samples)
    webrtc = [delay for _, delay in samples]
    webrtc_flashes = [
        at for at in (page.get("video") or {}).get("flashes") or [] if isinstance(at, int | float)
    ]
    held_ms = 1000 / stream.fps
    differences, delays = [], []
    for flash in _player_flashes(page, player):
        behind = flash.get("behind_ms")
        expected = flash["at"] - (behind if isinstance(behind, int | float) else 0.0) - held_ms
        near = [w for w in webrtc_flashes if abs(w - expected) <= MSE_PAIR_WITHIN_MS]
        if not near:
            continue
        paired = min(near, key=lambda w: abs(w - expected))
        difference = flash["at"] - paired
        differences.append(difference)
        # The WebRTC flash's own frame among the capture samples: the same time shown.
        shown = origin + paired
        own = next((d for at, d in by_shown.items() if abs(at - shown) < 1.0), None)
        if own is not None:
            delays.append(own + difference)
    return {
        "player": player.key,
        "method": f"glass to glass: WebRTC by captureTimestamp, {player.label} by its flashes "
        "against WebRTC's on the same page"
        if webrtc
        else f"{player.label} minus WebRTC only: the browser reports no captureTimestamp",
        "webrtc_ms": _spread(webrtc) if webrtc else None,
        f"{player.key}_ms": _spread(delays) if delays else None,
        f"{player.key}_minus_webrtc_ms": _spread(differences),
        f"{player.key}_flashes": len(_player_flashes(page, player)),
    }


def latency_summary(report: dict[str, Json]) -> str:
    """The latency report in a few words: each path's median and p90, in ms."""
    player = PLAYERS[report.get("player") or MSE.key]

    def spread(name: str) -> str:
        value = report.get(name)
        if not isinstance(value, dict) or value.get("median") is None:
            return "none"
        return f"{value['median']:.0f} ms (p90 {value['p90']:.0f}, {value['count']})"

    return (
        f"WebRTC {spread('webrtc_ms')}, {player.label} {spread(f'{player.key}_ms')}, "
        f"{player.label} minus WebRTC {spread(f'{player.key}_minus_webrtc_ms')}"
    )


def _expected_mime(stream: Stream) -> tuple[str | None, bool]:
    """The audio codec the output's type must name, and whether `audio_omitted` is due.

    The codec as it names the camera's audio, `None` for none.

    The live container, which an LL-HLS session's segments are cut from, carries AAC-LC (RFC 6381
    `mp4a.40.2`) and Opus (its sample entry `Opus`, Opus in ISOBMFF §4.3) as the camera sends them
    and leaves anything else out with the warning.
    """
    match stream.audio_codec:
        case "MPEG4-GENERIC":
            return "mp4a.40.2", False
        case "opus":
            return "opus", False
        case "none":
            return None, False
        case _:
            return None, True


def _codecs(mime: str) -> list[str]:
    """The entries of a MIME type's `codecs` parameter (RFC 6381 §3)."""
    match = re.search(r'codecs="([^"]*)"', mime)
    return [c.strip() for c in match.group(1).split(",")] if match else []


def _player_gates(
    page: Json, stream: Stream, player: Player, first_mime: str
) -> tuple[dict[str, Json], list[str]]:
    """What every player beside the WebRTC session is gated on: what is measured, and each failure.

    That the picture plays (its frames advance at `TWO_ELEMENTS_FRAMES_SHOWN_SHARE` of the camera's
    or more, never stalling longer than `MSE_STALL_MS`, with the flashes), that the page reports
    no error of it, that the type the daemon first gave (`first_mime`, before any retry without
    the audio) names the camera's audio as the container takes it, and that the output ended by
    its close command.
    """
    played = page.get(player.key) or {}
    failures = [f"{player.label}: {error}" for error in played.get("errors") or []]
    low, high = _window(page)
    play_s = (high - low) / 1000 if math.isfinite(high) else 0.0
    camera_frames = stream.fps * play_s
    frames = [
        at
        for at in (played.get("video") or {}).get("frames") or []
        if isinstance(at, int | float) and low <= at <= high
    ]
    edges = [low, *frames, high] if math.isfinite(high) else frames
    gap = max((b - a for a, b in itertools.pairwise(edges)), default=None)
    flashes = _player_flashes(page, player)
    measured: dict[str, Json] = {
        f"{player.key}_frames_shown": len(frames),
        f"{player.key}_longest_gap_ms": gap,
        f"{player.key}_flashes": len(flashes),
    }
    if len(frames) < TWO_ELEMENTS_FRAMES_SHOWN_SHARE * camera_frames or not frames:
        failures.append(
            f"{player.label} frames shown at {TWO_ELEMENTS_FRAMES_SHOWN_SHARE:.0%} of the camera's "
            f"{camera_frames:.0f} or more (got {len(frames)})"
        )
    if gap is None or gap > MSE_STALL_MS:
        failures.append(
            f"{player.label} never without a new frame for over {MSE_STALL_MS:.0f} ms (got {gap})"
        )
    wanted = math.floor(play_s * FLASH_SHARE)
    if len(flashes) < wanted or not flashes:
        failures.append(
            f"a flash a second seen through {player.label}, {wanted} or more (got {len(flashes)})"
        )
    codecs = [c.lower() for c in _codecs(first_mime)]
    audio, omitted = _expected_mime(stream)
    warnings = played.get("warnings") or []
    if audio is not None and audio not in codecs[1:]:
        failures.append(f"{player.output}'s type names the camera's {audio} (got {first_mime!r})")
    if audio is None and len(codecs) != 1:
        failures.append(f"{player.output}'s type names the video alone (got {first_mime!r})")
    if omitted != ("audio_omitted" in warnings):
        failures.append(
            f"an audio_omitted warning {'' if omitted else 'not '}sent (got {warnings})"
        )
    closed = played.get("closed") or {}
    if closed.get("reason") != "closed":
        failures.append(f"{player.output} closed by {player.close} (got {closed or None})")
    return measured, failures


def _sound(page: Json, player: Player) -> dict[str, Json]:
    """What the page heard of `player`'s element: a report, with its A/V skew."""
    played = page.get(player.key) or {}
    sound = played.get("audio") or {}
    beeps = [b for b in sound.get("beeps") or [] if isinstance(b, int | float)]
    sync = av_sync(
        [f["at"] for f in _player_flashes(page, player)],
        beeps,
        (page.get("timings") or {}).get("first_frame", 0.0),
        None,
    )
    end = played.get("end") or {}
    return {
        "in_output": len(_codecs(played.get("mime") or "")) > 1,
        "tap": sound.get("tap"),
        "heard": (sound.get("peak") or 0.0) > BEEP_PEAK,
        "peak": sound.get("peak"),
        "beeps": len(beeps),
        "av_sync_median_ms": sync.median_ms,
        "av_sync_pairs": sync.pairs,
        "decoded_bytes": end.get("audio_decoded_bytes"),
        "moz_has_audio": end.get("moz_has_audio"),
        "audio_tracks": end.get("audio_tracks"),
    }


def mse_checks(page: Json, stream: Stream) -> tuple[dict[str, Json], dict[str, Json], list[str]]:
    """The MSE player's checks: what is measured, the report, and each failure as a sentence.

    Gated only that the picture plays (see the module) and that the output's MIME type names the
    camera's audio as the container takes it; the rest is the report.
    """
    mse = page.get("mse")
    if not isinstance(mse, dict):
        return {}, {}, ["the page played no live fMP4 through MSE"]
    measured, failures = _player_gates(
        page, stream, MSE, mse.get("refused_mime") or mse.get("mime") or ""
    )
    report = {
        "api": mse.get("api"),
        "mime": mse.get("mime"),
        "refused_mime": mse.get("refused_mime"),
        "content_type": mse.get("content_type"),
        "is_type_supported": mse.get("support"),
        "warnings": mse.get("warnings") or [],
        "audio": _sound(page, MSE),
        "frame_callback": (mse.get("video") or {}).get("frame_callback"),
        "appends": mse.get("appends"),
        "bytes": mse.get("bytes"),
        "seeks": mse.get("seeks"),
        "catch_ups": mse.get("catch_ups"),
        "waiting": mse.get("waiting"),
        "removes": mse.get("removes"),
        "quota_exceeded": mse.get("quota_exceeded"),
        "timings": mse.get("timings"),
        "jumped_to": mse.get("jumped_to"),
        "end": mse.get("end"),
        "closed": mse.get("closed"),
    }
    return measured, report, failures


def _seconds_spread(page: Json, samples: list[Json], name: str) -> dict[str, Json]:
    """The spread (`_spread`) of field `name` of the samples taken within the play window."""
    low, high = _window(page)
    values = [
        sample[name]
        for sample in samples
        if isinstance(sample, dict)
        and isinstance(sample.get("at"), int | float)
        and low <= sample["at"] <= high
        and isinstance(sample.get(name), int | float)
    ]
    return _spread(values)


def llhls_checks(page: Json, stream: Stream) -> tuple[dict[str, Json], dict[str, Json], list[str]]:
    """The LL-HLS player's checks: what is measured, the report, and each failure as a sentence.

    Gated as the MSE player is (`_player_gates`): no fatal hls.js error, the picture plays, the
    session's type names the camera's audio, `closed` after `hls/close`. The rest is the report:
    which path played (hls.js, or the browser's own HLS), what hls.js and the browser said of the
    type, the playlist's part target and hold-back as hls.js read them, its own latency estimate
    and target over the play window, its stalls and non-fatal errors, a refused `play()` (the
    frames tell whether it played), and whether the sound was heard.
    """
    llhls = page.get("llhls")
    if not isinstance(llhls, dict):
        return {}, {}, ["the page played no LL-HLS"]
    refused_by_hlsjs = llhls.get("refused_by_hlsjs") or {}
    first_mime = (
        llhls.get("refused_mime") or refused_by_hlsjs.get("mime") or llhls.get("mime") or ""
    )
    measured, failures = _player_gates(page, stream, LLHLS, first_mime)
    samples = llhls.get("samples") or []
    report = {
        "path": llhls.get("path"),
        "hlsjs": llhls.get("hlsjs"),
        "native": llhls.get("native"),
        "api": llhls.get("api"),
        "levels": llhls.get("levels"),
        "buffer_codecs": llhls.get("buffer_codecs"),
        "playlist": llhls.get("playlist"),
        "mime": llhls.get("mime"),
        "refused_mime": llhls.get("refused_mime"),
        "refused_by_hlsjs": llhls.get("refused_by_hlsjs"),
        "is_type_supported": llhls.get("support"),
        "warnings": llhls.get("warnings") or [],
        "audio": _sound(page, LLHLS),
        "frame_callback": (llhls.get("video") or {}).get("frame_callback"),
        "hls_latency_s": _seconds_spread(page, samples, "latency_s"),
        "target_latency_s": _seconds_spread(page, samples, "target_latency_s"),
        "samples": samples,
        "stalls": llhls.get("stalls"),
        "waiting": llhls.get("waiting"),
        "hls_errors": llhls.get("hls_errors") or [],
        "play_errors": llhls.get("play_errors") or [],
        "parts": llhls.get("parts"),
        "segments": llhls.get("segments"),
        "playlist_loads": llhls.get("playlist_loads"),
        "timings": llhls.get("timings"),
        "end": llhls.get("end"),
        "closed": llhls.get("closed"),
    }
    return measured, report, failures


def _browser_estimate(page: Json) -> float | None:
    """The browser's own A/V skew, where it reports one.

    Video playout minus audio playout on the sender's clock (`estimatedPlayoutTimestamp`,
    webrtc-stats §8.5).
    """
    end = (page.get("stats") or {}).get("end")
    video = _number(inbound(end, "video"), "estimatedPlayoutTimestamp")
    audio = _number(inbound(end, "audio"), "estimatedPlayoutTimestamp")
    if video is None or audio is None:
        return None
    return video - audio


def jitter_buffer_bound_ms(kind: str, engine: str | None) -> float:
    """The bound on the mean jitter-buffer delay of `kind` in the browser `engine`, in ms."""
    if kind == "audio" and engine == "safari":
        return SAFARI_AUDIO_JITTER_BUFFER_MS
    return JITTER_BUFFER_MS[kind]


def check(  # noqa: PLR0915 -- one check after another
    page: Json,
    stream: Stream,
    disrupt: str | None = None,
    engine: str | None = None,
    *,
    player: str | None = None,
) -> Verdict:
    """The checks on what the page measured; each failed one as a sentence.

    With `disrupt`, the case's disruption (`harness.Case.disrupt`), the window after the recovery;
    `engine` is the browser (`chrome`, `firefox`, `safari`) where a bound depends on it; with
    `player` (`harness.Case.player`), that player's checks (`mse_checks`, `llhls_checks`) and the
    latency report as well.
    """
    failures = [f"the page: {error}" for error in page.get("errors", [])]
    failures += disruption_failures(page, disrupt)
    if stream.audio_codec == "MPEG4-GENERIC" and page.get("stream_end") is not None:
        failures += [] if transcoded(page) else ["an Opus track transcoded from the camera's AAC"]
    measured: dict[str, Json] = {}

    def expect(ok: bool, failure: str) -> None:  # noqa: FBT001 -- a condition and its sentence
        if not ok:
            failures.append(failure)

    stats = page.get("stats") or {}
    start, end = stats.get("start"), stats.get("end")
    play_s = (
        (end["at"] - start["at"]) / 1000 if start and end and "at" in start and "at" in end else 0.0
    )
    measured["play_s"] = play_s
    video_page = page.get("video", {})
    audio_page = page.get("audio", {})

    # What a viewer sees.
    ttff = page.get("time_to_first_frame_ms")
    measured["time_to_first_frame_ms"] = ttff
    expect(
        isinstance(ttff, int | float) and ttff <= FIRST_FRAME_MS,
        f"first frame within {FIRST_FRAME_MS:.0f} ms of the offer (got {ttff})",
    )
    camera_frames = stream.fps * play_s
    shown = (video_page.get("presented_at_end") or 0) - (video_page.get("presented_at_start") or 0)
    measured["frames_shown"] = shown
    share = TWO_ELEMENTS_FRAMES_SHOWN_SHARE if player else FRAMES_SHOWN_SHARE
    expect(
        shown > 0 and shown >= share * camera_frames,
        f"frames shown at {share:.0%} of the camera's {camera_frames:.0f} or more (got {shown})",
    )
    size = (video_page.get("width"), video_page.get("height"))
    measured["picture"] = f"{size[0]}x{size[1]}"
    expect(
        size == (stream.width, stream.height),
        f"a {stream.width}x{stream.height} picture (got {size[0]}x{size[1]})",
    )
    luma = (video_page.get("luma_min", 255.0), video_page.get("luma_max", 0.0))
    measured["luma"] = list(luma)
    expect(
        luma[0] < LUMA_DARK and luma[1] > LUMA_BRIGHT,
        f"black and white frames shown (luma {luma[0]:.0f} to {luma[1]:.0f})",
    )
    window = (
        start.get("at", 0.0) if start else 0.0,
        end.get("at", math.inf) if end else math.inf,
    )
    every_flash = video_page.get("flashes", [])
    flashes = [at for at in every_flash if window[0] <= at <= window[1]]
    measured["flashes"] = len(flashes)
    flashes_wanted = math.floor(play_s * FLASH_SHARE)
    expect(
        len(flashes) >= flashes_wanted and len(flashes) > 0,
        f"a flash a second seen, {flashes_wanted} or more (got {len(flashes)})",
    )

    # What a viewer hears.
    peak = audio_page.get("peak", 0.0)
    measured["beep_peak"] = peak
    expect(peak > BEEP_PEAK, f"the beep heard, peak above {BEEP_PEAK} (got {peak:.3f})")
    first_frame = page.get("timings", {}).get("first_frame", 0.0)
    beeps = audio_page.get("beeps", [])
    done = page.get("disruption") if disrupt is not None else None
    settled_from = first_frame
    sync_before = None
    if isinstance(done, dict):
        at = done.get("at", 0.0)
        sync_before = av_sync(
            [flash for flash in every_flash if flash < at],
            beeps,
            first_frame + SYNC_SETTLE_MS,
            None,
        )
        settled_from = done.get("recovered", at)
    sync = av_sync(flashes, beeps, settled_from + SYNC_SETTLE_MS, _browser_estimate(page))
    expect(
        sync.flashes > 0 and sync.pairs * 2 >= sync.flashes,
        f"a beep with half the flashes or more (got {sync.pairs} of {sync.flashes})",
    )

    # The connection and trickle ICE both ways.
    ice = page.get("ice", {})
    sent, received = ice.get("local_candidates_sent", 0), ice.get("remote_candidates", 0)
    ends = (ice.get("local_end_sent"), ice.get("remote_end"))
    expect(
        sent >= 1 and received >= 1 and ends == (True, True),
        f"candidates trickled both ways with their ends (sent {sent}, received {received}, "
        f"ends {ends})",
    )
    state = page.get("connection_state")
    measured["connection_state"] = state
    expect(state == "connected", f"the connection connected (state {state!r})")
    pair = _pair(end)
    measured["nominated_pair"] = pair is not None
    expect(pair is not None, "a nominated, succeeded candidate pair in getStats()")

    # The stats every browser reports, the same way for each.
    video_start, video = inbound(start, "video"), inbound(end, "video")
    audio_start, audio = inbound(start, "audio"), inbound(end, "audio")
    expect(bool(video), "inbound-rtp stats of the video")
    expect(bool(audio), "inbound-rtp stats of the audio")
    decoded = _delta(video_start, video, "framesDecoded")
    measured["frames_decoded"] = decoded
    expect(
        decoded is not None and decoded >= RATE_SHARE * camera_frames,
        f"framesDecoded at {RATE_SHARE:.0%} of the camera's {camera_frames:.0f} or more "
        f"(got {decoded})",
    )
    wanted = {
        "video": stream.fps * play_s,  # one packet a frame at least
        "audio": stream.audio_packets_per_second * play_s,
    }
    for kind, (first, last) in {
        "video": (video_start, video),
        "audio": (audio_start, audio),
    }.items():
        packets = _delta(first, last, "packetsReceived")
        measured[f"{kind}_packets_received"] = packets
        expect(
            packets is not None and packets >= RATE_SHARE * wanted[kind],
            f"{kind} packetsReceived at {RATE_SHARE:.0%} of {wanted[kind]:.0f} or more "
            f"(got {packets})",
        )
        total, lost = _number(last, "packetsReceived"), _number(last, "packetsLost")
        measured[f"{kind}_packets_lost"] = lost
        allowed = MAX_LOSS * ((total or 0) + max(lost or 0, 0))
        expect(
            lost is not None and lost <= allowed,
            f"{kind} packetsLost at most {MAX_LOSS:.1%} of the packets (got {lost} of {total})",
        )
        buffer_ms = _mean_ms(
            _delta(first, last, "jitterBufferDelay"),
            _delta(first, last, "jitterBufferEmittedCount"),
        )
        measured[f"{kind}_jitter_buffer_ms"] = buffer_ms
        bound = jitter_buffer_bound_ms(kind, engine)
        expect(
            buffer_ms is not None and 0 < buffer_ms <= bound,
            f"a mean {kind} jitter-buffer delay above 0 and at most {bound:.0f} ms "
            f"(got {buffer_ms})",
        )
    processing_ms = _mean_ms(_delta(video_start, video, "totalProcessingDelay"), decoded)
    buffer_ms = measured["video_jitter_buffer_ms"]
    beyond = None if processing_ms is None or buffer_ms is None else processing_ms - buffer_ms
    measured["video_beyond_jitter_buffer_ms"] = beyond
    beyond_bound = BEYOND_JITTER_BUFFER_FRAMES * 1000 / stream.fps
    expect(
        beyond is not None and beyond <= beyond_bound,
        f"a mean video processing delay beyond the jitter buffer of at most {beyond_bound:.0f} ms, "
        f"a frame interval (got {beyond})",
    )
    level = _number(audio, "audioLevel")
    measured["audio_level"] = level
    expect(level is not None and 0 <= level <= 1, f"an audioLevel within 0 to 1 (got {level})")
    energy = _delta(audio_start, audio, "totalAudioEnergy")
    energy_wanted = ENERGY_SHARE * stream.beep_energy_per_second() * play_s
    measured["audio_energy"] = energy
    expect(
        energy is not None and energy >= energy_wanted,
        f"totalAudioEnergy of the beeps, {energy_wanted:.4f} or more (got {energy})",
    )
    reports: dict[str, Json] = {}
    latencies = None
    if player is not None:
        player_checks = {MSE.key: mse_checks, LLHLS.key: llhls_checks}[player]
        player_measured, reports[player], player_failures = player_checks(page, stream)
        measured |= player_measured
        failures += player_failures
        latencies = latency(page, stream, PLAYERS[player])
    return Verdict(
        measured=measured,
        diagnostics=diagnostics(page),
        av_sync=sync,
        failures=failures,
        av_sync_before=sync_before,
        mse=reports.get(MSE.key),
        llhls=reports.get(LLHLS.key),
        latency=latencies,
    )

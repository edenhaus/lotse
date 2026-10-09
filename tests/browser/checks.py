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
"""

from __future__ import annotations

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


def check(  # noqa: PLR0915 -- one check after another
    page: Json, stream: Stream, disrupt: str | None = None
) -> Verdict:
    """The checks on what the page measured; each failed one as a sentence.

    With `disrupt`, the case's disruption (`harness.Case.disrupt`), the window after the recovery.
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
    expect(
        shown > 0 and shown >= FRAMES_SHOWN_SHARE * camera_frames,
        f"frames shown at {FRAMES_SHOWN_SHARE:.0%} of the camera's {camera_frames:.0f} or more "
        f"(got {shown})",
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
        expect(
            buffer_ms is not None and 0 < buffer_ms <= JITTER_BUFFER_MS[kind],
            f"a mean {kind} jitter-buffer delay above 0 and at most "
            f"{JITTER_BUFFER_MS[kind]:.0f} ms (got {buffer_ms})",
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
    return Verdict(
        measured=measured,
        diagnostics=diagnostics(page),
        av_sync=sync,
        failures=failures,
        av_sync_before=sync_before,
    )

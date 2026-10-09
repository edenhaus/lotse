"""The checks' unit tests: no browser, the page's result written by hand."""

from __future__ import annotations

import copy
from typing import Any

import pytest

import checks
from checks import (
    NOT_REPORTED,
    Stream,
    av_sync,
    capture_times,
    check,
    diagnostics,
    disruption_failures,
    parse_duration,
    transcoded,
)

STREAM = Stream.from_json(
    {
        "width": 640,
        "height": 480,
        "fps": 30,
        "flash_frames": 3,
        "audio_codec": "PCMU",
        "audio_packets_per_second": 50,
        "beep_hz": 1000,
        "beep_packets": 5,
        "beep_peak_milli": 250,
        "ignored": True,
    }
)


def snapshot(at: float, frames: int, audio_packets: int, energy: float) -> dict[str, Any]:
    """Stats as Chrome reported them on 2026-10-06, scaled to `frames` and `audio_packets`."""
    return {
        "at": at,
        "stats": [
            {"id": "T01", "type": "transport", "selectedCandidatePairId": "CP1"},
            {
                "id": "CP1",
                "type": "candidate-pair",
                "nominated": True,
                "state": "succeeded",
                "currentRoundTripTime": 0.001,
            },
            {"id": "CP2", "type": "candidate-pair", "nominated": False, "state": "succeeded"},
            {"id": "CV", "type": "codec", "mimeType": "video/H264"},
            {"id": "CA", "type": "codec", "mimeType": "audio/PCMU"},
            {
                "type": "inbound-rtp",
                "kind": "video",
                "codecId": "CV",
                "packetsReceived": frames * 11 // 10,
                "packetsLost": 0,
                "framesDecoded": frames,
                "jitterBufferDelay": frames * 0.010,
                "jitterBufferEmittedCount": frames,
                "jitterBufferTargetDelay": frames * 0.014,
                "totalProcessingDelay": frames * 0.0115,
                "totalDecodeTime": frames * 0.0012,
                "frameWidth": 640,
                "frameHeight": 480,
                "framesPerSecond": 30,
                "estimatedPlayoutTimestamp": 4_000_311_514_398,
            },
            {
                "type": "inbound-rtp",
                "kind": "audio",
                "codecId": "CA",
                "packetsReceived": audio_packets,
                "packetsLost": 0,
                "jitterBufferDelay": audio_packets * 160 * 0.042,
                "jitterBufferEmittedCount": audio_packets * 160,
                "audioLevel": 0.0,
                "totalAudioEnergy": energy,
                "estimatedPlayoutTimestamp": 4_000_311_514_354,
            },
        ],
    }


def good_page() -> dict[str, Any]:
    """A page that played 20 s as the camera sent it."""
    return {
        "errors": [],
        "time_to_first_frame_ms": 37,
        "timings": {"first_frame": 2_000.0},
        "video": {
            "presented_at_start": 10,
            "presented_at_end": 601,
            "width": 640,
            "height": 480,
            "luma_min": 0.0,
            "luma_max": 255.0,
            "flashes": [2_000.0 + 1_000 * s for s in range(20)],
            "frame_callback": "requestVideoFrameCallback",
        },
        "audio": {
            "peak": 0.26,
            "beeps": [2_050.0 + 1_000 * s for s in range(20)],
        },
        "ice": {
            "local_candidates_sent": 2,
            "local_end_sent": True,
            "remote_candidates": 1,
            "remote_end": True,
            "states": ["2864 connected"],
        },
        "connection_state": "connected",
        "offer_codecs": {"video": ["H264"]},
        "stats": {
            "start": snapshot(2_000.0, 10, 20, 0.01),
            "end": snapshot(22_000.0, 610, 1_020, 0.29),
        },
    }


def test_a_page_that_played_passes() -> None:
    verdict = check(good_page(), STREAM)
    assert verdict.failures == []
    assert verdict.measured["play_s"] == 20.0
    assert verdict.measured["frames_shown"] == 591
    assert verdict.measured["frames_decoded"] == 600
    assert verdict.measured["audio_packets_received"] == 1_000
    assert verdict.measured["video_jitter_buffer_ms"] == pytest.approx(10.0)
    assert verdict.measured["video_beyond_jitter_buffer_ms"] == pytest.approx(1.5)
    assert verdict.measured["audio_jitter_buffer_ms"] == pytest.approx(42.0)
    assert verdict.measured["audio_energy"] == pytest.approx(0.28)
    assert verdict.av_sync.pairs == 17, "the flashes of the first 3 s are left out"
    assert verdict.av_sync.median_ms == 50.0
    assert verdict.av_sync.browser_estimate_ms == 44.0
    assert verdict.as_json()["av_sync"]["within_ebu_r37"] is True


def set_path(page: dict[str, Any], path: str, value: object) -> None:
    """Sets `/a/b/0/c` in the page; a number indexes a list, `kind=video` finds that stats."""
    *parents, last = path.strip("/").split("/")
    node: Any = page
    for key in parents:
        if key.startswith("kind="):
            node = next(s for s in node if s.get("kind") == key.removeprefix("kind="))
        else:
            node = node[int(key)] if key.isdigit() else node[key]
    if value is None:
        del node[last]
    else:
        node[last] = value


END_VIDEO = "/stats/end/stats/kind=video"
END_AUDIO = "/stats/end/stats/kind=audio"


@pytest.mark.parametrize(
    ("path", "value", "failure"),
    [
        ("/errors", ["no answer"], "the page: no answer"),
        ("/time_to_first_frame_ms", 6_000, "first frame within 5000 ms"),
        ("/video/presented_at_end", 400, "frames shown at 80%"),
        ("/video/height", 360, "a 640x480 picture (got 640x360)"),
        ("/video/luma_max", 100.0, "black and white frames shown"),
        ("/video/flashes", [5_000.0 + 1_000 * s for s in range(12)], "a flash a second seen"),
        ("/audio/peak", 0.05, "the beep heard"),
        ("/audio/beeps", [], "a beep with half the flashes or more (got 0 of 17)"),
        ("/ice/remote_end", False, "candidates trickled both ways"),
        ("/connection_state", "failed", "the connection connected"),
        ("/stats/end/stats/1/nominated", False, "a nominated, succeeded candidate pair"),
        (f"{END_VIDEO}/framesDecoded", 300, "framesDecoded at 90%"),
        (f"{END_VIDEO}/packetsReceived", 300, "video packetsReceived at 90%"),
        (f"{END_AUDIO}/packetsReceived", 500, "audio packetsReceived at 90%"),
        (f"{END_AUDIO}/packetsLost", 2, "audio packetsLost at most 0.1%"),
        (f"{END_VIDEO}/packetsLost", None, "video packetsLost at most 0.1%"),
        (f"{END_VIDEO}/jitterBufferDelay", 610 * 0.2, "a mean video jitter-buffer delay"),
        (f"{END_VIDEO}/totalProcessingDelay", 610 * 0.05, "a mean video processing delay beyond"),
        (f"{END_VIDEO}/totalProcessingDelay", None, "a mean video processing delay beyond"),
        (f"{END_AUDIO}/jitterBufferEmittedCount", None, "a mean audio jitter-buffer delay"),
        (f"{END_AUDIO}/audioLevel", 1.5, "an audioLevel within 0 to 1"),
        (f"{END_AUDIO}/totalAudioEnergy", 0.02, "totalAudioEnergy of the beeps"),
    ],
)
def test_each_shortfall_fails_alone(path: str, value: object, failure: str) -> None:
    page = good_page()
    set_path(page, path, value)
    failures = check(page, STREAM).failures
    assert len(failures) == 1, failures
    assert failures[0].startswith(failure), failures


def test_one_lost_packet_in_a_thousand_passes() -> None:
    page = good_page()
    set_path(page, f"{END_AUDIO}/packetsLost", 1)
    assert check(page, STREAM).failures == []


def test_a_page_that_measured_nothing_fails_every_check() -> None:
    verdict = check({}, STREAM)
    assert verdict.measured["play_s"] == 0.0
    assert len(verdict.failures) == 22, verdict.failures
    assert "inbound-rtp stats of the video" in verdict.failures
    assert verdict.diagnostics["video"]["frame_width"] == NOT_REPORTED


def test_what_some_browsers_report_is_a_diagnostic() -> None:
    found = diagnostics(good_page())
    assert found["video"]["codec"] == "video/H264"
    assert found["video"]["frame_width"] == 640
    assert found["video"]["processing_delay_ms"] == pytest.approx(11.5)
    assert found["video"]["decode_ms"] == pytest.approx(1.2)
    assert found["video"]["jitter_buffer_target_ms"] == pytest.approx(14.0)
    assert found["audio"]["codec"] == "audio/PCMU"
    assert found["transport_selected_candidate_pair"] == "CP1"
    assert found["round_trip_ms"] == pytest.approx(1.0)
    assert found["offer_codecs"] == {"video": ["H264"]}
    # A browser without them (Safari: no frameWidth, no totalDecodeTime in MDN's list; Firefox
    # before 153: no selectedCandidatePairId) passes and shows "not reported".
    page = good_page()
    for key in ("frameWidth", "totalDecodeTime", "estimatedPlayoutTimestamp"):
        set_path(page, f"{END_VIDEO}/{key}", None)
    set_path(page, "/stats/end/stats/0/selectedCandidatePairId", None)
    found = diagnostics(page)
    assert found["video"]["frame_width"] == NOT_REPORTED
    assert found["video"]["decode_ms"] == NOT_REPORTED
    assert found["transport_selected_candidate_pair"] == NOT_REPORTED
    assert found["round_trip_ms"] == pytest.approx(1.0), "the nominated pair instead"
    verdict = check(page, STREAM)
    assert verdict.failures == []
    assert verdict.av_sync.browser_estimate_ms is None


def test_flashes_pair_with_the_nearest_beep_within_400_ms() -> None:
    sync = av_sync(
        [1_000.0, 2_000.0, 3_000.0, 4_000.0, 5_000.0],
        [1_500.0, 2_030.0, 2_990.0, 4_020.0, 4_500.0],
        2_000.0,
        None,
    )
    assert (sync.flashes, sync.pairs) == (4, 3), "5000 has no beep within 400 ms"
    assert sync.skews_ms == [30.0, -10.0, 20.0]
    assert sync.median_ms == 20.0
    assert (sync.min_ms, sync.max_ms) == (-10.0, 30.0)
    assert sync.within_ebu_r37 is True
    # EBU R37: sound at most 40 ms early and 60 ms late.
    assert av_sync([1_000.0], [1_060.0], 0.0, None).within_ebu_r37 is True
    assert av_sync([1_000.0], [1_061.0], 0.0, None).within_ebu_r37 is False
    assert av_sync([1_000.0], [960.0], 0.0, None).within_ebu_r37 is True
    assert av_sync([1_000.0], [959.0], 0.0, None).within_ebu_r37 is False
    assert av_sync([1_000.0, 2_000.0], [1_010.0, 2_030.0], 0.0, None).median_ms == 20.0
    none = av_sync([], [1.0], 0.0, None)
    assert (none.pairs, none.median_ms, none.min_ms, none.within_ebu_r37) == (0, None, None, None)


def test_durations_parse_as_seconds() -> None:
    assert parse_duration("20s") == 20.0
    assert parse_duration("20") == 20.0
    assert parse_duration("500ms") == 0.5
    assert parse_duration("2m") == 120.0
    with pytest.raises(ValueError, match="not a duration"):
        parse_duration("soon")


def test_the_beeps_energy_is_a_sines_over_100_ms_a_second() -> None:
    assert STREAM.beep_energy_per_second() == pytest.approx(0.25**2 / 2 * 0.1)
    assert copy.replace(STREAM, beep_packets=50).beep_energy_per_second() == pytest.approx(
        0.25**2 / 2
    )
    assert checks.ENERGY_SHARE * STREAM.beep_energy_per_second() * 20 == pytest.approx(0.03125)


NTP_1970 = checks.NTP_UNIX_OFFSET_MS


def test_capture_times_place_each_frame_shown_on_the_wall_clock() -> None:
    page = good_page()
    # Chrome 154 (2026-10-07): captureTimestamp in NTP ms, the page's times in Unix ms.
    page["video"]["capture"] = [
        # The source's last delivered frame is the one shown.
        {
            "shown": 1_000_060.0,
            "received": 1_000_010.0,
            "frame_rtp": 9_000,
            "delivered": 1_000_040.0,
            "source_rtp": 9_000,
            "capture": NTP_1970 + 1_000_000,
            "offset": 0,
        },
        # The frame shown is one later than the source's (3000 ticks, 33.3 ms): moved to it.
        {
            "shown": 1_000_100.0,
            "received": 1_000_045.0,
            "frame_rtp": 12_000,
            "delivered": 1_000_075.0,
            "source_rtp": 9_000,
            "capture": NTP_1970 + 1_000_000,
            "offset": None,
        },
        # Across the RTP clock's wrap, the frame shown one before the source's; no receiveTime.
        {
            "shown": 1_000_150.0,
            "received": None,
            "frame_rtp": (1 << 32) - 1_500,
            "delivered": 1_000_120.0,
            "source_rtp": 1_500,
            "capture": NTP_1970 + 1_000_100,
            "offset": None,
        },
        # Without a capture time, or not a sample: left out.
        {"shown": 1.0, "capture": None},
        "junk",
    ]
    page["video"]["no_capture_time"] = 3
    page["capture_time"] = {"video": "asked", "audio": "asked"}
    page["answer_extensions"] = {
        "video": [f"13 {checks.ABS_CAPTURE_TIME}", "3 urn:3gpp:video-orientation"],
        "audio": ["9 urn:ietf:params:rtp-hdrext:sdes:mid"],
    }
    found = capture_times(page)
    assert found["asked"] == {"video": "asked", "audio": "asked"}
    assert found["negotiated"] == {"video": True, "audio": False}
    assert (found["frames"], found["frames_without"]) == (4, 3)
    # To render: 60, 100 - 33.3 and 150 - (100 - 33.3); to receive: 10 and 45 - 33.3.
    assert found["capture_to_render_ms"] == pytest.approx(66.667, abs=0.001)
    assert found["capture_to_receive_ms"] == pytest.approx((10 + 11.667) / 2, abs=0.001)
    assert found["receive_to_render_ms"] == pytest.approx(52.5)
    assert found["capture_to_delivery_ms"] == pytest.approx(40.0)
    assert found["sender_capture_time_offset_ms"] == 0
    # A browser without captureTimestamp (Firefox, Safari) has nothing to report.
    assert diagnostics(good_page())["capture_time"] == {
        "asked": NOT_REPORTED,
        "negotiated": {},
        "frames": 0,
        "frames_without": 0,
        "capture_to_receive_ms": NOT_REPORTED,
        "receive_to_render_ms": NOT_REPORTED,
        "capture_to_render_ms": NOT_REPORTED,
        "capture_to_delivery_ms": NOT_REPORTED,
        "sender_capture_time_offset_ms": NOT_REPORTED,
    }
    # Without RTP timestamps the source's capture time is the frame's.
    page["video"]["capture"] = [{"shown": 1_000_050.0, "capture": NTP_1970 + 1_000_000}]
    assert capture_times(page)["capture_to_render_ms"] == 50.0


def disrupted_page(mode: str) -> dict[str, Any]:
    """A page that played a window, had `mode` happen at 22 s, and a window from 23.5 s."""
    page = good_page()
    page["before"] = {"stats": page["stats"]}
    page["stats"] = {
        "start": snapshot(23_500.0, 610, 1_020, 0.29),
        "end": snapshot(43_500.0, 1_210, 2_020, 0.57),
    }
    set_path(page, "/before/stats/end/stats/kind=video/pliCount", 0)
    set_path(page, f"{END_VIDEO}/pliCount", 1)
    page["video"]["presented_at_start"] = 601
    page["video"]["presented_at_end"] = 1_192
    # Sound 50 ms after the picture before; 20 ms after the recovery.
    page["video"]["flashes"] = [2_000.0 + 1_000 * s for s in range(42)]
    page["audio"]["beeps"] = [2_050.0 + 1_000 * s for s in range(20)] + [
        22_020.0 + 1_000 * s for s in range(22)
    ]
    counters = {"reconnects": 0, "restarts": 0, "state": "live"}
    after = {"reconnects": 1, "restarts": 1, "state": "live"}
    page["disruption"] = {"mode": mode, "at": 22_000.0, "before": counters, "recovered": 23_500.0}
    match mode:
        case "pli":
            page["disruption"]["keyframe_request"] = "sent"
        case "reconnect":
            page["disruption"]["after"] = after
        case _:
            page["disruption"] |= {
                "after": after,
                "closed": "worker_crashed: the camera's worker process exited",
                "time_to_first_frame_ms": 540,
            }
    return page


@pytest.mark.parametrize("mode", ["pli", "reconnect", "crash"])
def test_a_disrupted_page_is_judged_on_the_window_after_the_recovery(mode: str) -> None:
    verdict = check(disrupted_page(mode), STREAM, mode)
    assert verdict.failures == []
    assert verdict.measured["flashes"] == 20, "the flashes of the second window"
    assert verdict.measured["frames_shown"] == 591
    assert (verdict.av_sync.pairs, verdict.av_sync.median_ms) == (17, 20.0)
    before = verdict.av_sync_before
    assert before is not None
    assert (before.pairs, before.median_ms) == (17, 50.0), "from 3 s after the first frame"
    found = verdict.diagnostics["disruption"]
    assert found["mode"] == mode
    assert found["plis_sent"] == 1.0
    assert found["recovery_ms"] == 1_500.0
    assert found["before_video_jitter_buffer_ms"] == pytest.approx(10.0)
    assert found["before_audio_jitter_buffer_ms"] == pytest.approx(42.0)
    assert check(good_page(), STREAM).av_sync_before is None
    assert diagnostics(good_page())["disruption"] == NOT_REPORTED


@pytest.mark.parametrize(
    ("mode", "path", "value", "failure"),
    [
        ("pli", "/disruption/mode", "crash", "a pli disruption"),
        ("pli", "/disruption/recovered", None, "a recovery after the pli"),
        ("pli", "/disruption/keyframe_request", None, "the page's keyframe request sent"),
        ("reconnect", "/disruption/after/reconnects", 0, "the stream reconnected (0 to 0)"),
        ("reconnect", "/disruption/after", None, "the stream reconnected (0 to None)"),
        ("crash", "/disruption/closed", "stream_deleted: gone", "the session closed with"),
        ("crash", "/disruption/after/restarts", 0, "the session closed with"),
    ],
)
def test_a_disruption_that_did_not_happen_fails(
    mode: str, path: str, value: object, failure: str
) -> None:
    page = disrupted_page(mode)
    set_path(page, path, value)
    failures = disruption_failures(page, mode)
    assert len(failures) == 1, failures
    assert failures[0].startswith(failure), failures


def test_a_disruption_is_the_one_the_case_asks_for() -> None:
    assert disruption_failures(good_page(), None) == []
    assert disruption_failures(disrupted_page("pli"), None)[0].startswith("no disruption asked")
    assert disruption_failures(good_page(), "pli") == ["a pli disruption (the page did None)"]
    page = disrupted_page("pli")
    page["disruption"]["mode"] = "reboot"
    assert disruption_failures(page, "reboot") == ["a known disruption, not 'reboot'"]


def test_an_aac_camera_is_played_through_the_transcoder() -> None:
    aac = copy.replace(STREAM, audio_codec="MPEG4-GENERIC")
    page = good_page()
    native = {"id": "a0", "kind": "audio", "codec": "aac_lc", "derived_from": None}
    derived = {"id": "a1", "kind": "audio", "codec": "opus", "derived_from": "a0"}
    page["stream_end"] = {"tracks": [{"id": "v0", "codec": "h264"}, native, derived]}
    assert transcoded(page)
    assert check(page, aac).failures == []
    assert diagnostics(page)["daemon_tracks"][2] == derived
    page["stream_end"]["tracks"] = [native]
    assert not transcoded(page)
    assert check(page, aac).failures == ["an Opus track transcoded from the camera's AAC"]
    # Through go2rtc the page reads no stream from the server: not judged.
    del page["stream_end"]
    assert check(page, aac).failures == []


def test_a_kind_without_stats_at_the_start_counts_from_zero() -> None:
    # The transcoder starts with the session, so its first Opus packet can come after the
    # first frame and the snapshot taken then (Chrome 154, 2026-10-07).
    page = good_page()
    page["stats"]["start"]["stats"] = [
        s for s in page["stats"]["start"]["stats"] if s.get("kind") != "audio"
    ]
    verdict = check(page, STREAM)
    assert verdict.failures == []
    assert verdict.measured["audio_packets_received"] == 1_020

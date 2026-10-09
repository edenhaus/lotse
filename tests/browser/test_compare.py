"""The comparison and usage, unit-tested: no browser, the runs written by hand."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

import pytest

from compare import compare, delta, negotiated, outcomes, percentile, pick, summarise, table
from usage import Sample, Sampler, usage


def run(
    ttff: float | None,
    video_ms: float,
    audio_ms: float,
    cpu: float | None,
    failures: tuple[str, ...] = (),
) -> dict[str, Any]:
    """A run's result as `test_comparison._run` writes it, with the fields the comparison reads."""
    return {
        "round": 1,
        "failures": list(failures),
        "measured": {
            "time_to_first_frame_ms": ttff,
            "video_jitter_buffer_ms": video_ms,
            "audio_jitter_buffer_ms": audio_ms,
            "frames_decoded": 600,
        },
        "av_sync": {"median_ms": 60.0},
        "diagnostics": {
            "video": {"codec": "video/H264", "decode_ms": "not reported"},
            "audio": {"codec": "audio/PCMU"},
        },
        "usage": {"total": {"cpu_percent": cpu, "rss_mean_mib": 15.0, "rss_max_mib": 16.0}},
    }


def test_pick_finds_numbers_only() -> None:
    result = run(30, 7.0, 50.0, 1.5)
    assert pick(result, ("measured", "time_to_first_frame_ms")) == 30.0
    assert pick(result, ("usage", "total", "cpu_percent")) == 1.5
    assert pick(result, ("diagnostics", "video", "decode_ms")) is None  # "not reported"
    assert pick(result, ("diagnostics", "video", "codec", "deeper")) is None
    assert pick(result, ("missing",)) is None
    assert pick({"flag": True}, ("flag",)) is None


def test_percentiles_are_nearest_rank() -> None:
    values = [50.0, 10.0, 40.0, 20.0, 30.0]
    assert percentile(values, 0.5) == 30.0
    assert percentile(values, 0.95) == 50.0
    assert percentile(values, 0.0) == 10.0
    assert percentile([7.0], 0.95) == 7.0
    assert percentile([], 0.5) is None
    assert percentile([1.0, 2.0], 0.5) == 1.0


def test_summaries_skip_runs_without_the_metric() -> None:
    runs = [run(30, 7, 50, 1.0), run(None, 8, 55, None), run(50, 9, 60, 2.0)]
    summary = summarise(runs, ("measured", "time_to_first_frame_ms"))
    assert (summary.runs, summary.p50, summary.p95) == (2, 30.0, 50.0)
    assert (summary.min, summary.max, summary.values) == (30.0, 50.0, [30.0, 50.0])
    assert summarise([], ("measured", "frames_decoded")).p50 is None


def test_a_delta_is_lotse_minus_the_other_and_none_without_both() -> None:
    assert delta(12.0, 7.0) == 5.0
    assert delta(30.0, 230.0) == -200.0
    assert delta(None, 7.0) is None
    assert delta(12.0, None) is None


def test_outcomes_count_the_runs_played_and_passed_and_list_every_failure() -> None:
    failed = run(30, 7, 50, 1, failures=("no end of candidates", "frozen"))
    failed["round"] = 2
    gone = {"server": "go2rtc", "version": None, "round": 3, "error": "go2rtc did not come up"}
    assert outcomes([run(30, 7, 50, 1), failed, gone]) == {
        "runs": 3,
        "played": 2,
        "passed": 1,
        "failures": [
            "run 2: no end of candidates",
            "run 2: frozen",
            "run 3: did not play: go2rtc did not come up",
        ],
    }
    assert outcomes([]) == {"runs": 0, "played": 0, "passed": 0, "failures": []}


def test_the_codecs_negotiated_leave_out_what_is_not_reported() -> None:
    unreported = run(30, 7, 50, 1)
    unreported["diagnostics"]["audio"]["codec"] = "not reported"
    opus = run(30, 7, 50, 1)
    opus["diagnostics"]["audio"]["codec"] = "audio/opus"
    assert negotiated([run(30, 7, 50, 1), unreported, opus, {}]) == {
        "video": ["video/H264"],
        "audio": ["audio/PCMU", "audio/opus"],
    }


def test_the_report_sets_every_server_side_by_side_with_lotse_s_differences() -> None:
    lotse = [run(30, 7, 50, 1.0), run(35, 8, 52, 1.2), run(32, 7, 55, 1.1)]
    go2rtc = [run(230, 47, 80, 1.3), run(400, 45, 79, 1.4), run(120, 48, 81, 1.2)]
    ffmpeg = [run(250, 40, 90, 9.0), run(260, 41, 91, 9.5)]
    comparison = compare(lotse, {"go2rtc": go2rtc, "go2rtc-ffmpeg": ffmpeg})
    assert list(comparison) == ["metrics", "deltas", "negotiated", "outcomes"]
    ttff = comparison["metrics"]["time_to_first_frame_ms"]
    assert list(ttff) == ["lotse", "go2rtc", "go2rtc-ffmpeg"]
    assert (ttff["lotse"]["p50"], ttff["go2rtc"]["p50"], ttff["go2rtc"]["p95"]) == (32, 230, 400)
    assert (ttff["go2rtc-ffmpeg"]["p50"], ttff["go2rtc-ffmpeg"]["runs"]) == (250, 2)
    assert comparison["deltas"]["time_to_first_frame_ms"] == {
        "go2rtc": {"p50": -198.0, "p95": -365.0},
        "go2rtc-ffmpeg": {"p50": -218.0, "p95": -225.0},
    }
    assert comparison["deltas"]["video_decode_ms"]["go2rtc"] == {"p50": None, "p95": None}
    assert list(comparison["deltas"]) == list(comparison["metrics"])
    assert comparison["negotiated"]["go2rtc"] == {"video": ["video/H264"], "audio": ["audio/PCMU"]}
    assert list(comparison["negotiated"]) == ["lotse", "go2rtc", "go2rtc-ffmpeg"]
    assert comparison["outcomes"]["go2rtc-ffmpeg"] == {
        "runs": 2,
        "played": 2,
        "passed": 2,
        "failures": [],
    }
    markdown = table(comparison)
    assert markdown.splitlines()[:2] == [
        (
            "| metric | lotse p50 | lotse p95 | go2rtc p50 | go2rtc p95 "
            "| go2rtc-ffmpeg p50 | go2rtc-ffmpeg p95 | Δ go2rtc p50 | Δ go2rtc-ffmpeg p50 |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    assert (
        "| time_to_first_frame_ms | 32.0 | 35.0 | 230.0 | 400.0 | 250.0 | 260.0 | -198.0 | -218.0 |"
        in markdown
    )
    assert "| av_skew_ms | 60.0 | 60.0 | 60.0 | 60.0 | 60.0 | 60.0 | 0.0 | 0.0 |" in markdown
    assert "| video_decode_ms | - | - | - | - | - | - | - | - |" in markdown


def test_lotse_worse_than_another_server_is_reported_not_failed() -> None:
    comparison = compare(
        [run(300, 7, 50, 1.0)],
        {"go2rtc": [run(400, 7, 50, 1.0)], "go2rtc-ffmpeg": [run(200, 7, 50, 1.0)]},
    )
    assert comparison["deltas"]["time_to_first_frame_ms"]["go2rtc-ffmpeg"]["p50"] == 100.0
    assert comparison["outcomes"]["lotse"]["failures"] == []
    assert "failures" not in comparison


def test_another_server_s_runs_that_did_not_play_are_reported_with_the_others() -> None:
    gone = {"server": "go2rtc", "version": None, "round": 1, "error": "go2rtc did not come up"}
    comparison = compare(
        [run(30, 7, 50, 1.0)], {"go2rtc": [gone, run(230, 47, 80, 1.3, ("no end of candidates",))]}
    )
    assert comparison["metrics"]["time_to_first_frame_ms"]["go2rtc"]["runs"] == 1
    assert comparison["deltas"]["time_to_first_frame_ms"]["go2rtc"]["p50"] == -200.0
    assert comparison["outcomes"]["go2rtc"] == {
        "runs": 2,
        "played": 1,
        "passed": 0,
        "failures": [
            "run 1: did not play: go2rtc did not come up",
            "run 1: no end of candidates",
        ],
    }
    assert comparison["outcomes"]["lotse"]["passed"] == 1
    every_run_gone = compare([run(30, 7, 50, 1.0)], {"go2rtc": [gone]})
    assert every_run_gone["metrics"]["time_to_first_frame_ms"]["go2rtc"]["p50"] is None
    assert every_run_gone["deltas"]["time_to_first_frame_ms"]["go2rtc"]["p50"] is None


def test_usage_is_cpu_over_time_and_memory_over_the_window() -> None:
    mib = 2**20
    samples = {
        "supervisor": [
            Sample(at=0.0, cpu_s=0.0, rss=4 * mib),  # before the window
            Sample(at=1.0, cpu_s=1.0, rss=6 * mib),
            Sample(at=3.0, cpu_s=1.5, rss=8 * mib),
        ],
        "worker": [
            Sample(at=1.0, cpu_s=2.0, rss=10 * mib),
            Sample(at=2.0, cpu_s=3.0, rss=10 * mib),
        ],
        "late": [Sample(at=3.0, cpu_s=0.1, rss=mib)],  # one sample: no span
    }
    result = usage(samples, since=1.0, until=3.0)
    assert result["processes"] == {
        "supervisor": {"cpu_percent": 25.0, "rss_mean_mib": 7.0, "rss_max_mib": 8.0},
        "worker": {"cpu_percent": 100.0, "rss_mean_mib": 10.0, "rss_max_mib": 10.0},
    }
    assert result["total"] == {"cpu_percent": 125.0, "rss_mean_mib": 17.0, "rss_max_mib": 18.0}
    nothing = usage(samples, since=10.0, until=20.0)
    assert nothing == {
        "processes": {},
        "total": {"cpu_percent": None, "rss_mean_mib": None, "rss_max_mib": None},
    }


def test_the_sampler_follows_a_process_and_its_children() -> None:
    sleeper = [sys.executable, "-c", "import time; time.sleep(5)"]
    children = [subprocess.Popen(sleeper) for _ in range(2)]  # noqa: S603 -- this Python
    sampler = Sampler(pid=os.getpid(), root_label="test", child_label="child")
    try:
        sampler.start()
        time.sleep(0.6)
    finally:
        sampler.stop()
        for child in children:
            child.kill()
            child.wait()
    labels = sorted(sampler.samples)
    assert labels[0].startswith("child ")
    assert labels[1] == labels[0] + " #2"
    assert labels[2] == "test"
    assert all(len(series) >= 2 for series in sampler.samples.values())
    assert all(s.rss > 0 for s in sampler.samples["test"])


def test_the_sampler_of_a_gone_process_has_nothing() -> None:
    gone = subprocess.Popen([sys.executable, "-c", "pass"])
    gone.wait()
    sampler = Sampler(pid=gone.pid, root_label="gone", child_label="child")
    sampler.start()
    sampler.stop()
    assert sampler.samples == {}


@pytest.mark.parametrize("share", [0.5, 0.95])
def test_a_single_run_is_its_own_percentile(share: float) -> None:
    assert percentile([42.0], share) == 42.0

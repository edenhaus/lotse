"""The comparison: lotse's runs side by side with each other server's, reported, never judged.

The other servers are go2rtc's two paths (`go2rtc`, its own RTSP client, and `go2rtc-ffmpeg`, a
camera it pulls through ffmpeg). Everything here is a pure function of the runs' results, which
`test_comparison.py` collects: for each server, what `checks.check` measured in each run, its
diagnostics and the processes' usage, or why the run did not play. Every metric is summarised per
server (median, 95th percentile, range), and lotse's median and 95th percentile are set against
each other server's as a difference. Nothing here passes or fails: lotse's runs are held to the
browser test's own checks (`checks.check`), which `test_comparison.py` applies, and the other
servers' figures and failed checks are recorded only.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

from checks import NOT_REPORTED

type Json = Any
"""A value decoded from JSON."""

METRICS: dict[str, tuple[str, ...]] = {
    "time_to_first_frame_ms": ("measured", "time_to_first_frame_ms"),
    "frames_shown": ("measured", "frames_shown"),
    "frames_decoded": ("measured", "frames_decoded"),
    "video_packets_lost": ("measured", "video_packets_lost"),
    "audio_packets_lost": ("measured", "audio_packets_lost"),
    "video_jitter_buffer_ms": ("measured", "video_jitter_buffer_ms"),
    "audio_jitter_buffer_ms": ("measured", "audio_jitter_buffer_ms"),
    "video_beyond_jitter_buffer_ms": ("measured", "video_beyond_jitter_buffer_ms"),
    "av_skew_ms": ("av_sync", "median_ms"),
    "video_jitter_buffer_target_ms": ("diagnostics", "video", "jitter_buffer_target_ms"),
    "audio_jitter_buffer_target_ms": ("diagnostics", "audio", "jitter_buffer_target_ms"),
    "video_processing_delay_ms": ("diagnostics", "video", "processing_delay_ms"),
    "video_decode_ms": ("diagnostics", "video", "decode_ms"),
    "capture_to_render_ms": ("diagnostics", "capture_time", "capture_to_render_ms"),
    "receive_to_render_ms": ("diagnostics", "capture_time", "receive_to_render_ms"),
    "video_frames_dropped": ("diagnostics", "video", "frames_dropped"),
    "audio_concealed_samples": ("diagnostics", "audio", "concealed_samples"),
    "round_trip_ms": ("diagnostics", "round_trip_ms"),
    "cpu_percent": ("usage", "total", "cpu_percent"),
    "rss_mean_mib": ("usage", "total", "rss_mean_mib"),
    "rss_max_mib": ("usage", "total", "rss_max_mib"),
}
"""What the report compares, and where each run's result has it. `measured` and `av_sync` are
`checks.check`'s; `diagnostics` are the getStats() fields only some browsers report (absent when
"not reported"); `usage` is `usage.usage` of the server's processes over the play time."""

LOTSE = "lotse"
"""The server every other one is set against."""


def pick(run: Json, path: tuple[str, ...]) -> float | None:
    """The number at `path` in a run's result; `None` when absent or not a number."""
    value = run
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def percentile(values: list[float], share: float) -> float | None:
    """The nearest-rank percentile: the smallest value with at least `share` of them at or below.

    With five runs the median is the third and the 95th percentile the largest.
    """
    if not values:
        return None
    ordered = sorted(values)
    rank = max(math.ceil(share * len(ordered)), 1)
    return ordered[rank - 1]


@dataclass(frozen=True, kw_only=True)
class Summary:
    """One metric over one server's runs."""

    runs: int
    p50: float | None
    p95: float | None
    min: float | None
    max: float | None
    values: list[float]


def summarise(runs: list[Json], path: tuple[str, ...]) -> Summary:
    """A metric's summary over the runs that report it."""
    values = [value for run in runs if (value := pick(run, path)) is not None]
    return Summary(
        runs=len(values),
        p50=percentile(values, 0.5),
        p95=percentile(values, 0.95),
        min=min(values, default=None),
        max=max(values, default=None),
        values=values,
    )


def delta(mine: float | None, theirs: float | None) -> float | None:
    """The difference of lotse's figure from another server's; `None` when either has none."""
    if mine is None or theirs is None:
        return None
    return mine - theirs


def outcomes(runs: list[Json]) -> dict[str, Json]:
    """How a server's runs went: how many played, and each run's failed checks or error.

    A run that did not play carries `error` (`test_comparison._run`); one that played carries the
    failures of `checks.check`, which only lotse is held to.
    """
    played = [run for run in runs if "error" not in run]
    failures: list[str] = []
    for run in runs:
        prefix = f"run {run.get('round')}"
        if "error" in run:
            failures.append(f"{prefix}: did not play: {run['error']}")
        failures.extend(f"{prefix}: {failure}" for failure in run.get("failures") or [])
    return {
        "runs": len(runs),
        "played": len(played),
        "passed": sum(1 for run in played if not run.get("failures")),
        "failures": failures,
    }


def negotiated(runs: list[Json]) -> dict[str, list[str]]:
    """The codecs each kind played with over the runs (getStats() `codec` `mimeType`)."""
    codecs: dict[str, set[str]] = {"video": set(), "audio": set()}
    for run in runs:
        for kind, found in codecs.items():
            codec = ((run.get("diagnostics") or {}).get(kind) or {}).get("codec")
            if isinstance(codec, str) and codec != NOT_REPORTED:
                found.add(codec)
    return {kind: sorted(found) for kind, found in codecs.items()}


def compare(lotse: list[Json], others: dict[str, list[Json]]) -> dict[str, Json]:
    """The report: each metric per server, lotse's differences, the codecs and how the runs went.

    `others` has each other server's runs by its name, in the order the report lists them;
    `deltas` has, per metric and other server, lotse's median and 95th percentile minus that
    server's (negative where lotse's figure is lower).
    """
    runs = {LOTSE: lotse, **others}
    metrics = {
        name: {server: summarise(each, path) for server, each in runs.items()}
        for name, path in METRICS.items()
    }
    return {
        "metrics": {
            name: {server: asdict(summary) for server, summary in each.items()}
            for name, each in metrics.items()
        },
        "deltas": {
            name: {
                server: {
                    "p50": delta(each[LOTSE].p50, each[server].p50),
                    "p95": delta(each[LOTSE].p95, each[server].p95),
                }
                for server in others
            }
            for name, each in metrics.items()
        },
        "negotiated": {server: negotiated(each) for server, each in runs.items()},
        "outcomes": {server: outcomes(each) for server, each in runs.items()},
    }


def table(comparison: dict[str, Json]) -> str:
    """The comparison as a Markdown table.

    Each metric's median and 95th percentile per server, then lotse's median minus each other
    server's.
    """

    def shown(value: float | None) -> str:
        return "-" if value is None else f"{value:.1f}"

    servers = list(next(iter(comparison["metrics"].values()), {}))
    others = list(next(iter(comparison["deltas"].values()), {}))
    lines = [
        "| metric | "
        + " | ".join([*(f"{s} p50 | {s} p95" for s in servers), *(f"Δ {o} p50" for o in others)])
        + " |",
        "|---|" + "---:|---:|" * len(servers) + "---:|" * len(others),
    ]
    for name, each in comparison["metrics"].items():
        cells = [f"{shown(each[s]['p50'])} | {shown(each[s]['p95'])}" for s in servers]
        deltas = [shown(comparison["deltas"][name][o]["p50"]) for o in others]
        lines.append(f"| {name} | {' | '.join([*cells, *deltas])} |")
    return "\n".join(lines)

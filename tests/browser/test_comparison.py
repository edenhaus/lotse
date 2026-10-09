"""The go2rtc comparison: the same browser, page and camera through lotse and through go2rtc.

go2rtc 1.9.14 is configured and driven as its common deployment configures it (`servers.py`,
`go2rtc.yaml`), on both of its paths for an RTSP camera: its own RTSP client (`go2rtc`) and
ffmpeg (`go2rtc-ffmpeg`, an `ffmpeg:` source). Each round plays the synthetic camera once through
each server, the order reversed between rounds so a drift on the machine falls on all alike; every
run starts its server, camera and browser afresh.
The page and `checks.check` are the browser test's (`test_browser.py`); only the signaling differs
(`servers.py`). A thread samples each server's processes (`usage.py`) and `compare.compare`
summarises them side by side. `compare.json` and `compare.md` go to `--out`, each run's logs and
report to `run-<round>-<server>/` there.

The comparison is a report: no figure of go2rtc's passes or fails anything. lotse's runs must pass
every check of the browser test, as there; go2rtc's failed checks and runs that did not play are
recorded in the report (go2rtc sends no end of candidates, which the trickle check expects).
"""

from __future__ import annotations

import json
import platform
import time
from dataclasses import asdict
from functools import partial
from typing import TYPE_CHECKING, Any

import psutil
import pytest

import servers
from checks import check
from compare import LOTSE, compare, table
from harness import versions
from usage import Sampler, usage

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager
    from pathlib import Path

    from harness import Settings

SERVERS: dict[str, Callable[[Settings, Path], AbstractContextManager[servers.Running]]] = {
    LOTSE: servers.lotse,
    "go2rtc": servers.go2rtc,
    "go2rtc-ffmpeg": partial(servers.go2rtc, ffmpeg=True),
}
"""The servers compared and how each starts, in this order in odd rounds and reversed in even
ones."""


def _run(settings: Settings, server: str, round_: int) -> dict[str, Any]:
    """One play through `server`: what `checks.check` made of it, and the server's usage.

    A run of lotse's that does not play fails the test there and then; one of another server's is
    recorded with its `error`, and the comparison goes on.
    """
    out = settings.out / f"run-{round_}-{server}"
    out.mkdir(parents=True, exist_ok=True)
    if server == LOTSE:
        return _play(settings, server, round_, out)
    try:
        return _play(settings, server, round_, out)
    except (Exception, pytest.fail.Exception) as err:  # noqa: BLE001 -- recorded, not raised
        result = {"server": server, "version": None, "round": round_, "error": str(err)}
        (out / "report.json").write_text(json.dumps(result, indent=2) + "\n")
        return result


def _play(settings: Settings, server: str, round_: int, out: Path) -> dict[str, Any]:
    """The play `_run` describes, its report written to `out`."""
    with SERVERS[server](settings, out) as running, servers.browser(settings, out) as driver:
        sampler = Sampler(
            pid=running.pid, root_label=running.root_label, child_label=running.child_label
        )
        sampler.start()
        try:
            user_agent, page = servers.play(driver, running.served, settings.play_s)
        finally:
            finished = time.monotonic()
            sampler.stop()
        ran = versions(driver, settings)
    verdict = check(page, running.served.stream)
    play_s = verdict.measured.get("play_s") or 0.0
    version = running.version or (page.get("daemon") or {}).get("version")
    result = {
        "server": server,
        "version": version,
        "round": round_,
        **verdict.as_json(),
        "av_sync": asdict(verdict.av_sync),
        "usage": usage(sampler.samples, finished - play_s, finished),
        "browser": ran["browser"],
        "user_agent": user_agent,
    }
    (out / "report.json").write_text(json.dumps({**result, "page": page}, indent=2) + "\n")
    return result


def _version(runs: list[dict[str, Any]]) -> str | None:
    """A server's version: the first its runs learned."""
    return next((run["version"] for run in runs if run.get("version")), None)


def _machine() -> dict[str, object]:
    """The machine the runs shared."""
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpus": psutil.cpu_count(logical=True),
        "cores": psutil.cpu_count(logical=False),
        "memory_gib": round(psutil.virtual_memory().total / 2**30, 1),
    }


def test_lotse_and_go2rtc_side_by_side(settings: Settings) -> None:
    if settings.go2rtc is None:
        pytest.fail("--go2rtc required for the comparison (scripts/compare.sh sets it)")
    results: dict[str, list[dict[str, Any]]] = {server: [] for server in SERVERS}
    for round_ in range(1, settings.runs + 1):
        order = list(SERVERS) if round_ % 2 else list(reversed(SERVERS))
        for server in order:
            results[server].append(_run(settings, server, round_))
    lotse, others = results[LOTSE], {s: r for s, r in results.items() if s != LOTSE}
    comparison = compare(lotse, others)
    first = lotse[0]
    report = {
        "engine": settings.engine,
        "browser": first["browser"],
        "machine": _machine(),
        "play_s": settings.play_s,
        "runs": settings.runs,
        "servers": {server: {"version": _version(results[server])} for server in SERVERS},
        **comparison,
        "results": results,
    }
    (settings.out / "compare.json").write_text(json.dumps(report, indent=2) + "\n")
    browser = first["browser"]
    against = ", ".join(f"{s} {report['servers'][s]['version']}" for s in others)
    heading = (
        f"lotse {report['servers'][LOTSE]['version']} against {against}, {settings.runs} runs of "
        f"{settings.play_s:g} s each, {browser['name']} {browser['version']} on "
        f"{report['machine']['platform']}"
    )
    played = ", ".join(
        f"{s} {o['played']}/{o['runs']} played, {o['passed']} passed the checks"
        for s, o in comparison["outcomes"].items()
    )
    markdown = (
        f"{heading}\n\n{table(comparison)}\n\n"
        "Δ: lotse's median minus the other server's.\n"
        f"negotiated: {comparison['negotiated']}\nruns: {played}\n"
    )
    (settings.out / "compare.md").write_text(markdown)
    print(markdown)  # noqa: T201 -- the run's summary, shown by `-rA`
    # lotse's own checks only: the comparison and the other servers' runs fail nothing.
    failures = [f"lotse {failure}" for failure in comparison["outcomes"][LOTSE]["failures"]]
    assert not failures, "\n".join(failures)

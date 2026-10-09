"""The browser test: a real browser plays the camera through the daemon, written once for all.

Selenium loads the test page from the dev viewer, hands it the camera and the play time, clicks
Start (a real user gesture, which lets WebAudio run in Safari) and waits for the page's result.
The page puts the stream with `preload`, offers once it is live (the first frame comes from the
GOP cache), trickles its candidates, plays, and returns what it measured; `checks.check` decides,
the same way in every browser. One test per case (`harness.CASES`, `--case`): the camera's audio,
and what happens to the stream between a first window and the one the checks take (a keyframe
request, a camera reconnect, a worker crash). The report goes to `report.json` in the case's
directory in `--out` either way.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from checks import check
from harness import versions
from servers import play

if TYPE_CHECKING:
    from pathlib import Path

    from selenium.webdriver.remote.webdriver import WebDriver

    from harness import Case, Served, Settings


def _ms(value: float | None) -> str:
    """A skew for the summary."""
    return "none" if value is None else f"{value:.1f} ms"


def test_the_browser_plays_and_hears_the_camera(
    settings: Settings, case: Case, out: Path, served: Served, driver: WebDriver
) -> None:
    user_agent, page = play(driver, served, settings.play_s, case.disrupt)
    verdict = check(page, served.stream, case.disrupt)
    report = {
        "engine": settings.engine,
        "case": case.name,
        "about": case.about,
        **versions(driver, settings),
        "user_agent": user_agent,
        "stream": served.stream.__dict__,
        **verdict.as_json(),
        "page": page,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    browser, sync, before = report["browser"], verdict.av_sync, verdict.av_sync_before
    summary = (
        f"{case.name} ({case.about}), {browser['name']} {browser['version']} on "
        f"{browser['platform']}: {json.dumps(verdict.measured)}; A/V skew median "
        f"{_ms(sync.median_ms)} over {sync.pairs} pairs (the browser's own estimate "
        f"{_ms(sync.browser_estimate_ms)})"
    )
    if before is not None:
        summary += (
            f", before the {case.disrupt} {_ms(before.median_ms)} over {before.pairs} pairs; "
            f"{json.dumps(verdict.diagnostics['disruption'])}"
        )
    print(summary)  # noqa: T201 -- the run's one line, shown by `-rA`
    assert not verdict.failures, summary + "\n" + "\n".join(verdict.failures)

"""The browser test's options and fixtures: the daemon, the camera and page, and the browser.

`--browser chrome|firefox` picks the browser; without it the browser test and the comparison
are skipped and only the unit tests run. `--case` picks the browser test's cases (`harness.CASES`,
all by default); each writes its report and logs to its own directory in `--out`.
`scripts/browser.sh` (`mise run browser`) builds the release daemon and the `lotse-browser` example
and passes them as `--lotse` and `--lotse-browser`; `scripts/compare.sh` (`mise run compare`)
passes `--go2rtc` and `--runs` as well.

The browser is the installed one (the runner image's current stable on CI) unless
`--browser-version` asks Selenium Manager to fetch another (Chrome for Testing, Firefox); its
driver is the one Selenium Manager resolves for it: on `PATH` when that matches the browser, else
fetched. The report records the versions that ran.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import servers
from checks import parse_duration
from harness import CASES, Case, Served, Settings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from selenium.webdriver.remote.webdriver import WebDriver

ENGINES = ("chrome", "firefox")
"""The browsers the test runs on."""


def pytest_addoption(parser: pytest.Parser) -> None:
    """The browser test's command line."""
    group = parser.getgroup("lotse browser test")
    group.addoption("--browser", choices=ENGINES, help="the browser; without it, unit tests only")
    group.addoption("--play", default="20s", help="how long the page plays after the first frame")
    group.addoption("--lotse", help="the daemon's binary (`lotse`)")
    group.addoption("--lotse-browser", help="the `lotse-browser` example's binary")
    group.addoption("--go2rtc", help="go2rtc's binary, for the comparison")
    group.addoption(
        "--runs", type=int, default=5, help="the comparison's plays through each server"
    )
    group.addoption("--camera", help="an RTSP camera to play instead of the synthetic one")
    group.addoption("--out", help="the directory of the report and the logs")
    group.addoption("--headful", action="store_true", help="a window instead of headless")
    group.addoption(
        "--browser-arg", action="append", default=[], help="a browser argument (repeatable)"
    )
    group.addoption("--browser-version", help="a version Selenium Manager fetches (`142`, `beta`)")
    group.addoption("--browser-binary", help="the browser's executable, if not the default")
    group.addoption(
        "--case",
        action="append",
        choices=(*CASES, "all"),
        help="a case of the browser test (repeatable; default all): "
        + "; ".join(f"{case.name}: {case.about}" for case in CASES.values()),
    )


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """One browser test per case `--case` names (all by default)."""
    if "case" in metafunc.fixturenames:
        named = metafunc.config.getoption("--case") or ["all"]
        names = list(CASES) if "all" in named else list(dict.fromkeys(named))
        metafunc.parametrize("case", [CASES[name] for name in names], ids=names, scope="function")


@pytest.fixture(scope="session")
def settings(request: pytest.FixtureRequest) -> Settings:
    """The command line; skips the browser tests when no browser is named."""
    config = request.config
    engine = config.getoption("--browser")
    if engine is None:
        pytest.skip("no --browser: the browser test runs through `mise run browser <engine>`")
    missing = [flag for flag in ("--lotse", "--lotse-browser") if not config.getoption(flag)]
    if missing:
        pytest.fail(f"{', '.join(missing)} required with --browser (scripts/browser.sh sets them)")
    out = Path(config.getoption("--out") or f"browser-{engine}").resolve()
    out.mkdir(parents=True, exist_ok=True)
    go2rtc = config.getoption("--go2rtc")
    return Settings(
        engine=engine,
        play_s=parse_duration(config.getoption("--play")),
        lotse=Path(config.getoption("--lotse")).resolve(),
        lotse_browser=Path(config.getoption("--lotse-browser")).resolve(),
        camera=config.getoption("--camera"),
        out=out,
        headless=not config.getoption("--headful"),
        browser_args=config.getoption("--browser-arg"),
        browser_version=config.getoption("--browser-version"),
        browser_binary=config.getoption("--browser-binary"),
        go2rtc=Path(go2rtc).resolve() if go2rtc else None,
        runs=config.getoption("--runs"),
    )


@pytest.fixture
def out(settings: Settings, case: Case) -> Path:
    """The case's directory for its report and logs."""
    directory = settings.out / case.name
    directory.mkdir(parents=True, exist_ok=True)
    return directory


@pytest.fixture
def served(settings: Settings, case: Case, out: Path) -> Iterator[Served]:
    """The daemon, the camera with the case's audio and the page (`servers.lotse`)."""
    with servers.lotse(settings, out, audio=case.audio) as running:
        yield running.served


@pytest.fixture
def driver(settings: Settings, out: Path) -> Iterator[WebDriver]:
    """A browser session (`servers.browser`); quit after the test."""
    with servers.browser(settings, out) as session:
        yield session

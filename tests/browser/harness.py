"""The browser test's harness: its settings, the browser's options, and the versions that ran."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import selenium
from selenium import webdriver

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from selenium.webdriver.remote.webdriver import WebDriver

    from checks import Stream


@dataclass(frozen=True, kw_only=True)
class Case:
    """One run of the browser test: the camera's audio and what happens to the stream midway."""

    name: str
    audio: str
    """The synthetic camera's audio (`lotse-browser --audio`): `pcmu` or `aac`."""
    disrupt: str | None
    """What the page does after a first window, before the window the checks take: `pli` (a
    keyframe request of its own), `reconnect` (the harness restarts the camera's publisher) or
    `crash` (the harness kills the worker); `None` plays one window after join."""
    about: str


CASES = {
    case.name: case
    for case in (
        Case(name="join", audio="pcmu", disrupt=None, about="PCMU, after join"),
        Case(name="aac", audio="aac", disrupt=None, about="AAC transcoded to Opus, after join"),
        Case(name="pli", audio="pcmu", disrupt="pli", about="PCMU, after a keyframe request"),
        Case(
            name="reconnect",
            audio="pcmu",
            disrupt="reconnect",
            about="PCMU, after the camera's publisher restarts",
        ),
        Case(name="crash", audio="pcmu", disrupt="crash", about="PCMU, after a worker crash"),
    )
}
"""Every case, the order `--case all` runs them in."""


@dataclass(frozen=True, kw_only=True)
class Settings:
    """The browser test's command line, parsed."""

    engine: str
    play_s: float
    lotse: Path
    lotse_browser: Path
    camera: str | None
    out: Path
    headless: bool
    browser_args: list[str]
    browser_version: str | None
    browser_binary: str | None
    go2rtc: Path | None = None
    """go2rtc's binary, for the comparison."""
    runs: int = 1
    """How many times the comparison plays through each server."""


@dataclass(frozen=True, kw_only=True)
class Served:
    """What `lotse-browser` serves: the page, the camera, and the stream the camera sends."""

    page: str
    camera: str
    stream: Stream
    command: Callable[[str], dict[str, Any]] | None = None
    """Sends `lotse-browser` a command line and returns its answer (`restart-camera`)."""
    daemon_pid: int | None = None
    """The daemon's process, whose child is the worker a crash kills."""


def tail(path: Path, lines: int = 40) -> str:
    """The last lines of a log."""
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
    except OSError as err:
        return f"({path}: {err})"


def options(settings: Settings) -> webdriver.ChromeOptions | webdriver.FirefoxOptions | None:
    """The browser's options: headless where it has a mode for it, sound without a gesture."""
    options: webdriver.ChromeOptions | webdriver.FirefoxOptions
    match settings.engine:
        case "chrome":
            options = webdriver.ChromeOptions()
            if settings.headless:
                options.add_argument("--headless=new")
            options.add_argument("--autoplay-policy=no-user-gesture-required")
        case "firefox":
            options = webdriver.FirefoxOptions()
            if settings.headless:
                options.add_argument("-headless")
            # Autoplay with sound, without a gesture (0: allowed).
            options.set_preference("media.autoplay.default", 0)
            options.set_preference("media.autoplay.blocking_policy", 0)
            # H.264 is the OpenH264 plugin, which Firefox fetches itself; automation profiles
            # turn that off.
            options.set_preference("media.gmp-manager.updateEnabled", value=True)
            # The daemon listens on loopback: let ICE gather there.
            options.set_preference("media.peerconnection.ice.loopback", value=True)
        case _:
            # Safari takes no options: it has no headless mode, and the click on Start is the
            # gesture that lets it play.
            return None
    for argument in settings.browser_args:
        options.add_argument(argument)
    if settings.browser_version:
        options.browser_version = settings.browser_version
    if settings.browser_binary:
        options.binary_location = settings.browser_binary
    return options


def versions(session: WebDriver, settings: Settings) -> dict[str, object]:
    """The browser, driver and harness that ran, for the report."""
    caps = session.capabilities
    match settings.engine:
        case "chrome":
            driver_version = caps.get("chrome", {}).get("chromedriverVersion")
        case "firefox":
            driver_version = caps.get("moz:geckodriverVersion")
        case _:
            driver_version = None  # safaridriver reports none; it ships with Safari
    service = getattr(session, "service", None)
    return {
        "browser": {
            "name": caps.get("browserName"),
            "version": caps.get("browserVersion"),
            "platform": caps.get("platformName"),
            "headless": settings.headless,
        },
        "driver": {
            "version": driver_version or "not reported",
            "path": getattr(service, "path", None) or "not reported",
        },
        "selenium": selenium.__version__,
        "python": platform.python_version(),
        "host": f"{platform.system()} {platform.release()} {platform.machine()}",
        "ci": os.environ.get("GITHUB_ACTIONS") == "true",
    }

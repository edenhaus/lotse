"""The harness's unit tests: the browser's options, and a driver stopped as Selenium stops it."""

from __future__ import annotations

import http.server
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from selenium import webdriver
from selenium.webdriver.common.service import Service

from harness import Settings, options

if TYPE_CHECKING:
    from collections.abc import Iterator


def settings_for(engine: str, *, headless: bool = True) -> Settings:
    return Settings(
        engine=engine,
        play_s=20.0,
        lotse=Path("lotse"),
        lotse_browser=Path("lotse-browser"),
        camera=None,
        out=Path("out"),
        headless=headless,
        browser_args=[],
        browser_version=None,
        browser_binary=None,
    )


def test_headless_firefox_plays_web_audio_on_the_mock_audio_output() -> None:
    wanted = options(settings_for("firefox"))
    assert isinstance(wanted, webdriver.FirefoxOptions)
    assert "-headless" in wanted.arguments
    assert wanted.preferences["media.cubeb.force_mock_context"] is True


def test_firefox_with_a_window_plays_on_the_real_audio_output() -> None:
    wanted = options(settings_for("firefox", headless=False))
    assert isinstance(wanted, webdriver.FirefoxOptions)
    assert "-headless" not in wanted.arguments
    assert "media.cubeb.force_mock_context" not in wanted.preferences


class _NoShutdown(http.server.BaseHTTPRequestHandler):
    """A driver without `GET /shutdown`: geckodriver answers 405, safaridriver 404."""

    status = 405

    def do_GET(self) -> None:
        self.send_response(self.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_: object) -> None:
        pass


class _Driver(Service):
    """Selenium's service for a driver at a given port; nothing is started."""

    def command_line_args(self) -> list[str]:
        return []


@pytest.fixture(params=[405, 404], ids=["geckodriver", "safaridriver"])
def driver_port(request: pytest.FixtureRequest) -> Iterator[int]:
    handler = type("Handler", (_NoShutdown,), {"status": request.param})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_a_driver_without_a_shutdown_endpoint_stops_without_a_warning(driver_port: int) -> None:
    # Selenium drops the unclosed HTTPError; pyproject's filter keeps `error` from failing on it.
    _Driver(executable_path="driver", port=driver_port).send_remote_shutdown_command()

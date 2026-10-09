"""The servers the browser plays the camera through, and one play of the test page.

`lotse` starts a release daemon and `lotse-browser` (the camera and the dev viewer that serves the
page and relays its signaling to the daemon); `go2rtc` starts `lotse-browser` for the camera and the
page, and go2rtc configured and driven as its common deployment does it: that deployment's config
file (`go2rtc.yaml`, its differences listed there) and go2rtc's client library, go2rtc-client,
over the Unix socket, for the stream and its preload, the camera's URL as the source or, with
`ffmpeg`, behind `FFMPEG_PREFIX`. The page
then signals to go2rtc's WebSocket API (`?signal=go2rtc`). `play` runs the page once, the same
for every server, and acts on the stream where the page's case asks the harness to (`disrupt`).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import secrets
import shutil
import signal
import socket as sockets
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import psutil
import pytest
from aiohttp import ClientSession, ClientTimeout, UnixConnector, encode_basic_auth
from go2rtc_client import Go2RtcRestClient
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.safari.service import Service as SafariService

from checks import Stream
from harness import Served, options, tail

if TYPE_CHECKING:
    from collections.abc import Iterator

    from selenium.webdriver.remote.webdriver import WebDriver

    from harness import Settings

PAGE_OVERHEAD_S = 60.0
"""What the page takes beyond the play time: the stream going live, the answer, the first frame."""

START_TIMEOUT_S = 15.0
"""How long a server may take to come up (the daemon's control socket, go2rtc's API)."""

STOP_TIMEOUT_S = 15.0
"""How long a process may take to stop when asked."""

LIVE_TIMEOUT_S = 10.0
"""How long go2rtc may take to receive the camera's video and audio once the stream is preloaded;
the page gives lotse's stream the same 10 s to go live."""

WARM_MS = 1_500
"""How long the stream stays live before the offer, so a GOP cache holds a whole group of pictures
(one IDR a second)."""

TRACKS = 2
"""The camera's tracks, video and audio."""

STREAM_ID = "browser"
"""The stream's name in both servers."""

GO2RTC_CONFIG = Path(__file__).with_name("go2rtc.yaml")
"""go2rtc's configuration as its common deployment writes it, with the differences it lists."""

GO2RTC_BOOTED = "INF [api] listen addr="
"""The log line the deployment waits for before it uses go2rtc (observed 2026-10-07)."""

GO2RTC_URL = "http://localhost:11984/"
"""The base URL the deployment gives go2rtc's client; over the Unix socket only its path counts."""

FFMPEG_PREFIX = "ffmpeg:"
"""What the deployment puts in front of a camera's URL to have go2rtc pull it through ffmpeg
(observed 2026-10-07). go2rtc 1.9.14 runs `ffmpeg:<rtsp url>` without `#video` or `#audio` as
`ffmpeg -allowed_media_types video+audio -fflags nobuffer -flags low_delay -rtsp_flags prefer_tcp
-i <url> -c copy -rtsp_transport tcp -f rtsp <its own RTSP server>`, a remux of both tracks
(`parseArgs` in go2rtc's `internal/ffmpeg/ffmpeg.go`), found on its PATH."""


@dataclass(frozen=True, kw_only=True)
class Running:
    """A server playing the camera: what the page needs and the processes to measure."""

    name: str
    """`lotse`, `go2rtc` or `go2rtc-ffmpeg`."""
    version: str | None
    """The server's version, where the harness learns it before the page runs."""
    served: Served
    """The page and the camera."""
    pid: int
    """The server's process; its descendants (lotse's worker, go2rtc's ffmpeg) count as its own."""
    root_label: str
    """What the report calls the server's process."""
    child_label: str
    """What the report calls its descendants, followed by their name."""


def stop(process: subprocess.Popen[bytes], name: str) -> int:
    """Waits for `process` to end, killing it after `STOP_TIMEOUT_S`; its exit code."""
    try:
        return process.wait(timeout=STOP_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        pytest.fail(f"{name} did not stop within {STOP_TIMEOUT_S:.0f} s")


def _free_port() -> int:
    """A TCP port nothing listens on just now (another process may take it before go2rtc does)."""
    with sockets.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@contextmanager
def _page(settings: Settings, socket: Path, out: Path, audio: str = "pcmu") -> Iterator[Served]:
    """`lotse-browser`: the camera and the dev viewer, which relays to `socket`; stopped after.

    The camera sends `audio` (`pcmu` or `aac`); `Served.command` sends `lotse-browser` a command.
    """
    camera = ["--camera", settings.camera] if settings.camera else []
    log = out / "lotse-browser.log"
    with log.open("wb") as stderr:
        page = subprocess.Popen(  # noqa: S603 -- the binary the command line names, no shell
            [settings.lotse_browser, "--socket", socket, "--audio", audio, *camera],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
        )
    try:
        line = page.stdout.readline() if page.stdout else b""
        if not line:
            pytest.fail(f"lotse-browser did not start:\n{tail(log)}")
        ready = json.loads(line)

        def command(text: str) -> dict[str, Any]:
            """One command line to `lotse-browser`, and its one line of answer."""
            if page.stdin is None or page.stdout is None:
                pytest.fail("lotse-browser has no stdin or stdout")
            page.stdin.write(text.encode() + b"\n")
            page.stdin.flush()
            answer: dict[str, Any] = json.loads(page.stdout.readline() or b"{}")
            return answer

        yield Served(
            page=ready["page"],
            camera=ready["camera"],
            stream=Stream.from_json(ready["stream"]),
            command=command,
        )
    finally:
        # Its stdin ending stops the camera and the dev viewer.
        if page.stdin is not None:
            page.stdin.close()
        if page.stdout is not None:
            page.stdout.close()
        stop(page, "lotse-browser")


@contextmanager
def lotse(settings: Settings, out: Path, audio: str = "pcmu") -> Iterator[Running]:
    """A release daemon on a private socket with WebRTC on loopback, and `lotse-browser`.

    The camera sends `audio`. Both stopped after, the daemon's exit checked. The page puts the
    stream itself.
    """
    # A short path: a Unix socket path must fit in sun_path (104 bytes on macOS).
    directory = Path(tempfile.mkdtemp(prefix="lotse-browser.", dir="/tmp"))
    socket = directory / "lotse.sock"
    daemon_log = out / "lotse.log"
    with daemon_log.open("wb") as log:
        daemon = subprocess.Popen(  # noqa: S603 -- the binary the command line names, no shell
            [
                settings.lotse,
                "serve",
                "--socket",
                socket,
                "--sandbox",
                "off",
                "--webrtc-udp-listen",
                "127.0.0.1:0",
                "--webrtc-tcp-listen",
                "off",
                "--log-format",
                "json",
                "--log-level",
                "info",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
    try:
        deadline = time.monotonic() + START_TIMEOUT_S
        while not socket.is_socket():
            if daemon.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"the daemon did not come up:\n{tail(daemon_log)}")
            time.sleep(0.1)
        with _page(settings, socket, out, audio) as served:
            yield Running(
                name="lotse",
                version=None,  # the page reads it from the daemon's hello
                served=dataclasses.replace(served, daemon_pid=daemon.pid),
                pid=daemon.pid,
                root_label="supervisor",
                child_label="worker",
            )
    finally:
        daemon.send_signal(signal.SIGTERM)
        status = stop(daemon, "the daemon")
        shutil.rmtree(directory, ignore_errors=True)
        if status != 0:
            pytest.fail(f"the daemon exited with {status}:\n{tail(daemon_log)}")


async def _register(socket: Path, username: str, password: str, source: str) -> str:
    """The camera registered with go2rtc as `source` and preloaded; go2rtc's version.

    As the deployment registers a camera whose stream it preloads (observed 2026-10-07): it checks
    the version and the source's scheme, puts the stream with the source and an ffmpeg fallback
    that transcodes the audio to Opus for browsers that cannot play the camera's, and enables its
    preload. The source is the camera's URL, with `FFMPEG_PREFIX` in front for the ffmpeg path.
    Then it waits until go2rtc receives video and audio, as the page waits for lotse's stream to be
    live.
    """
    async with ClientSession(
        connector=UnixConnector(path=str(socket)),
        headers={"Authorization": encode_basic_auth(username, password)},
    ) as session:
        client = Go2RtcRestClient(session, GO2RTC_URL)
        version = await client.validate_server_version()
        schemes = await client.schemes.list()
        if source.partition(":")[0] not in schemes:
            pytest.fail(f"go2rtc does not support {source}'s scheme (it has {sorted(schemes)})")
        streams = await client.streams.list()
        if STREAM_ID not in streams:
            await client.streams.add(
                STREAM_ID, [source, f"ffmpeg:{STREAM_ID}#audio=opus#query=log_level=debug"]
            )
        await client.preload.enable(STREAM_ID)
        deadline = time.monotonic() + LIVE_TIMEOUT_S
        while not await _receiving(session, STREAM_ID):
            if time.monotonic() > deadline:
                pytest.fail(f"go2rtc received no video and audio in {LIVE_TIMEOUT_S:.0f} s")
            await asyncio.sleep(0.1)
        return str(version)


async def _receiving(session: ClientSession, name: str) -> bool:
    """Whether go2rtc's stream `name` receives packets of every track of its first producer.

    go2rtc's `GET /api/streams?src=` (its REST API) lists each producer's receivers with their
    packet counts.
    """
    async with session.get(
        f"{GO2RTC_URL}api/streams", params={"src": name}, timeout=ClientTimeout(total=5)
    ) as response:
        response.raise_for_status()
        info: dict[str, Any] = await response.json()
    producers = info.get("producers") or []
    receivers = (producers[0].get("receivers") or []) if producers else []
    return len(receivers) >= TRACKS and all(r.get("packets", 0) > 0 for r in receivers)


@contextmanager
def go2rtc(settings: Settings, out: Path, *, ffmpeg: bool = False) -> Iterator[Running]:
    """go2rtc as its common deployment runs it, the camera registered as there, and `lotse-browser`.

    With `ffmpeg` the camera is registered with `FFMPEG_PREFIX` in front of its URL, and go2rtc
    pulls it through ffmpeg; without, through go2rtc's own RTSP client. `lotse-browser` serves the
    camera and the page; its relay is not used, so its socket has no daemon behind it.
    """
    if settings.go2rtc is None:
        pytest.fail("--go2rtc required for the comparison (scripts/compare.sh sets it)")
    if ffmpeg and shutil.which("ffmpeg") is None:
        pytest.fail("ffmpeg is not on PATH, where go2rtc looks for it (mise install)")
    directory = Path(tempfile.mkdtemp(prefix="lotse-go2rtc.", dir="/tmp"))
    unix = directory / "go2rtc.sock"
    # Credentials generated per start (`token_hex`), the file next to the socket, as deployed.
    username, password = secrets.token_hex(), secrets.token_hex()
    api_port = _free_port()
    config = directory / "go2rtc.yaml"
    config.write_text(
        Template(GO2RTC_CONFIG.read_text()).substitute(
            api_port=api_port,
            unix_socket=unix,
            username=username,
            password=password,
            rtsp_port=_free_port(),
            webrtc_port=_free_port(),
        )
    )
    server_log = out / "go2rtc.log"
    with server_log.open("wb") as log:
        # As deployed: `go2rtc -c <file>`, stdout and stderr together.
        server = subprocess.Popen(  # noqa: S603 -- the binary the command line names, no shell
            [settings.go2rtc, "-c", config],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    try:
        deadline = time.monotonic() + START_TIMEOUT_S
        while GO2RTC_BOOTED not in server_log.read_text(errors="replace") or not unix.is_socket():
            if server.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"go2rtc did not come up:\n{tail(server_log)}")
            time.sleep(0.1)
        with _page(settings, directory / "no-daemon.sock", out) as served:
            source = f"{FFMPEG_PREFIX}{served.camera}" if ffmpeg else served.camera
            version = asyncio.run(_register(unix, username, password, source))
            query = urlencode({"signal": "go2rtc", "api": f"ws://127.0.0.1:{api_port}/api/ws"})
            yield Running(
                name="go2rtc-ffmpeg" if ffmpeg else "go2rtc",
                version=version,
                served=Served(
                    page=f"{served.page}?{query}", camera=served.camera, stream=served.stream
                ),
                pid=server.pid,
                root_label="go2rtc",
                child_label="child",
            )
    finally:
        # As deployed, stopped with SIGTERM.
        server.terminate()
        stop(server, "go2rtc")
        shutil.rmtree(directory, ignore_errors=True)


@contextmanager
def browser(settings: Settings, out: Path) -> Iterator[WebDriver]:
    """A browser session through the driver Selenium Manager resolves; quit after."""
    log = str(out / "driver.log")
    wanted = options(settings)
    session: WebDriver
    if isinstance(wanted, webdriver.ChromeOptions):
        session = webdriver.Chrome(options=wanted, service=ChromeService(log_output=log))
    elif isinstance(wanted, webdriver.FirefoxOptions):
        session = webdriver.Firefox(options=wanted, service=FirefoxService(log_output=log))
    else:
        session = webdriver.Safari(service=SafariService())
    session.set_script_timeout(settings.play_s + PAGE_OVERHEAD_S)
    session.set_page_load_timeout(30)
    try:
        yield session
    finally:
        with contextlib.suppress(Exception):
            session.quit()


def _kill_worker(served: Served, pid: Any) -> None:  # noqa: ANN401 -- the page's JSON
    """Kills the worker `pid` (`SIGKILL`), once it is known to be the daemon's child."""
    if not isinstance(pid, int) or served.daemon_pid is None:
        pytest.fail(f"no worker to kill (pid {pid!r}, daemon {served.daemon_pid})")
    try:
        parent = psutil.Process(pid).ppid()
    except psutil.Error as err:
        pytest.fail(f"the worker {pid}: {err}")
    if parent != served.daemon_pid:
        pytest.fail(f"process {pid} is not the daemon's ({served.daemon_pid}) but {parent}'s")
    os.kill(pid, signal.SIGKILL)


def _act(served: Served, checkpoint: dict[str, Any]) -> None:
    """What the harness does to the stream at the page's checkpoint.

    It restarts the camera's publisher (`reconnect`) or kills the worker (`crash`).
    """
    match checkpoint.get("mode"):
        case "reconnect":
            if served.command is None:
                pytest.fail("no lotse-browser to restart the camera")
            answer = served.command("restart-camera")
            if answer.get("restarted") is not True:
                pytest.fail(f"the camera did not restart: {answer}")
        case "crash":
            _kill_worker(served, checkpoint.get("worker_pid"))
        case other:
            pytest.fail(f"the page asked for {other!r} at its checkpoint")


def play(
    driver: WebDriver, served: Served, play_s: float, disrupt: str | None = None
) -> tuple[str, Any]:
    """Runs the page once: the browser's user agent and what the page measured.

    Loads the page, hands it the camera, the play time and the disruption, clicks Start (a real
    user gesture, which lets WebAudio run in Safari) and waits for the page's result. Where the
    page reaches its checkpoint first, the harness acts (`_act`) and tells it to go on.
    """
    driver.get(served.page)
    driver.execute_script(
        "window.lotseTest.configure(arguments[0]);",
        {
            "stream_id": STREAM_ID,
            "url": served.camera,
            "play_ms": round(play_s * 1000),
            "warm_ms": WARM_MS,
            "disrupt": disrupt,
        },
    )
    user_agent: str = driver.execute_script("return navigator.userAgent;")
    driver.find_element(By.ID, "start").click()
    if disrupt is not None:
        reached = driver.execute_async_script(
            "const done = arguments[arguments.length - 1];"
            "Promise.race([window.lotseTest.checkpoint.then((c) => ({ checkpoint: c })),"
            " window.lotseTest.finished.then(() => ({}))]).then(done);"
        )
        if "checkpoint" in reached:
            _act(served, reached["checkpoint"])
            driver.execute_script("window.lotseTest.proceed();")
    page = driver.execute_async_script(
        "const done = arguments[arguments.length - 1]; window.lotseTest.finished.then(done);"
    )
    return user_agent, page

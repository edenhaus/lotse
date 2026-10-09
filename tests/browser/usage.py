"""What a server's processes use while the browser plays: CPU and resident memory, from psutil.

A thread samples the server's process and its descendants (lotse's worker, any ffmpeg go2rtc
starts) every `INTERVAL_S`; `Sampler.usage` sums the CPU time each used and the resident memory
it held over a window of the run, the play time after the first frame. psutil reads the kernel's
own accounting (`/proc/<pid>/stat` and `status` on Linux, `proc_pidinfo` on macOS), so the numbers
are the ones `ps` and `top` show.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import psutil

INTERVAL_S = 0.25
"""How often the processes are sampled."""


@dataclass(frozen=True, kw_only=True)
class Sample:
    """One process at one moment."""

    at: float
    """`time.monotonic()` of the sample."""
    cpu_s: float
    """User and system CPU time since the process started, seconds."""
    rss: int
    """Resident memory, bytes."""


@dataclass(kw_only=True)
class Sampler:
    """Samples a process tree on a thread from `start` to `stop`."""

    pid: int
    """The server's process."""
    root_label: str
    """The report's name for it."""
    child_label: str
    """The report's name for its descendants, followed by their own."""
    samples: dict[str, list[Sample]] = field(default_factory=dict)
    """Each process's samples, by its label."""
    _labels: dict[int, str] = field(default_factory=dict)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        """Starts sampling."""
        self._thread = threading.Thread(target=self._run, name="usage", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stops sampling."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join()

    def _label(self, process: psutil.Process) -> str:
        """The report's name of a process, the same for it on every sample.

        The root's label; a descendant's is `child_label` and its name, numbered from the
        second of the same name.
        """
        if (label := self._labels.get(process.pid)) is not None:
            return label
        if process.pid == self.pid:
            label = self.root_label
        else:
            label = base = f"{self.child_label} {process.name()}"
            taken = set(self._labels.values())
            number = 2
            while label in taken:
                label, number = f"{base} #{number}", number + 1
        self._labels[process.pid] = label
        return label

    def _run(self) -> None:
        """Samples until stopped; a process that ends is no longer sampled."""
        try:
            root = psutil.Process(self.pid)
        except psutil.Error:
            return
        while not self._stop.is_set():
            try:
                tree = [root, *root.children(recursive=True)]
            except psutil.Error:
                return
            for process in tree:
                try:
                    with process.oneshot():
                        times = process.cpu_times()
                        sample = Sample(
                            at=time.monotonic(),
                            cpu_s=times.user + times.system,
                            rss=process.memory_info().rss,
                        )
                        label = self._label(process)
                except psutil.Error:
                    continue
                self.samples.setdefault(label, []).append(sample)
            self._stop.wait(INTERVAL_S)


def usage(samples: dict[str, list[Sample]], since: float, until: float) -> dict[str, object]:
    """CPU and memory of each process over `since` to `until` (monotonic seconds), and the sum.

    CPU is the CPU time used between the first and last sample in the window over the time
    between them, as a share of one core (100 % is one core busy). Memory is the mean and the
    peak of the resident set over the window's samples. A process with fewer than two samples in
    the window is left out, and the sum is `None` when none is left.
    """
    processes: dict[str, dict[str, float]] = {}
    for label, series in samples.items():
        window = [s for s in series if since <= s.at <= until]
        if len(window) < 2 or window[-1].at <= window[0].at:  # noqa: PLR2004 -- two make a span
            continue
        first, last = window[0], window[-1]
        processes[label] = {
            "cpu_percent": (last.cpu_s - first.cpu_s) / (last.at - first.at) * 100,
            "rss_mean_mib": sum(s.rss for s in window) / len(window) / 2**20,
            "rss_max_mib": max(s.rss for s in window) / 2**20,
        }
    total = {
        name: sum(values[name] for values in processes.values()) if processes else None
        for name in ("cpu_percent", "rss_mean_mib", "rss_max_mib")
    }
    return {"processes": processes, "total": total}

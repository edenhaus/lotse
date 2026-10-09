#!/bin/sh
# The go2rtc comparison: the browser test's page, camera and checks, played through a release daemon
# and through go2rtc as its common deployment configures and drives it (tests/browser/go2rtc.yaml,
# tests/browser/servers.py), on both of go2rtc's paths for an RTSP camera (its own RTSP client, and
# ffmpeg), alternating, N runs each; tests/browser/test_comparison.py reports them side by side. The
# report fails nothing: only lotse's runs failing the browser test's own checks fail it. go2rtc and
# the ffmpeg it runs are the releases pinned in mise.toml, found on PATH.
#
# usage: scripts/compare.sh chrome|firefox|safari [runs] [play] [pytest arguments...]
#
# Runs through scripts/browser.sh (the builds, uv, the browser's options); the report goes to
# target/compare-<engine>/compare.json and compare.md, each run's logs and report to
# target/compare-<engine>/run-<round>-<server>/. `mise run compare` calls it.
set -eu

ENGINE="${1:-chrome}"
RUNS="${2:-5}"
PLAY="${3:-20s}"
if [ "$#" -ge 3 ]; then shift 3; else shift "$#"; fi
GO2RTC="$(command -v go2rtc)" || { echo "go2rtc is not on PATH (mise install)" >&2; exit 2; }

export LOTSE_BROWSER_TEST=test_comparison.py
export LOTSE_BROWSER_OUT="target/compare-$ENGINE"
exec scripts/browser.sh "$ENGINE" "$PLAY" --go2rtc "$GO2RTC" --runs "$RUNS" "$@"

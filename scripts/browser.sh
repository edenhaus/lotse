#!/bin/sh
# The browser test against a release daemon: a real browser plays the synthetic camera through
# the daemon and the dev viewer, driven by Selenium from one pytest test in tests/browser/, the
# same for every browser. The camera is ffmpeg publishing to MediaMTX, both pinned in mise.toml and
# found on PATH, which the `lotse-browser` example starts and stops (lotse_testing::mediamtx).
#
# usage: scripts/browser.sh chrome|firefox|safari [play] [pytest arguments...]
#
# Builds `lotse` and `lotse-browser` in release and runs the test with uv (the Python and the
# packages pinned in tests/browser/uv.lock); the test starts the daemon, `lotse-browser` and the
# browser once per case (`--case join|aac|pli|reconnect|crash|all`, repeatable, default all;
# tests/browser/harness.py), and writes target/browser-<engine>/<case>/report.json with the
# daemon's, the example's and the driver's logs. `mise run browser` calls it.
#
# The browser is the installed one, its driver the one Selenium Manager resolves for it (on PATH
# when it matches, else fetched); `--browser-version 142` (Chrome for Testing, Firefox) has
# Selenium Manager fetch that browser instead. Chrome and Firefox run headless unless
# LOTSE_BROWSER_HEADFUL=1; Safari has no headless mode, and its driver must be enabled once
# (`sudo safaridriver --enable`). $LOTSE_BROWSER_ARGS adds browser arguments (space-separated).
# scripts/compare.sh runs the go2rtc comparison through it: $LOTSE_BROWSER_TEST names the test file
# (test_browser.py) and $LOTSE_BROWSER_OUT the report's directory (target/browser-<engine>).
set -eu

ENGINE="${1:-chrome}"
PLAY="${2:-20s}"
if [ "$#" -ge 2 ]; then shift 2; elif [ "$#" -ge 1 ]; then shift; fi
case "$ENGINE" in
  chrome | firefox | safari) ;;
  *) echo "usage: scripts/browser.sh chrome|firefox|safari [play] [pytest arguments...]" >&2; exit 2 ;;
esac

# On Linux the daemon is the static musl build that ships (as in scripts/load.sh); elsewhere
# (macOS, development only) the host build.
if [ "$(uname -s)" = Linux ]; then
  TARGET="$(uname -m)-unknown-linux-musl"
  cargo build --release --locked --bin lotse --target "$TARGET"
  LOTSE="$PWD/target/$TARGET/release/lotse"
else
  cargo build --release --locked --bin lotse
  LOTSE="$PWD/target/release/lotse"
fi
cargo build --release --locked -p lotse-testing --example lotse-browser

set -- --browser "$ENGINE" --play "$PLAY" --lotse "$LOTSE" \
  --lotse-browser "$PWD/target/release/examples/lotse-browser" \
  --out "$PWD/${LOTSE_BROWSER_OUT:-target/browser-$ENGINE}" "$@"
[ "${LOTSE_BROWSER_HEADFUL:-0}" != 1 ] || set -- "$@" --headful
for arg in ${LOTSE_BROWSER_ARGS:-}; do
  set -- "$@" "--browser-arg=$arg"
done

# Selenium Manager sends usage statistics unless told not to.
export SE_AVOID_STATS=true
cd tests/browser
exec uv run --locked pytest "${LOTSE_BROWSER_TEST:-test_browser.py}" -rA "$@"

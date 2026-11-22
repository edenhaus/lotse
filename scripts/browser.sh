#!/bin/sh
# The browser test against a release daemon: a real browser plays the synthetic camera through
# the daemon and the dev viewer, driven by Selenium from one pytest test in tests/browser/, the
# same for every browser. The camera is ffmpeg publishing to MediaMTX, both pinned in mise.toml and
# found on PATH, which the `rocko-browser` example starts and stops (rocko_testing::mediamtx).
#
# usage: scripts/browser.sh chrome|firefox|safari [play] [pytest arguments...]
#
# Builds `rocko` and `rocko-browser` in release and runs the test with uv (the Python and the
# packages pinned in tests/browser/uv.lock); the test starts the daemon, `rocko-browser` and the
# browser once per case (`--case join|aac|pli|reconnect|crash|mse|mse-pcmu|mse-opus|llhls|llhls-opus|all`,
# repeatable, default all; tests/browser/harness.py), and writes
# target/browser-<engine>/<case>/report.json with the daemon's, the example's and the driver's
# logs. `mise run browser` calls it.
#
# The browser is the installed one, its driver the one Selenium Manager resolves for it (on PATH
# when it matches, else fetched); `--browser-version 142` (Chrome for Testing, Firefox) has
# Selenium Manager fetch that browser instead. Chrome and Firefox run headless unless
# ROCKO_BROWSER_HEADFUL=1; Safari has no headless mode, and its driver must be enabled once
# (`sudo safaridriver --enable`). $ROCKO_BROWSER_ARGS adds browser arguments (space-separated).
# The LL-HLS cases' page loads hls.js, an exact release, from jsDelivr, which the browser runs only
# if its bytes match the page's Subresource Integrity hash (crates/rocko-testing/src/browser/page.html);
# the other cases reach nothing beyond the machine.
# scripts/compare.sh runs the go2rtc comparison through it: $ROCKO_BROWSER_TEST names the test file
# (test_browser.py) and $ROCKO_BROWSER_OUT the report's directory (target/browser-<engine>).
set -eu

ENGINE="${1:-chrome}"
PLAY="${2:-20s}"
if [ "$#" -ge 2 ]; then shift 2; elif [ "$#" -ge 1 ]; then shift; fi
case "$ENGINE" in
  chrome | firefox | safari) ;;
  *) echo "usage: scripts/browser.sh chrome|firefox|safari [play] [pytest arguments...]" >&2; exit 2 ;;
esac

# On Linux the daemon is the static musl build that ships (as in scripts/load.sh); elsewhere
# (macOS, for Safari) the host build.
if [ "$(uname -s)" = Linux ]; then
  TARGET="$(uname -m)-unknown-linux-musl"
  cargo build --release --locked --bin rocko --target "$TARGET"
  ROCKO="$PWD/target/$TARGET/release/rocko"
else
  cargo build --release --locked --bin rocko
  ROCKO="$PWD/target/release/rocko"
fi
cargo build --release --locked -p rocko-testing --example rocko-browser

set -- --browser "$ENGINE" --play "$PLAY" --rocko "$ROCKO" \
  --rocko-browser "$PWD/target/release/examples/rocko-browser" \
  --out "$PWD/${ROCKO_BROWSER_OUT:-target/browser-$ENGINE}" "$@"
[ "${ROCKO_BROWSER_HEADFUL:-0}" != 1 ] || set -- "$@" --headful
for arg in ${ROCKO_BROWSER_ARGS:-}; do
  set -- "$@" "--browser-arg=$arg"
done

# Selenium Manager sends usage statistics unless told not to.
export SE_AVOID_STATS=true
cd tests/browser
exec uv run --locked pytest "${ROCKO_BROWSER_TEST:-test_browser.py}" -rA "$@"

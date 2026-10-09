#!/bin/sh
# The load generator and soak against a release daemon.
#
# Builds `lotse` and the `lotse-load` example in release, starts `lotse serve` on a private
# socket with WebRTC on loopback, runs `lotse-load` with the arguments given (see its
# --help-less usage line in crates/lotse-testing/src/load/args.rs), stops the daemon with
# SIGTERM and fails if `lotse-load` failed or the daemon did not exit cleanly. `mise run load`
# and `mise run soak` call it.
#
# The sandbox is off unless LOTSE_LOAD_SANDBOX says otherwise: a sandboxed process is not
# dumpable, which closes its /proc/<pid>/fd to the generator, and the soak counts descriptors.
# The sandbox changes no media path; the sandbox-isolation job covers it.
set -eu

SANDBOX="${LOTSE_LOAD_SANDBOX:-off}"

# On Linux the daemon is the static musl build that ships, with mimalloc;
# elsewhere (macOS, development only) the host build.
if [ "$(uname -s)" = Linux ]; then
  TARGET="$(uname -m)-unknown-linux-musl"
  cargo build --release --locked --bin lotse --target "$TARGET"
  LOTSE="target/$TARGET/release/lotse"
else
  cargo build --release --locked --bin lotse
  LOTSE=target/release/lotse
fi
cargo build --release --locked -p lotse-testing --example lotse-load

# A short path: a Unix socket path must fit in sun_path (104 bytes on macOS), which macOS's
# per-user TMPDIR alone nearly fills.
DIR="$(mktemp -d /tmp/lotse-load.XXXXXX)"
chmod 0700 "$DIR"
SOCKET="$DIR/lotse.sock"
LOG="$DIR/lotse.log"

"$LOTSE" serve --socket "$SOCKET" --sandbox "$SANDBOX" \
  --webrtc-udp-listen 127.0.0.1:0 --webrtc-tcp-listen off \
  --log-format json --log-level warn 2>"$LOG" &
DAEMON=$!

i=0
until [ -S "$SOCKET" ]; do
  i=$((i + 1))
  if [ "$i" -ge 100 ] || ! kill -0 "$DAEMON" 2>/dev/null; then
    cat "$LOG" >&2
    echo "FAIL: the daemon did not come up" >&2
    exit 1
  fi
  sleep 0.1
done

status=0
target/release/examples/lotse-load --socket "$SOCKET" "$@" || status=$?

kill -TERM "$DAEMON"
daemon=0
wait "$DAEMON" || daemon=$?
if [ "$status" -ne 0 ] || [ "$daemon" -ne 0 ]; then
  echo "daemon log ($LOG), last lines:" >&2
  tail -n 50 "$LOG" >&2
  [ "$daemon" -eq 0 ] || echo "FAIL: the daemon exited with $daemon" >&2
  exit 1
fi
rm -rf "$DIR"

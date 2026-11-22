#!/bin/sh
# The load generator and soak against a release daemon.
#
# Builds `rocko` and the `rocko-load` example in release, starts `rocko serve` on a private
# socket with WebRTC on loopback, runs `rocko-load` with the arguments given (see its
# --help-less usage line in crates/rocko-testing/src/load/args.rs), stops the daemon with
# SIGTERM and fails if `rocko-load` failed or the daemon did not exit cleanly. `mise run load`
# and `mise run soak` call it.
#
# The sandbox is off unless ROCKO_LOAD_SANDBOX says otherwise: a sandboxed process is not
# dumpable, which closes its /proc/<pid>/fd to the generator, and the soak counts descriptors.
# The sandbox changes no media path; CI's Sandbox isolation job covers it.
set -eu

SANDBOX="${ROCKO_LOAD_SANDBOX:-off}"

[ "$(uname -s)" = Linux ] || { echo "the load generator and the soak run on Linux only" >&2; exit 2; }

# The daemon is the static musl build that ships, with mimalloc.
TARGET="$(uname -m)-unknown-linux-musl"
cargo build --release --locked --bin rocko --target "$TARGET"
ROCKO="target/$TARGET/release/rocko"
cargo build --release --locked -p rocko-testing --example rocko-load

# A short path: a Unix socket path must fit in sun_path (108 bytes on Linux).
DIR="$(mktemp -d /tmp/rocko-load.XXXXXX)"
chmod 0700 "$DIR"
SOCKET="$DIR/rocko.sock"
LOG="$DIR/rocko.log"

"$ROCKO" serve --socket "$SOCKET" --sandbox "$SANDBOX" \
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
target/release/examples/rocko-load --socket "$SOCKET" "$@" || status=$?

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

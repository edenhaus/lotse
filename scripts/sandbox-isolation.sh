#!/bin/sh
# The sandbox-isolation check.
#
# Runs inside a container under Docker's default seccomp profile, as root, the way
# a deployment's container may start the daemon: the supervisor binds its socket in a
# root-owned 0700 directory, drops to 65534 and applies its sandbox; workers apply
# theirs. Checks, through `lotse ctl`, that `info.sandbox` reports every layer, that a
# sandboxed worker on the fake source goes live, that a crashing worker is restarted
# without touching the other stream, and that the daemon stops cleanly on SIGTERM.
# First, as root with `--sandbox off`, which must still drop the supervisor and its
# workers to 65534: no mode parses camera bytes as root.
#
# Needs a `lotse` built with `--features source-fake`, at $LOTSE (default /lotse).
set -eu

LOTSE="${LOTSE:-/lotse}"
DIR="${LOTSE_DIR:-/run/lotse}"
SOCKET="$DIR/lotse.sock"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# `ctl <args>`: the daemon's compact JSON answer on stdout.
ctl() {
  "$LOTSE" ctl --socket "$SOCKET" --compact "$@"
}

# `field <json> <key>`: the value of a top-level string, number or bool key.
field() {
  printf '%s' "$1" | grep -o "\"$2\":[^,}]*" | head -n 1 | cut -d: -f2- | tr -d '"'
}

# `start <mode>`: the daemon as root in sandbox mode <mode>, up once `hello` answers.
start() {
  "$LOTSE" serve --socket "$SOCKET" --sandbox "$1" --user 65534 --group 65534 \
    --linger-ms 200 --log-format json --log-level debug 2>"$DIR/lotse.log" &
  DAEMON=$!
  i=0
  until [ -S "$SOCKET" ] && ctl info >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || { cat "$DIR/lotse.log" >&2; fail "the daemon did not come up ($1)"; }
    sleep 0.1
  done
}

# `wait_live <stream>`: until the stream is live.
wait_live() {
  i=0
  until [ "$(field "$(ctl stream get "$1")" state)" = "live" ]; do
    i=$((i + 1))
    [ "$i" -lt 200 ] || { cat "$DIR/lotse.log" >&2; fail "$1 never went live: $(ctl stream get "$1")"; }
    sleep 0.1
  done
}

# `all_unprivileged <count>`: at least <count> lotse processes (the supervisor and its
# workers) run, and every one has real, effective, saved and filesystem uid 65534.
all_unprivileged() {
  name="$(basename "$LOTSE" | cut -c 1-15)" # the kernel's `comm`, at most 15 bytes
  n=0
  for status in /proc/[0-9]*/status; do
    grep -q "^Name:[[:space:]]*$name\$" "$status" 2>/dev/null || continue
    uids="$(grep '^Uid:' "$status" | tr -s '[:space:]' ' ')"
    [ "$uids" = "Uid: 65534 65534 65534 65534 " ] || fail "$status: $uids"
    n=$((n + 1))
  done
  [ "$n" -ge "$1" ] || fail "expected at least $1 lotse processes, found $n"
  echo "$n lotse processes, all uid 65534"
}

mkdir -m 0700 -p "$DIR"

# `--sandbox off` skips Landlock and seccomp, never the privilege drop.
start off
sandbox="$(ctl info | grep -o '"sandbox":{.*}' | head -n 1)"
echo "sandbox off: $sandbox"
[ "$(field "$sandbox" mode)" = "off" ] || fail "sandbox mode is not off"
[ "$(field "$sandbox" uid)" = "65534" ] || fail "the supervisor kept root with the sandbox off"
[ "$(field "$sandbox" gid)" = "65534" ] || fail "the supervisor kept gid 0 with the sandbox off"
ctl stream put front --url fake://127.0.0.1/ --preload >/dev/null
wait_live front
all_unprivileged 2
ctl stream delete front >/dev/null
kill -TERM "$DAEMON"
wait "$DAEMON" || fail "the daemon did not exit cleanly (off)"
echo "OK: privileges dropped with the sandbox off"

# The sandbox on.
start on

info="$(ctl info)"
echo "info: $info"
sandbox="$(printf '%s' "$info" | grep -o '"sandbox":{.*}' | head -n 1)"
echo "sandbox: $sandbox"
[ "$(field "$sandbox" mode)" = "on" ] || fail "sandbox mode is not on"
[ "$(field "$sandbox" uid)" = "65534" ] || fail "the supervisor did not drop to 65534"
[ "$(field "$sandbox" no_new_privs)" = "true" ] || fail "no_new_privs is not set"
[ "$(field "$sandbox" seccomp)" = "enforced" ] || fail "seccomp is not enforced under the container's profile"
[ "$(field "$sandbox" fs)" = "enforced" ] || fail "Landlock fs rules are not enforced"
echo "landlock net: $(field "$sandbox" net) (abi $(field "$sandbox" abi))"

# A sandboxed worker on the fake source goes live.
ctl stream put front --url fake://127.0.0.1/ --preload >/dev/null
wait_live front
echo "front: $(ctl stream get front)"
all_unprivileged 2

# A crashing worker is restarted with backoff; front is unaffected.
ctl stream put crash --url fake://127.0.0.2/ --options '{"crash":true}' --preload >/dev/null
i=0
until [ "$(field "$(ctl stream get crash)" state)" = "restarting" ]; do
  i=$((i + 1))
  [ "$i" -lt 200 ] || { cat "$DIR/lotse.log" >&2; fail "crash never restarted: $(ctl stream get crash)"; }
  sleep 0.1
done
crash="$(ctl stream get crash)"
echo "crash: $crash"
printf '%s' "$crash" | grep -q '"code":"worker_crashed"' || fail "last_error is not worker_crashed"
[ "$(field "$(ctl stream get front)" state)" = "live" ] || fail "front was affected by the crash"
metrics="$(ctl metrics)"
[ "$(field "$metrics" worker_restarts)" -ge 1 ] || fail "no worker restart counted: $metrics"

# Clean stop.
ctl stream delete crash >/dev/null
ctl stream delete front >/dev/null
kill -TERM "$DAEMON"
wait "$DAEMON" || fail "the daemon did not exit cleanly"
grep -q '"event":"ready"' "$DIR/lotse.log" || fail "no ready event in the log"
echo "OK: sandbox enforced, workers isolated, clean stop"

#!/bin/sh
# The TURN client end to end against a real coturn.
#
# Starts two coturn containers, one with a long-term user, an allocation lifetime capped
# at 20 s (so a viewer playing past it proves the refresh) and nonces that go stale after
# 8 s (so each refresh is answered with a 438 first), one with TURN REST
# credentials as a hosted TURN service hands them out (`use-auth-secret`; coturn does not mix the two
# in one server), then runs the ignored `coturn_` tests in crates/lotse/tests/signaling.rs
# one at a time, since each counts its server's allocations, and removes the containers.
#
# Networking: the containers share the host's network (`--network host`), listen and relay on
# 127.0.0.1 and allow loopback peers, so the viewer's host candidate is the peer. Linux only.
set -eu

[ "$(uname -s)" = Linux ] || { echo "the TURN end-to-end test runs on Linux only" >&2; exit 2; }

# coturn 4.18.0 (2026-09-08), the multi-arch index digest.
IMAGE="coturn/coturn:4.18.0@sha256:bbefd3e1fdfdc0d58770fe01b581fd8b00d9f3a5580d00acb77cf719a6bc78e3"
STATIC=lotse-turn-e2e-static
REST=lotse-turn-e2e-rest
SECRET=lotse-rest-secret

cleanup() {
  docker rm -f "$STATIC" "$REST" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT INT TERM

# `start <name> <listening port> <first relay port> <metrics port> <coturn args...>`
start() {
  name=$1 port=$2 relay=$3 metrics=$4
  shift 4
  last=$((relay + 31))
  set -- --network host "$IMAGE" --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --prometheus-address=127.0.0.1 "$@"
  docker run -d --name "$name" --entrypoint turnserver "$@" -n --log-file=stdout --verbose \
    --realm=lotse.test --fingerprint \
    --lt-cred-mech --no-tls --allow-loopback-peers --listening-port="$port" \
    --min-port="$relay" --max-port="$last" --prometheus --prometheus-port="$metrics" >/dev/null
  i=0
  until curl -fs "http://127.0.0.1:$metrics/metrics" >/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || { docker logs "$name" >&2; echo "FAIL: $name did not start" >&2; exit 1; }
    sleep 0.2
  done
}

start "$STATIC" 34780 49400 19641 --user=lotse:lotse-static --max-allocate-lifetime=20 --stale-nonce=8
start "$REST" 34790 49432 19642 --use-auth-secret --static-auth-secret="$SECRET"

# A TURN REST credential valid for an hour: the expiry as the username's prefix, the
# password base64(HMAC-SHA1(secret, username)) (draft-uberti-behave-turn-rest-00 §2.2).
username="$(($(date +%s) + 3600)):ha-cloud"
credential=$(docker exec "$REST" sh -c 'printf %s "$1" | openssl dgst -sha1 -hmac "$2" -binary | base64' \
  _ "$username" "$SECRET")

export LOTSE_COTURN_STATIC=127.0.0.1:34780 LOTSE_COTURN_STATIC_METRICS=127.0.0.1:19641
export LOTSE_COTURN_REST=127.0.0.1:34790 LOTSE_COTURN_REST_METRICS=127.0.0.1:19642
export LOTSE_COTURN_REST_USERNAME="$username" LOTSE_COTURN_REST_CREDENTIAL="$credential"

if ! cargo nextest run -p lotse --all-features --locked --test signaling \
  --run-ignored only --test-threads 1 coturn_; then
  for name in "$STATIC" "$REST"; do
    echo "--- $name" >&2
    docker logs "$name" 2>&1 | tail -n 60 >&2
  done
  exit 1
fi

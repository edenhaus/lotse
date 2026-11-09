#!/bin/sh
# The release image under rootless Podman, as README.md's "Running in a container" runs it. CI's
# Rootless Podman job runs this as the runner's unprivileged user.
#
# Builds the image from Dockerfile and a static release binary with `podman build`, then:
#
# 1. starts it as it is, as 65532: read-only, without a capability, no_new_privs, the ports
#    published, a tmpfs of its own on /run/lotse, a volume on /data, the control TLS listener on and the
#    sandbox required. It must go ready; `lotse ctl info` through `podman exec` must report every
#    sandbox layer enforced as 65532; every lotse process must run as 65532 with no capability
#    and a seccomp filter; a worker must start and reach its source's error; `lotse identity`
#    must read the identity the start made in the volume.
# 2. starts it as root (`--user 0`) with CAP_SETUID and CAP_SETGID alone and a root-owned socket
#    directory: it must drop to 65532 (LOTSE_USER and LOTSE_GROUP) and report the same.
# 3. starts it as root again, with CAP_DAC_OVERRIDE besides, on the directories of 65532 (the
#    first start's /data volume, and a volume on /run/lotse, which takes the image's directory's
#    owner and mode): the owner checks take the uid a start as root drops to, so it must come up
#    on them, serve the identity the first start made, and drop to 65532.
#
# Usage: scripts/rootless-podman.sh <static lotse binary> [x86_64|aarch64]
set -eu

BIN="${1:?usage: $0 <static lotse binary> [x86_64|aarch64]}"
ARCH="${2:-$(uname -m)}"
IMAGE=localhost/lotse:rootless-check
NAME=lotse-rootless-check
VOLUME=lotse-rootless-check-data
RUN_VOLUME=lotse-rootless-check-run
ID=65532 # the image's user and group, LOTSE_USER and LOTSE_GROUP
SOCKET=/run/lotse/lotse.sock

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

cleanup() {
  podman container rm --force --ignore "$NAME" >/dev/null 2>&1 || true
  podman volume rm --force "$VOLUME" "$RUN_VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

case "$ARCH" in
  x86_64) platform=amd64 ;;
  aarch64) platform=arm64 ;;
  *) fail "unknown arch $ARCH" ;;
esac
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = "true" ] ||
  fail "podman is not rootless: run this as an unprivileged user"
podman version --format 'podman {{.Client.Version}}'
podman info --format 'network: {{.Host.NetworkBackend}}, cgroups {{.Host.CgroupsVersion}} ({{.Host.CgroupManager}}: {{.Host.CgroupControllers}}), storage {{.Store.GraphDriverName}}'

# The context Dockerfile takes: the binary at target/image/<arch>/lotse.
context="$(mktemp -d)"
install -D -m 0755 "$BIN" "$context/target/image/$platform/lotse"
podman build --quiet --file Dockerfile --platform "linux/$platform" --tag "$IMAGE" "$context" >/dev/null
echo "built $IMAGE from $BIN"

# The resource limits of the README's unit, where the cgroup controllers are delegated to this
# user: without a systemd user session they are not, and Podman refuses the limits.
limits=""
controllers="$(podman info --format '{{.Host.CgroupControllers}}')"
case "$controllers" in
  *memory*) case "$controllers" in *pids*) limits="--pids-limit=512 --memory=1g" ;; esac ;;
esac
echo "resource limits: ${limits:-none (no delegated memory and pids controllers)}"

# `start <podman run options...>`: the container, detached, until its `ready` event.
start() {
  # shellcheck disable=SC2086 # $limits is a list of options
  podman run --detach --name "$NAME" --read-only --security-opt=no-new-privileges \
    --publish 18556:18556/udp --publish 18556:18556/tcp --publish 18557:18557/tcp \
    --env LOTSE_SANDBOX=require --env LOTSE_WEBRTC_ADVERTISE=192.0.2.10 \
    $limits "$@" "$IMAGE" >/dev/null
  i=0
  until podman logs "$NAME" 2>&1 | grep -q '"event":"ready"'; do
    i=$((i + 1))
    if [ "$i" -ge 100 ] || [ "$(podman inspect --format '{{.State.Running}}' "$NAME")" != "true" ]; then
      podman logs "$NAME" >&2 || true
      fail "the daemon did not go ready"
    fi
    sleep 0.2
  done
}

# `ctl <args>`: `lotse ctl` inside the container, as its user, over the socket.
ctl() {
  podman exec "$NAME" /lotse ctl --socket "$SOCKET" --compact "$@"
}

# `stop`: the daemon stopped by SIGTERM; it must exit 0.
stop() {
  podman stop --time 10 "$NAME" >/dev/null
  code="$(podman inspect --format '{{.State.ExitCode}}' "$NAME")"
  [ "$code" = 0 ] || { podman logs "$NAME" >&2; fail "the daemon exited $code"; }
  podman container rm "$NAME" >/dev/null
}

# `sandboxed <mode>`: `info.sandbox` reports every layer enforced, as $ID.
sandboxed() {
  sandbox="$(ctl info | jq -c .sandbox)"
  echo "sandbox: $sandbox"
  printf '%s' "$sandbox" | jq -e --argjson id "$ID" '
    .mode == "require" and .uid == $id and .gid == $id and .no_new_privs == true
    and .seccomp == "enforced" and .landlock.fs == "enforced" and .landlock.net == "enforced"
    and ((.notes // []) | length == 0)' >/dev/null || fail "a sandbox layer is missing: $sandbox"
}

# `processes`: the container's first process and every descendant, by host pid.
processes() {
  found="$(podman inspect --format '{{.State.Pid}}' "$NAME")"
  all="$found"
  while [ -n "$found" ]; do
    next=""
    for status in /proc/[0-9]*/status; do
      ppid="$(awk '/^PPid:/ {print $2}' "$status" 2>/dev/null)" || continue
      for parent in $found; do
        if [ "$ppid" = "$parent" ]; then
          pid="${status#/proc/}"
          next="$next ${pid%/status}"
        fi
      done
    done
    found="$next"
    all="$all$next"
  done
  echo "$all"
}

# `unprivileged <count>`: at least <count> processes in the container, each with real, effective,
# saved and filesystem uid and gid $ID as the container sees them (the host's ids through the
# user namespace's map), no capability in its effective, permitted or bounding set, no_new_privs
# and a seccomp filter. Read from the host's /proc: `podman top` needs a cgroup, which a rootless
# container without delegated controllers does not get.
unprivileged() {
  n=0
  for pid in $(processes); do
    status="/proc/$pid/status"
    line="$(awk -v map="/proc/$pid/uid_map" -v gmap="/proc/$pid/gid_map" '
      function inside(file, id,   line, f) {
        while ((getline line < file) > 0) {
          split(line, f, " ")
          if (id >= f[2] && id < f[2] + f[3]) { close(file); return id - f[2] + f[1] }
        }
        close(file)
        return "unmapped"
      }
      /^Name:/ { name = $2 }
      /^Uid:/ { uids = inside(map, $2) " " inside(map, $3) " " inside(map, $4) " " inside(map, $5) }
      /^Gid:/ { gids = inside(gmap, $2) " " inside(gmap, $3) " " inside(gmap, $4) " " inside(gmap, $5) }
      /^CapEff:/ { eff = $2 } /^CapPrm:/ { prm = $2 } /^CapBnd:/ { bnd = $2 }
      /^NoNewPrivs:/ { nnp = $2 } /^Seccomp:/ { seccomp = $2 }
      END { print name, "uids", uids, "gids", gids, "eff", eff, "prm", prm, "bnd", bnd, "nnp", nnp, "seccomp", seccomp }
    ' "$status" 2>/dev/null)" || continue # a process that has exited since
    echo "pid $pid: $line"
    want="lotse uids $ID $ID $ID $ID gids $ID $ID $ID $ID eff 0000000000000000 prm 0000000000000000"
    case "$line" in
      "$want bnd "*" nnp 1 seccomp 2") ;;
      *) fail "pid $pid is not unprivileged: $line" ;;
    esac
    n=$((n + 1))
  done
  [ "$n" -ge "$1" ] || fail "expected at least $1 processes, found $n"
}

# 1. As the image's user.
cleanup
start --cap-drop=all --tmpfs /run/lotse:rw,mode=0700,U --volume "$VOLUME:/data" \
  --env 'LOTSE_CONTROL_LISTEN=[::]:18557'
echo "OK: ready as $ID, rootless, read-only, without capabilities"
sandboxed
# A worker: started, sandboxed, and failing to reach a port nothing listens on, which it
# reports; a worker that could not start would report a crash instead.
ctl stream put front --url rtsp://127.0.0.1:9/ --preload >/dev/null
i=0
until [ "$(ctl stream get front | jq -r '.last_error.code // empty')" = source_unreachable ]; do
  i=$((i + 1))
  [ "$i" -lt 100 ] || { podman logs "$NAME" >&2; fail "the worker never reported its source: $(ctl stream get front)"; }
  sleep 0.2
done
echo "front: $(ctl stream get front)"
unprivileged 1
pin="$(podman exec "$NAME" /lotse identity)"
podman logs "$NAME" 2>&1 | grep -q "\"server_pin\":\"$pin\"" || fail "lotse identity read $pin, not the served pin"
echo "OK: lotse identity reads the volume's identity, $pin"
ctl stream delete front >/dev/null
stop

# 2. As root, with CAP_SETUID and CAP_SETGID alone: it binds in its own directory and drops.
start --user 0 --cap-drop=all --cap-add=SETUID,SETGID --tmpfs /run/lotse:rw,mode=0700
echo "OK: ready as root with CAP_SETUID and CAP_SETGID"
sandboxed
unprivileged 1
stop

# 3. As root on the directories of the uid it drops to.
start --user 0 --cap-drop=all --cap-add=SETUID,SETGID,DAC_OVERRIDE \
  --volume "$RUN_VOLUME:/run/lotse" --volume "$VOLUME:/data" \
  --env 'LOTSE_CONTROL_LISTEN=[::]:18557'
echo "OK: ready as root on the directories of $ID"
sandboxed
podman logs "$NAME" 2>&1 | grep -q "\"server_pin\":\"$pin\"" || fail "the start as root did not serve the identity $pin"
unprivileged 1
stop
echo "OK: the release image runs rootless, read-only and without capabilities"

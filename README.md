# lotse

A small, fast, memory-safe media daemon built for Home Assistant. It takes
camera streams (RTSP, HLS or MPEG-TS over HTTP, and WebRTC cameras such as
Nest, Ring and Matter ones, whose signaling its client relays) and serves them to
browsers over WebRTC, with two-way audio designed in from the start, and
as event recordings: fragmented MP4 that starts before the event, from the
seconds it keeps in memory, for its client to store. It does nothing
else.

> [!WARNING]
> **Design phase, not for production use.** lotse is at an early stage. It
> has not had an independent security review and has not been tested
> widely. The control API, configuration and command line may change
> between versions without migration. Don't rely on it for your cameras,
> and don't expose its ports to the internet unless you accept that risk.

## Why

Live camera view in Home Assistant needs little from a media daemon: one
signaling path (offer/answer/candidate), a stream registry, a JPEG
snapshot, a way to keep a stream connected without viewers, and a recording of
an event with the seconds before it.

lotse is scoped to exactly that, written in Rust with a sans-IO WebRTC
engine, a battle-tested RTSP client, in-process audio transcoding, a
process per camera, and a typed control API over a private Unix socket
that any program can drive; Home Assistant's integration is the client it
is designed with.

## Design principles

- **Live.** RTP packets are cut through to viewers the moment they arrive,
  never held for a whole frame. Every queue is bounded by age. Keyframes
  are requested from the camera instead of replaying old ones. The target
  is glass-to-glass p50 under 300 ms on LAN.
- **Isolated.** One sandboxed worker process per camera connection. A
  crash costs that camera's viewers, never the other cameras.
- **Least privilege by default.** Started as root, it binds its sockets
  and drops to an unprivileged uid; its container image starts as one and
  needs no capability. Every process runs under
  seccomp and Landlock. C code that decodes camera bytes runs in a
  throwaway decoder process with no network and no files.
- **Strict.** `#![forbid(unsafe_code)]` in all our crates; C libraries
  (libopus, mimalloc, OpenH264) only through existing safe wrappers.
  Pedantic Clippy. No panics on network input. Fuzzed parsers.
- **Safe control plane.** Filesystem Unix socket in a private per-spawn
  directory, peer-credential checks. Over the network only when asked,
  and then mutual TLS with pinned certificates, paired with a one-time
  code. No shell-outs. Explicit resource limits.
- **Fast.** One UDP socket for all viewers, zero-copy fan-out with `Bytes`,
  no per-packet allocation on the hot path, static musl binaries tuned per
  target.
- **Small surface.** Only the features live viewing and event recordings need. New features start
  as a design, reviewed before any code.

## Platforms

| Target | Role | Notes |
|---|---|---|
| `x86_64-unknown-linux-musl` | Production | Static binary, x86-64-v2 baseline + runtime dispatch |
| `aarch64-unknown-linux-musl` | Production | Static binary, ARMv8.0 baseline + runtime dispatch |

## Trying it with a camera

For development only; in production a client program drives the daemon
over the control API. In M1 an H.264 camera plays video (no audio yet)
over RTSP/TCP, on the LAN or through a STUN-only NAT.

```sh
mkdir -m 700 /tmp/lotse     # the control socket's directory must be private
cargo run -p lotse -- serve --socket /tmp/lotse/lotse.sock --log-format text
cargo run -p lotse-testing --bin lotse-dev-viewer -- --socket /tmp/lotse/lotse.sock
```

Open <http://127.0.0.1:8080>, enter the camera's `rtsp://user:pass@host/path`
URL and press Play. The video fills the window beside the controls (below
them on a phone). The field shows the password masked unless you are
editing it, so screenshots do not leak it; copying and reloads keep the
real URL. *Save* keeps the stream id, URL, an optional name, the
orientation and the two-way audio choice in the browser's local storage,
the URL without its user and password: those stay with the tab (session
storage), so a reload keeps
them and a new tab asks for them again (pick the stream, type them into
the URL and *Save*). Picking a saved stream plays it, and the list shows
its password masked too. *Orientation* is
`stream/put`'s `orientation`: changing it while playing puts the stream
again and the open session turns the picture from its next frame, without
reconnecting; the CVO row says whether the answer negotiated the video
orientation extension or the browser did not offer it. *Two-way audio*
puts the stream with the RTSP field `backchannel` and offers a
send-only audio m-line right after; the daemon answers it from the
camera's backchannel once its probe found it, or declines it with
`backchannel_declined` and why while the session plays (the page shows it); *Talk* then
asks for the microphone and sends it to the camera's speaker, and
stopping releases the backchannel for other viewers. The browser offers
the microphone only to a page opened at `localhost` or a loopback
address. The page shows
the session's progress, the time to the first frame and the browser's
receive statistics. `lotse-dev-viewer` relays the page to the daemon's
socket and nothing else.
`--listen ADDR` serves it elsewhere than `127.0.0.1:8080`, on a loopback
address only: anything that reaches the relay drives the daemon, so an
address reachable from the network also needs `--insecure-listen`.

Browsers reach the daemon's WebRTC media at the host addresses of its UDP
socket (`--webrtc-udp-listen`) and ICE-TCP listener
(`--webrtc-tcp-listen`). Behind a container's bridge network, with those
ports published instead of host networking, those addresses are the
container's own, which no browser reaches: `--webrtc-advertise`
(`LOTSE_WEBRTC_ADVERTISE`, `webrtc.advertise` in the config file) names up
to eight addresses, `IP` or `IP:PORT`, that browsers are told instead, and
with one set they are told none of the container's own.

Every source of `stream/put` is named by its `protocol`, with that
protocol's own fields beside it, and `stream/get` reports it in the same
shape (its URL redacted); `info.protocols` lists the protocols a build
registered:

```json
{ "protocol": "rtsp",   "url": "rtsp://user:pass@cam/s1", "transport": "udp", "backchannel": true }
{ "protocol": "rtsps",  "url": "rtsps://cam/s1", "tls": { "pin": "AB:CD:…" } }
{ "protocol": "http",   "url": "http://cam/live.m3u8", "max_bandwidth": 4000000 }
{ "protocol": "https",  "url": "https://cam/live.m3u8", "tls": "insecure" }
{ "protocol": "webrtc", "data_channel": "dataSendChannel" }
```

A URL protocol's name is its URL's scheme; credentials go in the URL's
userinfo. `tls` is `"roots"` (the default), `"insecure"` (warned about on
every connection) or `{"pin": "<SHA-256 fingerprint>"}`. `lotse ctl
stream put` names a source by its `--url`'s scheme, or by `--protocol`
for one without a URL, and merges `--options` into it.

A WebRTC camera (Home Assistant's native WebRTC cameras: Nest, Ring,
Matter) has no address lotse could connect to, so a stream names it by
its protocol alone, `{"protocol": "webrtc"}`, and the stream is its
identity; its one field is `data_channel` (the data channel label the
camera's integration asks for, `dataSendChannel` for Nest). The offer
always asks for the camera's audio; a camera without audio rejects that
m-line (RFC 3264 §6) and the stream has video alone. lotse makes the offer, but the camera's signaling is its
cloud's, so the control-API client relays it: it subscribes with
`signaling/subscribe`, takes each `offer` event (it names the stream) and
each `candidate` event to the camera, and brings back the camera's answer, its
candidates and its errors with `signaling/answer`, `signaling/candidate`
and `signaling/error`; a `closed` event ends the camera's session. The
media then comes straight from the camera to the worker over UDP: the
source gathers its candidates on the host addresses of the WebRTC UDP
front door (`--webrtc-udp-listen`; the `ready` event lists them), each on
a port of its own, so the camera's media server must reach one of them.
With no host address found, or without a subscribed client, the source
reports `source_unreachable`.
The dev viewer does not relay signaling, so such a source needs a client
that does.

## Running in a container

The release image (`ghcr.io/<owner>/lotse`, built from `Dockerfile`)
holds the static binary alone and runs as uid and gid 65532 from the start.
A rootless engine maps that uid from its default subordinate ids (any uid
below 65536 is in them), so the daemon runs as nobody's root and with no
capability at all, under its own sandbox: `LOTSE_SANDBOX=require` refuses
to start without every layer. Podman is the engine this is written and
tested for (CI's Rootless Podman job runs the image this way).

As a rootless Podman Quadlet unit,
`~/.config/containers/systemd/lotse.container`:

```ini
[Unit]
Description=lotse media daemon
Wants=network-online.target
After=network-online.target

[Container]
ContainerName=lotse
Image=ghcr.io/<owner>/lotse:<version>@sha256:<digest>
ReadOnly=true
DropCapability=ALL
NoNewPrivileges=true
# The socket's directory, the container user's, mode 0700 as `serve` checks it.
Tmpfs=/run/lotse:rw,mode=0700,U
Volume=lotse-data:/data
PublishPort=18556:18556/udp
PublishPort=18556:18556/tcp
# The control API over mutual TLS, for a client outside the container.
PublishPort=18557:18557/tcp
Environment=LOTSE_CONTROL_LISTEN=[::]:18557
# The host's LAN address, which browsers are told.
Environment=LOTSE_WEBRTC_ADVERTISE=192.168.1.10
Environment=LOTSE_SANDBOX=require
HealthCmd=["/lotse", "ctl", "--socket", "/run/lotse/lotse.sock", "info"]
HealthInterval=30s
PidsLimit=512
Memory=1G

[Service]
Restart=always

[Install]
WantedBy=default.target
```

`systemctl --user daemon-reload && systemctl --user start lotse` starts
it, and `loginctl enable-linger` starts it at boot without a login.
`podman logs lotse` shows the first client's pairing code and
`podman exec lotse /lotse pair` makes another. Without the TLS listener a
client reaches the socket only from inside the container, or from a
container that shares `/run/lotse` as a volume and runs as 65532 (or the
uid `LOTSE_ALLOW_UID` names).

- `HealthCmd` is a JSON array: the image has no shell, and Podman runs a
  plain string through `/bin/sh -c`, which fails.
- `Tmpfs=`'s `U` gives the tmpfs to the container's user; Podman refuses
  `uid=` and `gid=` there.
- `Memory=` needs Podman 5.5 or later (`PodmanArgs=--memory=1g` before),
  and `Memory=` and `PidsLimit=` need the cgroup controllers a systemd user
  session delegates. Size them for the cameras: each camera connection is
  a worker process of its own.
- No `UserNS=`: the default rootless user namespace already maps 65532,
  and the daemon needs no host uid inside it.

The same as one `podman run`:

```sh
podman run -d --name lotse --read-only --cap-drop=all --security-opt=no-new-privileges \
  --tmpfs /run/lotse:rw,mode=0700,U -v lotse-data:/data \
  -p 18556:18556/udp -p 18556:18556/tcp -p 18557:18557/tcp \
  -e 'LOTSE_CONTROL_LISTEN=[::]:18557' -e LOTSE_WEBRTC_ADVERTISE=192.168.1.10 \
  -e LOTSE_SANDBOX=require --pids-limit=512 --memory=1g \
  ghcr.io/<owner>/lotse:<version>@sha256:<digest>
```

A compose file works the same way under podman-compose or docker compose,
with the same settings (`read_only`, `cap_drop: [ALL]`,
`security_opt: [no-new-privileges:true]`, the tmpfs, the volume, the
ports, the environment, `pids_limit`, `mem_limit`); Docker's tmpfs takes
`uid=65532,gid=65532` in place of `U`.

Started as root instead (`--user 0`), the daemon binds and drops to
`LOTSE_USER` and `LOTSE_GROUP`, which the image sets to 65532 too. It then
needs CAP_SETUID and CAP_SETGID, and its socket and data directories may
belong to root or to 65532: reaching 65532's as root takes
CAP_DAC_OVERRIDE, and making the enrolled clients' directory for 65532
takes CAP_CHOWN. The start as 65532 needs none of them.

No host network is needed. Every browser session shares one UDP port and
one ICE-TCP port, 18556, published as it is (keep the host's port the
container's, or advertise `IP:PORT`). The daemon's own addresses are the
container's, so `LOTSE_WEBRTC_ADVERTISE` names the host's LAN address that
browsers are told instead, and with it set they are told none of the
container's. What the rootless network does to this, observed on
2026-11-09 with Podman 5.8.9 (pasta 2026-10-02) and Podman 4.9.3
(Ubuntu 24.04: slirp4netns 1.2.1, pasta 2024-02-20):

- pasta, the default from Podman 5.0, copies the host's address into the
  container: the daemon listed the host's address and port 18556 as its
  host candidate. A datagram or a connection to the published port from
  another machine arrived with that machine's address and port, and the
  answer left from the published port. So under pasta the host candidate
  alone is reachable, without `LOTSE_WEBRTC_ADVERTISE`. Not verified: a
  browser's ICE session end to end, a host with several addresses or
  interfaces (pasta copies those of the default route's interface), and
  the host's address changing while the container runs. Setting
  `LOTSE_WEBRTC_ADVERTISE` keeps the candidate right whichever network the
  engine uses.
- slirp4netns, the default before Podman 5, gives the container 10.0.2.100
  (and an `fd00::` address), which no browser reaches:
  `LOTSE_WEBRTC_ADVERTISE` is required. Its default port forwarder replaces
  the source of an inbound datagram or connection with 10.0.2.100 and a
  port of its own; `--network slirp4netns:port_handler=slirp4netns` keeps
  the browser's. Not verified: an ICE session through the default
  forwarder.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

This is the Rust default (rustc, std, serde), so contributors and tooling
expect it. The Apache-2.0 option carries the contributor patent grant; the
MIT option keeps GPLv2 compatibility for distro packaging. Both are
compatible with Home Assistant core (Apache-2.0), and lotse ships as a
separate binary.
Narrowing to Apache-2.0 alone later needs no contributor consent, because
every contribution is already offered under it; broadening from
Apache-2.0 alone would need every copyright holder. Whether the Open Home
Foundation has an Apache-2.0-only policy is still open.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

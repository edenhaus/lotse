# rocko

A small, fast, memory-safe media daemon built for Home Assistant. It takes
camera streams (RTSP, HLS or MPEG-TS over HTTP, and WebRTC cameras such as
Nest, Ring and Matter ones, whose signaling its client relays) and serves them to
browsers over WebRTC, with two-way audio designed in from the start, as
live fMP4 over HTTP where WebRTC cannot connect, and
as event recordings: fragmented MP4 that starts before the event, from the
seconds it keeps in memory, for its client to store. It does nothing
else.

> [!WARNING]
> **Design phase, not for production use.** rocko is at an early stage. It
> has not had an independent security review and has not been tested
> widely. The control API, configuration and command line may change
> between versions without migration. Don't rely on it for your cameras,
> and don't expose its ports to the internet unless you accept that risk.

## Why

Live camera view in Home Assistant needs little from a media daemon: one
signaling path (offer/answer/candidate), a stream registry, a JPEG
snapshot, a way to keep a stream connected without viewers, and a recording of
an event with the seconds before it.

rocko is scoped to exactly that, written in Rust with a sans-IO WebRTC
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
  seccomp and Landlock, and by default (`--sandbox require`) refuses to
  start on a kernel that lacks a layer; `--sandbox on` runs with the
  layers it has and reports the rest. C code that decodes camera bytes is to
  run in a throwaway decoder process with no network and no files; none
  exists yet, as nothing decodes camera bytes in C: the one C library,
  libopus, runs in the camera's worker, where it encodes audio and decodes
  the talk-back audio a viewer sends.
- **Strict.** `#![forbid(unsafe_code)]` in all our crates; C libraries
  (libopus today; OpenH264 with snapshots) only through existing safe
  wrappers.
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
mkdir -m 700 /tmp/rocko     # the control socket's directory must be private
cargo run -p rocko -- serve --socket /tmp/rocko/rocko.sock --log-format text --sandbox on
cargo run -p rocko-testing --bin rocko-dev-viewer -- --socket /tmp/rocko/rocko.sock
```

`--sandbox on`: a development host (macOS, or a kernel without every
seccomp and Landlock layer) cannot meet the default, `require`, which
refuses to start and names the missing layer.

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
receive statistics. `rocko-dev-viewer` relays the page to the daemon's
socket and nothing else.
`--listen ADDR` serves it elsewhere than `127.0.0.1:8080`, on a loopback
address only: anything that reaches the relay drives the daemon, so an
address reachable from the network also needs `--insecure-listen`.

Browsers reach the daemon's WebRTC media at the host addresses of its UDP
socket (`--webrtc-udp-listen`) and ICE-TCP listener
(`--webrtc-tcp-listen`). Behind a container's bridge network, with those
ports published instead of host networking, those addresses are the
container's own, which no browser reaches: `--webrtc-advertise`
(`ROCKO_WEBRTC_ADVERTISE`, `webrtc.advertise` in the config file) names up
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
every connection) or `{"pin": "<SHA-256 fingerprint>"}`. `rocko ctl
stream put` names a source by its `--url`'s scheme, or by `--protocol`
for one without a URL, and merges `--options` into it.

A WebRTC camera (Home Assistant's native WebRTC cameras: Nest, Ring,
Matter) has no address rocko could connect to, so a stream names it by
its protocol alone, `{"protocol": "webrtc"}`, and the stream is its
identity; its one field is `data_channel` (the data channel label the
camera's integration asks for, `dataSendChannel` for Nest). The offer
always asks for the camera's audio; a camera without audio rejects that
m-line (RFC 3264 §6) and the stream has video alone. rocko makes the offer, but the camera's signaling is its
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

## Live fMP4 over HTTP

WebRTC is the main path to a browser. Where it cannot connect (UDP
blocked, no TURN server), a client falls back to live fMP4 over HTTP, which
a browser plays through Media Source Extensions about half a second behind
the camera:

```json
{ "id": 7, "type": "live/create", "stream_id": "front", "audio": true }
```

The result names the output, its MIME type with the RFC 6381 `codecs`
parameter, for the client's `MediaSource.isTypeSupported`, and where its
bytes are:

```json
{ "live_id": "01JD…", "mime": "video/mp4; codecs=\"avc1.640028,mp4a.40.2\"", "url": "/v0/live/01JD…" }
```

`GET /v0/live/{live_id}` on the same socket (or the mTLS listener) takes the
bytes once, in the chunked transfer coding: the init segment, then one
`moof`+`mdat` per video frame with the audio up to it, from the stream's
cached keyframe on. The client proxies it to the browser; the daemon refuses
a request that carries `Origin`. The command waits for the worker's init
segment, at most `limits.live_start_timeout_ms` (10 s), since the MIME type
needs the camera's parameter sets. The connection goes on reading and
answering other commands meanwhile, so the result may come after theirs: an
on-demand WebRTC camera starts for the output and sends its offer to the
`signaling/subscribe` subscription, and the client's `signaling/answer` on
the same connection is what lets the create finish. A waiting create counts
against the connection's subscription cap from the start.

- **Join.** The output starts at the stream's cached GOP and sends it at
  once, so its first frame is as old as that GOP: up to the camera's
  keyframe interval behind live. A player appends the burst and jumps to the
  end of what it buffered.
- **A slow reader.** A frame is out one frame interval after it arrived
  (each waits for the next to know its duration). When the body is read
  slower than the camera sends and more than `limits.live_buffer_bytes`
  (1 MiB) wait in the worker, the output drops every frame up to the next
  keyframe and goes on from where its video ended, so the player's timeline
  has no hole; `closed` counts the drops. A client that reads nothing for
  10 s is dropped.
- **Audio.** AAC-LC and Opus go in as the camera sends them; anything else
  (G.711, G.722) is left out with an `audio_omitted` warning, never
  transcoded: `"audio": false` asks for video alone, for a player that
  cannot play the stream's audio.
- **The end.** `closed` names why: `closed` (`live/close`), `client_gone`,
  `session_closed` (the control connection that created it closed or
  unsubscribed), `not_fetched` (no `GET` within
  `limits.live_fetch_timeout_ms`, 10 s), `stream_deleted`, `stream_changed`,
  `codec_changed` (another codec, profile, level or picture size: create a
  new output, whose init segment describes it), `no_video_track`,
  `source_not_live`, `worker_crashed`, `shutting_down`, `internal_error`.
  The body ends with its last chunk when the output ends.
- **Limits.** `limits.max_live` (16) outputs at once and
  `limits.max_live_per_stream` (8) per stream; one more is `limit_reached`.

## LL-HLS

Where a player wants a playlist rather than one fMP4 body (a native HLS
player, one without Media Source Extensions), a client plays the stream as
Low-Latency HLS (draft-pantos-hls-rfc8216bis-22):

```json
{ "id": 8, "type": "hls/create", "stream_id": "front", "audio": true }
```

The result names the session, the MIME type of its segments with their
`codecs`, and its Media Playlist:

```json
{ "hls_id": "01JE…", "mime": "video/mp4; codecs=\"avc1.640028,mp4a.40.2\"", "playlist": "/v0/hls/01JE…/index.m3u8" }
```

`GET /v0/hls/{hls_id}/index.m3u8` on the same socket (or the mTLS listener)
is the playlist; it names `init.mp4`, the segments `seg{msn}.m4s` and the
parts `part{msn}.{index}.m4s` relative to itself. The client proxies them to
the player; the daemon refuses a request that carries `Origin`.

- **One window per stream.** The sessions of one stream and `audio` choice
  share one live output, which the daemon reads itself into a window of
  segments and parts: the first `hls/create` starts it and waits, as
  `live/create` does, for the init segment; later ones join at once. A
  segment starts with a keyframe and lasts `limits.hls_segment_target_ms`
  (1 s) or the camera's keyframe interval if that is longer; a part is the
  whole frames that fit `limits.hls_part_target_ms` (200 ms). The playlist
  lists 6 segments and the parts of the last three Target Durations.
- **Latency.** A player starts three parts behind the playlist's end
  (`PART-HOLD-BACK`, three Part Target Durations: about 600 ms with the
  default), so it plays a little under a second behind the camera, one
  frame interval more since a frame waits for the next to know its
  duration. Lower part targets lower it at the price of more requests: a
  player makes a blocking playlist request and a part request per part.
- **Blocking requests.** `index.m3u8?_HLS_msn=M&_HLS_part=N` is held until
  the playlist holds that part (a Blocking Playlist Reload), and so is a
  request for the part the playlist's `EXT-X-PRELOAD-HINT` names, or any
  request before the first segment completes. A held request is answered
  503 `source_timeout` after three Target Durations; `limits.max_hls_blocked_per_session`
  (4: the reload and the part a player holds, twice) and
  `limits.max_hls_blocked` (128) bound how many wait at once, past which a
  request is 429 `limit_reached`. A directive asking too far ahead is 400.
- **Requests in flight.** A request counts from its arrival until its
  response's connection ends (the client took the last byte, through TLS
  too) or its client goes, a held one included:
  `limits.max_hls_requests_per_session` (8: the two held, a download and
  the init segment, twice) and `limits.max_hls_requests` (256) bound how
  many are in flight at once, past which a request is 429 `limit_reached`.
  A client taking a response slowly keeps its place, so these bound the
  connections LL-HLS keeps open and the media its responses hold.
- **Answers.** The playlist is `application/vnd.apple.mpegurl` with
  `Cache-Control: no-cache`, a segment or part `video/mp4` with
  `max-age=60`; each has its `Content-Length`, and each response closes its
  connection: a player holds a few at once. A name the window no longer
  holds is 404 `hls_resource_not_found`, a session that is gone 404
  `hls_not_found`.
- **The end.** A session ends on `hls/close` (`closed`), when the control
  connection that created it closes or unsubscribes (`session_closed`),
  without a request for `limits.hls_idle_timeout_ms` (30 s: a player asks
  several times a second; `idle`), counted from the `hls/create`'s answer,
  so a slow start does not end it, or with its output, whose `closed`
  carries the live output's reasons, or `window_full` when the stream sends
  no keyframe within `limits.hls_window_bytes`. The output ends when its
  last session leaves.
- **Limits.** `limits.max_hls_outputs` (8, each also a live output under
  `limits.max_live`) windows of at most `limits.hls_window_bytes` (32 MiB:
  seven 2 s segments of a 16 Mbit/s stream) each, so at most 256 MiB of
  media in the windows, and one segment or part more for each request in
  flight; `limits.max_hls_sessions` (32) and
  `limits.max_hls_sessions_per_stream` (8) sessions; one more is
  `limit_reached` naming the limit.
- **Deviations from the draft.** The Target Duration and Part Target
  Duration rise when a camera's keyframe interval grows or its frame rate
  falls, where §6.2.1 says they never change (the alternative breaks their
  upper bounds); the window's segment count and byte cap drop a segment
  even when the playlist then lasts less than three Target Durations
  (§6.2.2); and the playlist has no `EXT-X-PROGRAM-DATE-TIME` (Appendix
  B.1), there being one rendition and no wall clock in the window.

## Running in a container

The release image (`ghcr.io/<owner>/rocko`, built from `Dockerfile`)
holds the static binary alone and runs as uid and gid 65532 from the start.
A rootless engine maps that uid from its default subordinate ids (any uid
below 65536 is in them), so the daemon runs as nobody's root and with no
capability at all, under its own sandbox: `ROCKO_SANDBOX=require` refuses
to start without every layer. Podman is the engine this is written and
tested for (CI's Rootless Podman job runs the image this way).

As a rootless Podman Quadlet unit,
`~/.config/containers/systemd/rocko.container`:

```ini
[Unit]
Description=rocko media daemon
Wants=network-online.target
After=network-online.target

[Container]
ContainerName=rocko
Image=ghcr.io/<owner>/rocko:<version>@sha256:<digest>
ReadOnly=true
DropCapability=ALL
NoNewPrivileges=true
# The socket's directory, the container user's, mode 0700 as `serve` checks it.
Tmpfs=/run/rocko:rw,mode=0700,U
Volume=rocko-data:/data
PublishPort=30415:30415/udp
PublishPort=30415:30415/tcp
# The control API over mutual TLS, for a client outside the container.
PublishPort=18557:18557/tcp
Environment=ROCKO_CONTROL_LISTEN=[::]:18557
# The host's LAN address, which browsers are told.
Environment=ROCKO_WEBRTC_ADVERTISE=192.168.1.10
Environment=ROCKO_SANDBOX=require
HealthCmd=["/rocko", "ctl", "--socket", "/run/rocko/rocko.sock", "info"]
HealthInterval=30s
PidsLimit=512
Memory=1G

[Service]
Restart=always

[Install]
WantedBy=default.target
```

`systemctl --user daemon-reload && systemctl --user start rocko` starts
it, and `loginctl enable-linger` starts it at boot without a login.
`podman logs rocko` shows the first client's pairing code and
`podman exec rocko /rocko pair` makes another. Without the TLS listener a
client reaches the socket only from inside the container, or from a
container that shares `/run/rocko` as a volume and runs as 65532: the
directory is 0700 and the socket 0600, both 65532's, so another uid
cannot open it, whatever `ROCKO_ALLOW_UID` admits.

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
podman run -d --name rocko --read-only --cap-drop=all --security-opt=no-new-privileges \
  --tmpfs /run/rocko:rw,mode=0700,U -v rocko-data:/data \
  -p 30415:30415/udp -p 30415:30415/tcp -p 18557:18557/tcp \
  -e 'ROCKO_CONTROL_LISTEN=[::]:18557' -e ROCKO_WEBRTC_ADVERTISE=192.168.1.10 \
  -e ROCKO_SANDBOX=require --pids-limit=512 --memory=1g \
  ghcr.io/<owner>/rocko:<version>@sha256:<digest>
```

A compose file works the same way under podman-compose or docker compose,
with the same settings (`read_only`, `cap_drop: [ALL]`,
`security_opt: [no-new-privileges:true]`, the tmpfs, the volume, the
ports, the environment, `pids_limit`, `mem_limit`); Docker's tmpfs takes
`uid=65532,gid=65532` in place of `U`.

Started as root instead (`--user 0`), the daemon binds and drops to
`ROCKO_USER` and `ROCKO_GROUP`, which the image sets to 65532 too. It then
needs CAP_SETUID and CAP_SETGID, and its socket and data directories may
belong to root or to 65532: reaching 65532's as root takes
CAP_DAC_OVERRIDE, and making the enrolled clients' directory for 65532
takes CAP_CHOWN. The start as 65532 needs none of them.

A data volume of the 0.0.1 image, which started as root and dropped to
65534, belongs to root and 65534 and is no use to 65532. Give it to 65532
once, before the first start of the new image:

```sh
podman run --rm -v rocko-data:/data mirror.gcr.io/library/busybox:1.37.0 \
  chown -R 65532:65532 /data
```

No host network is needed. Every browser session shares one UDP port and
one ICE-TCP port, 30415, published as it is (keep the host's port the
container's, or advertise `IP:PORT`). The daemon's own addresses are the
container's, so `ROCKO_WEBRTC_ADVERTISE` names the host's LAN address that
browsers are told instead, and with it set they are told none of the
container's. What the rootless network does to this, observed on
2026-11-09 with Podman 5.8.9 (pasta 2026-10-02) and Podman 4.9.3
(Ubuntu 24.04: slirp4netns 1.2.1, pasta 2024-02-20):

- pasta, the default from Podman 5.0, copies the host's address into the
  container: the daemon listed the host's address, at the published port,
  as its host candidate. A datagram or a connection to the published port from
  another machine arrived with that machine's address and port, and the
  answer left from the published port. So under pasta the host candidate
  alone is reachable, without `ROCKO_WEBRTC_ADVERTISE`. Not verified: a
  browser's ICE session end to end, a host with several addresses or
  interfaces (pasta copies those of the default route's interface), and
  the host's address changing while the container runs. Setting
  `ROCKO_WEBRTC_ADVERTISE` keeps the candidate right whichever network the
  engine uses.
- slirp4netns, the default before Podman 5, gives the container 10.0.2.100
  (and an `fd00::` address), which no browser reaches:
  `ROCKO_WEBRTC_ADVERTISE` is required. Its default port forwarder replaces
  the source of an inbound datagram or connection with 10.0.2.100 and a
  port of its own; `--network slirp4netns:port_handler=slirp4netns` keeps
  the browser's. Not verified: an ICE session through the default
  forwarder.

## Metrics with Prometheus

The daemon serves its metrics at `GET /v0/metrics`, on the control socket
and on the mutual-TLS control listener (`ROCKO_CONTROL_LISTEN`), never
anywhere without authentication. The scraper's `Accept` header picks the
format, as Prometheus negotiates it: OpenMetrics 1.0, which Prometheus asks
for by default, or the Prometheus text format 0.0.4, the fallback for
anything else (a wildcard included).
They are the numbers `metrics/get` returns: the supervisor's and each
worker's memory and tasks, the WebRTC demux's counters, and each stream's
counters, labelled with its stream id. A Prometheus scrapes them over the
listener as a `metrics` client: its certificate's pin may read
`/v0/metrics` and nothing else, so a leaked scraper key exposes the
metrics, never control of the daemon. The commands below are those of the
container above; `--socket` and `--data-dir` name the paths elsewhere.

1. On the Prometheus host, make its key and certificate. The private key
   never leaves that host; the daemon only gets the certificate's pin:

   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout rocko-client.key -out rocko-client.pem -days 36500 -subj "/CN=prometheus"
   openssl x509 -in rocko-client.pem -noout -fingerprint -sha256
   ```

   The fingerprint after `=` is the pin, taken as printed, in either case,
   with or without the colons. The daemon never checks a client certificate's
   validity (the pin is the authority, and removing it is how a client is
   revoked), so the lifetime only matters to Prometheus. The listener
   accepts ECDSA P-256 and Ed25519 keys only: an RSA key is refused in the
   handshake.

2. Enroll the pin as a `metrics` client, either fixed in the configuration
   (`ROCKO_METRICS_CLIENTS`, `--metrics-clients` or `[metrics] clients`,
   comma-separated like `ROCKO_CONTROL_CLIENTS`; a restart takes it), or at
   once, with no restart, over the control socket, which keeps it in the
   data directory:

   ```sh
   podman exec rocko /rocko ctl clients add <pin> metrics
   ```

   A pin is either a `control` or a `metrics` client: one given both roles
   stops the start, and `clients add` refuses a pin that has the other
   role until it is removed. `clients list` shows each pin's role.

3. Copy the daemon's certificate to Prometheus, which trusts it as its CA
   file and checks the DNS name `rocko` in it:

   ```sh
   podman exec rocko /rocko identity --certificate > rocko-server.pem
   ```

   It prints the certificate alone, never the key. An identity made before
   the daemon put that name in its certificate has none, and the command
   says so: `podman exec rocko /rocko identity --reissue` makes a new
   certificate from the same key, which changes the pin, so every client
   pairs again (and a client that pinned the old one by hand takes the new
   one), and the daemon serves it once restarted.

4. Scrape it:

   ```yaml
   scrape_configs:
     - job_name: rocko
       scheme: https
       metrics_path: /v0/metrics
       static_configs: [{ targets: ["<host>:18557"] }]
       tls_config:
         ca_file: /etc/prometheus/rocko-server.pem
         server_name: rocko
         cert_file: /etc/prometheus/rocko-client.pem
         key_file: /etc/prometheus/rocko-client.key
   ```

5. Revoke it with `podman exec rocko /rocko ctl clients remove <pin>`,
   which closes its connections at once; a fixed pin goes from the
   configuration instead.

The metrics' names start with `rocko_`, a counter's end in `_total`, and
units are in the name (`_bytes`, `_seconds`). Over TLS, a `metrics`
client is answered 403 on every other route and 404 on a path that does
not exist. `mise run interop` runs this setup against a real Prometheus.

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
compatible with Home Assistant core (Apache-2.0), and rocko ships as a
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

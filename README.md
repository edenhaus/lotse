# lotse

A small, fast, memory-safe media daemon built for Home Assistant. It takes
camera streams (RTSP first) and serves them to browsers over WebRTC, with
two-way audio designed in from the start, and does nothing else.

> [!WARNING]
> **Design phase, not for production use.** lotse is at an early stage. It
> has not had an independent security review and has not been tested
> widely. The control API, configuration and command line may change
> between versions without migration. Don't rely on it for your cameras,
> and don't expose its ports to the internet unless you accept that risk.

## Why

Live camera view in Home Assistant needs little from a media daemon: one
signaling path (offer/answer/candidate), a stream registry, a JPEG
snapshot, and a way to keep a stream connected without viewers.

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
  and drops to an unprivileged uid. Every process runs under
  seccomp and Landlock. C code that decodes camera bytes runs in a
  throwaway decoder process with no network and no files.
- **Strict.** `#![forbid(unsafe_code)]` in all our crates; C libraries
  (libopus, mimalloc, OpenH264) only through existing safe wrappers.
  Pedantic Clippy. No panics on network input. Fuzzed parsers.
- **Safe control plane.** Filesystem Unix socket in a private per-spawn
  directory, peer-credential checks. No TCP control plane. No shell-outs.
  Explicit resource limits.
- **Fast.** One UDP socket for all viewers, zero-copy fan-out with `Bytes`,
  no per-packet allocation on the hot path, static musl binaries tuned per
  target.
- **Small surface.** Only the features live viewing needs. New features start
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
real URL. *Save* keeps the stream id, URL, an optional name and the
orientation in the browser's local storage, the URL without its user and
password: those stay with the tab (session storage), so a reload keeps
them and a new tab asks for them again (pick the stream, type them into
the URL and *Save*). Picking a saved stream plays it, and the list shows
its password masked too. *Orientation* is
`stream/put`'s `orientation`: changing it while playing puts the stream
again and the open session turns the picture from its next frame, without
reconnecting; the CVO row says whether the answer negotiated the video
orientation extension or the browser did not offer it. The page shows
the session's progress, the time to the first frame and the browser's
receive statistics. `lotse-dev-viewer` relays the page to the daemon's
socket and nothing else.
`--listen ADDR` serves it elsewhere than `127.0.0.1:8080`, on a loopback
address only: anything that reaches the relay drives the daemon, so an
address reachable from the network also needs `--insecure-listen`.

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

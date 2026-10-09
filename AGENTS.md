# AGENTS.md

Instructions for AI-assisted development in this repository. `CLAUDE.md`
includes this file; keep all agent guidance here. `AI_POLICY.md` states the
rule for humans: whoever submits a change can explain every line of it.

## What this is

lotse is a media daemon built for Home Assistant: RTSP cameras in, WebRTC
to browsers out, driven by its client over a Unix-socket control API. It is in the
design phase.

## Commands

mise is the only tool to install by hand: `mise install` fetches the pinned
tools (Rust from `rust-toolchain.toml`, the rest from `mise.toml`, each
download checked against `mise.lock`) and installs the git hooks. After
changing `[tools]`, run `mise lock` and commit both files.

Every check is a prek hook in `.pre-commit-config.yaml`: fmt, clippy,
rustdoc, cargo-hack, cargo-shear, the fuzz crate's `cargo check`, the
crate-layering and license-list checks, cargo-deny, codespell, actionlint, zizmor and file hygiene run on `git commit` (only when matching files changed).
Add new checks there. No test
is a hook: the tests, the doctests, coverage and mutants are mise tasks
that CI runs.

CI is `.github/workflows/ci.yml`, the one workflow that runs the jobs of a
push, a PR, the nightly run and a run by hand; `build.yml` is a
workflow it calls, and only `release.yml` (it publishes, so nothing in
it may restore a cache), `scorecard.yml`, `pr-title.yml` and
`cleanup-caches.yml` (a closed PR's caches deleted) stand apart (each
says why). Its Build job compiles the musl tests once per arch
into a nextest archive that the Tests, Interop, TURN and Sandbox
isolation jobs run without compiling, and its Fuzz build job compiles the
fuzz targets once for the Fuzz jobs, which run up to 4 targets each in
parallel: on a PR only the targets built from a file it changed
(`scripts/fuzz-select.sh`), else all, 5 min each nightly; every compiling job keeps a Rust
cache, saved by every run and restored from the PR's own (GitHub scopes
them to it) or else from `main`'s. A new job goes into `ci.yml`; workflow
and job names start with a capital letter.

| Command | What it does |
|---|---|
| `mise run check` | every hook on all files (CI's Check job) |
| `prek run <hook-id>` | one hook, e.g. `prek run cargo-clippy` |
| `mise run test` | the tests (`scripts/nextest.sh`, nextest filters as usual) and the doctests, on Linux |
| `mise run test-browser` | the browser test's unit tests, no browser (CI's Check job) |
| `mise run coverage` | the 100 % line-coverage gate (`cargo llvm-cov nextest`) |
| `mise run mutants [base]` | `cargo mutants --in-diff` against a base ref (default `origin/main`) |
| `mise run turn-e2e` | the TURN client against a real coturn in Docker (ignored `coturn_` tests) |
| `mise run load [cameras] [viewers] [duration]` | the load generator against a release daemon (`target/load-report.json`) |
| `mise run soak [duration] [cycle]` | the soak: viewer and camera churn, checked for memory, task and descriptor growth (`target/soak-report.json`) |
| `mise run interop` | the daemon against MediaMTX fed by ffmpeg (pinned in `mise.toml`): RTSP over TCP and UDP, video only and with AAC, PCMU and Opus (ignored `mediamtx_` tests) |
| `mise run browser [chrome\|firefox\|safari] [play] [case]` | the browser test: one pytest test (`tests/browser/`) has Selenium drive a real browser playing ffmpeg's stream from MediaMTX through a release daemon, per case (`join`, `aac`, `pli`, `reconnect`, `crash`, or `all`, the default) (`target/browser-<engine>/<case>/`); needs the browser, Selenium Manager finds or fetches its driver |
| `mise run compare [engine] [runs] [play]` | the browser test through lotse and through go2rtc, side by side; a report, not a gate (`target/compare-<engine>/compare.json`) |
| `mise run test-musl` | the tests on the static musl target (Linux only); CI's Tests job runs them from the Build job's archive |
| `mise run test-archive` | the musl tests built and archived for other machines, then the doctests (CI's Build job) |
| `mise run audit` | RustSec advisories, the root and the fuzz workspace (network) |
| `mise run fuzz <target> [secs]` | one `cargo fuzz` target on the date-pinned nightly the task installs, under the contract's time and memory limits (`scripts/fuzz.sh`, as CI; cargo-fuzz installed by hand, the one nightly use) |
| `mise run set-version <version>` | the workspace version and its lockfile entries; only a release build sets it, from the tag (the repository keeps `0.0.0-dev`) |
| `mise run release-build [x86_64\|aarch64]` | static musl binary (Linux only); zig links every musl build (`.cargo/config.toml`) |
| `mise run sbom` / `mise run licenses` | a release's CycloneDX SBOMs and `THIRD_PARTY_LICENSES.md`, in `target/dist/` |
| `mise run image load [arch]` | the scratch release image from the static binary, into the local Docker as `lotse:dev` |

## Layout

Cargo workspace, one binary (`crates/lotse`), library crates under
`crates/`. Dependencies only
point downward and `lotse-core` knows nothing about RTSP, WebRTC, HTTP or
processes. The allowed edges are listed in `.cargo/layering.toml` and
checked by a hook: adding a dependency edge means editing that file in
the same PR. `cargo shear` fails on declared
dependencies nothing uses, so never add a dependency ahead of the code that
uses it. The binary only parses the CLI and dispatches to
`lotse-supervisor` or `lotse-worker`; both are libraries with tests.
The clients, the Python `lotse-client` among them, live in their own repository,
[lotse-clients](https://github.com/edenhaus/lotse-clients): their models are generated from a copy of the API's JSON Schema bundle.

## Conventions

- Lints live in the root `Cargo.toml` (`[workspace.lints]`) and
  `clippy.toml`; every crate opts in with `[lints] workspace = true`. Do
  not relax them per crate. Suppress a lint only with
  `#[expect(lint, reason = "...")]`; `#[allow]` on an item is itself a lint
  error, because an `expect` fails once the lint no longer fires.
- Test modules relax the production-only lints with one inner attribute as
  the first line of `mod tests` (or of an integration test file):
  `#![allow(clippy::arithmetic_side_effects, clippy::missing_docs_in_private_items, reason = "test code")]`.
  Unwrap, expect, panic, indexing and printing are already allowed in
  tests by `clippy.toml`.
- No `unsafe`, no `unwrap`/`expect`/`panic`/`unreachable`/indexing/unchecked
  arithmetic in non-test code. Parsers use `get()`/`split_at_checked()`,
  arithmetic is explicitly `checked_`/`wrapping_`/`saturating_`. `assert!`
  in production code is a panic: use `debug_assert!` or return an error.
- `clippy.toml` `disallowed-methods` enforce design rules: tasks are spawned
  through `lotse_core::task::spawn_named` (never `tokio::spawn`), time comes
  from the injected clock (never `Instant::now`), configuration is read
  once in the binary (never `std::env::var`), and only the supervisor
  spawns processes. The one implementation of each carries a scoped
  `expect`.
- No `println!`/`eprintln!`; log through `tracing`. Secrets are newtypes
  that redact in `Debug`/`Display`.
- Log every state change and every decision with its reason and
  structured fields, at the level it deserves; nothing per
  packet above `trace`, repeated media-path conditions rate-limited.
- `thiserror` in libraries, `anyhow` only in `main`.
- Every item has rustdoc, private ones included (`missing_docs` +
  `clippy::missing_docs_in_private_items`): what it is for and the
  invariants it keeps. Every crate root states its purpose, the process it
  runs in, what it must not depend on, and the standards it implements.
- Sources and outputs implement specifications, and the code says which:
  every protocol module cites the spec and section it implements, every
  spec-derived constant cites its clause, tests carry the clause in their
  name, and a knowing deviation is tagged `SPEC-DEVIATION` with its
  reason. Behavior of clients, browsers
  and third-party software is cited as observed behavior, with a version
  and a date, never as "the spec".
- No untested code. Every behavior, error paths included, has a test in the
  same PR that asserts it; bug fixes start with a failing regression test.
  CI gates on 100 % line coverage (`mise run coverage`) and on
  `cargo mutants --in-diff` (`mise run mutants`); an equivalent mutant is
  excluded in `.cargo/mutants.toml` with its reason. Code a test cannot
  reach is dead or needs a seam (fake, injected clock/fault). Fakes for a
  crate's own types live behind its `test-util` feature; `lotse-testing`
  is a dev-dependency of everything except `lotse-core`.
- Every dependency goes in `[workspace.dependencies]` with
  `default-features = false` and a comment saying why it exists. It must
  pass `cargo deny`, and a protocol
  engine's owning crate is recorded in `.cargo/layering.toml`.
- Conventional Commits PR titles, enforced by `pr-title.yml`: PRs are
  squash-merged with their title, so commit messages are not checked.
- An API change flows Rust DTOs, then the bundle (`cargo run -p
  lotse-api-types --example schema > crates/lotse-api-types/schema/api.json`),
  in one commit; the `api-schema` hook fails on a stale bundle. Once it
  reaches `main`, CI's clients job has lotse-clients open a PR with the bundle
  and the regenerated models, whose CI runs the contract tests against
  that commit.

## Gotchas

- Linux is the only platform: the targets are Linux musl (x86-64-v2,
  aarch64 ARMv8.0), and the tests and every gate run on Linux, in CI.
  Test and measure on Linux (CI, or a Linux container), never elsewhere.
  The one exception is the nightly Safari browser test, which needs
  GitHub's macOS runner and the host build there.
- musl builds run on Linux only (`test-musl`, `test-archive`,
  `release-build`, CI's Build and Release build on one native runner per
  arch).
- `panic = "abort"` in every profile: `catch_unwind` does not work, and a
  panic ends the process. Cargo ignores the setting for the test profile,
  so a test that needs abort semantics must run a release-profile binary
  in a subprocess.
- A release is publishing the draft that Release Drafter keeps on GitHub
  (CI's Release notes job, `.github/release-drafter.yml`): the merged PRs'
  Conventional Commit titles sort its notes and pick the version, and
  publishing it starts `release.yml`, which sets that version from the tag
  and builds, attests and attaches everything. The workspace version in
  the repository stays `0.0.0-dev`, so a build from source says it is
  not a release; never bump it, never tag by hand.
- AI-generated changes must be explainable by the human submitting them
  (`AI_POLICY.md`).

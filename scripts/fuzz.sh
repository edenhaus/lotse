#!/bin/sh
# One cargo-fuzz target for a while, under the limits that make the fuzz contract's "never hang,
# never allocate unbounded" a finding instead of a slow run. `mise run fuzz` and CI's fuzz-smoke
# both run this, so the limits live here only.
#
# Usage: scripts/fuzz.sh <target> [secs], with NIGHTLY naming the pinned nightly (mise.toml's fuzz
# task and ci.yml's fuzz-smoke set it) and fuzz/Cargo.lock already fetched `--locked`.
#
# libFuzzer's options (https://llvm.org/docs/LibFuzzer.html#options), each limit a finding when
# crossed (a `timeout-*` or `oom-*` artifact):
# - `-timeout=10`: one input running longer than 10 s is a hang. libFuzzer's default, 1200 s,
#   outlasts the whole run. The timer is a SIGALRM every few seconds, so a harness's own blocking
#   reads retry on EINTR.
# - `-malloc_limit_mb=64`: any single allocation over 64 MiB, reported with its stack however
#   briefly it lives: what a length field from the input sizes. The largest buffer the design
#   allows is a 4 MiB access unit (`max_frame_bytes`), which a growing `Vec` takes to 8 MiB.
# - `-rss_limit_mb=1024`: the process growing past 1 GiB resident, the backstop for memory that
#   piles up across inputs. Most of a run's resident memory is AddressSanitizer's quarantine of
#   freed blocks, not the target's: `relay_framer`, the heaviest, holds 57 MiB without one,
#   passed 1.2 GiB within 60 s at the default 256 MiB, and peaked at 610 MiB at 64 MiB
#   (ASAN_OPTIONS below; a caller's own ASAN_OPTIONS still win), macOS arm64, 2026-10-08.
# `-max_len` stays libFuzzer's (4096 bytes from an empty corpus, else the largest corpus input):
# every target's input format reaches its paths within it.
set -eu

target=${1:?usage: scripts/fuzz.sh <target> [secs]}
secs=${2:-60}
: "${NIGHTLY:?NIGHTLY names the pinned nightly toolchain (mise.toml, ci.yml)}"

ASAN_OPTIONS="quarantine_size_mb=64${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
export ASAN_OPTIONS

exec cargo "+$NIGHTLY" fuzz run "$target" -- \
  -max_total_time="$secs" \
  -timeout=10 \
  -malloc_limit_mb=64 \
  -rss_limit_mb=1024

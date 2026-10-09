#!/bin/sh
# `cargo nextest run` on the workspace's tests, built here or taken from an archive.
#
# usage: scripts/nextest.sh [nextest run arguments...]
#
# Without $LOTSE_NEXTEST_ARCHIVE it builds the tests (`--workspace --all-features --locked`) for
# the host, or for the target $LOTSE_NEXTEST_TARGET names. With it, it runs the binaries of that
# archive, which CI's Build job makes once per arch (`mise run test-archive`): they are extracted
# into ./target, where the paths compiled into them point (`env!("CARGO_BIN_EXE_lotse")`), so the
# checkout must be at the path the archive was built in, as on every GitHub runner. Running an
# archive needs neither cargo nor rustc, only cargo-nextest. The tests run on Linux only.
set -eu

[ "$(uname -s)" = Linux ] || { echo "the tests run on Linux only" >&2; exit 2; }

if [ -n "${LOTSE_NEXTEST_ARCHIVE:-}" ]; then
  exec cargo-nextest nextest run --archive-file "$LOTSE_NEXTEST_ARCHIVE" \
    --workspace-remap . --extract-to . --extract-overwrite "$@"
fi
exec cargo nextest run --workspace --all-features --locked \
  ${LOTSE_NEXTEST_TARGET:+--target "$LOTSE_NEXTEST_TARGET"} "$@"

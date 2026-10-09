#!/bin/sh
# The fuzz targets a change reaches, one per line: the targets built from a file it changed. CI's
# Fuzz build job runs this on a PR and runs only these targets.
#
# Usage: scripts/fuzz-select.sh <dir> <base> <target>..., in the repository's root after
# `cargo fuzz build`: <dir> holds the built targets, <base> is the commit to compare HEAD with
# (empty: every target).
#
# A target's dep-info file, <dir>/<target>.d, which cargo writes next to the binary, lists every
# source file the binary was built from, its crates' and their dependencies' (one Makefile rule:
# `<binary>: <source> <source> ...`, absolute paths). So the selection is by crate: a change to
# any file of a crate a target links selects that target, whether or not the target reaches the
# changed code. A file that changes how every target builds or runs selects them all; so does a
# missing base.
set -eu

dir=${1:?usage: scripts/fuzz-select.sh <dir> <base> <target>...}
base=${2?usage: scripts/fuzz-select.sh <dir> <base> <target>...}
shift 2

if [ -z "$base" ] || ! git diff --quiet "$base" HEAD -- \
  Cargo.toml Cargo.lock fuzz/Cargo.toml fuzz/Cargo.lock rust-toolchain.toml .cargo/config.toml \
  scripts/fuzz.sh scripts/fuzz-parallel.sh scripts/fuzz-select.sh .github/workflows/ci.yml; then
  printf '%s\n' "$@"
  exit 0
fi

changed=$(mktemp)
trap 'rm -f "$changed"' EXIT
git diff --name-only "$base" HEAD >"$changed"

root=$(git rev-parse --show-toplevel)
for target in "$@"; do
  # Checked here: the pipeline's status is grep's, so a missing file would deselect the target.
  [ -f "$dir/$target.d" ] || { echo "fuzz-select: no dep-info $dir/$target.d" >&2; exit 1; }
  # The rule's sources, one per line and relative to the root, against the changed paths.
  if sed 's/^[^:]*: *//' "$dir/$target.d" | tr ' ' '\n' | sed "s|^$root/||" | grep -Fxqf "$changed"; then
    echo "$target"
  fi
done

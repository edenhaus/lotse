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
# changed code. What the dep-info cannot list selects by crate too: a crate's Cargo.toml or
# build.rs (a feature or dependency change changes the code it builds) and a file deleted from a
# crate (it is in no dep-info of HEAD; a rename counts as one, its old path deleted) select every
# target that links a source of that crate. A file that changes how every target builds or runs
# selects them all: the root's and the fuzz workspace's Cargo.toml and Cargo.lock (a dependency's
# version, or a workspace dependency's features, changes code no crate's own files show), the
# toolchain, cargo's config, the fuzz scripts and CI's workflow; so does a missing base. A crate's
# Cargo.toml that turns on a feature of a dependency shared with other crates changes that
# dependency for every target (cargo unifies features over the build), but features are additive
# and the selection stays with the crate's own targets.
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

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# --no-renames: a renamed file is listed as its old path deleted and its new path added.
git diff --name-only --no-renames "$base" HEAD >"$tmp/changed"
git diff --name-only --no-renames --diff-filter=D "$base" HEAD >"$tmp/deleted"
# The crates (`crates/<name>/`, one per line) a change reaches as a whole.
{
  sed -n -e 's|^\(crates/[^/]*/\)Cargo\.toml$|\1|p' -e 's|^\(crates/[^/]*/\)build\.rs$|\1|p' "$tmp/changed"
  sed -n 's|^\(crates/[^/]*/\).*|\1|p' "$tmp/deleted"
} >"$tmp/crates"

root=$(git rev-parse --show-toplevel)
for target in "$@"; do
  # Checked here: the pipeline's status is its last command's, so a missing file would deselect it.
  [ -f "$dir/$target.d" ] || { echo "fuzz-select: no dep-info $dir/$target.d" >&2; exit 1; }
  # The rule's sources, one per line and relative to the root.
  sed 's/^[^:]*: *//' "$dir/$target.d" | tr ' ' '\n' | sed "s|^$root/||" >"$tmp/sources"
  # A changed source, or a source of a crate the change reaches as a whole.
  if grep -Fxqf "$tmp/changed" "$tmp/sources" ||
    sed -n 's|^\(crates/[^/]*/\).*|\1|p' "$tmp/sources" | grep -Fxqf "$tmp/crates"; then
    echo "$target"
  fi
done

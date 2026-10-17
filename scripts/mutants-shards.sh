#!/bin/sh
# How many Mutants jobs a run needs: its mutants, up to <per> a job and at most <max> jobs. CI's
# Mutants plan jobs run this and start one Mutants job (`mise run mutants --shard k/count`) for
# each shard it prints: on a PR for its changed lines, nightly for the whole workspace.
#
# Usage: scripts/mutants-shards.sh <base|--all> [per] [max], in the repository's root: <base> is
# the ref HEAD is compared with, as in `mise run mutants`; `--all` counts every mutant of the
# workspace, as `mise run mutants --all`. Prints GitHub step outputs: `count`, the number of jobs,
# and `shards`, their indices as a JSON array (`[]` when there are no mutants).
#
# `--list` builds nothing, so this takes seconds. It lists what `mise run mutants` would test: the
# same arguments, the same `.cargo/mutants.toml`. A count that disagrees with the run's would only
# make slices uneven; every mutant still falls in one of the `count` slices.
set -eu

base=${1:?usage: scripts/mutants-shards.sh <base|--all> [per] [max]}
per=${2:-10}
max=${3:-8}

if [ "$base" = --all ]; then
  mutants=$(cargo mutants --workspace --all-features --list | wc -l)
else
  diff=$(mktemp)
  trap 'rm -f "$diff"' EXIT
  git diff "$base...HEAD" >"$diff"
  mutants=$(cargo mutants --workspace --all-features --in-diff "$diff" --list | wc -l)
fi

count=$(((mutants + per - 1) / per))
[ "$count" -le "$max" ] || count=$max
shards=
k=0
while [ "$k" -lt "$count" ]; do
  shards=${shards:+$shards,}$k
  k=$((k + 1))
done

echo "$mutants mutants, $count shards" >&2
printf 'count=%s\nshards=[%s]\n' "$count" "$shards"

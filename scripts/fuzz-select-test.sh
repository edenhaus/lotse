#!/bin/sh
# The test of scripts/fuzz-select.sh, a prek hook: it runs the script in a throwaway git repository
# with three crates and fake dep-info files, one case per kind of change, and fails on any case
# whose selection is not the expected one.
#
# Usage: scripts/fuzz-select-test.sh [<fuzz-select.sh>], the script to test defaulting to the one
# next to this file.
set -eu

script=$(realpath "${1:-$(dirname "$0")/fuzz-select.sh}")

# prek runs a hook with the repository's GIT_* variables set (GIT_INDEX_FILE, for one); left set,
# they would point this test's git commands at the real repository instead of the throwaway one.
# The user's and the system's git config stay out too (a signing or hook setting would break the
# commits below).
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_COMMON_DIR GIT_PREFIX
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo=$tmp/repo
bin=$tmp/bin # the dep-info directory, outside the repository as cargo's target directory is
mkdir -p "$repo" "$bin"
cd "$repo"

git init -q -b main .
git config user.name fuzz-select-test
git config user.email fuzz-select-test@example.invalid
for crate in a b c; do
  mkdir -p "crates/$crate/src"
  printf '[package]\nname = "%s"\n' "$crate" >"crates/$crate/Cargo.toml"
  echo "// $crate" >"crates/$crate/src/lib.rs"
  echo "// $crate, not built" >"crates/$crate/src/old.rs"
done
mkdir -p fuzz/fuzz_targets
for target in t1 t2 t3; do echo "// $target" >"fuzz/fuzz_targets/$target.rs"; done
echo readme >README.md
git add -A
git commit -qm base

# HEAD's dep-info, as cargo writes it: t1 links crate a and a registry crate, t2 links a and b, t3
# links c. No target lists old.rs, as no build lists a file the crate does not compile.
t=$repo/fuzz/fuzz_targets
c=$repo/crates
echo "$bin/t1: $t/t1.rs $c/a/src/lib.rs /registry/x-1.0/src/lib.rs" >"$bin/t1.d"
echo "$bin/t2: $t/t2.rs $c/a/src/lib.rs $c/b/src/lib.rs" >"$bin/t2.d"
echo "$bin/t3: $t/t3.rs $c/c/src/lib.rs" >"$bin/t3.d"

failed=0

# expect <case> <base> <expected targets, space-separated>: runs the script against HEAD.
expect() {
  if "$script" "$bin" "$2" t1 t2 t3 >"$tmp/out" 2>"$tmp/err"; then
    got=$(tr '\n' ' ' <"$tmp/out" | sed 's/ $//')
  else
    got="exit $?: $(cat "$tmp/err")"
  fi
  if [ "$got" = "$3" ]; then
    echo "ok: $1"
  else
    echo "FAIL: $1: selected [$got], expected [$3]" >&2
    failed=1
  fi
}

# change <case> <expected targets> <command>: runs the command on a branch off the base commit,
# commits it and checks the selection against the base.
change() {
  git checkout -q -B case main
  sh -c "$3"
  git add -A
  git commit -qm "$1"
  expect "$1" main "$2"
}

change "a changed source selects its targets" "t3" 'echo "// changed" >>crates/c/src/lib.rs'
change "a crate's Cargo.toml selects every target of the crate" "t1 t2" \
  'echo "[features]" >>crates/a/Cargo.toml'
change "a crate's Cargo.toml selects no other crate's targets" "t2" \
  'echo "[features]" >>crates/b/Cargo.toml'
change "a crate's build.rs selects every target of the crate" "t3" \
  'echo "fn main() {}" >crates/c/build.rs'
change "a deleted file selects every target of its crate" "t3" 'git rm -q crates/c/src/old.rs'
change "a renamed file selects every target of its old crate" "t2" \
  'git mv crates/b/src/old.rs crates/b/src/new.rs'
change "an unrelated change selects none" "" 'echo changed >>README.md'
change "the root Cargo.toml selects every target" "t1 t2 t3" 'echo "[workspace]" >Cargo.toml'
change "the root Cargo.lock selects every target" "t1 t2 t3" 'echo "version = 4" >Cargo.lock'
expect "no base selects every target" "" "t1 t2 t3"
git checkout -q main # no change that selects every target before the dep-info is read
rm "$bin/t2.d"
expect "a missing dep-info fails" main "exit 1: fuzz-select: no dep-info $bin/t2.d"

exit "$failed"

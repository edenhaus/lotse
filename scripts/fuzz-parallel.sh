#!/bin/sh
# Several fuzz targets at once, each through scripts/fuzz.sh: libFuzzer runs one process on one
# core, so CI's Fuzz jobs each run up to 4 targets on the runner's 4 vCPUs, and 4 times the 1 GiB
# resident limit fits its 16 GB. Each target's output goes to its own log, printed once all are
# done; a failing target's log is printed unfolded, after an error annotation naming it.
#
# Usage: scripts/fuzz-parallel.sh <secs> <target>..., with FUZZ_BIN_DIR naming the built targets
# (scripts/fuzz.sh). Logs go to target/fuzz-logs/, failing inputs to fuzz/artifacts/<target>/.
set -eu

secs=${1:?usage: scripts/fuzz-parallel.sh <secs> <target>...}
shift
: "${FUZZ_BIN_DIR:?FUZZ_BIN_DIR names the built targets}"

logs=target/fuzz-logs
mkdir -p "$logs"
for target in "$@"; do
  (
    if scripts/fuzz.sh "$target" "$secs" >"$logs/$target.log" 2>&1; then
      echo 0 >"$logs/$target.status"
    else
      echo "$?" >"$logs/$target.status"
    fi
  ) &
done
wait

failed=0
for target in "$@"; do
  status=$(cat "$logs/$target.status")
  if [ "$status" -eq 0 ]; then
    echo "::group::$target: no finding in $secs s"
    cat "$logs/$target.log"
    echo "::endgroup::"
  else
    echo "::error title=Fuzz target $target::exit status $status; the failing input is in fuzz/artifacts/$target/ (the job's fuzz-findings artifact)"
    cat "$logs/$target.log"
    failed=1
  fi
done
exit "$failed"

#!/usr/bin/env bash
# CI gate for the U-Boot FIT fuzz target: build it, then replay the committed
# seeds through it once each. REPLAY ONLY — libFuzzer runs with -runs=0, so it
# executes the inputs it is given and never mutates them. Any sanitizer report
# or crash on a seed fails the job.
#
# Usage: ci-replay.sh [--version-file pin.txt] [--out build/] [--no-build]
#
#   --version-file, --out  passed to build.sh (same defaults)
#   --no-build             reuse an existing <out>/sandbox/u-boot
#
# Seeds come from replay/: each *.its is compiled to a FIT with the tree's own
# mkimage (and must list cleanly with mkimage -l, so the seed is known to be a
# valid FIT); any other file except *.md is replayed as is.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/build
BUILD_ARGS=()
BUILD=1

die() { echo "ci-replay.sh: $*" >&2; exit 1; }

while (( $# )); do
  case $1 in
    --version-file) [[ $# -ge 2 ]] || die "$1 needs a file"; BUILD_ARGS+=("$1" "$2"); shift 2 ;;
    --out)          [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    --no-build)     BUILD=0; shift ;;
    -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)              die "unknown argument: $1 (see --help)" ;;
  esac
done
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

if (( BUILD )); then
  bash "$HERE/build.sh" "${BUILD_ARGS[@]}" --out "$OUT"
fi
B=$OUT/sandbox
[[ -x $B/u-boot ]] || die "no fuzz binary at $B/u-boot (run build.sh)"

# --- Seeds ----------------------------------------------------------------------
R=$OUT/replay
rm -rf "$R" && mkdir -p "$R"
if [[ -f $B/toolchain.txt ]]; then
  epoch=$(sed -n 's/^source_date_epoch //p' "$B/toolchain.txt")
fi
shopt -s nullglob
for f in "$HERE"/replay/*; do
  name=$(basename "$f")
  case $name in
    *.md) ;;
    *.its)
      # mkimage runs "dtc" from PATH: use the tree's own. SOURCE_DATE_EPOCH
      # fixes the timestamp, so the seed is the same bytes on every run.
      PATH=$B/scripts/dtc:$PATH SOURCE_DATE_EPOCH=${epoch:-0} \
        "$B/tools/mkimage" -f "$f" "$R/${name%.its}.itb" >/dev/null
      "$B/tools/mkimage" -l "$R/${name%.its}.itb" >/dev/null \
        || die "mkimage does not accept the FIT built from $name"
      ;;
    *) cp "$f" "$R/$name" ;;
  esac
done
seeds=("$R"/*)
(( ${#seeds[@]} )) || die "no seeds in $HERE/replay"

# --- Replay -----------------------------------------------------------------------
# The sandbox thread starts as "./u-boot -T" and finds test.dtb (which holds
# the fuzzing-engine device) relative to the working directory, hence the cd.
# Artefacts from a failing seed go to <out>/results/, which stays local.
mkdir -p "$OUT/results"
LOG=$OUT/results/replay.log
set +e
( cd "$B" && UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format \
    ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0} \
    ./u-boot -runs=0 -artifact_prefix="$OUT/results/" "$R" ) > "$LOG" 2>&1
rc=$?
set -e
cat "$LOG"
(( rc == 0 )) || die "replay failed (exit $rc); see $LOG"
# libFuzzer must have read every seed, or the job proved nothing.
grep -qE "INFO: seed corpus: files: ${#seeds[@]} " "$LOG" \
  || die "libFuzzer did not load all ${#seeds[@]} seed(s)"
# With -runs=0 libFuzzer executes an empty input plus each seed, then stops; any
# more executions would mean it mutated, which this job must never do.
runs=$(sed -n 's/^Done \([0-9][0-9]*\) runs .*/\1/p' "$LOG")
[[ -n $runs ]] || die "libFuzzer did not report its run count"
(( runs <= ${#seeds[@]} + 1 )) || die "libFuzzer ran $runs inputs for ${#seeds[@]} seed(s): it mutated"
echo "replayed ${#seeds[@]} seed(s) through fuzz_fit_check_format: no crash"

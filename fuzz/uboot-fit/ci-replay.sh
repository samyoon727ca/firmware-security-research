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
# Either way the binary must come from the --version-file pin: its version and
# SHA-256 are checked against <out>/sandbox/toolchain.txt before any replay.
#
# Seeds come from replay/: each *.its is compiled to a FIT with the tree's own
# mkimage (and must list cleanly with mkimage -l, so the seed is known to be a
# valid FIT); any other file except *.md is replayed as is. Every seed must be
# a FIT that fit_check_format() accepts: after the fuzz target itself, the
# seeds are replayed through fuzz_fit_check_format_accept, which aborts on a
# rejected input, so a seed that only reaches the first error branch fails.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=$HERE/pin.txt
OUT=$HERE/build
BUILD=1

die() { echo "ci-replay.sh: $*" >&2; exit 1; }

while (( $# )); do
  case $1 in
    --version-file) [[ $# -ge 2 ]] || die "$1 needs a file"; PIN=$2; shift 2 ;;
    --out)          [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    --no-build)     BUILD=0; shift ;;
    -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)              die "unknown argument: $1 (see --help)" ;;
  esac
done
[[ -f $PIN ]] || die "no pin file: $PIN"
if (( BUILD )); then
  # build.sh refuses an --out it did not create, and marks the one it uses.
  bash "$HERE/build.sh" --version-file "$PIN" --out "$OUT"
fi
# <out>/replay is deleted and recreated below: only touch a build.sh output.
[[ -f $OUT/.uboot-fit-build ]] || die "$OUT is not a build.sh output (no .uboot-fit-build marker)"
OUT=$(cd "$OUT" && pwd)
B=$OUT/sandbox
[[ -x $B/u-boot ]] || die "no fuzz binary at $B/u-boot (run build.sh)"
# The binary must come from the pin this run names: with --no-build, <out> may
# hold a build of another release. build.sh writes this line last.
[[ -f $B/toolchain.txt ]] || die "no $B/toolchain.txt: the build is incomplete (run build.sh)"
pin() { awk -v k="$1:" '$1 == k {print $2}' "$PIN"; }
want="u-boot $(pin version) sha256 $(pin sha256)"
have=$(head -n 1 "$B/toolchain.txt")
[[ $have == "$want" ]] \
  || die "$B/u-boot was built from '$have', not '$want' ($PIN); rebuild it (drop --no-build)"

# --- Seeds ----------------------------------------------------------------------
R=$OUT/replay
rm -rf "$R" && mkdir -p "$R"
epoch=$(sed -n 's/^source_date_epoch //p' "$B/toolchain.txt")
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
# Logs and artefacts from a failing seed go to <out>/results/, which stays local.
mkdir -p "$OUT/results"
replay() { # fuzz test: run every seed through it once, with -runs=0
  local name=$1 log=$OUT/results/$1.log rc runs
  set +e
  ( cd "$B" && UBOOT_SB_FUZZ_TEST=$name \
      ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0} \
      ./u-boot -runs=0 -artifact_prefix="$OUT/results/" "$R" ) > "$log" 2>&1
  rc=$?
  set -e
  cat "$log"
  (( rc == 0 )) || die "$name: replay failed (exit $rc); see $log"
  # libFuzzer must have read every seed, or the run proved nothing.
  grep -qE "INFO: seed corpus: files: ${#seeds[@]} " "$log" \
    || die "$name: libFuzzer did not load all ${#seeds[@]} seed(s)"
  # With -runs=0 libFuzzer executes an empty input plus each seed, then stops;
  # any more executions would mean it mutated, which this job must never do.
  runs=$(sed -n 's/^Done \([0-9][0-9]*\) runs .*/\1/p' "$log")
  [[ -n $runs ]] || die "$name: libFuzzer did not report its run count"
  (( runs <= ${#seeds[@]} + 1 )) || die "$name: libFuzzer ran $runs inputs for ${#seeds[@]} seed(s): it mutated"
}
replay fuzz_fit_check_format          # the fuzz target: no crash on any seed
replay fuzz_fit_check_format_accept   # the seeds pass fit_check_format() in this build
echo "replayed ${#seeds[@]} seed(s) through fuzz_fit_check_format: no crash, all accepted"

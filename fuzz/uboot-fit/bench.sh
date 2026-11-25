#!/usr/bin/env bash
# LOCAL ONLY (refuses to run where $CI or $GITHUB_ACTIONS is set): fuzz each
# variant, real crypto and crypto stub, for N seconds from the committed seeds
# and print its exec/s. A performance number for the README, not a finding.
#
# Usage: bench.sh [--out build/] [--seconds 60]
#   --out      a ci-replay.sh output: both variants built from pin.txt, seeds in replay/
#   --seconds  fuzzing time per variant (default 60)
#
# libFuzzer fork mode, -ignore_crashes=1: fresh <out>/corpus/bench-<variant>/; log and
# crash artefacts in <out>/results/bench-<variant>* (candidates: keep local). exec/s
# is runs / seconds from the last status line. Stop rule: see README.md.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/build
SECS=60
. "$HERE/stub.sh"

die() { echo "bench.sh: $*" >&2; exit 1; }

while (( $# )); do
  case $1 in
    --out)      [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    --seconds)  [[ $# -ge 2 ]] || die "$1 needs a number"; SECS=$2; shift 2 ;;
    -h|--help)  sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)          die "unknown argument: $1 (see --help)" ;;
  esac
done
[[ -z ${CI:-} && -z ${GITHUB_ACTIONS:-} ]] || die "local only: CI replays the seeds and never fuzzes"
[[ $SECS =~ ^[1-9][0-9]{0,4}$ ]] || die "--seconds must be a whole number from 1 to 99999"
OUT=$(cd "$OUT" && pwd) RES=$OUT/results
[[ -f $OUT/replay/minimal.itb ]] || die "no compiled seeds in $OUT/replay (run ci-replay.sh)"
pin() { awk -v k="$1:" '$1 == k {print $2}' "$HERE/pin.txt"; }
pinned="u-boot $(pin version) sha256 $(pin sha256)"
for B in "$OUT/sandbox" "$OUT/stub-sandbox"; do  # both, before either runs
  [[ -x $B/u-boot && $(head -n 1 "$B/toolchain.txt" 2>/dev/null) == "$pinned" ]] \
    || die "no $B/u-boot built from '$pinned' (pin.txt; run ci-replay.sh, which builds both variants)"
done
mkdir -p "$RES"
echo "host: $(uname -srm), $(nproc) CPU(s); $(sed -n 3p "$OUT/sandbox/toolchain.txt")"

status='^#([0-9]+): .* oom/timeout/crash: [0-9]+/[0-9]+/([0-9]+) time: ([0-9]+)s'
for v in real stub; do
  B=$OUT/sandbox want=0; [[ $v == real ]] || B=$OUT/stub-sandbox want=2
  marks=$(stub_marks "$B/u-boot")
  (( marks == want )) || die "$B/u-boot carries $marks crypto-stub mark(s), want $want for the $v variant"
  cp "$HERE"/replay/{control-dev.dtb,p2-signed.kernel.sha256} "$B/"
  C=$OUT/corpus/bench-$v log=$RES/bench-$v.log rc=0
  rm -rf "$C" && mkdir -p "$C"
  echo "fuzzing the $v variant ($B/u-boot) for ${SECS}s ..."
  ( cd "$B" && UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format \
      ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0} \
      ./u-boot -fork=1 -ignore_crashes=1 -max_total_time="$SECS" -detect_leaks=0 \
        -artifact_prefix="$RES/bench-$v-" "$C" "$OUT/replay" ) > "$log" 2>&1 || rc=$?
  # Fork mode exits with its last job's code, even a kept crash's: fail only if unfinished.
  grep -q '^INFO: exiting: ' "$log" || die "the $v run did not finish (exit $rc); see $log"
  [[ $(grep -E "$status" "$log" | tail -n 1) =~ $status ]] && (( BASH_REMATCH[3] > 0 )) \
    || die "no libFuzzer status line in $log"
  eps=$(( BASH_REMATCH[1] / BASH_REMATCH[3] ))
  echo "$v: $eps exec/s (${BASH_REMATCH[1]} runs in ${BASH_REMATCH[3]}s; crashes kept in results/: ${BASH_REMATCH[2]}; exit $rc; log $log)"
done
(( eps >= 100 )) || echo "STOP RULE: the stub variant (run last) ran under ~100 exec/s; stop and report, do not start a campaign"

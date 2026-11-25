#!/usr/bin/env bash
# Replay inputs on the REAL-CRYPTO build, <out>/sandbox/u-boot (from the pin,
# no crypto-stub mark: stub.sh), one at a time through fuzz_fit_confirm with
# libFuzzer -timeout=25, and say what each does: crash, timeout, verified or
# rejected. Run it on every crypto-stub hit: only what it confirms counts.
#
# Usage: confirm.sh [--version-file pin.txt] [--out build/] <input>...
#
# Verdicts go to stdout and are appended to <out>/results/confirm.txt under a
# dated line naming the binary; logs to <out>/results/confirm-<sha256>.log.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=$HERE/pin.txt
OUT=$HERE/build
T=25  # seconds per input before libFuzzer reports a timeout
. "$HERE/stub.sh"

die() { echo "confirm.sh: $*" >&2; exit 1; }

while (( $# )); do
  case $1 in
    --version-file) [[ $# -ge 2 ]] || die "$1 needs a file"; PIN=$2; shift 2 ;;
    --out)          [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    -*)             die "unknown option: $1 (see --help)" ;;
    *)              break ;;
  esac
done
(( $# )) || die "no inputs (see --help)"
for input in "$@"; do [[ -f $input ]] || die "not a file: $input"; done
[[ -f $PIN ]] || die "no pin file: $PIN"
B=$OUT/sandbox
[[ -x $B/u-boot && -f $B/toolchain.txt ]] || die "no finished real-crypto build at $B (run build.sh)"
B=$(cd "$B" && pwd)
RES=$(dirname "$B")/results
pin() { awk -v k="$1:" '$1 == k {print $2}' "$PIN"; }
want="u-boot $(pin version) sha256 $(pin sha256)"
have=$(head -n 1 "$B/toolchain.txt")
[[ $have == "$want" ]] || die "$B/u-boot was built from '$have', not '$want' ($PIN)"
marks=$(stub_marks "$B/u-boot")
(( marks == 0 )) || die "$B/u-boot carries $marks crypto-stub mark(s): not a real-crypto build, refusing"
grep -qE '[[:space:]]fuzz_fit_confirm$' < <(nm "$B/u-boot") || die "$B/u-boot lacks fuzz_fit_confirm; rebuild with build.sh"
cp "$HERE"/replay/{control-dev.dtb,p2-signed.kernel.sha256} "$B/"

mkdir -p "$RES"
echo "== $(date -u +%FT%TZ) confirm.sh: real-crypto binary $B/u-boot ($have; sha256 $(sha256sum < "$B/u-boot" | cut -d' ' -f1))" \
  | tee -a "$RES/confirm.txt"
for input in "$@"; do
  abs=$(readlink -f -- "$input")
  sum=$(sha256sum < "$abs" | cut -d' ' -f1)
  log=$RES/confirm-$sum.log
  rc=0
  # A file argument makes libFuzzer run that one input.
  ( cd "$B" && UBOOT_SB_FUZZ_TEST=fuzz_fit_confirm \
      ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0} \
      ./u-boot -runs=0 -detect_leaks=0 -timeout=$T "$abs" ) > "$log" 2>&1 || rc=$?
  ! grep -qF "$STUB_BANNER" "$log" || die "$B/u-boot printed the crypto-stub banner; refusing"
  verdict=$(sed -n 's/^fit_fuzz: confirm: //p' "$log" | tail -n 1)
  if (( rc != 0 )) && grep -q 'ERROR: libFuzzer: timeout' "$log"; then
    verdict="timeout over ${T}s (exit $rc)"
  elif (( rc != 0 )); then
    verdict="crash exit $rc"
    if grep -q '^UBOOT_FIT_ORACLE: verified!=booted' "$log"; then verdict+=", oracle: verified!=booted"; fi
  fi
  [[ -n $verdict ]] || die "no verdict for $input (exit 0); see $log"
  printf '%s  %s  %s  (%s; log %s)\n' "${verdict%% *}" "$sum" "$input" "${verdict#* }" "$log" \
    | tee -a "$RES/confirm.txt"
done

#!/usr/bin/env bash
# CVE-2026-46728 regression (../regressions/CVE-2026-46728.md): fit_config_check_sig()
# before 2092322b31cc hashes the nodes the signature's own hashed-nodes names,
# which the signature does not cover. Builds the real-crypto harness at the
# fix's parent, at the fix and at the pin, makes the "clone" input from the
# signed seed (clone_images.py) and asserts through confirm.sh on each build:
#   fix^ 532a4804e965 (pins/cve-2026-46728-pre.txt)  the oracle fires: verdict crash,
#        with the UBOOT_FIT_ORACLE marker (fit_config_verify() passed on the copies,
#        bootm loaded the swapped /images/kernel)
#   fix  2092322b31cc (pins/cve-2026-46728-fix.txt)  rejected by fit_config_verify(),
#        so the oracle never compares
#   2026.07 (pin.txt)                                the same
# On each build the signed seed itself must verify and boot its signed kernel
# first, so a fire is the input's doing, not a stale digest.
#
# Usage: check_cve_2026_46728.sh [--out build/] [--no-build]
#   --out       build root (default: build/ next to fuzz/uboot-fit): pin.txt is
#               built in <out>, fix^ and fix in <out>/cve-2026-46728-{pre,fix}
#   --no-build  reuse those builds (each must still come from its pin)
#
# The input is generated into <out>/regress-cve-2026-46728/, never committed.
# confirm.sh verdicts and logs stay in each build's results/ and are printed
# only outside CI ($CI / $GITHUB_ACTIONS unset); under CI only the outcome
# per build is printed.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(dirname "$HERE")
OUT=$TOP/build
BUILD=1

die() { echo "check_cve_2026_46728.sh: $*" >&2; exit 1; }
in_ci() { [[ -n ${CI:-} || -n ${GITHUB_ACTIONS:-} ]]; }

while (( $# )); do
  case $1 in
    --out)      [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    -h|--help)  sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)          die "unknown argument: $1 (see --help)" ;;
  esac
done
command -v python3 >/dev/null || die "missing tool: python3"
PRE=$TOP/pins/cve-2026-46728-pre.txt FIX=$TOP/pins/cve-2026-46728-fix.txt
if (( BUILD )); then
  # The pin first: build.sh marks <out>, then accepts the two trees inside it.
  bash "$TOP/build.sh" --out "$OUT"
  bash "$TOP/build.sh" --version-file "$PRE" --out "$OUT/cve-2026-46728-pre"
  bash "$TOP/build.sh" --version-file "$FIX" --out "$OUT/cve-2026-46728-fix"
fi
# <out>/regress-cve-2026-46728 is deleted and recreated: only touch a build.sh output.
[[ -f $OUT/.uboot-fit-build ]] || die "$OUT is not a build.sh output (no .uboot-fit-build marker)"
OUT=$(cd "$OUT" && pwd)

SEED=$TOP/replay/p2-signed.fit
G=$OUT/regress-cve-2026-46728
IN=$G/cve-2026-46728.fit
rm -rf "$G" && mkdir -p "$G"
python3 -I "$HERE/clone_images.py" "$SEED" "$IN"

check() { # label, pin, build dir, fires|quiet
  local label=$1 pin=$2 dir=$3 expect=$4 out v
  out=$(bash "$TOP/confirm.sh" --version-file "$pin" --out "$dir" "$SEED" "$IN") \
    || die "$label: confirm.sh failed; its logs stay in $dir/results/"
  if ! in_ci; then echo "$out"; fi
  mapfile -t v < <(grep -E '^(crash|timeout|verified|rejected) ' <<< "$out")
  # (A verdict from the sandbox console ends in \r, so no pattern reaches past its text.)
  [[ ${#v[@]} == 2 && ${v[0]} == "verified "*"; bootm loads the signed kernel"* ]] \
    || die "$label: the signed seed did not verify and boot its kernel, so this build proves nothing"
  if [[ $expect == fires ]]; then
    # The oracle's own signal: confirm.sh adds it only for the UBOOT_FIT_ORACLE marker line.
    [[ ${v[1]} == "crash "*", oracle: verified!=booted;"* ]] \
      || die "$label: the oracle did not fire on the CVE-2026-46728 input; full log kept locally in results/"
    echo "CVE-2026-46728 input on $label: verified, but bootm loaded other kernel bytes: the oracle fires (as intended)"
  else
    [[ ${v[1]} == "rejected "*"(by fit_config_verify() "* ]] \
      || die "$label: confirm.sh did not report the CVE-2026-46728 input rejected by fit_config_verify(); full log kept locally in results/"
    echo "CVE-2026-46728 input on $label: rejected by fit_config_verify(); the oracle stays quiet"
  fi
}
check "fix^ (532a4804e965)" "$PRE" "$OUT/cve-2026-46728-pre" fires
check "fix (2092322b31cc)" "$FIX" "$OUT/cve-2026-46728-fix" quiet
check "U-Boot $(awk '$1 == "version:" {print $2}' "$TOP/pin.txt") (pin.txt)" "$TOP/pin.txt" "$OUT" quiet

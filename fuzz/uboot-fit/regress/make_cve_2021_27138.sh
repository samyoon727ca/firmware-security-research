#!/usr/bin/env bash
# Build regress/cve-2021-27138.fit, the CVE-2021-27138 regression input, from
# the signed seed replay/p2-signed.fit and the donor regress/cve-2021-27138.its.
#
# Usage: make_cve_2021_27138.sh [--version-file pin.txt] [--out build/]
#   (as for make_seed.sh: the finished build of that pin supplies mkimage and dtc)
#
# CVE-2021-27138 (fixed in v2021.04-rc2): libfdt's lookup lets "kernel" match a
# node "kernel@1", while a config signature hashes its hashed-nodes by exact
# path. An extra kernel@1 in front of the signed "kernel" keeps the signature
# valid, and bootm loads kernel@1. Advisory: the two fix commits, both tagged
# CVE-2021-27138 (reported by Bruce Monroe, Arie Haenel, Julien Lenoir, Intel):
#   https://github.com/u-boot/u-boot/commit/79af75f7776fc20b0d7eb6afe1e27c00fdb4b9b4
#     "fit: Don't allow verification of images with @ nodes"
#   https://github.com/u-boot/u-boot/commit/3f04db891a353f4b127ed57279279f851c6b4917
#     "image: Check for unit addresses in FITs" (fit_check_format() rejects '@')
# and https://nvd.nist.gov/vuln/detail/CVE-2021-27138.
#
# mkimage compiles the donor (its warning that '@' breaks signing is the point),
# graft_node.py inserts kernel@1 into a copy of the seed (no key needed), and the
# result may differ from the seed only by that node. Commit the output.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(dirname "$HERE")
PIN=$TOP/pin.txt
OUT=$TOP/build

die() { echo "make_cve_2021_27138.sh: $*" >&2; exit 1; }

while (( $# )); do
  case $1 in
    --version-file) [[ $# -ge 2 ]] || die "$1 needs a file"; PIN=$2; shift 2 ;;
    --out)          [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)              die "unknown argument: $1 (see --help)" ;;
  esac
done
[[ -f $PIN ]] || die "no pin file: $PIN"
B=$OUT/sandbox
# Only the pinned tree's tools are used (same check as make_seed.sh).
[[ -f $B/toolchain.txt ]] || die "no $B/toolchain.txt: build the tree first (build.sh)"
pin() { awk -v k="$1:" '$1 == k {print $2}' "$PIN"; }
want="u-boot $(pin version) sha256 $(pin sha256)"
have=$(head -n 1 "$B/toolchain.txt")
[[ $have == "$want" ]] || die "$B was built from '$have', not '$want' ($PIN)"
for t in tools/mkimage scripts/dtc/dtc; do [[ -x $B/$t ]] || die "no $B/$t in the build"; done
command -v python3 >/dev/null || die "missing tool: python3"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
SEED=$TOP/replay/p2-signed.fit
PATH=$B/scripts/dtc:$PATH SOURCE_DATE_EPOCH=0 \
  "$B/tools/mkimage" -f "$HERE/cve-2021-27138.its" "$W/donor.fit" >/dev/null
python3 -I "$HERE/graft_node.py" "$SEED" "$W/donor.fit" /images/kernel@1 "$W/out.fit"

# Against the seed, the decompiled result may only gain lines, kernel@1's.
dts() { "$B/scripts/dtc/dtc" -q -I dtb -O dts "$1"; }
diff <(dts "$SEED") <(dts "$W/out.fit") > "$W/dts.diff" || true
grep -q '^> .*kernel@1 {' "$W/dts.diff" || die "kernel@1 is not in the result"
! grep -q '^<' "$W/dts.diff" || die "the result lost or changed lines of the seed"
cp "$W/out.fit" "$HERE/cve-2021-27138.fit"
echo "wrote regress/cve-2021-27138.fit ($(wc -c < "$HERE/cve-2021-27138.fit") bytes)"

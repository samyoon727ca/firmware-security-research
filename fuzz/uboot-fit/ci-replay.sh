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
# valid FIT); each *.fit is a signed seed from make_seed.sh, replayed as is.
# control-dev.dtb is the control devicetree holding the dev key, and
# p2-signed.kernel.sha256 the digest of the kernel it signed: both are copied
# into the run directory, where the target reads them, and are not seeds; nor
# is any other *.sha256 or *.md. Every seed must be a FIT that
# fit_check_format() accepts: after the fuzz target itself, the seeds are
# replayed through fuzz_fit_check_format_accept, which aborts on a rejected
# input, so a seed that only reaches the first error branch fails. The signed
# seeds then go through fuzz_fit_config_verify_check, which aborts unless each
# one verifies against control-dev.dtb and the same FIT with a kernel byte
# flipped does not, and unless the verified-equals-booted oracle loads the
# signed kernel through bootm's lookup and stays quiet. Last,
# fuzz_fit_oracle_hook_check runs the oracle with its expected digest swapped
# (a test-only hook): it must fire, i.e. abort with the UBOOT_FIT_ORACLE marker.
# Then regress/cve-2021-27138.fit (a public n-day) must not fire on the pin,
# and must fire on v2021.01 (pins/v2021.01.txt, built into <out>/v2021.01).
#
# The full libFuzzer/ASan log goes to <out>/results/ and is printed only
# outside CI ($CI / $GITHUB_ACTIONS unset). Under CI the job prints the seed and
# run counts on success and only the fuzz-test name and exit code on failure:
# no stack trace, input bytes or crash-file name reaches a public CI log.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=$HERE/pin.txt
OUT=$HERE/build
BUILD=1

die() { echo "ci-replay.sh: $*" >&2; exit 1; }
in_ci() { [[ -n ${CI:-} || -n ${GITHUB_ACTIONS:-} ]]; }

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
S=$OUT/signed
rm -rf "$R" "$S" && mkdir -p "$R" "$S"
[[ -f $HERE/replay/control-dev.dtb ]] || die "no replay/control-dev.dtb (run make_seed.sh)"
cp "$HERE/replay/control-dev.dtb" "$B/control-dev.dtb"
[[ -f $HERE/replay/p2-signed.kernel.sha256 ]] || die "no replay/p2-signed.kernel.sha256 (run make_seed.sh)"
cp "$HERE/replay/p2-signed.kernel.sha256" "$B/p2-signed.kernel.sha256"
epoch=$(sed -n 's/^source_date_epoch //p' "$B/toolchain.txt")
shopt -s nullglob
for f in "$HERE"/replay/*; do
  name=$(basename "$f")
  case $name in
    *.md|*.sha256|control-dev.dtb) ;;
    *.fit) cp "$f" "$R/$name"; cp "$f" "$S/$name" ;;
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
signed=("$S"/*)
(( ${#signed[@]} )) || die "no signed *.fit seeds in $HERE/replay (run make_seed.sh)"

# --- Replay -----------------------------------------------------------------------
# The sandbox thread starts as "./u-boot -T" and finds test.dtb (which holds
# the fuzzing-engine device) relative to the working directory, hence the cd.
# Logs and artefacts from a failing seed go to <out>/results/, which stays local.
mkdir -p "$OUT/results"
run() { # fuzz test, seed dir, artefact name prefix: run every seed through it once, with -runs=0
  local log=$OUT/results/$1.log rc
  # -detect_leaks=0: LeakSanitizer is off here (ASAN_OPTIONS), so libFuzzer's
  # own leak check cannot report anything. It would only run an input a second
  # time when that input allocated more than it freed, as the first one through
  # the oracle does (sandbox address-map tags, made once per pointer), and the
  # run count below would read that second run as a mutation.
  set +e
  ( cd "$B" && UBOOT_SB_FUZZ_TEST=$1 \
      ASAN_OPTIONS=${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0} \
      ./u-boot -runs=0 -detect_leaks=0 -artifact_prefix="$OUT/results/$3" "$2" ) > "$log" 2>&1
  rc=$?
  set -e
  # The log can hold a sanitizer stack trace and the Base64 of a crashing
  # input, so under CI it stays in results/ and only counts are printed.
  if ! in_ci; then cat "$log"; fi
  return "$rc"
}
replay() { # fuzz test, seed dir, seed count: run every seed through it once; none may fail
  local name=$1 dir=$2 n=$3 log=$OUT/results/$1.log rc=0 runs
  run "$name" "$dir" "" || rc=$?
  if (( rc != 0 )); then
    if in_ci; then
      die "$name: replay failed (exit $rc); full log kept locally in results/ (not printed under CI)"
    fi
    die "$name: replay failed (exit $rc); see $log"
  fi
  if in_ci; then grep -E '^INFO: seed corpus: files:|^Done [0-9]+ runs' "$log" || true; fi
  # libFuzzer must have read every seed, or the run proved nothing.
  grep -qE "INFO: seed corpus: files: $n " "$log" \
    || die "$name: libFuzzer did not load all $n seed(s)"
  # With -runs=0 libFuzzer executes an empty input plus each seed, then stops;
  # any more executions would mean it mutated, which this job must never do.
  runs=$(sed -n 's/^Done \([0-9][0-9]*\) runs .*/\1/p' "$log")
  [[ -n $runs ]] || die "$name: libFuzzer did not report its run count"
  (( runs <= n + 1 )) || die "$name: libFuzzer ran $runs inputs for $n seed(s): it mutated"
}
replay fuzz_fit_check_format "$R" ${#seeds[@]}          # the fuzz target: no crash on any seed
replay fuzz_fit_check_format_accept "$R" ${#seeds[@]}   # the seeds pass fit_check_format() in this build
echo "replayed ${#seeds[@]} seed(s) through fuzz_fit_check_format: no crash, all accepted"
# The signed seeds verify against control-dev.dtb; a flipped kernel byte is rejected.
replay fuzz_fit_config_verify_check "$S" ${#signed[@]}
log=$OUT/results/fuzz_fit_config_verify_check.log
ok=$(grep -c '^fit_fuzz: [0-9]*-byte signed seed verifies; kernel tampering rejected' "$log" || true)
(( ok >= ${#signed[@]} )) || die "fuzz_fit_config_verify_check: only $ok of ${#signed[@]} signed seed(s) reported a pass"
ok=$(grep -c '^fit_fuzz: oracle: bootm loads the signed kernel; quiet on the seed' "$log" || true)
(( ok >= ${#signed[@]} )) || die "fuzz_fit_config_verify_check: the oracle passed on only $ok of ${#signed[@]} signed seed(s)"
echo "${#signed[@]} signed seed(s) verify against control-dev.dtb; tampered copies rejected; oracle quiet"

# The oracle test hook must fire: the run aborts at the oracle, with the marker,
# on the first signed seed. Its artefact (a committed seed, not a finding) is
# saved as results/oracle-hook-crash-*, apart from anything a campaign finds.
name=fuzz_fit_oracle_hook_check
log=$OUT/results/$name.log
rc=0
run "$name" "$S" oracle-hook- || rc=$?
(( rc != 0 )) || die "$name: the oracle did not fire on the swapped digest"
grep -q '^fit_fuzz: oracle test hook: expected digest swapped' "$log" \
  && grep -q '^UBOOT_FIT_ORACLE: verified!=booted' "$log" \
  && ! grep -q '^fit_fuzz: signed seed check failed' "$log" \
  || die "$name: exit $rc, but not at the oracle; full log kept locally in results/ (not printed under CI)"
echo "oracle test hook: the oracle fires when the expected digest is swapped (exit $rc, as intended)"

# --- CVE-2021-27138 regression ---------------------------------------------------
# The oracle's positive control (README). On the pin, fit_check_format() rejects
# the '@' node and the target stays quiet: an abort fails the replay.
REG=$HERE/regress/cve-2021-27138.fit
G=$OUT/regress
rm -rf "$G" && mkdir -p "$G" && cp "$REG" "$G/"
replay fuzz_fit_check_format "$G" 1
echo "CVE-2021-27138 input: the oracle stays quiet on U-Boot $(pin version)"

# On v2021.01 it must fire. That tree has no libFuzzer: the glue's "fuzz"
# command runs the same target once on the file, from the run directory.
OB=$OUT/v2021.01/sandbox
PIN=$HERE/pins/v2021.01.txt
if (( BUILD )); then bash "$HERE/build.sh" --version-file "$PIN" --out "$OUT/v2021.01"; fi
want="u-boot $(pin version) sha256 $(pin sha256)"
[[ $(head -n 1 "$OB/toolchain.txt" 2>/dev/null) == "$want" ]] \
  || die "$OB/u-boot is not a finished build of '$want'; rebuild it (drop --no-build)"
cp "$HERE/replay/control-dev.dtb" "$HERE/replay/p2-signed.kernel.sha256" "$REG" "$OB/"
log=$OUT/results/cve-2021-27138-v2021.01.log
rc=0
( cd "$OB" && ./u-boot -D -c "fuzz fuzz_fit_check_format cve-2021-27138.fit" ) > "$log" 2>&1 || rc=$?
if ! in_ci; then cat "$log"; fi
# fit_image_load() names the node it loads; the signature covers "kernel".
(( rc != 0 )) && grep -q '^UBOOT_FIT_ORACLE: verified!=booted' "$log" \
  && grep -q "Trying 'kernel@1' kernel subimage" "$log" \
  || die "v2021.01: the oracle did not fire on kernel@1 (exit $rc); full log kept locally in results/"
echo "CVE-2021-27138 input: the oracle fires on U-Boot 2021.01, bootm loaded kernel@1 (exit $rc, as intended)"

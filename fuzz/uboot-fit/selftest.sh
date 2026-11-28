#!/usr/bin/env bash
# Offline self-test for fuzz/uboot-fit/ (no network, no U-Boot build).
# Checks:
#   1. fit_fuzz.c holds only the upstreamable fuzz_fit_check_format FUZZ_TEST,
#      while fit_fuzz_ci.c includes fit_fuzz.c and holds the local check harnesses.
#   2. Under bash < 4, build.sh / ci-replay.sh / check_cve_2026_46728.sh fail
#      cleanly with a bash-version message (and still serve --help).
#   3. Under bash 4+ (CI / WSL), ci-replay.sh --no-build rejects stale
#      fit_fuzz.c, fit_fuzz_ci.c, config, legacy toolchain.txt, and stale
#      stub-sandbox builds, and accepts fresh provenance.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
in_ci() { [[ -n ${CI:-} || -n ${GITHUB_ACTIONS:-} ]]; }
die() { echo "selftest.sh: FAIL: $*" >&2; exit 1; }

# --- 1. fit_fuzz.c holds only the upstreamable FUZZ_TEST ----------------------
fuzz_tests=$(grep -E '^FUZZ_TEST\(' "$HERE/fit_fuzz.c" || true)
[[ $fuzz_tests == "FUZZ_TEST(fuzz_fit_check_format, 0);" ]] \
  || die "fit_fuzz.c should register only fuzz_fit_check_format, found: $fuzz_tests"
grep -qxF '#include "fit_fuzz.c"' "$HERE/fit_fuzz_ci.c" \
  || die "fit_fuzz_ci.c does not #include \"fit_fuzz.c\""
for t in fuzz_fit_check_format_accept fuzz_fit_config_verify_check \
         fuzz_fit_oracle_hook_check fuzz_fit_confirm; do
  grep -qxF "FUZZ_TEST($t, 0);" "$HERE/fit_fuzz_ci.c" \
    || die "fit_fuzz_ci.c lacks FUZZ_TEST($t, 0);"
done

# --- 2. Bash version guard (on bash < 4) / --help on any bash -----------------
for s in "$HERE/build.sh" "$HERE/ci-replay.sh" "$HERE/regress/check_cve_2026_46728.sh"; do
  bash "$s" --help >/dev/null || die "$(basename "$s") --help failed"
done

if (( ${BASH_VERSINFO[0]:-0} < 4 )); then
  if in_ci; then
    die "bash 4+ required under CI (found ${BASH_VERSION:-unknown})"
  fi
  for s in "$HERE/build.sh" "$HERE/ci-replay.sh" "$HERE/regress/check_cve_2026_46728.sh"; do
    out=$(bash "$s" 2>&1 || true)
    grep -q 'needs bash 4+' <<< "$out" \
      || die "$(basename "$s") did not report 'needs bash 4+' under bash $BASH_VERSION: $out"
  done
  echo "[SKIP] ci-replay.sh --no-build provenance check (host bash is $BASH_VERSION; CI runs it on bash 4+)"
  exit 0
fi

# --- 3. ci-replay.sh --no-build provenance check (bash 4+) --------------------
command -v sha256sum >/dev/null || die "missing tool: sha256sum"
sha256_of() { sha256sum "$1" | awk '{print $1}'; }
pin_of() { awk -v k="$2:" '$1 == k {print $2}' "$1"; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/sandbox" "$T/stub-sandbox"
echo "selftest" > "$T/.uboot-fit-build"
# Empty executable placeholders: once check_toolchain passes, ci-replay.sh moves
# on to stub_marks (nm), which fails without printing a stale/provenance error.
printf '#!/bin/sh\nexit 0\n' > "$T/sandbox/u-boot"
printf '#!/bin/sh\nexit 0\n' > "$T/stub-sandbox/u-boot"
chmod +x "$T/sandbox/u-boot" "$T/stub-sandbox/u-boot"

PIN=$HERE/pin.txt
VER=$(pin_of "$PIN" version)
SHA=$(pin_of "$PIN" sha256)
H_FUZZ=$(sha256_of "$HERE/fit_fuzz.c")
H_CI=$(sha256_of "$HERE/fit_fuzz_ci.c")
H_CFG=$(sha256_of "$HERE/fuzz.config")
BAD_SHA=0000000000000000000000000000000000000000000000000000000000000000

write_tc() { # path, ver, sha, h_fuzz, h_ci, h_cfg
  {
    echo "u-boot $2 sha256 $3"
    echo "source_date_epoch 0"
    echo "clang version test"
    [[ -z ${4:-} ]] || echo "fit_fuzz.c $4"
    [[ -z ${5:-} ]] || echo "fit_fuzz_ci.c $5"
    [[ -z ${6:-} ]] || echo "config $6"
  } > "$1"
}

run_replay() { # [extra args...]
  local out rc=0
  out=$(bash "$HERE/ci-replay.sh" --no-build --out "$T" "$@" 2>&1) || rc=$?
  printf '%s' "$out"
  return "$rc"
}

expect_fail_matching() { # label, expected-substring, [extra args...]
  local label=$1 needle=$2 out rc=0
  shift 2
  out=$(run_replay "$@") || rc=$?
  (( rc != 0 )) || die "$label: expected non-zero exit"
  grep -qF "$needle" <<< "$out" \
    || die "$label: expected '$needle' in output, got: $out"
}

# 3a. Fresh provenance passes check_toolchain (proceeds past it to stub_marks/nm).
write_tc "$T/sandbox/toolchain.txt" "$VER" "$SHA" "$H_FUZZ" "$H_CI" "$H_CFG"
write_tc "$T/stub-sandbox/toolchain.txt" "$VER" "$SHA" "$H_FUZZ" "$H_CI" "$H_CFG"
out=$(run_replay || true)
! grep -qE 'is stale:|was built from' <<< "$out" \
  || die "fresh provenance rejected unexpectedly: $out"

# 3b. Stale fit_fuzz.c rejected.
write_tc "$T/sandbox/toolchain.txt" "$VER" "$SHA" "$BAD_SHA" "$H_CI" "$H_CFG"
expect_fail_matching "stale fit_fuzz.c" "is stale: fit_fuzz.c SHA-256"

# 3c. Stale fit_fuzz_ci.c rejected.
write_tc "$T/sandbox/toolchain.txt" "$VER" "$SHA" "$H_FUZZ" "$BAD_SHA" "$H_CFG"
expect_fail_matching "stale fit_fuzz_ci.c" "is stale: fit_fuzz_ci.c SHA-256"

# 3d. Stale fuzz.config rejected.
write_tc "$T/sandbox/toolchain.txt" "$VER" "$SHA" "$H_FUZZ" "$H_CI" "$BAD_SHA"
expect_fail_matching "stale fuzz.config" "is stale: fuzz.config SHA-256"

# 3e. Legacy toolchain.txt (no harness/config hashes) rejected.
write_tc "$T/sandbox/toolchain.txt" "$VER" "$SHA" "" "" ""
expect_fail_matching "legacy toolchain.txt" "is stale: fit_fuzz.c SHA-256 is 'missing'"

# 3f. Fresh sandbox + stale stub-sandbox rejected.
write_tc "$T/sandbox/toolchain.txt" "$VER" "$SHA" "$H_FUZZ" "$H_CI" "$H_CFG"
write_tc "$T/stub-sandbox/toolchain.txt" "$VER" "$SHA" "$H_FUZZ" "$H_CI" "$BAD_SHA"
expect_fail_matching "stale stub-sandbox config" "stub-sandbox/u-boot is stale: fuzz.config SHA-256"

# 3g. Wrong U-Boot version/sha256 rejected.
write_tc "$T/sandbox/toolchain.txt" "2025.01" "$SHA" "$H_FUZZ" "$H_CI" "$H_CFG"
expect_fail_matching "wrong U-Boot version" "was built from"

# 3h. Alternate pin with its own config (pins/v2021.01.txt -> v2021.01.config).
V21_PIN=$HERE/pins/v2021.01.txt
V21_VER=$(pin_of "$V21_PIN" version)
V21_SHA=$(pin_of "$V21_PIN" sha256)
V21_CFG=$(sha256_of "$HERE/pins/v2021.01.config")
write_tc "$T/sandbox/toolchain.txt" "$V21_VER" "$V21_SHA" "$H_FUZZ" "$H_CI" "$BAD_SHA"
write_tc "$T/stub-sandbox/toolchain.txt" "$V21_VER" "$V21_SHA" "$H_FUZZ" "$H_CI" "$V21_CFG"
expect_fail_matching "v2021.01 stale config" "is stale: v2021.01.config SHA-256" --version-file "$V21_PIN"
write_tc "$T/sandbox/toolchain.txt" "$V21_VER" "$V21_SHA" "$H_FUZZ" "$H_CI" "$V21_CFG"
out=$(run_replay --version-file "$V21_PIN" || true)
! grep -qE 'is stale:|was built from' <<< "$out" \
  || die "v2021.01 fresh provenance rejected unexpectedly: $out"

echo "selftest.sh: all checks passed"

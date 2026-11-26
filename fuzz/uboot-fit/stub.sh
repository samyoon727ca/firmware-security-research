# Sourced by build.sh, ci-replay.sh, confirm.sh and bench.sh: the two marks
# crypto-stub.patch puts in a binary, the stub's symbol and banner.
STUB_SYMBOL=fuzz_crypto_stub_verify
STUB_BANNER=UBOOT_FIT_CRYPTO_STUB

# stub_marks <u-boot>: print how many it carries (real build 0, stub build 2).
stub_marks() {
  local syms n=0
  syms=$(nm "$1") || return 1
  if grep -qE "[[:space:]]$STUB_SYMBOL\$" <<< "$syms"; then n=$((n + 1)); fi
  if grep -aqF "$STUB_BANNER" "$1"; then n=$((n + 1)); fi
  echo "$n"
}

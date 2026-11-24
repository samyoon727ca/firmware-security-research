#!/usr/bin/env bash
# Build the U-Boot sandbox as a libFuzzer + ASan binary carrying the FIT
# format-check fuzz target (fit_fuzz.c).
#
# Usage: build.sh [--version-file pin.txt] [--out build/]
#
#   --version-file  U-Boot pin: version, url, sha256, optional mirrors and
#                   source_date_epoch (default: pin.txt next to this script)
#   --out           output directory, git-ignored (default: build/ next to
#                   this script). Must be new, empty, or an earlier build.sh
#                   output (it holds a .uboot-fit-build marker), because the
#                   script deletes and recreates its src/ and sandbox/.
#
# Steps: download the pinned tarball and refuse it unless its SHA-256 matches;
# unpack it into <out>/src; copy fit_fuzz.c into the tree's test/fuzz/; build
# sandbox_defconfig + fuzz.config with clang (CONFIG_FUZZ adds
# -fsanitize=fuzzer,address); check the .config and the linked binary.
# Result: <out>/sandbox/u-boot, a libFuzzer binary. Run it with
#   UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format <out>/sandbox/u-boot [args]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=$HERE/pin.txt
OUT=$HERE/build
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 2)}
CC=${CC:-clang}

die() { echo "build.sh: $*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

while (( $# )); do
  case $1 in
    --version-file) [[ $# -ge 2 ]] || die "$1 needs a file"; PIN=$2; shift 2 ;;
    --out)          [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *)              die "unknown argument: $1 (see --help)" ;;
  esac
done
[[ -f $PIN ]] || die "no pin file: $PIN"
# The script deletes and recreates <out>/src and <out>/sandbox, so it only
# writes into a directory that is new, empty, or one it made itself (marked).
MARKER=.uboot-fit-build
if [[ -e $OUT ]]; then
  [[ -d $OUT ]] || die "--out is not a directory: $OUT"
  if [[ ! -f $OUT/$MARKER && -n $(ls -A "$OUT") ]]; then
    die "--out $OUT is not empty and has no $MARKER marker; refusing to delete anything in it"
  fi
fi
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
echo "build tree of fuzz/uboot-fit/build.sh; its src/, sandbox/ and replay/ are rebuilt on each run" > "$OUT/$MARKER"

for tool in curl sha256sum tar bzip2 make "$CC"; do
  command -v "$tool" >/dev/null || die "missing tool: $tool"
done

pin() { awk -v k="$1:" '$1 == k {print $2}' "$PIN"; }

VER=$(pin version)
SHA=$(pin sha256)
# Both end up in paths and in a sha256sum line, so take only the expected shape.
[[ $VER =~ ^v?[0-9]{4}\.[0-9]{2}(-rc[0-9]+)?$ ]] || die "bad version in $PIN: '$VER'"
[[ $SHA =~ ^[0-9a-f]{64}$ ]] || die "bad sha256 in $PIN: '$SHA'"
mapfile -t URLS < <(pin url; pin mirror)
(( ${#URLS[@]} )) || die "no url in $PIN"

fetch() { # sha256 dest url [mirror...]
  # The SHA-256 decides what is accepted; a URL is only a carrier. The URLs
  # are tried in order, and the first that delivers the pinned bytes is used.
  local sha=$1 dest=$2 url; shift 2
  if [[ -f $dest ]] && echo "$sha  $dest" | sha256sum -c --status; then
    echo "using cached $(basename "$dest")"; return
  fi
  rm -f "$dest"
  for url in "$@"; do
    if ! curl -sSfL --proto '=https' --retry 3 --connect-timeout 20 -o "$dest.part" "$url"; then
      echo "download failed: $url" >&2; rm -f "$dest.part"; continue
    fi
    if echo "$sha  $dest.part" | sha256sum -c --status; then
      mv "$dest.part" "$dest"; echo "fetched $(basename "$dest") from $url"; return
    fi
    echo "SHA-256 mismatch for $url" >&2; rm -f "$dest.part"
  done
  die "no source delivered $(basename "$dest") with SHA-256 $sha"
}

# --- Source -------------------------------------------------------------------
DL=$OUT/dl
mkdir -p "$DL"
TAR=$(basename "${URLS[0]}")
[[ $TAR =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "bad tarball name in url: '$TAR'"
TAR=$DL/$TAR
fetch "$SHA" "$TAR" "${URLS[@]}"

SRC=$OUT/src/u-boot-${VER#v}
rm -rf "$OUT/src" && mkdir -p "$OUT/src"
tar -xf "$TAR" -C "$OUT/src"
[[ -f $SRC/Makefile ]] || die "tarball did not unpack to $SRC"

# --- Patch the fuzz target into U-Boot's own fuzz directory -------------------
[[ -f $SRC/test/fuzz/Makefile && -f $SRC/include/test/fuzz.h ]] \
  || die "U-Boot $VER has no test/fuzz/ (FUZZ_TEST) mechanism to add the target to"
cp "$HERE/fit_fuzz.c" "$SRC/test/fuzz/fit_fuzz.c"
printf '\nobj-$(CONFIG_FIT) += fit_fuzz.o\n' >> "$SRC/test/fuzz/Makefile"

# --- Configure ------------------------------------------------------------------
if [[ -n $(pin source_date_epoch) ]]; then
  SOURCE_DATE_EPOCH=$(pin source_date_epoch)
  export SOURCE_DATE_EPOCH
fi
B=$OUT/sandbox
rm -rf "$B"
MK=(make -s -C "$SRC" O="$B" CC="$CC")
"${MK[@]}" sandbox_defconfig
"$SRC/scripts/kconfig/merge_config.sh" -m -O "$B" "$B/.config" "$HERE/fuzz.config" >/dev/null
"${MK[@]}" olddefconfig

# Every line of fuzz.config must survive olddefconfig: Kconfig silently drops
# options whose dependencies are not met (CONFIG_FUZZ needs CC_IS_CLANG).
bad=0
while read -r line; do
  if [[ $line =~ ^(CONFIG_[A-Z0-9_]+)=(.*)$ ]]; then
    grep -qxF "$line" "$B/.config" || { echo "  .config lacks: $line" >&2; bad=1; }
  elif [[ $line =~ ^#\ (CONFIG_[A-Z0-9_]+)\ is\ not\ set$ ]]; then
    ! grep -q "^${BASH_REMATCH[1]}=" "$B/.config" || { echo "  .config sets: ${BASH_REMATCH[1]}" >&2; bad=1; }
  fi
done < "$HERE/fuzz.config"
(( bad == 0 )) || die "fuzz.config did not apply (is \$CC=$CC a clang?)"

# --- Build ------------------------------------------------------------------------
# The sandbox links thin archives, so ld holds every object open at once; that
# is more than the common 1024-descriptor soft limit. Raise it to the hard limit.
ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
"${MK[@]}" -j"$JOBS"

# The link must carry the libFuzzer entry point, ASan and the FIT target.
syms=$(nm "$B/u-boot")
for sym in LLVMFuzzerTestOneInput __asan_init fuzz_fit_check_format fit_check_format; do
  grep -qE "[[:space:]]$sym\$" <<< "$syms" || die "u-boot does not define $sym"
done
[[ -f $B/arch/sandbox/dts/test.dtb ]] || die "no test.dtb (the fuzzing-engine device lives in it)"

# What produced this build; ci-replay.sh takes source_date_epoch from here.
{
  echo "u-boot $VER sha256 $SHA"
  echo "source_date_epoch ${SOURCE_DATE_EPOCH:-}"
  "$CC" --version | head -n 1
} > "$B/toolchain.txt"
echo "built $B/u-boot (U-Boot $VER, $(head -n 1 < <("$CC" --version)))"

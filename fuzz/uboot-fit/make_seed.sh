#!/usr/bin/env bash
# Build the signed replay seed from P2's FIT source (seeds/cc.its) with the
# pinned tree's own mkimage, and the control devicetree that holds its key.
#
# Usage: make_seed.sh [--version-file pin.txt] [--out build/]
#
#   --version-file, --out  as for build.sh; <out>/sandbox must be a finished
#                          build of that pin (run build.sh or ci-replay.sh first)
#
# Steps: create a DEV-ONLY RSA-3072 key keys/cc-os-dev.{key,crt} unless one is
# there (keys/ is git-ignored; delete it to rotate the key); write the dummy
# payloads; run "mkimage -f cc.its -k keys -K control.dtb -r", which signs the
# configuration and writes the public key into an empty control devicetree as
# /signature/key-cc-os-dev with required = "conf"; check the result with the
# tree's fit_check_sign. Writes, all committed:
#   replay/p2-signed.fit             the signed FIT
#   replay/control-dev.dtb           control DTB with the dev public key
#   replay/p2-signed.kernel.sha256   SHA-256 (hex) of the signed kernel payload
#   replay/p2-signed.regions.sha256  SHA-256 (hex) the signature covers, the
#                                    only digest the crypto-stub build accepts
# The private key never leaves keys/.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PIN=$HERE/pin.txt
OUT=$HERE/build
KEYS=$HERE/keys
KEY_NAME=cc-os-dev   # key-name-hint in seeds/cc.its, as in P2

die() { echo "make_seed.sh: $*" >&2; exit 1; }

while (( $# )); do
  case $1 in
    --version-file) [[ $# -ge 2 ]] || die "$1 needs a file"; PIN=$2; shift 2 ;;
    --out)          [[ $# -ge 2 ]] || die "$1 needs a directory"; OUT=$2; shift 2 ;;
    -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *)              die "unknown argument: $1 (see --help)" ;;
  esac
done
[[ -f $PIN ]] || die "no pin file: $PIN"
command -v openssl >/dev/null || die "missing tool: openssl"
B=$OUT/sandbox
# Only the pinned tree's tools may make the seeds (same check as ci-replay.sh).
[[ -f $B/toolchain.txt ]] || die "no $B/toolchain.txt: build the tree first (build.sh)"
pin() { awk -v k="$1:" '$1 == k {print $2}' "$PIN"; }
want="u-boot $(pin version) sha256 $(pin sha256)"
have=$(head -n 1 "$B/toolchain.txt")
[[ $have == "$want" ]] || die "$B was built from '$have', not '$want' ($PIN)"
for t in tools/mkimage tools/fit_check_sign scripts/dtc/dtc; do
  [[ -x $B/$t ]] || die "no $B/$t in the build"
done
epoch=$(sed -n 's/^source_date_epoch //p' "$B/toolchain.txt")

# --- Dev key (never committed) ----------------------------------------------------
if [[ ! -f $KEYS/$KEY_NAME.key ]]; then
  mkdir -p "$KEYS" && chmod 700 "$KEYS"
  ( umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$KEYS/$KEY_NAME.key" 2>/dev/null )
  rm -f "$KEYS/$KEY_NAME.crt"
  echo "generated dev-only key $KEYS/$KEY_NAME.key"
fi
# mkimage -K reads the public key from the certificate.
if [[ ! -f $KEYS/$KEY_NAME.crt ]]; then
  openssl req -batch -new -x509 -days 1 -key "$KEYS/$KEY_NAME.key" -out "$KEYS/$KEY_NAME.crt" \
    -subj "/CN=$KEY_NAME (uboot-fit dev-only)"
fi

# --- Sign -------------------------------------------------------------------------
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cp "$HERE/seeds/cc.its" "$W/cc.its"
# Fixed dummy payloads, a few KiB each: the same bytes on every run.
dummy() { # line size: the line repeated, cut to size bytes
  local s=""
  while (( ${#s} < $2 )); do s+="$1"$'\n'; done
  printf '%s' "${s:0:$2}"
}
dummy 'uboot-fit dummy kernel payload' 4096 > "$W/Image.gz"
dummy 'uboot-fit dummy kernel.dtb'     2048 > "$W/kernel.dtb"
dummy 'uboot-fit dummy initramfs'      2048 > "$W/initramfs.cpio.gz"
printf '/dts-v1/;\n/ {\n};\n' > "$W/control.dts"
"$B/scripts/dtc/dtc" -q -I dts -O dtb -o "$W/control.dtb" "$W/control.dts"
# mkimage runs "dtc" from PATH: use the tree's own. SOURCE_DATE_EPOCH fixes the
# signature timestamp, so the same key gives the same bytes.
( cd "$W" && PATH=$B/scripts/dtc:$PATH SOURCE_DATE_EPOCH=${epoch:-0} \
    "$B/tools/mkimage" -f cc.its -k "$KEYS" -K control.dtb -r p2-signed.fit >/dev/null )
"$B/tools/fit_check_sign" -f "$W/p2-signed.fit" -k "$W/control.dtb" >/dev/null \
  || die "fit_check_sign does not verify the signed FIT"
(( $(wc -c < "$W/p2-signed.fit") <= 64 * 1024 )) || die "signed FIT is over the target's 64 KiB input limit"
# The signed-region digest: the signature value (from mkimage -l), opened with
# the public key, is a SHA-256 DigestInfo; its last 32 bytes are the digest.
sig=$("$B/tools/mkimage" -l "$W/p2-signed.fit" | sed -n 's/^ *Sign value: *\([0-9a-f]*\)$/\1/p')
[[ $sig =~ ^[0-9a-f]{768}$ ]] || die "no single RSA-3072 signature value in mkimage -l output"
python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))' "$sig" > "$W/sig.bin"
info=$(openssl pkeyutl -verifyrecover -certin -inkey "$KEYS/$KEY_NAME.crt" -in "$W/sig.bin" | od -An -v -tx1 | tr -d ' \n')
[[ $info =~ ^3031300d060960864801650304020105000420([0-9a-f]{64})$ ]] \
  || die "the signature does not open to a SHA-256 DigestInfo"
regions=${BASH_REMATCH[1]}

mkdir -p "$HERE/replay"
cp "$W/p2-signed.fit" "$HERE/replay/p2-signed.fit"
cp "$W/control.dtb" "$HERE/replay/control-dev.dtb"
sha256sum "$W/Image.gz" | awk '{print $1}' > "$HERE/replay/p2-signed.kernel.sha256"
echo "$regions" > "$HERE/replay/p2-signed.regions.sha256"
echo "wrote replay/p2-signed.fit, replay/control-dev.dtb, replay/p2-signed.{kernel,regions}.sha256"

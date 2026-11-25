# `uboot-fit` — U-Boot FIT parser fuzz target (Phase 0)

In-process libFuzzer + ASan target for **U-Boot's FIT parser** as the boot loader runs it: the
U-Boot **sandbox** built from the pinned **v2026.07** release tarball (the same pin as P2's
verified-boot chain), with `fit_check_format()` fed one fuzzer input per call. That function is
the first code to touch a loaded FIT, **before** the signature check (P2 SR-005.1), so every
byte it reads is attacker-chosen. When the format check passes, the target runs
`fit_config_verify()` on the default configuration against a control devicetree holding a
`required = "conf"` key, as P2's boot loader does: config lookup, `hashed-nodes`, region
building, then the RSA check. When that passes, a **verified-equals-booted oracle** checks that
the kernel bootm would boot is the one the key signed (see [The oracle](#the-verified-equals-booted-oracle)).

Phase 0 is the kill switch: it shows that the sandbox builds with clang + libFuzzer and links
the target, and CI replays a committed seed through it. It does no fuzzing campaign.

> **⚠️ Scope & safety: DEFENSIVE, in-process, no hardware.** This parses bytes in a host
> process. Research / defensive use under coordinated disclosure; see
> [`../../docs/disclosure-policy.md`](../../docs/disclosure-policy.md).
> **Results stay local.** Corpora, crash/leak/oom/timeout artefacts, `results/`, `keys/` and
> the build tree are git-ignored (`.gitignore`). Never commit them, never paste a crashing
> input or its stack into an issue, PR or commit message, and record hashes and provenance in
> the paperwork, never the bytes. No U-Boot sources or binaries are committed either; they
> are rebuilt from `pin.txt`. `ci-replay.sh` keeps the full libFuzzer/ASan log in `results/`
> and prints it only outside CI: under CI (`$CI` or `$GITHUB_ACTIONS` set) it prints the seed
> and run counts, or on failure only the fuzz-test name and exit code, and the workflow never
> uploads `results/`.

## Files

| File | Role |
|------|------|
| `pin.txt` | U-Boot release: version, tarball URL + mirrors, SHA-256, `SOURCE_DATE_EPOCH` |
| `build.sh` | download → SHA-256 check (fails closed) → unpack into `build/` → patch the target in → build; `--crypto-stub` builds the stubbed-RSA variant apart (see [Crypto-stub build](#crypto-stub-build-fuzzing-only)) |
| `crypto-stub.patch`, `stub.sh` | the RSA stub (`lib/rsa/rsa-verify.c`, under `FUZZ_CRYPTO_STUB`), and the symbol and banner that tell a stub binary from a real one |
| `fuzz.config` | Kconfig fragment over `sandbox_defconfig`: `CONFIG_FUZZ` (libFuzzer + ASan), `FIT`, `FIT_SIGNATURE`, `FIT_FULL_CHECK`, no legacy images (as P2's `p2.config`) |
| `fit_fuzz.c` | the target, `FUZZ_TEST(fuzz_fit_check_format)`, plus the replay-only seed checks `fuzz_fit_check_format_accept`, `fuzz_fit_config_verify_check` and the oracle test hook `fuzz_fit_oracle_hook_check`, and `confirm.sh`'s verdict test `fuzz_fit_confirm`; copied into the tree's `test/fuzz/` at build time |
| `seeds/cc.its` | P2's FIT source (`cc/fit/cc.its` in `uas-sec-p2-verified-boot`, provenance in the file): kernel + fdt + ramdisk, sha256 hashes, one config signed with `sign-images` |
| `make_seed.sh` | signs `seeds/cc.its` over dummy payloads with a dev-only key and the tree's own `mkimage`; writes the four `replay/` files below |
| `replay/` | committed seeds, each a FIT `fit_check_format()` accepts. `minimal.its` is compiled with the tree's own `mkimage`; `p2-signed.fit` is the signed seed, `control-dev.dtb` the control DTB with its public key (`required = "conf"`), `p2-signed.kernel.sha256` the SHA-256 of its kernel payload (the oracle's expected digest), `p2-signed.regions.sha256` the digest its signature covers (the only one the stub accepts) |
| `ci-replay.sh` | build both variants, then replay `replay/` with `-runs=0` (never mutates) through each; used by `.github/workflows/uboot-fit.yml` |
| `confirm.sh` | replays inputs on the **real-crypto** build only: crash / timeout / verified / rejected each, appended to `build/results/confirm.txt` |
| `bench.sh` | **local only**, never in CI: fuzzes each variant for N seconds into `corpus/` and `build/results/`, prints exec/s |

## Build

Linux (WSL Ubuntu or CI), clang with libFuzzer, plus U-Boot's host build deps:

```bash
sudo apt install -y clang llvm libclang-rt-dev make bison flex bc libssl-dev libgnutls28-dev \
    uuid-dev python3-dev python3-setuptools swig pkg-config

fuzz/uboot-fit/build.sh                                  # pin.txt -> build/sandbox/u-boot
fuzz/uboot-fit/build.sh --version-file other-pin.txt --out build-other/
```

The build uses U-Boot's own fuzz mechanism (`CONFIG_FUZZ` adds `-fsanitize=fuzzer,address`;
the target registers with `FUZZ_TEST`), so it can go upstream unchanged. `build.sh` checks that
every line of `fuzz.config` survived `olddefconfig`, and that the linked `u-boot` defines
`LLVMFuzzerTestOneInput`, `__asan_init` and the target.

## Replay (what CI runs)

```bash
fuzz/uboot-fit/ci-replay.sh              # build + replay
fuzz/uboot-fit/ci-replay.sh --no-build   # replay against an existing build/
```

`ci-replay.sh` replays the seeds twice, both with `-runs=0`: through the fuzz target (no crash
or sanitizer report), then through `fuzz_fit_check_format_accept`, which aborts unless
`fit_check_format()` returns 0. The second run shows the seeds get past the format check in this
build, so they reach the parser code after it, not only its first error branch.

A third run replays the signed seeds (`replay/*.fit`) through `fuzz_fit_config_verify_check`,
which aborts unless each one passes `fit_config_verify()` against `control-dev.dtb` and its
kernel passes `fit_image_verify()`, and unless both tampered copies are rejected: one kernel
payload byte flipped (caught by the kernel's hash check; the config signature leaves out
`data` and covers the hash value instead, and the check asserts that too) and one byte of the
kernel's hash value flipped (caught by `fit_config_verify()`). It also runs the oracle: on the
seed, bootm's lookup must load the signed kernel and the oracle must stay quiet; on the flipped
payload byte, bootm's lookup must refuse the kernel (counted, not reported). A fourth run,
`fuzz_fit_oracle_hook_check`, must **fail**: it aborts at the oracle with the marker line (see
below). Either way the binary must come from the `--version-file` pin: `ci-replay.sh` compares its version and SHA-256
with `build/sandbox/toolchain.txt`, so `--no-build` cannot replay a build of another release.
The crypto-stub build replays the seeds too and must accept a flipped signature byte that the real build rejects; `confirm.sh` must call the signed seed verified, `minimal.itb` rejected.

To run one input by hand: the sandbox finds `test.dtb`, and the target `control-dev.dtb` and
`p2-signed.kernel.sha256`, relative to the working directory, so run from the build directory
and pass absolute paths (`ci-replay.sh` copies both files there, and `build/replay/` holds the
compiled seeds once it has run). The target aborts if either file is missing: the sandbox's own
control DTB has no key, and `fit_config_verify()` accepts any FIT against it; without the digest
the oracle has nothing to compare.

```bash
cd fuzz/uboot-fit/build/sandbox
UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format ./u-boot -runs=0 "$PWD/../replay"
```

## The verified-equals-booted oracle

A sanitizer sees memory errors, not a verification bypass: the class of CVE-2021-27097 and
CVE-2021-27138, where a FIT passes `fit_config_verify()` but bootm loads bytes that were never
signed. The oracle in `fit_fuzz.c` asserts the property directly. For every input that passes
`fit_check_format()` and `fit_config_verify()` on the default configuration, and only then, it:

1. looks the kernel up **the way bootm does**: the same `fit_image_load()` call as
   `boot_get_kernel()` in `boot/bootm.c` (default configuration, `IH_ARCH_DEFAULT`,
   `IH_TYPE_KERNEL`, `FIT_LOAD_IGNORED`, `images.verify` on) on the same buffer, with
   `control-dev.dtb` as the key blob. So bootm's own config and image hash checks run too;
2. hashes the bytes it returns, the `os_data`/`os_len` bootm would boot, with SHA-256;
3. compares that with `p2-signed.kernel.sha256`, the kernel the dev key signed. Only that key
   can make a FIT verify, and it signed nothing else. On a mismatch it prints the one-line marker
   `UBOOT_FIT_ORACLE: verified!=booted` and aborts, so libFuzzer saves the input as a crash.

**Verified but not booted is not a bypass.** If `fit_image_load()` fails after
`fit_config_verify()` passed (e.g. the kernel's data no longer matches its hash, or its type is
wrong), bootm boots nothing. The target counts it, prints `fit_fuzz: oracle: verified, but bootm
would not load the kernel (<err>); not a bypass, <n> so far` and goes on.

**Test hook.** `fuzz_fit_oracle_hook_check` runs the same path on the signed seed with one bit
of the expected digest flipped, so the oracle must fire on 2026.07 without any bypass input. The
swapped digest exists only in that function, which runs only when named
(`UBOOT_SB_FUZZ_TEST=fuzz_fit_oracle_hook_check`); the fuzz target always uses the digest file.
It prints `fit_fuzz: oracle test hook: …` before the marker, and `ci-replay.sh` saves its
artefact as `results/oracle-hook-crash-*`.

**Reading a hit.** Only a crash whose log has the `UBOOT_FIT_ORACLE: verified!=booted` line is an
oracle hit; any other abort is an ordinary crash candidate. Re-run the saved input by hand
(above) with `fuzz_fit_check_format`: `fit_image_load()`'s trace above the marker names the
configuration and kernel node bootm used, and `fit_config_verify()`'s names the key. Rule out
the harness first (if the committed seed fires too, the digest file is stale, not the parser),
then minimise, root-cause it in source, and run the dedup gate before any claim.

> **A hit on 2026.07 is unreported by definition.** It stays in git-ignored paths (`results/`,
> the corpus, the build tree) and goes nowhere else: no issue, CI log, commit message or PR
> text, and not its input bytes, stack or digest, as
> [`../../docs/disclosure-policy.md`](../../docs/disclosure-policy.md) and the embargo guard
> (`tools/embargo-guard.sh`) require. The CI job never fuzzes, prints no replay log and uploads
> no `results/`.

## Crypto-stub build (fuzzing only)

Real RSA on every input slows fuzzing, so an **opt-in** build stubs it for structure
exploration; a hit counts only once `confirm.sh` reproduces it on real crypto.

```bash
fuzz/uboot-fit/build.sh --crypto-stub      # -> build/stub-sandbox/u-boot, source in build/stub-src/
fuzz/uboot-fit/confirm.sh <input>...       # real crypto only: crash / timeout / verified / rejected
fuzz/uboot-fit/bench.sh [--seconds 60]     # LOCAL ONLY (refuses under CI): exec/s of each variant
```

`crypto-stub.patch` (in `stub-src/` only, compiled only under `-DFUZZ_CRYPTO_STUB`) makes
`rsa_verify_key()` skip the RSA maths and accept only if the SHA-256 of the signed regions equals
`replay/p2-signed.regions.sha256`, the digest the committed seed's signature covers. It differs
from real RSA only in ignoring the signature bytes: the fuzzer must keep the hashed nodes and values.
A stub binary prints `*** UBOOT_FIT_CRYPTO_STUB … ***` at startup and defines
`fuzz_crypto_stub_verify` (`stub.sh`). `build.sh` and `ci-replay.sh` fail unless the stub build
has both marks and the real build neither; `confirm.sh` refuses a binary with either, names the
one it ran and appends its verdicts to `build/results/confirm.txt`.

Measured exec/s, a performance number and not a finding (2026-11-25, `bench.sh` defaults, Apple
M2 Pro host: Colima VM (aarch64, Linux 6.8, 4 vCPUs), Ubuntu 24.04 container, clang 18.1.3):

| Variant | exec/s |
|---------|-------:|
| real crypto (`sandbox/`) | 8303 |
| crypto stub (`stub-sandbox/`) | 10201 |

**Stop rule** (from the proposal): if even the stubbed build runs under ~100 exec/s, stop and
report rather than start a campaign. `bench.sh` prints a `STOP RULE` line when that happens.

## Regenerating the signed seed

```bash
fuzz/uboot-fit/build.sh          # or ci-replay.sh: the pinned tree's mkimage, dtc, fit_check_sign
fuzz/uboot-fit/make_seed.sh      # rewrites replay/p2-signed.fit, control-dev.dtb, p2-signed.{kernel,regions}.sha256
```

`make_seed.sh` refuses a build that is not from `pin.txt`. It copies `seeds/cc.its` next to
fixed dummy payloads (a few KiB each, not a kernel), signs it with
`mkimage -f cc.its -k keys -K control.dtb -r` (`SOURCE_DATE_EPOCH` from the pin) and checks the
result with the tree's `fit_check_sign`. Commit the four `replay/` files together: the seed only
verifies against the control DTB made in the same run.

**The key is dev-only.** It is an RSA-3072 key, `keys/cc-os-dev.key` (+ `.crt`), created by
`make_seed.sh` on first use and reused after; delete `keys/` to rotate it. `keys/` is git-ignored
and the private key is never committed: CI needs only the committed public half in
`control-dev.dtb`. It signs nothing but these fuzz seeds and has no relation to any P2 or
release key.

## Notes

- The sandbox's `malloc()` is U-Boot's own heap, which ASan cannot see into, so the target
  copies each input into an aligned static buffer and poisons the bytes after it. A read past
  the input's end is reported even when it stays inside the buffer.
- Inputs under one FDT header (40 bytes) are skipped: `fdt_check_header()` reads a whole header
  before it checks the size, because every real caller has that much memory behind the pointer.
- **`--out` safety.** `build.sh` deletes and recreates `<out>/src` and `<out>/sandbox` (`stub-*` with `--crypto-stub`), and
  `ci-replay.sh` recreates `<out>/replay` and `<out>/signed`, so both refuse an `--out` that is
  not new, empty, or marked with the `.uboot-fit-build` file `build.sh` writes there.
- **Older releases (v2021.01, for the CVE-2021-27138 oracle task).** The pin is overridable, but
  this build path does not carry over as is: trees from before roughly 2022 have no
  `test/fuzz/` `FUZZ_TEST` mechanism (`build.sh` stops with a clear error), and their
  `fit_check_format()` takes no size argument, so `fit_fuzz.c` does not compile there. That task
  needs its own entry point (a standalone `LLVMFuzzerTestOneInput`) or a backport of the fuzz
  mechanism.
- **Pin.** `pin.txt` was checked against `cc/uboot/pin.txt` in `uas-sec-p2-verified-boot`: the
  version, URL, SHA-256, mirrors, commit and `SOURCE_DATE_EPOCH` all match.
- Every crash is a **candidate**, not a finding: minimize, root-cause in source, and run the
  dedup gate before any claim of novelty.

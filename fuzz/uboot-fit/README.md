# `uboot-fit` — U-Boot FIT parser fuzz target (Phase 0)

In-process libFuzzer + ASan target for **U-Boot's FIT parser** as the boot loader runs it: the
U-Boot **sandbox** built from the pinned **v2026.07** release tarball (the same pin as P2's
verified-boot chain), with `fit_check_format()` fed one fuzzer input per call. That function is
the first code to touch a loaded FIT, **before** the signature check (P2 SR-005.1), so every
byte it reads is attacker-chosen.

Phase 0 is the kill switch: it shows that the sandbox builds with clang + libFuzzer and links
the target, and CI replays a committed seed through it. It does no fuzzing campaign.

> **⚠️ Scope & safety: DEFENSIVE, in-process, no hardware.** This parses bytes in a host
> process. Research / defensive use under coordinated disclosure; see
> [`../../docs/disclosure-policy.md`](../../docs/disclosure-policy.md).
> **Results stay local.** Corpora, crash/leak/oom/timeout artefacts, `results/`, `keys/` and
> the build tree are git-ignored (`.gitignore`). Never commit them, never paste a crashing
> input or its stack into an issue, PR or commit message, and record hashes and provenance in
> the paperwork, never the bytes. No U-Boot sources or binaries are committed either; they
> are rebuilt from `pin.txt`.

## Files

| File | Role |
|------|------|
| `pin.txt` | U-Boot release: version, tarball URL + mirrors, SHA-256, `SOURCE_DATE_EPOCH` |
| `build.sh` | download → SHA-256 check (fails closed) → unpack into `build/` → patch the target in → build |
| `fuzz.config` | Kconfig fragment over `sandbox_defconfig`: `CONFIG_FUZZ` (libFuzzer + ASan), `FIT`, `FIT_SIGNATURE`, `FIT_FULL_CHECK`, no legacy images (as P2's `p2.config`) |
| `fit_fuzz.c` | the target, `FUZZ_TEST(fuzz_fit_check_format)`; copied into the tree's `test/fuzz/` at build time |
| `replay/` | committed seeds; `minimal.its` is compiled to a FIT with the tree's own `mkimage` |
| `ci-replay.sh` | build, then replay `replay/` with `-runs=0` (never mutates); used by `.github/workflows/uboot-fit.yml` |

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

To run one input by hand: the sandbox finds `test.dtb` relative to the working directory, so
run from the build directory and pass absolute paths (`build/replay/` holds the compiled seeds
once `ci-replay.sh` has run):

```bash
cd fuzz/uboot-fit/build/sandbox
UBOOT_SB_FUZZ_TEST=fuzz_fit_check_format ./u-boot -runs=0 "$PWD/../replay"
```

## Notes

- The sandbox's `malloc()` is U-Boot's own heap, which ASan cannot see into, so the target
  copies each input into an aligned static buffer and poisons the bytes after it. A read past
  the input's end is reported even when it stays inside the buffer.
- Inputs under one FDT header (40 bytes) are skipped: `fdt_check_header()` reads a whole header
  before it checks the size, because every real caller has that much memory behind the pointer.
- **`--out` safety.** `build.sh` deletes and recreates `<out>/src` and `<out>/sandbox`, and
  `ci-replay.sh` recreates `<out>/replay`, so both refuse an `--out` that is not new, empty, or
  marked with the `.uboot-fit-build` file `build.sh` writes there.
- **Older releases (v2021.01, for the CVE-2021-27138 oracle task).** The pin is overridable, but
  this build path does not carry over as is: trees from before roughly 2022 have no
  `test/fuzz/` `FUZZ_TEST` mechanism (`build.sh` stops with a clear error), and their
  `fit_check_format()` takes no size argument, so `fit_fuzz.c` does not compile there. That task
  needs its own entry point (a standalone `LLVMFuzzerTestOneInput`) or a backport of the fuzz
  mechanism.
- **Pin cross-check pending.** `pin.txt` is meant to match `cc/uboot/pin.txt` in
  `uas-sec-p2-verified-boot`. The SHA-256 was checked against the tarball the release mirrors
  serve, but not yet diffed against P2's file; someone with access to P2 should compare the
  `url` and `sha256` lines.
- Every crash is a **candidate**, not a finding: minimize, root-cause in source, and run the
  dedup gate before any claim of novelty.

# firmware-security-research: guide

This repository is a public portfolio of embedded and firmware security work on publicly available targets. It holds reusable assessment tooling (scripts that take a firmware image through triage, version diffing, reporting and charting), security engineering documents for open platforms such as drone autopilots, and the paperwork and case studies from live vulnerability-research runs. Its readers are the owner and anyone reviewing the work, and its tooling is used by the owner and by AI agents working in the repo.

## How it fits

- **Program plan.** Deliverables carry IDs (P0.x to P7.x, T2) tracked in
  [`roadmap.md`](roadmap.md), which is the single place status lives. Restart notes for the
  next working session are in [`NEXT-SESSION.md`](NEXT-SESSION.md).
- **Sibling repository.** The U-Boot fuzz target reuses the release pin and FIT source of
  `uas-sec-p2-verified-boot` (P2's verified-boot chain); `fuzz/uboot-fit/pin.txt` and
  `fuzz/uboot-fit/seeds/cc.its` record that provenance. Personal planning lives in a separate
  private companion repository, not here (`CLAUDE.md`).
- **External tools and pins.**
  - U-Boot **v2026.07**, tarball pinned by SHA-256 with mirrors and a fixed
    `SOURCE_DATE_EPOCH` (`fuzz/uboot-fit/pin.txt`).
  - CI runs on `ubuntu-24.04` with Python **3.12**; GitHub Actions are pinned to full commit
    SHAs (`.github/workflows/checks.yml`, `.github/workflows/uboot-fit.yml`).
  - `pymavlink` (unpinned, `tools/mavlink-sectest/requirements.txt`) for the MAVLink harness.
  - The Rust signing crate has no external dependencies (`tools/mavlink-signing/Cargo.toml`).
  - The firmware toolchain (binwalk, sasquatch, jefferson, ubi_reader, QEMU) is installed by
    `.claude/skills/firmware-triage/scripts/setup-tools.sh`; Ghidra is used for headless
    decompilation by the scripts under `research/*/ghidra/`.
  - Live MAVLink tests run against ArduPilot or PX4 SITL (software-in-the-loop simulators).
- **What depends on it.** Nothing in this repo is a library for other code; its outputs are
  documents, writeups and disclosure paperwork.

## How it works

The core is the **assessment funnel**: five Claude Code Skills under `.claude/skills/`, each a
`SKILL.md` instruction file plus small scripts, chained so one stage's output feeds the next.

```text
vendor firmware (acquired by hand, never committed)
  -> firmware-triage   extract, inventory, rank binaries by dangerous C sinks
  -> binary-diff       old vs new rootfs -> ranked "silent fix" candidates
  -> (Ghidra confirmation + dedup against public CVEs: human judgment)
  -> finding.json      one record per finding
       -> finding-to-vendor-report   CVSS score + PSIRT report + disclosure email
       -> finding-to-cve-writeup     CVE JSON 5.1 + public writeup + sanitize lint
  -> security-dataviz  SVG charts and mermaid diagrams for briefings
```

1. **Triage.** `.claude/skills/firmware-triage/scripts/triage.sh` extracts and inventories a
   root filesystem; `sink_scan.py` scores ELF binaries that call sinks like `system`/`strcpy`
   and writes a CSV.
2. **Diff.** `.claude/skills/binary-diff/scripts/fw_diff.py` compares two extracted versions
   and writes `diff-candidates.csv`, pointing at the binary most likely to hold a fixed bug.
3. **Finding record.** A `finding.json` (template:
   `.claude/skills/finding-to-vendor-report/templates/finding.json`) is the shared input for
   reporting. `cvss.py` computes CVSS v3.1; `make_report.py` validates the record and fills
   the vendor-report template.
4. **Publication.** `.claude/skills/finding-to-cve-writeup/scripts/make_cve.py` emits a CVE
   JSON record; `sanitize_check.py` lints a writeup for key material, unfilled placeholders and
   weaponized payloads before it goes into `writeups/`.
5. **Visuals.** `.claude/skills/security-dataviz/scripts/chart.py` and `diagram.py`.

Each live run gets a working area under `research/<target>/` (acquisition log with hashes,
target notes, Ghidra scripts, finding record). [`track1-acquisition-runbook.md`](track1-acquisition-runbook.md)
is the step-by-step procedure.

Three side pipelines sit next to the funnel:

- **MAVLink harness** (`tools/mavlink-sectest/mavlink_sectest.py`): connects to a SITL
  autopilot, checks signing, benign command injection, replay, cleartext telemetry and
  failsafe settings, and writes a JSON report plus a CSV the dataviz skill can chart. It
  refuses non-local endpoints without `--allow-nonsim` (`tools/mavlink-sectest/mavlink_sectest.py:153`).
- **MAVLink signing crate** (`tools/mavlink-signing/src/lib.rs`): Rust sign/verify/anti-replay,
  the control the capstone recommends; design in `tools/mavlink-signing/SPEC.md`.
- **U-Boot FIT fuzz target** (`fuzz/uboot-fit/`): `build.sh` downloads the pinned tarball,
  checks its SHA-256 and fails closed (`fuzz/uboot-fit/build.sh:89`), then builds the U-Boot
  sandbox with libFuzzer + ASan (AddressSanitizer) and links `fit_fuzz.c`. The target runs
  `fit_check_format()`, then `fit_config_verify()`, then a "verified-equals-booted" oracle that
  aborts with a marker line if bootm would load a kernel other than the signed one
  (`fuzz/uboot-fit/fit_fuzz.c:216`). `ci-replay.sh` replays the committed seeds. Because real
  RSA on every input slows fuzzing, `build.sh --crypto-stub` builds a second, opt-in variant in
  its own tree whose RSA check only compares the signed-region digest
  (`fuzz/uboot-fit/crypto-stub.patch`); a stub binary carries a symbol and a startup banner
  (`fuzz/uboot-fit/stub.sh`). `confirm.sh` replays inputs on the real-crypto build only and
  records a verdict for each; `bench.sh` measures exec/s of both variants, locally only.
  Details: [`../fuzz/uboot-fit/README.md`](../fuzz/uboot-fit/README.md).

## Code map

| Path | What's there |
|------|--------------|
| `README.md` | Overview, repository map, narrative status |
| `docs/roadmap.md` | Deliverable status, Track 1 run ledger, the "Next" list |
| `docs/NEXT-SESSION.md` | Restart notes and how to reproduce each run |
| `docs/disclosure-policy.md` | Coordinated disclosure, legal and ethics scope |
| `docs/track1-*.md` | Target selection, acquisition runbook, run 4 (UAS/autonomy) plan |
| `docs/track2/` | Engineering documents: secure boot, threat model, hardening, anti-tamper, FPGA, capstone assessment, leadership brief; `assets/` holds committed capstone results |
| `.claude/skills/` | The five funnel Skills (`SKILL.md`, `scripts/`, `reference/`, `templates/`) |
| `tools/run-checks.sh` | The verification gate run locally and in CI |
| `tools/embargo-guard.sh`, `tools/install-hooks.sh` | Git hooks that keep pre-disclosure material out of this public repo |
| `tools/mavlink-sectest/` | MAVLink SITL test harness |
| `tools/mavlink-signing/` | Rust MAVLink v2 signing crate and its spec |
| `fuzz/uboot-fit/` | U-Boot FIT parser fuzz target, pin, seeds, crypto-stub patch, CI replay, `confirm.sh`/`bench.sh`, CVE-2026-46728 regression notes |
| `research/dlink-rtl819x/`, `research/zyxel-cpe/`, `research/draytek-vigor/` | Track 1 router runs 1 to 3: logs, hashes, Ghidra scripts, finding paperwork |
| `research/uas-autonomy/` | Run 4: Micro-XRCE-DDS Agent scope, fuzz harnesses (`ucdr_fuzz`, `agent_fuzz`, `xrce_probe`) and results |
| `writeups/` | Published case studies (both deduped as n-days) |
| `.github/workflows/` | `checks.yml` (the gate) and `uboot-fit.yml` (fuzz build + seed replay) |

## Run it and test it

The canonical environment is Linux (WSL Ubuntu on the owner's machine); `CLAUDE.md` explains
why Git Bash on Windows does not work. One-time setup:

```bash
sudo apt update && sudo apt install -y build-essential python3-dev python3-venv
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/mavlink-sectest/requirements.txt   # pymavlink
tools/install-hooks.sh                                   # embargo guard, once per clone
```

The gate, exactly as CI runs it after installing pymavlink:

```bash
bash tools/run-checks.sh       # pass bar: "0 failed"
```

It uses `.venv` if present (`tools/run-checks.sh:18`). Steps whose toolchain is absent print
`[skip]` instead of failing: the funnel smoke test without `gcc` (`tools/run-checks.sh:113`),
the Rust tests without `cargo` (`tools/run-checks.sh:148`), and the ELF sink scan when the host
compiler does not produce ELF, e.g. macOS (`tools/run-checks.sh:125`). Outside CI a missing
pymavlink skips only the encode/decode roundtrip; under `CI` it fails
(`tools/mavlink-sectest/mavlink_sectest.py:300`). CI's `ubuntu-24.04` runner has `gcc` and
`cargo`, so no step skips there except the embargo section.

The fuzz target (Linux, clang with libFuzzer; package list in
[`../fuzz/uboot-fit/README.md`](../fuzz/uboot-fit/README.md)):

```bash
fuzz/uboot-fit/ci-replay.sh              # build from pin.txt, then replay the seeds
fuzz/uboot-fit/ci-replay.sh --no-build   # replay against an existing build/
fuzz/uboot-fit/build.sh --crypto-stub    # the stubbed-RSA variant, for fuzzing only
fuzz/uboot-fit/confirm.sh <input>...     # verdict per input on the real-crypto build
fuzz/uboot-fit/bench.sh [--seconds 60]   # exec/s of both variants; refuses to run under CI
```

`ci-replay.sh` builds both variants before replaying (`fuzz/uboot-fit/ci-replay.sh:61`).

CI runs this in `uboot-fit.yml` only when `fuzz/uboot-fit/**` or that workflow changes. It
needs network access to fetch the U-Boot tarball.

Running the funnel on real data and the harness live (commands from the README):

```bash
.claude/skills/firmware-triage/scripts/triage.sh   <rootfs> triage-out/<ver>
.claude/skills/binary-diff/scripts/fw_diff.py       <old_rootfs> <new_rootfs> --out diff-out
python3 tools/mavlink-sectest/mavlink_sectest.py --selftest              # no SITL needed
mavlink_sectest.py --connect udp:127.0.0.1:14550 --out report.json --csv findings.csv  # needs SITL
```

Needs something special: live harness runs need a running ArduPilot/PX4 SITL; real triage needs
vendor firmware (downloading it is a user-confirmed step) and the binwalk toolchain; Ghidra
scripts need a local Ghidra install; the embargo checks need local `drafts/private/` content.
None of these run in CI.

## What's verified

What `tools/run-checks.sh` checks, in CI on every pull request and on `main`:

- **Every Python file under `.claude/` and `tools/` parses**, and every shell script there plus
  tracked `fuzz/*.sh` passes `bash -n` (steps 1 and 2).
- **CVSS calculator** matches its built-in vectors (`cvss.py --selftest`,
  `.claude/skills/finding-to-vendor-report/scripts/cvss.py:96`).
- **MAVLink harness logic** passes its offline self-test, including a real pymavlink roundtrip
  in CI (`tools/mavlink-sectest/mavlink_sectest.py:272`), and the gate checks that a missing
  pymavlink fails under CI and skips outside it (`tools/run-checks.sh:53`).
- **Embargo matcher** passes its self-test (`tools/embargo-guard.sh selftest`).
- **Tracked SVGs are well-formed XML**, mermaid blocks in `docs/` are balanced, and relative
  Markdown links resolve (steps 4 to 6).
- **Funnel smoke test** on a synthetic root filesystem with a deliberately unsafe `httpd`:
  `triage.sh`, `sink_scan.py` (must flag `httpd`), `fw_diff.py`, `chart.py`, then
  `make_report.py --validate`, `make_cve.py` and `diagram.py` on the template finding
  (`tools/run-checks.sh:112`).
- **Rust signing crate**: `cargo test`, seven tests in `tools/mavlink-signing/src/lib.rs`,
  including pymavlink interop vectors and a SHA-256 known-answer test.
- **Published writeups pass the sanitize linter** and every `research/*/finding.json`
  validates (step 9).

What `uboot-fit.yml` checks: the pinned sandbox builds and links the target; the seeds replay
with no sanitizer report; they pass `fit_check_format()`; the signed seed passes
`fit_config_verify()` while two tampered copies are rejected; and the oracle's test hook must
fire (`fuzz/uboot-fit/fit_fuzz.c:235`, `:264`, `:375`, `:410`; driver
`fuzz/uboot-fit/ci-replay.sh`). It also checks that the real build rejects a flipped signature
byte and carries neither stub mark, that the stub build carries both, replays the seeds through
it and must see it accept the flipped signature byte (`fuzz/uboot-fit/ci-replay.sh:79`,
`:195`), and that `confirm.sh` calls the signed seed verified and `minimal.itb` rejected
(`fuzz/uboot-fit/ci-replay.sh:206`). Replay only, with `-runs=0`: no fuzzing happens in CI,
and `bench.sh` is never run there.

Not tested, or only documented:

- The firmware-extraction path itself (binwalk and friends) and `setup-tools.sh`; the smoke
  test feeds an already-extracted directory.
- Ghidra scripts under `research/*/ghidra/` and the run 1 runner
  `research/dlink-rtl819x/extract-and-diff.sh`: steps 1 and 2 only cover `.claude/`, `tools/`
  and `fuzz/`, so these are not even parse-checked.
- The run 4 fuzz harnesses under `research/uas-autonomy/` are built and run by hand; their
  campaign results are recorded in the `phase2-*-results.md` files there.
- Live harness behaviour against SITL: the committed results in `docs/track2/assets/` come
  from manual runs, written up in `docs/track2/uas-capstone-assessment.md`.
- Track 2 documents are prose; only their links, SVGs and mermaid syntax are checked.
- The embargo hooks and tree scan run only on the owner's machine (step 10 skips in CI).

## Decisions and constraints

- **Public repo, no blobs.** Firmware images, extracted trees, Ghidra projects and analysis
  output are git-ignored (`.gitignore`); hashes go in each run's acquisition log instead.
- **Embargo guard.** Pre-disclosure drafts live in the git-ignored `drafts/private/`, and the
  pattern list the hooks match is itself untracked, because tracking it would disclose what it
  protects (`tools/embargo-guard.sh:9`). Hooks are never to be bypassed (`CLAUDE.md`).
- **Coordinated disclosure, human gates.** Downloading vendor firmware and any outbound
  contact are user-confirmed steps; the tooling automates triage and drafting, never the
  judgment ([`disclosure-policy.md`](disclosure-policy.md), roadmap "Working rules").
- **Fuzz results stay local.** Crashes, corpora, `results/` and the dev signing key are
  git-ignored (`fuzz/uboot-fit/.gitignore`); under CI, `ci-replay.sh` prints only counts or the
  failing test name, never a log (`fuzz/uboot-fit/ci-replay.sh:139`).
- **Pinned and reproducible.** U-Boot is pinned by SHA-256 with a fixed build timestamp so the
  signed seed is byte-identical on every build (`fuzz/uboot-fit/pin.txt`); `ci-replay.sh`
  refuses to replay a build that does not match the pin (`fuzz/uboot-fit/ci-replay.sh:75`).
  CI actions are pinned to commit SHAs.
- **Crypto stub is opt-in and never trusted alone.** The stub lives in its own source and object
  trees so its patch never reaches the real build (`fuzz/uboot-fit/build.sh:100`); `build.sh`
  fails unless the stub build has both stub marks and the real build neither
  (`fuzz/uboot-fit/build.sh:160`), and a hit counts only once `confirm.sh`, which refuses a
  binary with either mark, reproduces it on real crypto (`fuzz/uboot-fit/confirm.sh:42`).
- **Simulation first.** The MAVLink harness only talks to localhost unless explicitly told
  otherwise, and its injected command is a benign read (`AUTOPILOT_VERSION`).
- **Rust for the signing control**, because it sits on an untrusted-bytes parser/crypto
  boundary (`tools/mavlink-signing/SPEC.md`).
- **Deterministic gate.** SVG and link checks look at tracked files only, so ignored work trees
  on a workstation do not change the result (`tools/run-checks.sh:63`).
- **Acquisition feasibility gates target choice**: run 2 stalled because patched firmware was
  ISP-gated, which drove the re-pick to DrayTek ([`track1-target-selection.md`](track1-target-selection.md)).

## Open edges

- **No new CVE yet.** Runs 1 and 3 were both deduped as n-days and run 2 is blocked at
  acquisition; the remaining Track 1 upside is the DrayTek fan-out to other models
  ([`roadmap.md`](roadmap.md) "Next").
- **Run 4 (P7.2) in progress**: hypotheses H2 and H4 are not yet tested
  (`research/uas-autonomy/`, roadmap "Next" item 1).
- **U-Boot fuzz target is Phase 0**: builds both variants and replays, exec/s measured, no
  campaign run (`fuzz/uboot-fit/README.md`, "Crypto-stub build"); older releases such
  as v2021.01 need a different entry point (`fuzz/uboot-fit/README.md`, "Notes").
- **GNSS-spoofing plan (T2)** is written but its SITL run is pending
  (`docs/track2/uas-gnss-spoofing-test-plan.md`).
- **P7.3** flight-controller teardown needs an owned board; the run 3 case study has no
  runtime proof yet (roadmap "Next" items 6 and 7).
- **Gate coverage gap**: Python and shell under `research/` are not parse-checked
  (`tools/run-checks.sh:26`, `:39`).
- **`pymavlink` is unpinned** in `tools/mavlink-sectest/requirements.txt`, so CI picks up
  whatever version is current.
- **Held writeup stub**: `research/draytek-vigor/writeup-download_ovpn.md` is the retired
  new-CVE writeup, kept as a stub after the n-day reclassification (`CLAUDE.md`).

# CLAUDE.md — working notes for this repo

Embedded/firmware security portfolio. Start with [`README.md`](README.md) for the
map, [`docs/roadmap.md`](docs/roadmap.md) for deliverable status and what is next, and
[`docs/NEXT-SESSION.md`](docs/NEXT-SESSION.md) for restart paths.

## Canonical environment: WSL (Ubuntu), not Git Bash

The tooling is Linux-native (binwalk, squashfs-tools, QEMU) and the scripts call
`python3` + `bash`. Run everything inside **WSL Ubuntu**, where the repo is at
`/mnt/c/Users/samyo/Desktop/Claude`:

```bash
wsl -e bash -lc 'cd /mnt/c/Users/samyo/Desktop/Claude && bash tools/run-checks.sh'
```

**Git Bash gotcha (Windows):** in Git Bash, `python3` resolves to the Microsoft
Store *App Execution Alias* stub, not a real interpreter — so `run-checks.sh` and
every `python3` script fail with "Python was not found". The real interpreter is
`C:\Users\samyo\AppData\Local\Programs\Python\Python312\python.exe` (invoke it as
`python`, or `py -3`). Prefer WSL; if you must use Git Bash, either call `python`
explicitly or disable the `python3` alias under Settings → Apps → Advanced app
settings → App execution aliases.

## Verification

`tools/run-checks.sh` is the deterministic gate (Python/shell parse, self-tests,
SVG/mermaid/link checks, funnel smoke test, `cargo test` for the signing crate, the
sanitize linter over `writeups/`, and `finding.json` validation). The same script runs
in CI on every pull request and on `main` (`.github/workflows/checks.yml`). The bar is
**0 failed**; the pass count is not a fixed number — steps whose toolchain is absent
(`gcc`, `cargo`) print `[skip]`, and the embargo-guard section only runs where
`drafts/private/` has content. SVG checks cover tracked files only, so git-ignored
`work/` and build trees no longer change the result. Deps (one-time, needs sudo):

```bash
sudo apt update && sudo apt install -y build-essential python3-dev python3-venv
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/mavlink-sectest/requirements.txt   # pymavlink
```

Note: on Python 3.14 there is no prebuilt `pymavlink` wheel, so pip compiles its
`dfindexer` C extension — that needs `build-essential` (provides `libc6-dev` /
`stdint.h`) and `python3-dev` (`Python.h`). `gcc` alone fails with
`fatal error: stdint.h: No such file or directory`. Re-activate the venv
(`. .venv/bin/activate`) in new shells before running the mavlink harness.

For the Track 1 firmware toolchain (binwalk, sasquatch, jefferson, ubi_reader,
QEMU), run `.claude/skills/firmware-triage/scripts/setup-tools.sh`.

## Running the pieces

```bash
# Assessment funnel (Track 3 skills)
.claude/skills/firmware-triage/scripts/triage.sh   <rootfs> triage-out/<ver>
.claude/skills/firmware-triage/scripts/sink_scan.py <rootfs> --out sinks.csv
.claude/skills/binary-diff/scripts/fw_diff.py       <old_rootfs> <new_rootfs> --out diff-out
.claude/skills/finding-to-vendor-report/scripts/make_report.py finding.json --validate
.claude/skills/finding-to-cve-writeup/scripts/make_cve.py       finding.json
.claude/skills/security-dataviz/scripts/chart.py bars --csv sinks.csv --label path --value score --out c.svg

# UAS harness (Track 1 / P5.1) — logic self-test needs no SITL
python3 tools/mavlink-sectest/mavlink_sectest.py --selftest
```

## Track 1 working state

Live research lives under `research/` (git-ignored blobs; paperwork committed) and
public writeups under `writeups/`. Four Track 1 runs so far (run 4 — the UAS / autonomy
run against the Micro-XRCE-DDS Agent — is in progress; its state is in
`docs/track1-uas-run-plan.md`, `docs/NEXT-SESSION.md` and `research/uas-autonomy/`). The
three router runs:

- **Run 1 — D-Link DIR-816L Rev B** (BE MIPS): acquired + fingerprinted; first
  cross-version candidate (`cgibin` HNAP SOAPAction command injection) **deduped as
  an n-day** — written up as a case study, not a new CVE
  (`research/dlink-rtl819x/`, `writeups/dir-816l-hnap-soapaction-cmdinjection.md`).
- **Run 2 — Zyxel CPE**: **blocked at acquisition** — 2026 patched CPE firmware is
  ISP-gated, so the fix is not provenance-acquirable to diff (`research/zyxel-cpe/`).
  This exposed the acquisition-feasibility gate that drove the run-3 re-pick.
- **Run 3 — DrayTek Vigor300B** (ARM-LE, Comcerto): confirmed at the code level, then
  **deduped as an n-day — NOT novel.** Diffing the public `1.5.1.6 → 1.5.1.7` window found
  the silent hardening of a `download_ovpn` OS command injection in `mainfunction.cgi` — an
  incomplete-blocklist sanitizer *bypass* that runs as **root** (post-auth operator/admin).
  On live re-check (2026-09-18) the endpoint proved to be **CVE-2024-45890** (DrayTek
  Vigor**3900**, `mainfunction.cgi` `action=download_ovpn`, post-auth, CVSS 8.0, pub.
  2024-11-04); the earlier "no matching CVE / novel" claim was a **dedup miss** (the check
  was scoped to the `vigor300b_firmware` list; the CVE is filed under `vigor3900_firmware`).
  The 300B is not in that CVE's CPE list, so residual value is (a) a methodology case study
  — **published** at `writeups/draytek-vigor300b-download_ovpn-cmdinjection.md` — and (b) a
  CPE coverage-gap note to DrayTek/MITRE (affected-product extension, **not** a new CVE) —
  `research/draytek-vigor/vendor-report.md` + `disclosure-email.txt`, **sent to DrayTek
  2026-09-21**. Vendor reply confirmed the 2960/300B/3900 share the 1.5.1.7 fix but declines the
  CVE edit as non-CNA → vendor-side disclosure **closed**; optional CPE correction now routes to
  MITRE (see `acquisition-log.md` §Disclosure log). The new-CVE paperwork was retired: `finding.json`
  reclassified n-day, the held writeup stubbed, the RESERVED CVE record deleted. Ghidra
  decompile+disasm evidence under git-ignored `diff-out-dt/ghidra/`. **A genuinely new CVE
  could now only come from the fan-out to a still-supported, out-of-CPE, unpatched model.**
  See `research/draytek-vigor/finding-openvpn-cmdinjection.md` and `acquisition-log.md`.

See also the target-selection dossier (`docs/track1-target-selection.md`) — it carries
the 2026-09-14 re-pick rationale (acquisition-feasibility gate → DrayTek).

## Guardrails (see [`docs/disclosure-policy.md`](docs/disclosure-policy.md))

- Unclassified, publicly-available targets only; no ITAR/EAR technical data.
- Firmware blobs are **never committed** (see `.gitignore`); record hashes in the
  acquisition log, not the binaries.
- Vulnerability work follows **coordinated disclosure**. Downloading vendor
  firmware and any outbound disclosure contact are user-confirmed steps.
- **Embargo guard.** This repository is public. Pre-disclosure drafts live under the
  git-ignored `drafts/private/`, and `tools/embargo-guard.sh` enforces that as git hooks
  (pre-commit, commit-msg, pre-push): it blocks private paths and any added line, commit
  message, or branch name matching the local, untracked `drafts/private/.embargo-patterns`.
  Install once per clone with `tools/install-hooks.sh` (re-run after the guard changes);
  audit the checkout with `tools/embargo-guard.sh scan-tree`. Never bypass with
  `--no-verify`, and never copy the patterns file into a tracked path.

## Doc-consistency note

Status lives in one place: [`docs/roadmap.md`](docs/roadmap.md). On any status change,
update it first, then the summaries that repeat it — the README "Status" section and
repository map, `docs/NEXT-SESSION.md`, and `docs/portfolio-blueprint.svg`.

The certification list appears in two places that must agree: the roadmap's competency
section and `docs/portfolio-blueprint.svg` cell 8 (`Sec+ · CASP+ · CISSP`).

**This repository is public and holds the work only.** Personal details — employment,
affiliations, eligibility, career plans, timelines, target organizations — do not belong in
any tracked file, commit message, branch name or PR text. Planning of that kind lives in
the private companion repository.

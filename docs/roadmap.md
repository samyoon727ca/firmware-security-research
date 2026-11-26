# Roadmap

Status of every deliverable in this repository, what each one evidences, and what is next.
This is the one place status is recorded; the [README](../README.md) summarizes it and
[`NEXT-SESSION.md`](NEXT-SESSION.md) holds the working restart notes.

Legend: **built** exists and is verified · **done** a run or step that was executed ·
**in progress** · **planned** · **open** not started.

## Track 1 run ledger

Every live run is recorded with its outcome, including the ones that did not produce a new finding.

| Run | Target | Outcome | Record |
|-----|--------|---------|--------|
| 1 | D-Link DIR-816L Rev B (RTL819x, MIPS-BE) | Unauthenticated HNAP `SOAPAction` command injection confirmed in Ghidra, then **deduped as an n-day** (CVE-2015-2051 class) | [writeup](../writeups/dir-816l-hnap-soapaction-cmdinjection.md) · [`research/dlink-rtl819x/`](../research/dlink-rtl819x/README.md) |
| 2 | Zyxel CPE | **Blocked at acquisition** — the patched firmware is ISP-gated, so the fix cannot be acquired with provenance and diffed | [`research/zyxel-cpe/`](../research/zyxel-cpe/README.md) |
| 3 | DrayTek Vigor300B (Comcerto, ARM-LE) | `download_ovpn` root command injection confirmed at the code level, then **deduped as an n-day** (CVE-2024-45890, filed under the sibling Vigor3900). Coverage-gap notice sent to the vendor 2026-09-21; vendor confirmed the shared fix | [writeup](../writeups/draytek-vigor300b-download_ovpn-cmdinjection.md) · [`research/draytek-vigor/`](../research/draytek-vigor/README.md) |
| 4 | UAS / autonomy: PX4, ArduPilot, Micro-XRCE-DDS Agent | Phase 0 dedup map and Phase 1 PX4 re-anchor **done**. Phase 2 **in progress**: H5 probe blocked at the publisher; H1, target B and H3 fuzzing campaigns each ended in a documented clean negative | [run plan](track1-uas-run-plan.md) · [known territory](../research/uas-autonomy/known-territory.md) |

## Deliverables

IDs are stable and are the ones other documents cite (for example "P5.1").

### Foundations and the assessment funnel

| ID | Deliverable | Status | Evidences |
|----|-------------|--------|-----------|
| P0.1 | [Disclosure policy and research scope](disclosure-policy.md) | built | Program discipline |
| P0.2 | [Target-selection dossier](track1-target-selection.md) | built | Firmware assessment; supply-chain risk |
| P0.3 | `firmware-triage` skill | built | Firmware assessment; software assurance |
| P1.1 | Firmware acquisition with hashes and SoC confirmed from the image | done (runs 1 and 3) | Firmware assessment; configuration management |
| P1.2 | Triage report per version | done (runs 1 and 3) | Firmware assessment |
| P1.3 | `binary-diff` skill | built | Software assurance; configuration management |
| P1.4 | Cross-version diff report | done (DrayTek 1.5.1.6 → 1.5.1.7 silent fix flagged) | Firmware assessment; cyber T&E |
| P2.1 | Ghidra decompilation review of top candidates | done (runs 1 and 3) | Embedded reversing |
| P2.2 | Emulation harness (QEMU / FirmAE) for a router target | open | Cyber T&E |
| P2.3 | Runtime proof of concept on an emulated or owned device | open | Assessment |
| P2.4 | `finding-to-vendor-report` skill (CVSS v3.1, vendor report, advisory form, memo) | built | Written communication |
| P2.5 | Vendor-ready report, submitted | done (DrayTek coverage-gap notice, 2026-09-21) | Assessment; communication |
| P3.1 | `finding-to-cve-writeup` skill (CVE JSON 5.1, sanitize linter) | built | Written communication |
| P3.2 | Coordinated disclosure and CVE request | open (DrayTek vendor-side disclosure closed; a CPE correction routes to MITRE) | Program discipline |
| P3.3 | Public writeups | two n-day case studies published | Assessment; communication |
| P4.1 | `security-dataviz` skill | built | Visual communication |

### Engineering documents

| ID | Deliverable | Status | Evidences |
|----|-------------|--------|-----------|
| P4.2 | [Secure boot and hardware root of trust](track2/secure-boot-root-of-trust.md) | built | Embedded hardware features; secure boot |
| P4.3 | [UAS autopilot threat model (NIST SP 800-160)](track2/uas-autopilot-threat-model.md) | built | Security architecture; requirements |
| P4.4 | [Embedded hardening writeup (800-53 / CMMC mapping)](track2/embedded-hardening-writeup.md) | built | Controls mapping; secure boot |
| P5.2 | [Milestone security architecture and anti-tamper](track2/milestone-security-architecture-and-anti-tamper.md) | built | Milestone documentation; MBSE; anti-tamper |
| P6.1 | [FPGA security reference](track2/fpga-security-reference.md) | built | Embedded hardware / FPGA features |
| P6.3 | [Leadership security brief](track2/uas-security-brief.html) | built | Briefing |

### UAS capstone and the autonomy run

| ID | Deliverable | Status | Evidences |
|----|-------------|--------|-----------|
| P5.1 | [MAVLink assessment against SITL](track2/uas-capstone-assessment.md) with [hardening](track2/uas-mavlink-hardening.md) | done (stock link 4 FAIL / 1 PASS on ArduPilot and PX4; signing clears T1/T5) | Embedded assessment; cyber T&E |
| P6.2 | [Rust MAVLink v2 signing module](../tools/mavlink-signing/SPEC.md) | built (7/7 tests, including a pymavlink interop vector) | Systems-language build; software assurance |
| P7.1 | PX4 re-anchor and CVE-2026-1579 dedup pass | done (2026-09-21) | Embedded assessment; architecture |
| P7.2 | [Micro-XRCE-DDS Agent assessment](../research/uas-autonomy/phase2-micro-xrce-dds-scope.md) | in progress (see run 4) | Embedded assessment; software assurance; cyber T&E |
| P7.3 | Flight-controller secure-boot teardown | planned (needs an owned board) | Embedded hardware; anti-tamper |
| P7.4 | [U-Boot FIT parser fuzz target](../fuzz/uboot-fit/README.md) (`fit_check_format`, pinned v2026.07 sandbox) | built (Phase 0: libFuzzer + ASan build links; dev-signed seed through `fit_config_verify`; verified-equals-booted oracle via bootm's `fit_image_load()`; CI replays the seeds and fires the oracle's test hook; n-day regressions: the oracle fires on CVE-2021-27138 at v2021.01 and on CVE-2026-46728 at its fix's parent, quiet on the fixed trees; no campaign yet) | Secure boot; software assurance; cyber T&E |
| T2 | [GNSS-spoofing test plan](track2/uas-gnss-spoofing-test-plan.md) | plan written; SITL run pending | Cyber T&E |

## Next

1. **P7.2** — the remaining hypotheses in the published sequence: H2 (fragment reassembly, which
   needs the session layer) and H4 (session and privilege logic, a stateful test rather than a
   byte fuzz).
2. **T2** — run the GNSS-spoofing matrix in SITL and fill in the results.
3. **Telemetry encryption (T4)** — put an encrypted transport between ground station and
   companion computer and re-run `mavlink-sectest` through it.
4. **P6.2 as an inline proxy** — enforce signing on the wire, proven by the harness.
5. **FPGA in simulation** — a security RTL core with known-answer tests, wired into the gate.
6. **P2.2 / P2.3** — emulate a ≤ 1.5.1.6 Vigor300B and add a runtime proof to the run 3 case study.
7. **P7.3** — hardware teardown, once a board is on the bench.

## Competency coverage

| Competency | Evidence |
|-----------|----------|
| 1. Security architecture; deriving requirements from threats | P4.3, P5.2, P5.1 |
| 2. Embedded hardware / FPGA features: secure boot, key management | P4.2, P4.4, P6.1 |
| 3. Firmware and embedded security assessment | P0.3, P1.x, P2.1, P5.1, P7.x |
| 4. USG methodology (NIST SP 800-160 / 800-53 / 800-193, CMMC, Cyber T&E) | P4.2, P4.3, P4.4, P5.1 |
| 5. Milestone documentation, MBSE, SCRM, software assurance, configuration management | P5.2, P0.2, P1.3 |
| 6. Anti-tamper process | P5.2, P4.2 (process level; no hands-on artifact) |
| 7. Briefing, visual and written | P6.3, P4.1, P2.4, P3.1, P3.3 |
| Systems-language build | P6.2 |

Certifications: Security+ and CASP+ / SecurityX (held); CISSP (in progress). The same list
appears in cell 8 of [`portfolio-blueprint.svg`](portfolio-blueprint.svg); keep the two in step.

## Working rules

- Automate the funnel (triage, diffing, drafting, charts); never automate the judgment
  (exploitation, severity calls, final report review).
- Build a skill the third time a task would otherwise be repeated by hand.
- Dedup before any novelty claim, across every sibling product that shares the codebase.
- Record negative and blocked outcomes with the same care as findings.

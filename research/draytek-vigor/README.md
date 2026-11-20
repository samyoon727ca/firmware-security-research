# Research — DrayTek Vigor (Track 1, third target)

Working area for the third Track 1 assessment — rotating to a target that clears the
**acquisition-feasibility gate** the first two runs exposed: the *patched* firmware
must be publicly downloadable to diff the fix under our provenance rule.

- D-Link (run 1): public but EOL/saturated → **n-day** case study
  ([`writeups/dir-816l-hnap-soapaction-cmdinjection.md`](../../writeups/dir-816l-hnap-soapaction-cmdinjection.md)).
- Zyxel (run 2): fresh but recent CPE firmware is **ISP-gated** → 2026 fix not
  acquirable, blocked at acquisition ([`../zyxel-cpe/`](../zyxel-cpe/)).
- **DrayTek (run 3): fresh + fully public archive + active CNA + less-swarmed.**

**Paperwork only is tracked here** (acquisition log, hashes, notes). Firmware blobs
and extracted filesystems are git-ignored and never committed.

- Target rationale: [`docs/track1-target-selection.md`](../../docs/track1-target-selection.md)
  — see the 2026-09-14 re-pick (acquisition-feasibility gate → DrayTek).
- Procedure: [`docs/track1-acquisition-runbook.md`](../../docs/track1-acquisition-runbook.md)
  — the funnel is vendor-agnostic; the *extract* step is re-fingerprinted per target
  (DrayTek packaging differs from D-Link's SEAMA/squashfs-LZMA).
- Objective (going in): a **novel** finding with a real CVE (DrayTek is an active CNA;
  coordinated disclosure per [`docs/disclosure-policy.md`](../../docs/disclosure-policy.md)).
  **Outcome:** the `download_ovpn` finding was confirmed at the code level but **deduped as an
  n-day (CVE-2024-45890)** on live re-check — a methodology case study, not a new CVE. A new
  CVE now depends on the model fan-out. See [`finding-openvpn-cmdinjection.md`](finding-openvpn-cmdinjection.md).
- Plan + diff strategy: [`target-notes.md`](target-notes.md).

Working dirs created at runtime (ignored): `work/`, `triage-out/`, `diff-out/`.

## Variant tracing from the sanitizer

[`ghidra/trace_sanitizer_sinks.java`](ghidra/trace_sanitizer_sinks.java) is a headless
Ghidra script that starts at the bypassable sanitizer (`FUN_0000ad8c` @ `0xad8c` in
`mainfunction.cgi`) and follows its callers out to `system()`/`popen()` sinks. A patch
diff only shows the sites the vendor already fixed; searching outward from the sanitizer
also finds the call sites the patch did *not* touch.

```bash
<ghidra>/support/analyzeHeadless <project_dir> vigor_trace \
  -import <rootfs>/…/mainfunction.cgi \
  -processor "ARM:LE:32:v7" \
  -scriptPath research/draytek-vigor/ghidra \
  -postScript trace_sanitizer_sinks.java drafts/private/draytek-vigor/trace.json 0xad8c 2 json \
  -deleteProject
```

To re-run on a binary already in the project, replace `-import <path>` with
`-process mainfunction.cgi` (and drop `-deleteProject` if you want to keep it).

Arguments (positional, in this order):

| # | Argument | Default | Meaning |
|---|---|---|---|
| 1 | `output_file` | **required** | Where to write results. If missing or empty, the script prints usage and writes nothing. It warns (but still writes) if the path is not under a `drafts/private/` directory. |
| 2 | `sanitizer_hex` | `0xad8c` | Sanitizer entry address; an empty arg keeps the default. |
| 3 | `depth` | `2` | Callee levels to follow from each caller (caller = level 0; `>= 0`). |
| 4 | `format` | `json` | `json` (array of objects) or `csv` (one row per site; list fields joined by `;`, an action written as `name\|handler\|prolog\|login_level`). |

Output: one record per sink call site.

| Field | Meaning |
|---|---|
| `sanitizer` | Sanitizer entry address |
| `caller_fn` | Sanitizer caller reaching the site in the fewest levels (`name@entry`); any other callers go in `note` |
| `sink_fn` | Function containing the sink call (`name@entry`) |
| `sink_addr` | Address of the call instruction |
| `sink` | `system`, `popen`, or the wrapper function's name |
| `format` | Recovered command format string, or `null` |
| `percent_s_count` | Number of `%s` conversions in `format` (`null` if `format` is `null`) |
| `quoting` | List of `single`\|`double`\|`unquoted`, one per `%s`, in order |
| `any_unquoted` | `true` if any `%s` is unquoted (`null` if `format` is `null`) |
| `actions` | List of `{name, handler, prolog, login_level}` for CGI actions whose handler reaches the site (`login_level` is always `null`; the prolog address is reported instead) |
| `note` | Recovery notes / additional callers, or `null` |

The console prints only a one-line summary (site count + output path).

**Embargo.** Results are pre-disclosure material. Write them only under the git-ignored
`drafts/private/` and never commit them, per
[`docs/disclosure-policy.md`](../../docs/disclosure-policy.md).

**Validation.** The known positive is the already-public CVE-2024-45890 `download_ovpn`
site ([`finding-openvpn-cmdinjection.md`](finding-openvpn-cmdinjection.md)): it should
report as unquoted in 1.5.1.6 and as quoted in 1.5.1.7.

#!/usr/bin/env python3
"""Assemble a vendor-ready vulnerability report from a finding's evidence.

Reads a finding JSON (see templates/finding.json), computes the CVSS v3.1 score
from its vector, and fills the report template. Automates the *drafting*; the
analyst still writes the technical description / impact narrative and reviews the
final report before sending. No third-party deps.

Usage:
    make_report.py finding.json [--template templates/vendor-report.md] [--out report.md]
    make_report.py finding.json --validate
    make_report.py finding.json --memo [--to "<recipient>"] [--draft] [--out memo.md]
    make_report.py finding.json --advisory [--out advisory.md]

--advisory renders templates/github-advisory.md: one paste-ready value per field of
GitHub's "Report a vulnerability" form (title, summary, details, proof of concept,
impact, affected products, CVSS vector, CWEs, AI-assistance box). It reads the optional
`advisory` block of the finding and falls back to the report fields.

--memo renders the one-page disclosure memo (templates/disclosure-memo.md) that goes to
the affected party once the submission has been validated: summary, steps to reproduce
and the proof of concept (embedded from the file named in the finding's `poc.file`).
It refuses to render until `disclosure.validated` holds the validation date; --draft
overrides that and stamps the memo as an unvalidated draft.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cvss  # noqa: E402  (sibling module)

CWE = {
    "CWE-77": "Command Injection", "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting", "CWE-22": "Path Traversal",
    "CWE-119": "Improper Restriction of Operations within Memory Buffer",
    "CWE-120": "Classic Buffer Overflow", "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow", "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write", "CWE-134": "Uncontrolled Format String",
    "CWE-190": "Integer Overflow or Wraparound", "CWE-306": "Missing Authentication",
    "CWE-798": "Use of Hard-coded Credentials", "CWE-259": "Use of Hard-coded Password",
    "CWE-321": "Use of Hard-coded Cryptographic Key", "CWE-311": "Missing Encryption",
    "CWE-352": "Cross-Site Request Forgery", "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference", "CWE-284": "Improper Access Control",
    "CWE-863": "Incorrect Authorization", "CWE-89": "SQL Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-248": "Uncaught Exception", "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free", "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
}
FENCE_LANG = {".py": "python", ".sh": "bash", ".c": "c", ".cpp": "cpp", ".js": "javascript",
              ".rb": "ruby", ".go": "go", ".rs": "rust", ".http": "http", ".txt": "text"}
REQUIRED = ["title", "vendor", "researcher", "products", "cwe", "vuln_type",
            "component", "cvss_v31_vector", "description", "repro_steps",
            "impact", "remediation"]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate(f):
    errs, warns = [], []
    for k in REQUIRED:
        if not f.get(k):
            errs.append(f"missing required field: {k}")
    cwe = f.get("cwe", "")
    if cwe and cwe not in CWE:
        warns.append(f"CWE {cwe} not in local name map (add it, or verify at cwe.mitre.org)")
    vec = f.get("cvss_v31_vector", "")
    if vec:
        try:
            cvss.score(vec)
        except ValueError as e:
            errs.append(f"invalid CVSS vector: {e}")
    prods = f.get("products", [])
    for i, p in enumerate(prods):
        if not p.get("model") or not p.get("affected_versions"):
            warns.append(f"product[{i}] missing model or affected_versions")
    return errs, warns


def products_table(prods):
    rows = ["| Model | HW rev | Affected versions | Fixed in | Firmware SHA-256 |",
            "|-------|--------|-------------------|----------|------------------|"]
    for p in prods:
        rows.append("| {model} | {hw_rev} | {affected_versions} | {fixed_version} | {sha256} |".format(
            model=p.get("model", ""), hw_rev=p.get("hw_rev", ""),
            affected_versions=p.get("affected_versions", ""),
            fixed_version=p.get("fixed_version", "") or "(unpatched)",
            sha256=p.get("sha256", "") or ""))
    return "\n".join(rows)


def numbered(steps):
    return "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))


def affected_list(prods):
    rows = []
    for p in prods:
        fixed = p.get("fixed_version", "") or "no fixed release yet"
        rows.append(f"- **{p.get('model', '')}** — {p.get('affected_versions', '')} (fixed in: {fixed})")
    return "\n".join(rows)


def poc_block(poc, base_dir):
    """Markdown for the proof of concept: run line, embedded source, expected result."""
    if not poc:
        return "_No proof-of-concept file is attached to this finding (`poc.file` is not set)._"
    parts = []
    if poc.get("run"):
        parts.append("Run:\n\n```bash\n" + poc["run"] + "\n```")
    name = poc.get("file", "")
    if name:
        path = name if os.path.isabs(name) else os.path.join(base_dir, name)
        with open(path, encoding="utf-8") as src:
            code = src.read().rstrip("\n")
        lang = FENCE_LANG.get(os.path.splitext(name)[1].lower(), "")
        parts.append(f"`{os.path.basename(name)}`:\n\n```{lang}\n{code}\n```")
    if poc.get("expected"):
        parts.append("Expected result: " + poc["expected"])
    return "\n\n".join(parts)


def advisory_values(f, base_dir, steps_md, poc_md):
    """Values for templates/github-advisory.md (GitHub 'Report a vulnerability' form)."""
    adv = f.get("advisory", {})
    prods = f.get("products", [])
    first = prods[0] if prods else {}

    details = adv.get("details", "") or f.get("description", "")
    fix = adv.get("fix", "") or f.get("remediation", "")
    if fix:
        details += "\n\n**Suggested fix:** " + fix
    patch = adv.get("patch_file", "")
    if patch:
        path = patch if os.path.isabs(patch) else os.path.join(base_dir, patch)
        with open(path, encoding="utf-8") as src:
            details += "\n\n```diff\n" + src.read().rstrip("\n") + "\n```"

    poc = "**Setup:** " + (adv.get("setup", "") or f.get("preconditions", ""))
    poc += "\n\n" + steps_md + "\n\n" + poc_md

    cwes = adv.get("cwes") or ([f["cwe"]] if f.get("cwe") else [])
    cwe_rows = "\n".join(f"- `{c}` — {CWE.get(c, '(look up the name in the CWE search box)')}" for c in cwes)

    ai = adv.get("ai_assistance")
    if ai is None:
        ai_md = ("_Not recorded in the finding (`advisory.ai_assistance`). Tick the box if any AI tool "
                 "helped find or write up the report._")
    elif ai:
        ai_md = "**Tick the box.**" + (" " + adv["ai_note"] if adv.get("ai_note") else "")
    else:
        ai_md = "Leave unticked."

    banner = ""
    if not f.get("disclosure", {}).get("reproduced_by_reporter"):
        banner = ("> **Before submitting:** reproduce the issue yourself against the affected version and "
                  "read every field — the reporter is responsible for the content. Then set "
                  "`disclosure.reproduced_by_reporter` to the date to clear this notice.\n\n")
    return {
        "advisory_title": adv.get("title", "") or f.get("title", ""),
        "advisory_details_md": details,
        "advisory_poc_md": poc,
        "advisory_impact": adv.get("impact", "") or f.get("impact", ""),
        "advisory_ecosystem": adv.get("ecosystem", "") or "Other",
        "advisory_package": adv.get("package", "") or first.get("model", ""),
        "advisory_affected": adv.get("affected_range", "") or first.get("affected_versions", ""),
        "advisory_patched": ("`" + adv["patched"] + "`") if adv.get("patched") else "_leave empty — no patched release yet_",
        "advisory_cwes_md": cwe_rows or "_none selected_",
        "advisory_ai": ai_md,
        "advisory_banner": banner,
    }


def render(f, base_dir=".", recipient="", draft=False):
    cv = cvss.score(f["cvss_v31_vector"])
    steps = f.get("repro_steps", [])
    repro_md = numbered(steps)
    disc = f.get("disclosure", {})
    poc = f.get("poc", {})
    tracking = " · ".join(x for x in (disc.get("advisory_id", ""), disc.get("cve_id", "")) if x)
    vals = {
        "title": f.get("title", ""),
        "vendor": f.get("vendor", ""),
        "researcher": f.get("researcher", ""),
        "contact": f.get("contact", ""),
        "products_table": products_table(f.get("products", [])),
        "cwe": f.get("cwe", ""),
        "cwe_name": CWE.get(f.get("cwe", ""), ""),
        "vuln_type": f.get("vuln_type", ""),
        "component": f.get("component", ""),
        "preconditions": f.get("preconditions", ""),
        "cvss_vector": cv["vector"],
        "cvss_score": f"{cv['base_score']}",
        "cvss_severity": cv["severity"],
        "description": f.get("description", ""),
        "repro_steps_md": repro_md,
        "impact": f.get("impact", ""),
        "remediation": f.get("remediation", ""),
        "discovery_method": f.get("discovery_method", ""),
        "reported_date": disc.get("reported", ""),
        "target_public": disc.get("target_public", "90 days from report"),
        # --- disclosure memo ---
        "recipient": recipient or f"{f.get('vendor', '')} security team",
        "summary": f.get("summary", "") or f.get("description", ""),
        "affected_md": affected_list(f.get("products", [])),
        "memo_steps_md": numbered(poc.get("steps") or steps),
        "poc_md": poc_block(poc, base_dir),
        "tracking": tracking or "identifier pending",
        "validated_date": disc.get("validated", "") or "NOT VALIDATED",
        "memo_banner": ("> **DRAFT — the submission has not been validated. Do not send.**\n\n"
                        if draft else ""),
    }
    vals.update(advisory_values(f, base_dir, vals["memo_steps_md"], vals["poc_md"]))
    return vals


def fill(template, vals):
    missing = set()

    def sub(m):
        key = m.group(1).strip()
        if key in vals:
            return str(vals[key])
        missing.add(key)
        return m.group(0)

    out = re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", sub, template)
    return out, missing


def main():
    ap = argparse.ArgumentParser(description="Assemble a vendor vulnerability report from a finding JSON.")
    ap.add_argument("finding")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--template", default=os.path.join(here, "..", "templates", "vendor-report.md"))
    ap.add_argument("--out", default="")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--memo", action="store_true",
                    help="render the one-page disclosure memo (needs disclosure.validated)")
    ap.add_argument("--to", default="", help="memo recipient (default: '<vendor> security team')")
    ap.add_argument("--draft", action="store_true",
                    help="with --memo: render before validation, stamped as a draft")
    ap.add_argument("--advisory", action="store_true",
                    help="render the field-by-field input for GitHub's 'Report a vulnerability' form")
    args = ap.parse_args()
    if args.memo and args.advisory:
        ap.error("--memo and --advisory are separate documents; render them one at a time")
    if args.memo:
        args.template = os.path.join(here, "..", "templates", "disclosure-memo.md")
    if args.advisory:
        args.template = os.path.join(here, "..", "templates", "github-advisory.md")

    f = load(args.finding)
    errs, warns = validate(f)
    for w in warns:
        print(f"[warn] {w}", file=sys.stderr)
    if errs:
        for e in errs:
            print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)
    if args.validate:
        print("[validate] finding OK", file=sys.stderr)
        return

    if args.memo:
        if not f.get("poc", {}).get("file"):
            print("[warn] finding has no poc.file; the memo will carry no proof of concept", file=sys.stderr)
        validated = f.get("disclosure", {}).get("validated", "")
        if not validated and not args.draft:
            print("[error] disclosure.validated is empty: the memo ships only after the submission is "
                  "validated. Set the date, or pass --draft for a stamped preview.", file=sys.stderr)
            sys.exit(1)
        if validated and args.draft:
            print("[warn] --draft given but disclosure.validated is set; rendering as a draft anyway",
                  file=sys.stderr)

    with open(args.template, encoding="utf-8") as t:
        template = t.read()
    vals = render(f, base_dir=os.path.dirname(os.path.abspath(args.finding)),
                  recipient=args.to, draft=args.draft)
    out, missing = fill(template, vals)
    for k in sorted(missing):
        print(f"[warn] template placeholder not provided: {{{{{k}}}}}", file=sys.stderr)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as o:
            o.write(out)
        print(f"[make_report] wrote {args.out}  (CVSS {vals['cvss_score']} {vals['cvss_severity']})",
              file=sys.stderr)
    else:
        sys.stdout.buffer.write(out.encode("utf-8"))


if __name__ == "__main__":
    main()

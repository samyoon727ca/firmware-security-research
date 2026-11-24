#!/usr/bin/env bash
# Repository verification: lints, skill/tool self-tests, SVG + mermaid validation,
# internal-link check, and a funnel smoke test. Deterministic; safe to run in CI.
# Usage: tools/run-checks.sh   (run from repo root)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0; pass=0
ok(){ pass=$((pass+1)); printf '  [ok]   %s\n' "$*"; }
bad(){ fail=$((fail+1)); printf '  [FAIL] %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# Use the project virtualenv if present, so python-based self-tests run against
# the provisioned deps (e.g. the mavlink harness needs pymavlink) instead of a
# bare system python3. Safe no-op when .venv is absent (e.g. minimal CI) or when
# already inside a venv. set +u around the source: activate scripts predate the
# nounset guard this script runs under.
if [ -z "${VIRTUAL_ENV:-}" ] && [ -f .venv/bin/activate ]; then
  set +u; . .venv/bin/activate; set -u
  echo "[info] activated .venv ($(python3 -V 2>&1))"
fi

echo "== 1. Python parses =="
while IFS= read -r f; do
  if python3 -c "import ast,sys; ast.parse(open('$f').read())" 2>/dev/null; then ok "$f"; else bad "parse $f"; fi
done < <(find .claude tools -name '*.py' | sort)

echo "== 2. Shell syntax =="
# fuzz/ scripts from tracked files only: a local fuzz/uboot-fit/build.sh run
# unpacks the whole U-Boot source (with its own *.sh) into git-ignored build/.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  fuzz_sh="$(git ls-files 'fuzz/*.sh')"
else
  fuzz_sh="$(find fuzz -name '*.sh' -not -path '*/build/*')"
fi
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if bash -n "$f" 2>/dev/null; then ok "$f"; else bad "bash -n $f"; fi
done < <({ find .claude tools -name '*.sh'; printf '%s\n' "$fuzz_sh"; } | sort)

echo "== 3. Self-tests =="
if python3 .claude/skills/finding-to-vendor-report/scripts/cvss.py --selftest >/dev/null 2>&1; then ok "cvss.py --selftest"; else bad "cvss.py --selftest"; fi
# Outside CI, a missing pymavlink skips only the roundtrip (the selftest prints
# a [SKIP] line); the offline logic checks still decide the result.
if mav_out="$(python3 tools/mavlink-sectest/mavlink_sectest.py --selftest 2>&1)"; then
  ok "mavlink_sectest.py --selftest"
  if printf '%s\n' "$mav_out" | grep -q '\[SKIP\] pymavlink roundtrip'; then
    echo "  [skip] mavlink_sectest.py pymavlink roundtrip: pymavlink not installed and \$CI unset"
  fi
else
  bad "mavlink_sectest.py --selftest"
fi
# With pymavlink made unimportable, the selftest must fail under CI=true and pass without CI.
mav_noimport='import runpy,sys; sys.modules["pymavlink"]=None; sys.argv=["mavlink_sectest.py","--selftest"]; runpy.run_path("tools/mavlink-sectest/mavlink_sectest.py",run_name="__main__")'
if ! CI=true python3 -c "$mav_noimport" >/dev/null 2>&1 && (unset CI; python3 -c "$mav_noimport" >/dev/null 2>&1); then
  ok "mavlink selftest: missing pymavlink fails under CI, skips outside"
else
  bad "mavlink selftest: missing pymavlink fails under CI, skips outside"
fi
if sh tools/embargo-guard.sh selftest >/dev/null 2>&1; then ok "embargo-guard.sh selftest"; else bad "embargo-guard.sh selftest"; fi

echo "== 4. SVG well-formed =="
# Tracked SVGs only, so the result is the same on a clean checkout and on a
# workstation whose git-ignored work/ and build/ trees hold third-party SVGs.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  svgs="$(git ls-files '*.svg' | sort)"
else
  svgs="$(find . -name '*.svg' -not -path './.git/*' | sort)"
fi
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if python3 -c "import xml.dom.minidom;xml.dom.minidom.parse('$f')" 2>/dev/null; then ok "$f"; else bad "xml $f"; fi
done <<< "$svgs"

echo "== 5. Mermaid blocks balanced =="
python3 - <<'PY' && ok "mermaid blocks" || bad "mermaid blocks"
import re,glob,sys
bad=0
for f in glob.glob("docs/**/*.md",recursive=True):
    for i,b in enumerate(re.findall(r"```mermaid\n(.*?)```",open(f).read(),re.S),1):
        head=b.strip().split()[0]
        bal=(b.count("[")-b.count("]"),b.count("(")-b.count(")"),b.count('"')%2,b.count("{")-b.count("}"))
        if head not in("flowchart","graph","stateDiagram-v2","sequenceDiagram","timeline") or bal!=(0,0,0,0):
            print(f"    bad mermaid in {f} #{i}: head={head} bal={bal}");bad+=1
sys.exit(1 if bad else 0)
PY

echo "== 6. Internal doc links resolve =="
python3 - <<'PY' && ok "internal links" || bad "internal links"
import re,glob,os,subprocess,sys
missing=0
# Tracked + untracked-but-unignored docs only: git-ignored trees (drafts/private/,
# work/, build dirs) are not part of the repo and must not change the result.
try:
    files=subprocess.run(["git","ls-files","--cached","--others","--exclude-standard","--","*.md"],
                         capture_output=True,text=True,check=True).stdout.splitlines()
except Exception:
    files=[f for f in glob.glob("**/*.md",recursive=True) if ".git/" not in f]
for f in files:
    if not os.path.exists(f): continue
    if "/templates/" in f: continue   # fill-in skeletons: their links name files the user generates
    base=os.path.dirname(f)
    for m in re.findall(r"\]\(([^)]+)\)",open(f).read()):
        link=m.split("#")[0]
        if not link or link.startswith(("http://","https://","mailto:")): continue
        tgt=os.path.normpath(os.path.join(base,link))
        if not os.path.exists(tgt):
            print(f"    {f}: missing -> {link}");missing+=1
sys.exit(1 if missing else 0)
PY

echo "== 7. Funnel smoke test =="
if have gcc; then
  T="$(mktemp -d)"; RF="$T/rootfs"; mkdir -p "$RF/bin" "$RF/www/cgi-bin" "$RF/etc"
  printf '#include <string.h>\n#include <stdlib.h>\nint main(int c,char**v){char b[8];strcpy(b,v[1]);system(b);return 0;}\n' > "$T/v.c"
  gcc -w -o "$RF/bin/httpd" "$T/v.c" 2>/dev/null
  printf '#!/bin/sh\nsystem("ping $QUERY_STRING")\n' > "$RF/www/cgi-bin/p.cgi"
  printf 'admin:x:0:0::/:/bin/sh\n' > "$RF/etc/passwd"
  bash .claude/skills/firmware-triage/scripts/triage.sh "$RF" "$T/out" >/dev/null 2>&1 \
    && [ -f "$T/out/inventory.txt" ] && ok "triage.sh" || bad "triage.sh"
  # sink_scan.py only scans ELF binaries. A host compiler that writes another
  # format (macOS clang -> Mach-O) can't exercise the httpd assertion, so skip it
  # there with a reason; the CSV is still produced for chart.py below.
  # A missing binary (compile failure) takes the ELF branch and fails as before.
  if [ ! -f "$RF/bin/httpd" ] || [ "$(head -c 4 "$RF/bin/httpd" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; then
    python3 .claude/skills/firmware-triage/scripts/sink_scan.py "$RF" --out "$T/sinks.csv" >/dev/null 2>&1 \
      && grep -q httpd "$T/sinks.csv" && ok "sink_scan.py" || bad "sink_scan.py"
  else
    python3 .claude/skills/firmware-triage/scripts/sink_scan.py "$RF" --out "$T/sinks.csv" >/dev/null 2>&1
    echo "  [skip] sink_scan.py: host gcc did not produce an ELF test httpd; ELF sink scan not exercised (CI runs it)"
  fi
  cp -r "$RF" "$T/rootfs2"; printf '#!/bin/sh\nsafe_ping "$QUERY_STRING"\n' > "$T/rootfs2/www/cgi-bin/p.cgi"
  python3 .claude/skills/binary-diff/scripts/fw_diff.py "$RF" "$T/rootfs2" --out "$T/diff" >/dev/null 2>&1 \
    && [ -f "$T/diff/diff-candidates.csv" ] && ok "fw_diff.py" || bad "fw_diff.py"
  python3 .claude/skills/security-dataviz/scripts/chart.py bars --csv "$T/sinks.csv" \
    --label path --value score --out "$T/c.svg" >/dev/null 2>&1 \
    && python3 -c "import xml.dom.minidom;xml.dom.minidom.parse('$T/c.svg')" && ok "chart.py" || bad "chart.py"
  rm -rf "$T"
else
  echo "  [skip] gcc absent; funnel ELF smoke test skipped (selftests already cover logic)"
fi
FIND=.claude/skills/finding-to-vendor-report/templates/finding.json
python3 .claude/skills/finding-to-vendor-report/scripts/make_report.py "$FIND" --validate >/dev/null 2>&1 && ok "make_report --validate" || bad "make_report --validate"
python3 .claude/skills/finding-to-cve-writeup/scripts/make_cve.py "$FIND" >/dev/null 2>&1 && ok "make_cve" || bad "make_cve"
python3 .claude/skills/security-dataviz/scripts/diagram.py taint a b c >/dev/null 2>&1 && ok "diagram.py taint" || bad "diagram.py taint"

echo "== 8. Rust crate (mavlink-signing) =="
if have cargo; then
  cargo test --quiet --manifest-path tools/mavlink-signing/Cargo.toml >/dev/null 2>&1 \
    && ok "cargo test (mavlink-signing)" || bad "cargo test (mavlink-signing)"
else
  echo "  [skip] cargo absent; mavlink-signing tests not run"
fi

echo "== 9. Published writeups + finding records =="
for f in writeups/*.md; do
  [ -f "$f" ] || continue
  python3 .claude/skills/finding-to-cve-writeup/scripts/sanitize_check.py "$f" >/dev/null 2>&1 \
    && ok "sanitize_check $f" || bad "sanitize_check $f"
done
for f in research/*/finding.json; do
  [ -f "$f" ] || continue
  python3 .claude/skills/finding-to-vendor-report/scripts/make_report.py "$f" --validate >/dev/null 2>&1 \
    && ok "make_report --validate $f" || bad "make_report --validate $f"
done

echo "== 10. Embargo guard (local only) =="
# Applies only where pre-disclosure drafts exist (drafts/private/ in the main
# checkout). A clean checkout / CI has none, so both checks are skipped there.
MAIN="$(cd "$(git rev-parse --git-common-dir 2>/dev/null)/.." 2>/dev/null && pwd)"
if [ -n "$MAIN" ] && [ -n "$(find "$MAIN/drafts/private" -type f -not -path '*/.git/*' 2>/dev/null | head -n 1)" ]; then
  HOOKS="$(git rev-parse --git-common-dir)/hooks"
  if cmp -s tools/embargo-guard.sh "$HOOKS/embargo-guard" \
     && grep -q embargo-guard "$HOOKS/pre-commit" "$HOOKS/commit-msg" "$HOOKS/pre-push" 2>/dev/null; then
    ok "embargo hooks installed and current"
  else
    bad "embargo hooks missing or stale (run tools/install-hooks.sh)"
  fi
  if [ -f "$MAIN/drafts/private/.embargo-patterns" ]; then
    sh tools/embargo-guard.sh scan-tree >/dev/null 2>&1 && ok "no embargoed pattern in tracked/unignored files" \
      || bad "embargoed pattern in tracked/unignored files (run tools/embargo-guard.sh scan-tree)"
  else
    bad "drafts/private/ has files but no .embargo-patterns"
  fi
else
  echo "  [skip] no drafts/private/ content; nothing to guard"
fi

echo
echo "==== $pass passed, $fail failed ===="
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)

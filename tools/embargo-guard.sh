#!/bin/sh
# Embargo guard — enforces docs/disclosure-policy.md §3 mechanically.
#
# Blocks a commit or push that would put pre-disclosure material into this
# (public) repository: anything under drafts/private/, any *.private.md /
# *.embargoed.md file, and any added line, commit message, or branch name that
# matches a pattern in the local, git-ignored patterns file.
#
# The patterns file is NOT tracked (it would disclose what it protects). It is
# looked up at, in order:
#   $EMBARGO_PATTERNS
#   <this worktree>/drafts/private/.embargo-patterns
#   <main checkout>/drafts/private/.embargo-patterns
# One extended regex per line, matched case-insensitively; '#' starts a comment.
# With no patterns file the content scan is skipped (the path rules still apply),
# so a fresh clone and CI are unaffected.
#
# Modes (the git hooks call the first three; install with tools/install-hooks.sh):
#   pre-commit            scan staged paths + added lines
#   commit-msg <file>     scan the commit message
#   pre-push <remote> <url>   scan every commit being pushed (stdin: git's ref lines)
#   scan-tree             scan all tracked + untracked-unignored files (audit)
#   status                show whether patterns and hooks are in place
#   selftest              verify the matcher (no git needed)
set -u

PATH_RX='(^|/)drafts/private/|\.private\.md$|\.embargoed\.md$'
ZERO=0000000000000000000000000000000000000000
TMP=""

say() { printf 'embargo-guard: %s\n' "$*" >&2; }
cleanup() { [ -n "$TMP" ] && rm -f "$TMP"; }
trap cleanup EXIT

main_root() {
  c="$(git rev-parse --git-common-dir 2>/dev/null)" || return 1
  (cd "$c/.." 2>/dev/null && pwd)
}

patterns_file() {
  if [ -n "${EMBARGO_PATTERNS:-}" ]; then printf '%s\n' "$EMBARGO_PATTERNS"; return 0; fi
  top="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  for r in "$top" "$(main_root 2>/dev/null || true)"; do
    [ -n "$r" ] && [ -f "$r/drafts/private/.embargo-patterns" ] && {
      printf '%s\n' "$r/drafts/private/.embargo-patterns"; return 0; }
  done
  return 1
}

# Compile the patterns file into $TMP (comments, blanks and CRs stripped).
# Returns 1 when there is nothing to match against.
load_patterns() {
  pf="$(patterns_file)" || return 1
  [ -f "$pf" ] || return 1
  TMP="$(mktemp)" || return 1
  tr -d '\r' < "$pf" | grep -v -E '^[[:space:]]*(#|$)' > "$TMP" || true
  [ -s "$TMP" ]
}

# scan <label>: read text on stdin; return 1 (and show the hits) if any pattern matches.
scan() {
  [ -n "$TMP" ] && [ -s "$TMP" ] || { cat > /dev/null; return 0; }
  hits="$(grep -n -i -E -f "$TMP" 2>/dev/null | head -n 10)"
  [ -z "$hits" ] && return 0
  say "BLOCKED — embargoed pattern in $1:"
  printf '%s\n' "$hits" | cut -c1-160 | sed 's/^/    /' >&2
  return 1
}

# check_paths <label>: read file paths on stdin; return 1 if any is embargo-only.
check_paths() {
  bad="$(grep -E "$PATH_RX" | sort -u | head -n 10)"
  [ -z "$bad" ] && return 0
  say "BLOCKED — private path in $1:"
  printf '%s\n' "$bad" | sed 's/^/    /' >&2
  return 1
}

warn_if_unguarded() {
  r="$(main_root 2>/dev/null || true)"
  if [ -n "$r" ] && [ -d "$r/drafts/private" ] && \
     [ -n "$(find "$r/drafts/private" -type f -not -path '*/.git/*' 2>/dev/null | head -n 1)" ]; then
    say "warning: drafts/private/ has files but no .embargo-patterns — content scan is OFF"
  fi
}

blocked() {
  say "Nothing was changed. Remove the embargoed material and retry."
  say "Do not bypass with --no-verify while an embargo is running."
  exit 1
}

mode="${1:-}"
[ $# -gt 0 ] && shift

case "$mode" in
  pre-commit)
    load_patterns || warn_if_unguarded
    rc=0
    git diff --cached --name-only --diff-filter=ACMR | check_paths "staged files" || rc=1
    git diff --cached --no-color -U0 --diff-filter=ACMR | grep '^+' | scan "staged changes" || rc=1
    [ "$rc" -eq 0 ] || blocked
    ;;

  commit-msg)
    load_patterns || true
    grep -v '^#' "$1" | scan "the commit message" || blocked
    ;;

  pre-push)
    remote="${1:-origin}"
    load_patterns || warn_if_unguarded
    rc=0
    while read -r local_ref local_sha remote_ref remote_sha; do
      [ "$local_sha" = "$ZERO" ] && continue            # branch deletion
      printf '%s\n' "$remote_ref" | scan "the branch name" || rc=1
      if [ "$remote_sha" != "$ZERO" ] && git cat-file -e "$remote_sha^{commit}" 2>/dev/null; then
        range="$remote_sha..$local_sha"
        set -- "$range"
      else
        set -- "$local_sha" --not "--remotes=$remote"
      fi
      git log --format= --name-only --diff-filter=ACMR "$@" | check_paths "commits pushed to $remote_ref" || rc=1
      git log --format=%B "$@" | scan "a commit message pushed to $remote_ref" || rc=1
      git log --format= -p -U0 --no-color "$@" | grep '^+' | scan "commits pushed to $remote_ref" || rc=1
    done
    [ "$rc" -eq 0 ] || blocked
    ;;

  scan-tree)
    load_patterns || { say "no patterns file — nothing to scan against"; exit 0; }
    rc=0
    git ls-files --cached --others --exclude-standard | check_paths "the working tree" || rc=1
    hits="$(git grep --untracked -n -I -i -E -f "$TMP" -- . 2>/dev/null | head -n 20)"
    if [ -n "$hits" ]; then
      say "BLOCKED — embargoed pattern in tracked/unignored files:"
      printf '%s\n' "$hits" | cut -c1-160 | sed 's/^/    /' >&2
      rc=1
    fi
    [ "$rc" -eq 0 ] && say "working tree clean"
    exit "$rc"
    ;;

  status)
    if pf="$(patterns_file)"; then
      load_patterns && n="$(wc -l < "$TMP" | tr -d ' ')" || n=0
      say "patterns: $n active ($pf)"
    else
      say "patterns: none found (content scan off)"; warn_if_unguarded
    fi
    h="$(git rev-parse --git-common-dir 2>/dev/null)/hooks"
    for k in pre-commit commit-msg pre-push; do
      if [ -f "$h/$k" ] && grep -q 'embargo-guard' "$h/$k"; then say "hook $k: installed"
      else say "hook $k: MISSING (run tools/install-hooks.sh)"; fi
    done
    ;;

  selftest)
    d="$(mktemp -d)" || exit 1
    printf '# comment line\r\n\r\nZZ-CANARY-[0-9]+\r\nsecond pattern\n' > "$d/p"
    EMBARGO_PATTERNS="$d/p"; export EMBARGO_PATTERNS
    fail=0
    load_patterns || { say "selftest: patterns did not load"; fail=1; }
    [ "$(wc -l < "$TMP" | tr -d ' ')" = 2 ] || { say "selftest: comment/blank stripping wrong"; fail=1; }
    printf 'a line\nhas zz-canary-42 in it\n' | scan "selftest (expected hit)" 2>/dev/null && { say "selftest: missed a match"; fail=1; }
    printf 'nothing to see\n# comment line\n' | scan "selftest" || { say "selftest: false positive"; fail=1; }
    printf 'docs/a.md\ndrafts/private/x/f1.md\n' | check_paths "selftest" 2>/dev/null && { say "selftest: missed a private path"; fail=1; }
    printf 'notes.embargoed.md\n' | check_paths "selftest" 2>/dev/null && { say "selftest: missed *.embargoed.md"; fail=1; }
    printf 'docs/a.md\nresearch/private-notes.md\n' | check_paths "selftest" || { say "selftest: path false positive"; fail=1; }
    rm -rf "$d"
    [ "$fail" -eq 0 ] && echo "embargo-guard selftest: OK"
    exit "$fail"
    ;;

  *)
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
exit 0

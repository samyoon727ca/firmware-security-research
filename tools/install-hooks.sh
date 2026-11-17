#!/usr/bin/env bash
# Install the embargo guard as local git hooks (pre-commit, commit-msg, pre-push).
#
# The guard is COPIED into .git/hooks/ rather than referenced from the working
# tree, so it keeps running on branches that predate tools/embargo-guard.sh.
# Re-run this after the guard script changes (run-checks.sh flags a stale copy).
# Usage: tools/install-hooks.sh   (run from anywhere inside the repo)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
hooks="$(git rev-parse --git-common-dir)/hooks"
mkdir -p "$hooks"

cp tools/embargo-guard.sh "$hooks/embargo-guard"
chmod +x "$hooks/embargo-guard" 2>/dev/null || true
echo "installed $hooks/embargo-guard"

for h in pre-commit commit-msg pre-push; do
  if [ -e "$hooks/$h" ] && ! grep -q 'embargo-guard' "$hooks/$h"; then
    echo "SKIPPED $h: an unrelated hook already exists at $hooks/$h — add this line to it:"
    echo "    \"\$(git rev-parse --git-common-dir)/hooks/embargo-guard\" $h \"\$@\" || exit 1"
    continue
  fi
  printf '#!/bin/sh\n# installed by tools/install-hooks.sh — do not edit\nexec "$(git rev-parse --git-common-dir)/hooks/embargo-guard" %s "$@"\n' "$h" > "$hooks/$h"
  chmod +x "$hooks/$h" 2>/dev/null || true
  echo "installed $hooks/$h"
done

sh "$hooks/embargo-guard" status

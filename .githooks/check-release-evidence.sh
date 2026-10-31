#!/bin/sh
# Release evidence check (DE-49). A release needs, for its platform and version:
#   SCAN-<platform>-<version>.md   with "Result: PASS"                      (standing rules, section 1)
#   PANEL-<platform>-<version>.md  with "Result: PASS" and 3 reviewers, each "Verdict: PASS", none FAIL
# in security/ or docs/security/. Platform "*" accepts any platform (used for version tags).
# Usage: .githooks/check-release-evidence.sh <platform|*> <version> [rev]
#   no rev: reads the working tree (release gate scripts); rev: reads that commit (pre-push on tags).
# Every release gate script calls this before it builds, signs, uploads or deploys. Exit 1 = stop.
plat=${1:?usage: check-release-evidence.sh <platform|*> <version> [rev]}; ver=${2:?version}; rev=$3
top=$(git rev-parse --show-toplevel) || exit 1
files() {
  if [ -n "$rev" ]; then git ls-tree -r --name-only "$rev" -- security docs/security 2>/dev/null
  else (cd "$top" && ls security/* docs/security/* 2>/dev/null); fi
}
show() { if [ -n "$rev" ]; then git show "$rev:$1"; else cat "$top/$1"; fi; }
pick() {  # $1 = SCAN or PANEL; prints the matching file names
  files | while read -r f; do
    b=$(basename "$f")
    case "$b" in "$1"-*-"$ver".md) ;; *) continue ;; esac
    [ "$plat" = "*" ] || [ "$b" = "$1-$plat-$ver.md" ] || continue
    echo "$f"
  done
}
fail=0
scan=$(pick SCAN); panel=$(pick PANEL)
if [ -z "$scan" ]; then echo "  - no SCAN-$plat-$ver.md in security/ or docs/security/" >&2; fail=1; fi
for f in $scan; do
  show "$f" | grep -q '^Result: PASS' || { echo "  - $f does not say Result: PASS" >&2; fail=1; }
done
if [ -z "$panel" ]; then echo "  - no PANEL-$plat-$ver.md (the 3-reviewer panel review) in security/ or docs/security/" >&2; fail=1; fi
for f in $panel; do
  body=$(show "$f")
  printf '%s\n' "$body" | grep -q '^Result: PASS' || { echo "  - $f does not say Result: PASS" >&2; fail=1; }
  printf '%s\n' "$body" | grep -q "^Version: $ver\$" || { echo "  - $f has no line 'Version: $ver'" >&2; fail=1; }
  r=$(printf '%s\n' "$body" | grep -c '^## Reviewer ')
  p=$(printf '%s\n' "$body" | grep -c '^Verdict: PASS')
  if [ "$r" -lt 3 ] || [ "$p" -lt 3 ]; then echo "  - $f needs 3 reviewers, each 'Verdict: PASS' (has $r reviewers, $p passes)" >&2; fail=1; fi
  printf '%s\n' "$body" | grep -q '^Verdict: FAIL' && { echo "  - $f has a reviewer with Verdict: FAIL" >&2; fail=1; }
done
if [ "$fail" = 0 ]; then echo "check-release-evidence: $plat $ver has a passing scan and panel review." >&2
else echo "check-release-evidence: $plat $ver is not cleared for release (DE-49)." >&2; fi
exit $fail

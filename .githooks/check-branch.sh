#!/bin/sh
# Checks every commit on BRANCH that is not on BASE against the Ghost Labs commit rules (DE-32).
# Usage: .githooks/check-branch.sh <branch> [base, default main]
# Run it in the session's copy BEFORE bringing a claude/<key> branch back to the Mac. Exit 1 = do not bring it back.
# shellcheck source=.githooks/rules.sh
. "$(dirname "$0")/rules.sh"
branch=${1:?usage: check-branch.sh <branch> [base]}; base=${2:-main}
fail=0; n=0
# One item, one branch (DE-38): a second unmerged claude/ branch for the same key fails too.
sh "$(dirname "$0")/check-duplicate-branch.sh" "$branch" || fail=1
for c in $(git rev-list "$base..$branch"); do
  n=$((n+1))
  out=$(gl_check_message "$(git log -1 --format=%B "$c")"; m=$?; gl_check_ident "$(git log -1 --format="%an <%ae> / %cn <%ce>" "$c")"; exit $((m | $?))) || { git log -1 --format='%h %s' "$c"; echo "$out"; fail=1; }
done
if [ "$fail" = 0 ]; then echo "check-branch: $n commit(s) on $branch pass the Ghost Labs rules."
else echo "check-branch: $branch breaks the Ghost Labs rules. Reword the commits (git rebase) before bringing it back." >&2; fi
exit $fail

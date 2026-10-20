#!/bin/sh
# One item, one branch (DE-38). Refuses a claude/ branch when another unmerged
# claude/ branch for the same Ravenwood board key already exists, locally or on origin.
# A branch already merged into any non-claude branch (main, a release branch such as
# rc-1-commercial) is finished work and doesn't count.
# Usage: .githooks/check-duplicate-branch.sh <branch>
# Called by .githooks/pre-push and .githooks/check-branch.sh. Exit 1 = continue on the
# existing branch instead (cherry-pick your commits onto it).
branch=${1:?usage: check-duplicate-branch.sh <branch>}
branch=${branch#refs/heads/}
case "$branch" in claude/*) ;; *) exit 0 ;; esac
key=$(printf '%s\n' "${branch#claude/}" | grep -oE '^[A-Z][A-Z0-9]{0,4}-[0-9]{1,6}' | head -1)
[ -n "$key" ] || exit 0
# True when the commit is already contained in a branch that isn't a claude/ branch.
merged() {
  git cat-file -e "$1^{commit}" 2>/dev/null || return 1
  git for-each-ref --contains "$1" --format='%(refname)' refs/heads refs/remotes/origin |
    grep -v -e '/claude/' -e '/HEAD$' | grep -q .
}
# name<TAB>sha for every claude/<KEY> branch we can see: local, remote-tracking, and live on origin.
list() {
  git for-each-ref --format='%(refname:short)	%(objectname)' refs/heads/claude refs/remotes/origin/claude
  git ls-remote --heads origin 'claude/*' 2>/dev/null | awk '{print $2 "\t" $1}'
}
others=$(list | sed -e 's#^refs/heads/##' -e 's#^origin/##' | while IFS='	' read -r name sha; do
  [ "$name" = "$branch" ] && continue
  printf '%s\n' "$name" | grep -Eq "^claude/${key}(-|$)" || continue
  merged "$sha" && continue
  echo "$name"
done | sort -u)
[ -z "$others" ] && exit 0
echo "check-duplicate-branch: $key already has an unmerged branch:" >&2
printf '%s\n' "$others" | sed 's/^/  /' >&2
echo "One item, one branch (DE-38): continue on that branch (cherry-pick your commits onto it) instead of $branch." >&2
exit 1

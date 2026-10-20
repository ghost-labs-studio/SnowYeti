#!/bin/sh
# Ghost Labs commit rules (DE-32). Shared by commit-msg and check-branch.sh.
# 1. Every commit names its Ravenwood board key, e.g. WA-123.
# 2. No Claude attribution lines in any commit.
# Prints the problems and returns 1 when a message breaks a rule.
gl_check_message() {
  msg=$(printf '%s\n' "$1" | grep -v '^#')
  bad=0
  first=$(printf '%s\n' "$msg" | sed -n '1p')
  case "$first" in
    Merge\ *|Revert\ *) ;;
    *)
      if ! printf '%s\n' "$msg" | grep -Eq '(^|[^A-Za-z0-9])[A-Z][A-Z0-9]{0,4}-[0-9]{1,6}([^0-9]|$)'; then
        echo "  - no Ravenwood board key (add one, e.g. WA-123)"; bad=1
      fi ;;
  esac
  hits=$(printf '%s\n' "$msg" | grep -Ein '^[[:space:]]*co-authored-by:.*(claude|anthropic)|^[[:space:]]*claude-session:|generated with \[?claude|noreply@anthropic\.com|claude\.ai/code/session')
  if [ -n "$hits" ]; then
    echo "  - Claude attribution lines are not allowed in Ghost Labs commits:"
    printf '%s\n' "$hits" | sed 's/^/      line /'
    bad=1
  fi
  return $bad
}
# 3. The author and committer are a person, never Claude (an author of "Claude <noreply@anthropic.com>" is attribution too).
gl_check_ident() {
  if printf '%s\n' "$1" | grep -Eiq 'claude|anthropic'; then echo "  - author or committer is Claude ($1); commit as Larry"; return 1; fi
  return 0
}

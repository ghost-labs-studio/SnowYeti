#!/bin/sh
# Tests for .githooks/check-release-evidence.sh (DE-59). Run from anywhere: sh .githooks/test-check-release-evidence.sh
# Builds throwaway git repos in a temporary folder; prints one line per case and exits 1 if any case is wrong.
# Isolated from the user's git config (signing, global hooks) so it never prompts and never fails for that reason.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
here=$(cd "$(dirname "$0")" && pwd)
gate=$here/check-release-evidence.sh
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
log=$tmp/results  # case_ runs at the end of a pipe (a subshell), so results go to a file
: > "$log"
H=0123456789abcdef0123456789abcdef01234567

hdr() { printf '# Panel review: test web 1.0.0\n\nResult: %s\nVersion: %s\nCommit: %s\n\n' "${1:-PASS}" "${2:-1.0.0}" "${3:-$H}"; }
rev() {  # $1 number, $2 verdict, $3 findings text
  printf '## Reviewer %s: lens\nLens: test\nVerdict: %s\nFindings: %s\n\n' "$1" "$2" "${3:-none}"
}
revs() { rev 1 "${1:-PASS}" "$4"; rev 2 "${2:-PASS}" "$5"; rev 3 "${3:-PASS}" "$6"; }
arb() {  # $1 pass number, $2 verdict, rest = ruling lines (without the leading "- ")
  num=$1; verdict=$2; shift 2
  printf '## Arbitrator (pass %s)\nInputs: rule set, code, reviews\n' "$num"
  if [ $# = 0 ]; then printf 'Rulings: none\n'; else printf 'Rulings:\n'; for r in "$@"; do printf -- '- %s\n' "$r"; done; fi
  printf 'Disagreements: none\nVerdict: %s\n\n' "$verdict"
}
newrepo() { d=$(mktemp -d "$tmp/case.XXXXXX"); mkdir -p "$d/security"; git -C "$d" init -q; echo "$d"; }

# case_ <name> <expected exit 0|1> <expected text or ""> ; the PANEL body comes on stdin
case_() {
  name=$1; want=$2; text=$3
  d=$(newrepo)
  printf 'Result: PASS\n' > "$d/security/SCAN-web-1.0.0.md"
  cat > "$d/security/PANEL-web-1.0.0.md"
  out=$(cd "$d" && PATH=${GATE_PATH:-$PATH} sh "$gate" web 1.0.0 2>&1); got=$?
  ok=1
  [ "$got" = "$want" ] || ok=0
  if [ -n "$text" ]; then printf '%s\n' "$out" | grep -qF -- "$text" || ok=0; fi
  if [ "$ok" = 1 ]; then echo "ok   $name" | tee -a "$log"
  else echo "FAIL $name (exit $got, wanted $want)" | tee -a "$log"; printf '%s\n' "$out" | sed 's/^/     /'; fi
}

echo "-- should pass"
{ hdr; revs; arb 1 PASS; } | case_ "one pass, no findings" 0 "arbitrated panel review"
{ hdr; revs FAIL PASS PASS "R1-1 Low verbose error"; arb 1 PASS "R1-1 | upheld | Low | errors | real but low"; } | case_ "reviewer FAIL, finding upheld at Low" 0 ""
{ hdr; revs FAIL PASS PASS "R1-1 High auth bypass"; arb 1 PASS "R1-1 | rejected | High | auth | endpoint is not exposed"; } | case_ "reviewer FAIL, finding rejected" 0 ""
{ hdr; revs PASS PASS PASS "R1-1 Low a" "R2-1 Low b; R2-2 Info c"; arb 1 PASS "R1-1 | upheld | Low | x | y" "R2-1 | rejected | Low | x | dup of R1-1" "R2-2 | changed | Info | x | y" "A-1 | upheld | Low | x | arbitrator's own"; } | case_ "every finding ruled, arbitrator adds one" 0 ""
{ hdr; revs FAIL PASS PASS "R1-1 High bypass"; arb 1 FAIL "R1-1 | upheld | High | auth | bypass"; revs PASS PASS PASS; arb 2 PASS; } | case_ "two passes, fixed in pass 2" 0 ""
{ hdr; revs; arb 1 PASS; } | awk '{ printf "%s\r\n", $0 }' | case_ "CRLF line endings" 0 ""
{ hdr; revs PASS PASS PASS "R1-1 Low a"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n- R1-1 | upheld | Low | x | reason with a | in it\nDisagreements:\nR1 vs R2 | rejected R2 view | rule 7\nVerdict: PASS\n'; } | case_ "pipes in a reason and in Disagreements" 0 ""
{ hdr; revs FAIL PASS PASS "r1-1 Low lowercase id"; arb 1 PASS "R1-1 | upheld | Low | x | y"; } | case_ "lowercase finding id ruled as R1-1" 0 ""
{ hdr; revs PASS PASS PASS "R1-1 Low x; see the R1-1 note" ; arb 1 PASS "r1-1 | rejected | Low | x | not a breach"; } | case_ "id written twice, ruled once in lowercase" 0 ""

echo "-- should be refused"
{ hdr; revs; } | case_ "no arbitrator section" 1 "has no ## Arbitrator (pass N) section"
{ hdr; revs FAIL PASS PASS "R1-1 High x"; arb 1 FAIL "R1-1 | upheld | High | auth | bypass"; } | case_ "arbitrator FAIL with Result PASS" 1 "disagrees with the last arbitrator"
{ hdr FAIL; revs; arb 1 PASS; } | case_ "Result FAIL" 1 "a release needs Result: PASS"
{ hdr; revs PASS PASS PASS "" "R2-1 Medium x"; arb 1 PASS "R2-1 | upheld | Medium | input | unchecked path"; } | case_ "PASS with an upheld Medium" 1 "upheld 1 Critical, High or Medium"
{ hdr; revs PASS PASS PASS "" "R2-1 Low x"; arb 1 PASS "R2-1 | changed | Critical | input | worse than said"; } | case_ "PASS with a finding changed to Critical" 1 "upheld 1 Critical, High or Medium"
{ hdr; revs FAIL PASS PASS "R1-1 High auth bypass" "R2-1 Low log"; arb 1 PASS "R2-1 | rejected | Low | logging | not sensitive"; } | case_ "a finding with no ruling" 1 "finding R1-1 has no ruling"
{ hdr; revs PASS PASS PASS "R1-1 Low a"; arb 1 PASS; } | case_ "Rulings: none with a finding named" 1 "says Rulings: none but the reviewers named"
{ hdr; revs; arb 1 PASS " | upheld | Low |  | "; } | case_ "ruling with empty fields" 1 "malformed"
{ hdr; revs PASS PASS PASS "R1-1 High x"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n  - R1-1 | upheld | High | a | b\nDisagreements: none\nVerdict: PASS\n'; } | case_ "indented ruling" 1 "malformed"
{ hdr; revs PASS PASS PASS "R1-1 High x"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n* R1-1 | upheld | Critical | a | b\nDisagreements: none\nVerdict: PASS\n'; } | case_ "star-bullet ruling" 1 "malformed"
{ hdr; revs PASS PASS PASS "R1-1 High x"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n| R1-1 | upheld | High | a | b |\nDisagreements: none\nVerdict: PASS\n'; } | case_ "Markdown table ruling" 1 "malformed"
{ hdr; revs PASS PASS PASS "R1-1 High x"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n- R1-1 upheld High auth bypass\nDisagreements: none\nVerdict: PASS\n'; } | case_ "ruling without pipes" 1 "malformed"
{ hdr; rev 1 PASS; rev 2 PASS; arb 1 PASS; } | case_ "only 2 reviewers" 1 "needs 3 reviewer sections"
{ hdr; rev 1 PASS; rev 1 PASS; rev 1 PASS; arb 1 PASS; } | case_ "three sections all Reviewer 1" 1 "two sections for reviewer 1"
{ hdr; printf '## Reviewer 1\nVerdict: FAIL\nFindings: none\nVerdict: PASS\n\n'; rev 2 PASS; rev 3 PASS; arb 1 PASS; } | case_ "reviewer with two Verdict lines" 1 "reviewer 1 needs exactly one Verdict"
{ hdr; revs PASS MAYBE PASS; arb 1 PASS; } | case_ "reviewer verdict not PASS or FAIL" 1 "reviewer 2 needs exactly one Verdict"
{ hdr; revs; printf '## Arbitrator (pass 1)\nDisagreements: none\nVerdict: PASS\n'; } | case_ "arbitrator with no Rulings line" 1 "no Rulings: line"
{ hdr; revs; printf '## Arbitrator (pass 1)\nRulings: none\nVerdict: PASS\n'; } | case_ "arbitrator with no Disagreements line" 1 "no Disagreements: line"
{ hdr; revs; printf '## Arbitrator (pass 1)\nRulings: none\nDisagreements: none\nVerdict: PASS\nVerdict: PASS\n'; } | case_ "two arbitrator verdicts" 1 "exactly one Verdict"
{ hdr; revs; arb 1 PASS; revs; arb 3 PASS; } | case_ "passes numbered 1 then 3" 1 "numbered pass 1, 2, 3"
{ hdr; revs FAIL PASS PASS "R1-1 High x"; arb 1 FAIL "R1-1 | upheld | High | a | b"; revs; } | case_ "pass 2 with no arbitrator yet" 1 "after the last arbitrator have no ruling"
{ hdr; revs; arb 1 PASS; printf '## Pass 2 Reviewer 1\nVerdict: FAIL\n'; } | case_ "heading: ## Pass 2 Reviewer 1" 1 "heading not in the exact form"
{ hdr; revs; arb 1 PASS; revs; printf '## Arbitrator (Pass 2)\nRulings: none\nDisagreements: none\nVerdict: FAIL\n'; } | case_ "heading: ## Arbitrator (Pass 2)" 1 "heading not in the exact form"
{ hdr; revs; printf '## arbitrator (pass 1)\nRulings: none\nDisagreements: none\nVerdict: PASS\n'; } | case_ "heading: ## arbitrator (pass 1)" 1 "heading not in the exact form"
{ hdr; printf '##Reviewer 1\nVerdict: PASS\n'; rev 2 PASS; rev 3 PASS; arb 1 PASS; } | case_ "heading: ##Reviewer 1" 1 "heading not in the exact form"
{ hdr; revs; printf '## Arbitrator (pass 1) - DRAFT, not yet run\nRulings: none\nDisagreements: none\nVerdict: PASS\n'; } | case_ "heading: arbitrator marked DRAFT" 1 "heading not in the exact form"
{ hdr; revs PASS PASS PASS "R1-1 Low x"; arb 1 PASS "R1-1 | changed | Low | a | b"; printf '## Ruling details\n- A-1 | upheld | Critical | a | b\n'; } | case_ "sub-heading with an upheld Critical" 1 "unexpected heading after the first reviewer"
{ hdr; revs FAIL PASS PASS "R1-1 High x"; arb 1 FAIL "R1-1 | upheld | High | a | b"; printf '<!-- next pass\n'; revs; arb 2 PASS; printf -- '-->\n'; } | case_ "pass 2 hidden in an HTML comment" 1 "inside a code block or HTML comment"
{ hdr; revs FAIL PASS PASS "R1-1 High x"; arb 1 FAIL "R1-1 | upheld | High | a | b"; printf '```\n'; revs; arb 2 PASS; printf '```\n'; } | case_ "pass 2 hidden in a code fence" 1 "inside a code block or HTML comment"
{ printf '# Panel\n\nResult: PASS\nResult: PASS\nVersion: 1.0.0\nCommit: %s\n\n' "$H"; revs; arb 1 PASS; } | case_ "two Result lines" 1 "exactly one Result: line"
{ hdr PASS 1.0.1; revs; arb 1 PASS; } | case_ "wrong Version line" 1 "has Version: 1.0.1, not 1.0.0"
{ hdr PASS 1x0x0; revs; arb 1 PASS; } | case_ "Version 1x0x0 for 1.0.0" 1 "has Version: 1x0x0"
{ printf '# Panel\n\nResult: PASS\nVersion: 1.0.0\n\n'; revs; arb 1 PASS; } | case_ "no Commit line" 1 "exactly one Commit: line"
{ hdr PASS 1.0.0 "<full commit hash>"; revs; arb 1 PASS; } | case_ "Commit not filled in" 1 "Commit: must be the commit hash"
{ hdr; revs; arb 1 PASS; printf 'Verdict: PASS\n'; printf '# Appendix\n'; } | case_ "heading after the arbitrator" 1 "unexpected heading"
{ printf '# Panel\n\nResult: PASS\nVersion: 1.0.0\nCommit: %s\nVerdict: PASS\n\n' "$H"; revs; arb 1 PASS; } | case_ "Verdict line in the header" 1 "verdict or ruling line before the first reviewer"

echo "-- pass 3 acceptance (DE-59 review)"
{ hdr; revs FAIL PASS PASS "R1-1 Critical x <!-- note -->"; arb 1 PASS; } | case_ "finding with a trailing HTML comment" 1 "inside a code block or HTML comment in a reviewer"
fence=$(printf '\140\140\140')  # three backticks
{ hdr; printf '## Reviewer 1: a\nVerdict: FAIL\nFindings:\n%stext\nR1-1 Critical x\n%s\n\n' "$fence" "$fence"; rev 2 PASS; rev 3 PASS; arb 1 PASS; } | case_ "finding inside a code fence" 1 "inside a code block or HTML comment in a reviewer"
{ hdr; revs FAIL PASS PASS "High: auth bypass"; arb 1 PASS; } | case_ "finding with no id" 1 "names no finding id"
{ hdr; revs FAIL PASS PASS "r1-1 High x"; arb 1 PASS; } | case_ "lowercase id with no ruling" 1 "finding R1-1 has no ruling"
{ hdr; revs FAIL PASS PASS 'R1\-1 High x'; arb 1 PASS; } | case_ "escaped-hyphen id with no ruling" 1 "finding R1-1 has no ruling"
{ hdr; revs FAIL PASS PASS "R1$(printf '\342\200\221')1 High x"; arb 1 PASS; } | case_ "non-breaking-hyphen id with no ruling" 1 "finding R1-1 has no ruling"
{ hdr; revs FAIL PASS PASS "none"; arb 1 PASS; } | case_ "reviewer FAIL with Findings: none" 1 "names no finding id"
{ hdr; revs PASS PASS PASS "R1-1 High x"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n- R1-1 | rejected | Low | auth | see below\nDisagreements:\n- R1-1 | upheld | High | auth | real after all\nVerdict: PASS\n'; } | case_ "upheld High under Disagreements" 1 "ruling line outside the Rulings block"
{ hdr; revs; printf '## Arbitrator (pass 1)\nInputs: x\nRulings: none\nDisagreements:\n- A-1 | upheld | Critical | secrets | key committed\nVerdict: PASS\n'; } | case_ "upheld Critical under Disagreements" 1 "ruling line outside the Rulings block"
{ hdr; revs; printf '## Arbitrator (pass 1)\nInputs: x\nRulings: none\nVerdict: PASS\n- A-1 | upheld | Critical | a | b\nDisagreements: none\n'; } | case_ "ruling after Verdict, before Disagreements" 1 "ruling line outside the Rulings block"
{ hdr; revs; arb 1 PASS; { revs FAIL PASS PASS "R1-1 Critical x"; printf '## Arbitrator (pass 2)\nRulings:\n- R1-1 upheld Critical\nDisagreements: none\nVerdict: FAIL\n'; } | sed 's/^/ /'; } | case_ "pass 2 indented one space" 1 "indented, quoted or HTML heading"
{ hdr; printf '## Reviewer 1: a\n> Verdict: FAIL\nVerdict: PASS\nFindings: none\n\n'; rev 2 PASS; rev 3 PASS; arb 1 PASS; } | case_ "quoted Verdict line" 1 "indented, quoted, listed or emphasized Verdict"
{ hdr; printf '## Reviewer 1: a\n- Verdict: FAIL\nVerdict: PASS\nFindings: none\n\n'; rev 2 PASS; rev 3 PASS; arb 1 PASS; } | case_ "listed Verdict line" 1 "indented, quoted, listed or emphasized Verdict"
{ hdr; printf '## Reviewer 1: a\n**Verdict:** FAIL\nVerdict: PASS\nFindings: none\n\n'; rev 2 PASS; rev 3 PASS; arb 1 PASS; } | case_ "bold Verdict line" 1 "indented, quoted, listed or emphasized Verdict"
{ hdr; revs; arb 1 PASS; revs; printf '<h2>Arbitrator (pass 2)</h2>\nRulings: none\nDisagreements: none\nVerdict: FAIL\n'; } | case_ "HTML heading for an arbitrator" 1 "indented, quoted or HTML heading"

echo "-- pass 4 acceptance (DE-59 review, allowlist R1-1 and file count R2-1)"
fail2() { revs FAIL PASS PASS "R1-1 Critical x"; }
{ hdr; revs; arb 1 PASS; fail2 | sed 's/^/1. /'; printf '1. ## Arbitrator (pass 2)\n1. Rulings: none\n1. Verdict: FAIL\n'; } | case_ "pass 2 as ordered-list items" 1 "starts with a list, quote, number or heading marker"
{ hdr; revs; arb 1 PASS; printf '1) Verdict: FAIL\n'; } | case_ "ordered item with a parenthesis" 1 "starts with a list, quote, number or heading marker"
{ hdr; revs; arb 1 PASS; printf 'Arbitrator (pass 2)\n-------------------\nVerdict: FAIL\n'; } | case_ "setext heading for pass 2" 1 "underline or rule line"
{ hdr; revs; arb 1 PASS; printf 'Arbitrator (pass 2)\n===\n'; } | case_ "setext = underline" 1 "underline or rule line"
{ hdr; revs; arb 1 PASS; printf -- '* * *\n'; } | case_ "spaced thematic break" 1 "underline or rule line"
{ hdr; printf '## Reviewer 1: a\n<b>Verdict:</b> FAIL\nVerdict: PASS\nFindings: none\n\n'; rev 2 PASS; rev 3 PASS; arb 1 PASS; } | case_ "HTML bold Verdict" 1 "HTML tag or character reference"
{ hdr; revs; arb 1 PASS; printf 'x <h2>Arbi&#116;rator (pass 2)</h2>\n'; } | case_ "entity inside an HTML heading" 1 "HTML tag or character reference"
{ hdr; revs; arb 1 PASS; printf 'Arbi&#116;rator (pass 2) Verdict&#58; FAIL\n'; } | case_ "character reference alone" 1 "HTML tag or character reference"
{ hdr; revs; arb 1 PASS; printf '<h2\n'; } | case_ "split HTML tag" 1 "HTML tag or character reference"
{ hdr; revs; arb 1 PASS; printf 'Verdict\\: FAIL\n'; } | case_ "backslash-escaped colon" 1 "has a backslash"
{ hdr; revs; arb 1 PASS; printf '\\## Arbitrator (pass 2)\n'; } | case_ "backslash-escaped heading" 1 "has a backslash"
{ hdr; printf '## Reviewer 1: a\nVerdict: FAIL\nFindings:\n- R1-1 High x\n\n'; rev 2 PASS; rev 3 PASS; arb 1 PASS "R1-1 | upheld | Low | x | y"; } | case_ "bulleted finding refused (one plain line per finding)" 1 "starts with a list"
{ hdr; revs PASS PASS PASS "R1-1 Low a"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n- R1-1 | upheld | Low | x | y\nDisagreements:\n- R1 and R2 agreed\nVerdict: PASS\n'; } | case_ "bulleted Disagreements line" 1 "starts with a list"
{ hdr; revs; printf '## Arbitrator (pass 1)\nInputs: x\nRulings: none\nDisagreements: none\n> Verdict: FAIL\nVerdict: PASS\n'; } | case_ "quote marker in the arbitrator" 1 "starts with a list"
{ hdr; revs PASS PASS PASS "R1-1 Low a"; printf '## Arbitrator (pass 1)\nInputs: x\nRulings:\n- R1-1 | upheld | Low | x | y\n\n- A-1 | upheld | Low | x | blank line between rulings\nDisagreements: none\nVerdict: PASS\n'; } | case_ "ruling lines with a blank line between" 0 ""

echo "-- pass 5 acceptance (DE-59 review: bare CR, link definitions, footnotes, header content, stopped pass)"
{ hdr; revs; arb 1 PASS; printf 'Pass 2 follows.\r## Arbitrator (pass 2)\rRulings: none\rDisagreements: none\rVerdict: FAIL\n'; } | case_ "bare CR line endings" 1 "carriage return inside it"
{ hdr; revs; arb 1 PASS; printf 'Pass 2 follows.\r## Arbitrator (pass 2)\rVerdict: FAIL\n'; } | awk '{ printf "%s\r\n", $0 }' | case_ "bare CR inside CRLF lines" 1 "carriage return inside it"
{ hdr; revs; printf '## Arbitrator (pass 1)\nInputs: x\nThe arbitrator upholds an open Critical. Final verdict: FAIL\n\n[note]: /x "\nRulings: none\nDisagreements: none\nVerdict: PASS\n"\n'; } | case_ "link definition title hiding the fields" 1 "starts with \"[\""
{ hdr; revs; arb 1 PASS; printf 'See the follow-up pass[^p2].\n\n[^p2]: ## Arbitrator (pass 2)\n'; } | case_ "footnote definition with a heading" 1 "starts with \"[\""
{ hdr; revs; arb 1 PASS; printf '   [^b]: Verdict: FAIL\n'; } | case_ "indented footnote definition" 1 "starts with \"[\""
{ printf '# Panel review: test web 1.0.0\n\nResult: PASS\nVersion: 1.0.0\nCommit: %s\n\nArbitrator (pass 1)\n-------------------\n\nVerdict&#58; FAIL\n\n<script>\n' "$H"; revs; arb 1 PASS; } | case_ "header: setext fake arbitrator and an HTML block" 1 "HTML tag or character reference"
{ printf '# Panel review: test web 1.0.0\n\nResult: PASS\nVersion: 1.0.0\nCommit: %s\n\nArbitrator (pass 1)\n===\n\n' "$H"; revs; arb 1 PASS; } | case_ "header: setext heading" 1 "underline or rule line"
{ printf '# Panel review: test web 1.0.0\n\nResult: PASS\nVersion: 1.0.0\nCommit: %s\n\n<style>\n' "$H"; revs; arb 1 PASS; } | case_ "header: raw style block" 1 "HTML tag or character reference"
{ printf '# Panel review: test web 1.0.0\n\nResult: PASS\nVersion: 1.0.0\nCommit: %s\n\nVerdict\\: FAIL\n\n' "$H"; revs; arb 1 PASS; } | case_ "header: backslash escape" 1 "has a backslash"
{ printf '# Panel review: test web 1.0.0\n\nResult: PASS\nVersion: 1.0.0\nCommit: %s\n\n[x]: /y "\n' "$H"; revs; arb 1 PASS; } | case_ "header: link definition" 1 "starts with \"[\""
stopped3() { printf '## Arbitrator (pass 3)\nInputs: rule set, code, reviews\nStopped: the cap, pass 3 is the last allowed pass and R1-1 is open.\nOpen: R1-1, Medium, s1, tried a strict check.\nOption: fix with direction and allow further passes.\nOption: accept through security/accepted-findings.\nRulings:\n- R1-1 | upheld | Medium | s1 | still open\nDisagreements: none\nVerdict: FAIL\n\n'; }
{ hdr; revs FAIL PASS PASS "R1-1 Medium x"; arb 1 FAIL "R1-1 | upheld | Medium | s1 | open"; revs FAIL PASS PASS "R1-1 Medium x"; arb 2 FAIL "R1-1 | upheld | Medium | s1 | open"; revs FAIL PASS PASS "R1-1 Medium x"; stopped3; revs; arb 4 PASS; } | case_ "stopped pass 3 in the template form, then pass 4 PASS" 0 ""
{ hdr; revs FAIL PASS PASS "R1-1 Medium x"; arb 1 FAIL "R1-1 | upheld | Medium | s1 | open"; revs FAIL PASS PASS "R1-1 Medium x"; arb 2 FAIL "R1-1 | upheld | Medium | s1 | open"; revs FAIL PASS PASS "R1-1 Medium x"; stopped3; } | case_ "stopped pass 3 alone is not cleared" 1 "did not rule PASS"
{ hdr; revs PASS PASS PASS "R1-1 Low a path C:/Program Files/x and the URL https://example.com/a?b=1"; arb 1 PASS "R1-1 | upheld | Low | x | n less than max"; } | case_ "honest prose with paths and URLs" 0 ""

# R2-1: a report-list loop that never runs (bash 3.2 skips a loop whose here-doc temp file can't be made) must not clear
sed 's/^\(  *\)\{0,1\}done <<EOF$/\1done <\/dev\/null; : <<EOF/' "$gate" > "$tmp/gate-noheredoc.sh"
n=$(grep -c 'done </dev/null; : <<EOF' "$tmp/gate-noheredoc.sh")
if [ "$n" = 4 ]; then echo "ok   simulated skipped loops: all 4 report loops rewritten" | tee -a "$log"; else echo "FAIL simulated skipped loops: rewrote $n of 4" | tee -a "$log"; fi
d=$(newrepo); printf 'Result: PASS\n' > "$d/security/SCAN-web-1.0.0.md"; { hdr; revs; arb 1 PASS; } > "$d/security/PANEL-web-1.0.0.md"
out=$(cd "$d" && sh "$tmp/gate-noheredoc.sh" web 1.0.0 2>&1); got=$?
if [ "$got" = 1 ] && [ "$(printf '%s\n' "$out" | grep -c 'read 0 of 1 report')" = 2 ]; then echo "ok   loops that never ran are refused (web, both loops)" | tee -a "$log"
else echo "FAIL loops that never ran are refused (web) (exit $got)" | tee -a "$log"; printf '%s\n' "$out" | sed 's/^/     /'; fi
out=$(cd "$d" && sh "$tmp/gate-noheredoc.sh" '*' 1.0.0 2>&1); got=$?
if [ "$got" = 1 ] && [ "$(printf '%s\n' "$out" | grep -c 'read 0 of 1 report')" = 4 ]; then echo "ok   loops that never ran are refused (*, all 4 loops)" | tee -a "$log"
else echo "FAIL loops that never ran are refused (*) (exit $got)" | tee -a "$log"; printf '%s\n' "$out" | sed 's/^/     /'; fi
out=$(cd "$d" && sh "$gate" '*' 1.0.0 2>&1); got=$?
if [ "$got" = 0 ]; then echo "ok   the real gate still clears the same repo (*)" | tee -a "$log"; else echo "FAIL the real gate refused a good repo (*) (exit $got)" | tee -a "$log"; printf '%s\n' "$out" | sed 's/^/     /'; fi

# awk that fails, or prints nothing, must not clear the gate
mkdir -p "$tmp/badawk" "$tmp/quietawk"
printf '#!/bin/sh\necho "awk: syntax error" >&2\nexit 2\n' > "$tmp/badawk/awk"
printf '#!/bin/sh\ncat >/dev/null\nexit 0\n' > "$tmp/quietawk/awk"
chmod 755 "$tmp/badawk/awk" "$tmp/quietawk/awk"
{ hdr; revs; arb 1 PASS; } | GATE_PATH="$tmp/badawk:$PATH" case_ "awk exits 2" 1 "could not be checked"
{ hdr; revs; arb 1 PASS; } | GATE_PATH="$tmp/quietawk:$PATH" case_ "awk prints nothing" 1 "could not be checked"

check() {  # $1 name, $2 expected exit, $3... command run in the repo $d
  name=$1; want=$2; shift 2
  out=$(cd "$d" && "$@" 2>&1); got=$?
  if [ "$got" = "$want" ]; then echo "ok   $name" | tee -a "$log"
  else echo "FAIL $name (exit $got, wanted $want)" | tee -a "$log"; printf '%s\n' "$out" | sed 's/^/     /'; fi
}
good() { { hdr PASS "$1"; revs; arb 1 PASS; }; }

echo "-- pass 6 acceptance (DE-59 review: header lines that look hidden, quoted or listed footnotes and underlines)"
H6() { printf '# Panel review: test web 1.0.0\n\nResult: PASS\nVersion: 1.0.0\nCommit: %s\n\n' "$H"; }
bt=$(printf '\140\140\140')
{ H6; printf 'Note <!--\n\nArbitrator (pass 2)\n===================\n\nVerdict&#58; FAIL, open High R1-9 upheld\n\n<details><summary>draft notes</summary>\n\n-- end of note -->\n\n'; revs; arb 1 PASS; } | case_ "header: inline comment opener hiding a fake arbitrator" 1 "HTML tag or character reference"
{ H6; printf '    %s\nArbitrator (pass 2)\n===================\n\nVerdict FAIL, open High R1-9 upheld\n%s\n\n' "$bt" "$bt"; revs; arb 1 PASS; } | case_ "header: fence indented 4 spaces" 1 "has a code fence"
{ H6; printf '%s\nnotes\n~~~\n\n' "$bt"; revs; arb 1 PASS; } | case_ "header: tilde line closing a backtick fence" 1 "has a code fence"
{ H6; printf '    <!--\nArbitrator (pass 1)\n-------------------\n\nVerdict FAIL\n\n    -->\n\n'; revs; arb 1 PASS; } | case_ "header: indented comment" 1 "HTML tag or character reference"
{ H6; printf 'See the later pass[^a].\n    %s\n[^a]: Arbitrator (pass 2) FAIL\n    %s\n\n' "$bt" "$bt"; revs; arb 1 PASS; } | case_ "header: footnote between indented fences" 1 "starts with \"[\""
{ H6; printf '<!-- notes --><script>\n\n'; revs; arb 1 PASS; } | case_ "header: tag after a comment closer on one line" 1 "HTML tag or character reference"
{ H6; printf 'See the later pass[^a] and its ruling[^b].\n> [^a]: ## Arbitrator (pass 2)\n\n> [^b]: Verdict: FAIL, open Critical R1-9 upheld\n\n'; revs; arb 1 PASS; } | case_ "header: quoted footnote definitions" 1 "starts with \"[\""
{ H6; printf 'See the later pass[^a].\n- [^a]: Arbitrator (pass 2) FAIL\n\n'; revs; arb 1 PASS; } | case_ "header: listed footnote definition" 1 "starts with \"[\""
{ H6; printf '> Arbitrator (pass 2)\n> ---\n> Final ruling: FAIL. Open upheld Critical R1-9, release blocked.\n\n'; revs; arb 1 PASS; } | case_ "header: quoted setext heading" 1 "underline or rule line"
{ H6; printf '1. Arbitrator (pass 2)\n   ===\n\n'; revs; arb 1 PASS; } | case_ "header: setext inside a numbered item" 1 "underline or rule line"
{ H6; printf 'A summary with a/path/to/file.sh, https://example.com/x?y=1 and commit 0123abc.\n> A quoted plain note.\n\n'; revs; arb 1 PASS; } | case_ "header: honest summary and quote" 0 ""

# release interface: commit mode with platform "*" (pre-push on version tags)
d=$(newrepo); printf 'Result: PASS\n' > "$d/security/SCAN-mac-3.0.0.md"
{ hdr PASS 3.0.0; revs FAIL PASS PASS "R1-1 Medium x"; arb 1 FAIL "R1-1 | upheld | Medium | s1 | open"; revs FAIL PASS PASS "R1-1 Medium x"; arb 2 FAIL "R1-1 | upheld | Medium | s1 | open"; revs FAIL PASS PASS "R1-1 Medium x"; stopped3; revs; arb 4 PASS; } > "$d/security/PANEL-mac-3.0.0.md"
git -C "$d" add -A && git -C "$d" -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false commit -q --no-verify -m "DE-59 test"
check "commit mode *: stopped pass 3 then pass 4 PASS clears" 0 sh "$gate" '*' 3.0.0 HEAD
d=$(newrepo); printf 'Result: PASS\n' > "$d/security/SCAN-mac-3.0.0.md"
{ printf '# Panel review: test mac 3.0.0\n\nResult: PASS\nVersion: 3.0.0\nCommit: %s\n\n> Arbitrator (pass 2)\n> ---\n> Verdict FAIL\n\n' "$H"; revs; arb 1 PASS; } > "$d/security/PANEL-mac-3.0.0.md"
git -C "$d" add -A && git -C "$d" -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false commit -q --no-verify -m "DE-59 test"
check "commit mode *: quoted setext in the header is refused" 1 sh "$gate" '*' 3.0.0 HEAD

echo "-- SCAN reports, platforms and file places"
d=$(newrepo); good 1.0.0 > "$d/security/PANEL-web-1.0.0.md"; printf 'Result: FAIL\nResult: PASS\n' > "$d/security/SCAN-web-1.0.0.md"
check "SCAN with both Result: FAIL and Result: PASS" 1 sh "$gate" web 1.0.0
printf 'Result: PASSED\n' > "$d/security/SCAN-web-1.0.0.md"
check "SCAN with Result: PASSED" 1 sh "$gate" web 1.0.0
d=$(newrepo); printf 'Result: PASS\n' > "$d/security/SCAN-mac-1.0.0.md"; good 1.0.0 > "$d/security/PANEL-web-1.0.0.md"
check "platform * with SCAN-mac but PANEL-web" 1 sh "$gate" '*' 1.0.0
printf 'Result: PASS\n' > "$d/security/SCAN-web-1.0.0.md"; good 1.0.0 > "$d/security/PANEL-mac-1.0.0.md"
check "platform * with both platforms complete" 0 sh "$gate" '*' 1.0.0
d=$(newrepo); mkdir -p "$d/security/archive"; printf 'Result: PASS\n' > "$d/security/SCAN-web-1.0.0.md"; good 1.0.0 > "$d/security/archive/PANEL-web-1.0.0.md"
check "PANEL only in a subfolder" 1 sh "$gate" web 1.0.0
d=$(newrepo); mkdir -p "$d/docs/security"; printf 'Result: PASS\n' > "$d/docs/security/SCAN-web-1.0.0.md"; good 1.0.0 > "$d/docs/security/PANEL-web-1.0.0.md"
check "reports in docs/security/" 0 sh "$gate" web 1.0.0

echo "-- commit mode (pre-push on tags reads a commit, not the working tree)"
d=$(newrepo); printf 'Result: PASS\n' > "$d/security/SCAN-mac-2.0.0.md"; good 2.0.0 > "$d/security/PANEL-mac-2.0.0.md"
if ! { git -C "$d" add -A && git -C "$d" -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false commit -q --no-verify -m "DE-59 test"; }; then
  echo "FAIL could not make the test commit" | tee -a "$log"
fi
rm "$d/security/PANEL-mac-2.0.0.md"
check "commit mode reads the commit" 0 sh "$gate" '*' 2.0.0 HEAD
check "working-tree mode sees the PANEL is gone" 1 sh "$gate" mac 2.0.0

echo "-- the gate file and the template"
if [ -x "$gate" ]; then echo "ok   gate is executable" | tee -a "$log"; else echo "FAIL gate is not executable (chmod 755, git update-index --chmod=+x)" | tee -a "$log"; fi
d=$(newrepo); printf 'Result: PASS\n' > "$d/security/SCAN-web-1.0.0.md"
sed 's/<version>/1.0.0/g' "$here/PANEL-TEMPLATE.md" > "$d/security/PANEL-web-1.0.0.md"
check "unfilled template is refused" 1 sh "$gate" web 1.0.0
sed -e 's/<version>/1.0.0/g' -e 's/<platform>/web/g' -e 's/<product>/Test/' -e 's/<Month D, YYYY>/October 31, 2026/' \
    -e "s/^Commit: <.*>\$/Commit: $H/" -e 's/^Result: <.*>$/Result: PASS/' -e 's/^Verdict: <.*>$/Verdict: PASS/' \
    -e 's/^Findings: <.*>$/Findings: none/' -e 's/^Inputs: <\(.*\)>$/Inputs: \1/' -e 's/^Rulings:$/Rulings: none/' \
    -e '/^- <finding id>/d' -e 's/^Disagreements: <.*>$/Disagreements: none/' \
    "$here/PANEL-TEMPLATE.md" > "$d/security/PANEL-web-1.0.0.md"
check "filled-in template passes" 0 sh "$gate" web 1.0.0

fails=$(grep -c '^FAIL' "$log")
echo "test-check-release-evidence: $(wc -l < "$log" | tr -d ' ') checks, $fails failed"
[ "$fails" = 0 ]

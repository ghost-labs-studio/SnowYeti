#!/bin/sh
# Release evidence check (DE-49; arbitrator DE-58, DE-59). A release needs, for its platform and version,
# in security/ or docs/security/ (directly, not in a subfolder):
#   SCAN-<platform>-<version>.md   with exactly one "Result:" line, and it says "Result: PASS" (standing rules, section 1)
#   PANEL-<platform>-<version>.md  laid out as .githooks/PANEL-TEMPLATE.md     (standing rules, sections 1 and 7)
# Platform "*" (version tags) needs a SCAN and a PANEL for every platform that has either one.
# PANEL rules this script enforces:
#   - Header (before the first "## " heading): one "Result: PASS", one "Version: <version>" (exact), one "Commit:" hash.
#   - One or more passes. A pass is "## Reviewer 1", "## Reviewer 2", "## Reviewer 3" (numbered 1..k, k >= 3, each
#     with exactly one "Verdict: PASS" or "Verdict: FAIL"), then "## Arbitrator (pass N)", numbered 1, 2, 3 in order.
#   - Each arbitrator section has "Rulings:" (or "Rulings: none" when no reviewer in that pass named a finding),
#     then one ruling line per finding, then "Disagreements:", and exactly one "Verdict: PASS" or "Verdict: FAIL".
#     Ruling line: - <id> | upheld|rejected|changed | Critical|High|Medium|Low|Info | <rule> | <reason>
#     Every finding id (R<n>-<n>) a reviewer names in that pass needs a ruling; the arbitrator's own are A-<n>.
#   - The last arbitrator's verdict is the result: it must be PASS, with nothing upheld or changed at Critical,
#     High or Medium. Reviewer verdicts are input, not the result.
#   - Refused: unfilled "<...>" placeholders, any other heading after the first reviewer, headings that look like a
#     reviewer or arbitrator heading but aren't in the exact form, Verdict or ruling lines outside their section,
#     and review content inside code fences or HTML comments.
#   - Rendered must equal read (DE-59 pass 5): no carriage return inside a line, and anywhere in the file no HTML
#     tag or character reference, backslash, underline or rule line, or line starting with "["; after the first
#     reviewer heading no list, quote, number or heading marker except the exact headings and "- " rulings.
# Usage: .githooks/check-release-evidence.sh <platform|*> <version> [rev]
#   no rev: reads the working tree (release gate scripts); rev: reads that commit (pre-push on tags).
# Every release gate script calls this before it builds, signs, uploads or deploys. Exit 1 = stop.
plat=${1:?usage: check-release-evidence.sh <platform|*> <version> [rev]}; ver=${2:?version}; rev=$3
top=$(git rev-parse --show-toplevel) || exit 1
set -f
files() {  # every file directly under security/ or docs/security/, one path per line
  if [ -n "$rev" ]; then
    git -c core.quotePath=false ls-tree --name-only "$rev" -- security/ docs/security/ 2>/dev/null
  else
    for d in security docs/security; do
      [ -d "$top/$d" ] && (cd "$top" && find "$d" -maxdepth 1 -type f 2>/dev/null)
    done
  fi
}
show() { if [ -n "$rev" ]; then git show "$rev:$1"; else cat "$top/$1"; fi; }
pick() {  # $1 = SCAN or PANEL; prints the matching file names
  files | while IFS= read -r f; do
    b=${f##*/}
    case "$f" in security/"$b"|docs/security/"$b") ;; *) continue ;; esac
    case "$b" in "$1"-*-"$ver".md) ;; *) continue ;; esac
    [ "$plat" = "*" ] || [ "$b" = "$1-$plat-$ver.md" ] || continue
    printf '%s\n' "$f"
  done
}
platof() { b=${1##*/}; b=${b#*-}; printf '%s\n' "${b%-"$ver".md}"; }  # PANEL-mac-1.2.3.md -> mac

# Reads a PANEL report on stdin; prints one problem per line, then "__checked__" as the last line.
panel_problems() {
  PANEL_VER=$ver LC_ALL=C awk '
    function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
    function prob(m) { print m }
    function isph(s) { return (s ~ /^<[^>]*>$/) }
    function rulingish(s, l) { l = tolower(s); return (index(s, "|") && l ~ /(upheld|rejected|changed)/) }
    function strictruling(l) { return (l ~ /^[ \t]*[-*+][ \t]+[^|]*\|[ \t]*(upheld|rejected|changed)[ \t]*\|/) }
    function norm(s) {  # finding ids: any case, and "\-" or Unicode dashes read as "-"
      s = toupper(s); gsub(/\\-/, "-", s)
      gsub(/\342\200\220|\342\200\221|\342\200\222|\342\200\223|\342\200\224|\342\200\225|\342\210\222/, "-", s)
      return s
    }
    function endsec(   id, n, i) {
      if (sec == "rev") {
        nrev++
        if (rvn != 1 || rbad) prob("pass " (na + 1) ": reviewer " revnum " needs exactly one Verdict: PASS or Verdict: FAIL line")
        if ((rfail || fnon) && rids == 0) prob("pass " (na + 1) ": reviewer " revnum " says FAIL or lists findings but names no finding id (R" revnum "-1, R" revnum "-2 ...)")
      } else if (sec == "arb") {
        na++
        if (curnum != na) prob("arbitrator sections must be numbered pass 1, 2, 3 in order (section " na " says pass " curnum ")")
        if (nrev < 3) prob("pass " na " needs 3 reviewer sections before its arbitrator (has " nrev + 0 ")")
        for (i = 1; i <= nrev; i++) if (!(i in revseen)) { prob("pass " na ": reviewers must be numbered 1 to " nrev " with no gaps"); break }
        if (!rul) prob("pass " na " arbitrator has no Rulings: line")
        if (!dis) prob("pass " na " arbitrator has no Disagreements: line")
        if (bad > 0) prob("pass " na " arbitrator has " bad " malformed ruling, verdict or field line(s)")
        if (vp + vf != 1) prob("pass " na " arbitrator needs exactly one Verdict: PASS or Verdict: FAIL")
        if (vp == 1 && blk > 0) prob("pass " na " arbitrator says PASS but upheld " blk " Critical, High or Medium finding(s)")
        n = 0
        for (id in ids) { n++; if (!(id in ruled)) prob("pass " na ": finding " id " has no ruling from the arbitrator") }
        if (rulnone && n > 0) prob("pass " na " says Rulings: none but the reviewers named " n " finding(s)")
        if (rulnone && nruled > 0) prob("pass " na " says Rulings: none but has ruling lines")
        lastpass = (vp == 1 && vf == 0) ? "PASS" : "FAIL"
        nrev = 0; split("", revseen); split("", ids); split("", ruled); nruled = 0
      }
      sec = ""; rvn = 0; rbad = 0; rfail = 0; fnon = 0; rids = 0; indis = 0; vp = 0; vf = 0; rul = 0; rulnone = 0; inrul = 0; dis = 0; blk = 0; bad = 0
    }
    {
      sub(/\r$/, "")
      line = $0; low = tolower(line)
      # A carriage return inside a line is a line ending to Markdown renderers (CommonMark, GitHub) but not to awk,
      # so text after it would render as its own line without being read (DE-59 pass 5, R1-1). Only CRLF is allowed.
      if (index(line, "\r")) prob("line " NR " has a carriage return inside it: use plain LF or CRLF line endings")
      # Whole file (DE-59 passes 5 and 6, R1-1): checked on every line, before the code-fence and comment tracking
      # below, so no line can escape them by looking hidden to this script while rendering as text. Refused: any
      # HTML tag, comment opener or character reference; any backslash; any code fence (``` or ~~~, anywhere on the
      # line); any underline or rule line; any line starting with "[" (link reference definitions and footnotes,
      # which hide or move text). The underline and "[" checks also look past leading quote and list markers.
      t = line; sub(/^[ \t]+/, "", t)
      u = t
      while (u ~ /^(>|[-*+]([ \t]|$)|[0-9]+[.)]([ \t]|$))/) { sub(/^(>|[-*+]|[0-9]+[.)])/, "", u); sub(/^[ \t]+/, "", u) }
      if (line ~ /<[A-Za-z\/!?]/ || line ~ /&#?[A-Za-z0-9]+;/) prob("line " NR " has an HTML tag or character reference (an HTML comment counts too): write it as plain text")
      if (index(line, "\\")) prob("line " NR " has a backslash: write it as plain text, without escapes")
      if (index(line, "```") || index(line, "~~~")) prob("line " NR " has a code fence (``` or ~~~): write it as plain text")
      if (t ~ /^(=+|-+|\*+|_+)[ \t]*$/ || t ~ /^[-*_][ \t]*[-*_][ \t]*[-*_][-*_ \t]*$/ || u ~ /^(=+|-+|\*+|_+)[ \t]*$/ || u ~ /^[-*_][ \t]*[-*_][ \t]*[-*_][-*_ \t]*$/) prob("line " NR " is an underline or rule line: remove it (headings use ## at the start of the line)")
      if (substr(t, 1, 1) == "[" || substr(u, 1, 1) == "[") prob("line " NR " starts with \"[\" (a link definition or footnote would hide or move text): write it as plain text")
      # Code fences and HTML comments: nothing that counts may hide in them.
      hidden = 0
      if (line ~ /^[ \t]*(```|~~~)/) { infence = !infence; hidden = 1 }
      else if (infence) hidden = 1
      if (incomment || index(line, "<!--")) {
        hidden = 1
        if (index(line, "<!--")) incomment = 1
        if (index(line, "-->")) incomment = 0
      }
      if (hidden) {
        if ((sec == "rev" || sec == "arb") && trim(line) != "")
          prob("text inside a code block or HTML comment in a reviewer or arbitrator section (line " NR "): write it as plain text")
        else if (line ~ /^#/ || low ~ /^[ \t]*(verdict|result|rulings):/ || rulingish(line))
          prob("review content inside a code block or HTML comment (line " NR "): remove the fence or comment, or the content")
        next
      }
      # Structure lines must be plain, at the start of the line: an indented, quoted, listed, emphasized or HTML
      # heading or Verdict, Result or Rulings line would render as one but not be read as one.
      ds = line; sub(/^[ \t>]+/, "", ds)
      if (ds ~ /^[-*+][ \t]+/) { sub(/^[-*+][ \t]+/, "", ds); sub(/^[ \t>]+/, "", ds) }
      gsub(/[*_]/, "", ds); dl = tolower(ds)
      if ((substr(line, 1, 1) != "#" && dl ~ /^#/ && dl ~ /reviewer|arbitrator/) || (low ~ /<h[1-6]/ && low ~ /reviewer|arbitrator/))
        prob("indented, quoted or HTML heading naming a reviewer or arbitrator (line " NR "): use the exact form at the start of the line")
      if (dl ~ /^(verdict|result|rulings)[ \t]*:/ && low !~ /^(verdict|result|rulings):/)
        prob("indented, quoted, listed or emphasized Verdict, Result or Rulings line (line " NR "): write it plainly at the start of the line")
      # Allowlist (DE-59 pass 4, R1-1): after the first reviewer heading every line is plain text. Refused: any line
      # that starts (after spaces) with a Markdown block marker (> - * + 1. 1) #), except an exact heading at the
      # start of the line and a "- " ruling line under Rulings:; any HTML tag or character reference; any backslash
      # escape; any setext underline or thematic break. Anything that could render as structure must be read as it.
      t = line; sub(/^[ \t]+/, "", t)
      if (seenrev) {
        mark = (t ~ /^(>|[-*+]([ \t]|$)|[0-9]+[.)]([ \t]|$)|#)/)
        if (mark && substr(line, 1, 1) == "#" && line ~ /^#+[ \t]/) mark = 0      # headings: checked below
        if (mark && sec == "arb" && inrul && substr(line, 1, 2) == "- ") mark = 0  # a ruling line
        if (mark) prob("line " NR " starts with a list, quote, number or heading marker after the first reviewer section: write it as plain text (only \"- \" ruling lines under Rulings: may start with \"- \")")
      }
    }
    /^#/ {
      if (line ~ /^## Arbitrator \(pass [0-9]+\)[ \t]*$/) {
        endsec(); n = line; sub(/^## Arbitrator \(pass /, "", n); sub(/\).*$/, "", n)
        sec = "arb"; curnum = n + 0; seenrev = 1; inbody = 1; next
      }
      if (line ~ /^## Reviewer [0-9]+(:.*)?$/) {
        endsec(); n = line; sub(/^## Reviewer /, "", n); sub(/[^0-9].*$/, "", n)
        sec = "rev"; revnum = n + 0
        if (revnum in revseen) prob("pass " (na + 1) " has two sections for reviewer " revnum)
        revseen[revnum] = 1; seenrev = 1; inbody = 1; next
      }
      if (low ~ /reviewer|arbitrator/) { endsec(); sec = "other"; inbody = 1; prob("heading not in the exact form \"## Reviewer N\" or \"## Arbitrator (pass N)\" (line " NR "): " line); next }
      if (line ~ /^#+([ \t]|$)/) {
        if (line ~ /^##/ || seenrev) inbody = 1
        endsec(); sec = "other"
        if (seenrev) prob("unexpected heading after the first reviewer section (line " NR "): " line)
        next
      }
    }
    {
      v = ""
      if (low ~ /^verdict:/) v = trim(substr(line, 9))
      if (!inbody) {
        if (low ~ /^result:/) { nres++; res = trim(substr(line, 8)); if (isph(res) || index(res, "<")) prob("Result: is not filled in") }
        else if (low ~ /^version:/) { nver++; if (trim(substr(line, 9)) != ENVIRON["PANEL_VER"]) badver = trim(substr(line, 9)) }
        else if (low ~ /^commit:/) { ncom++; c = trim(substr(line, 8)); if (length(c) < 7 || length(c) > 40 || c !~ /^[0-9a-f]+$/) prob("Commit: must be the commit hash the panel reviewed (has \"" c "\")") }
        else if (low ~ /^(date|scan report):/ && index(line, "<")) prob("unfilled placeholder in the header (line " NR "): " line)
        else if (low ~ /^verdict:/ || rulingish(line)) prob("verdict or ruling line before the first reviewer section (line " NR ")")
        next
      }
      if (sec == "rev") {
        if (low ~ /^verdict:/) { rvn++; if (v == "FAIL") rfail = 1; else if (v != "PASS") rbad = 1 }
        else if (low ~ /^findings:/) {
          fv = trim(substr(line, 10))
          if (isph(fv)) prob("pass " (na + 1) " reviewer " revnum ": Findings: is not filled in")
          if (tolower(fv) != "none") fnon = 1
        }
        s = " " norm(line)
        while (match(s, /[^A-Z0-9]R[0-9]+-[0-9]+/)) { ids[substr(s, RSTART + 1, RLENGTH - 1)] = 1; rids++; s = substr(s, RSTART + RLENGTH) }
        next
      }
      if (sec == "arb") {
        if (low ~ /^verdict:/) { inrul = 0; indis = 0; if (v == "PASS") vp++; else if (v == "FAIL") vf++; else bad++; next }
        if (low ~ /^rulings:/) {
          r = trim(substr(line, 9)); rul++; inrul = 1
          if (tolower(r) == "none") rulnone = 1; else if (r != "") bad++
          next
        }
        if (low ~ /^disagreements:/) { inrul = 0; indis = 1; dis++; if (isph(trim(substr(line, 15)))) bad++; next }
        if (low ~ /^inputs:/) { if (isph(trim(substr(line, 8)))) bad++; next }
        if (inrul) {
          if (trim(line) == "") next
          if (substr(line, 1, 2) != "- ") { bad++; next }
          k = split(substr(line, 3), p, "|")
          if (k < 5) { bad++; next }
          id = norm(trim(p[1])); r = tolower(trim(p[2])); sv = tolower(trim(p[3])); ru = trim(p[4]); rs = trim(p[5])
          for (i = 6; i <= k; i++) rs = rs "|" p[i]
          rs = trim(rs)
          if (id !~ /^(R[0-9]+-[0-9]+|A-[0-9]+)$/ || ru == "" || rs == "" || isph(ru) || isph(rs)) { bad++; next }
          if (r != "upheld" && r != "rejected" && r != "changed") { bad++; next }
          if (sv != "critical" && sv != "high" && sv != "medium" && sv != "low" && sv != "info") { bad++; next }
          if ((r == "upheld" || r == "changed") && (sv == "critical" || sv == "high" || sv == "medium")) blk++
          ruled[id] = 1; nruled++
          next
        }
        if (strictruling(low) || (!indis && rulingish(line))) prob("pass " (na + 1) ": ruling line outside the Rulings block (line " NR "); every ruling goes under Rulings:")
        next
      }
      if (low ~ /^verdict:/ || rulingish(line)) prob("verdict or ruling line outside a reviewer or arbitrator section (line " NR ")")
    }
    END {
      endsec()
      if (infence) prob("a code fence is never closed")
      if (incomment) prob("an HTML comment is never closed")
      if (nres != 1) prob("needs exactly one Result: line before the first ## heading (has " nres + 0 ")")
      else if (res != "PASS") prob("Result: is \"" res "\"; a release needs Result: PASS")
      if (nver != 1) prob("needs exactly one Version: line before the first ## heading (has " nver + 0 ")")
      else if (badver != "") prob("has Version: " badver ", not " ENVIRON["PANEL_VER"])
      if (ncom != 1) prob("needs exactly one Commit: line before the first ## heading (has " ncom + 0 ")")
      if (na == 0) prob("has no ## Arbitrator (pass N) section; every pass needs an arbitrator (DE-58; see PANEL-TEMPLATE.md)")
      else {
        if (nrev > 0) prob(nrev " reviewer section(s) after the last arbitrator have no ruling")
        if (lastpass != "PASS") prob("the last arbitrator (pass " na ") did not rule PASS")
        else if (res != "" && res != "PASS") prob("Result: " res " disagrees with the last arbitrator verdict (PASS)")
        if (res == "PASS" && lastpass != "PASS") prob("Result: PASS disagrees with the last arbitrator verdict (FAIL)")
      }
      print "__checked__"
    }
  '
}

fail=0
scan=$(pick SCAN); panel=$(pick PANEL)
lines() { printf '%s\n' "$1" | grep -c .; }  # non-empty lines in $1
nscan=$(lines "$scan"); npanel=$(lines "$panel")
counted() {  # $1 loop name, $2 files read, $3 files expected: a loop that read fewer files than it was given failed (DE-59 R2-1)
  if [ "$2" != "$3" ]; then
    printf '  - %s read %s of %s report(s); not cleared (the list could not be read)\n' "$1" "$2" "$3" >&2; fail=1
  fi
}
if [ -z "$scan" ]; then printf '  - no SCAN-%s-%s.md in security/ or docs/security/\n' "$plat" "$ver" >&2; fail=1; fi
if [ -z "$panel" ]; then printf '  - no PANEL-%s-%s.md (the panel review with its arbitrator) in security/ or docs/security/\n' "$plat" "$ver" >&2; fail=1; fi
has() {  # $1 = list of paths, $2 = SCAN or PANEL, $3 = platform: is that exact report in the list?
  printf '%s\n' "$1" | grep -qxF -e "security/$2-$3-$ver.md" -e "docs/security/$2-$3-$ver.md"
}
if [ "$plat" = "*" ]; then  # every platform found needs both reports
  k=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    k=$((k + 1))
    p=$(platof "$f")
    has "$panel" PANEL "$p" || { printf '  - %s has no matching PANEL-%s-%s.md\n' "$f" "$p" "$ver" >&2; fail=1; }
  done <<EOF
$scan
EOF
  counted "SCAN pairing" "$k" "$nscan"
  k=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    k=$((k + 1))
    p=$(platof "$f")
    has "$scan" SCAN "$p" || { printf '  - %s has no matching SCAN-%s-%s.md\n' "$f" "$p" "$ver" >&2; fail=1; }
  done <<EOF
$panel
EOF
  counted "PANEL pairing" "$k" "$npanel"
fi
k=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  k=$((k + 1))
  body=$(show "$f" | tr -d '\r')
  n=$(printf '%s\n' "$body" | grep -c '^Result:')
  if [ "$n" != 1 ] || ! printf '%s\n' "$body" | grep -qx 'Result: PASS'; then
    printf '  - %s needs exactly one Result: line, and it must say Result: PASS\n' "$f" >&2; fail=1
  fi
done <<EOF
$scan
EOF
counted "SCAN check" "$k" "$nscan"
k=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  k=$((k + 1))
  out=$(show "$f" | panel_problems); rc=$?
  last=$(printf '%s\n' "$out" | tail -n 1)
  if [ "$rc" != 0 ] || [ "$last" != "__checked__" ]; then
    printf '  - %s could not be checked (awk exit %s); not cleared\n' "$f" "$rc" >&2; fail=1; continue
  fi
  probs=$(printf '%s\n' "$out" | sed '$d')
  if [ -n "$probs" ]; then
    printf '%s\n' "$probs" | while IFS= read -r line; do printf '  - %s %s\n' "$f" "$line" >&2; done
    fail=1
  fi
done <<EOF
$panel
EOF
counted "PANEL check" "$k" "$npanel"
if [ "$fail" = 0 ]; then printf 'check-release-evidence: %s %s has a passing scan and an arbitrated panel review.\n' "$plat" "$ver" >&2
else printf 'check-release-evidence: %s %s is not cleared for release (DE-49, DE-59). See .githooks/PANEL-TEMPLATE.md.\n' "$plat" "$ver" >&2; fi
exit "$fail"

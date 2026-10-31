# Panel review: <product> <platform> <version>

Result: <PASS or FAIL: the last arbitrator's verdict>
Version: <version>
Date: <Month D, YYYY>
Scan report: SCAN-<platform>-<version>.md
Commit: <full commit hash the panel reviewed>

Three independent reviewers (subagents that have not seen the work or each other's findings) each review the
release with their own lens and give every finding an id (R1-1, R1-2 for Reviewer 1, and so on). Then an
independent arbitrator (a separate subagent that wrote neither the work nor any review) gets the rule set, the
work and every finding word for word. It rules on each finding, settles disagreements, adds anything missed (ids
A-1, A-2), and gives the pass's verdict (standing rules, section 7; DE-58). The arbitrator's verdict, not a count
of reviewer verdicts, is the pass's result, and Result: above is the last pass's arbitrator verdict.

Any arbitrator FAIL, or any finding upheld or changed at Critical, High or Medium, is fixed and the panel and a
fresh arbitrator run again: copy the four sections below as the next pass, under the last one, as plain text
(not inside a code block or an HTML comment). Anything accepted goes in security/accepted-findings with an expiry
and board key. .githooks/check-release-evidence.sh checks this layout and refuses any "<...>" left unfilled (DE-59).

Every finding gets an id (R1-1, R2-3 and so on). Every id a reviewer writes in its section, including one it
mentions from an earlier pass, needs a ruling from that pass's arbitrator. A reviewer that says FAIL or lists findings
must name at least one id. Write every line as plain text, with LF or CRLF line endings. Anywhere in the file: no
code blocks or HTML comments, no backslash at all, no "<" directly before a letter (write "less than", or Result of
Config and Error for a generic type), no character codes (an "&" with a name or number and a semicolon), no
underline or rule lines (--- or ===), and no line starting with "[". From the first reviewer heading down, also no line starting with a list, quote, number or
heading marker (> - * + 1. 1) #) except the exact "## Reviewer N" and "## Arbitrator (pass N)" headings and the "- "
ruling lines under Rulings:. So write Windows paths with forward slashes, one finding per plain line (no bullets),
and every ruling under Rulings:.

When a pass reaches a loop limit (standing rules section 7, DE-62), write its arbitrator section in this same form:
the "## Arbitrator (pass N)" heading, a plain line starting "Stopped:" that says why, each open upheld finding and
each of the owner's options on its own plain line (no numbers, no bullets, no pipe characters), the rulings under
Rulings:, a Disagreements: line, and "Verdict: FAIL". Never edit it afterwards. If the owner allows further passes, add them below it, continuing the
numbering (pass N+1).

Upgrading a report written before DE-59: (1) add a Commit: line to the header with the full commit hash the panel
reviewed; (2) rename each reviewer heading to the exact form "## Reviewer N: lens name" (heading only, never the
review text); (3) move any other heading (Summary, Appendix) above the first reviewer, or remove it; (4) rewrite
bulleted or numbered findings as plain lines and remove HTML and comments, code fences, character codes,
backslashes, rule lines, lines starting with "[" (such as link references) and quote markers, and save with LF or
CRLF line endings (or run a fresh panel);
(5) give a fresh arbitrator the rule set, the code and the three reviews word for word and add its
"## Arbitrator (pass 1)" section below them.

## Reviewer 1: Attacker
Lens: how would I break in? Auth bypass, injection, path traversal, CSRF, DNS rebinding, unsafe deserialization,
exposed endpoints and ports, privilege escalation, abuse of the update or install path.
Verdict: <PASS or FAIL>
Findings: <none, or one line per finding: R1-1, its severity, the rule it breaks, what was found>

## Reviewer 2: Secure code
Lens: the diff since the last release and the code it touches. Input validation, error handling, crypto use,
secrets handling, logging of sensitive data, permissions and entitlements, platform settings.
Verdict: <PASS or FAIL>
Findings: <none, or one line per finding: R2-1, its severity, the rule it breaks, what was found>

## Reviewer 3: Supply chain and release
Lens: dependencies and pinning, build and upload scripts, CI, signing, what ships inside the package, the
scan report's own coverage and anything it skipped.
Verdict: <PASS or FAIL>
Findings: <none, or one line per finding: R3-1, its severity, the rule it breaks, what was found>

## Arbitrator (pass 1)
Inputs: <the rule set (standing rules sections 1 and 7, the scan report), the diff and code, and all three reviews word for word>
Rulings:
- <finding id> | <upheld, rejected or changed> | <Critical, High, Medium, Low or Info> | <rule> | <reason>
Disagreements: <none, or how each was settled, citing the rule>
Verdict: <PASS or FAIL>

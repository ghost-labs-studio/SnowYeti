# Panel review: <product> <platform> <version>

Result: PASS
Version: <version>
Date: <Month D, YYYY>
Scan report: SCAN-<platform>-<version>.md
Commit: <full commit hash the panel reviewed>

Three independent reviewers (subagents that have not seen the work or each other's findings) each review the
release with their own lens. Any reviewer FAIL makes the result FAIL. High and Medium findings are fixed and the
panel re-run before release; anything accepted goes in security/accepted-findings with an expiry and board key.

## Reviewer 1: Attacker
Lens: how would I break in? Auth bypass, injection, path traversal, CSRF, DNS rebinding, unsafe deserialization,
exposed endpoints and ports, privilege escalation, abuse of the update or install path.
Verdict: PASS
Findings: none / list with severity

## Reviewer 2: Secure code
Lens: the diff since the last release and the code it touches. Input validation, error handling, crypto use,
secrets handling, logging of sensitive data, permissions and entitlements, platform settings.
Verdict: PASS
Findings: none / list with severity

## Reviewer 3: Supply chain and release
Lens: dependencies and pinning, build and upload scripts, CI, signing, what ships inside the package, the
scan report's own coverage and anything it skipped.
Verdict: PASS
Findings: none / list with severity

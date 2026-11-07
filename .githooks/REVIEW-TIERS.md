# Review tiers (DE-98, November 3, 2026)

How big a rule-set review panel is, and how it spends tokens. Standing rules section 7 (DE-58, DE-62) still
governs every review: an independent arbitrator in every pass, its verdict is the result, at most 3 passes, the
same rule set all the way through. This file only decides how many reviewers sit on the panel and what they read.

Changing this file, `classify-risk.py` or its tests is itself a high change and needs a DE item.

## 1. Pick the tier

Run the classifier on the work under review:

    python3 .githooks/classify-risk.py --rev <commit> --base <where the review starts> \
      --ruleset-version <standing rules date or SHA-256> --feed-version <threat feed version> --json

It prints `tier` (low, normal or high), the reason for each file, whether the random sample raised it, and a
`cache_key`. It needs no network and never fails open: an error, an empty change or anything it can't read is high.

| Tier | Panel | Who sits on it |
|---|---|---|
| high | full panel | Reviewer 1 attacker, Reviewer 2 secure code, Reviewer 3 supply chain and release, then the arbitrator |
| normal | 1 reviewer | Reviewer 2 secure code, then the arbitrator |
| low | no reviewer | the arbitrator alone, judging the scan report and the diff against the rule set |

Always high, whatever the files say:

- Every release (Larry, November 3, 2026). The release PANEL report, its template and `check-release-evidence.sh`
  are unchanged: 3 reviewers and an arbitrator, every time.
- Any change to `.githooks/`, `.github/`, `security/`, CI, lockfiles and manifests, build, sign, deploy, install
  and release scripts, migrations, entitlements and platform manifests, service workers, agent instructions
  (CLAUDE.md, skills), scripts of any kind, an executable bit, a symlink or a submodule.
- Code whose changed lines (added or removed) touch auth, sessions, tokens, secrets, crypto, network calls,
  permissions, HTML injection sinks, process execution, file system, deserialization, SQL or storage bindings,
  validation or escaping, suppression comments, or the Ravenwood and Patchwork integrations.
- Prose that mentions credentials or keys, or tells someone to run, install, disable, bypass or skip something.
- About 1 in 10 low and normal changes (the escalation sample). The draw mixes the change's hash with a random
  salt kept in the clone's .git, so it can't be worked out ahead of time, and every draw is logged per base: once a
  base has been sampled, a later draw on it (a reworded change) stays sampled.
- Security territory by name: a path with auth, session, token, secret, crypto, login, admin, permission, role,
  policy, route, middleware, api, guard, intake, webhook, upload or similar in it; Worker and server folders, and any
  code under a folder holding a wrangler config; build, install and test harness files (setup.py, build.rs,
  Package.swift, *.config.js and the like); editor, tool and agent config (.vscode, .devcontainer, ESLint, Babel,
  Renovate, Husky, AGENT.md, GEMINI.md, .cursor and the like).

## 2. Rules the arbitrator adds at every tier

- The arbitrator may raise the tier (and the session then runs the missing reviewers in the same pass). It may
  never lower it, and nobody else may either.
- At low and normal tiers, the arbitrator also judges whether the classifier was right. If it would have wanted
  a higher tier, it says so in its rulings as a classifier miss. A miss found by the escalation sample (a sampled
  change whose full panel upholds a Medium or higher finding that a lower tier would not have looked for) is a
  classifier miss too.
- Every classifier miss gets a DE item to fix the classifier, and the review continues at the higher tier.

## 3. What reviewers read (token budget)

- **Fixed prefix first, in the same bytes every time:** the rule set (standing rules sections 1 and 7 and the
  rules the review is judged against), then the reviewer's lens, then this file. The variable part comes after:
  the diff, then the code it touches, then the scan report. Keeping the prefix identical lets prompt caching reuse
  it across reviewers, passes and sessions.
- **The diff and the code it touches, not whole files or the repo.** For each changed function or block, the whole
  function and its callers in the same file. A reviewer may ask the session for more, and gets it.
- **The scan report**, including the threat feed's results, so the panel doesn't spend tokens on what the
  scanners already decide (known CVEs, secrets, lint-level code smells).
- Passes 2 and 3 are scoped as DE-62 says: the upheld findings and the diff since the previous pass.

## 4. Models

- Reviewer seats: a fast model (for example sonnet).
- The arbitrator: the strongest model the session has (for example opus).
- A reviewer that can't finish its review is rerun, never skipped. A missing arbitrator means no verdict.

## 5. Cache

When the arbitrator rules PASS, record it with the arbitrator's record file:
`classify-risk.py ... --ruleset-version V --feed-version F --record PASS --report <arbitrator record>`. The record
must end in `Verdict: PASS`; its path and SHA-256 are stored, and a later lookup checks the file is unchanged and
still says PASS. Without both version flags there is no cache at all. The same command later reports
`cache_hit: true` for the identical change (same diff, classifier, rule-set version and feed version) when the PASS
was recorded at that tier or a higher one, in the same clone, for 30 days, and the session doesn't run that review
again. Releases and sampled
changes are never served from the cache. A FAIL clears nothing.

## 6. Report the cost

Each review's workflow step detail on Flight ends with the tier and the cost, so the savings can be checked:

    tier normal (sampled: no), 1 reviewer + arbitrator, 41k tokens, 3m10s

Release PANEL reports keep their own format (DE-59); the tier and cost go in the workflow step and the item's
notes, not in the PANEL file.

## 7. The threat feed and the SBOM

- `security-scan.py` runs `threat-feed.py` on every full scan and on a quick scan when a lockfile or manifest
  changed: every pinned package against OSV, and anything on the CISA KEV catalog as Critical. It reads npm
  (package-lock, yarn v1 and Berry, pnpm), PyPI (requirements and constraints files with their includes,
  Pipfile.lock, poetry.lock, uv.lock), Cargo, RubyGems, Packagist, NuGet and SwiftPM lockfiles. Like every scanner,
  any match blocks. So does an unreachable feed with no good copy under 48 hours old, a lockfile it can't parse, a
  version that isn't exact, and a symlinked lockfile. Every lockfile is read the way its installer reads it, and anything
  the reader can't place exactly is an error, never skipped (DE-102): strict UTF-8 with no byte order mark; CRLF read as
  LF, and a bare CR or any other character an installer may treat as a line break (\x0b, \x0c, \x1c to \x1e, \x85,
  U+2028, U+2029) refused; no line over 65,536 characters; a requirements file that names a source encoding other
  than UTF-8 in pip's first two lines refused; pip option lines split as pip splits them, every -r and -c include
  followed, and any option it doesn't know (or an abbreviation) refused; TOML read with tomllib where Python has it;
  pnpm keys strict, with YAML tags, anchors and escapes refused. A lockfile it has no reader for yet (Gradle, CocoaPods, Go and
  a few others) is a finding, `threat-feed:not-covered:<path>:<hash>`, which blocks until a reader is added or the
  finding is accepted in security/accepted-findings with an expiry and a board key. The cloud workspace can't reach
  OSV or CISA, so cloud sessions bring work to main through a pull request, where the required GitHub check runs it.
- Every release writes `security/SBOM-<platform>-<version>.json` with `sbom.py write` (built from the commit, not
  the working tree), and the pre-push hook refuses a version tag whose commit has no SBOM matching its lockfiles,
  whose SBOM names another version or platform, or that has a lockfile the SBOM can't describe and nobody accepted. The SBOM is recorded in Patchwork with the
  release, and the daily threat feed task checks shipped releases' SBOMs as well as main.

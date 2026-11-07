#!/usr/bin/env python3
"""Ghost Labs review risk classifier (DE-98, November 3, 2026). Deterministic; no network; no model.

Sorts a change into the review tier that decides how large its rule-set review panel is
(.githooks/REVIEW-TIERS.md, standing rules section 7):

  high    the full panel: 3 reviewers (attacker, secure code, supply chain) + arbitrator, 3-pass cap
  normal  1 reviewer (secure code lens) + arbitrator
  low     the scan report + arbitrator only

The arbitrator is in every pass at every tier (DE-58). The arbitrator may raise a tier, never lower it.

Rules, in the order they are applied:
  1. --release, or a version tag: always high (Larry, November 3, 2026: releases always get the full panel).
  2. Every changed file gets its own tier; the change's tier is the highest of them (mixed = highest).
  3. High when the path is security, build or supply-chain territory (HIGH_PATHS), when the file is a script,
     lockfile, manifest, config or migration, when it is a symlink, a submodule, or its mode changed, when the
     changed lines touch a HIGH_SIGNALS term, and when the file can't be read or placed (an unknown type).
  4. Low only for prose and images that can't run (LOW_EXTS), outside the high paths, with no high signal.
  5. Normal for other recognized source code.
  6. Any error, an empty change, or a change it can't diff: high. It never fails open.
  7. Random escalation sample: about 1 in 10 low or normal changes is raised to high. The draw is the change's
     own hash, so it is reproducible and checkable, and the only way to get a new draw is to change the work.

The cache key (SHA-256 of the diff, the classifier version, the rule-set version and the feed version) lets a
session skip re-reviewing an identical change that already passed in the same clone (.git/security-review/).

Usage:
  classify-risk.py [--rev REV] [--base BASE] [--release] [--ruleset-version V] [--feed-version V]
                   [--record PASS|FAIL] [--json]
Exit 0 with the tier printed (or JSON); exit 1 only for a usage error, and then the tier to use is high.
Changing this file, its tests or REVIEW-TIERS.md is itself a high change and needs a DE item (DE-98).
"""
import argparse, fnmatch, hashlib, json, os, re, shutil, subprocess, sys, time

VERSION = "1.2.0"
TIERS = ["low", "normal", "high"]
SAMPLE_PERCENT = 10
CONTEXT = 5   # lines of context around each change that the signal check also reads
CACHE_DAYS = 30

# Paths that are always high (fnmatch against the repo-relative path, lowercased).
HIGH_PATHS = [
    ".githooks/*", ".github/*", "security/*", "*/security/*", "release/*", "*/release/*", "scripts/*",
    "*/scripts/*", "ops/*", "*/ops/*", "infra/*", "*/infra/*", "*migrations/*", "*.entitlements",
    "*info.plist", "*androidmanifest.xml", "*wrangler.toml", "*wrangler.json", "*wrangler.jsonc",
    "*dockerfile", "*docker-compose*", "*.env", "*.env.*", "*/.env*", ".env*", "*sw.js", "*service-worker*",
    "*package.json", "*package-lock.json", "*npm-shrinkwrap.json", "*yarn.lock", "*pnpm-lock.yaml",
    "*requirements*.txt", "*pyproject.toml", "*poetry.lock", "*pipfile*", "*uv.lock", "*cargo.toml",
    "*cargo.lock", "*go.mod", "*go.sum", "*podfile*", "*package.resolved", "*build.gradle*",
    "*settings.gradle*", "*gradle.properties", "*gradle-wrapper.properties", "*.csproj", "*.sln",
    "*packages.lock.json", "*nuget.config", "*makefile", "*cmakelists.txt", "*.xcconfig", "*.pbxproj",
    "*.xcscheme", "*.plist", "*.mobileprovision", "*.p8", "*.p12", "*.pem", "*.key", "*.cer", "*.keystore",
    "*.jks", "*tsconfig*.json", "*vite.config*", "*webpack.config*", "*rollup.config*", "*esbuild*",
    "*.npmrc", "*.yarnrc*", "*.gitattributes", "*.gitmodules", "*.gitignore", "*_headers", "*_redirects",
    "*manifest.json", "*manifest.webmanifest", "*claude.md", "*agents.md", "*.claude/*", "*skill.md",
    # Security territory by name (pass 1 R1-1): any path segment or file name that says what it guards.
    "*auth*", "*session*", "*token*", "*secret*", "*crypto*", "*login*", "*logout*", "*signin*", "*signup*",
    "*password*", "*credential*", "*admin*", "*permission*", "*acl*", "*role*", "*policy*", "*route*",
    "*router*", "*middleware*", "*api*", "*oauth*", "*sso*", "*saml*", "*jwt*", "*csrf*", "*cors*", "*csp*",
    "*security*", "*guard*", "*intake*", "*webhook*", "*payment*", "*billing*", "*upload*", "*download*",
    # Worker and server code (A-1); a code file in a folder holding a wrangler config is high too (see below).
    "worker/*", "*/worker/*", "workers/*", "*/workers/*", "functions/*", "*/functions/*", "server/*",
    "*/server/*", "*worker*",
    # Build, sign, deploy and install scripts by folder and by role name, in any language (pass 2 R1-1).
    "script/*", "*/script/*", "bin/*", "*/bin/*", "tools/*", "*/tools/*", "tool/*", "*/tool/*", "build/*",
    "*/build/*", "ci/*", "*/ci/*", "tasks/*", "*/tasks/*", "hack/*", "*/hack/*", "deploy/*", "*/deploy/*",
    "*deploy*", "*install*", "*build*", "*release*", "*publish*", "*bootstrap*", "*migrat*", "*provision*",
    "*sign*", "*notar*", "*package*", "*bundle*", "*ship*", "*upgrade*", "*update*", "*setup*", "*cron*",
    # Build, install and test harness code (R1-7).
    "*setup.py", "*setup.cfg", "*build.rs", "*package.swift", "*conftest.py", "*.config.js", "*.config.cjs",
    "*.config.mjs", "*.config.ts", "*.config.mts", "*.config.cts", "*gulpfile*", "*gruntfile*", "*jenkinsfile",
    "*rakefile", "*gemfile*", "*constraints*.txt", "*pipfile.lock", "*composer.json", "*composer.lock",
    "*vagrantfile", "*procfile", "*justfile", "*taskfile*", "*.podspec",
    # Editor, tool and agent config that can run code (A-2, R1-10).
    ".vscode/*", "*/.vscode/*", ".devcontainer/*", "*/.devcontainer/*", ".idea/*", "*/.idea/*",
    "*.code-workspace", "*.eslintrc*", "*eslint.config*", "*.babelrc*", "*babel.config*", "*.prettierrc*",
    "*prettier.config*", "*renovate.json*", "*dependabot*", ".husky/*", "*/.husky/*", "*lefthook*",
    "*.pre-commit-config*", "*agent*.md", "*gemini.md", "*copilot-instructions.md", ".cursor/*", "*/.cursor/*",
    "*.cursorrules", "*.windsurfrules", "*.clinerules", "*.mcp.json", "*mcp.json",
]
# Extensions that run, configure or install: always high.
HIGH_EXTS = {".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".command", ".yml", ".yaml",
             ".toml", ".ini", ".cfg", ".conf", ".sql", ".plist", ".xml", ".pkg", ".dmg", ".exe", ".dll",
             ".so", ".dylib", ".a", ".o", ".jar", ".aar", ".apk", ".aab", ".ipa", ".wasm", ".zip", ".tar",
             ".gz", ".tgz", ".bin", ".node", ".pyc", ".lock", ".service", ".desktop", ".reg", ".vbs",
             ".applescript", ".scpt", ".workflow", ".mobileconfig", ".htaccess"}
# Recognized source code: normal unless a signal or a path makes it high.
CODE_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".py", ".swift", ".kt", ".kts",
             ".java", ".rs", ".cs", ".go", ".c", ".h", ".cc", ".cpp", ".hpp", ".m", ".mm", ".rb", ".php",
             ".html", ".htm", ".vue", ".svelte", ".json", ".graphql", ".proto", ".svg", ".xaml", ".storyboard",
             ".xib", ".strings", ".stringsdict", ".xcstrings", ".scss", ".sass", ".less"}
# Prose and images that can't run: low unless a path or a signal makes them more.
LOW_EXTS = {".md", ".markdown", ".txt", ".rst", ".adoc", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp",
            ".avif", ".ico", ".icns", ".heic", ".tif", ".tiff", ".bmp", ".pdf", ".woff", ".woff2", ".ttf",
            ".otf", ".mp3", ".wav", ".m4a", ".aac", ".mp4", ".mov"}
# Fonts, media and PDFs are low only as whole new or replaced files the scanners already see; text checks don't apply.
BINARY_LOW = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".icns", ".heic", ".tif", ".tiff",
              ".bmp", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".wav", ".m4a", ".aac", ".mp4", ".mov"}

# Terms in the changed lines (added or removed) that make any file high. Broad on purpose: a false high only
# costs tokens; a false low costs review.
HIGH_SIGNALS = re.compile(r"""(?ix)
  auth|login|logout|sign.?in|sign.?up|session|cookie|token|secret|passw|passphrase|credential|api.?key|bearer|
  oauth|openid|saml|jwt|jwk|csrf|xsrf|cors|origin|referer|same.?site|httponly|content.security|
  \bcsp\b|x-frame|strict-transport|hsts|permission|entitle|privilege|admin|\brole|\bacl\b|tenant|owner|
  crypto|cipher|encrypt|decrypt|hash|hmac|sha\d|md5|\baes\b|\brsa\b|ecdsa|ed25519|random|nonce|salt|signature|
  \bsign\(|verify|certificate|keychain|keystore|notar|codesign|
  fetch\(|xmlhttprequest|websocket|eventsource|sendbeacon|postmessage|\burl\(|https?://|\bwss?://|
  \bredirect|location\.|window\.open|navigator\.|\bimport\s*\(|require\s*\(|\bimport\b.+\bfrom\b|
  eval\(|new\s+function|settimeout\(\s*['"]|innerhtml|outerhtml|insertadjacenthtml|document\.write|
  dangerouslysetinnerhtml|v-html|\{\{\{|\|\s*safe|mark_safe|srcdoc|
  exec\(|execsync|spawn|child_process|subprocess|os\.system|popen|shell\s*=|runtime\.getruntime|process\.env|
  getenv|environ|\bfs\.|readfile|writefile|unlink|rmdir|chmod|chown|symlink|path\.join|\.\./|
  deseriali|pickle|yaml\.load|marshal|\bpickle\b|\bsql\b|select\s.+\sfrom|insert\s+into|\bupdate\s.+\sset\b|
  delete\s+from|\.prepare\(|\.query\(|\.raw\(|\bd1\b|\bkv\b|\br2\b|durable|binding|
  allowlist|blocklist|denylist|whitelist|blacklist|validate|sanitiz|escape|textcontent|
  nosec|nosemgrep|gitleaks|shellcheck|eslint-disable|ts-ignore|@ts-nocheck|noqa|
  webview|javascriptinterface|exported|debuggable|cleartext|nsapptransportsecurity|nsallowsarbitraryloads|
  @\[|ravenwood|patchwork|intake|webhook|worker|service.?binding|\brpc\b|
  fetch\s*\(|axios|\$\.(ajax|get|post|getjson)|superagent|got\(|ky\.|http\.(request|get)|https\.(request|get)|
  net\.(connect|createserver)|dgram|urlopen|urllib|requests\.|httpx|aiohttp|http\.client|socket|
  \.(get|post|put|delete|patch|all|use|route|on|handle)\s*\(|addeventlistener|\bon\w+\s*=|
  \.src\s*=|\bsrc\s*=|\bhref\s*=|\baction\s*=|formaction|//[a-z0-9-]+(\.[a-z0-9-]+)+|<script|<iframe|<form|
  <object|<embed|<link|<meta|<base|\bopen\s*\(|os\.remove|os\.rename|rmtree|shutil\.|tempfile|
  __import__|getattr\s*\(|setattr\s*\(|\.system\s*\(|importlib|
  localstorage|sessionstorage|indexeddb|caches\.|serviceworker|\bheaders\b|\bstatus\b|\bresponse\b|
  \brequest\b|\bwindow\[|globalthis|reflect\.|proxy\(|wasm|atob|btoa|buffer\.from|\bblob\b
""")
# Case-sensitive: the Function constructor runs a string as code; "function (" doesn't.
CASE_SIGNALS = re.compile(r"\bFunction\s*\(|\bnew\s+Function\b")
# In prose (Markdown, text), the code terms above are noise ("the Worker", "Ravenwood"), so prose is judged on what
# matters in prose: credentials, keys, and instructions to run or install something.
PROSE_SIGNALS = re.compile(r"""(?ix)
  secret|passw|passphrase|credential|api.?key|bearer|private.?key|begin\s[a-z ]*key|token|session.?id|
  \bssn\b|account.?number|\.sh\b|\.zsh\b|\.ps1\b|curl\s|wget\s|sudo\s|chmod\s|--no-verify|npx\s|pip\s+install|
  npm\s+(install|i)\b|brew\s+install|glrun|security\s+find-generic-password|disable|bypass|skip\s+the\s+(scan|hook|panel)
""")
PROSE_EXTS = {".md", ".markdown", ".txt", ".rst", ".adoc"}
# Low files that carry active content are at least normal.
LOW_ACTIVE = re.compile(r"(?i)<script|javascript:|@import|url\(|expression\(|behavior:|-moz-binding|<iframe|<object|<embed|on\w+\s*=")


def proc(args, root, text=True):
    """The one place this script starts a process: git, by its full path, a fixed argument list, no shell."""
    exe = shutil.which("git")
    if not exe:
        raise RuntimeError("git is not installed")
    return subprocess.run([exe, *args], cwd=root, capture_output=True, text=text)


def git(args, root, text=True):
    p = proc(args, root, text)
    if p.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {(p.stderr if text else p.stderr.decode(errors='replace')).strip()}")
    return p.stdout


def raise_to(cur, new):
    return new if TIERS.index(new) > TIERS.index(cur) else cur


def path_tier(path):
    """The tier a path alone gives, with the reason."""
    p = path.lower()
    for pat in HIGH_PATHS:
        if fnmatch.fnmatch(p, pat):
            return "high", f"high path ({pat})"
    base = os.path.basename(p)
    ext = os.path.splitext(base)[1]
    if not ext and base.startswith("."):
        return "high", "dotfile"
    if ext in HIGH_EXTS:
        return "high", f"runs or configures ({ext})"
    if ext in CODE_EXTS:
        return "normal", f"source code ({ext})"
    if ext in LOW_EXTS:
        return "low", f"prose or image ({ext})"
    return "high", f"unknown file type ({ext or 'no extension'})"


def classify(root, rev, base, release=False, ruleset_version="", feed_version="", salt=b""):
    out = {"classifier": VERSION, "rev": rev, "base": base, "tier": "high", "files": [], "reasons": [],
           "sampled": False, "release": bool(release), "cache_key": None, "cache_hit": None}
    try:
        rev_sha = git(["rev-parse", "--verify", f"{rev}^{{commit}}"], root).strip()
        base_sha = git(["rev-parse", "--verify", f"{base}^{{commit}}"], root).strip()
        out["rev"], out["base"] = rev_sha, base_sha
        # --no-renames: a rename is a delete plus an add, so both paths are judged. --no-ext-diff, --no-textconv:
        # the repo's own config can't change what the classifier reads.
        # Repo-controlled config can't hide or reshape anything: submodules are never ignored (.gitmodules
        # ignore=all, pass 1 R1-2), no prefix or relative tricks, no external diff or text conversion.
        pin = ["-c", "diff.ignoreSubmodules=none", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
               "-c", "diff.relative=false", "-c", "diff.external=", "-c", "core.quotePath=false"]
        flags = ["--no-renames", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", "--no-relative"]
        raw = git([*pin, "diff", "--raw", "-z", *flags, "--abbrev=40", base_sha, rev_sha], root)
        # Changed lines with context (pass 1 R1-1): a signal near the change counts too.
        patch = proc([*pin, "diff", *flags, "--binary", "--full-index", f"-U{CONTEXT}", base_sha, rev_sha], root, text=False)
        if patch.returncode:
            raise RuntimeError("git diff failed")
        diff_bytes = patch.stdout
    except Exception as e:  # anything it can't read is high
        out["reasons"].append(f"can't diff ({e}); high")
        return out

    entries = [x for x in raw.split("\0")]
    files = []
    i = 0
    while i < len(entries) - 1:
        meta, path = entries[i], entries[i + 1]
        i += 2
        if not meta.startswith(":"):
            out["reasons"].append(f"unexpected diff line ({meta[:40]}); high")
            return out
        old_mode, new_mode, _, _, status = meta[1:].split(" ")
        files.append((path, old_mode, new_mode, status))
    if not files:
        out["reasons"].append("no changes to classify; high")
        return out

    # Changed lines per file from the -U0 patch (added and removed lines; both count).
    # The path comes from the "diff --git a/P b/P" line (renames are off, so both sides are the same path; a quoted
    # or odd name doesn't parse and its file is then high). Header lines run until the first hunk, so a removed
    # line that starts with "--" is never mistaken for a header.
    lines = {}
    cur, in_header = None, False
    for ln in diff_bytes.split(b"\n"):
        if ln.startswith(b"diff --git a/"):
            s = ln[len(b"diff --git a/"):].decode("utf-8", "replace")
            n = (len(s) - 3) // 2
            cur = s[:n] if n > 0 and s[n:n + 3] == " b/" and s[n + 3:] == s[:n] else None
            in_header = True
            if cur is not None:
                lines.setdefault(cur, [])
        elif cur is None:
            continue
        elif in_header:
            if ln.startswith(b"@@"):
                in_header = False
            elif ln.startswith(b"GIT binary patch") or ln.startswith(b"Binary files "):
                lines[cur].append("\0binary")
                in_header = False
        elif ln[:1] in (b"+", b"-", b" "):
            lines[cur].append(ln[1:].decode("utf-8", "replace"))

    # Code under a folder holding a Worker config is Worker code (A-1).
    try:
        tracked = git(["ls-tree", "-r", "-z", "--name-only", rev_sha], root).split("\0")
    except Exception as e:
        out["reasons"].append(f"can't list the tree ({e}); high")
        return out
    worker_dirs = {os.path.dirname(t) for t in tracked
                   if os.path.basename(t).lower() in ("wrangler.toml", "wrangler.json", "wrangler.jsonc")}
    raw_paths = {f[0] for f in files}
    stray = set(lines) - raw_paths
    if stray:   # the patch names a file the raw list doesn't: something is off
        out["reasons"].append(f"diff lists disagree ({sorted(stray)[:3]}); high")
        return out

    tier = "low"
    for path, old_mode, new_mode, status in files:
        ft, why = path_tier(path)
        ext = os.path.splitext(path.lower())[1]
        modes = {m for m in (old_mode, new_mode) if m != "000000"}
        if modes - {"100644"}:
            ft, why = "high", f"mode {'/'.join(sorted(modes))} (executable, symlink or submodule)"
        if ft != "high" and ext in CODE_EXTS and any(d == "" or path.startswith(d + "/") for d in worker_dirs):
            ft, why = "high", "Worker code (a wrangler config is above it)"
        changed = lines.get(path)
        if ft != "high":
            if changed is None:   # any status, deletes included (pass 1 R1-8)
                ft, why = "high", "changed lines not readable"
            else:
                binary = any(c == "\0binary" for c in changed)
                if binary and ext not in BINARY_LOW:
                    ft, why = "high", "binary change in a non-media file"
                elif not binary and ext in BINARY_LOW:   # a "picture" git reads as text (pass 1 R2-7)
                    ft, why = "high", "text content in a media file"
                elif not binary:
                    text = "\n".join(changed)
                    m = (PROSE_SIGNALS if ext in PROSE_EXTS else HIGH_SIGNALS).search(text)
                    if not m and ext not in PROSE_EXTS:
                        m = CASE_SIGNALS.search("\n".join(changed))
                    if m:
                        ft, why = "high", f"changed lines touch '{m.group(0).strip()[:30]}'"
                    elif ft == "low" and LOW_ACTIVE.search(text):
                        ft, why = "normal", "active content in a prose or style file"
        out["files"].append({"path": path, "status": status, "tier": ft, "reason": why})
        tier = raise_to(tier, ft)

    if tier == "high":
        out["reasons"].append("at least one file is high")
    else:
        out["reasons"].append(f"every file is {tier} or lower")

    h = hashlib.sha256()
    for part in (b"DE-98", VERSION.encode(), ruleset_version.encode(), feed_version.encode(), diff_bytes):
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    out["cache_key"] = h.hexdigest()
    # The draw mixes in a random salt kept in this clone's .git, so an author can't compute it ahead of time
    # (pass 1 R1-4); main() also logs draws per base, so a redraw after a sample stays sampled.
    draw = hashlib.sha256(b"sample:" + salt + hashlib.sha256(diff_bytes).digest() + VERSION.encode()).digest()
    if tier != "high" and int.from_bytes(draw[:4], "big") % 100 < SAMPLE_PERCENT:
        out["sampled"] = True
        out["reasons"].append(f"random escalation sample ({SAMPLE_PERCENT}%): raised from {tier}; record any miss")
        tier = "high"
    if release:
        out["reasons"].append("release: always the full panel")
        tier = "high"
    out["tier"] = tier
    return out


def cache_dir(root):
    gd = git(["rev-parse", "--git-dir"], root).strip()
    return os.path.join(root if not os.path.isabs(gd) else "", gd, "security-review")


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def report_passes(path):
    """The arbitrator's record: its last Verdict line says PASS."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        verdicts = [ln.strip() for ln in fh if ln.strip().startswith("Verdict:")]
    return bool(verdicts) and verdicts[-1] == "Verdict: PASS"


def cache_lookup(root, key, tier):
    """An earlier PASS of this exact change at this tier or higher, in this clone, within CACHE_DAYS, whose
    arbitrator record still exists unchanged and still says PASS. Anything odd is no hit."""
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", key or ""):
            return None
        with open(os.path.join(cache_dir(root), key)) as fh:
            rec = json.load(fh)
        age = time.time() - float(rec["at"])
        if rec.get("verdict") != "PASS" or not 0 <= age <= CACHE_DAYS * 86400:
            return None
        if rec.get("tier") not in TIERS or TIERS.index(rec["tier"]) < TIERS.index(tier):
            return None
        rp = rec.get("report")
        if not rp or not os.path.isfile(rp) or sha256_file(rp) != rec.get("report_sha256") or not report_passes(rp):
            return None
        return rec
    except Exception:  # a corrupt record is no hit (pass 1 R2-8)
        return None


def cache_record(root, key, tier, verdict, report):
    d = cache_dir(root)
    os.makedirs(d, exist_ok=True)
    rec = {"tier": tier, "verdict": verdict, "at": int(time.time())}
    if verdict == "PASS":
        rp = os.path.abspath(report)
        if not report_passes(rp):
            raise RuntimeError(f"{report} doesn't end in Verdict: PASS")
        rec.update(report=rp, report_sha256=sha256_file(rp))
    with open(os.path.join(d, key + ".tmp"), "w") as fh:
        json.dump(rec, fh)
    os.replace(os.path.join(d, key + ".tmp"), os.path.join(d, key))


def clone_salt(root):
    """A random value made once per clone and kept in .git, never committed."""
    d = cache_dir(root)
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "salt")
    try:
        with open(f, "rb") as fh:
            v = fh.read()
        if len(v) == 32:
            return v
    except OSError:
        pass
    v = os.urandom(32)
    with open(f + ".tmp", "wb") as fh:
        fh.write(v)
    os.replace(f + ".tmp", f)
    return v


def draw_log(root, base, sampled):
    """Logs each draw per base. Returns True when an earlier draw for this base was sampled."""
    f = os.path.join(cache_dir(root), "draws.log")
    before = False
    try:
        with open(f) as fh:
            before = any(ln.split()[:2] == [base, "sampled"] for ln in fh if ln.strip())
    except OSError:
        pass
    with open(f, "a") as fh:
        fh.write(f"{base} {'sampled' if sampled else 'not-sampled'} {int(time.time())}\n")
    return before


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ghost Labs review risk classifier (DE-98)")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--base", help="what the review starts from (default: merge-base with origin's default branch)")
    ap.add_argument("--release", action="store_true", help="a release review: always high")
    ap.add_argument("--ruleset-version", default="", help="e.g. the standing rules' SHA-256 or date")
    ap.add_argument("--feed-version", default="", help="the threat feed snapshot's SHA-256")
    ap.add_argument("--record", choices=["PASS", "FAIL"], help="record this change's arbitrator verdict in the cache")
    ap.add_argument("--report", help="with --record PASS: the arbitrator's record whose last verdict is PASS")
    ap.add_argument("--json", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        print("high")
        return 1 if e.code else 0
    root = os.getcwd()
    try:
        root = git(["rev-parse", "--show-toplevel"], root).strip()
        base = a.base
        if not base:
            try:
                default = git(["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"], root).strip().split("/", 1)[1]
            except Exception:  # no origin/HEAD: the usual default
                default = "main"
            base = git(["merge-base", a.rev, f"refs/remotes/origin/{default}"], root).strip()
        tags = git(["tag", "--points-at", a.rev], root).split()
        rel = a.release or any(re.search(r"\d+\.\d+", t) for t in tags)
        res = classify(root, a.rev, base, rel, a.ruleset_version, a.feed_version, clone_salt(root))
        if res.get("cache_key") and not res["release"]:
            pre = res["tier"]
            if draw_log(root, res["base"], res["sampled"]) and not res["sampled"] and pre != "high":
                res["sampled"] = True
                res["reasons"].append("this base was sampled before: a redraw stays sampled")
                res["tier"] = "high"
    except Exception as e:
        res = {"classifier": VERSION, "tier": "high", "reasons": [f"error ({e}); high"], "files": [],
               "sampled": False, "release": True, "cache_key": None, "cache_hit": None}
    try:
        res["cache_hit"] = False
        versions = bool(a.ruleset_version and a.feed_version)
        if res.get("cache_key") and versions:
            if a.record:
                if a.record == "PASS" and not a.report:
                    raise RuntimeError("--record PASS needs --report (the arbitrator's record)")
                cache_record(root, res["cache_key"], res["tier"], a.record, a.report)
            hit = cache_lookup(root, res["cache_key"], res["tier"])
            res["cache_hit"] = bool(hit) and not res["release"] and not res["sampled"]
        elif a.record or res.get("cache_key"):
            res["reasons"].append("no cache: --ruleset-version and --feed-version are both needed for the cache")
            if a.record:
                raise RuntimeError("--record needs --ruleset-version and --feed-version")
    except Exception as e:
        res["cache_hit"] = False
        res["reasons"].append(f"cache not used ({e})")
        if a.record:
            print("high")
            print(f"  {e}", file=sys.stderr)
            return 1
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(res["tier"])
        for r in res["reasons"]:
            print(f"  {r}", file=sys.stderr)
        for f in res["files"]:
            print(f"  {f['tier']:6} {f['path']}  ({f['reason']})", file=sys.stderr)
        if res.get("cache_hit"):
            print("  cache: this exact change already passed at this tier in this clone; no re-review needed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

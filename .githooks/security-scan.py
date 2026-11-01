#!/usr/bin/env python3
"""Ghost Labs security scan (DE-49). Called by .githooks/pre-push; also runs by hand.

Runs the full standing-rules section 1 static scan over the exact commit being pushed and refuses
the push on ANY finding, unless the finding is listed, unexpired, in security/accepted-findings.

  Secrets       gitleaks over the full git history reachable from the commit
  Code          semgrep (p/default, p/secrets and a pack per language found), bandit for Python,
                shellcheck for sh/bash scripts
  Dependencies  pip-audit (requirements*.txt, pyproject.toml), npm audit (package-lock.json),
                cargo audit (Cargo.lock)

Fails closed: a missing scanner, a scanner error, a ruleset that can't download, or a bad allowlist
entry all block, the same as a finding. Checks that need a build or a running app (Apple bundle,
Android manifest, live attack tests) stay in the release gates (standing rules, section 1).

Two modes (DE-56, October 30, 2026). pre-push picks: full for the default branch and tags, quick otherwise.
  full   everything above (main, tags, the GitHub check, release gates).
  quick  feature-branch pushes: gitleaks over the new commits only (BASE..REV), semgrep, bandit, shellcheck and
         the inline-disable check on the files changed since BASE, and each dependency audit only where its
         lockfile or manifest changed. Allowlist, pin and ignore-file checks always run in full. Any finding blocks.

Usage:
  security-scan.py [--rev REV] [--mode full|quick] [--base BASE] [--report FILE] [--quiet]
    --rev     commit, branch or tag to scan (default HEAD)
    --mode    full (default) or quick; quick needs --base and falls back to full without a usable one
    --base    for quick: the commit already scanned (the remote branch tip or the merge-base with main)
    --report  also write the Markdown report here (always written to .git/security-scan/)
Exit 0 = PASS, 1 = findings or errors (push refused), 2 = usage error.

Allowlist, security/accepted-findings (one entry per line, # starts a comment):
  <finding id> | <expires YYYY-MM-DD> | <reason, with the board key that tracks the fix>
  path:<tool or *>:<glob> | <expires> | <reason>        skips one tool (or all) under a path
Entries must expire within 180 days. An expired, malformed or too-long entry blocks the push.
Every entry is recorded in the Ghost Labs Security Program (section 6) before it is committed.
Finding ids are printed in the report, ready to copy.
"""
import argparse, datetime, fnmatch, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time

MAX_DAYS = 180
CACHE_HOURS = 12
SKIP_DIRS = ["node_modules", ".git", "build", "dist", ".venv", "venv", "__pycache__", "DerivedData",
             ".build", "Pods", "target", ".gradle", ".wrangler", "vendor"]
SEMGREP_PACKS = {".py": "p/python", ".js": "p/javascript", ".mjs": "p/javascript", ".ts": "p/typescript",
                 ".tsx": "p/typescript", ".swift": "p/swift", ".kt": "p/kotlin", ".kts": "p/kotlin",
                 ".rs": "p/rust", ".cs": "p/csharp", ".go": "p/golang", ".java": "p/java"}
BREW = {"gitleaks": "gitleaks", "semgrep": "semgrep", "bandit": "bandit", "shellcheck": "shellcheck",
        "pip-audit": "pip-audit", "npm": "node", "cargo-audit": "cargo-audit"}


def run(cmd, cwd=None, timeout=1800, text=True, data=None, extra_env=None):
    """The one place this script starts a process: a fixed argument list, no shell, the tool's full path."""
    exe = shutil.which(cmd[0])
    if not exe:
        raise RuntimeError(f"{cmd[0]} is not installed")
    env = dict(os.environ, SEMGREP_SEND_METRICS="off", NO_COLOR="1", **(extra_env or {}))
    return subprocess.run([exe, *cmd[1:]], cwd=cwd, capture_output=True, text=text, timeout=timeout, env=env, input=data)


def sh(cmd, cwd=None, timeout=1800):
    p = run(cmd, cwd=cwd, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def h12(text):
    return hashlib.sha256(" ".join(str(text).split()).encode()).hexdigest()[:12]


RULE_CACHE = os.path.expanduser("~/.cache/ghost-labs-security/semgrep")
RULES_FRESH_H, RULES_MAX_DAYS = 24, 7


def is_rules(body):
    """A Semgrep rule pack as the registry sends it: YAML starting "rules:", or (since late October 2026) JSON with a
    non-empty "rules" list after a YAML "---" line; semgrep reads both. Anything else (an HTML page, an error) isn't."""
    text = body.lstrip()
    if text.startswith(b"---"):
        text = text[3:].lstrip()
    if text.startswith(b"rules:"):
        return True
    try:
        d = json.loads(text)
    except ValueError:
        return False
    return isinstance(d, dict) and isinstance(d.get("rules"), list) and len(d["rules"]) > 0


def rule_pack(pack, errors):
    """A local copy of a Semgrep registry pack: refreshed daily, used up to 7 days old if the registry can't be
    reached, so a registry outage doesn't stop pushes but stale rules do. Returns the file, or None (an error)."""
    os.makedirs(RULE_CACHE, exist_ok=True)
    f = os.path.join(RULE_CACHE, pack.replace("/", "_") + ".yml")
    age = time.time() - os.path.getmtime(f) if os.path.exists(f) else None
    if age is None or age > RULES_FRESH_H * 3600:
        try:
            got = run(["curl", "-fsSL", "--proto", "=https", "--max-time", "30", f"https://semgrep.dev/c/{pack}"], text=False)
            if got.returncode:
                raise RuntimeError(f"curl exit {got.returncode}")
            body = got.stdout
            if not is_rules(body):
                raise ValueError("not a rules file")
            with open(f + ".tmp", "wb") as fh:
                fh.write(body)
            os.replace(f + ".tmp", f)
            return f
        except Exception as e:
            if age is not None and age < RULES_MAX_DAYS * 86400:
                print(f"security-scan: Semgrep registry unreachable ({e}); using {pack} from {int(age // 3600)}h ago", file=sys.stderr)
                return f
            errors.append(f"semgrep {pack}: can't download the rules ({e}) and no copy under {RULES_MAX_DAYS} days old")
            return None
    return f


def git(*args):
    rc, out, err = sh(["git", *args])
    if rc:
        raise RuntimeError(f"git {' '.join(args)}: {err.strip()}")
    return out.strip()


class Scan:
    def __init__(self, root, rev, base=None):
        self.root, self.rev, self.base = root, rev, base   # base set = quick mode
        self.tree = None   # the checked-out scan tree, set by main()
        self.findings = []   # dicts: id, tool, severity, path, line, title
        self.errors = []     # strings: anything that stopped a scanner from giving a full answer
        self.ran = []        # (tool, what) pairs

    def need(self, tool):
        if shutil.which(tool):
            return True
        self.errors.append(f"{tool} is not installed (brew install {BREW.get(tool, tool)})")
        return False

    def add(self, tool, rule, path, line, severity, title, key):
        fid = f"{tool}:{rule}:{path}:{h12(key)}"
        self.findings.append(dict(id=fid, tool=tool, rule=rule, path=path, line=line,
                                  severity=severity, title=(title or "").strip().splitlines()[0][:200] if title else ""))

    # --- the scanners -------------------------------------------------------------------------------
    def gitleaks(self):
        if not self.need("gitleaks"):
            return
        m = re.search(r"(\d+)\.(\d+)", git("--version"))
        if not m or (int(m.group(1)), int(m.group(2))) < (2, 36):
            self.errors.append(f"git 2.36 or newer is needed to scan merge commits ({git('--version')}); brew install git")
            return
        with tempfile.TemporaryDirectory() as t:
            rep = os.path.join(t, "g.json")
            rc, out, err = sh(["gitleaks", "git", self.root, "--no-banner", "--redact", "--exit-code", "1",
                               "--ignore-gitleaks-allow", "--gitleaks-ignore-path", t,
                               # --diff-merges=remerge: a merge shows what its author changed beyond git's own merge,
                               # so a secret added while resolving a merge is seen (git log -p shows merges empty).
                               f"--log-opts=--diff-merges=remerge {f'{self.base}..{self.rev}' if self.base else self.rev}",
                               "--report-format", "json", "--report-path", rep])
            self.ran.append(("gitleaks", f"new commits {self.base[:9]}..{self.rev[:9]}" if self.base
                             else f"history reachable from {self.rev}"))
            if rc not in (0, 1) or not os.path.exists(rep):
                self.errors.append(f"gitleaks exit {rc}: {(err or out).strip()[-300:]}")
                return
            for f in json.load(open(rep)) or []:
                fp = f.get("File") or ""
                if fp.startswith("b/") and not os.path.exists(os.path.join(self.tree or "", fp)) \
                        and os.path.exists(os.path.join(self.tree or "", fp[2:])):
                    f["File"] = fp[2:]   # gitleaks misreads remerge's CONFLICT header and keeps the diff's b/ prefix
                self.add("gitleaks", f.get("RuleID"), f.get("File"), f.get("StartLine"), "SECRET",
                         f"{f.get('Description')} in commit {str(f.get('Commit'))[:9]}", f.get("Fingerprint"))

    def semgrep(self, tree, exts, files=None):
        if files is not None and not files:
            self.ran.append(("semgrep", "no changed files"))
            return
        if not self.need("semgrep"):
            return
        packs = ["p/default", "p/secrets"] + sorted({SEMGREP_PACKS[e] for e in exts if e in SEMGREP_PACKS})
        cmd = ["semgrep", "scan", "--metrics=off", "--json", "--quiet", "--timeout", "60", "--disable-nosem"]
        for p in packs:
            f = rule_pack(p, self.errors)
            if f:
                cmd += ["--config", f]
        if "--config" not in cmd:
            return
        for d in SKIP_DIRS:
            cmd += ["--exclude", d]
        targets = [tree] if files is None else [os.path.join(tree, f) for f in files]
        rc, out, err = sh(cmd + targets, timeout=3600)
        self.ran.append(("semgrep", " ".join(packs) + ("" if files is None else f" on {len(files)} changed file(s)")))
        try:
            d = json.loads(out)
        except Exception:
            self.errors.append(f"semgrep exit {rc}, no JSON: {err.strip()[-300:]}")
            return
        for e in d.get("errors", []):
            lvl = str(e.get("level", "error")).lower()
            if lvl in ("warn", "warning", "info"):
                continue
            self.errors.append(f"semgrep: {e.get('type')} {str(e.get('message'))[:200]}")
        for r in d.get("results", []):
            path = os.path.relpath(r["path"], tree)
            ex = r.get("extra", {})
            line = r.get("start", {}).get("line")
            try:  # key on the source line itself (newer semgrep hides extra.lines without a login)
                text = open(os.path.join(tree, path), errors="replace").read().splitlines()[line - 1]
            except Exception:
                text = f"{r.get('check_id')}{path}{line}"
            cid = str(r.get("check_id")).split("ghost-labs-security.semgrep.", 1)[-1]  # drop the cache-path prefix
            self.add("semgrep", cid, path, line, ex.get("severity", "?"), ex.get("message"), text)

    def bandit(self, tree, files=None):
        if files is not None and not files:
            return
        if not self.need("bandit"):
            return
        targets = ["-r", tree] if files is None else [os.path.join(tree, f) for f in files]
        rc, out, err = sh(["bandit", *targets, "-f", "json", "-q", "--ignore-nosec", "-x", ",".join(f"*/{d}/*" for d in SKIP_DIRS)])
        self.ran.append(("bandit", "all Python, every severity" if files is None else f"{len(files)} changed Python file(s), every severity"))
        try:
            d = json.loads(out)
        except Exception:
            self.errors.append(f"bandit exit {rc}, no JSON: {err.strip()[-300:]}")
            return
        for e in d.get("errors", []):
            self.errors.append(f"bandit: {os.path.relpath(e.get('filename', ''), tree)}: {e.get('reason')}")
        for r in d.get("results", []):
            path = os.path.relpath(r["filename"], tree)
            text = r.get("issue_text") or ""
            if r.get("test_id") in ("B105", "B106", "B107"):  # never echo a possible secret into the report
                text = re.sub(r"'[^']{4,}'", "'<redacted>'", text)
            try:  # key on the flagged source line itself, so ids survive edits to nearby lines
                src = open(os.path.join(tree, path), errors="replace").read().splitlines()[r.get("line_number") - 1]
            except Exception:
                src = f"{r.get('test_id')}{path}{r.get('line_number')}"
            self.add("bandit", r.get("test_id"), path, r.get("line_number"), r.get("issue_severity"), text, src)

    def shellcheck(self, tree, scripts):
        if not scripts or not self.need("shellcheck"):
            return
        for i in range(0, len(scripts), 200):
            chunk = scripts[i:i + 200]
            rc, out, err = sh(["shellcheck", "-f", "json1", "-x", *[os.path.join(".", c) for c in chunk]], cwd=tree)
            try:
                d = json.loads(out)
            except Exception:
                self.errors.append(f"shellcheck exit {rc}: {err.strip()[-300:]}")
                continue
            for c in d.get("comments", []):
                path = os.path.normpath(c["file"])
                try:
                    text = open(os.path.join(tree, path), errors="replace").read().splitlines()[c["line"] - 1]
                except Exception:
                    text = f"{c['code']}{c['line']}"
                self.add("shellcheck", f"SC{c['code']}", path, c["line"], c.get("level"), c.get("message"), text)
        self.ran.append(("shellcheck", f"{len(scripts)} sh/bash scripts"))

    def pip_audit(self, tree, reqs, projects):
        if not (reqs or projects) or not self.need("pip-audit"):
            return
        targets = [["-r", r] for r in reqs] + [[p] for p in projects]
        for t in targets:
            rc, out, err = sh(["pip-audit", "-f", "json", "--progress-spinner", "off", *t], cwd=tree, timeout=1800)
            label = t[-1]
            try:
                d = json.loads(out)
            except Exception:
                self.errors.append(f"pip-audit {label}: exit {rc}: {err.strip()[-300:]}")
                continue
            deps = d.get("dependencies", d) if isinstance(d, dict) else d
            for dep in deps:
                if "skip_reason" in dep:
                    continue
                for v in dep.get("vulns", []):
                    self.add("pip-audit", v.get("id"), label, None, "VULN",
                             f"{dep['name']} {dep.get('version')}: {v.get('description', '')}", f"{dep['name']}{dep.get('version')}")
            self.ran.append(("pip-audit", label))

    def npm_audit(self, tree, locks):
        if not locks or not self.need("npm"):
            return
        for lock in locks:
            d0 = os.path.dirname(lock) or "."
            rc, out, err = sh(["npm", "audit", "--package-lock-only", "--json"], cwd=os.path.join(tree, d0))
            try:
                d = json.loads(out)
            except Exception:
                self.errors.append(f"npm audit {lock}: exit {rc}: {err.strip()[-300:]}")
                continue
            if "error" in d:
                self.errors.append(f"npm audit {lock}: {str(d['error'])[:300]}")
                continue
            for name, v in (d.get("vulnerabilities") or {}).items():
                for via in v.get("via", []):
                    if isinstance(via, dict):
                        self.add("npm-audit", f"GHSA:{via.get('source')}", lock, None, via.get("severity"),
                                 f"{name}: {via.get('title')}", f"{name}{via.get('range')}")
            self.ran.append(("npm audit", lock))

    def cargo_audit(self, tree, locks):
        if not locks:
            return
        if not shutil.which("cargo-audit") and not shutil.which("cargo"):
            self.errors.append("cargo-audit is not installed (brew install cargo-audit)")
            return
        exe = ["cargo-audit", "audit"] if shutil.which("cargo-audit") else ["cargo", "audit"]
        for lock in locks:
            rc, out, err = sh([*exe, "--json", "--file", lock], cwd=tree)
            try:
                d = json.loads(out)
            except Exception:
                self.errors.append(f"cargo audit {lock}: exit {rc}: {err.strip()[-300:]}")
                continue
            for v in (d.get("vulnerabilities") or {}).get("list", []):
                a, p = v.get("advisory", {}), v.get("package", {})
                self.add("cargo-audit", a.get("id"), lock, None, "VULN", f"{p.get('name')} {p.get('version')}: {a.get('title')}",
                         f"{p.get('name')}{p.get('version')}")
            for kind, items in (d.get("warnings") or {}).items():
                for w in items:
                    a, p = w.get("advisory") or {}, w.get("package") or {}
                    self.add("cargo-audit", a.get("id") or kind, lock, None, kind.upper(),
                             f"{p.get('name')} {p.get('version')}: {a.get('title') or kind}", f"{p.get('name')}{p.get('version')}{kind}")
            self.ran.append(("cargo audit", lock))


SUPPRESS_FILES = [".gitleaksignore", ".gitleaks.toml", ".semgrepignore", ".bandit"]
SUPPRESS_RE = re.compile(r"#\s*shellcheck\s+disable=")


def suppressions(s, tree, scripts):
    """Every exception goes through security/accepted-findings, so in-code and ignore-file suppressions are findings."""
    for dp, dns, fns in os.walk(tree):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for f in fns:
            if f in SUPPRESS_FILES:
                p = os.path.relpath(os.path.join(dp, f), tree)
                s.add("suppression", f, p, None, "SUPPRESS", f"{f} would hide findings; use security/accepted-findings", open(os.path.join(dp, f), errors="replace").read())
    for p in scripts:
        for n, line in enumerate(open(os.path.join(tree, p), errors="replace"), 1):
            if SUPPRESS_RE.search(line):
                s.add("suppression", "shellcheck-disable", p, n, "SUPPRESS", "inline shellcheck disable; use security/accepted-findings", line)
    s.ran.append(("suppression check", "ignore files and inline disables"))


def inventory(tree):
    exts, scripts, reqs, projects, npm, cargo = set(), [], [], [], [], []
    for dp, dns, fns in os.walk(tree):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        rel = os.path.relpath(dp, tree)
        for f in fns:
            p = os.path.normpath(os.path.join(rel, f))
            ext = os.path.splitext(f)[1].lower()
            exts.add(ext)
            if f == "package-lock.json":
                npm.append(p)
            elif f == "Cargo.lock":
                cargo.append(p)
            elif re.fullmatch(r"requirements.*\.txt", f):
                reqs.append(p)
            elif f == "pyproject.toml":
                projects.append(os.path.dirname(p) or ".")
            if ext in (".sh", ".bash") or (ext == "" and not os.path.islink(os.path.join(dp, f))):
                try:
                    with open(os.path.join(dp, f), "rb") as fh:
                        first = fh.readline(120)
                except Exception:
                    first = b""
                if ext in (".sh", ".bash") and not re.match(rb"#!.*\bzsh\b", first):
                    scripts.append(p)
                elif ext == "" and re.match(rb"#!\s*/(usr/)?bin/(env\s+)?(ba)?sh\b", first):
                    scripts.append(p)
    return exts, sorted(scripts), sorted(reqs), sorted(projects), sorted(npm), sorted(cargo)


MAX_PIN_DAYS = 30
PIN_WARN_DAYS = 7


def check_pins(tree, commit, today):
    """Pinned downloads (DE-55). security/pins lists the files that name third-party code a build downloads and runs:
        <pin file path> | <max days, at most 30> | <what it pins, naming its board key>
    Each pin file, exactly as committed, needs a passing review: security/PIN-<name>-<YYYY-MM-DD>.md with the lines
        Pin-File: <path>   Pin-Blob: <git blob hash of that file>   Date: <YYYY-MM-DD>   Result: PASS
    A pin file changed without such a review blocks. So does a review older than its max days: an old pin is as
    dangerous as an unchecked one, so it must be refreshed (or reviewed again) to push. Returns (problems, notes)."""
    problems, notes = [], []
    manifest = os.path.join(tree, "security", "pins")
    if not os.path.exists(manifest):
        return problems, notes
    reports = []
    secdir = os.path.join(tree, "security")
    for name in sorted(os.listdir(secdir)):
        if not (name.startswith("PIN-") and name.endswith(".md")):
            continue
        fields = {}
        for line in open(os.path.join(secdir, name), encoding="utf-8", errors="replace"):
            m = re.match(r"^(Pin-File|Pin-Blob|Date|Result):\s*(\S+)", line)
            if m and m.group(1) not in fields:
                fields[m.group(1)] = m.group(2)
        reports.append((name, fields))
    for n, raw in enumerate(open(manifest, encoding="utf-8"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [x.strip() for x in line.split("|")]
        where = f"security/pins line {n}"
        if len(parts) != 3 or not parts[1].isdigit() or not re.search(r"[A-Z][A-Z0-9]{0,4}-[0-9]+", parts[2]):
            problems.append(f"{where}: needs '<pin file> | <max days, 30 or less> | <what, with its board key>'")
            continue
        path, max_days = parts[0], min(int(parts[1]), MAX_PIN_DAYS)
        got = run(["git", "rev-parse", f"{commit}:{path}"])
        if got.returncode:
            problems.append(f"{where}: {path} is not in this commit")
            continue
        blob = got.stdout.strip()
        dated = []
        for name, f in reports:
            if f.get("Pin-File") == path and f.get("Pin-Blob") == blob and f.get("Result") == "PASS":
                try:
                    dated.append((datetime.date.fromisoformat(f.get("Date", "")), name))
                except ValueError:
                    problems.append(f"security/{name}: Date is not YYYY-MM-DD")
        if not dated:
            problems.append(f"pinned download {path} (blob {blob[:12]}) has no passing review: refresh it and write "
                            f"security/PIN-<name>-<date>.md with Pin-File: {path}, Pin-Blob: {blob}, Date and Result: PASS")
            continue
        when, name = max(dated)
        age = (today - when).days
        if age > max_days:
            problems.append(f"pinned download {path}: its review ({name}, {when}) is {age} days old, past {max_days}; "
                            f"refresh the pin to the current upstream release, or review it again")
        elif age > max_days - PIN_WARN_DAYS:
            notes.append(f"pinned download {path}: review {when} expires in {max_days - age} days; refresh it soon")
        else:
            notes.append(f"pinned download {path}: reviewed {when} ({name}), {max_days - age} days left")
    return problems, notes


def load_allowlist(path, today):
    entries, problems = [], []
    if not os.path.exists(path):
        return entries, problems
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        where = f"security/accepted-findings line {n}"
        if len(parts) != 3 or not all(parts):
            problems.append(f"{where}: needs '<id> | <expires YYYY-MM-DD> | <reason>'")
            continue
        fid, exp, reason = parts
        try:
            expd = datetime.date.fromisoformat(exp)
        except ValueError:
            problems.append(f"{where}: expiry '{exp}' is not YYYY-MM-DD")
            continue
        if expd < today:
            problems.append(f"{where}: expired {exp} ({fid}); fix the finding or renew it with a reason")
            continue
        if (expd - today).days > MAX_DAYS:
            problems.append(f"{where}: expiry {exp} is more than {MAX_DAYS} days out")
            continue
        if not re.search(r"[A-Z][A-Z0-9]{0,4}-[0-9]+", reason):
            problems.append(f"{where}: the reason must name the board key that tracks it (e.g. DE-49)")
            continue
        if fid.startswith("path:"):
            bits = fid.split(":", 2)
            # A path entry must start at a named folder or file: '*', '**/x' or '?' first would switch off a scanner
            # for the whole repo (DE-56 review).
            if len(bits) != 3 or not bits[2] or bits[2][0] in "*?[" or bits[1] == "*" and "/" not in bits[2]:
                problems.append(f"{where}: path entries must name a folder (path:<tool>:<folder>/<glob>), not match the whole repo")
                continue
        entries.append(dict(id=fid, expires=exp, reason=reason, line=n))
    return entries, problems


def allowed(f, entries):
    for e in entries:
        if e["id"].startswith("path:"):
            _, tool, glob = e["id"].split(":", 2)
            if tool in ("*", f["tool"]) and f.get("path") and fnmatch.fnmatch(f["path"], glob):
                return e
        elif e["id"] == f["id"]:
            return e
    return None


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--report")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--mode", choices=("full", "quick"), default="full")
    ap.add_argument("--base")
    a = ap.parse_args()
    root = git("rev-parse", "--show-toplevel")
    os.chdir(root)
    gitdir = git("rev-parse", "--git-common-dir")
    commit = git("rev-parse", f"{a.rev}^{{commit}}")
    tree_id = git("rev-parse", f"{a.rev}^{{tree}}")
    today = datetime.date.today()
    # Quick mode scans what is new since a base that was already scanned. No usable base means the full scan.
    base, mode_note = None, "full scan"
    if a.mode == "quick":
        mb = ""
        if a.base and not re.fullmatch(r"0+", a.base):
            rc, out, _ = sh(["git", "merge-base", a.base, commit])
            mb = out.strip() if rc == 0 else ""
        if mb and mb != commit:
            base = mb
        elif mb == commit:
            base = commit   # nothing new: only the always-on checks
        else:
            mode_note = f"full scan (quick asked, but no usable base{' ' + a.base[:9] if a.base else ''})"
    outdir = os.path.join(os.path.abspath(gitdir), "security-scan")
    os.makedirs(outdir, exist_ok=True)

    # The allowlist comes from the commit being pushed, not the working tree.
    with tempfile.TemporaryDirectory(prefix="gl-scan-") as tree:
        # Every tracked file of the commit, through a private index. Not git archive: it drops export-ignore paths.
        with tempfile.TemporaryDirectory(prefix="gl-idx-") as ix:
            idx = {"GIT_INDEX_FILE": os.path.join(ix, "index")}
            if run(["git", "read-tree", commit], extra_env=idx).returncode or \
                    run(["git", "checkout-index", "-a", "-f", f"--prefix={tree}/"], extra_env=idx).returncode:
                raise RuntimeError(f"could not check out {commit[:9]} to scan")
        alpath = os.path.join(tree, "security", "accepted-findings")
        alhash = h12(open(alpath).read()) if os.path.exists(alpath) else "none"
        changed = None   # None = whole tree (full); a set of paths = quick
        if base:
            rc, out, err = sh(["git", "diff", "--name-only", "--no-renames", "--diff-filter=ACMRT", "-z", base, commit])
            if rc:
                raise RuntimeError(f"git diff {base[:9]}..{commit[:9]}: {err.strip()}")
            changed = {p for p in out.split("\0") if p and os.path.isfile(os.path.join(tree, p))
                       and not any(part in SKIP_DIRS for part in p.split("/")[:-1])}
            mode_note = f"quick scan: {len(changed)} changed file(s) since {base[:9]}"

        cache = os.path.join(outdir, "pass-cache.json")
        try:
            c = json.load(open(cache))
            # Keyed on the commit, not the tree: the same tree can sit on top of a history that added and removed a
            # secret. A full pass covers a later scan of the same commit; a quick pass only the same commit and base.
            mode_ok = c.get("commit") == commit and (c.get("mode") == "full" or (base and c.get("base") == base))
            if mode_ok and c.get("tree") == tree_id and c.get("allow") == alhash and c.get("day") == str(today) \
                    and time.time() - c.get("at", 0) < CACHE_HOURS * 3600 and c.get("max_exp_ok", "") >= str(today):
                if not a.quiet:
                    print(f"security-scan: PASS (same commit {commit[:9]} passed at {time.strftime('%H:%M', time.localtime(c['at']))})", file=sys.stderr)
                return 0
        except (OSError, ValueError, KeyError, TypeError):
            print("security-scan: no usable pass cache, running the full scan", file=sys.stderr) if not a.quiet else None

        s = Scan(root, commit, base if changed is not None else None)
        s.tree = tree
        exts, scripts, reqs, projects, npm, cargo = inventory(tree)
        files = py = None
        if changed is not None:
            def touched(dir_, names):   # a dependency audit runs when its lockfile or a manifest beside it changed
                return any(os.path.normpath(os.path.join(dir_, n)) in changed for n in names)
            files = sorted(changed)
            py = [f for f in files if f.endswith(".py")]
            exts = {os.path.splitext(f)[1].lower() for f in files}
            scripts = [p for p in scripts if p in changed]
            reqs = [r for r in reqs if r in changed]
            projects = [d for d in projects if touched(d, ["pyproject.toml", "uv.lock", "poetry.lock"])]
            npm = [l for l in npm if touched(os.path.dirname(l), ["package-lock.json", "package.json"])]
            cargo = [l for l in cargo if l in changed or any(f.endswith("Cargo.toml") and f.startswith(os.path.dirname(l)) for f in files)]
            s.ran.append(("mode", mode_note))
        entries, problems = load_allowlist(alpath, today)
        pin_problems, pin_notes = check_pins(tree, commit, today)
        problems += pin_problems
        if os.path.exists(os.path.join(tree, "security", "pins")):
            s.ran.append(("pinned downloads", "; ".join(pin_notes) or "checked"))
        print(f"security-scan: scanning {commit[:9]} ({mode_note}{', this takes a few minutes' if changed is None else ''})...", file=sys.stderr)
        steps = (s.gitleaks, lambda: s.semgrep(tree, exts, files), lambda: s.bandit(tree, py) if ".py" in exts else None,
                     lambda: s.shellcheck(tree, scripts), lambda: suppressions(s, tree, scripts), lambda: s.pip_audit(tree, reqs, projects),
                     lambda: s.npm_audit(tree, npm), lambda: s.cargo_audit(tree, cargo))
        if base == commit:   # nothing new since the base: the always-on checks only
            steps = (lambda: suppressions(s, tree, []),)
        for step in steps:
            try:
                step()
            except subprocess.TimeoutExpired as e:
                s.errors.append(f"timed out: {' '.join(map(str, e.cmd))[:120]}")
            except Exception as e:  # fail closed
                s.errors.append(f"scanner crashed: {e}")

    blocking, accepted = [], []
    for f in s.findings:
        e = allowed(f, entries)
        (accepted if e else blocking).append((f, e))
    used = {e["line"] for _, e in accepted}
    unused = [e for e in entries if e["line"] not in used] if changed is None else []   # only a full scan can tell
    ok = not blocking and not s.errors and not problems
    result = "PASS" if ok else "FAIL"

    lines = [f"# Security scan: {os.path.basename(root)} {commit[:9]}", "",
             f"Result: {result}", f"Mode: {mode_note}", f"Commit: {commit}", f"Tree: {tree_id}", f"Date: {time.strftime('%Y-%m-%d %H:%M %Z')}",
             f"Blocking findings: {len(blocking)}", f"Accepted (allowlisted): {len(accepted)}",
             f"Scanner errors: {len(s.errors)}", f"Allowlist and pin problems: {len(problems)}", "", "## What ran", ""]
    lines += [f"- {t}: {w}" for t, w in s.ran] or ["- nothing ran"]
    if s.errors:
        lines += ["", "## Scanner errors (each blocks)", ""] + [f"- {e}" for e in s.errors]
    if problems:
        lines += ["", "## Allowlist and pin problems (each blocks)", ""] + [f"- {p}" for p in problems]
    if blocking:
        lines += ["", "## Blocking findings", "", "Fix each one, or add its id to security/accepted-findings with an expiry and the board key.", ""]
        for f, _ in sorted(blocking, key=lambda x: (x[0]["tool"], x[0]["path"] or "", x[0]["line"] or 0)):
            loc = f"{f['path']}:{f['line']}" if f["line"] else (f["path"] or "")
            lines += [f"- [{f['severity']}] {loc} {f['title']}", f"  `{f['id']}`"]
    if accepted:
        lines += ["", "## Accepted findings", ""]
        for f, e in accepted:
            lines += [f"- {f['path']}:{f['line'] or ''} {f['rule']} (until {e['expires']}: {e['reason']})"]
    if unused:
        lines += ["", "## Allowlist entries that matched nothing (remove them)", ""] + [f"- line {e['line']}: {e['id']}" for e in unused]
    report = "\n".join(lines) + "\n"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for p in [os.path.join(outdir, f"{stamp}-{commit[:9]}.md"), os.path.join(outdir, "latest.md")] + ([a.report] if a.report else []):
        with open(p, "w") as fh:
            fh.write(report)
    with open(os.path.join(outdir, "latest.json"), "w") as fh:
        json.dump(dict(result=result, commit=commit, errors=s.errors, problems=problems,
                       blocking=[f for f, _ in blocking], accepted=[f for f, _ in accepted]), fh, indent=1)

    if ok:
        exp = min([e["expires"] for e in entries] or ["9999-12-31"])
        json.dump(dict(tree=tree_id, allow=alhash, day=str(today), at=time.time(), max_exp_ok=exp,
                       mode="quick" if changed is not None else "full", base=base, commit=commit), open(cache, "w"))
        print(f"security-scan: PASS, {mode_note} ({len(accepted)} accepted, {', '.join(t for t, _ in s.ran if t != 'mode')})", file=sys.stderr)
        for t, w in s.ran:
            if t == "pinned downloads" and "expires in" in w:
                print(f"  note: {w}", file=sys.stderr)
        return 0
    if os.path.exists(cache):
        os.remove(cache)
    print(f"security-scan: FAIL. Push refused: {len(blocking)} finding(s), {len(s.errors)} scanner error(s), "
          f"{len(problems)} allowlist or pin problem(s).", file=sys.stderr)
    for f, _ in blocking[:15]:
        print(f"  [{f['severity']}] {f['path']}:{f['line'] or ''} {f['title'][:100]}", file=sys.stderr)
    for e in (s.errors + problems)[:10]:
        print(f"  ! {e}", file=sys.stderr)
    print(f"  Full report: {os.path.join(outdir, 'latest.md')}", file=sys.stderr)
    print("  Never bypass with --no-verify (standing rules, DE-49).", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # anything unexpected blocks
        print(f"security-scan: FAIL. The scan could not run: {e}", file=sys.stderr)
        sys.exit(1)

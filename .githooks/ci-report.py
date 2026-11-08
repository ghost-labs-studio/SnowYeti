#!/usr/bin/env python3
"""Ghost Labs CI scan reporting (DE-109, PW-55, PW-56, WA-291; Larry, November 7, 2026: Patchwork runs the scanning).

The GitHub security-scan job calls this to report itself to Ravenwood, the hub, so the scan shows live, step by step,
on Ravenwood's Flight and on Patchwork's Scans page, and to send Patchwork (through Ravenwood) the scan's report and the
repo's package list, which Patchwork's daily feed checks against OSV and CISA's KEV catalog.

  ci-report.py start                      starts the workflow (its id goes to $GITHUB_OUTPUT as workflow=...)
  ci-report.py step KEY STATUS [DETAIL]   running, passed, failed or skipped
  ci-report.py finish STATUS [SUMMARY]    passed or failed
  ci-report.py record REPORT.md RESULT    sends the scan report (kind push-scan) and the package list
  ci-report.py packages                   prints the package list as JSON (for a look; sends nothing)

It needs RAVENWOOD_SCAN_TOKEN: a Ravenwood run token scoped to this repo and its Patchwork asset (Ravenwood refuses
anything else from it), and PATCHWORK_ASSET, that asset's id. Without the token it does nothing and exits 0, so a repo
not set up yet, or a pull request from a fork, scans as before. Reporting never fails the scan: Ravenwood being down
prints a warning and the job goes on. The token is read from the environment only and never printed.
"""
import fnmatch
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.parse

BASE = os.environ.get("RAVENWOOD_URL", "https://ravenwood.ghost-labs.com").rstrip("/")
TOKEN = os.environ.get("RAVENWOOD_SCAN_TOKEN", "").strip()
REPO = os.environ.get("GITHUB_REPOSITORY", "")
ITEM = os.environ.get("RAVENWOOD_SCAN_ITEM", "") or "DE-109"  # must be the item the scan token was made for
ASSET = os.environ.get("PATCHWORK_ASSET", "").strip()
STATE = os.path.join(os.environ.get("RUNNER_TEMP", "."), "ravenwood-workflow")
STEPS = [("tools", "Install the scanners"), ("scan", "Full security scan"), ("packages", "Package list"), ("record", "Record in Patchwork")]
PACKAGES_MAX = 5000
NAME_RE = re.compile(r"^[A-Za-z0-9@._/:+~-]{1,214}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_~:-]{0,99}$")


def warn(msg):
    print(f"ci-report: {msg}", file=sys.stderr)


def post(path, body):
    """POST JSON to Ravenwood with the run token; the answer's JSON, or None on any failure."""
    u = urllib.parse.urlsplit(BASE)
    if u.scheme != "https" or not u.hostname or u.path not in ("", "/") or u.query or u.username:
        warn("RAVENWOOD_URL must be https://<host>.")
        return None
    what = path.split("/")[2] if path.count("/") > 1 else path
    try:
        # Each socket operation times out after 20 seconds, and the whole answer is read against a 60-second deadline
        # (pass 2, R2-6), so a slow answer can't hold the job.
        c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=20, context=ssl.create_default_context())
        c.request("POST", path, body=json.dumps(body).encode(), headers={
            "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "ghost-labs-ci-scan"})
        r = c.getresponse()
        deadline = time.monotonic() + 60
        raw = b""
        while len(raw) < 1_000_000:
            if time.monotonic() > deadline:
                raise TimeoutError("answer too slow")
            # read1 returns what has arrived (at most one socket read), so the deadline is checked between arrivals and a
            # slow answer can't hold one call past it (pass 3, R2-4).
            chunk = r.read1(65536)
            if not chunk:
                break
            raw += chunk
        c.close()
    except Exception as e:
        warn(f"Ravenwood not reached ({type(e).__name__}).")
        return None
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        data = {}
    if not 200 <= r.status < 300:
        why = data.get("error", "") if isinstance(data, dict) else ""
        warn(f"Ravenwood answered {r.status} for {what}: {str(why)[:200]}")
        return None
    return data if isinstance(data, dict) else {}


def workflow_id():
    try:
        with open(STATE, encoding="utf-8") as f:
            w = f.read().strip()
        return w if re.fullmatch(r"[0-9a-f-]{36}", w) else None
    except OSError:
        return None


def start():
    sha = os.environ.get("GITHUB_SHA", "")[:7]
    ref = os.environ.get("GITHUB_REF_NAME", "")[:60]
    name = REPO.split("/", 1)[-1]
    title = f"Security scan {name} {ref} {sha}".strip()[:120]
    out = post("/mcp/workflows", {"board": "development", "key": ITEM, "title": title, "kind": "script", "source": f"github:{REPO}",
                                  "steps": [{"key": k, "label": label} for k, label in STEPS]})
    w = None
    for d in (out, (out or {}).get("data"), (out or {}).get("workflow")):
        if isinstance(d, dict):
            for k in ("id", "workflow"):
                if isinstance(d.get(k), str) and re.fullmatch(r"[0-9a-f-]{36}", d[k]):
                    w = w or d[k]
    if w:
        with open(STATE, "w", encoding="utf-8") as f:
            f.write(w)
        gh = os.environ.get("GITHUB_OUTPUT")
        if gh:
            with open(gh, "a", encoding="utf-8") as f:
                f.write(f"workflow={w}\n")
        print(f"ci-report: reporting to Ravenwood as {title}")


def step(key, status, detail=None):
    w = workflow_id()
    if not w:
        return
    body = {"status": status}
    if detail:
        body["detail"] = re.sub(r"[\x00-\x1f\x7f]", " ", detail)[:300]
    post(f"/mcp/workflows/{w}/steps/{key}", body)


def finish(status, summary=None):
    w = workflow_id()
    if not w:
        return
    body = {"status": status}
    if summary:
        body["summary"] = re.sub(r"[\x00-\x1f\x7f]", " ", summary)[:500]
    post(f"/mcp/workflows/{w}/finish", body)


# ---------- the package list ----------

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "build", "dist", ".build", "target", "DerivedData"}


def tracked(pattern):
    """The repo's files whose names match pattern, outside build and dependency folders."""
    out = []
    for root, dirs, files in os.walk("."):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        out += [os.path.join(root, f)[2:] for f in sorted(files) if fnmatch.fnmatch(f, pattern)]
    return out


def read(path, limit=50_000_000):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read(limit)
    except (OSError, UnicodeDecodeError):
        return ""


def packages():
    """Every package the repo's lockfiles pin, outside .github/ (the CI's own tools aren't the product's; pass 2, R3-10).
    A lockfile that can't be read is skipped with a warning."""
    seen = set()

    def add(eco, name, version):
        if isinstance(name, str) and isinstance(version, str) and NAME_RE.match(name) and VERSION_RE.match(version):
            seen.add((eco, name, version))

    def load(path):
        try:
            j = json.loads(read(path))
        except ValueError:
            warn(f"{path} isn't JSON; skipped.")
            return None
        if not isinstance(j, dict):
            warn(f"{path} isn't a JSON object; skipped.")
            return None
        return j

    def npm_v1(deps):
        for name, p in (deps or {}).items():
            if isinstance(p, dict):
                add("npm", name, p.get("version"))
                npm_v1(p.get("dependencies"))

    files = [f for f in tracked("*") if not f.startswith(".github/")]
    pick = lambda pat: [f for f in files if fnmatch.fnmatch(os.path.basename(f), pat)]
    for lock in pick("package-lock.json"):
        j = load(lock)
        if j is None:
            continue
        pk = j.get("packages")
        if isinstance(pk, dict):
            for path, p in pk.items():
                if not path or not isinstance(p, dict) or p.get("link") or "node_modules/" not in path:
                    continue
                # An alias (node_modules/x with "name": "real") is the real package (R2-7).
                add("npm", p.get("name") if isinstance(p.get("name"), str) else path.rsplit("node_modules/", 1)[1], p.get("version"))
        elif isinstance(j.get("dependencies"), dict):
            npm_v1(j["dependencies"])  # lockfileVersion 1
    for lock in pick("*.lock") + pick("*requirements*.txt"):
        base = os.path.basename(lock)
        if base == "Cargo.lock":
            for block in read(lock).split("[[package]]")[1:]:
                n = re.search(r'^name = "([^"]+)"', block, re.M)
                v = re.search(r'^version = "([^"]+)"', block, re.M)
                if n and v and 'source = "registry+' in block:
                    add("crates.io", n.group(1), v.group(1))
            continue
        if base in ("poetry.lock", "uv.lock"):
            for block in re.split(r"^\[\[package\]\]$", read(lock), flags=re.M)[1:]:
                n = re.search(r'^name = "([^"]+)"', block, re.M)
                v = re.search(r'^version = "([^"]+)"', block, re.M)
                if n and v:
                    add("PyPI", n.group(1).lower().replace("_", "-"), v.group(1))
            continue
        for m in re.finditer(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([A-Za-z0-9][A-Za-z0-9.+_-]*)", read(lock), re.M):
            add("PyPI", m.group(1).lower().replace("_", "-"), m.group(2))
    for lock in pick("Pipfile.lock"):
        j = load(lock)
        for sec in ("default", "develop"):
            for name, p in ((j or {}).get(sec) or {}).items():
                if isinstance(p, dict) and isinstance(p.get("version"), str):
                    add("PyPI", name.lower().replace("_", "-"), p["version"].lstrip("="))
    for gosum in pick("go.sum"):
        # Only the module lines, not "/go.mod" ones, which name versions outside the build list (R2-7).
        for m in re.finditer(r"^(\S+) (v\S+) h1:", read(gosum), re.M):
            if not m.group(2).endswith("/go.mod"):
                add("Go", m.group(1), m.group(2))
    for res in pick("Package.resolved"):
        j = load(res)
        if j is None:
            continue
        pins = j.get("pins") or (j.get("object") or {}).get("pins") or []
        for p in pins if isinstance(pins, list) else []:
            if not isinstance(p, dict):
                continue
            loc = (p.get("location") or p.get("repositoryURL") or "")
            st = p.get("state") if isinstance(p.get("state"), dict) else {}
            if isinstance(loc, str):
                add("SwiftURL", loc.removesuffix(".git"), st.get("version"))
    for lock in pick("*gradle.lockfile"):
        for m in re.finditer(r"^([A-Za-z0-9._-]+:[A-Za-z0-9._-]+):([A-Za-z0-9][A-Za-z0-9.+_-]*)=", read(lock), re.M):
            add("Maven", m.group(1), m.group(2))
    out = [{"ecosystem": e, "name": n, "version": v} for e, n, v in sorted(seen)]
    if len(out) > PACKAGES_MAX:
        warn(f"{len(out)} packages; Patchwork takes {PACKAGES_MAX}, so the list is cut.")
    return out[:PACKAGES_MAX]


# ---------- the report ----------

HIGH = {"error", "high", "critical"}
MEDIUM = {"warning", "medium", "moderate"}
LOW = {"info", "low", "note"}


def counts(report_text):
    """Blocking findings by severity from security-scan.py's report (pass 2, R2-2):
    - each "- [SEVERITY] ..." line under "## Blocking findings": low, medium or high (a severity this doesn't know
      counts as high, so nothing is understated);
    - each line under "## Scanner errors" and "## Allowlist and pin problems": high (each blocks the scan);
    - the report's own "Blocking findings: N", "Scanner errors: N" and "Allowlist and pin problems: N" lines: when they
      add up to more than was counted, the rest count as high.
    Returns (high, medium, low, header_total)."""
    h = m = lo = 0
    section = ""
    header = 0
    for line in report_text.splitlines():
        hm = re.match(r"^(Blocking findings|Scanner errors|Allowlist and pin problems): (\d+)$", line)
        if hm and not section:
            header += int(hm.group(2))
            continue
        if line.startswith("## "):
            section = line[3:].strip().lower()
            continue
        if section.startswith("blocking findings"):
            sv = re.match(r"^- \[([^\]]*)\]", line)
            if not sv:
                continue
            sev = sv.group(1).strip().lower()
            if sev in LOW:
                lo += 1
            elif sev in MEDIUM:
                m += 1
            else:
                h += 1
        elif section.startswith("scanner errors") or section.startswith("allowlist and pin problems"):
            if line.startswith("- "):
                h += 1
    if header > h + m + lo:
        h += header - (h + m + lo)
    return h, m, lo, header


def record_missing(outcome):
    """A push or Scan now whose scan wrote no report still records a failing push-scan, so Patchwork never keeps showing the
    last passing one as if this commit passed (pass 3, R2-5)."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,59}", ASSET):
        warn("PATCHWORK_ASSET isn't set to this repo's Patchwork asset id; nothing recorded.")
        step("record", "skipped", "PATCHWORK_ASSET not set")
        return
    sha = os.environ.get("GITHUB_SHA", "")[:7]
    why = re.sub(r"[^a-z_-]", "", outcome)[:20] or "unknown"
    rep = {"asset_id": ASSET, "kind": "push-scan", "title": f"CI scan {REPO.split('/', 1)[-1]} {sha}"[:300], "result": "fail",
           # A fail with no invented findings: the text says why (pass 4, R1-3).
           "findings_high": 0, "findings_medium": 0, "findings_low": 0, "board_key": ITEM,
           "text": f"# CI scan {sha}\n\nResult: FAIL\n\nThe scan wrote no report ({why}): the scanner install or the scan itself stopped.\n"}
    ok = post("/mcp/security", {"board": "development", "key": ITEM, "tool": "record_report", "arguments": rep}) is not None
    step("record", "passed" if ok else "failed", f"no scan report ({why}): recorded as a fail" if ok else "Ravenwood didn't take the record")


def record(report_path, result):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,59}", ASSET):
        warn("PATCHWORK_ASSET isn't set to this repo's Patchwork asset id; nothing recorded.")
        step("record", "skipped", "PATCHWORK_ASSET not set")
        return
    text = read(report_path, 500_000)
    h, m, lo, header = counts(text)
    # A scan that blocked anything, or a report that doesn't say PASS, is a fail whatever the job said.
    if h or m or lo or header or not re.search(r"^Result: PASS$", text, re.M):
        result = "fail"
    # The text must fit Patchwork's 512 KB and Ravenwood's 640 KB once JSON-escaped (pass 2, R2-10).
    while text and len(json.dumps(text).encode()) > 480_000:
        text = text[: int(len(text) * 0.8)] + "\n\n(cut to fit)\n"
    sha = os.environ.get("GITHUB_SHA", "")[:7]
    rep = {"asset_id": ASSET, "kind": "push-scan", "title": f"CI scan {REPO.split('/', 1)[-1]} {sha}"[:300], "result": result,
           "findings_high": h, "findings_medium": m, "findings_low": lo, "board_key": ITEM}
    if text:
        rep["text"] = text
    try:
        pk = packages()
    except Exception as e:
        warn(f"couldn't read the package list ({type(e).__name__}); sending the report only.")
        pk = None
    step("packages", "passed" if pk is not None else "failed", f"{len(pk)} packages" if pk is not None else "couldn't read the lockfiles")
    step("record", "running")
    a = post("/mcp/security", {"board": "development", "key": ITEM, "tool": "record_report", "arguments": rep})
    b = post("/mcp/security", {"board": "development", "key": ITEM, "tool": "record_packages", "arguments": {"asset_id": ASSET, "packages": pk, "board_key": ITEM}}) if pk else None
    ok = a is not None and (b is not None or not pk)
    step("record", "passed" if ok else "failed", f"report {result}, {len(pk or [])} packages" if ok else "Ravenwood didn't take every record (see the job log)")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 0
    cmd = argv[1]
    if cmd == "packages":
        print(json.dumps(packages(), indent=1))
        return 0
    if not TOKEN:
        return 0  # not set up for reporting: the scan runs as before
    if not TOKEN.startswith("rws_"):
        warn("RAVENWOOD_SCAN_TOKEN isn't a Ravenwood scan token (rws_, scoped to this repo); nothing reported.")
        return 0
    if not re.fullmatch(r"ghost-labs-studio/[A-Za-z0-9][A-Za-z0-9._-]{0,99}", REPO):
        warn("not a ghost-labs-studio repository; nothing reported.")
        return 0
    if cmd == "start":
        start()
    elif cmd == "step" and len(argv) >= 4 and argv[3] in ("waiting", "running", "passed", "failed", "skipped"):
        step(argv[2], argv[3], argv[4] if len(argv) > 4 else None)
    elif cmd == "finish" and len(argv) >= 3 and argv[2] in ("passed", "failed", "stopped"):
        finish(argv[2], argv[3] if len(argv) > 3 else None)
    elif cmd == "record" and len(argv) == 4 and argv[3] in ("pass", "fail"):
        record(argv[2], argv[3])
    elif cmd == "record-missing" and len(argv) == 3:
        record_missing(argv[2])
    else:
        warn("unknown command.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Ghost Labs software bill of materials (DE-98, November 3, 2026).

Writes a CycloneDX 1.5 SBOM of every package pinned in the repo's lockfiles, for each release, to
security/SBOM-<platform>-<version>.json, and checks on a version tag that the SBOM still matches the lockfiles
(pre-push). The SBOM is recorded in Patchwork with the release (record_report, through Ravenwood), so the daily
threat feed can flag a new CVE in an app that has already shipped.

Usage:
  sbom.py write --product NAME --platform P --version V [--rev REV]   write security/SBOM-P-V.json
  sbom.py check PLATFORM VERSION [--rev REV]                        PLATFORM "*": any platform's SBOM
Exit 0: written or matches. 1: missing, unreadable or out of date (the tag push is refused). 2: usage.
"""
import argparse, glob, hashlib, json, os, re, sys, time, urllib.parse
import importlib.util

# Source only: no bytecode written or read (an empty cache prefix of this run's own), so a planted __pycache__ file
# can't run in place of the reviewed threat-feed.py (DE-98 pass 2).
import tempfile as _tempfile
sys.dont_write_bytecode = True
sys.pycache_prefix = _tempfile.mkdtemp(prefix="gl-nopyc-")
HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("gl_threat_feed", os.path.join(HERE, "threat-feed.py"))
tf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tf)

PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "SwiftURL": "swift", "RubyGems": "gem",
             "Packagist": "composer", "NuGet": "nuget", "Maven": "maven"}   # Maven: Gradle builds (DE-116)


def purl(eco, name, version):
    t = PURL_TYPE[eco]
    if t == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    if t == "swift":
        name = re.sub(r"^https?://", "", name)
        parts = name.split("/")
        return f"pkg:swift/{'/'.join(urllib.parse.quote(p, safe='') for p in parts)}@{urllib.parse.quote(version, safe='')}"
    if t == "maven" and ":" in name:   # group:name, the purl spec's namespace and name (DE-116)
        g, n = name.split(":", 1)
        return f"pkg:maven/{urllib.parse.quote(g, safe='')}/{urllib.parse.quote(n, safe='')}@{urllib.parse.quote(version, safe='')}"
    if t == "composer" and "/" in name:
        ns, n = name.split("/", 1)
        return f"pkg:composer/{urllib.parse.quote(ns, safe='')}/{urllib.parse.quote(n, safe='')}@{urllib.parse.quote(version, safe='')}"
    if t == "npm" and name.startswith("@") and "/" in name:
        scope, n = name.split("/", 1)
        return f"pkg:npm/{urllib.parse.quote(scope, safe='')}/{urllib.parse.quote(n, safe='')}@{urllib.parse.quote(version, safe='')}"
    return f"pkg:{t}/{urllib.parse.quote(name, safe='')}@{urllib.parse.quote(version, safe='')}"


# The scanners' own pins are checked by the threat feed but are not part of what ships (pass 3 R3-5).
NOT_SHIPPED = {".github/security-scan-tools.lock"}


def components(tree):
    covered, uncovered, errors = tf.lockfiles(tree)
    if errors:
        raise RuntimeError("; ".join(errors))
    comps = {}
    covered = [c for c in covered if c[0].replace(os.sep, "/") not in NOT_SHIPPED]
    uncovered = [u for u in uncovered if u.replace(os.sep, "/") not in NOT_SHIPPED]
    for lock, pkgs in covered:
        for eco, name, version in pkgs:
            p = purl(eco, name, version)
            c = comps.setdefault(p, {"type": "library", "name": name, "version": version, "purl": p,
                                     "bom-ref": p, "properties": []})
            c["properties"].append({"name": "ghost-labs:lockfile", "value": lock})
    return [comps[k] for k in sorted(comps)], uncovered


def build(tree, product, platform, version, commit):
    comps, uncovered = components(tree)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": "urn:uuid:" + _uuid(f"{product}|{platform}|{version}|{commit}"),
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [{"vendor": "Ghost Labs, LLC", "name": "sbom.py", "version": tf.VERSION}],
            "component": {"type": "application", "name": product, "version": version,
                          "properties": [{"name": "ghost-labs:platform", "value": platform},
                                         {"name": "ghost-labs:commit", "value": commit}]},
            "properties": [{"name": "ghost-labs:not-covered", "value": u} for u in uncovered],
        },
        "components": comps,
    }


def _uuid(s):
    h = hashlib.sha256(s.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-5{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def accepted_not_covered(tree, today=None):
    """Lockfiles security/accepted-findings accepts as not checked: an unexpired entry, within 180 days, with a board
    key, whose id is threat-feed:not-covered:<path>:<hash> (the same id security-scan.py prints)."""
    import datetime
    today = today or datetime.date.today()
    ok = set()
    f = os.path.join(tree, "security", "accepted-findings")
    if not os.path.isfile(f):
        return ok
    with open(f, encoding="utf-8") as fh:
        for line in fh:
            parts = [x.strip() for x in line.split("|")]
            if len(parts) != 3 or not parts[0].startswith("threat-feed:not-covered:"):
                continue
            try:
                exp = datetime.date.fromisoformat(parts[1])
            except ValueError:
                continue
            if not (today <= exp <= today + datetime.timedelta(days=180)):
                continue
            if not re.search(r"(^|[^A-Za-z0-9])[A-Z][A-Z0-9]{0,4}-[0-9]{1,6}([^0-9]|$)", parts[2]):
                continue
            ok.add(parts[0])
    return ok


def check(tree, platform, version):
    """Problems (empty list = OK): no SBOM for this version, an unreadable one, one that no longer matches, one
    whose own version or platform disagrees with its name, or a lockfile it can't describe that isn't accepted."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", version):
        return [f"sbom: bad version {version!r}"]
    pat = f"SBOM-{platform}-{version}.json" if platform != "*" else f"SBOM-*-{version}.json"
    files = sorted(glob.glob(os.path.join(tree, "security", pat)))
    if not files:
        return [f"sbom: no security/{pat} for this release (run .githooks/sbom.py write, DE-98)"]
    try:
        comps, uncovered = components(tree)
        want = {c["purl"] for c in comps}
    except Exception as e:
        return [f"sbom: can't read the lockfiles ({e})"]
    problems = []
    acc = accepted_not_covered(tree)
    for u in uncovered:   # the SBOM can't describe it: refused unless accepted (pass 1 R2-5, R3-4)
        if tf.not_covered_id(u) not in acc:
            problems.append(f"sbom: {u} can't be described (no reader); accept {tf.not_covered_id(u)} in "
                            f"security/accepted-findings with an expiry and board key, or add a reader")
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
            have = {c["purl"] for c in d.get("components", [])}
            if d.get("bomFormat") != "CycloneDX":
                raise ValueError("not CycloneDX")
            comp = d["metadata"]["component"]
            props = {x["name"]: x["value"] for x in comp.get("properties", [])}
            fplat, fver = re.fullmatch(r"SBOM-(.+)-([0-9.]+)\.json", os.path.basename(f)).groups()
            if comp.get("version") != fver or props.get("ghost-labs:platform") != fplat:   # pass 1 R3-6
                raise ValueError(f"it describes {props.get('ghost-labs:platform')} {comp.get('version')}, not {fplat} {fver}")
            if not re.fullmatch(r"[0-9a-f]{40}", props.get("ghost-labs:commit", "")):
                raise ValueError("no commit recorded")
        except Exception as e:
            problems.append(f"sbom: {os.path.relpath(f, tree)} unreadable ({e})")
            continue
        if have != want:
            problems.append(f"sbom: {os.path.relpath(f, tree)} doesn't match the lockfiles "
                            f"({len(want - have)} missing, {len(have - want)} extra); write it again")
    return problems


def git(args, cwd=None):
    """git through threat-feed.py's one process helper; returns stdout bytes or raises."""
    p = tf.tool(["git", *args], cwd=cwd)
    if p.returncode:
        raise RuntimeError(f"git {args[0]}: {p.stderr.decode(errors='replace').strip()[:200]}")
    return p.stdout


def tree_from_rev(rev, dest, cwd=None):
    """The commit's lockfiles, SBOMs and accepted findings, written under dest, so a tag is checked (and an SBOM is
    written) from what the commit holds, not the working tree (pass 1 R2-12)."""
    listing = git(["ls-tree", "-r", "-z", rev], cwd=cwd)
    for raw in listing.split(b"\0"):
        if not raw:
            continue
        meta, _, name = raw.partition(b"\t")
        mode = meta.split(b" ")[0]
        rel = name.decode("utf-8", "surrogateescape")
        base = os.path.basename(rel)
        parts = rel.split("/")
        if any(x in tf.SKIP_DIRS for x in parts[:-1]) or any(x in ("", ".", "..") for x in parts):
            continue
        # Every .txt too, so a requirements include with any name is there to read (pass 2 R2-2).
        # Gradle settings files too, so a build script can be matched to its build root's verification file (DE-116).
        wanted = tf.is_lockfile(base, rel) or base.lower().endswith(".txt") or rel == "security/accepted-findings" or \
            base in tf.GRADLE_SETTINGS or \
            (parts[0] == "security" and re.fullmatch(r"SBOM-.+\.json", base) and len(parts) == 2)
        if wanted:
            if mode != b"100644" and mode != b"100755":
                raise RuntimeError(f"{rel} is not a regular file in {rev} (mode {mode.decode()})")
            body = git(["show", f"{rev}:{rel}"], cwd=cwd)
            out = os.path.join(dest, *parts)
            if not os.path.realpath(out).startswith(os.path.realpath(dest) + os.sep):
                raise RuntimeError(f"{rel} would land outside the folder")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(body)


def check_uncovered(tree):
    _, uncovered = components(tree)
    acc = accepted_not_covered(tree)
    return [f"sbom: {u} can't be described (no reader); accept {tf.not_covered_id(u)} first" for u in uncovered
            if tf.not_covered_id(u) not in acc]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ghost Labs SBOM (DE-98)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("write")
    w.add_argument("--product", required=True)
    w.add_argument("--platform", required=True)
    w.add_argument("--version", required=True)
    w.add_argument("--rev", default="HEAD")
    c = sub.add_parser("check")
    c.add_argument("platform")
    c.add_argument("version")
    c.add_argument("--rev", help="check the commit (a tag push), not the working tree")
    a = ap.parse_args(argv)
    if a.cmd == "write":
        if not re.fullmatch(r"[A-Za-z0-9*_-]+", a.platform) or a.platform == "*" or \
                not re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", a.version):
            print("sbom: platform must be a word and version like 1.2.3", file=sys.stderr)
            return 2
        root = git(["rev-parse", "--show-toplevel"]).decode().strip()
        commit = git(["rev-parse", f"{a.rev}^{{commit}}"], cwd=root).decode().strip()
        import tempfile
        with tempfile.TemporaryDirectory(prefix="gl-sbom-") as tree:
            try:
                tree_from_rev(commit, tree, cwd=root)
                problems = [p for p in check_uncovered(tree)]
            except Exception as e:   # fail closed with a message, not a traceback
                problems = [f"sbom: can't read the lockfiles of {commit[:9]} ({e})"]
            if problems:
                for p in problems:
                    print(p, file=sys.stderr)
                return 1
            try:
                doc = build(tree, a.product, a.platform, a.version, commit)
            except Exception as e:
                print(f"sbom: can't build the SBOM ({e})", file=sys.stderr)
                return 1
        out = os.path.join(root, "security", f"SBOM-{a.platform}-{a.version}.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print(f"sbom: wrote {os.path.relpath(out, root)} ({len(doc['components'])} components)")
        return 0
    import tempfile
    if a.rev:
        with tempfile.TemporaryDirectory(prefix="gl-sbom-") as tree:
            try:
                tree_from_rev(a.rev, tree)
            except Exception as e:
                print(f"sbom: can't read {a.rev} ({e})", file=sys.stderr)
                return 1
            problems = check(tree, a.platform, a.version)
            if not problems:   # the SBOM's recorded commit must be the tagged commit or before it (pass 2 R3-5)
                for f in sorted(glob.glob(os.path.join(tree, "security", "SBOM-*.json"))):
                    if not re.fullmatch(r"SBOM-.+-" + re.escape(a.version) + r"\.json", os.path.basename(f)):
                        continue
                    with open(f) as fh:
                        props = {x["name"]: x["value"] for x in json.load(fh)["metadata"]["component"]["properties"]}
                    rec = props.get("ghost-labs:commit", "")
                    p = tf.tool(["git", "merge-base", "--is-ancestor", rec, a.rev])
                    if p.returncode != 0:
                        problems.append(f"sbom: {os.path.basename(f)} was written for {rec[:9]}, which isn't in {a.rev[:9]}'s history")
    else:
        tree = git(["rev-parse", "--show-toplevel"]).decode().strip()
        problems = check(tree, a.platform, a.version)
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Ghost Labs threat feed (DE-98, November 3, 2026).

Checks every dependency pinned in a repo's lockfiles against OSV (which carries the GitHub Advisory Database, PyPA,
RustSec, RubyGems, Packagist, NuGet and NVD CVE ids) and marks anything on the CISA Known Exploited Vulnerabilities
catalog as Critical. security-scan.py calls it on every full scan, and on a quick scan when a lockfile changed; the
daily scheduled task runs it over every repo and records new matches in Patchwork through Ravenwood.

Fails closed (pass 1 fixes):
  an unreachable OSV or KEV with no good copy under MAX_AGE_H, a truncated or malformed answer, a lockfile it can't
  parse, an unknown lockfile version, a lockfile that yields no packages, a symlinked lockfile, a version that isn't
  exact, and a path that isn't a directory are all errors. A lockfile format it doesn't read (CocoaPods, Go and
  others for now) is NOT CHECKED: security-scan.py reports it as a finding, which blocks unless
  security/accepted-findings accepts it with an expiry and a board key.

Gradle (DE-116, November 9, 2026): a build's gradle/verification-metadata.xml is Gradle's own record of every component
it resolved (plugins, buildscript and transitive ones included), so it is read as the lockfile, and a build.gradle or
build.gradle.kts is covered only when its build root (the nearest folder above it with settings.gradle or
settings.gradle.kts) has one. A verification file that lets any component through unlisted (trust by group, name or
version, trusted keys, signature checks) is an error. The build scripts themselves are never parsed.

Usage:
  threat-feed.py [--json] PATH...      PATH: a repo or a checked-out tree
Exit 0: no matches and no errors. 1: matches, not-checked lockfiles or errors. 2: usage.
"""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, sys, time
import shlex

VERSION = "1.5.0"   # DE-116: Gradle verification metadata, pip .lock files, constraint ceilings
CACHE = os.path.expanduser("~/.cache/ghost-labs-security/threat-feed")
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FRESH_H, MAX_AGE_H = 24, 48
# Only folders that are never source: anything under them is installed or generated, not pinned by this repo.
SKIP_DIRS = {".git", "node_modules", "__pycache__"}
# Lockfiles and pin files it can't read yet: each is a not-checked finding (pass 1 R2-5, R3-4).
UNCOVERED = {"build.gradle", "build.gradle.kts", "gradle.lockfile", "Podfile.lock", "go.sum", "go.mod",
             "Cartfile.resolved", "mix.lock", "pubspec.lock", "conan.lock", "vcpkg.json", "flake.lock",
             "bun.lockb", "deno.lock", "packages.config"}
ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,100}")   # used with fullmatch only
# Longest line a line-by-line reader takes before any pattern runs on it (DE-102, pass 6 R1-1): a longer line is an
# error, so a hostile megabyte-long line can't make a reader's regexes slow.
MAX_LINE = 65536   # raised from 4,096 (DE-102 pass 1 R2-2): a pip line with 60 --hash options is about 4,800
# Characters some installers treat as a line break (str.splitlines, YAML 1.1) besides \n and \r (DE-102 pass 1 R3-1):
# pip would read a package after one of them that a line-by-line reader never sees, so any of them is an error.
ODD_BREAKS = "\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
# pip's own coding-line rule (pip._internal.req.req_file): in either of the first two b"\n" segments that start with
# "#". pip decodes the file by it (unicode_escape or utf-7 can hide a line), so any coding other than UTF-8 is an error.
PIP_CODING_RE = re.compile(rb"coding[:=]\s*([-\w.]+)")


class LockError(ValueError):
    pass


def _capped(fh):
    """The file's lines, read the way every installer agrees on, or an error before any reader sees them: strict
    UTF-8 with no byte order mark, no line break other than \n, \r or \r\n (DE-102 pass 1 R3-1), and no line over
    MAX_LINE characters."""
    data = fh.buffer.read()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or data.startswith(b"\xef\xbb\xbf"):
        raise LockError("starts with a byte order mark")
    for seg in data.split(b"\n", 2)[:2]:   # read as pip reads it (DE-102 pass 2 R1-1)
        m = PIP_CODING_RE.search(seg) if seg[:1] == b"#" else None
        if m and m.group(1).decode("ascii", "replace").lower().replace("_", "-") not in ("utf-8", "utf8"):
            raise LockError(f"names the source encoding {m.group(1).decode('ascii', 'replace')!r}, which pip would "
                            f"decode the file by")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise LockError(f"isn't UTF-8 (byte {e.start})") from None
    bad = next((c for c in text if c in ODD_BREAKS), None)
    if bad is not None:
        raise LockError(f"has a {bad!r} character, which some installers read as a line break")
    text = text.replace("\r\n", "\n")   # every reader sees "\n" only (DE-102 pass 2 R2-2)
    if "\r" in text:   # a bare CR is a line break to pip but not to every reader (pass 2 R1-1)
        raise LockError("has a carriage return that isn't part of a CRLF line ending")
    for n, raw in enumerate(text.splitlines(keepends=True), 1):
        if len(raw.rstrip("\n")) > MAX_LINE:
            raise LockError(f"line {n} is {len(raw)} characters long, over the {MAX_LINE} limit")
        yield raw


def exact(version, where):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_!~-]*", version or "") or version.endswith("."):
        raise LockError(f"{where}: version {version!r} isn't an exact version")
    return version


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    if not isinstance(d, dict):
        raise LockError("not a JSON object")
    return d


def _npm(path):
    d = _load_json(path)
    ver = d.get("lockfileVersion")
    out = []
    if ver in (2, 3):
        pk = d.get("packages")
        if not isinstance(pk, dict):
            raise LockError(f"lockfileVersion {ver} without packages")
        for k, v in pk.items():
            if not k:
                continue
            if not isinstance(v, dict):
                raise LockError(f"package entry {k!r} isn't an object")
            if v.get("link"):
                continue
            name = v.get("name") or k.rsplit("node_modules/", 1)[-1]
            if "node_modules/" not in k:   # a workspace folder, not a downloaded package
                continue
            out.append(("npm", name, exact(v.get("version"), name)))
    elif ver == 1:
        def walk(deps):
            for name, v in (deps or {}).items():
                if not isinstance(v, dict):
                    raise LockError(f"dependency {name!r} isn't an object")
                out.append(("npm", name, exact(v.get("version"), name)))
                walk(v.get("dependencies"))
        walk(d.get("dependencies"))
    else:
        raise LockError(f"unknown lockfileVersion {ver!r}")
    return out


TOML_HEADER = re.compile(r"\[\[?[A-Za-z0-9_.-]+\]\]?")


LOCAL_KEYS = ("virtual", "editable")


def _uv_local(src, entry):
    """True only for uv's own project root: a source of exactly one key, virtual or editable, and nothing to download.
    Poetry and cargo don't read those keys at all (they install the entry), so only uv.lock asks (DE-102 pass 4 R3-1)."""
    if not isinstance(src, dict) or not any(k in src for k in LOCAL_KEYS):
        return False
    if len(src) != 1 or "wheels" in entry or "sdist" in entry:
        raise LockError(f"a uv source with {', '.join(sorted(src))} and {'a download' if ('wheels' in entry or 'sdist' in entry) else 'more keys'} can't be read exactly")
    return True


def _toml_packages(path, eco, uv=False):
    """[[package]] entries with name and version (Cargo.lock, poetry.lock, uv.lock). Read with tomllib, as cargo, uv
    and poetry read them, where Python has it (3.11 and later); otherwise a strict line reader that refuses any TOML
    form it doesn't read exactly (DE-102 pass 1 R3-2). An entry missing name or version is an error. Packages from a
    path or git source are listed too (a false match only blocks)."""
    lines = list(_strict_toml_lines(path))   # the text checks run either way
    try:
        import tomllib
    except ImportError:
        return _toml_lines(lines, eco, uv)
    try:
        d = tomllib.loads("".join(lines))
    except tomllib.TOMLDecodeError as e:
        raise LockError(f"not TOML ({e})") from None
    pk = d.get("package", [])
    if not isinstance(pk, list):
        raise LockError("package isn't a list of tables")
    out = []
    for p in pk:
        if not isinstance(p, dict):
            raise LockError("a package entry isn't a table")
        if uv and _uv_local(p.get("source"), p):
            continue   # uv's own project root (virtual or editable), not a download; any other mix is an error above
        if not isinstance(p.get("name"), str) or not isinstance(p.get("version"), str):
            raise LockError(f"[[package]] without name or version near {str(p)[:80]}")
        out.append((eco, p["name"], exact(p["version"], p["name"])))
    return out


def _strict_toml_lines(path):
    with open(path, encoding="utf-8") as fh:
        yield from _capped(fh)


def _toml_lines(lines, eco, uv=False):
    """The line reader, for Python without tomllib: every table header must be a plain [name] or [[name]] with
    nothing after it, and a top-level "package =" (an inline array) is refused."""
    out, cur, inpkg = [], None, False
    def close():
        if cur is not None and cur.get("_local"):   # uv's own project root, not a download (pass 4 R3-1)
            if cur.get("_download"):
                raise LockError(f"a uv virtual or editable source with a download near {cur.get('name')!r}")
            return
        if cur is not None:
            if "name" not in cur or "version" not in cur:
                raise LockError(f"[[package]] without name or version near {cur}")
            out.append((eco, cur["name"], exact(cur["version"], cur["name"])))
    top = True
    for raw in lines:
        line = raw.strip()
        if line.startswith("["):
            if not TOML_HEADER.fullmatch(line):
                raise LockError(f"can't read table header {line[:60]!r}")
            if cur is not None and cur.get("_local") and re.match(r"\[\[?package\.(sdist|wheels)\b", line):
                raise LockError("a uv virtual or editable source with a download")   # pass 4 R3-1, table form
            top = False
        elif top and re.match(r"^\s*\"?package\"?\s*=", line):
            raise LockError("an inline package array can't be read without tomllib")
        if line.startswith("[["):
            close()
            cur = {} if line == "[[package]]" else None
            inpkg = line == "[[package]]"
        elif line.startswith("["):
            close()
            cur, inpkg = None, False
        elif inpkg and cur is not None and raw[:1].isspace() and re.match(r"^\s+\"?(name|version)\"?\s*=", raw):
            raise LockError(f"can't read indented key {line[:60]!r} without tomllib")
        elif inpkg and cur is not None and not raw[:1].isspace():
            m = re.match(r"""^(name|version)\s*=\s*(?:"([^"]*)"|'([^']*)')\s*(#.*)?$""", line)
            if m:
                if m.group(2) is not None and "\\" in m.group(2):   # an escape only tomllib can read (pass 2 R1-2)
                    raise LockError(f"can't read escaped {line[:60]!r} without tomllib")
                cur[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
            elif uv and re.match(r"^source\s*=", line) and re.search(r"\b(virtual|editable)\b", line):
                # only the exact one-key form uv writes; anything else that mentions them is an error (pass 4 R3-1)
                if not re.fullmatch(r"""source\s*=\s*\{\s*(virtual|editable)\s*=\s*"[^"\\]*"\s*\}""", line):
                    raise LockError(f"can't read uv source {line[:60]!r} without tomllib")
                cur["_local"] = True
            elif uv and re.match(r"^(sdist|wheels)\s*=", line):
                cur["_download"] = True
            elif re.match(r"^(name|version)\s*=", line):
                raise LockError(f"can't read {line[:60]!r}")
    close()
    return out


PIP_OPTIONS = ("--hash", "--config-settings", "--global-option")   # allowed after a requirement on its line
# Options allowed on a line of their own, spelled exactly (pip also takes abbreviations; the reader doesn't, DE-102
# pass 2 R3-2). Includes are followed; the rest only change where pip downloads from or what it may install.
PIP_INCLUDES = {"-r", "--requirement", "-c", "--constraint"}
PIP_LINE_VALUE = PIP_INCLUDES | {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host",
                                 "--only-binary", "--no-binary", "-e", "--editable"}
PIP_LINE_FLAGS = {"--no-index", "--prefer-binary", "--pre", "--require-hashes"}


def _pip_is_comment(line):
    """pip's COMMENT_RE.match(line): the line is a comment from its first non-space character."""
    return line.lstrip().startswith("#")


def _pip_strip_comment(line):
    """pip's COMMENT_RE.sub("", line), in linear time (DE-102 pass 3 R1-1): cut at the first "#" that starts the line
    or follows whitespace."""
    i = line.find("#")
    while i != -1:
        if i == 0 or line[i - 1].isspace():
            return line[:i]
        i = line.find("#", i + 1)
    return line


def _pip_options(text, allowed_value, allowed_flags=()):
    """[(option, value)] from the options part of a pip line, split with shlex as pip does. An option that isn't
    allowed, an abbreviation, or an option with no value is an error."""
    try:
        toks = shlex.split(text)
    except ValueError as e:
        raise LockError(f"can't split options ({e})") from None
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t.startswith("--") and "=" in t:
            k, v = t.split("=", 1)
        elif len(t) > 2 and t[0] == "-" and t[1] != "-":   # "-rfile"
            k, v = t[:2], t[2:]
        else:
            k, v = t, None
        if k in allowed_flags and v is None:
            out.append((k, None))
            i += 1
            continue
        if k not in allowed_value:
            raise LockError(f"option {t[:40]!r} isn't one the reader knows (spelled in full)")
        if v is None:
            if i + 1 >= len(toks) or toks[i + 1].startswith("-"):
                raise LockError(f"{k} has no value")
            v = toks[i + 1]
            i += 1
        if not v:
            raise LockError(f"{k} has no value")
        out.append((k, v))
        i += 1
    return out


def _drop_pip_options(line):
    """A requirement line without its trailing options, split as pip splits it (the part before the first token that
    starts with "-" is the requirement). Only --hash, --config-settings and --global-option may follow."""
    toks = line.split(" ")
    k = next((n for n, t in enumerate(toks) if t.startswith("-")), len(toks))
    _pip_options(" ".join(toks[k:]), set(PIP_OPTIONS))
    return " ".join(t for t in toks[:k] if t)


def _pip_lines(path):
    """(line number, text) as pip sees them: strict text checks, backslash continuations joined, comments removed."""
    pending, first, size = [], None, 0
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(_capped(fh), 1):
            line = raw.rstrip("\n")
            if not line.endswith("\\") or _pip_is_comment(line):
                if _pip_is_comment(line):
                    line = " " + line
                if pending:
                    pending.append(line)
                    yield first, "".join(pending)
                    pending, size = [], 0
                else:
                    yield n, line
            else:
                if not pending:
                    first = n
                pending.append(line.strip("\\"))
                size += len(pending[-1])
                if size > MAX_LINE:   # a joined line has the same cap (pass 3 R1-1)
                    raise LockError(f"line {first} continues past the {MAX_LINE}-character limit")
    if pending:
        yield first, "".join(pending)


def _requirements(path, seen=None, root=None, constraint=None):
    """name==version lines, read the way pip reads them. -r and -c includes are followed inside the tree, wherever
    they sit on an option line. An unpinned or wildcard line, or an option the reader doesn't know, is an error: it
    can't be checked against a database of versions.
    constraint (DE-116): a constraints file (named *constraints*, or reached through -c) installs nothing; it only
    bounds what pip may pick. There a ceiling "name<=V" is also read, as V: with nothing above V allowed, V is what
    pip resolves to. Any other range is still an error."""
    if constraint is None:
        constraint = "constraints" in os.path.basename(path).lower()
    seen = seen if seen is not None else set()
    root = root or os.path.dirname(path)
    real = os.path.realpath(path)
    if real in seen:
        return []
    seen.add(real)
    out = []
    for n, raw in _pip_lines(path):
        line = _pip_strip_comment(raw).strip()
        if not line:
            continue
        if "${" in line:   # pip expands ${NAME} from the environment (DE-102 pass 3 R2-3)
            raise LockError(f"line {n}: an environment variable can't be read the way pip will expand it")
        if line.startswith("-"):   # an option line (pip: no requirement before the first "-" token)
            for k, v in _pip_options(line, PIP_LINE_VALUE, PIP_LINE_FLAGS):
                if k in ("-e", "--editable"):
                    if "://" in v or "+" in v.split("/", 1)[0] or not v.startswith((".", "/")):
                        raise LockError(f"line {n}: editable {v[:60]!r} isn't a local path")
                    continue
                if k not in PIP_INCLUDES:
                    continue
                if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", v):   # file:, https: and other URLs pip follows (R2-3)
                    raise LockError(f"line {n}: include {v[:60]!r} is a URL, not a path in the tree")
                inc = os.path.normpath(os.path.join(os.path.dirname(path), v))
                if not os.path.realpath(inc).startswith(os.path.realpath(root) + os.sep):
                    raise LockError(f"line {n}: include {inc} is outside the tree")
                out += _requirements(inc, seen, root, constraint or k in ("-c", "--constraint"))
            continue
        line = line.split(";", 1)[0].strip()
        line = _drop_pip_options(line)
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===?|<=)\s*(\S+)$", line)
        if not m or (m.group(3) == "<=" and not constraint):
            raise LockError(f"line {n}: {line[:60]!r} isn't pinned with ==" + (" (a <= ceiling is read only in a "
                            "constraints file)" if m else ""))
        out.append(("PyPI", m.group(1), exact(m.group(4), m.group(1))))
    return out


def _pipfile_lock(path):
    d = _load_json(path)
    out = []
    for sec in ("default", "develop"):
        for name, v in (d.get(sec) or {}).items():
            if not isinstance(v, dict) or not str(v.get("version", "")).startswith("=="):
                raise LockError(f"{name} isn't pinned with ==")
            out.append(("PyPI", name, exact(v["version"][2:], name)))
    return out


def _swift(path):
    d = _load_json(path)
    if d.get("version") not in (1, 2, 3):
        raise LockError(f"unknown Package.resolved version {d.get('version')!r}")
    pins = d.get("pins") or (d.get("object") or {}).get("pins")
    if not isinstance(pins, list):
        raise LockError("no pins list")
    out = []
    for p in pins:
        url = p.get("location") or p.get("repositoryURL")
        ver = (p.get("state") or {}).get("version")
        if not url:
            raise LockError("a pin without a location")
        if not ver:   # pinned to a branch or revision: can't be checked (pass 1 R3-7 a)
            raise LockError(f"{url} is pinned to a branch or revision, not a version")
        # OSV's SwiftURL names have no scheme and no .git (pass 1 R3-7 b): github.com/owner/repo
        name = re.sub(r"\.git$", "", re.sub(r"^[A-Za-z+]+://", "", url.strip()).rstrip("/"))   # case kept (pass 2 R3-4)
        out.append(("SwiftURL", name, exact(ver, name)))
    return out


NPM_NAME = re.compile(r"(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
# A registry range or tag: digits, letters, x * ^ ~ < > = | . + - _ and spaces. No "/", ":" or "#", which mean a
# GitHub shorthand, a URL, a path or a git ref (pass 3 R1-1).
NPM_RANGE = re.compile(r"[A-Za-z0-9.*^~<>=|+_ -]+")
# Clearly a version range: starts with a digit, an operator, * or v plus a digit. Anything else after "npm:" could be
# a package name or a dist-tag, and is never guessed (pass 4 R1-1): the entry's resolved URL decides, or it's an error.
# Each piece is matched on its own, with flat patterns and no nested repeats, so matching takes linear time on any
# input (pass 5 R1-1: the old one-regex grammar backtracked exponentially on a long "||" list).
MAX_SPEC = 512   # longer specs are an error before any pattern runs (raised from 128, DE-102: pass 6 R3-1 b)
# One number, or one x, X or *, per dotted segment (DE-102, pass 6 R1-3): "1.xx" or "1.2x" is a name, not a range.
_VER_RE = re.compile(r"v?[0-9]+(\.([0-9]+|[xX*])){0,2}")                                    # 1, 1.2, 1.2.x, 1.2.3
# Prerelease and build tails may hold "-" (DE-102, pass 6 R1-2): 1.0.0-beta-1, 19.0.0-rc-f994737d14-20240522.
_FULL_RE = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?")   # 1.2.3-beta.1+build
_OP_RE = re.compile(r"\^|~|[<>]=?|=")


def _is_version(tok):
    return bool(_FULL_RE.fullmatch(tok) or _VER_RE.fullmatch(tok))


def _clear_part(part):
    """One "||" alternative: "*", "V - V", or comparators ("^1.2", ">= 1.0 <2"), token by token."""
    toks = part.split()
    if toks == ["*"]:
        return True
    if len(toks) == 3 and toks[1] == "-":
        return _is_version(toks[0]) and _is_version(toks[2])
    if not toks:
        return False
    i = 0
    while i < len(toks):
        t = toks[i]
        m = _OP_RE.match(t)
        if m and m.end() == len(t):   # an operator on its own: the version is the next token
            if i + 1 >= len(toks) or not _is_version(toks[i + 1]):
                return False
            i += 2
            continue
        if not _is_version(t[m.end():] if m else t):
            return False
        i += 1
    return True


def clear_range(text):
    """True only for text that is plainly a semver range. Bare digits or v-digits with no dot or operator ("8",
    "v8") are not: they are also package names (pass 5 R1-2), so they go to the URL like any other word."""
    if len(text) > MAX_SPEC or not text.strip():
        return False
    if re.fullmatch(r"v?[0-9]+", text.strip()):
        return False
    return all(_clear_part(p) for p in text.split("||"))


class Ambiguous:
    """An "alias@npm:word" spec where word may be a package name or a dist-tag; only the resolved URL can tell."""
    def __init__(self, alias, word):
        self.alias, self.word = alias, word


def _split_name(spec):
    """'name@range' or '@scope/name@range' into (name, range); range is "" when absent."""
    k = spec.find("@", 1)
    return (spec, "") if k < 0 else (spec[:k], spec[k + 1:])


def _yarn_name(spec):
    """The real package name of one yarn spec, None for the repo's own code, or Ambiguous. Nothing is guessed: a
    spec it can't place exactly is an error (pass 2 R1-2, pass 3 R1-1, pass 4 R1-1)."""
    spec = spec.strip().strip('"')
    if len(spec) > 2 * MAX_SPEC:   # no pattern runs on a spec this long (pass 5 R1-1)
        raise LockError(f"spec too long to read ({len(spec)} characters)")
    name, rng = _split_name(spec)
    if not NPM_NAME.fullmatch(name):
        raise LockError(f"can't read spec {spec[:60]!r}")
    m = re.match(r"^([a-z+-]+):(.*)$", rng)
    if m is None:   # name@range or name@tag: a plain registry dependency, named in full
        if not NPM_RANGE.fullmatch(rng):
            raise LockError(f"{spec[:60]!r} isn't a registry range (a GitHub shorthand, path or URL can't be checked)")
        return name
    proto, rest = m.group(1), m.group(2)
    if proto == "npm":
        if clear_range(rest):
            return name   # "name@npm:^1.2.3": the same package by range
        if "::" in rest:   # Berry "npm:1.0.0::__archiveUrl=...": a tarball outside the registry (pass 5 R3-2)
            raise LockError(f"{spec[:60]!r} downloads from an archive URL outside the registry, which can't be checked")
        real, rr = _split_name(rest)
        if not NPM_NAME.fullmatch(real) or (rr and not NPM_RANGE.fullmatch(rr)):
            raise LockError(f"can't read alias {spec[:60]!r}")
        if rr or real.startswith("@"):
            return real   # "npm:real@range" or "npm:@s/real": only a package can be written that way
        return Ambiguous(name, real)   # "npm:word": a package or a tag
    if proto in ("workspace", "link", "portal", "file"):
        return None
    if proto == "patch":
        inner = rest.split("#", 1)[0].replace("%3A", ":")
        return _yarn_name(inner) if "@" in inner[1:] else name
    raise LockError(f"{spec[:60]!r} uses {proto}:, which can't be checked against a version database")


def _url_name(url):
    """The package name in a registry tarball URL (.../<name>/-/<file>.tgz or .../@scope/name/-/...), or None."""
    import urllib.parse
    u = urllib.parse.urlsplit(url.split("#", 1)[0])
    if u.scheme != "https" or "/-/" not in u.path:
        return None
    n = urllib.parse.unquote(u.path.split("/-/", 1)[0]).lstrip("/")
    return n if NPM_NAME.fullmatch(n) else None


def _yarn(path):
    """yarn.lock v1 and Berry (v2+): an entry line at column 0, then indented fields. Berry's resolution line, when
    present, names the real package; in v1 the resolved URL must agree with the spec, and decides an "npm:word"."""
    out = []
    entries, cur = [], None
    with open(path, encoding="utf-8") as fh:
        for raw in _capped(fh):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace():
                cur = None if line.startswith("__metadata") else {"head": line.rstrip(":"), "version": None,
                                                                    "res": None, "url": None}
                if cur is not None:
                    entries.append(cur)
                continue
            if cur is None or raw.startswith("    "):
                continue
            m = re.match(r'^  version:?\s+"?([^"\s]+)"?\s*$', line)
            if m:
                cur["version"] = m.group(1)
            m = re.match(r'^  resolution:\s+"?([^"\s]+)"?\s*$', line)
            if m:
                cur["res"] = m.group(1)
            m = re.match(r'^  resolved\s+"?([^"\s]+)"?\s*$', line)
            if m:
                cur["url"] = m.group(1)
    for e in entries:
        specs = [x for x in e["head"].split(",") if x.strip()]
        got = [_yarn_name(e["res"])] if e["res"] else [_yarn_name(x) for x in specs]
        if all(g is None for g in got):
            continue
        if any(g is None for g in got):
            raise LockError(f"entry {e['head'][:60]!r} mixes local and registry specs")
        url = _url_name(e["url"]) if e["url"] else None
        names = set()
        for g in got:
            if isinstance(g, Ambiguous):
                if url is None:
                    raise LockError(f"entry {e['head'][:60]!r}: npm:{g.word} could be a package or a tag, and no "
                                    f"registry URL says which")
                if url not in (g.word, g.alias):
                    raise LockError(f"entry {e['head'][:60]!r}: its URL names {url}, not {g.word} or {g.alias}")
                names.add(url)
            else:
                names.add(g)
        if len(names) != 1:
            raise LockError(f"entry {e['head'][:60]!r} mixes packages")
        name = names.pop()
        if url is not None and url != name:   # the spec and the download disagree
            raise LockError(f"entry {e['head'][:60]!r} reads as {name}, but its URL downloads {url}")
        if not e["version"]:
            raise LockError(f"entry {e['head'][:60]!r} has no version")
        out.append(("npm", name, exact(e["version"], name)))
    return out


PNPM_VERSIONS = re.compile(r"(5\.[0-9]+|6\.[0-9]+|7\.0|9\.0)")


def _pnpm_key(key, v5):
    key = key.strip().strip("'\"")
    if v5:
        # /name/1.2.3_peer@1.0.0 or /@scope/name/1.2.3_hash (pass 2 R1-3)
        parts = key.lstrip("/").split("/")
        n = 3 if parts[0].startswith("@") else 2
        if len(parts) != n:
            raise LockError(f"can't read v5 package key {key[:60]!r}")
        name, ver = "/".join(parts[:-1]), parts[-1].split("_", 1)[0]
    else:
        k = key.lstrip("/")
        if k.endswith(")") and "(" in k:   # (peer) suffix: cut at the first "(", by string methods (DE-102)
            k = k[:k.index("(")]
        if "@" not in k[1:]:
            raise LockError(f"can't read package key {key[:60]!r}")
        name, ver = k[: k.rindex("@")], k[k.rindex("@") + 1:]
        if "(" in ver or "_" in ver:
            raise LockError(f"can't read package key {key[:60]!r}")
    return name, ver


# "  name@1.0.0:" with nothing after the colon, or "  name@1.0.0: {}" (an empty entry, as v9 writes snapshots)
PNPM_KEY_LINE = re.compile(r"  (\S[^#{}\[\]]*?):( \{\})?")


def _pnpm(path):
    """pnpm-lock.yaml: package keys under "packages:" (v5 /name/1.2.3_peer, v6 /name@1.2.3(peer), v9 name@1.2.3).
    Only known lockfile versions are read. Strict (DE-102 pass 1 R3-2): inside "packages:" and "snapshots:" every line
    is a plain two-space "key:" line or a field indented four or more spaces; a comment after a key, a flow form or
    any other indent is an error, never skipped. In v9 every snapshot must name a package listed under "packages:"."""
    out, ver, sec, first_key = [], None, None, False
    keys = {"packages": set(), "snapshots": set()}
    with open(path, encoding="utf-8") as fh:
        for raw in _capped(fh):
            line = raw.rstrip("\r\n")
            m = re.match(r"^lockfileVersion:\s*'?([0-9.]+)'?\s*$", line)
            if m:
                ver = m.group(1)
                if not PNPM_VERSIONS.fullmatch(ver):
                    raise LockError(f"unknown pnpm lockfileVersion {ver}")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace():
                # Every top-level key is a plain word (DE-102 pass 3 R2-1): a quoted, tagged, anchored, complex or
                # flow-form head could be packages or snapshots under another spelling.
                if not re.match(r"^[A-Za-z][A-Za-z0-9_-]*:( |$)", line):
                    raise LockError(f"can't read top-level line {line[:60]!r}")
                head = line.split(":", 1)[0]
                if head in keys:
                    if line.rstrip() != head + ":":   # "packages: {...}" or "packages: # c"
                        raise LockError(f"can't read {line[:60]!r}")
                    sec, first_key = head, True
                else:
                    sec = None
                continue
            if sec is None:
                continue
            indent = len(line) - len(line.lstrip(" "))
            if line[:indent] != " " * indent or "\t" in line[:indent + 1]:
                raise LockError(f"can't read indent of {line.strip()[:60]!r}")
            if indent >= 4:
                if first_key:   # keys at indent 4: the whole mapping would be skipped (pass 3 R2-1)
                    raise LockError(f"{sec} keys aren't at indent 2")
                continue
            first_key = False
            km = PNPM_KEY_LINE.fullmatch(line.rstrip())
            if indent != 2 or not km:
                raise LockError(f"can't read {sec} key line {line.strip()[:60]!r}")
            if ver is None:
                raise LockError(f"{sec} before lockfileVersion")
            key = km.group(1)
            if key[0] in "&!*?|>%" or "\\" in key:   # YAML anchors, tags, complex keys, escapes (pass 2 R1-3)
                raise LockError(f"can't read {sec} key {key[:60]!r}")
            if key[0] in "'\"" and not (len(key) > 1 and key[-1] == key[0] and key[0] not in key[1:-1]):
                raise LockError(f"can't read quoted {sec} key {key[:60]!r}")
            name, v = _pnpm_key(key, ver.startswith("5"))
            if not NPM_NAME.fullmatch(name):
                raise LockError(f"{sec} key {key[:60]!r} doesn't name an npm package")
            exact(v, name)
            keys[sec].add((name, v))
    if ver is None:
        raise LockError("no lockfileVersion")
    if ver.startswith("9"):
        missing = keys["snapshots"] - keys["packages"]
        if missing:
            n, v = sorted(missing)[0]
            raise LockError(f"snapshot {n}@{v} has no entry under packages")
    elif keys["snapshots"]:
        raise LockError(f"snapshots: in a lockfileVersion {ver} file")
    return [("npm", n, v) for n, v in sorted(keys["packages"])]


def _gemfile_lock(path):
    out, inspecs = [], False
    with open(path, encoding="utf-8") as fh:
        for raw in _capped(fh):
            line = raw.rstrip("\n")
            if not line.strip():   # a blank line changes nothing; Bundler reads on (DE-102 pass 3 R2-2)
                continue
            if inspecs and line[0] == "\t" or "\t" in line[:len(line) - len(line.lstrip())]:
                raise LockError(f"can't read tab-indented line {line.strip()[:60]!r}")
            if not line.startswith(" "):
                inspecs = False
            if line.strip() == "specs:":
                inspecs = True
                continue
            m = re.match(r"^    ([A-Za-z0-9._-]+) \(([^)]+)\)$", line)
            if inspecs and re.match(r"^ {4}\S", line) and not m:   # a spec line it can't read (DE-102 pass 2)
                raise LockError(f"can't read spec line {line.strip()[:60]!r}")
            if inspecs and m:
                v = m.group(2).split("-", 1)[0]   # "1.13.0-x86_64-linux": the platform follows the first "-"
                out.append(("RubyGems", m.group(1), exact(v, m.group(1))))
    return out


def _composer(path):
    d = _load_json(path)
    out = []
    for sec in ("packages", "packages-dev"):
        for p in d.get(sec) or []:
            if not isinstance(p, dict) or not p.get("name"):
                raise LockError("a package without a name")
            ver = str(p.get("version", ""))
            if ver.startswith("dev-") or ver.endswith("-dev"):   # a branch, not a release (pass 2 R3-3)
                raise LockError(f"{p['name']} is pinned to a branch ({ver}), not a version")
            out.append(("Packagist", p["name"], exact(ver.lstrip("v"), p["name"])))
    return out


def _nuget(path):
    d = _load_json(path)
    if d.get("version") not in (1, 2):
        raise LockError(f"unknown packages.lock.json version {d.get('version')!r}")
    out = []
    for fw, deps in (d.get("dependencies") or {}).items():
        for name, v in (deps or {}).items():
            if not isinstance(v, dict):
                raise LockError(f"{name} isn't an object")
            if v.get("type") == "Project":
                continue
            out.append(("NuGet", name, exact(v.get("resolved"), name)))
    return out


# Gradle's dependency verification file (DE-116). Gradle writes each component on one line, attributes in this order;
# any other line naming a component is an error, never skipped.
GRADLE_COMPONENT_RE = re.compile(r'\s*<component group="([A-Za-z0-9][A-Za-z0-9._-]{0,199})" '
                                 r'name="([A-Za-z0-9][A-Za-z0-9._-]{0,199})" version="([^"<>&\s]{1,100})">')
GRADLE_KNOWN_RE = re.compile(r"\s*</?components>|\s*</component>")
GRADLE_TAG_RE = re.compile(r"<\s*/?\s*([\w.-]+:)?components?(?![\w.:-])")   # the element, with or without a prefix
# What lets a component through without its own <component> entry: trust by group, name or version (trust by file
# name alone covers only extra files such as sources jars), trusted keys, and signature checks.
GRADLE_TRUST_RE = re.compile(r"<trust\b[^>]*\b(group|name|version)\s*=|<trusted-keys?\b|<key-servers?\b|"
                             r"<verify-signatures>\s*true")
GRADLE_SETTINGS = ("settings.gradle", "settings.gradle.kts")


def _gradle_verification(path):
    """Every <component> in a gradle/verification-metadata.xml, as Maven group:name packages."""
    out = []
    with open(path, encoding="utf-8") as fh:
        lines = list(_capped(fh))
    text = "".join(lines)
    if re.search(r"<!(?!--)|<\?(?!xml\s)|&(?!(amp|lt|gt|quot|apos);)", text):
        raise LockError("has a DOCTYPE, entity, CDATA or processing instruction, which Gradle never writes")
    if "<verification-metadata" not in text:
        raise LockError("isn't a Gradle verification-metadata file")
    if GRADLE_TRUST_RE.search(text):
        raise LockError("lets components through without listing them (trust by group, name or version, trusted "
                        "keys or signature checks), so its list isn't every component the build resolves")
    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not GRADLE_TAG_RE.search(line):
            continue
        m = GRADLE_COMPONENT_RE.fullmatch(line)
        if m:
            out.append(("Maven", f"{m.group(1)}:{m.group(2)}", exact(m.group(3), f"{m.group(1)}:{m.group(2)}")))
        elif not GRADLE_KNOWN_RE.fullmatch(line):
            raise LockError(f"line {n}: a component line that isn't in Gradle's own form")
    if not out:   # Gradle lists at least the plugins a build applies; an empty list isn't read as "nothing to check"
        raise LockError("lists no components")
    return out


def _gradle_root_verified(tree, rel):
    """True when the build script at rel sits in a Gradle build whose root (the nearest folder at or above it with a
    settings file) has gradle/verification-metadata.xml as a regular file."""
    top = os.path.realpath(tree)
    d = os.path.dirname(os.path.join(tree, rel))
    while True:
        if any(os.path.isfile(os.path.join(d, s)) for s in GRADLE_SETTINGS):
            try:
                return stat.S_ISREG(os.lstat(os.path.join(d, "gradle", "verification-metadata.xml")).st_mode)
            except OSError:
                return False
        if os.path.realpath(d) == top or os.path.dirname(d) == d:
            return False
        d = os.path.dirname(d)


def is_gradle_verification(rel):
    parts = rel.replace(os.sep, "/").split("/")
    return parts[-1] == "verification-metadata.xml" and len(parts) > 1 and parts[-2] == "gradle"


PARSERS = {"package-lock.json": _npm, "npm-shrinkwrap.json": _npm, "Cargo.lock": lambda p: _toml_packages(p, "crates.io"),
           "poetry.lock": lambda p: _toml_packages(p, "PyPI"), "uv.lock": lambda p: _toml_packages(p, "PyPI", uv=True),
           "Package.resolved": _swift, "Pipfile.lock": _pipfile_lock, "yarn.lock": _yarn, "pnpm-lock.yaml": _pnpm,
           "Gemfile.lock": _gemfile_lock, "composer.lock": _composer, "packages.lock.json": _nuget,
           # The scanners' own pins (DE-56): pip hash-lock format, so the threat feed checks the tools too.
           "security-scan-tools.lock": _requirements}
REQ_RE = re.compile(r".*(requirements|constraints).*\.txt", re.I)
# pip's hash-lock format under a .lock name, such as build-requirements.lock (DE-116).
REQ_LOCK_RE = re.compile(r".*requirements.*\.lock", re.I)
# Anything that looks like a lockfile but has no reader is not checked (pass 2 R2-4), never silently skipped.
LOCKLIKE_RE = re.compile(r".*\.lock|.*lock.*\.json|.*lock.*\.ya?ml|.*lock.*\.toml|.*\.lockb", re.I)


def is_requirements(rel):
    parts = rel.replace(os.sep, "/").split("/")
    return bool(REQ_RE.fullmatch(parts[-1]) or REQ_LOCK_RE.fullmatch(parts[-1])) or \
        (len(parts) > 1 and parts[-2].lower() == "requirements"
                                                 and parts[-1].lower().endswith(".txt"))


def is_lockfile(name, rel=None):
    return name in PARSERS or name in UNCOVERED or is_requirements(rel or name) or bool(LOCKLIKE_RE.fullmatch(name)) \
        or is_gradle_verification(rel or name)


def not_covered_id(rel):
    """The finding id security-scan.py gives a not-checked lockfile (same form as its other ids)."""
    return f"threat-feed:not-covered:{rel}:" + hashlib.sha256(" ".join(rel.split()).encode()).hexdigest()[:12]


def lockfiles(tree):
    """(covered [(relpath, [(eco, name, version)])], uncovered [relpath], errors [str])."""
    covered, uncovered, errors = [], [], []
    if not os.path.isdir(tree):
        return [], [], [f"threat feed: {tree} is not a directory"]
    for dp, dns, fns in os.walk(tree):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for f in sorted(fns):
            full = os.path.join(dp, f)
            rel = os.path.normpath(os.path.relpath(full, tree))
            if not is_lockfile(f, rel):
                continue
            try:
                st = os.lstat(full)
            except OSError as e:
                errors.append(f"threat feed: can't read {rel} ({e})")
                continue
            if not stat.S_ISREG(st.st_mode):   # a symlink, FIFO or device (pass 1 R2-11)
                errors.append(f"threat feed: {rel} is not a regular file")
                continue
            parser = PARSERS.get(f) or ((lambda x: _requirements(x, root=tree)) if is_requirements(rel) else None) \
                or (_gradle_verification if is_gradle_verification(rel) else None)
            if f in ("build.gradle", "build.gradle.kts") and _gradle_root_verified(tree, rel):
                continue   # its components are read from the build root's verification file (DE-116)
            if f in UNCOVERED or parser is None:
                uncovered.append(rel)
                continue
            try:
                pkgs = sorted(set(parser(full)))
            except Exception as e:
                errors.append(f"threat feed: can't read {rel} ({e})")
                continue
            if not pkgs and (st.st_size > 200 or _looks_populated(f, full)):
                # a lockfile that yields nothing but looks like it lists packages, at any size (DE-102 pass 3 R2-1);
                # the size rule stays as a second net. A dependency-free lockfile reads as empty.
                errors.append(f"threat feed: {rel} yields no packages; format not understood")
                continue
            covered.append((rel, pkgs))
    return covered, uncovered, errors


# Per format, what a lockfile that lists any package must contain (DE-102 pass 3 R2-1). A file that matches but reads
# as empty is an error at any size.
POPULATED = {"pnpm-lock.yaml": re.compile(r"packages|snapshots|@[0-9]"),
             "Gemfile.lock": re.compile(r"^\s+\S+ ?\(", re.M),
             "yarn.lock": re.compile(r"^[^#\s_][^\n]*:|version|resolution", re.M)}
# TOML lockfiles need no entry: tomllib reads them as cargo, uv and poetry do, and the line reader without it refuses
# every form it doesn't read exactly (a uv project's own virtual root reads as empty on purpose).


def _looks_populated(name, path):
    pat = POPULATED.get(name)
    if pat is None:
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = "".join(ln for ln in fh if not ln.lstrip().startswith("#"))
    except OSError:
        return True
    return bool(pat.search(text))


# ---------- network, with a local copy ----------

def tool(cmd, cwd=None, data=None, timeout=600):
    """The one place this script (and sbom.py) starts a process: curl or git, by full path, a fixed argument list,
    no shell. Returns the CompletedProcess (bytes)."""
    if cmd[0] not in ("curl", "git"):
        raise RuntimeError(f"not an allowed tool: {cmd[0]}")
    exe = shutil.which(cmd[0])
    if not exe:
        raise RuntimeError(f"{cmd[0]} is not installed")
    return subprocess.run([exe, *cmd[1:]], cwd=cwd, input=data, capture_output=True, timeout=timeout)


def fetch(url, data=None, timeout=60):
    """curl, HTTPS only, no redirects, no ~/.curlrc, no URL globbing (pass 1 R1-9, R3-8); returns bytes or raises."""
    cmd = ["curl", "-q", "-fsS", "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "0", "-g",
           "--max-time", str(timeout)]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
    p = tool(cmd + [url], data=data, timeout=timeout + 10)
    if p.returncode:
        raise RuntimeError(f"curl exit {p.returncode} for {url.split('?')[0]}")
    return p.stdout


def cached(name, getter, valid, now=None):
    """A copy refreshed every FRESH_H hours, used up to MAX_AGE_H if the source can't be reached, else an error.
    Only a body that passes valid() is written or reused (pass 1 R2-4); a copy dated in the future is stale (R2-9)."""
    now = now or time.time()
    os.makedirs(CACHE, exist_ok=True)
    f = os.path.join(CACHE, name)
    copy, age = None, None
    if os.path.isfile(f) and not os.path.islink(f):
        age = now - os.path.getmtime(f)
        with open(f, "rb") as fh:
            copy = fh.read()
        try:
            valid(copy)
        except Exception:
            copy = None
        if age < 0:
            copy = None
    if copy is not None and age < FRESH_H * 3600:
        return copy, age
    try:
        body = getter()
        valid(body)
        with open(f + ".tmp", "wb") as fh:
            fh.write(body)
        os.replace(f + ".tmp", f)
        return body, 0
    except Exception as e:
        if copy is not None and age < MAX_AGE_H * 3600:
            return copy, age
        raise RuntimeError(f"{name}: source unreachable or bad ({e}) and no good copy under {MAX_AGE_H}h old")


def _kev_ids(body):
    d = json.loads(body)
    if not isinstance(d, dict) or not isinstance(d.get("vulnerabilities"), list):
        raise ValueError("KEV catalog isn't the expected shape")
    ids = {v["cveID"] for v in d["vulnerabilities"] if isinstance(v, dict) and isinstance(v.get("cveID"), str)}
    if len(ids) < 100:   # the catalog has well over a thousand; a short list is a broken download
        raise ValueError(f"KEV catalog looks truncated ({len(ids)} entries)")
    return ids, str(d.get("catalogVersion", ""))


def kev(get=fetch):
    body, age = cached("kev.json", lambda: get(KEV_URL), _kev_ids)
    ids, ver = _kev_ids(body)
    return ids, ver, hashlib.sha256(body).hexdigest(), age


def osv_query(pkgs, get=fetch):
    """{(eco, name, version): [vuln ids]} for every package, through OSV's batch API (1000 per call)."""
    pkgs = sorted(set(pkgs))
    out = {}
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        q = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        body = json.loads(get(OSV_BATCH, json.dumps(q).encode()))
        res = body.get("results") if isinstance(body, dict) else None
        if not isinstance(res, list) or len(res) != len(chunk):
            raise RuntimeError("OSV answered with the wrong number of results")
        for p, r in zip(chunk, res):
            if not isinstance(r, dict):
                raise RuntimeError(f"OSV result for {p[1]} isn't an object")
            if r.get("next_page_token"):
                raise RuntimeError(f"OSV result for {p[1]} is paged; not handled, failing closed")
            vulns = r.get("vulns", [])
            if not isinstance(vulns, list):
                raise RuntimeError(f"OSV vulns for {p[1]} isn't a list")
            ids = []
            for v in vulns:   # a malformed entry is an error, not "no vulnerability" (pass 1 R2-6)
                if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not ID_RE.fullmatch(v["id"]):
                    raise RuntimeError(f"OSV returned a malformed vulnerability for {p[1]}")
                ids.append(v["id"])
            if ids:
                out[p] = ids
    return out


def _vuln_ok(body):
    d = json.loads(body)
    if not isinstance(d, dict) or not isinstance(d.get("id"), str):
        raise ValueError("not an OSV record")
    return d


def osv_vuln(vid, get=fetch):
    if not ID_RE.fullmatch(vid):
        raise RuntimeError(f"bad vulnerability id {vid[:40]!r}")
    body, _ = cached(f"osv-{vid.replace(':', '_')}.json", lambda: get(OSV_VULN + vid), _vuln_ok)
    return _vuln_ok(body)


def severity(v, in_kev):
    if in_kev:
        return "Critical (CISA KEV)"
    s = str((v.get("database_specific") or {}).get("severity") or "").upper()
    return {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}.get(s, "High")


def check(tree, get=fetch, only=None):
    """Returns (matches, uncovered, notes, errors, feed_version). matches: dicts with lockfile, ecosystem, name,
    version, id, aliases, severity, kev, summary. uncovered: lockfiles it doesn't read (each a blocking finding in
    security-scan.py unless accepted). only: lockfile paths to check (quick mode), or None for all."""
    covered, uncovered, errors = lockfiles(tree)
    if only is not None:
        covered = [c for c in covered if c[0] in only]
        uncovered = [u for u in uncovered if u in only]
        errors = [e for e in errors if any(o in e for o in only)] if only else []
    notes = []
    if not covered:
        if only is None and not uncovered and not errors:
            notes.append("no lockfiles found")
        return [], uncovered, notes, errors, ""
    try:
        kev_ids, kev_ver, kev_sha, _ = kev(get)
    except Exception as e:
        return [], uncovered, notes, errors + [f"threat feed: {e}"], ""
    allp = [p for _, ps in covered for p in ps]
    try:
        hits = osv_query(allp, get)
    except Exception as e:
        return [], uncovered, notes, errors + [f"threat feed: OSV query failed ({e})"], ""
    matches = []
    for lock, ps in covered:
        for p in ps:
            for vid in hits.get(p, []):
                try:
                    v = osv_vuln(vid, get)
                except Exception as e:
                    errors.append(f"threat feed: can't read {vid} ({e})")
                    continue
                if v.get("withdrawn"):
                    continue
                al = v.get("aliases") or []
                aliases = sorted(set([vid] + [a for a in al if isinstance(a, str)]))
                in_kev = any(a in kev_ids for a in aliases)
                matches.append(dict(lockfile=lock, ecosystem=p[0], name=p[1], version=p[2], id=vid, aliases=aliases,
                                    severity=severity(v, in_kev), kev=in_kev, summary=str(v.get("summary") or "")[:200]))
    # The feed version covers the tool, the KEV catalog and what OSV answered (pass 1 R3-10).
    state = json.dumps(sorted([list(k) + sorted(v) for k, v in hits.items()]))
    feed_version = hashlib.sha256(f"{VERSION}|{kev_ver}|{kev_sha}|{state}".encode()).hexdigest()
    notes.append(f"{len(allp)} pinned package(s) in {len(covered)} lockfile(s) checked against OSV; KEV catalog {kev_ver}")
    return matches, uncovered, notes, errors, feed_version


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ghost Labs threat feed (DE-98)")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    report, bad = [], False
    for p in a.paths:
        try:
            m, unc, notes, errs, fv = check(p)
        except Exception as e:   # anything unexpected is an error for that path, never a clean result
            m, unc, notes, errs, fv = [], [], [], [f"threat feed: {e}"], ""
        report.append(dict(path=p, matches=m, not_checked=unc, notes=notes, errors=errs, feed_version=fv))
        bad = bad or bool(m or unc or errs)
    if a.json:
        print(json.dumps(dict(version=VERSION, repos=report), indent=1))
    else:
        for r in report:
            print(f"{r['path']}: {len(r['matches'])} match(es), {len(r['not_checked'])} not checked, {len(r['errors'])} error(s)")
            for m in r["matches"]:
                print(f"  [{m['severity']}] {m['lockfile']} {m['name']} {m['version']} {m['id']} {m['summary'][:80]}")
            for u in r["not_checked"]:
                print(f"  NOT CHECKED: {u} (no reader for this format; accept it or add a reader)")
            for e in r["errors"]:
                print(f"  ! {e}")
            for n in r["notes"]:
                print(f"  {n}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

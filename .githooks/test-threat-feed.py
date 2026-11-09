#!/usr/bin/env python3
"""Tests for threat-feed.py and sbom.py (DE-98). Run: python3 .githooks/test-threat-feed.py

The network is replaced by a fake inside the test process only; the scripts have no switch for fake data.
"""
import datetime, importlib.util, json, os, sys, tempfile, time, types, unittest, warnings

warnings.simplefilter("ignore", ResourceWarning)
sys.dont_write_bytecode = True
sys.pycache_prefix = tempfile.mkdtemp(prefix="gl-nopyc-")   # never read a planted pyc
HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


tf = load("tf", "threat-feed.py")
sb = load("sb", "sbom.py")

KEV = {"catalogVersion": "2026.11.03",
       "vulnerabilities": [{"cveID": f"CVE-2020-{i:05d}"} for i in range(200)] + [{"cveID": "CVE-2021-44228"}]}


class Fake:
    def __init__(self, vulns=None, fail=False, kev=KEV):
        self.vulns = vulns or {}   # (eco, name, version) -> [osv records]
        self.fail, self.kev, self.calls = fail, kev, []

    def __call__(self, url, data=None, timeout=60):
        self.calls.append(url)
        if self.fail:
            raise RuntimeError("unreachable")
        if url == tf.KEV_URL:
            return json.dumps(self.kev).encode()
        if url == tf.OSV_BATCH:
            q = json.loads(data)["queries"]
            res = []
            for x in q:
                key = (x["package"]["ecosystem"], x["package"]["name"], x["version"])
                res.append({"vulns": [{"id": v["id"]} for v in self.vulns[key]]} if key in self.vulns else {})
            return json.dumps({"results": res}).encode()
        if url.startswith(tf.OSV_VULN):
            vid = url[len(tf.OSV_VULN):]
            for vs in self.vulns.values():
                for v in vs:
                    if v["id"] == vid:
                        return json.dumps(v).encode()
        raise RuntimeError(f"unexpected {url}")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = tempfile.TemporaryDirectory()
        tf.CACHE = self.cache.name
        self.tree = self.tmp.name

    def write(self, rel, text):
        p = os.path.join(self.tree, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text))

    def npm(self, rel="worker/package-lock.json", pkgs=(("lodash", "4.17.15"), ("@scope/x", "1.0.0"))):
        packages = {"": {"name": "app", "version": "0.1.0"}}
        for n, v in pkgs:
            packages[f"node_modules/{n}"] = {"version": v}
        self.write(rel, {"lockfileVersion": 3, "packages": packages})

    def age(self, hours):
        for f in os.listdir(tf.CACHE):
            t = time.time() - hours * 3600
            os.utime(os.path.join(tf.CACHE, f), (t, t))


class Parsing(Base):
    def got(self):
        cov, unc, err = tf.lockfiles(self.tree)
        return {p: ps for p, ps in cov}, unc, err

    def test_lockfiles(self):
        self.npm()
        self.write("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.1"\n\n[[package]]\nname = \'x\'\nversion = \'0.2.0\'\nsource = "y"\n')
        self.write("tools/requirements.txt", "requests==2.19.0  # old\nbandit[toml]==1.7.0\n-r more.txt\n")
        self.write("tools/more.txt", "urllib3==1.26.0\n")
        self.write("node_modules/evil/package-lock.json", {"lockfileVersion": 3, "packages": {}})
        self.write("vendor/app/poetry.lock", '[[package]]\nname = "flask"\nversion = "2.0.0"\n')
        self.write("android/build.gradle", "x")
        got, unc, err = self.got()
        self.assertEqual(err, [])
        self.assertIn(("npm", "lodash", "4.17.15"), got["worker/package-lock.json"])
        self.assertIn(("npm", "@scope/x", "1.0.0"), got["worker/package-lock.json"])
        self.assertEqual(got["Cargo.lock"], [("crates.io", "serde", "1.0.1"), ("crates.io", "x", "0.2.0")])
        self.assertEqual(got["tools/requirements.txt"],
                         [("PyPI", "bandit", "1.7.0"), ("PyPI", "requests", "2.19.0"), ("PyPI", "urllib3", "1.26.0")])
        self.assertIn("vendor/app/poetry.lock", got)   # vendor is no longer skipped (pass 1 R1-5 c)
        self.assertNotIn("node_modules/evil/package-lock.json", got)
        self.assertEqual(unc, ["android/build.gradle"])

    def test_more_formats(self):
        self.write("yarn.lock", '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1":\n  version "7.2.0"\n  resolved "x"\n\nleft-pad@1.0.0:\n  version "1.0.0"\n')
        self.write("b/yarn.lock", '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n')
        self.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: x}\n\n  '@types/node@20.1.0':\n    resolution: {integrity: y}\n")
        self.write("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n      x (>= 1)\n    nokogiri (1.13.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n")
        self.write("composer.lock", {"packages": [{"name": "monolog/monolog", "version": "v2.3.0"}], "packages-dev": []})
        self.write("packages.lock.json", {"version": 1, "dependencies": {"net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"}, "Me": {"type": "Project"}}}})
        self.write("Pipfile.lock", {"default": {"django": {"version": "==3.2.0"}}, "develop": {}})
        self.write("Package.resolved", {"version": 2, "pins": [{"location": "https://github.com/Apple/swift-nio.git", "state": {"version": "2.40.0"}}]})
        got, unc, err = self.got()
        self.assertEqual(err, [], err)
        self.assertEqual(got["yarn.lock"], [("npm", "@babel/core", "7.2.0"), ("npm", "left-pad", "1.0.0")])
        self.assertEqual(got["b/yarn.lock"], [("npm", "lodash", "4.17.20")])
        self.assertEqual(got["pnpm-lock.yaml"], [("npm", "@types/node", "20.1.0"), ("npm", "lodash", "4.17.21")])
        self.assertEqual(got["Gemfile.lock"], [("RubyGems", "nokogiri", "1.13.0"), ("RubyGems", "rack", "2.2.3")])
        self.assertEqual(got["composer.lock"], [("Packagist", "monolog/monolog", "2.3.0")])
        self.assertEqual(got["packages.lock.json"], [("NuGet", "Newtonsoft.Json", "12.0.1")])
        self.assertEqual(got["Pipfile.lock"], [("PyPI", "django", "3.2.0")])
        self.assertEqual(got["Package.resolved"], [("SwiftURL", "github.com/Apple/swift-nio", "2.40.0")])  # R3-7 b

    def test_parse_surprises_are_errors(self):
        cases = {
            "a/package-lock.json": {"lockfileVersion": 4, "pkgs": {"x": 1}},              # R3-3
            "b/package-lock.json": "{not json",
            "c/Cargo.lock": '[[package]]\nname = "x"\n',                                    # no version
            "d/requirements.txt": "bad==1.0.*\n",                                           # R1-5 d
            "e/requirements.txt": "flask>=2\n",                                             # not pinned
            "f/Package.resolved": {"version": 9, "pins": []},
            "g/Package.resolved": {"version": 2, "pins": [{"location": "https://x/y", "state": {"branch": "main"}}]},  # R3-7 a
            "h/requirements.txt": "-r ../../outside.txt\n",
            "i/Cargo.lock": "[[package]]\nname = x\nversion = \"1\"\n",
        }
        for rel, body in cases.items():
            with self.subTest(rel=rel):
                self.tmp = tempfile.TemporaryDirectory()
                self.tree = self.tmp.name
                self.write(rel, body)
                _, _, err = self.got()
                self.assertTrue(err, rel)

    def test_pass2_yarn_alias_reads_the_real_name(self):   # pass 2 R1-2
        self.write("a/yarn.lock", '"safe@npm:lodash@4.17.4":\n  version "4.17.4"\n')
        self.write("b/yarn.lock", '__metadata:\n  version: 6\n\n"safe@npm:lodash@4.17.4":\n  version: 4.17.4\n  resolution: "lodash@npm:4.17.4"\n')
        got, _, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(got["a/yarn.lock"], [("npm", "lodash", "4.17.4")])
        self.assertEqual(got["b/yarn.lock"], [("npm", "lodash", "4.17.4")])

    def test_pass3_yarn_bare_alias_reads_the_real_name(self):   # pass 3 R1-1, pass 4 R1-1
        cases = {"safe@npm:@s/real": "@s/real", "safe@npm:lodash@4.17.4": "lodash", "safe@npm:@s/real@^1": "@s/real",
                 "lodash@npm:^4.17.0": "lodash", "lodash@npm:4.17.20": "lodash", "lodash@^4.17.0": "lodash",
                 "@babel/core@^7.0.0": "@babel/core", "x@>=1 <2": "x", "x@latest": "x", "app@workspace:.": None}
        for spec, want in cases.items():
            with self.subTest(spec=spec):
                self.assertEqual(tf._yarn_name(spec), want)
        for spec in ["lodash@user/repo", "x@./local.tgz", "x@npm:lodash@user/repo", "x@git+https://e.com/x.git",
                     "x@github:u/r", "x@https://e.com/x.tgz", "x@npm:@s", "x@#main", "bad name@1"]:
            with self.subTest(spec=spec):
                with self.assertRaises(tf.LockError):
                    tf._yarn_name(spec)

    def test_pass4_npm_word_is_never_guessed(self):   # pass 4 R1-1: package or tag, the URL decides, else an error
        for word in ["lodash", "p-limit", "d3", "q", "x-ray", "3d-view", "v8-compile-cache", "x", "X", "latest", "next"]:
            with self.subTest(word=word):
                g = tf._yarn_name(f"safe@npm:{word}")
                self.assertIsInstance(g, tf.Ambiguous)
                # no URL: an error, never a name
                self.tmp = tempfile.TemporaryDirectory()
                self.tree = self.tmp.name
                self.write("yarn.lock", f'"safe@npm:{word}":\n  version "2.0.0"\n')
                self.assertTrue(self.got()[2])
                # URL names the real package: read as it
                self.write("yarn.lock", f'"safe@npm:{word}":\n  version "2.0.0"\n  resolved "https://registry.yarnpkg.com/{word}/-/{word}-2.0.0.tgz#abc"\n')
                got, _, err = self.got()
                self.assertEqual((got.get("yarn.lock"), err), ([("npm", word, "2.0.0")], []))
        # npm:latest that is a tag: the URL names the alias itself
        self.write("yarn.lock", '"safe@npm:latest":\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/safe/-/safe-1.0.0.tgz"\n')
        got, _, err = self.got()
        self.assertEqual((got.get("yarn.lock"), err), ([("npm", "safe", "1.0.0")], []))
        # the URL names something else entirely: an error
        self.write("yarn.lock", '"safe@npm:p-limit":\n  version "2.0.0"\n  resolved "https://registry.yarnpkg.com/evil/-/evil-2.0.0.tgz"\n')
        self.assertTrue(self.got()[2])
        # a plain entry whose URL downloads another package: an error
        self.write("yarn.lock", 'lodash@^4.17.0:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/evil/-/evil-1.0.0.tgz"\n')
        self.assertTrue(self.got()[2])
        # a scoped URL, percent-encoded
        self.write("yarn.lock", '"safe@npm:@s/real":\n  version "1.0.0"\n  resolved "https://registry.npmjs.org/@s%2freal/-/real-1.0.0.tgz"\n')
        got, _, err = self.got()
        self.assertEqual((got.get("yarn.lock"), err), ([("npm", "@s/real", "1.0.0")], []))

    def test_pass5_range_check_is_linear(self):   # pass 5 R1-1: a crafted spec must not hang the gate
        import time
        hostile = [" || ".join(["1"] * 5000) + "!", "1 " * 5000 + "!", ">=" * 3000 + "1", "1.2.3-" + "a." * 3000,
                   " || ".join(["^1.2.3 <2"] * 2000) + " !"]
        for h in hostile:
            t = time.time()
            self.assertFalse(tf.clear_range(h))
            with self.assertRaises(tf.LockError):
                tf._yarn_name("a@npm:" + h)
            self.assertLess(time.time() - t, 1.0)
        t = time.time()
        self.write("yarn.lock", '"a@npm:' + " || ".join(["1"] * 40) + ' !":\n  version "1.0.0"\n')
        self.assertTrue(self.got()[2])
        self.assertLess(time.time() - t, 1.0)
        for r in ["^1.2.3", "~1.2", ">=1 <2", ">= 1.0.0 < 2", "1.0.0 || 2.x", "1.2.3-beta.1", "*", "1.2 - 2.3", "4.17.20"]:
            with self.subTest(r=r):
                self.assertTrue(tf.clear_range(r))
        for r in ["8", "v8", "1.", ".1", "^", "x", "latest", "3d-view", "1.2.3.4", ""]:
            with self.subTest(r=r):
                self.assertFalse(tf.clear_range(r))

    def test_pass5_digit_names_go_to_the_url(self):   # pass 5 R1-2
        for word in ["8", "v8"]:
            with self.subTest(word=word):
                self.assertIsInstance(tf._yarn_name(f"safe@npm:{word}"), tf.Ambiguous)
                self.write("yarn.lock", f'"safe@npm:{word}":\n  version "2.0.0"\n')
                self.assertTrue(self.got()[2])

    def test_pass5_url_and_head_checks(self):   # pass 5 R2-2: one test per surviving mutation
        bad = {
            "http URL": '"safe@npm:p-limit":\n  version "2.0.0"\n  resolved "http://registry.yarnpkg.com/p-limit/-/p-limit-2.0.0.tgz"\n',
            "local and registry in one head": '"x@workspace:., x@^1.0.0":\n  version "1.0.0"\n',
            "two packages in one head": '"a@^1.0.0, b@^1.0.0":\n  version "1.0.0"\n',
        }
        for what, body in bad.items():
            with self.subTest(what=what):
                self.write("yarn.lock", body)
                self.assertTrue(self.got()[2], what)
        good = {
            "hash in the URL": ('"safe@npm:p-limit":\n  version "2.0.0"\n  resolved "https://registry.yarnpkg.com/p-limit/-/p-limit-2.0.0.tgz#sha1abc"\n', "p-limit"),
            "percent-encoded scope": ('"@s/real@^1.0.0":\n  version "1.0.0"\n  resolved "https://registry.npmjs.org/@s%2freal/-/real-1.0.0.tgz"\n', "@s/real"),
        }
        for what, (body, name) in good.items():
            with self.subTest(what=what):
                self.write("yarn.lock", body)
                got, _, err = self.got()
                self.assertEqual((err, got["yarn.lock"][0][1]), ([], name))
        self.assertIsNone(tf._url_name("https://registry.npmjs.org/a/b/-/x.tgz"))   # a path NPM_NAME rejects
        self.assertEqual(tf._url_name("https://registry.npmjs.org/@s%2Freal/-/real-1.0.0.tgz"), "@s/real")

    def test_de102_ranges_and_caps(self):   # DE-102: pass 6 R1-2, R1-3, R2-1, R2-2 and R3-1
        for r in ["1.0.0-beta-1", "1.2.3+build-1", "19.0.0-rc-f994737d14-20240522", ">=1.0.0-rc-1", "1.0.0+build-5",
                  "1.x", "1.2.*", "v1.2.X"]:
            with self.subTest(r=r):
                self.assertTrue(tf.clear_range(r))
        for r in ["1.xx", "1.2x", "1.x0", "1.0x", "1.**", "v1.xx", "1 ||", "|| 1", "||", "1 - ", "- 1", "1 - garbage",
                  "1 |||| 2", "1 | 2", "1.2.3.", "1..2"]:
            with self.subTest(r=r):
                self.assertFalse(tf.clear_range(r))
        # a React canary through a Berry resolution line, which has no URL to fall back on
        self.write("yarn.lock", '__metadata:\n  version: 6\n\n"react@npm:19.0.0-rc-f994737d14-20240522":\n'
                   '  version: 19.0.0-rc-f994737d14-20240522\n  resolution: "react@npm:19.0.0-rc-f994737d14-20240522"\n')
        got, _, err = self.got()
        self.assertEqual((err, got.get("yarn.lock")), ([], [("npm", "react", "19.0.0-rc-f994737d14-20240522")]))
        # 18 ranges joined by " || " fit under the raised cap
        self.assertTrue(tf.clear_range(" || ".join(f"^{n}.0.0" for n in range(1, 19))))
        # a Berry archive URL alias says what it is
        with self.assertRaisesRegex(tf.LockError, "archive URL"):
            tf._yarn_name("foo@npm:1.0.0::__archiveUrl=https%3A%2F%2Fe.com%2Ffoo.tgz")
        # hostile specs just under the cap reach the per-part check, which must stay fast
        n = tf.MAX_SPEC
        hostile = [("1 || " * n)[: n - 2] + "!", ("1 " * n)[: n - 2] + "!", (">=" * n)[: n - 2] + "1",
                   ("1.2.3-" + "a." * n)[: n - 2] + "!", ("^1.2.3 <2 || " * n)[: n - 3] + " !"]
        for h in hostile:
            with self.subTest(h=h[:20]):
                self.assertLess(len(h), n)
                t = time.time()
                tf.clear_range(h)
                try:
                    tf._yarn_name("a@npm:" + h)
                except tf.LockError:
                    pass
                self.assertLess(time.time() - t, 1.0)
        # and the per-part check on its own, far past the cap, is linear too
        t = time.time()
        self.assertFalse(tf._clear_part("1 " * 100000 + "!"))
        self.assertLess(time.time() - t, 1.0)

    def test_de102_long_lines_are_errors_and_fast(self):   # DE-102: pass 6 R1-1, quadratic reader regexes
        bodies = {"requirements.txt": "a" + " " * 200000 + "==1.0\n",
                  "pnpm-lock.yaml": "lockfileVersion: '9.0'\n\npackages:\n\n  a@1" + "(" * 200000 + ":\n    x: y\n",
                  "yarn.lock": '"a@^1' + " " * 200000 + '":\n  version "1.0.0"\n',
                  "Gemfile.lock": "GEM\n  specs:\n    a (" + "1" * 200000 + ")\n",
                  "Cargo.lock": '[[package]]\nname = "' + "a" * 200000 + '"\nversion = "1.0.0"\n'}
        for rel, body in bodies.items():
            with self.subTest(rel=rel):
                self.tmp = tempfile.TemporaryDirectory()
                self.tree = self.tmp.name
                self.write(rel, body)
                t = time.time()
                _, _, err = self.got()
                self.assertLess(time.time() - t, 1.0)
                self.assertTrue(any("limit" in e for e in err), err)
        # just under the limit: the readers' own work stays fast and still ends in an error
        n = tf.MAX_LINE - 10
        t = time.time()
        with self.assertRaises(tf.LockError):
            tf._pnpm_key("/a@1" + "(" * n, False)
        self.assertEqual(tf._drop_pip_options("a" + " " * n + "b"), "a b")
        self.assertLess(time.time() - t, 1.0)
        # the string methods read what the old patterns read
        self.assertEqual(tf._pnpm_key("/react-dom@17.0.2(react@17.0.2)(x@1)", False), ("react-dom", "17.0.2"))
        self.assertEqual(tf._pnpm_key("@s/x@1.0.0(a@1)", False), ("@s/x", "1.0.0"))
        for line, want in [("flask==2.0.0 --hash=sha256:abc --hash=sha256:def", "flask==2.0.0"),
                           ("flask==2.0.0 --hash sha256:abc", "flask==2.0.0"),
                           ("x == 1.0 --config-settings=a=b --global-option=c", "x == 1.0"),
                           ("flask==2.0.0", "flask==2.0.0")]:
            with self.subTest(line=line):
                self.assertEqual(tf._drop_pip_options(line), want)

    def test_de102_p2_requirements_read_as_pip_reads_them(self):   # DE-102 pass 1 R3-1
        hide = {"form feed in a comment": "safe==1.0\n# c\x0cvuln==2.0\n",
                "vertical tab after a pin": "safe==1.0 # c\x0bvuln==2.0\n",
                "file separator": "safe==1.0\n# c\x1cvuln==2.0\n", "group separator": "safe==1.0\n# c\x1dvuln==2.0\n",
                "record separator": "safe==1.0\n# c\x1evuln==2.0\n", "next line": "safe==1.0\n# c\x85vuln==2.0\n",
                "line separator": "safe==1.0\n# c\u2028vuln==2.0\n", "paragraph separator": "safe==1.0\n# c\u2029vuln==2.0\n",
                "unicode_escape": "# coding: unicode_escape\nsafe==1.0\n# c\\nvuln==2.0\n",
                "utf-7 on line 2": "safe==1.0\n# -*- coding: utf-7 -*-\n# c+AAo-vuln==2.0\n",
                "byte order mark": "\ufeffsafe==1.0\n"}
        for what, body in hide.items():
            with self.subTest(what=what):
                self.tmp = tempfile.TemporaryDirectory()
                self.tree = self.tmp.name
                self.write("requirements.txt", body)
                got, _, err = self.got()
                self.assertTrue(err, what)
                self.assertNotIn("requirements.txt", got)
        p = os.path.join(self.tree, "requirements.txt")
        with open(p, "wb") as fh:
            fh.write(b"safe==1.0\n# \xff\n")
        self.assertTrue(self.got()[2])
        # the same checks cover every line reader
        self.write("requirements.txt", "safe==1.0\n")
        self.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  a@1.0.0:\n    x: y\n# \x85  vuln@1.0.0:\n")
        self.assertTrue(any("pnpm-lock.yaml" in e for e in self.got()[2]))
        os.remove(os.path.join(self.tree, "pnpm-lock.yaml"))
        # a coding comment below line 2 is only a comment, as for pip; a dangling option is an error again (R2-1)
        self.write("requirements.txt", "a==1.0\nb==2.0\n# coding: utf-7\n")
        got, _, err = self.got()
        self.assertEqual((err, got["requirements.txt"]), ([], [("PyPI", "a", "1.0"), ("PyPI", "b", "2.0")]))
        for line in ["x==1.0 --hash", "x==1.0 --hash=", "x==1.0 --hash --hash=sha256:abc"]:
            with self.subTest(line=line):
                with self.assertRaises(tf.LockError):
                    tf._drop_pip_options(line)
        # a 60-hash pip line (about 4,800 characters) reads under the raised cap (R2-2)
        self.write("requirements.txt", "numpy==2.0.0 " + " ".join("--hash=sha256:" + "%064x" % i for i in range(60)) + "\n")
        got, _, err = self.got()
        self.assertEqual((err, got["requirements.txt"]), ([], [("PyPI", "numpy", "2.0.0")]))
        self.assertEqual(tf.MAX_LINE, 65536)

    def test_de102_p2_toml_forms_are_read_or_refused(self):   # DE-102 pass 1 R3-2
        decoy = '[[package]]\nname = "safe"\nversion = "1.0.0"\n\n'
        forms = {"comment after header": decoy + '[[package]] # c\nname = "vuln"\nversion = "2.0.0"\n',
                 "spaces in header": decoy + '[[ package ]]\nname = "vuln"\nversion = "2.0.0"\n',
                 "indented keys": decoy + '[[package]]\n  name = "vuln"\n  version = "2.0.0"\n',
                 "quoted header": decoy + '[["package"]]\nname = "vuln"\nversion = "2.0.0"\n'}
        inline = 'package = [{ name = "vuln", version = "2.0.0" }]\n'
        for rel in ("Cargo.lock", "uv.lock", "poetry.lock"):
            for what, body in list(forms.items()) + [("inline", inline)]:
                with self.subTest(rel=rel, what=what):
                    self.tmp = tempfile.TemporaryDirectory()
                    self.tree = self.tmp.name
                    self.write(rel, body)
                    got, _, err = self.got()
                    # tomllib reads vuln; without it the line reader refuses the form: never only "safe"
                    self.assertTrue(err or ("crates.io" if rel == "Cargo.lock" else "PyPI", "vuln", "2.0.0") in got.get(rel, []),
                                    (what, got, err))
                    # and the line reader alone (Python without tomllib) always refuses
                    with self.assertRaises(tf.LockError):
                        tf._toml_lines(list(tf._strict_toml_lines(os.path.join(self.tree, rel))), "x")
        # tomllib and the line reader agree on an ordinary file
        self.write("Cargo.lock", '# generated\nversion = 4\n\n' + decoy + '[[package]]\nname = "serde"\nversion = "1.0.1"\nsource = "registry+https://x"\ndependencies = [\n "safe",\n]\n\n[metadata]\n')
        p = os.path.join(self.tree, "Cargo.lock")
        self.assertEqual(sorted(tf._toml_packages(p, "crates.io")), sorted(tf._toml_lines(list(tf._strict_toml_lines(p)), "crates.io")))

    def test_de102_p2_pnpm_forms_are_read_or_refused(self):   # DE-102 pass 1 R3-2
        head = "lockfileVersion: '9.0'\n\npackages:\n\n  safe@1.0.0:\n    resolution: {integrity: x}\n\n"
        bad = {"comment after key": head + "  vuln@1.0.0: # c\n    resolution: {integrity: y}\n",
               "flow form": head + "  vuln@1.0.0: {resolution: {integrity: y}}\n",
               "odd indent": head + "   vuln@1.0.0:\n    resolution: {integrity: y}\n",
               "tab indent": head + "\tvuln@1.0.0:\n",
               "flow packages": "lockfileVersion: '9.0'\npackages: {vuln@1.0.0: {resolution: {integrity: y}}}\n",
               "snapshot without package": head + "snapshots:\n\n  safe@1.0.0: {}\n\n  vuln@1.0.0: {}\n",
               "snapshots in v6": "lockfileVersion: '6.0'\n\npackages:\n\n  /safe@1.0.0:\n    x: y\n\nsnapshots:\n\n  /vuln@1.0.0:\n    x: y\n",
               # pass 2 R1-3: YAML tags, anchors, aliases, complex keys and escapes in a key
               "tag": head + "  !!str vuln@1.0.0:\n    resolution: {integrity: y}\n",
               "anchor": head + "  &a vuln@1.0.0:\n    resolution: {integrity: y}\n",
               "alias": head + "  *a:\n    resolution: {integrity: y}\n",
               "complex key": head + "  ? vuln@1.0.0\n  : {}\n",
               "escaped quote": head + '  "\\x76uln@1.0.0":\n    resolution: {integrity: y}\n',
               "doubled single quote": head + "  'vu''ln@1.0.0':\n    resolution: {integrity: y}\n",
               "unbalanced quote": head + "  'vuln@1.0.0:\n    resolution: {integrity: y}\n"}
        for what, body in bad.items():
            with self.subTest(what=what):
                self.tmp = tempfile.TemporaryDirectory()
                self.tree = self.tmp.name
                self.write("pnpm-lock.yaml", body)
                got, _, err = self.got()
                self.assertTrue(err, (what, got))
        self.write("pnpm-lock.yaml", head + "  '@s/x@2.0.0':\n    resolution: {integrity: z}\n\nsnapshots:\n\n"
                   "  safe@1.0.0: {}\n\n  '@s/x@2.0.0(safe@1.0.0)':\n    dependencies:\n      safe: 1.0.0\n")
        got, _, err = self.got()
        self.assertEqual((err, got["pnpm-lock.yaml"]), ([], [("npm", "@s/x", "2.0.0"), ("npm", "safe", "1.0.0")]))

    def test_de102_p3_dependency_free_lockfiles_read_empty(self):   # pass 2 R1-4: no false block
        files = {"pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n",
                 "uv.lock": 'version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n',
                 "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n",
                 "requirements.txt": "# nothing pinned yet\n-e .\n"}
        for rel, body in files.items():
            self.write(rel, body)
        got, _, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual({k: v for k, v in got.items()}, {k: [] for k in files})
        # a spec line the Gemfile reader can't read is an error, not skipped
        self.write("Gemfile.lock", "GEM\n  specs:\n    safe (1.0.0)\n    vuln(1.0.0)\n")
        self.assertTrue(self.got()[2])

    def test_de102_p3_line_endings(self):   # pass 2 R1-1 and R2-2: every reader, CRLF reads, a bare CR is refused
        files = {"requirements.txt": ("safe==1.0\nvuln==2.0\n", [("PyPI", "safe", "1.0"), ("PyPI", "vuln", "2.0")]),
                 "Gemfile.lock": ("GEM\n  specs:\n    safe (1.0.0)\n    vuln (2.0.0)\n", [("RubyGems", "safe", "1.0.0"), ("RubyGems", "vuln", "2.0.0")]),
                 "yarn.lock": ('safe@^1.0.0:\n  version "1.0.0"\n\nvuln@^2.0.0:\n  version "2.0.0"\n', [("npm", "safe", "1.0.0"), ("npm", "vuln", "2.0.0")]),
                 "pnpm-lock.yaml": ("lockfileVersion: '9.0'\n\npackages:\n\n  safe@1.0.0:\n    x: y\n\n  vuln@2.0.0:\n    x: y\n", [("npm", "safe", "1.0.0"), ("npm", "vuln", "2.0.0")]),
                 "Cargo.lock": ('[[package]]\nname = "safe"\nversion = "1.0.0"\n\n[[package]]\nname = "vuln"\nversion = "2.0.0"\n', [("crates.io", "safe", "1.0.0"), ("crates.io", "vuln", "2.0.0")])}
        for ending in ["\r\n", "mixed"]:
            for rel, (body, want) in files.items():
                with self.subTest(rel=rel, ending=ending):
                    self.tmp = tempfile.TemporaryDirectory()
                    self.tree = self.tmp.name
                    lines = body.split("\n")
                    text = "\r\n".join(lines) if ending == "\r\n" else "".join(
                        ln + ("\r\n" if k % 2 else "\n") for k, ln in enumerate(lines[:-1]))
                    with open(os.path.join(self.tree, rel), "w", newline="") as fh:
                        fh.write(text)
                    got, _, err = self.got()
                    self.assertEqual((err, got.get(rel)), ([], want))
        for rel, (body, _) in files.items():
            with self.subTest(rel=rel, ending="CR"):
                self.tmp = tempfile.TemporaryDirectory()
                self.tree = self.tmp.name
                with open(os.path.join(self.tree, rel), "w", newline="") as fh:
                    fh.write(body.replace("\n", "\r"))
                self.assertTrue(self.got()[2])
        # the bypass from pass 2: the coding line is in pip's first two "\n" segments
        self.write("requirements.txt", "")
        with open(os.path.join(self.tree, "requirements.txt"), "wb") as fh:
            fh.write(b"# a\rsafe==1.0\r# coding: unicode_escape\r# c\\nvuln==2.0\r")
        self.assertTrue(self.got()[2])

    def test_de102_p3_coding_lines_as_pip_reads_them(self):   # pass 2 R1-1, R2-4
        for body, ok in [("# -*- coding: utf-8 -*-\nsafe==1.0\n", True), ("# coding=UTF_8\nsafe==1.0\n", True),
                         ("safe==1.0\n# coding: latin-1\n", False), ("safe==1.0\nx==2.0\n# coding: utf-7\n", True),
                         ("#!x coding:utf-7\nsafe==1.0\n", False), (" # coding: utf-7\nsafe==1.0\n", True)]:
            with self.subTest(body=body[:30]):
                self.write("requirements.txt", body)
                self.assertEqual(not self.got()[2], ok)

    def test_de102_p3_option_lines_as_pip_reads_them(self):   # pass 2 R3-2
        self.write("a.txt", "a==1.0\n")
        self.write("b.txt", "b==2.0\n")
        follow = {"-r a.txt --hash=sha256:abc": ["a"], "-c a.txt -r b.txt": ["a", "b"], "--index-url https://x -r b.txt": ["b"],
                  "--prefer-binary -r b.txt": ["b"], "-r a.txt -r b.txt": ["a", "b"], "-ra.txt": ["a"],
                  "--requirement=b.txt": ["b"], '-r "b.txt"': ["b"], "-r a.txt \\\n  -r b.txt": ["a", "b"]}
        for line, want in follow.items():
            with self.subTest(line=line):
                self.write("requirements.txt", line + "\n")
                got, _, err = self.got()
                if "--hash" in line:   # pip refuses --hash on an option line too
                    self.assertTrue(err)
                    continue
                self.assertEqual((err, sorted(p[1] for p in got["requirements.txt"])), ([], want))
        for line in ["--requirem b.txt", "--constr a.txt", "--install-option=x", "-e git+https://e.com/x.git#egg=x",
                     "-e https://e.com/x.tgz", "--index-url", '-r "b.txt', "-x"]:
            with self.subTest(line=line):
                self.write("requirements.txt", line + "\n")
                self.assertTrue(self.got()[2], line)
        # a pin continued over several lines reads as one, as pip joins them
        self.write("requirements.txt", "x==1.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\n")
        got, _, err = self.got()
        self.assertEqual((err, got["requirements.txt"]), ([], [("PyPI", "x", "1.0")]))

    def test_de102_p4_small_lockfiles_never_read_empty_silently(self):   # pass 3 R2-1
        bad = {"pnpm-lock.yaml": ["lockfileVersion: '9.0'\n\"packages\":\n  vuln@1.0.0:\n    x: y\n",
                                  "lockfileVersion: '9.0'\n'packages':\n  vuln@1.0.0: {}\n",
                                  "lockfileVersion: '9.0'\n!!str packages:\n  vuln@1.0.0:\n    x: y\n",
                                  "lockfileVersion: '9.0'\n&a packages:\n  vuln@1.0.0:\n    x: y\n",
                                  "lockfileVersion: '9.0'\n? packages\n: {}\n",
                                  "lockfileVersion: '9.0'\npackages:\n    vuln@1.0.0:\n      x: y\n",
                                  "{lockfileVersion: '9.0', packages: {vuln@1.0.0: {}}}\n"],
               "Gemfile.lock": ["GEM\n  specs:\n\n    vuln (1.0.0)\n", "GEM\n  specs:\n\tvuln (1.0.0)\n",
                                "GEM\n  specs:\n    safe (1.0.0)\n\t    vuln (1.0.0)\n"]}
        for rel, bodies in bad.items():
            for body in bodies:
                with self.subTest(rel=rel, body=body[:40]):
                    self.tmp = tempfile.TemporaryDirectory()
                    self.tree = self.tmp.name
                    self.write(rel, body)
                    got, _, err = self.got()
                    # never "no packages" without an error: either it reads vuln or it refuses
                    names = [p[1] for p in got.get(rel, [])]
                    self.assertTrue(err or "vuln" in names, (got, err))
        # a blank line inside specs no longer hides the gems after it: they are read, as Bundler reads them
        self.write("Gemfile.lock", "GEM\n  specs:\n    safe (1.0.0)\n\n    vuln (2.0.0)\n")
        got, _, err = self.got()
        self.assertEqual((err, got["Gemfile.lock"]), ([], [("RubyGems", "safe", "1.0.0"), ("RubyGems", "vuln", "2.0.0")]))
        # the content rule on its own, below the 200-byte net
        self.assertTrue(tf._looks_populated("Gemfile.lock", os.path.join(self.tree, "Gemfile.lock")))

    def test_de102_p4_includes_pip_would_expand(self):   # pass 3 R2-3
        self.write("b.txt", "safe==1.0\n")
        for line in ["-r ${D}/b.txt", "-r file:b.txt", "-r file:///etc/b.txt", "-r https://e.com/b.txt", "-c ${X}",
                     "safe==${V}", "--index-url ${URL}"]:
            with self.subTest(line=line):
                self.write("requirements.txt", line + "\n")
                self.assertTrue(self.got()[2], line)

    def test_de102_p4_comment_strip_is_linear(self):   # pass 3 R1-1
        n = tf.MAX_LINE - 10
        t = time.time()
        self.assertEqual(tf._pip_strip_comment(" " * n + "x"), " " * n + "x")
        self.assertEqual(tf._pip_strip_comment("a" + " " * n + "#c"), "a" + " " * n)
        self.assertEqual(tf._pip_strip_comment("a#b #c"), "a#b ")
        self.assertEqual(tf._pip_strip_comment("#c"), "")
        self.assertLess(time.time() - t, 0.5)
        # a continuation chain longer than the cap is an error, fast
        self.write("requirements.txt", ("x \\\n" * 30000) + "==1.0\n")
        t = time.time()
        self.assertTrue(self.got()[2])
        self.assertLess(time.time() - t, 2.0)
        # pip's own rules, kept: a comment-only line ends a continuation; "a#b" is not a comment
        self.write("requirements.txt", "safe==1.0 \\\n# c\nvuln==2.0\n")
        got, _, err = self.got()
        self.assertEqual((err, sorted(p[1] for p in got["requirements.txt"])), ([], ["safe", "vuln"]))

    def test_de102_p5_virtual_and_editable_sources(self):   # pass 4 R3-1: poetry and uv still install these
        decoy = '[[package]]\nname = "safe"\nversion = "1.0.0"\n\n'
        hide = {"poetry.lock": [decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { virtual = "x" }\n',
                                decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\n\n[package.source]\nvirtual = "x"\n',
                                decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { editable = "." }\n'],
                "Cargo.lock": [decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { virtual = "x" }\n'],
                "uv.lock": [decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { registry = "https://pypi.org/simple", editable = "." }\n',
                            decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { virtual = ".", registry = "https://pypi.org/simple" }\n',
                            decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { virtual = "." }\nsdist = { url = "https://x/vuln-2.0.0.tar.gz" }\n',
                            decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { editable = "." }\nwheels = [\n { url = "https://x/vuln.whl" },\n]\n',
                            decoy + '[[package]]\nname = "vuln"\nversion = "2.0.0"\nsource = { virtual = "." }\n\n[[package.wheels]]\nurl = "https://x/vuln.whl"\n']}
        for rel, bodies in hide.items():
            eco = "crates.io" if rel == "Cargo.lock" else "PyPI"
            for body in bodies:
                with self.subTest(rel=rel, body=body[50:110]):
                    self.tmp = tempfile.TemporaryDirectory()
                    self.tree = self.tmp.name
                    self.write(rel, body)
                    p = os.path.join(self.tree, rel)
                    # tomllib and the line reader: either vuln is read or the file is refused, never only "safe"
                    for read in (lambda: tf.PARSERS[rel](p),
                                 lambda: tf._toml_lines(list(tf._strict_toml_lines(p)), eco, rel == "uv.lock")):
                        try:
                            names = [x[1] for x in read()]
                        except tf.LockError:
                            continue
                        self.assertIn("vuln", names)
        # uv's own project root still reads as empty on both paths
        self.write("uv.lock", decoy + '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n')
        p = os.path.join(self.tree, "uv.lock")
        self.assertEqual(tf.PARSERS["uv.lock"](p), [("PyPI", "safe", "1.0.0")])
        self.assertEqual(tf._toml_lines(list(tf._strict_toml_lines(p)), "PyPI", True), [("PyPI", "safe", "1.0.0")])

    def test_de102_p3_toml_fallback_refuses_escapes(self):   # pass 2 R1-2 (Low)
        lines = ['[[package]]\n', 'name = "\\u0076uln"\n', 'version = "1.0.0"\n']
        with self.assertRaises(tf.LockError):
            tf._toml_lines(lines, "crates.io")

    def test_de102_more_spec_kinds(self):   # pass 4 R2-2: survivors with no test
        for spec in ["x@file:../x", "x@link:../x", "x@portal:../x", "x@workspace:^"]:
            with self.subTest(spec=spec):
                self.assertIsNone(tf._yarn_name(spec))
        self.assertEqual(tf._yarn_name("x@patch:lodash@npm%3A4.17.21#./p.patch::locator=app"), "lodash")
        self.assertEqual(tf._yarn_name("x@patch:x@1.0.0#./p.patch"), "x")
        for spec in ["x@1:2", "x@1#2", "x@a/b", "x@npm:lo dash", "x@npm:@s/real@1:2", "x@exec:./x.sh", "x@NPM:lodash"]:
            with self.subTest(spec=spec):
                with self.assertRaises(tf.LockError):
                    tf._yarn_name(spec)

    def test_pass2_yarn_unplaceable_spec_is_an_error(self):
        self.write("yarn.lock", '"x@git+https://example.com/x.git":\n  version "1.0.0"\n')
        _, _, err = self.got()
        self.assertTrue(err)

    def test_pass2_pnpm_v5_peer_keys(self):   # pass 2 R1-3
        self.write("pnpm-lock.yaml", "lockfileVersion: 5.4\n\npackages:\n\n  /react-dom/17.0.2_react@17.0.2:\n    x: y\n\n"
                   "  /@babel/core/7.0.0_@babel+x@1.0.0:\n    x: y\n\n  /left-pad/1.3.0_ab12cd:\n    x: y\n\n  /plain/2.0.0:\n    x: y\n")
        got, _, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(got["pnpm-lock.yaml"], [("npm", "@babel/core", "7.0.0"), ("npm", "left-pad", "1.3.0"),
                                                 ("npm", "plain", "2.0.0"), ("npm", "react-dom", "17.0.2")])

    def test_pass2_pnpm_unknown_version_is_an_error(self):
        self.write("pnpm-lock.yaml", "lockfileVersion: 42.0\n\npackages:\n\n  x@1.0.0:\n    a: b\n")
        _, _, err = self.got()
        self.assertTrue(err)

    def test_pass2_lockfile_like_names_are_not_skipped(self):   # pass 2 R2-4
        self.write("dev-requirements.txt", "pytest==7.0.0\n")
        self.write("requirements/prod.txt", "flask==2.0.0\n")
        self.write("pdm.lock", "x")
        self.write("bun.lock", "x")
        got, unc, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(got["dev-requirements.txt"], [("PyPI", "pytest", "7.0.0")])
        self.assertEqual(got["requirements/prod.txt"], [("PyPI", "flask", "2.0.0")])
        self.assertEqual(sorted(unc), ["bun.lock", "pdm.lock"])

    def test_pass2_small_reader_fixes(self):   # pass 2 R2-6, R3-3, R3-4
        self.write("Gemfile.lock", "GEM\n  specs:\n    ffi (1.15.5-x64-mingw-ucrt)\n")
        self.write("uv.lock", '[[package]]\nname = "app"\nsource = { virtual = "." }\n\n[[package]]\nname = "idna"\nversion = "3.4"\n')
        self.write("sub/requirements.txt", "-r ../requirements-base.txt\nflask==2.0.0 --hash=sha256:abc\n")
        self.write("requirements-base.txt", "idna==3.4\n")
        self.write("Package.resolved", {"version": 2, "pins": [{"location": "https://github.com/Alamofire/Alamofire.git", "state": {"version": "5.0.0"}}]})
        got, _, err = self.got()
        self.assertEqual(err, [], err)
        self.assertEqual(got["Gemfile.lock"], [("RubyGems", "ffi", "1.15.5")])
        self.assertEqual(got["uv.lock"], [("PyPI", "idna", "3.4")])
        self.assertEqual(got["sub/requirements.txt"], [("PyPI", "flask", "2.0.0"), ("PyPI", "idna", "3.4")])
        self.assertEqual(got["Package.resolved"], [("SwiftURL", "github.com/Alamofire/Alamofire", "5.0.0")])
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = self.tmp.name
        self.write("composer.lock", {"packages": [{"name": "a/b", "version": "dev-master"}]})
        self.assertTrue(self.got()[2])

    def test_trailing_dot_version_is_an_error(self):   # pass 2 R2-5
        self.write("requirements.txt", "x==1.0.\n")
        self.assertTrue(self.got()[2])

    def test_unknown_shape_yielding_nothing_is_an_error(self):
        self.write("poetry.lock", "# generated\n" + "[metadata]\nlock-version = '9'\n" * 30)
        _, _, err = self.got()
        self.assertTrue(err)

    def test_symlinked_lockfile_is_an_error(self):   # R2-11
        self.write("real.txt", "x==1.0\n")
        os.symlink("/etc/hostname", os.path.join(self.tree, "requirements.txt"))
        _, _, err = self.got()
        self.assertTrue(any("regular file" in e for e in err), err)

    def test_not_a_directory(self):   # R2-3
        _, _, err = tf.lockfiles(os.path.join(self.tree, "nope"))
        self.assertTrue(err)
        self.assertEqual(tf.main([os.path.join(self.tree, "nope")]), 1)


class Check(Base):
    def test_clean(self):
        self.npm()
        m, unc, notes, err, fv = tf.check(self.tree, Fake())
        self.assertEqual((m, unc, err), ([], [], []))
        self.assertTrue(fv)

    def test_match_and_kev(self):
        self.npm()
        f = Fake({("npm", "lodash", "4.17.15"): [
            {"id": "GHSA-aaaa", "aliases": ["CVE-2021-44228"], "summary": "bad"},
            {"id": "GHSA-bbbb", "aliases": ["CVE-2099-1"], "database_specific": {"severity": "MODERATE"}},
            {"id": "GHSA-cccc", "withdrawn": "2026-01-01T00:00:00Z"}]})
        m, _, _, err, _ = tf.check(self.tree, f)
        self.assertEqual(err, [])
        by = {x["id"]: x for x in m}
        self.assertEqual(set(by), {"GHSA-aaaa", "GHSA-bbbb"})
        self.assertTrue(by["GHSA-aaaa"]["kev"])
        self.assertEqual(by["GHSA-aaaa"]["severity"], "Critical (CISA KEV)")
        self.assertEqual(by["GHSA-bbbb"]["severity"], "Medium")

    def test_feed_version_follows_osv(self):   # R3-10
        self.npm()
        fv1 = tf.check(self.tree, Fake())[4]
        fv2 = tf.check(self.tree, Fake({("npm", "lodash", "4.17.15"): [{"id": "GHSA-zzzz"}]}))[4]
        self.assertNotEqual(fv1, fv2)

    def test_unreachable_without_copy_fails_closed(self):
        self.npm()
        _, _, _, err, fv = tf.check(self.tree, Fake(fail=True))
        self.assertTrue(err)
        self.assertEqual(fv, "")

    def test_unreachable_with_recent_copy_uses_it(self):
        self.npm()
        tf.check(self.tree, Fake())
        self.age(30)
        _, _, _, err, _ = tf.check(self.tree, Fake(fail=True))
        self.assertTrue(any("OSV" in e for e in err), err)   # KEV from the copy; OSV has no copy and fails closed

    def test_stale_copy_fails_closed(self):
        self.npm()
        tf.check(self.tree, Fake())
        self.age(60)
        _, _, _, err, _ = tf.check(self.tree, Fake(fail=True))
        self.assertTrue(any("kev" in e.lower() for e in err), err)

    def test_future_copy_is_stale(self):   # R2-9
        self.npm()
        tf.check(self.tree, Fake())
        self.age(-1000)
        _, _, _, err, _ = tf.check(self.tree, Fake(fail=True))
        self.assertTrue(any("kev" in e.lower() for e in err), err)

    def test_truncated_kev_fails_closed_and_keeps_the_good_copy(self):   # R2-4
        self.npm()
        tf.check(self.tree, Fake())
        self.age(30)
        _, _, _, err, _ = tf.check(self.tree, Fake(kev={"vulnerabilities": [{"cveID": "CVE-1"}]}))
        self.assertEqual(err, [])   # the bad download is refused; the 30h good copy is used
        _, _, _, err, _ = tf.check(self.tree, Fake())
        self.assertEqual(err, [])
        self.tmp2 = tempfile.TemporaryDirectory()
        tf.CACHE = self.tmp2.name
        _, _, _, err, _ = tf.check(self.tree, Fake(kev={"vulnerabilities": [{"cveID": "CVE-1"}]}))
        self.assertTrue(any("truncated" in e for e in err), err)

    def test_malformed_osv_answers_fail_closed(self):   # R2-6, R3-8
        self.npm()
        for bad in [{"results": []}, {"results": [{"vulns": [{"no": "id"}]}, {}]}, {"results": [None, {}]},
                    {"results": [{"vulns": [{"id": "GHSA-[x]{y}?z"}]}, {}]}, []]:
            with self.subTest(bad=bad):
                class Bad(Fake):
                    def __call__(s, url, data=None, timeout=60):
                        if url == tf.OSV_BATCH:
                            return json.dumps(bad).encode()
                        return Fake.__call__(s, url, data, timeout)
                _, _, _, err, _ = tf.check(self.tree, Bad())
                self.assertTrue(err)

    def test_paged_osv_result_fails_closed(self):   # pass 2 R2-5
        self.npm()

        class Paged(Fake):
            def __call__(s, url, data=None, timeout=60):
                if url == tf.OSV_BATCH:
                    n = len(json.loads(data)["queries"])
                    return json.dumps({"results": [{"vulns": [], "next_page_token": str(n)}] * n}).encode()
                return Fake.__call__(s, url, data, timeout)
        self.assertTrue(tf.check(self.tree, Paged())[3])

    def test_planted_pyc_never_runs(self):   # pass 2 R3-1
        import py_compile
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "m.py"), "w") as fh:
            fh.write("X = 'good'\n")
        with open(os.path.join(d, "evil.py"), "w") as fh:
            fh.write("X = 'EVIL'\n")
        tag = sys.implementation.cache_tag
        py_compile.compile(os.path.join(d, "evil.py"), cfile=os.path.join(d, "__pycache__", f"m.{tag}.pyc"),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        self.assertEqual(load("m_test", os.path.join(d, "m.py")).X, "good")

    def test_quick_only_changed_lockfile(self):
        self.npm("a/package-lock.json")
        self.npm("b/package-lock.json", (("lodash", "4.17.15"),))
        f = Fake({("npm", "lodash", "4.17.15"): [{"id": "GHSA-aaaa"}]})
        m, _, _, _, _ = tf.check(self.tree, f, only={"a/package-lock.json"})
        self.assertEqual({x["lockfile"] for x in m}, {"a/package-lock.json"})
        self.assertEqual(tf.check(self.tree, f, only=set())[0], [])

    def test_uncovered_is_returned(self):
        self.write("app/build.gradle", "x")
        _, unc, _, _, _ = tf.check(self.tree, Fake())
        self.assertEqual(unc, ["app/build.gradle"])
        self.assertEqual(tf.main([self.tree]), 1)

    def test_no_lockfiles_no_network(self):
        f = Fake(fail=True)
        m, unc, notes, err, _ = tf.check(self.tree, f)
        self.assertEqual((m, unc, err, f.calls), ([], [], [], []))
        self.assertIn("no lockfiles found", notes)

    def test_curl_flags(self):   # R1-9, R3-8
        calls = []
        orig = tf.tool
        tf.tool = lambda cmd, **k: calls.append(cmd) or types.SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")
        try:
            tf.fetch("https://api.osv.dev/v1/vulns/X")
        finally:
            tf.tool = orig
        for flag in ["-q", "--proto-redir", "--max-redirs", "-g"]:
            self.assertIn(flag, calls[0])
        self.assertNotIn("-L", calls[0])
        self.assertNotIn("-fsSL", calls[0])


class Sbom(Base):
    def git(self, *a):
        # through threat-feed.py's own process helper; identity from the environment
        os.environ.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e",
                          GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        p = tf.tool(["git", *a], cwd=self.tree)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.decode()

    def test_build_and_check(self):
        self.npm()
        doc = sb.build(self.tree, "Lighthouse", "web", "0.6.0", "a" * 40)
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        purls = {c["purl"] for c in doc["components"]}
        self.assertIn("pkg:npm/lodash@4.17.15", purls)
        self.assertIn("pkg:npm/%40scope/x@1.0.0", purls)
        self.write("security/SBOM-web-0.6.0.json", doc)
        self.assertEqual(sb.check(self.tree, "web", "0.6.0"), [])
        self.npm(pkgs=(("lodash", "4.17.21"),))
        self.assertTrue(sb.check(self.tree, "web", "0.6.0"))

    def test_missing_sbom_fails(self):
        self.npm()
        self.assertTrue(sb.check(self.tree, "web", "9.9.9"))
        self.assertTrue(sb.check(self.tree, "*", "9.9.9"))

    def test_copied_sbom_for_another_version_fails(self):   # R3-6
        self.npm()
        self.write("security/SBOM-web-2.0.0.json", sb.build(self.tree, "L", "web", "1.0.0", "a" * 40))
        self.assertTrue(sb.check(self.tree, "*", "2.0.0"))

    def test_uncovered_lockfile_needs_acceptance(self):   # R2-5, R3-4
        self.write("app/build.gradle", "x")
        self.write("security/SBOM-android-1.0.0.json", sb.build(self.tree, "L", "android", "1.0.0", "a" * 40))
        self.assertTrue(sb.check(self.tree, "*", "1.0.0"))
        exp = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        self.write("security/accepted-findings", f"{tf.not_covered_id('app/build.gradle')} | {exp} | Gradle not read yet; DE-98\n")
        self.assertEqual(sb.check(self.tree, "*", "1.0.0"), [])
        self.write("security/accepted-findings", f"{tf.not_covered_id('app/build.gradle')} | {exp} | no board key\n")
        self.assertTrue(sb.check(self.tree, "*", "1.0.0"))

    def test_sbom_commit_must_be_in_history(self):   # pass 2 R3-5
        self.git("init", "-q", "-b", "main")
        self.npm(pkgs=(("a", "1.0.0"),))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "x")
        head = self.git("rev-parse", "HEAD").strip()
        cwd = os.getcwd()
        os.chdir(self.tree)
        try:
            self.write("security/SBOM-web-1.0.0.json", sb.build(self.tree, "P", "web", "1.0.0", "b" * 40))
            self.git("add", "-A")
            self.git("commit", "-q", "-m", "fake sbom")
            self.assertEqual(sb.main(["check", "*", "1.0.0", "--rev", "HEAD"]), 1)
            self.write("security/SBOM-web-1.0.0.json", sb.build(self.tree, "P", "web", "1.0.0", head))
            self.git("add", "-A")
            self.git("commit", "-q", "-m", "real sbom")
            self.assertEqual(sb.main(["check", "*", "1.0.0", "--rev", "HEAD"]), 0)
        finally:
            os.chdir(cwd)

    def test_scanner_pins_stay_out_of_the_sbom(self):   # pass 3 R3-5, pass 4 R2-2
        self.npm(pkgs=(("a", "1.0.0"),))
        self.write(".github/security-scan-tools.lock", "semgrep==1.0.0 \\\n    --hash=sha256:abc\n")
        self.assertIn(".github/security-scan-tools.lock", [c[0] for c in tf.lockfiles(self.tree)[0]])
        self.assertEqual({c["purl"] for c in sb.components(self.tree)[0]}, {"pkg:npm/a@1.0.0"})

    def test_write_reads_the_commit_not_the_work_tree(self):   # R2-12
        self.git("init", "-q", "-b", "main")
        self.npm(pkgs=(("a", "1.0.0"),))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "x")
        self.npm(pkgs=(("a", "1.1.0"),))   # uncommitted
        cwd = os.getcwd()
        os.chdir(self.tree)
        try:
            self.assertEqual(sb.main(["write", "--product", "P", "--platform", "web", "--version", "1.0.0"]), 0)
        finally:
            os.chdir(cwd)
        with open(os.path.join(self.tree, "security", "SBOM-web-1.0.0.json")) as fh:
            purls = {c["purl"] for c in json.load(fh)["components"]}
        self.assertEqual(purls, {"pkg:npm/a@1.0.0"})


GRADLE_HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n<verification-metadata xmlns="https://schema.gradle.org/dependency-'
               'verification">\n   <configuration>\n      <verify-metadata>true</verify-metadata>\n      <verify-signatures>'
               'false</verify-signatures>\n   </configuration>\n   <components>\n')
GRADLE_ONE = ('      <component group="androidx.activity" name="activity" version="1.10.1">\n'
              '         <artifact name="activity-component-1.10.1.aar">\n'
              '            <sha256 value="b62b" origin="Generated by Gradle"/>\n         </artifact>\n      </component>\n')
GRADLE_TWO = ('      <component group="org.jetbrains.kotlin" name="kotlin-gradle-plugin" version="2.2.20">\n'
              '         <artifact name="kotlin-gradle-plugin-2.2.20.jar">\n'
              '            <sha256 value="aa" origin="Generated by Gradle"/>\n         </artifact>\n      </component>\n')
GRADLE_TAIL = "   </components>\n</verification-metadata>\n"


class Readers116(Base):   # DE-116: Gradle verification metadata, pip .lock files, constraint ceilings
    def got(self):
        cov, unc, err = tf.lockfiles(self.tree)
        return {p: ps for p, ps in cov}, unc, err

    def gradle(self, root="apps/android", body=GRADLE_ONE + GRADLE_TWO, settings="settings.gradle.kts"):
        self.write(f"{root}/{settings}", 'rootProject.name = "x"\n')
        self.write(f"{root}/build.gradle.kts", 'plugins { id("com.android.application") version "9.4.0" apply false }\n')
        self.write(f"{root}/app/build.gradle.kts", 'dependencies { implementation("androidx.activity:activity:1.10.1") }\n')
        self.write(f"{root}/gradle/verification-metadata.xml", GRADLE_HEAD + body + GRADLE_TAIL)

    def test_gradle_metadata_is_read_and_covers_its_build(self):
        self.gradle()
        got, unc, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(unc, [])
        self.assertEqual(got["apps/android/gradle/verification-metadata.xml"],
                         [("Maven", "androidx.activity:activity", "1.10.1"),
                          ("Maven", "org.jetbrains.kotlin:kotlin-gradle-plugin", "2.2.20")])

    def test_groovy_settings_count_as_a_root(self):
        self.gradle(settings="settings.gradle")
        self.write("apps/android/app/build.gradle", "apply plugin: 'x'\n")
        got, unc, err = self.got()
        self.assertEqual((unc, err), ([], []))

    def test_gradle_without_metadata_stays_not_checked(self):
        self.write("apps/android/settings.gradle.kts", "x\n")
        self.write("apps/android/app/build.gradle.kts", "x\n")
        self.write("other/build.gradle", "x\n")   # no settings file anywhere above it
        _, unc, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(sorted(unc), ["apps/android/app/build.gradle.kts", "other/build.gradle"])

    def test_nested_build_needs_its_own_metadata(self):
        self.gradle()
        self.write("apps/android/tools/included/settings.gradle", "x\n")   # its own build root, no metadata
        self.write("apps/android/tools/included/build.gradle", "x\n")
        _, unc, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(unc, ["apps/android/tools/included/build.gradle"])

    def test_metadata_outside_a_gradle_folder_or_symlinked_does_not_cover(self):
        self.gradle()
        os.remove(os.path.join(self.tree, "apps/android/gradle/verification-metadata.xml"))
        self.write("apps/android/verification-metadata.xml", GRADLE_HEAD + GRADLE_ONE + GRADLE_TAIL)
        _, unc, err = self.got()
        self.assertEqual(sorted(unc), ["apps/android/app/build.gradle.kts", "apps/android/build.gradle.kts"])
        os.symlink(os.path.join(self.tree, "apps/android/verification-metadata.xml"),
                   os.path.join(self.tree, "apps/android/gradle/verification-metadata.xml"))
        _, unc, err = self.got()
        self.assertEqual(sorted(unc), ["apps/android/app/build.gradle.kts", "apps/android/build.gradle.kts"])
        self.assertTrue(any("not a regular file" in e for e in err), err)

    def test_gradle_forms_that_could_hide_a_component_are_errors(self):
        bad = {
            "trust by group": GRADLE_ONE.replace("   <components>", "") + '<trusted-artifacts><trust group="com.evil"/></trusted-artifacts>\n',
            "trusted key": GRADLE_ONE + '<trusted-keys><trusted-key id="ABCD" group="org.x"/></trusted-keys>\n',
            "split tag": GRADLE_ONE + '      <component group="a.b"\n          name="c" version="1.0">\n      </component>\n',
            "attribute order": GRADLE_ONE + '      <component name="c" group="a.b" version="1.0">\n      </component>\n',
            "prefixed": GRADLE_ONE + '      <dv:component group="a.b" name="c" version="1.0">\n      </dv:component>\n',
            "two on a line": GRADLE_ONE + '      <component group="a.b" name="c" version="1.0"></component><component group="d" name="e" version="2">\n',
            "entity": GRADLE_ONE + '      <component group="a.b" name="c" version="&v;">\n      </component>\n',
            "char ref": GRADLE_ONE + '      <component group="a.b" name="c" version="1&#46;0">\n      </component>\n',
            "range": GRADLE_ONE + '      <component group="a.b" name="c" version="[1.0,2.0)">\n      </component>\n',
        }
        for why, body in bad.items():
            with self.subTest(why):
                self.write("g/gradle/verification-metadata.xml", GRADLE_HEAD + body + GRADLE_TAIL)
                got, _, err = self.got()
                self.assertNotIn("g/gradle/verification-metadata.xml", got)
                self.assertTrue(any("g/gradle/verification-metadata.xml" in e for e in err), err)
        for why, text in {"doctype": '<?xml version="1.0"?>\n<!DOCTYPE x [<!ENTITY v "1">]>\n' + GRADLE_HEAD.split("\n", 1)[1] + GRADLE_ONE + GRADLE_TAIL,
                          "signatures": GRADLE_HEAD.replace("<verify-signatures>false", "<verify-signatures>true") + GRADLE_ONE + GRADLE_TAIL,
                          "not gradle": "<?xml version=\"1.0\"?>\n<project>\n" + GRADLE_ONE + "</project>\n",
                          "tiny empty": "<verification-metadata/>\n",
                          "empty": GRADLE_HEAD + GRADLE_TAIL,
                          "pi": GRADLE_HEAD + "<?evil x?>\n" + GRADLE_ONE + GRADLE_TAIL}.items():
            with self.subTest(why):
                self.write("g/gradle/verification-metadata.xml", text)
                got, _, err = self.got()
                self.assertNotIn("g/gradle/verification-metadata.xml", got)
                self.assertTrue(any("g/gradle/verification-metadata.xml" in e for e in err), (why, err))

    def test_trust_by_file_and_comments_are_fine(self):
        body = GRADLE_ONE + "<!-- a note -->\n"
        head = GRADLE_HEAD.replace("   </configuration>", '      <trusted-artifacts>\n         <trust file=".*-sources[.]jar" regex="true"/>\n      </trusted-artifacts>\n   </configuration>')
        self.write("g/gradle/verification-metadata.xml", head + body + GRADLE_TAIL)
        got, _, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(got["g/gradle/verification-metadata.xml"], [("Maven", "androidx.activity:activity", "1.10.1")])

    def test_pip_lock_files_are_read(self):
        lock = "# hash-locked\nmcp==1.29.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\ncryptography==48.0.1 \\\n    --hash=sha256:cc\n"
        self.write("apps/macos/spike/runtime-requirements-x86_64.lock", lock)
        self.write("apps/macos/spike/build-requirements.lock", "pip==25.3 --hash=sha256:dd\n")
        self.write("other/Requirements.LOCK", "flask==2.0.0\n")
        got, unc, err = self.got()
        self.assertEqual((unc, err), ([], []))
        self.assertEqual(got["apps/macos/spike/runtime-requirements-x86_64.lock"],
                         [("PyPI", "cryptography", "48.0.1"), ("PyPI", "mcp", "1.29.0")])
        self.assertEqual(got["apps/macos/spike/build-requirements.lock"], [("PyPI", "pip", "25.3")])
        self.assertIn("other/Requirements.LOCK", got)
        self.write("apps/macos/spike/x-requirements.lock", "flask>=2.0\n")   # still exact only
        _, _, err = self.got()
        self.assertTrue(any("x-requirements.lock" in e and "isn't pinned" in e for e in err), err)

    def test_constraint_ceilings(self):
        self.write("spike/constraints.txt", "# Intel wheels end at 48.0.1\ncryptography<=48.0.1\nidna == 3.10\n")
        got, unc, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(got["spike/constraints.txt"], [("PyPI", "cryptography", "48.0.1"), ("PyPI", "idna", "3.10")])
        for line in ("cryptography<48.0.1", "cryptography>=40", "cryptography<=48.0.1,>=40", "cryptography~=48.0",
                     "cryptography<=48.*", "cryptography!=47", "cryptography <= "):
            with self.subTest(line):
                self.write("spike/constraints.txt", line + "\n")
                _, _, err = self.got()
                self.assertTrue(any("spike/constraints.txt" in e for e in err), (line, err))

    def test_ceiling_only_in_a_constraints_file(self):
        self.write("requirements.txt", "cryptography<=48.0.1\n")
        _, _, err = self.got()
        self.assertTrue(any("requirements.txt" in e and "only in a constraints file" in e for e in err), err)
        self.write("requirements.txt", "flask==2.0.0\n-c pins/limits.txt\n")
        self.write("pins/limits.txt", "cryptography<=48.0.1\n-r more.txt\n")   # -c reaches it; -r below stays constraint
        self.write("pins/more.txt", "idna<=3.10\n")
        got, _, err = self.got()
        self.assertEqual(err, [])
        self.assertEqual(got["requirements.txt"], [("PyPI", "cryptography", "48.0.1"), ("PyPI", "flask", "2.0.0"),
                                                   ("PyPI", "idna", "3.10")])
        self.write("requirements.txt", "flask==2.0.0\n-r pins/limits.txt\n")   # the same file through -r: refused
        _, _, err = self.got()
        self.assertTrue(any("only in a constraints file" in e for e in err), err)

    def test_sbom_describes_gradle_builds(self):
        self.gradle()
        comps, unc = sb.components(self.tree)
        self.assertEqual(unc, [])
        self.assertEqual({c["purl"] for c in comps}, {"pkg:maven/androidx.activity/activity@1.10.1",
                                                    "pkg:maven/org.jetbrains.kotlin/kotlin-gradle-plugin@2.2.20"})

    def test_sbom_from_a_commit_brings_the_settings_file(self):
        os.environ.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e",
                          GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.gradle()
        for a in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "x"]):
            self.assertEqual(tf.tool(["git", *a], cwd=self.tree).returncode, 0)
        cwd = os.getcwd()
        os.chdir(self.tree)
        try:
            self.assertEqual(sb.main(["write", "--product", "P", "--platform", "android", "--version", "1.0.0"]), 0)
        finally:
            os.chdir(cwd)
        with open(os.path.join(self.tree, "security", "SBOM-android-1.0.0.json")) as fh:
            doc = json.load(fh)
        self.assertIn("pkg:maven/androidx.activity/activity@1.10.1", {c["purl"] for c in doc["components"]})
        self.assertFalse([p for p in json.dumps(doc).split('"') if p.endswith("build.gradle.kts")], doc)


if __name__ == "__main__":
    unittest.main(verbosity=1)

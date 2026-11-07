#!/usr/bin/env python3
"""Tests for classify-risk.py (DE-98). Run: python3 .githooks/test-classify-risk.py

Each case builds a throwaway git repo, makes one change and checks the tier the classifier gives. The cases that
matter most are the ones that must NOT come out low or normal: anything security, build or supply-chain related,
anything unreadable, and every release.
"""
import importlib.util, json, os, shutil, subprocess, sys, tempfile, unittest, warnings
warnings.simplefilter("ignore", ResourceWarning)
sys.dont_write_bytecode = True
sys.pycache_prefix = tempfile.mkdtemp(prefix="gl-nopyc-")   # never read a planted pyc

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("classify_risk", os.path.join(HERE, "classify-risk.py"))
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)

ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
           GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def run(cmd, cwd, check=False):
    """The one place the tests start a process: git or this Python, by full path, fixed arguments, no shell."""
    exe = cmd[0] if os.path.isabs(cmd[0]) else shutil.which(cmd[0])
    return subprocess.run([exe, *cmd[1:]], cwd=cwd, env=ENV, capture_output=True, text=True, check=check)


def g(root, *args):
    return run(["git", *args], root, check=True).stdout.encode()


class Repo:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        g(self.root, "init", "-q", "-b", "main")
        self.write("README.md", "hello\n")
        self.commit("base")
        self.base = g(self.root, "rev-parse", "HEAD").decode().strip()

    def write(self, path, text, mode=None):
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full) or self.root, exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(text.encode() if isinstance(text, str) else text)
        if mode:
            os.chmod(full, mode)

    def commit(self, msg="change"):
        g(self.root, "add", "-A")
        g(self.root, "commit", "-q", "--allow-empty", "-m", msg)
        return g(self.root, "rev-parse", "HEAD").decode().strip()

    def tier(self, release=False):
        rev = self.commit()
        return cr.classify(self.root, rev, self.base, release)


def no_sample(res):
    """The tier before the random escalation sample, so the rules can be tested on their own."""
    if res["sampled"]:
        return [f["tier"] for f in res["files"]]
    return res["tier"]


def base_tier(res):
    tiers = [f["tier"] for f in res["files"]]
    best = "low"
    for t in tiers:
        best = cr.raise_to(best, t)
    return best if res["files"] else res["tier"]


class Tiers(unittest.TestCase):
    def check(self, files, want, release=False, mode=None):
        r = Repo()
        for p, t in files.items():
            r.write(p, t, mode)
        res = r.tier(release)
        got = base_tier(res) if not release else res["tier"]
        self.assertEqual(got, want, json.dumps(res, indent=1))
        if want == "high":
            self.assertEqual(res["tier"], "high")
        return res

    # Low: prose and images, no signal.
    def test_docs_low(self):
        self.check({"docs/guide.md": "How to use the scope page.\n"}, "low")

    def test_prose_naming_systems_low(self):
        self.check({"docs/guide.md": "The Worker sends the scope to Ravenwood after Submit.\n"}, "low")

    def test_prose_run_instructions_high(self):
        for line in ["Run release/build.sh to ship.", "Paste the API key here.", "npm install the deps.",
                     "You can skip the scan for docs."]:
            with self.subTest(line=line):
                self.check({"docs/guide.md": line + "\n"}, "high")

    def test_image_low(self):
        self.check({"img/a.png": b"\x89PNG\r\n\x1a\n" + bytes(range(256))}, "low")

    def test_plain_css_low(self):
        self.check({"style.css": "body { color: #333; margin: 0; }\n"}, "low")

    # Normal: code with no signal.
    def test_plain_code_normal(self):
        self.check({"src/math.ts": "export function add(a: number, b: number) { return a + b; }\n"}, "normal")

    def test_css_import_normal_or_higher(self):
        r = self.check({"style.css": "@import 'x.css';\n"}, "normal")

    def test_svg_normal(self):
        self.check({"img/logo.svg": "<svg><circle r='4'/></svg>\n"}, "normal")

    # High: signals in code.
    def test_signals_high(self):
        for line in ["const t = localStorage.getItem('token');", "el.innerHTML = name;", "fetch('/api/x')",
                     "if (user.role === 'admin') {}", "crypto.subtle.digest('SHA-256', b)", "eval(code)",
                     "const s = require('child_process');", "db.prepare('SELECT * FROM users')",
                     "res.headers.set('Access-Control-Allow-Origin', '*')", "// eslint-disable-next-line",
                     "x = os.system(cmd)", "import { a } from './session.js';"]:
            with self.subTest(line=line):
                self.check({"src/app.js": line + "\n"}, "high")

    def test_signal_in_removed_line_high(self):
        r = Repo()
        r.write("src/app.js", "check(csrfToken);\nok();\n")
        r.base = r.commit("with check")
        r.write("src/app.js", "ok();\n")
        self.assertEqual(r.tier()["tier"], "high")

    def test_signal_in_markdown_high(self):
        self.check({"notes.md": "The admin password is in the vault.\n"}, "high")

    def test_removed_sql_comment_not_a_header(self):
        r = Repo()
        r.write("src/q.js", "-- password reset\nx();\n")
        r.base = r.commit("with line")
        r.write("src/q.js", "x();\n")
        self.assertEqual(r.tier()["tier"], "high")

    # High: paths, types, modes.
    def test_high_paths(self):
        for p in [".githooks/pre-push", ".github/workflows/ci.yml", "security/accepted-findings",
                  "worker/package.json", "worker/package-lock.json", "release/build.sh", "apps/ios/App.entitlements",
                  "worker/wrangler.toml", "worker/migrations/0003.sql", "worker/public/sw.js", "CLAUDE.md",
                  ".githooks/classify-risk.py", ".githooks/REVIEW-TIERS.md", "requirements.txt", "Cargo.lock",
                  ".env.local", "docs/run.sh", "x.yml", "Makefile", "apps/mac/Info.plist", ".gitattributes"]:
            with self.subTest(path=p):
                self.check({p: "plain\n"}, "high")

    def test_unknown_type_high(self):
        self.check({"data/blob.xyz": "plain\n"}, "high")
        self.check({"LICENSE": "plain\n"}, "high")

    def test_executable_mode_high(self):
        self.check({"docs/readme.md": "plain\n"}, "high", mode=0o755)

    def test_symlink_high(self):
        r = Repo()
        os.symlink("README.md", os.path.join(r.root, "link.md"))
        self.assertEqual(r.tier()["tier"], "high")

    def test_binary_non_media_high(self):
        self.check({"src/thing.js": b"\x00\x01\x02binary"}, "high")

    def test_mixed_takes_highest(self):
        self.check({"docs/a.md": "words\n", "src/b.ts": "export const x = 1;\n", "worker/package.json": "{}\n"}, "high")

    def test_rename_judges_both_paths(self):
        r = Repo()
        r.write(".githooks/old.sh", "echo hi\n")
        r.base = r.commit("hook")
        os.rename(os.path.join(r.root, ".githooks/old.sh"), os.path.join(r.root, "docs-old.md"))
        self.assertEqual(r.tier()["tier"], "high")

    def test_deleted_hook_high(self):
        r = Repo()
        r.write(".githooks/x.sh", "echo\n")
        r.base = r.commit("hook")
        os.remove(os.path.join(r.root, ".githooks/x.sh"))
        self.assertEqual(r.tier()["tier"], "high")

    def test_odd_name_high(self):
        self.check({"docs/a b\tc.md": "words\n"}, "high")

    # Fail-safe paths.
    def test_empty_change_high(self):
        r = Repo()
        res = r.tier()
        self.assertEqual(res["tier"], "high")

    def test_bad_revision_high(self):
        r = Repo()
        res = cr.classify(r.root, "nope", r.base)
        self.assertEqual(res["tier"], "high")

    def test_release_always_high(self):
        self.check({"docs/a.md": "words\n"}, "high", release=True)

    def test_cli_error_prints_high(self):
        r = Repo()
        p = run([sys.executable, os.path.join(HERE, "classify-risk.py"), "--rev", "nope", "--base", r.base], r.root)
        self.assertEqual(p.stdout.strip(), "high")

    def test_cli_tag_is_release(self):
        r = Repo()
        r.write("docs/a.md", "words\n")
        rev = r.commit()
        g(r.root, "tag", "v1.2.3")
        p = run([sys.executable, os.path.join(HERE, "classify-risk.py"), "--rev", rev, "--base", r.base], r.root)
        self.assertEqual(p.stdout.strip(), "high", p.stderr)


def cli(r, *args):
    p = run([sys.executable, os.path.join(HERE, "classify-risk.py"), *args, "--json"], r.root)
    return json.loads(p.stdout) if p.stdout.strip().startswith("{") else {"tier": p.stdout.strip(), "rc": p.returncode}


class SampleAndCache(unittest.TestCase):
    def test_sample_is_deterministic_and_about_ten_percent(self):
        r = Repo()
        sampled = 0
        n = 200
        for i in range(n):
            r.write("docs/a.md", f"words {i}\n")
            rev = r.commit()
            a = cr.classify(r.root, rev, r.base, salt=b"s" * 32)
            b = cr.classify(r.root, rev, r.base, salt=b"s" * 32)
            self.assertEqual((a["tier"], a["sampled"]), (b["tier"], b["sampled"]))
            if a["sampled"]:
                self.assertEqual(a["tier"], "high")
                sampled += 1
        self.assertTrue(5 <= sampled <= 40, sampled)

    def test_salt_changes_the_draw(self):
        r = Repo()
        diffs = 0
        for i in range(60):
            r.write("docs/a.md", f"words {i}\n")
            rev = r.commit()
            if cr.classify(r.root, rev, r.base, salt=b"a" * 32)["sampled"] != cr.classify(r.root, rev, r.base, salt=b"b" * 32)["sampled"]:
                diffs += 1
        self.assertGreater(diffs, 0)

    def test_redraw_after_sample_stays_sampled(self):
        r = Repo()
        for i in range(80):   # find a change the clone's salt samples, then redraw it with a cosmetic edit
            r.write("docs/a.md", f"words {i}\n")
            rev = r.commit()
            first = cli(r, "--rev", rev, "--base", r.base)
            if first["sampled"]:
                break
        else:
            self.skipTest("no sampled draw in 80 tries")
        r.write("docs/a.md", "words, edited\n")
        rev2 = r.commit()
        again = cli(r, "--rev", rev2, "--base", r.base)
        self.assertTrue(again["sampled"])
        self.assertEqual(again["tier"], "high")

    def test_cache_key_changes_with_inputs(self):
        r = Repo()
        r.write("docs/a.md", "words\n")
        rev = r.commit()
        k1 = cr.classify(r.root, rev, r.base, False, "rules1", "feed1")["cache_key"]
        k2 = cr.classify(r.root, rev, r.base, False, "rules2", "feed1")["cache_key"]
        k3 = cr.classify(r.root, rev, r.base, False, "rules1", "feed2")["cache_key"]
        self.assertEqual(len({k1, k2, k3}), 3)

    def report(self, r, verdict="PASS"):
        p = os.path.join(r.root, ".git", "arb.md")
        with open(p, "w") as fh:
            fh.write(f"## Arbitrator (pass 1)\nVerdict: {verdict}\n")
        return p

    def test_cache_hit_only_after_pass_with_a_passing_record(self):
        r = Repo()
        r.write("src/x.ts", "export const y = 2;\n")
        rev = r.commit()
        key = cr.classify(r.root, rev, r.base)["cache_key"]
        self.assertIsNone(cr.cache_lookup(r.root, key, "normal"))
        cr.cache_record(r.root, key, "normal", "FAIL", None)
        self.assertIsNone(cr.cache_lookup(r.root, key, "normal"))
        rp = self.report(r)
        cr.cache_record(r.root, key, "normal", "PASS", rp)
        self.assertIsNotNone(cr.cache_lookup(r.root, key, "normal"))
        self.assertIsNone(cr.cache_lookup(r.root, key, "high"))
        with open(rp, "a") as fh:   # the record changed: no hit
            fh.write("Verdict: FAIL\n")
        self.assertIsNone(cr.cache_lookup(r.root, key, "normal"))
        with self.assertRaises(RuntimeError):
            cr.cache_record(r.root, key, "normal", "PASS", rp)

    def test_corrupt_cache_record_is_no_hit(self):
        r = Repo()
        r.write("src/x.ts", "export const y = 2;\n")
        rev = r.commit()
        key = cr.classify(r.root, rev, r.base)["cache_key"]
        d = cr.cache_dir(r.root)
        os.makedirs(d, exist_ok=True)
        for body in ['{"verdict":"PASS","tier":"low","at":"x"}', "[]", "null", "{", '{"verdict":"PASS","tier":"high","at": 9999999999}']:
            with open(os.path.join(d, key), "w") as fh:
                fh.write(body)
            self.assertIsNone(cr.cache_lookup(r.root, key, "normal"), body)

    def test_cache_needs_both_versions(self):
        r = Repo()
        r.write("src/x.ts", "export const y = 2;\n")
        rev = r.commit()
        rp = self.report(r)
        res = cli(r, "--rev", rev, "--base", r.base, "--record", "PASS", "--report", rp)
        self.assertEqual(res.get("tier"), "high")   # refused: no versions given
        res = cli(r, "--rev", rev, "--base", r.base, "--ruleset-version", "r", "--feed-version", "f")
        self.assertFalse(res["cache_hit"])

    def test_cli_cache_round_trip(self):
        r = Repo()
        r.write("src/x.ts", "export const y = 2;\n")
        rev = r.commit()
        rp = self.report(r)
        v = ["--ruleset-version", "r", "--feed-version", "f"]
        first = cli(r, "--rev", rev, "--base", r.base, *v, "--record", "PASS", "--report", rp)
        if first["sampled"]:
            self.skipTest("this draw was sampled")
        self.assertTrue(cli(r, "--rev", rev, "--base", r.base, *v)["cache_hit"])

    def test_release_never_cached(self):
        r = Repo()
        r.write("docs/a.md", "words\n")
        rev = r.commit()
        rp = self.report(r)
        v = ["--ruleset-version", "r", "--feed-version", "f"]
        res = cli(r, "--rev", rev, "--base", r.base, "--release", *v, "--record", "PASS", "--report", rp)
        self.assertFalse(res["cache_hit"])

    def test_tagged_release_never_cached(self):
        r = Repo()
        r.write("src/x.ts", "export const y = 2;\n")
        rev = r.commit()
        rp = self.report(r)
        v = ["--ruleset-version", "r", "--feed-version", "f"]
        cli(r, "--rev", rev, "--base", r.base, *v, "--record", "PASS", "--report", rp)
        g(r.root, "tag", "v3.0.0")
        res = cli(r, "--rev", rev, "--base", r.base, *v)
        self.assertEqual(res["tier"], "high")
        self.assertTrue(res["release"])
        self.assertFalse(res["cache_hit"])


class PassOneFixes(unittest.TestCase):
    """One test per pass 1 finding the classifier fixes (DE-98)."""

    def tier(self, files, base_files=None, mode=None):
        r = Repo()
        if base_files:
            for p, t in base_files.items():
                r.write(p, t)
            r.base = r.commit("base files")
        for p, t in files.items():
            if t is None:
                os.remove(os.path.join(r.root, p))
            else:
                r.write(p, t, mode)
        return base_tier(r.tier())

    def test_r1_1_security_paths(self):
        for p in ["src/auth/guard.js", "src/session.ts", "app/routes/items.ts", "lib/middleware.py", "src/api/x.js",
                  "src/admin/page.tsx", "src/crypto.rs", "app/login.swift"]:
            with self.subTest(path=p):
                self.assertEqual(self.tier({p: "return true;\n"}, {p: "return false;\n"}), "high")

    def test_r1_1_signal_in_context(self):
        base = {"src/x.js": "a();\nb();\nverifyToken(t);\nc();\nd();\n"}
        self.assertEqual(self.tier({"src/x.js": "a();\nb();\nverifyToken(t);\nc();\nd2();\n"}, base), "high")

    def test_r1_2_submodule_hidden_by_gitmodules(self):
        sub = Repo()
        sub.write("x.txt", "1\n")
        s1 = sub.commit("s1")
        sub.write("x.txt", "2\n")
        s2 = sub.commit("s2")
        r = Repo()
        r.write(".gitmodules", "[submodule \"vendorx\"]\n\tpath = vendorx\n\turl = ./x\n\tignore = all\n")
        g(r.root, "add", ".gitmodules")
        g(r.root, "update-index", "--add", "--cacheinfo", f"160000,{s1},vendorx")
        g(r.root, "commit", "-q", "-m", "with submodule")
        r.base = g(r.root, "rev-parse", "HEAD").decode().strip()
        g(r.root, "update-index", "--cacheinfo", f"160000,{s2},vendorx")
        r.write("README.md", "hello again\n")
        g(r.root, "add", "README.md")
        g(r.root, "commit", "-q", "-m", "bump")
        rev = g(r.root, "rev-parse", "HEAD").decode().strip()
        res = cr.classify(r.root, rev, r.base)
        self.assertEqual(res["tier"], "high", json.dumps(res, indent=1))
        self.assertIn("vendorx", [f["path"] for f in res["files"]])

    def test_r1_6_r2_2_network_and_routes(self):
        for line in ['fetch ("/x");', "axios.post(u, d);", "new Image().src = u + d;", 'router.post("/items", h);',
                     'app.get("/v2/list", h);', "addEventListener('fetch', e => {});", "urllib.request.urlopen(u)",
                     "requests.get(u)", "open(p, 'w')", "shutil.rmtree(p)", "Function('x')()", "localStorage.setItem('a', b)"]:
            with self.subTest(line=line):
                self.assertEqual(self.tier({"src/app.js": line + "\n"}), "high")

    def test_r1_6_html_and_svg(self):
        self.assertEqual(self.tier({"index.html": "<script src=//evil.example/x.js></script>\n"}), "high")
        self.assertEqual(self.tier({"a.svg": "<svg onload=alert(1)></svg>\n"}), "high")

    def test_r1_7_build_files(self):
        for p in ["setup.py", "build.rs", "Package.swift", "conftest.py", "jest.config.js", "constraints.txt",
                  "Gemfile", "gulpfile.js"]:
            with self.subTest(path=p):
                self.assertEqual(self.tier({p: "x = 1\n"}), "high")

    def test_r1_8_quoted_delete(self):
        self.assertEqual(self.tier({'src/a"b.js': None}, {'src/a"b.js': "x = 1;\n"}), "high")
        self.assertEqual(self.tier({"src/t\tn.py": None}, {"src/t\tn.py": "x = 1\n"}), "high")

    def test_r2_7_text_in_media_file(self):
        self.assertEqual(self.tier({"img/x.png": "#!/bin/sh\necho hi\n"}), "high")

    def test_a1_worker_code(self):
        self.assertEqual(self.tier({"svc/src/b.ts": "const x = 1;\n"}, {"svc/wrangler.toml": "name = 'x'\n"}), "high")
        self.assertEqual(self.tier({"worker/src/b.ts": "const x = 1;\n"}), "high")

    def test_a2_config_json(self):
        for p in [".vscode/tasks.json", ".devcontainer/devcontainer.json", ".eslintrc.json", "renovate.json",
                  "AGENT.md", "GEMINI.md", ".github/copilot-instructions.md", ".cursor/rules.md"]:
            with self.subTest(path=p):
                self.assertEqual(self.tier({p: "{}\n"}), "high")

    def test_pass2_r1_1_role_named_scripts(self):
        for p in ["tools/deploy.js", "bin/install.py", "script/bootstrap.rb", "src/build.js", "src/sign.py",
                  "tasks/release.py", "build/make.js", "src/publish.js", "src/migrate.py", "ci/run.ts", "hack/x.go"]:
            with self.subTest(path=p):
                self.assertEqual(self.tier({p: "a = 1\n"}, {p: "a = 0\n"}), "high")

    def test_plain_data_json_still_normal(self):
        self.assertEqual(self.tier({"data/colors.json": '{"a": 1}\n'}), "normal")


if __name__ == "__main__":
    unittest.main(verbosity=1)

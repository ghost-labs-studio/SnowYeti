#!/usr/bin/env python3
"""Tests for security-scan.py's shellcheck hardening (DE-118). Run: python3 -I .githooks/test-security-scan.py"""
import importlib.util, json, os, re, shutil, sys, tempfile, time, unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("security_scan", os.path.join(HERE, "security-scan.py"))
ss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ss)


class Rec:
    """Stands in for the scan object: records what was added."""
    def __init__(self):
        self.found, self.ran, self.errors = [], [], []

    def add(self, tool, rule, path, line, sev, msg, text):
        self.found.append((tool, rule, path, line))

    def need(self, tool):
        return True


class Shellcheck118(unittest.TestCase):
    def setUp(self):
        self.tree = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tree, ignore_errors=True)

    def write(self, rel, text):
        p = os.path.join(self.tree, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)

    def test_directive_lines_with_disable_anywhere_are_found(self):
        hits = ["# shellcheck disable=SC2086", "#shellcheck disable=SC2086", "# shellcheck source=x.sh disable=SC2086",
                "echo $x  # shellcheck shell=bash disable=SC2086", "# shellcheck external-sources=true disable = SC2086",
                "\t#  shellcheck  enable=all disable=SC1091,SC2086"]
        misses = ["# shellcheck source=lib.sh", "# shellcheck shell=bash", "# not shellcheck disable=SC1", "echo disable=1",
                  "# shellcheckdisable=SC1"]
        for line in hits:
            self.assertTrue(ss.SUPPRESS_RE.search(line), line)
        for line in misses:
            self.assertFalse(ss.SUPPRESS_RE.search(line), line)

    def test_suppressions_report_them_and_the_rc_file(self):
        self.write("a.sh", "#!/bin/sh\n# shellcheck source=b.sh disable=SC2086\necho $1\n")
        self.write("sub/.shellcheckrc", "disable=SC2086\n")
        r = Rec()
        ss.suppressions(r, self.tree, ["a.sh"])
        self.assertIn(("suppression", "shellcheck-disable", "a.sh", 2), r.found)
        self.assertIn(("suppression", ".shellcheckrc", os.path.join("sub", ".shellcheckrc"), None), r.found)

    def test_a_long_line_is_checked_quickly(self):
        start = time.monotonic()
        self.assertFalse(ss.SUPPRESS_RE.search("# shellcheck " + "x " * 500000))
        self.assertLess(time.monotonic() - start, 5)

    def test_shellcheck_runs_with_norc_and_without_shellcheck_opts(self):
        seen = {}
        def fake(cmd, cwd=None, timeout=1800, drop_env=()):
            seen["cmd"], seen["drop"] = cmd, drop_env
            return 0, json.dumps({"comments": []}), ""
        orig = ss.sh
        ss.sh = fake
        try:
            self.write("a.sh", "#!/bin/sh\necho hi\n")
            ss.Scan.shellcheck(Rec(), self.tree, ["a.sh"])
        finally:
            ss.sh = orig
        self.assertIn("--norc", seen["cmd"])
        self.assertIn("SHELLCHECK_OPTS", seen["drop"])

    def test_run_drops_the_named_variables(self):
        os.environ["SHELLCHECK_OPTS"] = "--exclude=SC2086"
        try:
            p = ss.run([sys.executable, "-I", "-c", "import os; print(os.environ.get('SHELLCHECK_OPTS', 'gone'))"],
                       drop_env=("SHELLCHECK_OPTS",))
            self.assertEqual(p.stdout.strip(), "gone")
            p = ss.run([sys.executable, "-I", "-c", "import os; print(os.environ.get('SHELLCHECK_OPTS', 'gone'))"])
            self.assertEqual(p.stdout.strip(), "--exclude=SC2086")   # other tools are unchanged
        finally:
            del os.environ["SHELLCHECK_OPTS"]

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_a_real_rc_file_no_longer_hides_a_finding(self):
        self.write(".shellcheckrc", "disable=SC2086\n")
        self.write("a.sh", "#!/bin/sh\necho $1\n")
        r = Rec()
        os.environ["SHELLCHECK_OPTS"] = "--exclude=SC2086"
        try:
            ss.Scan.shellcheck(r, self.tree, ["a.sh"])
        finally:
            del os.environ["SHELLCHECK_OPTS"]
        self.assertIn(("shellcheck", "SC2086", "a.sh", 2), r.found)


if __name__ == "__main__":
    unittest.main()

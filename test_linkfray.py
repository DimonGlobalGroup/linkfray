#!/usr/bin/env python3
"""Tests for linkfray.py (stdlib unittest only)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "linkfray.py")
sys.path.insert(0, HERE)

import linkfray  # noqa: E402


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, TOOL, *argv],
        capture_output=True,
        text=True,
    )


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "tree")
        os.makedirs(os.path.join(self.root, "sub"))
        with open(os.path.join(self.root, "real.txt"), "w") as fh:
            fh.write("payload\n")
        with open(os.path.join(self.root, "sub", "inner.txt"), "w") as fh:
            fh.write("inner\n")

    def link(self, target, name):
        path = os.path.join(self.root, name)
        os.symlink(target, path)
        return path


class RuleTests(TreeCase):
    def rules_for(self, path):
        findings = linkfray.audit_link(
            path, os.path.realpath(self.root), max_chain=8
        )
        return sorted(f["rule"] for f in findings)

    def test_clean_relative_link_has_no_findings(self):
        p = self.link("real.txt", "good")
        self.assertEqual(self.rules_for(p), [])

    def test_dangling(self):
        p = self.link("gone.txt", "dangling")
        self.assertEqual(self.rules_for(p), ["dangling"])

    def test_self_loop_is_loop_not_dangling(self):
        p = self.link("selfish", "selfish")
        self.assertEqual(self.rules_for(p), ["loop"])

    def test_two_link_cycle_is_loop(self):
        self.link("cycle-b", "cycle-a")
        b = self.link("cycle-a", "cycle-b")
        self.assertEqual(self.rules_for(b), ["loop"])

    def test_absolute_target(self):
        p = self.link(os.path.join(self.root, "real.txt"), "abs")
        self.assertEqual(self.rules_for(p), ["absolute-target"])

    def test_escapes_root_via_dotdot(self):
        outside = os.path.join(self.tmp.name, "outside.txt")
        with open(outside, "w") as fh:
            fh.write("outside\n")
        p = self.link("../outside.txt", "escapee")
        self.assertEqual(self.rules_for(p), ["escapes-root"])

    def test_dotdot_that_stays_inside_is_clean(self):
        p = os.path.join(self.root, "sub", "up")
        os.symlink("../real.txt", p)
        self.assertEqual(self.rules_for(p), [])

    def test_messy_target(self):
        p = self.link("./real.txt", "messy")
        self.assertEqual(self.rules_for(p), ["messy-target"])

    def test_chain_hops_counted_and_long_chain_flagged(self):
        target = os.path.join(self.root, "real.txt")
        prev = "real.txt"
        # Build a 3-link chain: c3 -> c2 -> c1 -> real.txt
        self.link(prev, "c1")
        self.link("c1", "c2")
        p = self.link("c2", "c3")
        findings = linkfray.audit_link(
            p, os.path.realpath(self.root), max_chain=8
        )
        self.assertEqual(findings, [])
        final, hops, looped = linkfray.resolve_chain(p)
        self.assertFalse(looped)
        self.assertEqual(hops, 3)
        self.assertEqual(final, target)
        findings = linkfray.audit_link(
            p, os.path.realpath(self.root), max_chain=2
        )
        self.assertEqual([f["rule"] for f in findings], ["long-chain"])

    def test_chain_to_dangling_reports_final_hop_count(self):
        self.link("nowhere.txt", "end")
        p = self.link("end", "start")
        findings = linkfray.audit_link(
            p, os.path.realpath(self.root), max_chain=8
        )
        self.assertEqual([f["rule"] for f in findings], ["dangling"])
        self.assertEqual(findings[0]["hops"], 2)


class ScanTests(TreeCase):
    def test_directory_symlink_audited_not_followed(self):
        os.symlink("sub", os.path.join(self.root, "dirlink"))
        # A dangling link inside sub must be counted exactly once:
        # if the walk followed dirlink it would be seen twice.
        os.symlink("nope.txt", os.path.join(self.root, "sub", "inner-bad"))
        findings, dirs, links, errors = linkfray.scan_root(self.root, 8)
        self.assertEqual(errors, 0)
        dangling_paths = [f["path"] for f in findings if f["rule"] == "dangling"]
        self.assertEqual(len(dangling_paths), 1)
        self.assertEqual(links, 2)

    def test_scan_root_counts(self):
        self.link("real.txt", "ok")
        self.link("gone.txt", "bad")
        findings, dirs, links, errors = linkfray.scan_root(self.root, 8)
        self.assertEqual(dirs, 2)  # root + sub
        self.assertEqual(links, 2)
        self.assertEqual(len(findings), 1)


class CliTests(TreeCase):
    def test_text_output_and_exit_1_on_dangling(self):
        self.link("gone.txt", "bad")
        proc = run_cli("scan", self.root)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("HIGH dangling 1", proc.stdout)
        self.assertIn(
            "linkfray: 2 dirs scanned, 1 links, 1 findings "
            "(1 high, 0 medium, 0 low), 0 errors",
            proc.stdout,
        )

    def test_clean_tree_exit_0(self):
        self.link("real.txt", "ok")
        proc = run_cli("scan", self.root)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("0 findings", proc.stdout)

    def test_fail_on_never_exit_0_despite_dangling(self):
        self.link("gone.txt", "bad")
        proc = run_cli("scan", "--fail-on", "never", self.root)
        self.assertEqual(proc.returncode, 0)

    def test_min_severity_filters_output_and_exit(self):
        self.link(os.path.join(self.root, "real.txt"), "abs")
        proc = run_cli("scan", "--min-severity", "medium", self.root)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("0 findings", proc.stdout)

    def test_missing_root_exit_2_no_traceback(self):
        proc = run_cli("scan", os.path.join(self.tmp.name, "nope"))
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_file_as_root_exit_2(self):
        proc = run_cli("scan", os.path.join(self.root, "real.txt"))
        self.assertEqual(proc.returncode, 2)

    def test_bad_max_chain_exit_2(self):
        proc = run_cli("scan", "--max-chain", "-1", self.root)
        self.assertEqual(proc.returncode, 2)

    def test_json_structure_and_determinism(self):
        self.link("gone.txt", "bad")
        self.link("real.txt", "ok")
        first = run_cli("scan", "--json", self.root)
        second = run_cli("scan", "--json", self.root)
        self.assertEqual(first.returncode, 1)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertEqual(report["tool"], "linkfray")
        self.assertEqual(report["counts"]["links_scanned"], 2)
        self.assertEqual(report["counts"]["high"], 1)
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule"], "dangling")
        self.assertEqual(finding["target"], "gone.txt")
        self.assertEqual(finding["hops"], 1)

    def test_loop_finding_hops_is_null_in_json(self):
        self.link("selfish", "selfish")
        proc = run_cli("scan", "--json", self.root)
        report = json.loads(proc.stdout)
        loop_findings = [f for f in report["findings"] if f["rule"] == "loop"]
        self.assertEqual(len(loop_findings), 1)
        self.assertIsNone(loop_findings[0]["hops"])

    def test_version(self):
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)

    def test_read_only_tree_unchanged(self):
        self.link("gone.txt", "bad")
        before = sorted(os.listdir(self.root))
        run_cli("scan", self.root)
        after = sorted(os.listdir(self.root))
        self.assertEqual(before, after)
        self.assertTrue(os.path.islink(os.path.join(self.root, "bad")))


if __name__ == "__main__":
    unittest.main()

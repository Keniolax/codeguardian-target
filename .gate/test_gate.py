"""Tests for gate.py. Run: python3 -m unittest discover -s .gate"""

import json
import tempfile
import unittest
from pathlib import Path

import gate


def trivy_report(*vulns):
    return {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
        {"VulnerabilityID": v, "PkgName": "pkg", "InstalledVersion": "1.0.0", "Severity": "HIGH"}
        for v in vulns]}]}


class TrivyDiff(unittest.TestCase):
    def test_keeps_only_new_vulnerabilities(self):
        new = gate.normalize_trivy(trivy_report("CVE-1", "CVE-2"), trivy_report("CVE-1"))
        self.assertEqual([f["rule_id"] for f in new], ["CVE-2"])

    def test_nothing_new_means_nothing_reported(self):
        self.assertEqual(gate.normalize_trivy(trivy_report("CVE-1"), trivy_report("CVE-1")), [])

    def test_line_shift_does_not_make_a_misconfiguration_new(self):
        def mis(line):
            return {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
                {"ID": "DS026", "Status": "FAIL", "Severity": "LOW", "CauseMetadata": {"StartLine": line}}]}]}
        self.assertEqual(gate.normalize_trivy(mis(9), mis(3)), [])

    def test_extra_instance_of_a_check_is_new(self):
        one = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Status": "FAIL", "Severity": "HIGH"}]}]}
        two = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Status": "FAIL", "Severity": "HIGH"}] * 2}]}
        self.assertEqual(len(gate.normalize_trivy(two, one)), 1)

    def test_passed_misconfiguration_is_ignored(self):
        head = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Status": "PASS", "Severity": "HIGH"}]}]}
        self.assertEqual(gate.normalize_trivy(head, {}), [])


class SemgrepIds(unittest.TestCase):
    def test_local_rule_id_does_not_depend_on_the_runner_path(self):
        report = {"results": [{"check_id": "home.runner.work._temp..gate.rules.gate.child-process-exec-nonliteral",
                               "path": "routes/x.ts", "start": {"line": 3}, "extra": {"severity": "ERROR"}}]}
        self.assertEqual(gate.normalize_semgrep(report)[0]["rule_id"], "gate.child-process-exec-nonliteral")

    def test_registry_rule_id_is_unchanged(self):
        rid = "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection"
        report = {"results": [{"check_id": rid, "path": "a.ts", "start": {"line": 1}, "extra": {}}]}
        self.assertEqual(gate.normalize_semgrep(report)[0]["rule_id"], rid)


class InlineSuppression(unittest.TestCase):
    PATCH = (
        "diff --git a/routes/x.ts b/routes/x.ts\n"
        "--- a/routes/x.ts\n+++ b/routes/x.ts\n"
        "@@ -10,2 +10,3 @@\n"
        " const a = 1\n"
        "+eval(req.body.code) // nosemgrep\n"
        " const b = 2\n"
    )

    def test_added_nosemgrep_is_a_finding_with_its_line(self):
        found = gate.inline_suppressions(self.PATCH)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["file"], found[0]["line"]), ("routes/x.ts", 11))

    def test_removed_lines_are_not_flagged(self):
        self.assertEqual(gate.inline_suppressions(self.PATCH.replace("+eval", "-eval")), [])


class Decide(unittest.TestCase):
    def run_decide(self, scans, suppressions, patch=""):
        with tempfile.TemporaryDirectory() as d:
            for name, findings in scans.items():
                Path(d, f"{name}.json").write_text(json.dumps(findings))
            Path(d, "s.json").write_text(json.dumps({"suppressions": suppressions}))
            Path(d, "p.diff").write_text(patch)
            return gate.decide(d, str(Path(d, "p.diff")), str(Path(d, "s.json")), False)

    def all_clean(self):
        return {"semgrep": [], "gitleaks": [], "trivy": [], "zap": []}

    def test_clean_scans_pass(self):
        self.assertEqual(self.run_decide(self.all_clean(), [])["result"], "pass")

    def test_missing_scanner_output_fails(self):
        scans = self.all_clean()
        del scans["zap"]
        d = self.run_decide(scans, [])
        self.assertEqual((d["result"], d["missing_scanners"]), ("fail", ["zap"]))

    def test_new_high_finding_fails(self):
        scans = self.all_clean()
        scans["semgrep"] = [gate.finding("semgrep", "r", "high", "a.ts", 1, "t", "m")]
        self.assertEqual(self.run_decide(scans, [])["result"], "fail")

    def test_low_zap_alert_is_reported_not_blocking(self):
        scans = self.all_clean()
        scans["zap"] = [gate.finding("zap", "10021", "low", "http://x/", 0, "t", "m")]
        d = self.run_decide(scans, [])
        self.assertEqual((d["result"], len(d["reported"])), ("pass", 1))

    def test_suppression_with_reason_silences(self):
        scans = self.all_clean()
        scans["zap"] = [gate.finding("zap", "10098", "medium", "http://x/", 0, "t", "m")]
        sup = [{"scanner": "zap", "rule_id": "10098", "reason": "Present in Juice Shop v20.3.0 at import."}]
        d = self.run_decide(scans, sup)
        self.assertEqual((d["result"], len(d["suppressed"])), ("pass", 1))

    def test_suppression_without_reason_fails_the_gate(self):
        sup = [{"scanner": "zap", "rule_id": "10098", "reason": "noise"}]
        d = self.run_decide(self.all_clean(), sup)
        self.assertEqual(d["result"], "fail")
        self.assertTrue(d["suppression_problems"])


if __name__ == "__main__":
    unittest.main()

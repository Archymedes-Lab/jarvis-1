"""The verification runner that ships in the package: it must pass on this
tree, report a planted failure without raising, and drive the exit code."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.service import verifyjob
from jarvis.verify import invariants, properties, report, static
from jarvis.verify.models import response_ladder

# The response-ladder model takes seconds; tests about other parts of the
# report run the quick models only, and test_this_tree_passes runs them all.
QUICK_MODELS = tuple((i, n, (lambda: response_ladder.model(max_tick=1)) if n == "response ladder" else b)
                     for i, n, b in report.MODELS)


class ReportTests(unittest.TestCase):
    def setUp(self):
        if self._testMethodName != "test_this_tree_passes":
            patcher = patch.object(report, "MODELS", QUICK_MODELS)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_this_tree_passes(self):
        r = report.run(cases=20)
        self.assertTrue(r["ok"], report.text(r))
        self.assertEqual(len(r["properties"]), len(properties.PROPERTIES))
        self.assertEqual([m["invariant"] for m in r["models"]], ["V6", "V7", "V8", "V11", "V13"])
        self.assertTrue(all(m["exhausted"] for m in r["models"]))
        self.assertIn("PASSED", report.text(r))

    def test_registry_and_static_rules_are_part_of_the_run(self):
        r = report.run(cases=5)
        self.assertTrue(r["invariants"]["ok"], r["invariants"]["problems"])
        self.assertGreaterEqual(r["invariants"]["count"], 15)
        self.assertTrue(r["static"]["ok"] and r["static"]["applicable"])
        self.assertEqual([x["id"] for x in r["static"]["rules"]], ["S1", "S2", "S3", "S4"])
        text = report.text(r)
        self.assertIn("invariant registry", text)
        self.assertIn("S2 V14", text)

    def test_a_static_violation_fails_the_run_and_names_the_place(self):
        bad = {"ok": False, "applicable": True, "files": 1, "errors": [],
               "rules": [{"id": "S3", "invariant": "V14", "summary": "s", "violations": 1}],
               "violations": [{"rule": "S3", "invariant": "V14", "path": "jarvis/x.py", "line": 2,
                               "text": "os.system('id')"}]}
        with patch.object(static, "run", return_value=bad):
            r = report.run(cases=5)
        self.assertFalse(r["ok"])
        self.assertIn("jarvis/x.py:2", report.text(r))

    def test_a_registry_problem_fails_the_run(self):
        with patch.object(invariants, "conformance", return_value=["V99 has no executable check"]):
            r = report.run(cases=5)
        self.assertFalse(r["ok"])
        self.assertIn("V99 has no executable check", report.text(r))

    def test_a_crashing_rule_engine_is_a_failure_not_a_pass(self):
        with patch.object(static, "run", side_effect=RuntimeError("boom")):
            r = report.run(cases=5)
        self.assertFalse(r["ok"])
        self.assertIn("RuntimeError", report.text(r))

    def test_a_planted_failure_is_reported_not_raised(self):
        planted = (("V0", "planted", lambda g: g.int(0, 2), lambda v: v != 1),)
        with patch.object(properties, "PROPERTIES", properties.PROPERTIES + planted):
            r = report.run(cases=20)
        self.assertFalse(r["ok"])
        bad = [p for p in r["properties"] if not p["ok"]]
        self.assertEqual([p["name"] for p in bad], ["planted"])
        self.assertIn("FAILED", report.text(r))

    def test_a_broken_model_is_a_failure(self):
        def boom():
            raise RuntimeError("no model")
        with patch.object(report, "MODELS", (("V9", "broken", boom),)):
            r = report.run(cases=5)
        self.assertFalse(r["ok"])
        self.assertIn("RuntimeError", r["models"][0]["error"])

    def test_a_model_whose_code_is_not_shipped_is_not_applicable(self):
        from pathlib import Path

        from jarvis.verify.models import release
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(release, "DEPLOY_SCRIPT", Path(tmp) / "absent.py"), \
             patch.object(release, "deploy", None):
            r = report.run(cases=5)
        rel = [m for m in r["models"] if m["name"] == "release switch"][0]
        self.assertTrue(r["ok"])
        self.assertFalse(rel["applicable"])
        self.assertIn("not part of this copy", rel["reason"])
        self.assertIn("1 not applicable", report.summary(r))
        self.assertIn("n/a  V7", report.text(r))

    def test_cli_writes_json_and_sets_the_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v.json")
            with patch("sys.stdout"):
                code = report.main(["--cases", "10", "--json", path, "--quiet"])
            self.assertEqual(code, 0)
            with open(path) as fh:
                self.assertTrue(json.load(fh)["ok"])
            planted = (("V0", "planted", lambda g: 1, lambda v: False),)
            with patch.object(properties, "PROPERTIES", planted), patch("sys.stdout"):
                self.assertEqual(report.main(["--cases", "3", "--quiet"]), 1)


class VerifyJobTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(report, "MODELS", QUICK_MODELS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_passing_tree_is_an_ok_finding_with_a_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "j.db"))
            try:
                out = verifyjob.audit(store)
                meta = json.loads(store.get_meta(verifyjob.META, "{}"))
            finally:
                store.close()
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertTrue(meta["ok"])
        self.assertIn("properties", meta["summary"])

    def test_violation_is_high_and_names_the_invariant(self):
        planted = (("V0", "planted", lambda g: 1, lambda v: False),)
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "j.db"))
            try:
                with patch.object(properties, "PROPERTIES", planted):
                    out = verifyjob.audit(store)
            finally:
                store.close()
        self.assertEqual([f["severity"] for f in out], ["high"])
        self.assertIn("V0 planted", out[0]["detail"])
        self.assertIn("unverified", out[0]["detail"])


if __name__ == "__main__":
    unittest.main()

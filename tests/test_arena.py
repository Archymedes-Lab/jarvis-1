import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core.paths import PACKAGE_DIR
from jarvis.lab import intel, isolation, regression, runner, scoring
from jarvis.lab.providers import atomic
from jarvis.lab.scenario import Scenario, ScenarioError, load_dir

LIB = PACKAGE_DIR / "lab" / "scenarios"


def cred_scenario():
    return [s for s in load_dir(LIB) if s.id == "cred-lsass-read-t1003-001"][0]


class ScenarioModelTests(unittest.TestCase):
    def test_builtin_scenarios_load_and_are_valid(self):
        scenarios = load_dir(LIB)
        self.assertTrue(scenarios)
        for s in scenarios:
            self.assertEqual(s.safety, "synthetic")
            self.assertIn("classified", s.exercised)

    def test_live_scenario_cannot_be_synthetic_safety(self):
        with self.assertRaises(ScenarioError):
            Scenario(id="x", title="x", platform="win", safety="synthetic", source="live")

    def test_unknown_field_rejected(self):
        with self.assertRaises(ScenarioError):
            Scenario.from_dict({"id": "x", "title": "x", "platform": "win",
                                "safety": "synthetic", "source": "synthetic", "bogus": 1})


class IsolationTests(unittest.TestCase):
    def _s(self, source, safety):
        return Scenario(id="x", title="x", platform="win", safety=safety, source=source)

    def test_synthetic_and_replay_always_allowed(self):
        isolation.guard(self._s("synthetic", "synthetic"))
        isolation.guard(self._s("replay", "high_risk_detonation"))   # replaying telemetry runs nothing

    def test_live_refused_without_sandbox(self):
        with mock.patch.object(isolation, "is_sandbox", return_value=False):
            with self.assertRaises(isolation.Refused):
                isolation.guard(self._s("live", "safe_emulation"))

    def test_detonation_refused_even_in_sandbox_without_flag(self):
        with mock.patch.object(isolation, "is_sandbox", return_value=True):
            with self.assertRaises(isolation.Refused):
                isolation.guard(self._s("live", "high_risk_detonation"))
            isolation.guard(self._s("live", "safe_emulation"))       # allowed in sandbox
            with self.assertRaises(isolation.Refused):
                isolation.guard(self._s("live", "prohibited_in_automation"), allow_detonation=True)


class RunnerScoringTests(unittest.TestCase):
    def test_lsass_scenario_scores_the_full_observed_chain(self):
        card = runner.run(cred_scenario())
        self.assertTrue(card["ok"], card["properties"])
        self.assertEqual(card["score"], 100)
        for prop in ("observed", "understood", "correlated", "classified"):
            self.assertEqual(card["properties"][prop]["status"], "pass")
        self.assertEqual(card["earliest_decision"]["source_event"], 10)

    def test_missing_detection_fails_classified_not_observed(self):
        s = cred_scenario()
        # Break the classification expectation: the events still arrive, but no
        # detector produces a 'tampering' critical, so classified must fail
        # while observed/understood still pass.
        s.expect.classified = {"category": "tampering", "min_severity": "critical"}
        card = runner.run(s)
        self.assertEqual(card["properties"]["observed"]["status"], "pass")
        self.assertEqual(card["properties"]["classified"]["status"], "fail")
        self.assertFalse(card["ok"])

    def test_response_properties_score_when_provided(self):
        s = cred_scenario()
        s.expect.contained = True
        card = scoring.score(s, [], [], response={"contained": True})
        self.assertEqual(card["properties"]["contained"]["status"], "pass")


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = regression.Regression(Path(self.tmp.name) / "arena.db")

    def tearDown(self):
        self.reg.close()
        self.tmp.cleanup()

    def test_regression_is_flagged_when_score_drops(self):
        s = cred_scenario()
        self.reg.remember(s)
        self.reg.record({"scenario": s.id, "score": 100, "ok": True, "exercised": ["classified"],
                         "passed": ["classified"], "earliest_decision": {}})
        self.assertEqual(self.reg.regressions(), [])
        self.reg.record({"scenario": s.id, "score": 50, "ok": False, "exercised": ["classified"],
                         "passed": [], "earliest_decision": {}})
        regs = self.reg.regressions()
        self.assertEqual(regs[0]["id"], s.id)
        self.assertEqual((regs[0]["best"], regs[0]["now"]), (100, 50))


class AtomicImportTests(unittest.TestCase):
    def test_command_test_becomes_high_risk_live_spec(self):
        tech = {"attack_technique": "T1003.001", "display_name": "LSASS Memory",
                "atomic_tests": [
                    {"name": "Dump LSASS with comsvcs", "supported_platforms": ["windows"],
                     "auto_generated_guid": "abcd", "description": "x",
                     "executor": {"name": "command_prompt", "command": "rundll32 ..."}},
                    {"name": "Manual step", "supported_platforms": ["windows"],
                     "executor": {"name": "manual", "steps": "do it by hand"}},
                ]}
        scenarios = atomic.from_tests(tech)
        self.assertEqual(len(scenarios), 2)
        cmd = [s for s in scenarios if s.id == "atomic-abcd"][0]
        self.assertEqual(cmd.safety, "high_risk_detonation")
        self.assertEqual(cmd.source, "live")
        self.assertEqual(cmd.techniques, ["T1003.001"])
        # It must refuse to run outside a sandbox, and never produce/execute.
        with mock.patch.object(isolation, "is_sandbox", return_value=False):
            with self.assertRaises(isolation.Refused):
                runner.run(cmd)


class SelfDefenseTests(unittest.TestCase):
    def _by_id(self, sid):
        return [s for s in load_dir(LIB) if s.id == sid][0]

    def test_rewritten_segment_is_caught(self):
        card = runner.run(self._by_id("selfdef-eventlog-segment-edited"))
        self.assertTrue(card["ok"])
        self.assertEqual(card["properties"]["classified"]["status"], "pass")

    def test_deleted_segment_is_caught(self):
        card = runner.run(self._by_id("selfdef-eventlog-segment-deleted"))
        self.assertTrue(card["ok"])

    def test_sensor_blinding_is_telemetry_loss(self):
        card = runner.run(self._by_id("selfdef-sysmon-blinding-t1562"))
        self.assertTrue(card["ok"])
        self.assertEqual(card["properties"]["classified"]["status"], "pass")


class ResponseHalfTests(unittest.TestCase):
    def test_response_callback_scores_containment_chain(self):
        s = cred_scenario()
        s.expect.intervened = True
        s.expect.contained = True
        s.expect.verified = True

        def responder(scenario, events, findings):
            # A containment that worked, but recovery not verified.
            return {"intervened": True, "contained": True, "verified": False}

        card = runner.run(s, response=responder)
        self.assertEqual(card["properties"]["intervened"]["status"], "pass")
        self.assertEqual(card["properties"]["contained"]["status"], "pass")
        self.assertEqual(card["properties"]["verified"]["status"], "fail")
        self.assertIn("verified", card["exercised"])
        self.assertFalse(card["ok"])            # one exercised property failed


class CalderaImportTests(unittest.TestCase):
    def test_ability_becomes_live_high_risk_spec(self):
        from jarvis.lab.providers import caldera
        ability = {"ability_id": "ab12", "name": "Whoami", "tactic": "discovery",
                   "technique": {"attack_id": "T1033", "name": "Owner"},
                   "platforms": {"windows": {"psh": {"command": "whoami"}}}}
        s = caldera.from_ability(ability)
        self.assertEqual((s.safety, s.source), ("high_risk_detonation", "live"))
        self.assertEqual(s.techniques, ["T1033"])
        self.assertEqual(s.spec["command"], "whoami")

    def test_adversary_preserves_chain_order(self):
        from jarvis.lab.providers import caldera
        abilities = {"a": {"ability_id": "a", "name": "A", "technique": {"attack_id": "T1"},
                           "platforms": {"linux": {"sh": {"command": "id"}}}},
                     "b": {"ability_id": "b", "name": "B", "technique": {"attack_id": "T2"},
                           "platforms": {"linux": {"sh": {"command": "ls"}}}}}
        chain = caldera.from_adversary({"name": "apt", "atomic_ordering": ["b", "a"]}, abilities)
        self.assertEqual([s.spec["chain_position"] for s in chain], [1, 2])
        self.assertEqual([s.techniques[0] for s in chain], ["T2", "T1"])


class CandidateBatchTests(unittest.TestCase):
    def test_research_behaviors_become_classified_candidates(self):
        cands = intel.candidates_from([
            {"report_id": "r1", "title": "injector", "technique": "T1055.001"},
            {"report_id": "r2", "title": "unknown", "technique": "T9999"},
            {"technique": "T1003.001"},          # no report_id -> skipped
        ])
        self.assertEqual(len(cands), 2)
        summary = intel.coverage_summary(cands)
        self.assertEqual(summary["has_detector"], 1)
        self.assertEqual(len(summary["gaps"]), 1)
        self.assertEqual(summary["gaps"][0]["technique"], "T9999")
        for c in cands:
            with self.assertRaises(isolation.Refused):
                isolation.guard(c)


class IntelCandidateTests(unittest.TestCase):
    def test_candidate_is_prohibited_and_maps_coverage(self):
        c = intel.candidate(report_id="2026-1", title="new injector", technique="T1055",
                            observed=[{"kind": "image", "value": "x.exe"}])
        self.assertEqual(c.safety, "prohibited_in_automation")
        with self.assertRaises(isolation.Refused):
            isolation.guard(c)
        gap = intel.gap_report(c)
        self.assertTrue(gap["known_technique"])
        self.assertEqual(gap["relevant_events"], [8, 10, 25])

    def test_unknown_technique_is_a_gap(self):
        gap = intel.gap_report(intel.candidate(report_id="2", title="t", technique="T9999"))
        self.assertFalse(gap["has_detector"])
        self.assertIn("coverage gap", gap["verdict"])


if __name__ == "__main__":
    unittest.main()

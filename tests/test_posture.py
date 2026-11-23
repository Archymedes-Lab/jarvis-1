import copy
import json
import tempfile
import unittest
from unittest.mock import Mock

from jarvis.response import acknowledge, protocols, remediation
from jarvis.response.reporting import score
from jarvis.service import posture
from tests import _apiauth


class PostureTests(unittest.TestCase):
    def setUp(self):
        self.jobs = {"secrets": (60, "Secrets"), "internet": (60, "Network")}
        self.finding = {"title": "OpenAI API key in plaintext", "category": "secret",
                        "severity": "critical", "detail": "synthetic fixture"}
        self.snaps = {"secrets": {"ts": 1000, "findings": [self.finding]},
                      "internet": {"ts": 1000, "findings": []}}

    def test_acceptance_lowers_score_but_stays_debt_and_blocks_readiness(self):
        fid = acknowledge.finding_id(self.finding, "secrets")
        acks = {fid: {"severity": "critical", "expires": 1100, "confirmed_by": acknowledge.TERMINAL}}
        before = posture.build(self.snaps, self.jobs, now=1001)
        accepted = posture.build(self.snaps, self.jobs, now=1001, acks=acks)
        self.assertGreater(accepted["score"], before["score"])
        self.assertEqual(accepted["debt_counts"]["accepted"], 1)
        self.assertFalse(accepted["readiness_gates"]["no_weighted_findings"])
        expired = posture.build(self.snaps, self.jobs, now=1100, acks=acks)
        self.assertEqual(expired["debt_counts"]["accepted"], 0)
        self.assertEqual(expired["score"], before["score"])

    def test_collector_loss_never_improves_health(self):
        before = score.compute(self.snaps, self.jobs, 1001)["score"]
        for mode in ("missing", "stale", "failure"):
            snaps = copy.deepcopy(self.snaps)
            if mode == "missing":
                del snaps["secrets"]
            elif mode == "stale":
                snaps["secrets"]["ts"] = 1
            else:
                snaps["secrets"]["error"] = "unavailable"
            self.assertLessEqual(score.compute(snaps, self.jobs, 1001)["score"], before)

    def test_projection_uses_real_formula_and_does_not_mutate_evidence(self):
        original = copy.deepcopy(self.snaps)
        result = posture.build(self.snaps, self.jobs, now=1001)
        self.assertFalse(result["projection_is_verified"])
        self.assertGreater(result["projected_after_verified_remediation"], result["score"])
        self.assertEqual(self.snaps, original)
        self.assertEqual(result["readiness"], "blocked")

    def test_readiness_names_failed_gates_without_claiming_assurance(self):
        result = posture.build(self.snaps, self.jobs, now=1001,
                               repair_state={"status": "active", "failed": 1})
        self.assertEqual(result["readiness"], "blocked")
        self.assertFalse(result["readiness_gates"]["host_score_100"])
        self.assertTrue(result["readiness_gates"]["collector_coverage_100"])
        self.assertFalse(result["readiness_gates"]["no_weighted_findings"])
        self.assertFalse(result["readiness_gates"]["automatic_remediation_ledger_clear"])
        self.assertFalse(result["readiness_gates"]["sustained_health_100_15m"])
        self.assertIn("assurance is separate", result["readiness_scope"])

    def test_clean_snapshot_still_needs_sustained_proof(self):
        clean = {name: {**snap, "findings": []} for name, snap in self.snaps.items()}
        result = posture.build(clean, self.jobs, now=1001,
                               repair_state={"status": "active", "failed": 0,
                                             "blocked": 0, "actions": []})
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["readiness"], "blocked")
        self.assertFalse(result["readiness_gates"]["sustained_health_100_15m"])

    def test_candidate_requires_all_host_gates_and_is_not_release_certification(self):
        clean = {name: {**snap, "findings": []} for name, snap in self.snaps.items()}
        samples = [{"at": at, "score": 100, "coverage": 100, "verified": True}
                   for at in (1000, 1500, 2000)]
        # Rebase snapshots to the latest sample so coverage is still fresh.
        for snap in clean.values():
            snap["ts"] = 2000
        result = posture.build(clean, self.jobs, now=2000,
                               sustained_samples=samples,
                               repair_state={"status": "active", "failed": 0,
                                             "blocked": 0, "actions": []})
        self.assertEqual(result["readiness"], "candidate")
        self.assertTrue(all(result["readiness_gates"].values()))
        self.assertIn("host evidence gates only", result["readiness_scope"])

    def test_graph_rejects_cycle_and_secret_removal_requires_rotation(self):
        graph = protocols.RemediationGraph(protocols.BY_ID["plaintext-secrets"].remediation_edges)
        self.assertFalse(graph.can_proceed("remove_plaintext", set()))
        self.assertTrue(graph.can_proceed("remove_plaintext", {"rotate_secret"}))
        with self.assertRaises(ValueError):
            protocols.RemediationGraph({"a": ["b"], "b": ["a"]}).topological_order(["a", "b"])

    def test_http_posture_routes_return_unknown_for_empty_evidence(self):
        from jarvis.core.store import Store
        from jarvis.web.server import Handler
        with tempfile.TemporaryDirectory() as tmp:
            path = tmp + "/state.db"
            Store(path).close()
            handler = Handler.__new__(Handler)
            handler.db_path = path
            handler.headers = {"Host": "localhost:8787", **_apiauth.grant(self)}
            handler._send = Mock()
            for route in ("/api/posture", "/api/posture/path-to-100"):
                handler.path = route
                handler.do_GET()
                status, body = handler._send.call_args.args
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["score"], 0)
                self.assertFalse(json.loads(body)["projection_is_verified"])
            handler.headers = {"Host": "attacker.example"}
            handler.do_GET()
            self.assertEqual(handler._send.call_args.args[0], 403)

    def test_sustained_health_requires_repeated_fresh_verified_samples(self):
        samples = [
            {"at": 1000, "score": 100, "coverage": 100, "verified": True},
            {"at": 1500, "score": 100, "coverage": 100, "verified": True},
            {"at": 2000, "score": 100, "coverage": 100, "verified": True},
        ]
        self.assertEqual(score.sustained_health(samples[:1], now=1000)["status"],
                         "collecting")
        verified = score.sustained_health(samples, now=2000)
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["duration_s"], 1000)
        broken = score.sustained_health(samples + [{
            "at": 2100, "score": 99, "coverage": 100, "verified": False}],
            now=2100)
        self.assertEqual(broken["status"], "broken")
        self.assertEqual(score.sustained_health(samples, now=3000)["status"],
                         "unverified")

    def test_repair_audit_reports_only_bounded_ledger_metadata(self):
        from jarvis.core.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp + "/state.db")
            try:
                store.set_meta(remediation.META, json.dumps({
                    "telemetry": {"status": "verified", "job": "sysmon_linux",
                                  "at": 1000, "verified_at": 1001,
                                  "attempts": [900, 1000],
                                  "finding_keys": ["must-not-leak"]}}))
                result = remediation.audit(store, now=1100)
            finally:
                store.close()
        self.assertEqual(result["verified"], 1)
        self.assertEqual(result["actions"][0]["attempts_24h"], 2)
        self.assertNotIn("finding_keys", result["actions"][0])

    def test_repair_audit_tolerates_malformed_nested_timestamps(self):
        from jarvis.core.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp + "/state.db")
            try:
                store.set_meta(remediation.META, json.dumps({
                    "mount": {"status": "attempting", "at": "invalid",
                              "verified_at": {}, "attempts": ["invalid"]}}))
                result = remediation.audit(store, now=1100)
            finally:
                store.close()
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["actions"][0]["at"], 0)

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from jarvis.core import collection, incidents
from jarvis.core.store import Store
from jarvis.service.schedule import JOBS
from jarvis.service.scheduler import Scheduler
from jarvis.web.server import Handler, _performance_state
from tests import _apiauth


class PerformanceStateTests(unittest.TestCase):
    def test_duty_cycle_uses_measured_duration_over_cadence(self):
        from types import SimpleNamespace

        jobs = [
            {"name": "native", "label": "Native", "duration": 3, "interval": 60},
            {"name": "slow", "label": "Slow", "duration": 30, "interval": 60},
        ]
        scheduler = SimpleNamespace(current="slow", fast_current=None)
        with patch("builtins.open", side_effect=OSError("no proc")):
            result = _performance_state(jobs, scheduler)
        self.assertEqual(result["scheduled_duty_pct"], 55.0)
        self.assertEqual(result["top"][0]["name"], "slow")
        self.assertEqual(result["running"], ["slow"])
        self.assertIsNone(result["cpu_pct"])


class SchedulerColdStartTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = Scheduler(":memory:", ("wsl",))
        future = time.time() + 3600
        self.scheduler.next_run = {name: future for name in JOBS}
        self.scheduler.next_run["coverage"] = 0

    def test_automatic_coverage_waits_for_first_collector_sweep(self):
        self.assertIsNone(self.scheduler._due())
        self.scheduler.cold_start_pending.clear()
        self.assertEqual(self.scheduler._due(), "coverage")

    def test_forced_coverage_still_runs_during_cold_start(self):
        self.scheduler.force("coverage")
        self.assertEqual(self.scheduler._due(), "coverage")

    def test_automatic_report_waits_for_first_collector_sweep(self):
        self.scheduler.next_run["coverage"] = time.time() + 3600
        self.scheduler.next_run["report"] = 0
        self.assertIsNone(self.scheduler._due())
        self.scheduler.cold_start_pending.clear()
        self.assertEqual(self.scheduler._due(), "report")

    def test_cold_start_hold_is_bounded(self):
        # A starved or governor-deferred collector must not freeze the
        # coverage audit and the recorded score indefinitely.
        from jarvis.service import scheduler as scheduler_mod
        self.assertIsNone(self.scheduler._due())
        self.scheduler.started_at -= scheduler_mod.COLD_START_HOLD_S + 1
        self.assertTrue(self.scheduler.cold_start_pending)
        self.assertEqual(self.scheduler._due(), "coverage")

    def test_fresh_persisted_results_do_not_hold_cold_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "j.db")
            store = Store(db)
            try:
                store.save_snapshot("secrets", [], 1.0, "")
                store.save_snapshot("posture", [], 1.0, "collector failed")
            finally:
                store.close()
            pending = Scheduler(db, ("wsl",)).cold_start_pending
        self.assertNotIn("secrets", pending)
        self.assertIn("posture", pending)    # failing still holds the gate
        self.assertIn("deep_hidden", pending)    # never ran
        self.assertNotIn("coverage", pending)

    def test_initial_deadlines_use_current_time_not_epoch(self):
        scheduler = Scheduler(":memory:", ("wsl",))
        created = time.time()
        self.assertTrue(all(abs(deadline - created) < 1
                            for deadline in scheduler.next_run.values()))


class SchedulerFairnessTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = Scheduler(":memory:", ("wsl",))
        self.scheduler.cold_start_pending.clear()

    def test_relative_lateness_protects_short_interval_jobs(self):
        future = 2_000.0
        self.scheduler.next_run = {name: future for name in JOBS}
        # Firewall has been waiting longer in absolute seconds, but scan has
        # missed a larger share of its promised cadence and must run first.
        self.scheduler.next_run["firewall"] = 900.0
        self.scheduler.next_run["scan"] = 950.0
        with patch("jarvis.service.scheduler.time.time", return_value=1_000.0):
            self.assertEqual(self.scheduler._due(), "scan")

    def test_not_yet_due_jobs_are_not_selected(self):
        self.scheduler.next_run = {name: 1_001.0 for name in JOBS}
        with patch("jarvis.service.scheduler.time.time", return_value=1_000.0):
            self.assertIsNone(self.scheduler._due())


class JobRegistryTests(unittest.TestCase):
    def test_every_scheduled_job_has_a_runner_and_nothing_else_does(self):
        from jarvis.service import jobs
        self.assertEqual(set(jobs.RUNNERS), set(JOBS))

    def test_unknown_job_is_rejected(self):
        from jarvis.service import jobs
        with self.assertRaises(ValueError):
            jobs.run_job("no-such-job", ("wsl",), ":memory:")


class DefenderPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "state.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.scheduler = Scheduler(self.path, ("win",))
        self.finding = {"host": "win", "category": "credentials", "severity": "high",
                        "title": "untrusted reader", "where": "browser store"}
        self.conf = patch("jarvis.service.scheduler.alert.load_conf", return_value={})
        self.conf.start()
        self.addCleanup(self.conf.stop)

    def test_observation_is_committed_before_response_can_see_it(self):
        def respond(store, conf, job, findings, **kwargs):
            # A different connection proves this is committed, not just staged.
            other = Store(self.path)
            try:
                self.assertEqual(incidents.overview(other.db)["counts"]["active"], 1)
            finally:
                other.close()
            return findings

        with patch("jarvis.service.scheduler.run_job", return_value=[self.finding]), \
             patch("jarvis.service.scheduler.defense.process", side_effect=respond) as response:
            findings, error = self.scheduler.run_once(self.store, "intrusion")
        response.assert_called_once()
        self.assertEqual(findings, [self.finding])
        self.assertEqual(error, "")

    def test_collection_failure_preserves_incident_and_marks_coverage_unavailable(self):
        self.store.record_observation("intrusion", [self.finding], observed_at=100)
        with patch("jarvis.service.scheduler.run_job", side_effect=OSError("bridge down")):
            _, error = self.scheduler.run_once(self.store, "intrusion")
        result = incidents.overview(self.store.db)
        self.assertIn("bridge down", error)
        self.assertEqual(result["sources"][0]["coverage"], "unavailable")
        self.assertEqual(result["counts"]["unobserved"], 1)

    def test_journal_failure_inhibits_both_response_layers(self):
        with patch("jarvis.service.scheduler.run_job", return_value=[self.finding]), \
             patch.object(self.store, "record_observation", side_effect=OSError("disk full")), \
             patch("jarvis.service.scheduler.remediation.process") as repair, \
             patch("jarvis.service.scheduler.defense.process") as response:
            findings, error = self.scheduler.run_once(self.store, "intrusion")
        repair.assert_not_called()
        response.assert_not_called()
        self.assertIn("journal failed", error)
        self.assertEqual(findings, [self.finding])
        self.assertIn("journal failed", self.store.get_snapshots()["intrusion"]["error"])

    def test_response_exception_preserves_evidence_and_reports_error(self):
        with patch("jarvis.service.scheduler.run_job", return_value=[self.finding]), \
             patch("jarvis.service.scheduler.defense.process", side_effect=RuntimeError("response fault")):
            findings, error = self.scheduler.run_once(self.store, "intrusion")
        self.assertEqual(findings, [self.finding])
        self.assertIn("response failed", error)
        self.assertEqual(incidents.overview(self.store.db)["total"], 1)
        self.assertEqual(self.store.get_snapshots()["intrusion"]["findings"], [self.finding])

    def test_partial_collection_is_passed_to_authorization(self):
        def collect(*args):
            collection.succeeded("one provider")
            collection.failed("another provider", "offline")
            return [self.finding]

        with patch("jarvis.service.scheduler.run_job", side_effect=collect), \
             patch("jarvis.service.scheduler.defense.process", return_value=[self.finding]) as response:
            self.scheduler.run_once(self.store, "intrusion")
        self.assertEqual(response.call_args.kwargs["coverage"], "partial")

    def test_failed_repair_verification_also_inhibits_automatic_defense(self):
        with patch("jarvis.service.scheduler.run_job", return_value=[self.finding]), \
             patch("jarvis.service.scheduler.remediation.process",
                   return_value=([self.finding], "verification incomplete")), \
             patch("jarvis.service.scheduler.defense.process", return_value=[self.finding]) as response:
            self.scheduler.run_once(self.store, "intrusion")
        self.assertEqual(response.call_args.kwargs["coverage"], "partial")


class DefenderHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "state.db")
        store = Store(self.path)
        store.record_observation("test", [{"severity": "high", "title": "test incident"}])
        store.close()
        self.handler = Handler.__new__(Handler)
        self.handler.db_path = self.path
        self.handler.headers = {"Host": "localhost:8787", **_apiauth.grant(self)}
        self.handler._send = Mock()

    def request(self, path):
        self.handler.path = path
        self.handler.do_GET()
        return self.handler._send.call_args.args

    def test_read_only_endpoint_returns_incident_memory(self):
        status, body = self.request("/api/defender?limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 1)

    def test_bad_host_cannot_read_evidence(self):
        self.handler.headers = {"Host": "attacker.example"}
        self.assertEqual(self.request("/api/defender")[0], 403)

    def test_invalid_query_and_unknown_id_have_explicit_errors(self):
        self.assertEqual(self.request("/api/defender?limit=no")[0], 400)
        self.assertEqual(self.request("/api/defender?id=unknown")[0], 404)

    def test_detail_includes_the_transition_evidence(self):
        _, body = self.request("/api/defender")
        key = json.loads(body)["incidents"][0]["id"]
        status, detail = self.request("/api/defender?id=" + key)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(detail)["transitions"][0]["reason"], "first observation")

    def test_veil_requires_pairing_and_keeps_only_dashboard_findings(self):
        from jarvis.core.veil import TOKEN_KEY
        store = Store(self.path)
        store.set_meta(TOKEN_KEY, "paired-secret")
        store.close()
        self.handler.path = "/api/veil/events"
        self.handler.headers = {"Host": "localhost:8787", "X-JARVIS-Veil-Token": "paired-secret"}
        self.handler._json_body = Mock(return_value={
            "top_origin": "https://shop.example/private-path",
            # A named recorder, so the report yields a finding; the private
            # path must still be reduced away before anything is stored.
            "egress_origins": ["https://in.hotjar.com/private"],
            "listeners": {"input": 1, "keydown": 1},
            "surfaces": {}, "transports": {"fetch": 1},
        })
        self.handler.do_POST()
        self.assertEqual(self.handler._send.call_args.args[0], 202)
        store = Store(self.path)
        try:
            finding = store.get_snapshots()["veil"]["findings"][0]
        finally:
            store.close()
        self.assertEqual(finding["where"], "https://shop.example")
        self.assertNotIn("private", json.dumps(finding))

    def test_veil_rejects_unpaired_call_before_storing_metadata(self):
        self.handler.path = "/api/veil/events"
        self.handler.headers = {"Host": "localhost:8787", "X-JARVIS-Veil-Token": "wrong"}
        self.handler._json_body = Mock(return_value={})
        self.handler.do_POST()
        self.assertEqual(self.handler._send.call_args.args[0], 403)
        store = Store(self.path)
        try:
            self.assertNotIn("veil", store.get_snapshots())
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()


class SchedulerLaneTests(unittest.TestCase):
    """A long audit must not be able to make JARVIS look dead."""

    def setUp(self):
        from jarvis.service import scheduler as mod
        self.mod = mod
        self.scheduler = Scheduler(":memory:", ("wsl", "win"))
        self.scheduler.cold_start_pending.clear()

    def test_liveness_jobs_have_their_own_lane(self):
        self.scheduler.next_run = {name: 0.0 for name in JOBS}
        with patch("jarvis.service.scheduler.time.time", return_value=1_000.0):
            self.assertIn(self.scheduler._due("fast"), self.mod.FAST)
            self.assertNotIn(self.scheduler._due("main"), self.mod.FAST)

    def test_forced_jobs_go_to_their_own_lane(self):
        self.scheduler.next_run = {name: 9e9 for name in JOBS}
        self.scheduler.force("secrets")
        self.scheduler.force("bridge")
        self.assertEqual(self.scheduler._due("fast"), "bridge")
        self.assertEqual(self.scheduler._due("main"), "secrets")
        self.assertIsNone(self.scheduler._due("fast"))

    def test_health_uses_required_jobs_that_all_run_in_the_fast_lane(self):
        # protection.health() judges these by freshness; any of them left in
        # the main queue could be starved by a multi-minute audit again.
        self.assertTrue({"scan", "bridge"} <= set(self.mod.FAST))

    def test_short_tier0_jobs_cannot_starve_behind_long_audits(self):
        # native and watchdogs judge Monitoring; queued behind the post-boot
        # sweep on 2026-09-23 they aged past their freshness budget.
        self.assertTrue({"native", "watchdogs"} <= set(self.mod.FAST))
        self.scheduler.next_run = {name: 9e9 for name in JOBS}
        self.scheduler.next_run["native"] = 0.0
        with patch("jarvis.service.scheduler.time.time", return_value=1_000.0):
            self.assertEqual(self.scheduler._due("fast"), "native")
            self.assertIsNone(self.scheduler._due("main"))

    def test_fast_lane_stays_fresh_while_the_main_lane_is_busy(self):
        import threading
        release = threading.Event()
        ran = []

        def run_once(store, name):
            if name == "secrets":
                release.wait(5)
            else:
                ran.append(name)
            return [], ""

        self.scheduler.next_run = {name: 9e9 for name in JOBS}
        self.scheduler.force("secrets")
        with patch.object(self.scheduler, "run_once", side_effect=run_once), \
             patch.object(self.mod, "Store"), \
             patch.object(self.mod.notifications, "deliver"):
            self.scheduler.start()
            # Monotonic: the wall clock here steps by ~9 s (WSL clock fight).
            deadline = time.monotonic() + 3
            while self.scheduler.current != "secrets" and time.monotonic() < deadline:
                time.sleep(0.01)
            self.scheduler.force("bridge")
            # Its own deadline: under load (load average 6, 2026-11-06) the first wait could
            # use most of a shared 3 s and leave the forced bridge no time to be picked up.
            deadline = time.monotonic() + 10
            while "bridge" not in ran and time.monotonic() < deadline:
                time.sleep(0.01)
            busy = self.scheduler.current
            release.set()
        self.assertEqual(busy, "secrets")
        self.assertIn("bridge", ran)


class ClientDisconnectTests(unittest.TestCase):
    def test_a_client_that_hung_up_is_not_an_error(self):
        handler = Handler.__new__(Handler)
        handler.wfile = Mock(write=Mock(side_effect=BrokenPipeError()))
        handler.send_response = handler.send_header = handler.end_headers = Mock()
        handler.close_connection = False
        handler._send(200, "{}")
        self.assertTrue(handler.close_connection)


class ForcedPriorityTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = Scheduler(":memory:", ("wsl", "win"))
        self.scheduler.cold_start_pending.clear()
        self.now = 100_000.0

    def test_run_all_does_not_starve_an_overdue_critical_collector(self):
        # 2026-09-23: "run all" queued every job in dict order and sysmon,
        # near the end, went stale behind two full sweeps.
        self.scheduler.next_run = {name: self.now + 60 for name in JOBS}
        self.scheduler.next_run["sysmon"] = self.now - 2 * JOBS["sysmon"][0]
        # Lateness is measured from evidence (LANE-FAIRNESS-AND-OUTAGE-RECORD.md):
        # everything else verified moments ago, sysmon's evidence is 3x old.
        self.scheduler.evidence_ts = {name: self.now - 10 for name in JOBS}
        self.scheduler.evidence_ts["sysmon"] = self.now - 3 * JOBS["sysmon"][0]
        for name in JOBS:
            self.scheduler.force(name)
        with patch("jarvis.service.scheduler.time.time", return_value=self.now), \
             patch("jarvis.core.governor.live_pressure", return_value=(False, "")):
            self.assertEqual(self.scheduler._due("main"), "sysmon")
            self.assertNotIn("sysmon", self.scheduler.forced)  # one run satisfies both

    def test_forced_job_runs_before_it_is_due(self):
        self.scheduler.next_run = {name: self.now + 3600 for name in JOBS}
        self.scheduler.force("secrets")
        with patch("jarvis.service.scheduler.time.time", return_value=self.now), \
             patch("jarvis.core.governor.live_pressure", return_value=(False, "")):
            self.assertEqual(self.scheduler._due("main"), "secrets")
            self.assertNotIn("secrets", self.scheduler.forced)

    def test_governed_jobs_are_not_deferred_when_the_host_is_idle(self):
        # `pressured` used to be overwritten with a job's score inside the
        # loop, so an idle host still deferred every later governed job.
        self.scheduler.next_run = {name: self.now + 3600 for name in JOBS}
        self.scheduler.next_run["evasion"] = self.now - 10
        self.scheduler.next_run["secrets"] = self.now - JOBS["secrets"][0]
        # The same lateness, stated as evidence age: evasion just due,
        # secrets a full cadence overdue.
        self.scheduler.evidence_ts = {name: self.now - 10 for name in JOBS}
        self.scheduler.evidence_ts["evasion"] = self.now - JOBS["evasion"][0] - 10
        self.scheduler.evidence_ts["secrets"] = self.now - 2 * JOBS["secrets"][0]
        with patch("jarvis.service.scheduler.time.time", return_value=self.now), \
             patch("jarvis.core.governor.live_pressure", return_value=(False, "")):
            self.assertEqual(self.scheduler._due("main"), "secrets")

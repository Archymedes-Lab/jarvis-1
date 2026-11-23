"""Collector Reliability Plane: freshness budgets, leases and recovery.

Freshness invariant under test:

    every mandatory collector either has evidence younger than its hard
    deadline, or JARVIS is actively attempting recovery and clearly reports
    degraded coverage. There is never STALE + nothing recovering it.
"""

import time
import unittest

from jarvis.service import reliability
from jarvis.service.reliability import (
    CollectorHealth,
    CollectorSpec,
    ReliabilityState,
)
from jarvis.service.schedule import JOBS
from jarvis.service.scheduler import Scheduler


class FreshnessBudgetTests(unittest.TestCase):
    def test_budgets_match_proposal(self):
        interval = 300.0
        self.assertEqual(reliability.classify(270, interval), "FRESH")
        self.assertEqual(reliability.classify(300, interval), "FRESH")
        self.assertEqual(reliability.classify(340, interval), "LATE")
        self.assertEqual(reliability.classify(390, interval), "LATE")
        self.assertEqual(reliability.classify(391, interval), "DEGRADED")
        self.assertEqual(reliability.classify(600, interval), "DEGRADED")
        self.assertEqual(reliability.classify(601, interval), "STALE")
        self.assertEqual(reliability.classify(650, interval), "STALE")

    def test_missing_evidence_is_stale_never_clean(self):
        self.assertEqual(reliability.classify(-1, 300), "STALE")
        self.assertEqual(reliability.classify(None, 300), "STALE")

    def test_retry_is_bounded(self):
        self.assertEqual(reliability.retry_delay(0), 2.0)
        self.assertEqual(reliability.retry_delay(1), 5.0)
        self.assertEqual(reliability.retry_delay(2), 15.0)
        self.assertIsNone(reliability.retry_delay(3))
        self.assertIsNone(reliability.retry_delay(99))


class PriorityTests(unittest.TestCase):
    def test_approaching_stale_rises_to_top(self):
        spec = CollectorSpec(name="persistence", expected_interval=300,
                             criticality="high")
        fresh = reliability.priority(spec, 10)
        late = reliability.priority(spec, 340)
        stale = reliability.priority(spec, 650)
        self.assertLess(fresh, late)
        self.assertLess(late, stale)

    def test_criticality_weights_pressure(self):
        low = CollectorSpec(name="a", expected_interval=300, criticality="low")
        high = CollectorSpec(name="b", expected_interval=300, criticality="high")
        self.assertLess(reliability.priority(low, 100),
                        reliability.priority(high, 100))

    def test_specs_cover_every_job(self):
        specs = reliability.build_specs(JOBS)
        self.assertEqual(set(specs), set(JOBS))
        for spec in specs.values():
            self.assertGreater(spec.expected_interval, 0)
            self.assertGreater(spec.execution_timeout, 0)


class LeaseTests(unittest.TestCase):
    def test_lease_expiry_detects_dead_worker(self):
        health = CollectorHealth(name="persistence")
        lease = reliability.acquire_lease(health, "worker1", 45.0, now=1000.0)
        self.assertFalse(lease.expired(now=1000.0 + 44.0))
        self.assertTrue(lease.expired(now=1000.0 + 45.0))
        states = {"persistence": health}
        self.assertEqual(reliability.expired_leases(states, now=1000.0), [])
        self.assertEqual(
            reliability.expired_leases(states, now=2000.0), ["persistence"])

    def test_late_orphan_cannot_overwrite_newer_run(self):
        health = CollectorHealth(name="persistence")
        old = reliability.acquire_lease(health, "w1", 45.0, now=1000.0)
        # A newer run takes over; the orphan's late completion is ignored.
        new = reliability.acquire_lease(health, "w2", 45.0, now=1100.0)
        reliability.release_lease(health, old, success=True, now=1200.0)
        self.assertIs(health.active_lease, new)
        self.assertIsNone(health.last_success)
        reliability.release_lease(health, new, success=True, now=1200.0)
        self.assertIsNone(health.active_lease)
        self.assertEqual(health.last_success, 1200.0)
        self.assertEqual(health.consecutive_failures, 0)

    def test_last_known_good_survives_failed_rerun(self):
        state = ReliabilityState({
            "persistence": CollectorSpec(name="persistence",
                                         expected_interval=300)})
        verified_at = 1000.0
        entry = state.status("persistence", verified_at, "", now=1000.0)
        self.assertEqual(entry["freshness"], "FRESH")
        self.assertEqual(entry["last_verified"], verified_at)
        # The rerun fails: verified state stays, current coverage degrades.
        health = state.health["persistence"]
        health.consecutive_failures = 1
        entry = state.status("persistence", verified_at, "boom",
                             now=1000.0 + 650.0)
        self.assertEqual(entry["last_verified"], verified_at)
        self.assertEqual(entry["current_coverage"], "unavailable")


class InvariantTests(unittest.TestCase):
    def setUp(self):
        self.state = ReliabilityState({
            "scan": CollectorSpec(name="scan", expected_interval=60),
            "secrets": CollectorSpec(name="secrets", expected_interval=3600),
        })

    def test_stale_without_recovery_is_a_violation(self):
        snaps = {"scan": {"ts": 1000.0 - 500.0, "error": ""},
                 "secrets": {"ts": 999.0, "error": ""}}
        violations = self.state.invariant_violations(snaps, now=1000.0)
        self.assertEqual([v["collector"] for v in violations], ["scan"])

    def test_stale_with_active_recovery_is_supervised_not_silent(self):
        snaps = {"scan": {"ts": 1000.0 - 500.0, "error": ""},
                 "secrets": {"ts": 999.0, "error": ""}}
        self.state.health["scan"].recovery_state = "queued"
        self.assertEqual(
            self.state.invariant_violations(snaps, now=1000.0), [])

    def test_fresh_collectors_have_no_violations(self):
        snaps = {"scan": {"ts": 999.0, "error": ""},
                 "secrets": {"ts": 999.0, "error": ""}}
        self.assertEqual(
            self.state.invariant_violations(snaps, now=1000.0), [])

    def test_dependency_failures_collapse_to_one_root(self):
        result = self.state.dependency_root_cause(
            ["firewall", "control", "asep"])
        self.assertEqual(result["root"], "windows-bridge")
        self.assertIn("firewall", result["affected"])


class SchedulerIntegrationTests(unittest.TestCase):
    def test_native_collector_uses_process_boundary_and_preserves_status(self):
        import subprocess
        from unittest.mock import patch

        completed = subprocess.CompletedProcess(
            [], 0, stdout='{"findings":[{"title":"x"}],"error":"sensor: partial","status":"partial"}',
            stderr="")
        scheduler = Scheduler("/tmp/test-state.db", ("wsl", "win"))
        with patch("jarvis.service.scheduler.subprocess.run", return_value=completed) as run:
            findings, error, status = scheduler._collect("native", 12)
        self.assertEqual(findings[0]["title"], "x")
        self.assertEqual((error, status), ("sensor: partial", "partial"))
        command = run.call_args.args[0]
        self.assertEqual(command[2:4], ["jarvis.service.collector_worker", "native"])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_native_collector_timeout_is_unavailable_not_success(self):
        import subprocess
        from unittest.mock import patch

        scheduler = Scheduler("/tmp/test-state.db", ("win",))
        with patch("jarvis.service.scheduler.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(["worker"], 7)):
            findings, error, status = scheduler._collect("native", 7)
        self.assertEqual(findings, [])
        self.assertEqual(status, "unavailable")
        self.assertIn("worker terminated", error)

    def test_late_collector_is_queued_before_it_goes_stale(self):
        scheduler = Scheduler(":memory:", ("wsl",))
        # Persistence last verified 340s ago on a 300s cadence: LATE.
        snaps = {"hidden": {"ts": time.time() - 340.0, "error": "",
                            "findings": []}}
        queued = scheduler.supervise_once(snaps)
        self.assertIn("hidden", queued)
        self.assertEqual(
            scheduler.reliability.health["hidden"].recovery_state, "queued")

    def test_failed_run_enters_retry_and_success_clears_it(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from jarvis.core.store import Store

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / "state.db")
        store = Store(path)
        self.addCleanup(store.close)
        scheduler = Scheduler(path, ("wsl",))
        with patch("jarvis.service.scheduler.run_job",
                   side_effect=OSError("bridge down")), \
             patch("jarvis.service.scheduler.alert.load_conf",
                   return_value={}), \
             patch("jarvis.service.scheduler.remediation.process",
                   side_effect=RuntimeError("unreached")), \
             patch("jarvis.service.scheduler.defense.process",
                   side_effect=RuntimeError("unreached")):
            _, err = scheduler.run_once(store, "scan")
        self.assertIn("bridge down", err)
        health = scheduler.reliability.health["scan"]
        self.assertEqual(health.consecutive_failures, 1)
        self.assertEqual(health.recovery_state, "retrying")
        self.assertIsNone(health.active_lease)

    def test_reliability_status_never_raises(self):
        scheduler = Scheduler(":memory:", ("wsl",))
        summary = scheduler.reliability_status(snapshots={})["summary"]
        self.assertIn("violations", summary)
        self.assertIn("stale_collectors", summary)


if __name__ == "__main__":
    unittest.main()


class JobCostTests(unittest.TestCase):
    """The scheduler records what each run cost (CPU, memory growth) so the
    Monitoring view can rank collectors by real cost, not wall time."""

    def test_run_once_records_cpu_and_memory_growth(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            sched = Scheduler(tmp + "/s.db", ("wsl",))

            def busy(name, hosts, db_path):
                total = 0
                for i in range(300000):
                    total += i * i
                return [{"category": "x", "severity": "ok", "title": "t", "detail": "", "where": "", "host": "wsl"}]

            from jarvis.core.store import Store
            store = Store(tmp + "/s.db")
            try:
                with mock.patch("jarvis.service.scheduler.run_job", side_effect=busy), \
                     mock.patch("jarvis.service.scheduler.alert.load_conf", return_value={}), \
                     mock.patch("jarvis.service.scheduler.remediation.process", side_effect=lambda s, c, n, f, e, v: (f, e)), \
                     mock.patch("jarvis.service.scheduler.defense.process", side_effect=lambda s, c, n, f, coverage: f):
                    sched.run_once(store, "hidden")
            finally:
                store.close()
            cost = sched.job_cost["hidden"]
            self.assertGreater(cost["cpu_s"], 0.0)
            self.assertGreaterEqual(cost["rss_growth_kib"], 0)
            from jarvis.web.server import _performance_state
            perf = _performance_state([{"name": "hidden", "label": "Hidden", "interval": 300, "duration": 1.0}], sched)
            self.assertIn("cpu_pct", perf["top"][0])
            self.assertIsNotNone(perf["collector_cpu_pct"])

    def test_isolated_child_reports_its_own_cost(self):
        import subprocess
        from unittest import mock
        out = '{"findings":[],"error":"","status":"complete","cpu_s":1.25,"max_rss_kib":51200}'
        done = subprocess.CompletedProcess(["w"], 0, stdout=out, stderr="")
        from jarvis.service import scheduler as sched_mod
        with mock.patch("jarvis.service.scheduler.subprocess.run", return_value=done):
            sched_mod._isolated_job("native", ("win",), "/tmp/x.db", 5)
        self.assertEqual(sched_mod._CHILD_COST.value, (1.25, 51200))

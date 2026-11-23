"""A transient collector failure keeps a still-fresh good result, retries
soon, and never hides new evidence or outlives the freshness budget."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core import incidents
from jarvis.core.store import Store
from jarvis.service import scheduler as sched_mod
from jarvis.service.scheduler import Scheduler

GOOD = [{"category": "posture", "severity": "medium", "title": "old finding",
         "detail": "d", "where": "w", "host": "win"}]


class TransientHoldTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "j.db")
        self.sched = Scheduler(self.db, ("win",))
        self.store = Store(self.db)
        self.addCleanup(self.store.close)
        self.store.save_snapshot("posture", GOOD, 1.0, "")
        for target, fake in (
                ("remediation.process", lambda store, conf, name, f, err, verify: (f, err)),
                ("defense.process", lambda store, conf, name, f, coverage: f),
                ("alert.load_conf", lambda: {})):
            patcher = mock.patch(f"jarvis.service.scheduler.{target}", side_effect=fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_failed(self, findings=(), err="windows: PowerShell returned no payload"):
        with mock.patch.object(self.sched, "_collect",
                               return_value=(list(findings), err, "unavailable")):
            return self.sched.run_once(self.store, "posture")

    def snap(self):
        return self.store.get_snapshots()["posture"]

    def test_transient_failure_keeps_good_result_and_retries_soon(self):
        findings, err = self.run_failed()
        self.assertEqual(self.snap()["error"], "")
        self.assertEqual([f["title"] for f in self.snap()["findings"]], ["old finding"])
        self.assertEqual((findings, err), (GOOD, ""))
        self.assertIn("posture", self.sched.retry_soon)
        self.assertIn("PowerShell", self.store.get_meta("collector_retry_posture", ""))

    def test_new_finding_in_failed_run_is_recorded_not_hidden(self):
        new = dict(GOOD[0], title="new high", severity="high")
        self.run_failed([new])
        self.assertTrue(self.snap()["error"])
        self.assertNotIn("posture", self.sched.retry_soon)

    def test_stale_good_result_is_not_held(self):
        self.store.db.execute("UPDATE snapshots SET ts=? WHERE kind='posture'",
                              (time.time() - 10 * 86400,))
        self.store.db.commit()
        self.run_failed()
        self.assertTrue(self.snap()["error"])

    def test_repeated_failures_are_recorded_after_the_hold_limit(self):
        for _ in range(sched_mod.HOLD_MAX):
            self.run_failed()
            self.assertEqual(self.snap()["error"], "")
        self.run_failed()
        self.assertTrue(self.snap()["error"])

    def test_success_clears_the_retry_note(self):
        self.run_failed()
        with mock.patch.object(self.sched, "_collect", return_value=(GOOD, "", "complete")):
            self.sched.run_once(self.store, "posture")
        self.assertEqual(self.store.get_meta("collector_retry_posture", ""), "")


class CoverageAboutOtherCollectorsTests(unittest.TestCase):
    def test_reporting_another_collector_failure_is_not_a_blind_spot(self):
        about = {"category": "collectors", "severity": "high", "about_collector": "hidden"}
        own = {"category": "visibility", "severity": "medium"}
        self.assertEqual(incidents.coverage_status([about]), "complete")
        self.assertEqual(incidents.coverage_status([about, own]), "partial")


if __name__ == "__main__":
    unittest.main()

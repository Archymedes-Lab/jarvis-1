"""Cursor stall episodes and pointer-setting explanations (inputwatch)."""

import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host.inputwatch import analysis
from jarvis.core.store import Store


class StallMinuteTests(unittest.TestCase):
    def test_differences_cumulative_beats_into_intervals(self):
        rows = [(0, 10, 1000, 250), (60, 10, 1500, 250), (120, 14, 2000, 400)]
        self.assertEqual(analysis.stall_minutes(rows), [
            {"ts": 120, "slow": 4, "events": 500, "peak_rose_to": 400}])

    def test_session_reset_is_not_read_as_a_stall_or_negative(self):
        rows = [(0, 50, 9000, 900), (60, 0, 100, 0), (120, 1, 200, 60)]
        self.assertEqual(analysis.stall_minutes(rows), [])

    def test_gap_spanning_downtime_is_not_attributed_to_one_interval(self):
        rows = [(0, 0, 100, 0), (3600, 40, 5000, 800)]
        self.assertEqual(analysis.stall_minutes(rows), [])

    def test_below_threshold_is_not_a_stall(self):
        rows = [(0, 0, 100, 0), (60, analysis.STALL_EVENTS - 1, 900, 80)]
        self.assertEqual(analysis.stall_minutes(rows), [])


class StallFindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "jarvis.db"))
        self.addCleanup(self.store.close)

    def _beats(self, stalls, base=1_000_000):
        over, n = 0, 0
        for i in range(60):
            n += 500
            if i in stalls:
                over += 5
            self.store.db.execute(
                "INSERT INTO input_beats (ts, lat_over50, lat_samples, lat_max_ms) "
                "VALUES (?,?,?,?)", (base + 60 * i, over, n, 120))
        self.store.db.commit()
        return base + 60 * 60

    def test_isolated_hiccups_are_reported_without_severity(self):
        t = self._beats({10, 40})
        with mock.patch.object(analysis, "now", return_value=t):
            out = analysis._stall_findings(self.store)
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertIn("2 heartbeat interval", out[0]["title"])

    def test_repeated_stalls_are_low_and_carry_the_blind_spot(self):
        t = self._beats({5, 15, 25, 35})
        with mock.patch.object(analysis, "now", return_value=t):
            out = analysis._stall_findings(self.store)
        self.assertEqual(out[0]["severity"], "low")
        self.assertIn("installed earlier", out[0]["detail"])
        self.assertIn("not a verdict", out[0]["detail"])

    def test_no_stalls_adds_nothing(self):
        t = self._beats(set())
        with mock.patch.object(analysis, "now", return_value=t):
            self.assertEqual(analysis._stall_findings(self.store), [])


class PointerSettingTests(unittest.TestCase):
    def test_defaults_are_ok(self):
        out = analysis._pointer_findings({"sens": "10", "speed": "1", "trails": "0"})
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertIn("defaults", out[0]["title"])

    def test_changes_are_explanations_never_problems(self):
        out = analysis._pointer_findings({"sens": "4", "speed": "0", "trails": "7"})
        self.assertEqual(out[0]["severity"], "ok")
        for text in ("pointer speed is 4", "enhance pointer precision is 0",
                     "pointer trails is 7"):
            self.assertIn(text, out[0]["detail"])

    def test_unreadable_registry_is_silent_not_default(self):
        self.assertEqual(analysis._pointer_findings(None), [])
        self.assertEqual(analysis._pointer_findings({"t": None}), [])


if __name__ == "__main__":
    unittest.main()

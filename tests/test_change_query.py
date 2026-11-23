"""End-to-end read-only change query over committed event-log batches."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jarvis.core import event
from jarvis.core.change_query import summarize
from jarvis.core.eventlog import EventLog


class ChangeQueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "eventlog"
        self.now = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)

    def _event(self, record, offset, category="process", action="start"):
        return event.make(
            host="host", sensor="sensor", channel="sysmon",
            generation="gen", record=record, source="sysmon",
            source_event=1, time=(self.now + timedelta(seconds=offset)).isoformat(),
            category=category, action=action,
            process={"pid": 7, "guid": "{instance}",
                     "cmdline": "private command line"},
            raw="<secret>private evidence</secret>")

    def _append(self, events, *, status="complete", gap=None, at=None):
        with EventLog(self.root, writer=True) as log:
            log.append(events, {"sensor": "sensor", "channel": "sysmon",
                                "sequence": 1, "status": status, "gap": gap})
        # The cursor is stamped at actual commit; set a deterministic fixture
        # time in the committed cursor line without changing the events.
        path = self.root / "active.jsonl"
        lines = path.read_text().splitlines()
        last = json.loads(lines[-1])
        last["cursor"]["at"] = self.now.timestamp() if at is None else at
        lines[-1] = json.dumps(last)
        path.write_text("\n".join(lines) + "\n")

    def test_counts_committed_changes_without_private_fields(self):
        self._append([self._event(1, -8),
                      self._event(2, -2, "network", "connect"),
                      self._event(3, -30)])
        with EventLog(self.root) as log:
            result = summarize(log, now=self.now, seconds=10)
        self.assertEqual(result["observed_changes"],
                         {"network:connect": 1, "process:start": 1})
        self.assertEqual((result["first_matched_seq"],
                          result["last_matched_seq"]), (1, 2))
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual(result["coverage"], "partial")

    def test_sensor_read_delay_is_reported_only_when_measured(self):
        measured = self._event(1, -8)
        measured["received"] = (self.now - timedelta(seconds=6)).isoformat()
        measured["attrs"]["_received_basis"] = "sensor_read"
        legacy = self._event(2, -5)
        legacy["received"] = legacy["time"]
        legacy["attrs"]["_received_basis"] = "event_time_fallback"
        self._append([measured, legacy])
        with EventLog(self.root) as log:
            result = summarize(log, now=self.now)
        self.assertEqual(result["sensor_read_receipts"], 1)
        self.assertEqual(result["max_sensor_read_delay_seconds"], 2.0)

    def test_interrupted_uncommitted_tail_is_not_counted(self):
        self._append([self._event(1, -2)])
        with (self.root / "active.jsonl").open("a") as fh:
            fh.write(json.dumps(dict(self._event(2, -1), seq=2)) + "\n")
        with EventLog(self.root) as log:
            result = summarize(log, now=self.now)
        self.assertEqual(result["observed_total"], 1)
        self.assertEqual(result["last_committed_seq"], 1)

    def test_stale_or_failed_cursor_never_claims_complete_coverage(self):
        self._append([self._event(1, -2)], status="unavailable",
                     gap="record range lost", at=self.now.timestamp() - 600)
        with EventLog(self.root) as log:
            result = summarize(log, now=self.now)
        self.assertFalse(result["cursors"][0]["recent_commit"])
        self.assertTrue(any("stale or degraded" in note for note in
                            result["limitations"]))

    def test_bounded_replay_and_clock_anomalies_stay_explicit(self):
        self._append([self._event(1, -2), self._event(2, 60)])
        with EventLog(self.root) as log:
            result = summarize(log, now=self.now, scan_limit=1)
        self.assertEqual(result["observed_total"], 0)
        self.assertEqual(result["future_timestamps"], 1)
        self.assertIn("bounded scan may omit events in the requested time window",
                      result["limitations"])

    def test_invalid_window_and_scan_budget_rejected(self):
        with EventLog(self.root) as log:
            for seconds, limit in ((0, 1), (3601, 1), (10, 0), (10, 20001)):
                with self.assertRaises(ValueError):
                    summarize(log, now=self.now, seconds=seconds,
                              scan_limit=limit)


if __name__ == "__main__":
    unittest.main()

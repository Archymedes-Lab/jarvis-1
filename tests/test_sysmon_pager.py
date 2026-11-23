"""Sysmon fallback paging (2026-10-11).

A capped fallback query used to keep its cursor and fail on every run; the
Windows reviver re-forced it about every 30 s, and it held the only main
worker for hours while other collectors went stale. The query now reads
oldest-first and the cursor advances to the end of the page actually read.
"""
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from jarvis.collectors.telemetry import sysmon
from jarvis.core.store import Store

# Never ask the live Windows host for Sysmon's service state from a unit test;
# an empty answer judges nothing (sysmon._service_findings).
_status_patch = None


def setUpModule():
    global _status_patch
    from unittest import mock as _mock

    from jarvis.collectors.telemetry import sysmon as _sysmon
    _status_patch = _mock.patch.object(_sysmon, "status", return_value={})
    _status_patch.start()


def tearDownModule():
    _status_patch.stop()

NOW = 1_791_700_000.0
LAST = NOW - 3 * 3600          # cursor three hours behind


class SysmonPagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "jarvis.db"))
        self.store.set_meta("sysmon_thread_rules", sysmon.THREAD_RULES)
        self.store.set_meta("sysmon_last_run", int(LAST))
        self.store.commit()
        self.calls = []

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def run_audit(self, data):
        fetch = mock.MagicMock(return_value=data)
        with mock.patch.object(sysmon, "_native", return_value=None), \
             mock.patch.object(sysmon, "_query_blocked", return_value=None), \
             mock.patch.object(sysmon, "_ps", return_value={}), \
             mock.patch.object(sysmon, "status", return_value={"installed": True,
                                                               "readable": True}), \
             mock.patch.object(sysmon, "now", return_value=NOW), \
             mock.patch.object(sysmon, "_fetch", fetch), \
             mock.patch.object(sysmon.collection, "failed",
                               side_effect=lambda s, r: self.calls.append(("failed", r))), \
             mock.patch.object(sysmon.collection, "succeeded",
                               side_effect=lambda s: self.calls.append(("succeeded",))):
            findings = sysmon.audit(self.store, incremental=True)
        return findings, fetch

    def cursor(self):
        return float(self.store.get_meta("sysmon_last_run", 0) or 0)

    @staticmethod
    def page(**extra):
        return dict({"events": [], "complete": False, "rareComplete": True,
                     "readFailed": False, "capped": True,
                     "rareLast": None, "bulkLast": None}, **extra)

    def test_capped_page_advances_cursor_to_end_of_page(self):
        end = LAST + 1800
        findings, fetch = self.run_audit(self.page(
            bulkLast=datetime.fromtimestamp(end, timezone.utc).isoformat()))
        self.assertAlmostEqual(self.cursor(), end, delta=1)
        self.assertIn(("succeeded",), self.calls)
        self.assertNotIn("failed", [c[0] for c in self.calls])
        titles = {(f["severity"], f["title"]) for f in findings}
        self.assertIn(("medium", "Sysmon is catching up a backlog"), titles)
        self.assertNotIn(("high", "Sysmon event coverage is partial"), titles)
        # The read started at the cursor (with one minute of overlap), not at
        # a rounded number of minutes before now.
        self.assertEqual(fetch.call_args.kwargs["since_epoch"], int(LAST) - 60)

    def test_both_streams_capped_cursor_stops_at_the_earlier_page_end(self):
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()  # noqa: E731
        self.run_audit(self.page(rareLast=iso(LAST + 600), bulkLast=iso(LAST + 1800)))
        self.assertAlmostEqual(self.cursor(), LAST + 600, delta=1)

    def test_complete_run_moves_cursor_to_query_start(self):
        self.run_audit({"events": [], "complete": True, "rareComplete": True,
                        "readFailed": False, "capped": False})
        self.assertAlmostEqual(self.cursor(), NOW, delta=1)

    def test_read_failure_retains_cursor_and_reports_failure(self):
        findings, _ = self.run_audit({"events": [], "readFailed": True,
                                      "complete": False})
        self.assertEqual(self.cursor(), int(LAST))
        self.assertIn("failed", [c[0] for c in self.calls])
        self.assertIn("Sysmon event query failed", [f["title"] for f in findings])

    def test_capped_without_page_end_cannot_skip_events(self):
        # An interrupted or malformed page (no end time) must not move the
        # cursor: unread events would be skipped silently.
        findings, _ = self.run_audit(self.page(bulkLast="not-a-time"))
        self.assertEqual(self.cursor(), int(LAST))
        self.assertIn("failed", [c[0] for c in self.calls])
        self.assertIn("Sysmon event coverage is partial", [f["title"] for f in findings])

    def test_page_that_does_not_move_forward_is_not_progress(self):
        self.run_audit(self.page(bulkLast=datetime.fromtimestamp(
            LAST - 30, timezone.utc).isoformat()))
        self.assertEqual(self.cursor(), int(LAST))
        self.assertIn("failed", [c[0] for c in self.calls])

    def test_query_script_reads_oldest_first_and_trims_the_probe_event(self):
        captured = {}
        with mock.patch.object(sysmon, "_ps",
                               side_effect=lambda s, timeout=0: captured.setdefault("s", s) and {}):
            sysmon._fetch(since_epoch=LAST)
        script = captured["s"]
        self.assertIn("-Oldest", script)
        self.assertIn("Select-Object -First 1200", script)
        self.assertIn(f"FromUnixTimeMilliseconds({int(LAST * 1000)})", script)

    def test_cursor_written_by_a_page_is_readable_by_the_next_run(self):
        # Regression 2026-10-14: the page cursor was stored as a float and the
        # next run's int() read raised ValueError, reporting sysmon unavailable.
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()  # noqa: E731
        self.run_audit(self.page(bulkLast=iso(LAST + 1800.891129)))
        stored = self.store.get_meta("sysmon_last_run")
        self.assertEqual(int(stored), int(LAST + 1800))
        self.run_audit(self.page(bulkLast=iso(LAST + 3600)))
        self.assertEqual(self.cursor(), int(LAST + 3600))

    def test_legacy_float_cursor_does_not_crash_the_audit(self):
        self.store.set_meta("sysmon_last_run", "1791970195.891129")
        self.store.commit()
        findings, _ = self.run_audit({"events": [], "complete": True, "rareComplete": True,
                                      "readFailed": False, "capped": False})
        self.assertNotIn("failed", [c[0] for c in self.calls])
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()


class FakeLog:
    """Event log with records 1..last_seq, every one a Sysmon event."""

    def __init__(self, last_seq, pruned=()):
        self.last_seq = last_seq
        self.pruned = list(pruned)
        self.cursors = {"s": {"channel": sysmon.CHANNEL, "at": NOW}}
        self.reads = []

    def iter_events(self, after=0, until=None, since=None):
        self.reads.append((after, until, since))
        for seq in range(after + 1, (until or self.last_seq) + 1):
            yield {"seq": seq, "channel": sysmon.CHANNEL, "source_event": 1,
                   "time": "2026-10-11T10:00:00", "data": {}}

    def missing(self):
        return self.pruned

    def close(self):
        pass


class NativePageTests(unittest.TestCase):
    """The native read loaded 1,877,073 records at once (2026-10-11): the daemon
    grew ~500 MB every 2.5 s, stalled at its MemoryHigh, and was restarted in a
    loop. A run now reads at most one page and advances the cursor to its end."""

    def native(self, log, offset, page=20, since=None):
        store = mock.Mock()
        store.get_meta.side_effect = lambda k, d=0: {"sysmon_eventlog_seq": offset}.get(k, d)
        with mock.patch.object(sysmon, "EventLog", return_value=log), \
             mock.patch.object(sysmon, "now", return_value=NOW), \
             mock.patch.object(sysmon, "rows_from_events", side_effect=lambda ev: list(ev)):
            return sysmon._native(store, since=since, page=page)

    def test_backlog_is_read_one_page_at_a_time(self):
        log = FakeLog(last_seq=100)
        data, through = self.native(log, offset=10)
        self.assertEqual(through, 30)
        self.assertEqual(len(data["events"]), 20)
        self.assertEqual(data["backlog"], 70)
        self.assertTrue(data["complete"])
        self.assertEqual(log.reads, [(10, 30, None)])

    def test_small_gap_reads_everything_without_a_bound(self):
        data, through = self.native(FakeLog(last_seq=25), offset=10)
        self.assertEqual((through, data["backlog"], len(data["events"])), (25, 0, 15))

    def test_successive_pages_cover_every_record_exactly_once(self):
        log, offset, seen = FakeLog(last_seq=95), 0, []
        while True:
            data, through = self.native(log, offset=offset)
            seen += [e["seq"] for e in data["events"]]
            offset = through
            if not data["backlog"]:
                break
        self.assertEqual(seen, list(range(1, 96)))

    def test_pruned_range_beyond_the_page_does_not_mark_this_page_lost(self):
        data, _ = self.native(FakeLog(last_seq=100, pruned=[(60, 70)]), offset=10)
        self.assertTrue(data["complete"])
        lost, _ = self.native(FakeLog(last_seq=100, pruned=[(15, 18)]), offset=10)
        self.assertFalse(lost["complete"])

    def test_explicit_time_window_is_not_paged(self):
        log = FakeLog(last_seq=100)
        self.native(log, offset=10, since=NOW - 3600)
        self.assertIsNone(log.reads[0][1])

    def test_backlog_run_reports_catching_up_and_scheduler_reruns_it(self):
        from jarvis.service.scheduler import reports_backlog
        self.assertTrue(reports_backlog([{"title": "Sysmon is catching up a backlog"}]))
        self.assertFalse(reports_backlog([{"title": "Sysmon delivered 5 events"}]))
        self.assertFalse(reports_backlog(None))
        self.assertFalse(reports_backlog(["not a dict"]))


class NativeBacklogAuditTests(SysmonPagerTests):
    def test_backlog_page_moves_cursor_and_emits_the_rerun_signal(self):
        from jarvis.service.scheduler import reports_backlog
        self.store.set_meta("sysmon_eventlog_seq", 1000)
        self.store.commit()
        page = ({"events": [], "complete": True, "rareComplete": True,
                 "source": "native sensor", "pruned": False, "backlog": 5000}, 21000)
        with mock.patch.object(sysmon, "_native", return_value=page), \
             mock.patch.object(sysmon, "_ps", return_value={}), \
             mock.patch.object(sysmon, "status", return_value={"installed": True,
                                                               "readable": True}), \
             mock.patch.object(sysmon, "now", return_value=NOW):
            findings = sysmon.audit(self.store, incremental=True)
        self.assertEqual(int(self.store.get_meta("sysmon_eventlog_seq", 0)), 21000)
        hit = [f for f in findings if f["title"] == "Sysmon is catching up a backlog"]
        self.assertEqual([f["severity"] for f in hit], ["medium"])
        self.assertIn("5000", hit[0]["detail"])
        self.assertTrue(reports_backlog(findings))

"""A momentary writer-lock contention is not blindness.

The event log allows one writer; a CLI rebuild or a manual ingest can hold
the lock for a second. The collector must retry before it reports a gap —
but a genuinely wedged writer must still be reported, not retried forever.
"""

import tempfile
import unittest
from unittest import mock

from jarvis.collectors.telemetry import native
from jarvis.core.eventlog import EventLog, LogError
from jarvis.core.store import Store


class NativeContentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name + "/t.db")
        sleeper = mock.patch.object(native.time, "sleep")
        self.sleep_mock = sleeper.start()
        self.addCleanup(sleeper.stop)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_contention_is_retried_then_succeeds(self):
        real_open = EventLog

        def flaky(root, writer=False):
            if flaky.calls == 0:
                flaky.calls += 1
                raise LogError("another process is writing the event log")
            return real_open(self.logdir, writer=writer)

        flaky.calls = 0
        with tempfile.TemporaryDirectory() as logdir, \
             mock.patch.object(native, "EventLog", flaky):
            self.logdir = logdir
            log, busy = native._open_writer(logdir)
        self.assertIsNotNone(log)
        self.assertIsNone(busy)
        log.close()

    def test_wedged_writer_is_reported_after_the_retries(self):
        with mock.patch.object(native, "EventLog",
                               mock.Mock(side_effect=LogError("locked"))):
            log, busy = native._open_writer(None)
        self.assertIsNone(log)
        self.assertIsNotNone(busy)
        self.assertEqual(busy["severity"], "medium")
        self.assertIn("retries", busy["detail"])
        self.assertEqual(self.sleep_mock.call_count, native.LOCK_RETRIES)

    def test_audit_reports_busy_without_raising(self):
        # Hermetic: without this the real spool decides, and a machine without
        # the sensor stops at "not installed" before the writer is reached.
        from jarvis.platform.native import ingest
        with mock.patch.object(ingest, "preflight", return_value={"installed": True}), \
                mock.patch.object(native.mounts, "under_windows_drive", return_value=False), \
                mock.patch.object(native, "_open_writer", return_value=(None, {
                "category": "visibility", "severity": "medium",
                "title": "Event log is busy or unavailable",
                "detail": "x", "where": "y"})):
            findings = native.audit(self.store, hosts=("win",))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Event log is busy or unavailable")


if __name__ == "__main__":
    unittest.main()

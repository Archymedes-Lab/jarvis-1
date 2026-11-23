import json
import os
import tempfile
import time
import unittest

from jarvis.core.store import Store
from jarvis.service import avguard as pr
from jarvis.service.scheduler import Scheduler


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        pr._state.update(at=0.0, value=None, scan_at=0.0)

    def test_summary_levels_are_honest(self):
        self.assertEqual(pr.summarize({"rt": True, "av": True, "age": 1})["level"], "on")
        self.assertEqual(pr.summarize({"rt": False, "av": True, "age": 1})["level"], "off")
        self.assertEqual(pr.summarize({"rt": True, "av": True, "age": 30})["level"], "stale")
        unknown = pr.summarize(None)
        self.assertFalse(unknown["available"])
        self.assertIn("cannot say", unknown["summary"])

    def test_status_reads_only_and_is_cached(self):
        calls = []

        class R:
            returncode, stdout = 0, '{"rt":true,"av":true,"age":0,"scan":""}'

        def run(script, timeout):
            calls.append(script)
            return R()

        self.assertEqual(pr.status(1000, run, "win32")["level"], "on")
        pr.status(1010, run, "win32")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("Start-MpScan", calls[0])

    def test_unreadable_defender_is_unknown_not_safe(self):
        def boom(script, timeout):
            raise OSError("no powershell")

        self.assertFalse(pr.status(1, boom, "win32")["available"])
        self.assertFalse(pr.status(1, None, "linux")["available"])

    def test_scan_has_a_fixed_command_and_a_cooldown(self):
        started = []
        self.assertTrue(pr.scan(1000, lambda: started.append(1), "win32")["started"])
        self.assertFalse(pr.scan(1100, lambda: started.append(1), "win32")["started"])
        self.assertEqual(len(started), 1)
        self.assertTrue(pr.scan(1000 + pr.SCAN_COOLDOWN_S + 1, lambda: started.append(1), "win32")["started"])
        self.assertEqual(len(started), 2)
        self.assertIn("not mean the computer is clean", pr.scan(9_999_999, lambda: None, "win32")["message"])
        self.assertFalse(pr.scan(1, lambda: None, "linux")["started"])


class PauseTests(unittest.TestCase):
    def make(self):
        return Scheduler(os.path.join(tempfile.mkdtemp(), "t.db"), {"win"})

    def test_pause_is_bounded_and_ends_by_itself(self):
        s = self.make()
        now = time.time()
        self.assertFalse(s.is_paused(now))
        until = s.pause(10 ** 9, now)
        self.assertLessEqual(until - now, Scheduler.PAUSE_MAX_S)
        self.assertTrue(s.is_paused(now + 5))
        self.assertFalse(s.is_paused(until + 1))
        self.assertGreaterEqual(s.pause(1, now) - now, 60)

    def test_resume_ends_it_and_both_are_recorded(self):
        s = self.make()
        now = time.time()
        s.pause(3600, now)
        s.resume(now + 1)
        self.assertFalse(s.is_paused(now + 2))
        st = Store(s.db_path)
        log = json.loads(st.get_meta(Scheduler.PAUSE_LOG, "[]"))
        st.close()
        self.assertEqual([e["event"] for e in log], ["pause", "resume"])

    def test_a_pause_survives_restart_only_until_its_deadline(self):
        s = self.make()
        now = time.time()
        s.pause(3600, now)
        again = Scheduler(s.db_path, {"win"})
        self.assertTrue(again.is_paused(now + 10))
        self.assertFalse(again.is_paused(now + 7200))


if __name__ == "__main__":
    unittest.main()

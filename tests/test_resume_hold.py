"""Suspend/resume must not let coverage and report judge a catch-up sweep.

Windows Modern Standby freezes the WSL VM: the monotonic clock stops while
realtime is corrected on wake. Without a resume check the cold-start hold
stayed open, coverage ran mid-sweep, and a collapsed score was recorded.
"""
import time
import unittest
from unittest import mock

from jarvis.service import scheduler as sched_mod
from jarvis.service.scheduler import Scheduler


class ResumeHoldTests(unittest.TestCase):
    def setUp(self):
        self.s = Scheduler(":memory:", ("wsl",))
        self.s.cold_start_pending = set()        # steady state before sleep
        self.s.started_at = time.time() - 86400  # long past the startup hold

    def _clock(self, wall, mono):
        return mock.patch.multiple(sched_mod.time, time=mock.Mock(return_value=wall),
                                   monotonic=mock.Mock(return_value=mono))

    def test_wall_jump_without_monotonic_rearms_the_hold(self):
        self.s._clock = (1000.0, 50.0)
        with self._clock(1000.0 + 4 * 3600, 52.0), \
             mock.patch.object(self.s, "_cold_start_gate", return_value={"sysmon", "geo"}):
            self.assertTrue(self.s._note_resume())
        self.assertEqual(self.s.cold_start_pending, {"sysmon", "geo"})
        self.assertEqual(self.s.resume_count, 1)
        self.assertTrue(self.s._cold_start_holding(self.s.started_at + 60))

    def test_held_coverage_and_report_do_not_run_mid_sweep(self):
        now = time.time()
        self.s.next_run = {n: (now - 10 if n in ("coverage", "report") else now + 999)
                           for n in self.s.next_run}
        self.s.cold_start_pending = {"sysmon"}
        self.s.started_at = now
        self.assertIsNone(self.s._due("main"))
        self.s.force("coverage")                  # an explicit request still runs
        self.assertEqual(self.s._due("main"), "coverage")

    def test_long_job_or_ntp_slew_is_not_a_resume(self):
        self.s._clock = (1000.0, 50.0)
        with self._clock(1000.0 + 106.0, 50.0 + 106.0):   # the longest job: both clocks advance
            self.assertFalse(self.s._note_resume())
        with self._clock(1106.0 + 5.0 + 3.0, 156.0 + 3.0):  # 5 s clock correction
            self.assertFalse(self.s._note_resume())
        with self._clock(900.0, 160.0):                    # wall stepped backwards
            self.assertFalse(self.s._note_resume())
        self.assertEqual(self.s.resume_count, 0)
        self.assertEqual(self.s.cold_start_pending, set())

    def test_both_lanes_detect_one_resume_once(self):
        self.s._clock = (1000.0, 50.0)
        with self._clock(1000.0 + 3600, 51.0), \
             mock.patch.object(self.s, "_cold_start_gate", return_value={"geo"}):
            self.assertTrue(self.s._note_resume())
            self.assertFalse(self.s._note_resume())      # the other lane's beat
        self.assertEqual(self.s.resume_count, 1)

    def test_hold_is_bounded(self):
        with mock.patch.object(self.s, "_cold_start_gate", return_value={"deep_hidden"}):
            self.s._clock = (1000.0, 50.0)
            with self._clock(10000.0, 51.0):
                self.s._note_resume()
        self.assertFalse(self.s._cold_start_holding(
            self.s.started_at + sched_mod.COLD_START_HOLD_S + 1))

    def test_reliability_status_reports_resumes(self):
        self.s._clock = (1000.0, 50.0)
        with mock.patch.object(self.s, "_cold_start_gate", return_value={"geo"}):
            with self._clock(9000.0, 51.0):
                self.s._note_resume()
        resume = self.s.reliability_status(snapshots={})["resume"]
        self.assertEqual(resume["count"], 1)
        self.assertEqual(resume["last_at"], 9000.0)


if __name__ == "__main__":
    unittest.main()

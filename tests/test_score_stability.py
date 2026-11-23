"""The shown score stays the last verified one while a post-gap sweep
re-verifies, and only then; history skips warm-up points."""

import tempfile
import unittest
from pathlib import Path

from jarvis.core.store import Store
from jarvis.response.reporting import score

JOBS = {"posture": (600, "p"), "sysmon": (600, "s")}
BAD = [{"category": "rules", "severity": "medium", "title": "t", "where": "w"}]


class StableScoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(str(Path(self.tmp.name) / "j.db"))
        self.addCleanup(self.store.close)

    def snap(self, job, at, error=""):
        self.store.db.execute(
            "INSERT INTO snapshots(kind,ts,duration,error,payload) VALUES(?,?,?,?,?) "
            "ON CONFLICT(kind) DO UPDATE SET ts=excluded.ts, error=excluded.error, "
            "payload=excluded.payload", (job, at, 1.0, error, "[]"))
        self.store.db.commit()

    def record(self, now):
        return score.record(self.store, JOBS, now)

    def test_gap_holds_last_verified_until_the_sweep_finishes(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)                                   # verified: 100%
        wake = t + 4 * 3600                              # 4h asleep
        self.snap("posture", wake)                       # sysmon not yet re-run
        self.record(wake)
        shown = score.stable(self.store, JOBS, wake + 10)
        self.assertEqual((shown["state"], shown["score"]), ("verifying", 100))
        self.assertLess(shown["live"]["score"], 100)
        self.assertEqual(shown["live"]["coverage"], 50)
        self.assertTrue(any(area["blind"] for area in shown["live"]["areas"]))
        self.assertEqual(len(score.history_of(self.store)), 1)   # warm-up not recorded
        self.snap("sysmon", wake + 60)
        self.record(wake + 60)
        self.assertEqual(score.stable(self.store, JOBS, wake + 61)["state"], "current")
        self.assertEqual(len(score.history_of(self.store)), 2)

    def test_a_collector_already_failing_before_the_window_ends_the_hold(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)
        self.snap("sysmon", t + 60, error="PowerShell failed")   # failed before sleep
        wake = t + 4 * 3600
        self.snap("posture", wake)
        self.record(wake)
        self.assertEqual(score.stable(self.store, JOBS, wake + 5)["state"], "current")

    def test_a_failure_since_the_wake_is_retrying_not_a_collapse(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)
        wake = t + 4 * 3600
        self.snap("posture", wake), self.snap("sysmon", wake, error="PowerShell failed")
        self.record(wake)
        shown = score.stable(self.store, JOBS, wake + 5)
        self.assertEqual((shown["state"], shown["score"]), ("verifying", 100))
        self.assertEqual(shown["progress"]["retrying"], ["sysmon"])
        self.assertEqual(len(score.history_of(self.store)), 1)   # not recorded as a verdict

    def test_a_failure_past_the_retry_grace_ends_the_hold(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)
        wake = t + 4 * 3600
        self.snap("posture", wake), self.snap("sysmon", wake, error="PowerShell failed")
        self.record(wake)
        within = score.stable(self.store, JOBS, wake + score.WAKE_RETRY_GRACE_S)
        self.assertEqual(within["state"], "verifying")
        past = score.stable(self.store, JOBS, wake + score.WAKE_RETRY_GRACE_S + 1)
        self.assertEqual(past["state"], "current")
        self.assertLess(past["score"], 100)

    def test_a_failure_that_outlasts_the_window_applies_the_live_score(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)
        wake = t + 4 * 3600
        self.snap("posture", wake), self.snap("sysmon", wake, error="PowerShell failed")
        self.record(wake)
        late = wake + score.WARMUP_MAX_S + 1
        self.snap("posture", late), self.snap("sysmon", late, error="PowerShell failed")
        shown = score.stable(self.store, JOBS, late)
        self.assertEqual(shown["state"], "current")
        self.assertLess(shown["score"], 100)

    def test_scheduler_opened_window_shows_waking_with_progress(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)
        wake = t + 4 * 3600
        score.open_wake_window(self.store, wake)               # scheduler saw the resume
        self.snap("posture", wake + 20)
        shown = score.stable(self.store, JOBS, wake + 30,
                             phase={"resumed_at": wake, "current": ["sysmon"]})
        self.assertEqual((shown["state"], shown["phase"], shown["score"]),
                         ("verifying", "waking", 100))
        self.assertEqual(shown["progress"], {"checked": 1, "total": 2, "pending": ["sysmon"],
                                             "retrying": [], "running": ["sysmon"]})
        self.assertEqual(shown["verified_at"], t)
        self.assertEqual(shown["warmup_ends"], wake + score.WARMUP_MAX_S)

    def test_open_wake_window_does_not_extend_an_open_window(self):
        self.assertEqual(score.open_wake_window(self.store, 5000), 5000)
        self.assertEqual(score.open_wake_window(self.store, 5600), 5000)

    def test_the_hold_expires_and_does_not_reopen(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)
        wake = t + 4 * 3600
        self.snap("posture", wake)
        self.record(wake)
        late = wake + score.WARMUP_MAX_S + 60
        self.snap("posture", late)
        self.record(late)
        self.assertEqual(score.stable(self.store, JOBS, late + 1)["state"], "current")
        self.assertEqual(len(score.history_of(self.store)), 2)

    def test_no_gap_means_live(self):
        t = 1_000_000
        self.snap("posture", t), self.snap("sysmon", t)
        self.record(t)
        self.snap("posture", t + 300)
        self.record(t + 300)
        self.assertEqual(score.stable(self.store, JOBS, t + 301)["state"], "current")


if __name__ == "__main__":
    unittest.main()


class SameFactOnceTests(unittest.TestCase):
    def test_a_fact_reported_by_two_collectors_of_an_area_counts_once(self):
        f = {"category": "c", "severity": "medium", "title": "listener", "where": "w",
             "detail": "udp 127.0.0.1:323", "host": "wsl"}
        other = dict(f, detail="udp 127.0.0.1:324")
        jobs = {"hidden": (300, "h"), "deep_hidden": (86400, "d")}
        now = 1_000_000
        snaps = {"hidden": {"ts": now, "error": "", "findings": [f]},
                 "deep_hidden": {"ts": now, "error": "", "findings": [f]}}
        once = score.compute(snaps, jobs, now)
        area = next(a for a in once["areas"] if a["name"] == "Active threats")
        self.assertEqual(area["open"], {"medium": 1})
        snaps["deep_hidden"]["findings"] = [other]      # a different fact still counts
        twice = score.compute(snaps, jobs, now)
        area = next(a for a in twice["areas"] if a["name"] == "Active threats")
        self.assertEqual(area["open"], {"medium": 2})

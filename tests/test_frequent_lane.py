"""The frequent lane (2026-11-03): five-minute collectors never wait behind the
main lane's post-boot sweep, and a dead or wedged frequent lane is never silent.

Measured fault: after the 10:13 boot the single main worker owed a 1331 s sweep
(intrusion 299 s, secrets 168 s, firewall 117 s, ...). Twenty collectors went
STALE for 16 minutes with no error, among them audio, controls, resources,
canary, logins, sshwatch and wslmanifest. The replay of that boot lives in
tests/test_lane_fairness.py (PostBootFrequentLaneTests); this module holds the
lane's wiring, liveness and failure paths.
"""

import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from jarvis.core import mechanisms
from jarvis.core.store import Store
from jarvis.platform import interop_gate
from jarvis.service import links, protection, scheduler
from jarvis.service.links import SILENT, UP, LinkPlane
from jarvis.service.schedule import JOBS
from jarvis.service.scheduler import FREQUENT, Scheduler

NOW = 1_000_000.0



# These tests reason about the workstation schedule (Windows and Linux jobs side by
# side). On a host without Windows, such as CI's Linux runner, the live table omits
# the Windows jobs, so the module fills the shared table in for its run and restores
# it after (in place: scheduler, links and protection all hold the same dict).
_ADDED = []


def setUpModule():
    from jarvis.service import schedule
    workstation, _absent = schedule.applicable(True, True)
    for name, spec in workstation.items():
        if name not in schedule.JOBS:
            schedule.JOBS[name] = spec
            _ADDED.append(name)


def tearDownModule():
    from jarvis.service import schedule
    for name in _ADDED:
        schedule.JOBS.pop(name, None)
    _ADDED.clear()

def _no_pressure():
    return mock.patch("jarvis.core.governor.live_pressure", return_value=(False, ""))


class Dead:
    def is_alive(self):
        return False


class MembershipTests(unittest.TestCase):
    def test_every_short_cadence_evidence_job_left_the_main_lane(self):
        main_short = sorted(n for n in JOBS
                            if mechanisms.BY_NAME[n].lane == "main"
                            and mechanisms.BY_NAME[n].evidence
                            and JOBS[n][0] <= mechanisms.FREQUENT_MAX_INTERVAL)
        self.assertEqual(main_short, [])

    def test_the_jobs_that_went_stale_that_morning_are_in_the_lane(self):
        # Independent of the registry: the names come from the 2026-11-03 readback.
        for name in ("audio", "canary", "controls", "logins", "resources", "sshwatch",
                     "wslmanifest", "hidden", "privacy", "wsl", "netwatch", "input"):
            self.assertIn(name, FREQUENT, name)

    def test_lanes_are_disjoint(self):
        self.assertFalse(set(FREQUENT) & set(scheduler.FAST))
        self.assertFalse(set(FREQUENT) & set(scheduler.BULK))

    def test_measured_duty_leaves_room_to_catch_up(self):
        duty = sum(mechanisms.BY_NAME[n].cost_s / JOBS[n][0] for n in FREQUENT)
        self.assertLess(duty, mechanisms.LANE_DUTY_LIMIT)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.s = Scheduler(":memory:", ("wsl", "win"))
        self.s.cold_start_pending.clear()
        self.s.next_run = {n: NOW + 9e5 for n in JOBS}
        self.s.evidence_ts = {n: NOW - 10 for n in JOBS}

    def _due(self, lane):
        with _no_pressure(), mock.patch.object(scheduler.time, "time", return_value=NOW):
            return self.s._due(lane)

    def test_frequent_job_runs_while_the_main_lane_owes_a_backlog(self):
        for name in ("intrusion", "secrets", "firewall", "audio"):
            self.s.next_run[name] = NOW - 1
            self.s.evidence_ts[name] = NOW - 3 * JOBS[name][0]
        self.assertEqual(self._due("frequent"), "audio")
        self.assertIn(self._due("main"), {"intrusion", "secrets", "firewall"})

    def test_main_lane_never_takes_a_frequent_job_and_vice_versa(self):
        self.s.next_run = {n: NOW - 1 for n in JOBS}
        self.s.evidence_ts = {n: NOW - 5 * JOBS[n][0] for n in JOBS}
        picked = set()
        for _ in range(len(JOBS)):
            name = self._due("main")
            if name is None:
                break
            picked.add(name)
            self.s.next_run[name] = NOW + 9e5
        self.assertFalse(picked & set(FREQUENT))
        name = self._due("frequent")
        self.assertIn(name, FREQUENT)

    def test_forced_frequent_job_is_served_by_its_own_lane(self):
        self.s.force("resources")
        self.assertIsNone(self._due("main"))
        self.assertEqual(self._due("frequent"), "resources")
        self.assertEqual(self.s.forced, [])


class LivenessTests(unittest.TestCase):
    def test_a_dead_frequent_thread_fails_lane_liveness(self):
        s = Scheduler(":memory:", ("wsl",))
        s.frequent_thread = Dead()
        self.assertFalse(s.fast_alive())

    def test_running_jobs_reports_every_lane(self):
        s = Scheduler(":memory:", ("wsl",))
        s.current, s.frequent_current = "intrusion", "audio"
        self.assertEqual(sorted(scheduler.running_jobs(s)), ["audio", "intrusion"])
        # Fakes that keep only some lanes still work.
        self.assertEqual(scheduler.running_jobs(SimpleNamespace(current="x")), ["x"])

    def test_a_wedged_frequent_lane_makes_health_not_live(self):
        s = Scheduler(":memory:", ("wsl",))
        with tempfile.TemporaryDirectory() as tmp:
            db = tmp + "/t.db"
            st = Store(db)
            st.save_snapshot("scan", [], 0.1, "")
            st.close()
            s.is_alive = lambda: True
            self.assertTrue(protection.health(db, s)["live"])
            s.frequent_heartbeat_mono -= 1000
            state = protection.health(db, s)
        self.assertFalse(state["live"])
        self.assertGreaterEqual(state["frequent_lane_age"], 900)

    def _watchdog_pings(self, sched):
        pings = []

        class Stop(Exception):
            pass

        def sleep(_s):
            if pings or getattr(sleep, "done", False):
                raise Stop
            sleep.done = True

        with mock.patch.object(scheduler.sdnotify, "watchdog_usec", return_value=60_000_000), \
                mock.patch.object(scheduler.sdnotify, "watchdog", side_effect=lambda: pings.append(1)), \
                mock.patch.object(scheduler.time, "sleep", side_effect=sleep):
            try:
                scheduler.watchdog_loop(sched)
            except Stop:
                pass
        return pings

    def test_systemd_watchdog_is_withheld_while_the_frequent_lane_is_wedged(self):
        s = Scheduler(":memory:", ("wsl",))
        s.is_alive = lambda: True
        self.assertEqual(self._watchdog_pings(s), [1])
        s.frequent_heartbeat_mono -= 4000
        self.assertEqual(self._watchdog_pings(s), [])

    def test_link_plane_reports_a_dead_frequent_lane(self):
        class Sched:
            fast_thread = SimpleNamespace(is_alive=lambda: True)
            frequent_thread = Dead()
            bulk_thread = None

            def is_alive(self):
                return True

            def lane_age(self, lane):
                return 3.0

        plane = LinkPlane()
        with mock.patch("jarvis.response.alert.load_conf", return_value={}):
            ev = links.gather_evidence({}, NOW, scheduler=Sched(), plane=plane, windows=False,
                                       phone=lambda now: {"applicable": False, "reason": "t"})
        plane.tick(ev, NOW)
        self.assertEqual(plane.statuses["lane:frequent"]["state"], SILENT)
        self.assertEqual(plane.statuses["lane:frequent"]["reason"], "lane thread died")
        self.assertEqual(plane.statuses["lane:fast"]["state"], UP)


def _quiet_pipeline():
    return (mock.patch("jarvis.service.scheduler.alert.load_conf", return_value={}),
            mock.patch("jarvis.service.scheduler.remediation.process",
                       side_effect=lambda s, c, n, f, e, v: (f, e)),
            mock.patch("jarvis.service.scheduler.defense.process",
                       side_effect=lambda s, c, n, f, coverage: f))


class FailurePathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "s.db")

    def test_refused_powershell_launch_is_a_recorded_failure_never_clean(self):
        s = Scheduler(self.db, ("wsl", "win"))
        store = Store(self.db)
        self.addCleanup(store.close)
        a, b, c = _quiet_pipeline()
        with a, b, c, mock.patch("jarvis.service.scheduler.run_job",
                                 side_effect=interop_gate.Refused("interop gate open")):
            findings, err = s.run_once(store, "audio")
        self.assertIn("interop gate open", err)
        self.assertEqual(s.reliability.health["audio"].consecutive_failures, 1)

    def test_lanes_run_side_by_side_and_a_crashing_job_does_not_stop_the_lane(self):
        """Real threads: the main lane is held by a long audit; the frequent
        lane still runs, survives a collector that raises, and keeps going."""
        s = Scheduler(self.db, ("wsl", "win"))
        s.cold_start_pending.clear()
        far = time.time() + 9e5
        s.next_run = {n: far for n in JOBS}
        release = threading.Event()
        ran, stop = [], threading.Event()

        def fake_run_job(name, hosts, db_path=None, **_kw):
            ran.append(name)
            if name == "intrusion":
                release.wait(10)
            if name == "controls":
                raise RuntimeError("collector crashed")
            return []

        real_due = s._due

        def due(lane=None):
            if stop.is_set():
                raise SystemExit         # ends the lane loop; its finally closes the store
            return real_due(lane)

        for name in ("intrusion", "controls", "audio"):
            s.next_run[name] = time.time() - 1
        a, b, c = _quiet_pipeline()
        with a, b, c, _no_pressure(), \
                mock.patch("jarvis.service.scheduler.run_job", side_effect=fake_run_job), \
                mock.patch("jarvis.service.scheduler.notifications.deliver"), \
                mock.patch.object(s, "_due", side_effect=due), \
                mock.patch.object(s, "_collect",
                                  side_effect=lambda n, t: (fake_run_job(n, s.hosts), "", "complete")):
            threads = [threading.Thread(target=s._lane, args=(lane,), daemon=True)
                       for lane in ("main", "frequent")]
            for t in threads:
                t.start()
            deadline = time.monotonic() + 8
            # Wait for the main lane to have started the long audit too: the frequent lane
            # can finish both jobs before the main thread is scheduled at all under load
            # (seen 1 in 5 with five copies in parallel, 2026-11-06).
            while time.monotonic() < deadline and not {"intrusion", "controls", "audio"} <= set(ran):
                time.sleep(0.05)
            main_still_busy = s.current == "intrusion"
            release.set()
            stop.set()
            for t in threads:
                t.join(5)
        self.assertTrue(main_still_busy, "the main lane should still hold the long audit")
        self.assertTrue({"controls", "audio"} <= set(ran), ran)
        self.assertEqual(s.reliability.health["controls"].consecutive_failures, 1)
        self.assertEqual(s.reliability.health["audio"].consecutive_failures, 0)


if __name__ == "__main__":
    unittest.main()


class LaneSurvivesRunOnceErrors(unittest.TestCase):
    """2026-11-05: "database is locked" raised out of run_once (set_meta) killed
    the frequent, bulk and main lanes; the supervisors then restarted the daemon."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "j.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_lane_keeps_running_after_run_once_raises(self):
        import sqlite3
        s = Scheduler(self.db, ("wsl", "win"))
        s.cold_start_pending.clear()
        far = time.time() + 9e5
        s.next_run = {n: far for n in JOBS}
        calls, stop = [], threading.Event()
        first = next(n for n in JOBS if s._lane_of(n) == "frequent")

        def run_once(store, name):
            calls.append(name)
            if len(calls) == 1:
                raise sqlite3.OperationalError("database is locked")
            stop.set()
            return [], ""

        real_due = s._due

        def due(lane=None):
            if stop.is_set():
                raise SystemExit
            if len(calls) == 1:
                s.next_run[first] = time.time() - 1       # due again right away
            return real_due(lane)

        s.next_run[first] = time.time() - 1
        a, b, c = _quiet_pipeline()
        with a, b, c, _no_pressure(), \
                mock.patch("jarvis.service.scheduler.LANE_ERROR_PAUSE_S", 0), \
                mock.patch("jarvis.service.scheduler.notifications.deliver"), \
                mock.patch.object(s, "_due", side_effect=due), \
                mock.patch.object(s, "run_once", side_effect=run_once):
            t = threading.Thread(target=s._lane, args=("frequent",), daemon=True)
            t.start()
            t.join(10)
        self.assertEqual(calls, [first, first])            # the lane ran the job again
        self.assertEqual(s.lane_errors.get("frequent"), 1)

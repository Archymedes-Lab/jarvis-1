"""Lane fairness: no job can monopolise a lane, and lateness is real.

Measured fault (2026-10-10, release 677b2a83b901): the Windows reviver
re-forced a capped sysmon every ~30 s. Each run took about 57 s on the single
main worker, and the forced floor times criticality 4 beat every starving
collector. sysmon ran back to back for 7 hours while 36 collectors went STALE.
See docs/architecture/LANE-FAIRNESS-AND-OUTAGE-RECORD.md.
"""

import unittest
from unittest import mock

from jarvis.service import scheduler as sched_mod
from jarvis.service.schedule import JOBS
from jarvis.service.scheduler import BULK, FAST, FREQUENT, STARVING, Scheduler

# Measured durations (s) from the live dashboard on 2026-10-10; others ~5 s.
DURATIONS = {"sysmon": 57.0, "evidence": 314.0, "hidden": 32.5, "netwatch": 24.7,
             "internet": 21.2, "world": 49.7, "toolchain": 23.6, "rust_mirror": 27.2,
             "firewall": 15.3, "intrusion": 16.8, "spy": 13.4, "implant": 11.5,
             "resources": 11.3, "control": 10.5, "audio": 9.9, "boot": 83.6}



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


def replay_lanes(s, clock, lanes, durations, until, watched, tick=None,
                 worst_after=None, default_s=5.0):
    """Run `lanes` side by side in virtual time, as their threads do: each
    lane picks its next job with the real Scheduler._due when idle and holds
    it for the job's duration. Evidence lands when a run completes. Returns
    each watched job's completion times and its worst lateness after
    `worst_after`."""
    runs = {n: [] for n in watched}
    worst = {n: 0.0 for n in watched}
    busy = {lane: None for lane in lanes}               # lane -> (name, done_at)
    with _no_pressure(), mock.patch.object(sched_mod.time, "time", clock):
        while clock.t < until:
            if tick:
                tick(clock.t)
            for lane in lanes:
                job = busy[lane]
                if job and job[1] <= clock.t:
                    name = job[0]
                    s.last_attempt[name] = s.evidence_ts[name] = clock.t
                    s.next_run[name] = clock.t + JOBS[name][0]
                    if name in runs:
                        runs[name].append(clock.t)
                    busy[lane] = job = None
                if job is None:
                    name = s._due(lane)
                    if name is not None:
                        # A running job is not due again (the thread holds it).
                        s.next_run[name] = float("inf")
                        busy[lane] = (name, clock.t + durations.get(name, default_s))
            if worst_after is not None and clock.t > worst_after:
                for n in watched:
                    worst[n] = max(worst[n], s.lateness(n, clock.t))
            clock.t += 1.0
    return runs, worst


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class ForceTests(unittest.TestCase):
    def setUp(self):
        self.s = Scheduler(":memory:", ("wsl", "win"))
        self.s.cold_start_pending.clear()

    def test_repeated_force_requests_collapse_into_one(self):
        for _ in range(10):
            self.assertTrue(self.s.force("sysmon"))
        self.assertEqual(self.s.forced, ["sysmon"])

    def test_unknown_job_is_refused(self):
        self.assertFalse(self.s.force("nope"))
        self.assertEqual(self.s.forced, [])

    def test_owner_force_of_an_idle_job_runs_at_once(self):
        now = 1_000_000.0
        self.s.next_run = {n: now + 9e5 for n in JOBS}
        self.s.evidence_ts = {n: now - 10 for n in JOBS}
        self.s.force("firewall")
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertEqual(self.s._due("main"), "firewall")
        self.assertEqual(self.s.forced, [])

    def test_reforced_job_that_just_ran_waits_but_is_not_dropped(self):
        now = 1_000_000.0
        self.s.next_run = {n: now + 9e5 for n in JOBS}
        self.s.evidence_ts = {n: now - 10 for n in JOBS}
        self.s.last_attempt["sysmon"] = now - 5
        self.s.force("sysmon")
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertIsNone(self.s._due("main"))
        self.assertEqual(self.s.forced, ["sysmon"])
        later = now + sched_mod.FORCE_COOLDOWN_S + 1
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=later):
            self.assertEqual(self.s._due("main"), "sysmon")


class LatenessTests(unittest.TestCase):
    def setUp(self):
        self.s = Scheduler(":memory:", ("wsl", "win"))
        self.s.cold_start_pending.clear()

    def test_restart_does_not_hide_real_staleness(self):
        # After a restart next_run is "now" for every job; six hours of real
        # staleness must still count as six hours.
        now = 1_000_000.0
        self.s.evidence_ts = {"spy": now - 6 * 3600}
        self.assertGreaterEqual(self.s.lateness("spy", now), 6 * 3600 / JOBS["spy"][0])

    def test_no_evidence_at_all_is_long_overdue(self):
        self.s.evidence_ts = {}
        self.assertGreaterEqual(self.s.lateness("audio", 1_000_000.0), STARVING)

    def test_an_attempt_resets_lateness_even_when_it_failed(self):
        now = 1_000_000.0
        self.s.evidence_ts = {"sysmon": now - 7 * 3600}
        self.s.last_attempt["sysmon"] = now - 1
        self.assertLess(self.s.lateness("sysmon", now), 0.01)

    def test_starving_collector_beats_a_forced_critical_one(self):
        now = 1_000_000.0
        self.s.next_run = {n: now - 1 for n in JOBS}
        self.s.evidence_ts = {n: now - 10 for n in JOBS}
        self.s.evidence_ts["firewall"] = now - 45000     # 18.7x its 2400 s cadence
        self.s.evidence_ts["sysmon"] = now - 700
        self.s.reliability.health["sysmon"].consecutive_failures = 3
        self.s.force("sysmon")
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertEqual(self.s._due("main"), "firewall")

    def test_governor_defers_by_real_lateness(self):
        from jarvis.core import governor
        governed = sorted(n for n in governor.GOVERNED_JOBS if n in JOBS
                          and n not in FAST and n not in BULK)
        self.assertTrue(governed)
        name = governed[0]
        now = 1_000_000.0
        self.s.next_run = {n: now + 9e5 for n in JOBS}
        self.s.next_run[name] = now - 1
        pressured = mock.patch("jarvis.core.governor.live_pressure",
                               return_value=(True, "CPU 93%"))
        self.s.evidence_ts = {n: now for n in JOBS}
        self.s.evidence_ts[name] = now - 1.5 * JOBS[name][0]
        with pressured, mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertIsNone(self.s._due("main"))       # 1.5x late: deferred
        self.s.evidence_ts[name] = now - 4 * JOBS[name][0]
        with pressured, mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertEqual(self.s._due("main"), name)  # 4x late: runs


class BulkLaneTests(unittest.TestCase):
    def test_evidence_runs_only_in_the_bulk_lane(self):
        s = Scheduler(":memory:", ("wsl", "win"))
        s.cold_start_pending.clear()
        now = 1_000_000.0
        s.next_run = {n: now + 9e5 for n in JOBS}
        s.next_run["evidence"] = now - 1
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertIsNone(s._due("main"))
            self.assertIsNone(s._due("fast"))
            self.assertEqual(s._due("bulk"), "evidence")

    def test_lane_liveness_includes_the_bulk_lane(self):
        s = Scheduler(":memory:", ("wsl",))
        s.bulk_thread = mock.Mock(is_alive=mock.Mock(return_value=False))
        self.assertFalse(s.fast_alive())


class MonopolyReplayTests(unittest.TestCase):
    """Replay the measured fault in virtual time: a reviver re-forces sysmon
    every 30 s, each sysmon run takes 57 s, and every collector starts stale
    after a restart."""

    def _replay(self, hours=3.0, force_every=30.0):
        s = Scheduler(":memory:", ("wsl", "win"))
        s.cold_start_pending.clear()
        clock = Clock(1_000_000.0)
        start = clock.t
        main = [n for n in JOBS if n not in FAST and n not in BULK]
        s.next_run = {n: start for n in JOBS}
        s.evidence_ts = {n: start - 6 * 3600 for n in JOBS}   # 6 h stale at restart
        next_force = [start]

        def tick(now):
            while next_force[0] <= now:
                s.force("sysmon")
                next_force[0] += force_every

        runs, worst = replay_lanes(s, clock, ("main", "frequent"), DURATIONS,
                                   start + hours * 3600, main, tick=tick,
                                   worst_after=start + 3600)
        return s, runs, worst, start

    def test_every_main_collector_catches_up_within_the_first_hour(self):
        _s, runs, _worst, start = self._replay()
        missing = [n for n, r in runs.items() if not r or r[0] > start + 3600]
        self.assertEqual(missing, [], f"never caught up: {missing}")

    def test_sysmon_cannot_hold_the_lane(self):
        _s, runs, _worst, start = self._replay()
        busy = len(runs["sysmon"]) * DURATIONS["sysmon"]
        self.assertLess(busy / (3 * 3600), 0.25,
                        f"sysmon held {busy / (3 * 3600):.0%} of the main lane")

    def test_staleness_stays_bounded_after_catch_up(self):
        _s, _runs, worst, _start = self._replay()
        over = {n: round(v, 2) for n, v in worst.items() if v >= 3.0}
        self.assertEqual(over, {}, f"collectors past 3x their cadence: {over}")


# Measured on the live release after the 2026-11-03 10:13 boot (snapshot
# durations, s). Jobs not listed took under a second.
BOOT_2026_11_03 = {"intrusion": 299.0, "secrets": 168.0, "firewall": 117.0,
                   "deep_hidden": 113.0, "boot": 91.0, "control": 85.0, "storage": 75.0,
                   "evasion": 46.0, "memscan": 36.0, "implant": 35.0, "toolchain": 29.0,
                   "spy": 24.0, "hidden": 24.0, "arena": 22.0, "audio": 10.2,
                   "pixel": 10.8, "netwatch": 11.5, "resources": 16.5, "hunt": 12.3,
                   "backdoor": 8.7, "controls": 6.6, "preos": 6.5, "wsl": 5.5,
                   "internet": 5.4, "sysmon_linux": 5.4, "sysmon": 4.4, "containers": 4.2,
                   "model": 4.1, "privacy": 3.2, "attackmap": 3.1, "opshealth": 3.0,
                   "asep": 2.9, "patches": 2.4, "identity": 2.2, "bruteforce": 2.1}


class PostBootFrequentLaneTests(unittest.TestCase):
    """Replay of the 2026-11-03 boot: every job due at once with evidence from
    before the boot, the main lane owing a 1331 s sweep. Twenty collectors
    went STALE for 16 minutes behind it with no error."""

    HORIZON_S = 2 * 3600

    def _boot(self, frequent_lane):
        s = Scheduler(":memory:", ("wsl", "win"))
        s.cold_start_pending.clear()
        clock = Clock(1_000_000.0)
        start = clock.t
        s.boot_at = start - 60
        s.next_run = {n: start for n in JOBS}
        s.evidence_ts = {n: start - 3 * 3600 for n in JOBS}   # machine was off 3 h
        lanes = ("main", "frequent") if frequent_lane else ("main",)
        watched = sorted(FREQUENT)
        if frequent_lane:
            runs, worst = replay_lanes(s, clock, lanes, BOOT_2026_11_03,
                                       start + self.HORIZON_S, watched, default_s=0.5)
        else:
            with mock.patch.object(sched_mod, "FREQUENT", frozenset()):
                runs, worst = replay_lanes(s, clock, lanes, BOOT_2026_11_03,
                                           start + self.HORIZON_S, watched, default_s=0.5)
        return runs, start

    @staticmethod
    def _oldest(runs, start, until):
        """Each job's worst evidence age once it first ran after the boot."""
        out = {}
        for name, done in runs.items():
            if not done:
                out[name] = float("inf")
                continue
            gaps = [b - a for a, b in zip(done, done[1:])] + [until - done[-1]]
            out[name] = max(gaps)
        return out

    def test_the_old_single_lane_reproduces_the_stale_morning(self):
        # Without the lane the replay must show the fault, or the test below
        # proves nothing.
        runs, start = self._boot(frequent_lane=False)
        ages = self._oldest(runs, start, start + self.HORIZON_S)
        stale = sorted(n for n, age in ages.items()
                       if age > sched_mod.reliability.STALE_AFTER * JOBS[n][0])
        self.assertTrue(stale, "single-lane replay no longer reproduces the fault")

    def test_every_frequent_collector_runs_within_its_first_cadence_after_boot(self):
        runs, start = self._boot(frequent_lane=True)
        late = {n: (r[0] - start if r else None) for n, r in runs.items()
                if not r or r[0] - start > JOBS[n][0]}
        self.assertEqual(late, {}, "first post-boot run later than one cadence")

    def test_no_frequent_collector_goes_stale_behind_the_boot_sweep(self):
        runs, start = self._boot(frequent_lane=True)
        ages = self._oldest(runs, start, start + self.HORIZON_S)
        stale = {n: age for n, age in ages.items()
                 if age > sched_mod.reliability.STALE_AFTER * JOBS[n][0]}
        self.assertEqual(stale, {})
        # The wait past a job's cadence is bounded by one pass of the lane's
        # own declared costs, whatever the main lane is running.
        from jarvis.core import mechanisms
        one_pass = sum(mechanisms.BY_NAME[n].cost_s for n in FREQUENT)
        over = {n: age - JOBS[n][0] for n, age in ages.items()
                if age - JOBS[n][0] > one_pass}
        self.assertEqual(over, {}, f"waited past one {one_pass:.0f} s pass")


class OutageHookTests(unittest.TestCase):
    def test_supervise_reports_transitions_to_the_recorder(self):
        s = Scheduler(":memory:", ("wsl",))
        s.outages = mock.Mock()
        snaps = {"hidden": {"ts": 1.0, "error": "", "findings": []}}
        s.supervise_once(snaps)
        s.outages.observe.assert_called_once()
        args = s.outages.observe.call_args[0]
        self.assertIs(args[1], snaps)

    def test_a_failing_recorder_never_breaks_supervision(self):
        import time
        s = Scheduler(":memory:", ("wsl",))
        s.outages = mock.Mock(observe=mock.Mock(side_effect=RuntimeError("disk")))
        snaps = {"hidden": {"ts": time.time() - 340.0, "error": "", "findings": []}}
        self.assertIn("hidden", s.supervise_once(snaps))


if __name__ == "__main__":
    unittest.main()

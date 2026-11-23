"""Boot currency: evidence about machine state must postdate the current boot.

Measured fault (2026-10-27): after a Windows hard reset at 10:05 the daemon was
up and every core sensor complete within 35 s, yet memscan, posture and spy
still carried results from before the reboot 20 minutes later. Their age was
inside the cadence, so lateness ranked them behind everything else and the
reliability plane counted them FRESH while they described processes, services
and posture of a machine that no longer existed.
"""

import os
import tempfile
import unittest
from unittest import mock

from jarvis.core import mechanisms
from jarvis.core.store import Store
from jarvis.service import scheduler as sched_mod
from jarvis.service.schedule import JOBS
from jarvis.service.scheduler import BOOT_FLOOR, BOOT_SCOPED, Scheduler

BOOT = 1_000_000.0


def _no_pressure():
    return mock.patch("jarvis.core.governor.live_pressure", return_value=(False, ""))


def _sched(boot_at=BOOT):
    s = Scheduler(":memory:", ("wsl", "win"))
    s.cold_start_pending.clear()
    s.boot_at = boot_at
    return s


class RegistryTests(unittest.TestCase):
    def test_boot_scoped_set_is_machine_state_only(self):
        names = set(mechanisms.boot_scoped())
        for must in ("boot", "asep", "preos", "memscan", "hidden", "posture", "firewall"):
            self.assertIn(must, names)
        # Knowledge and file-content jobs are not changed by a reboot.
        for never in ("intel", "gaps", "attackmap", "feeds", "secrets", "coverage",
                      "report", "world", "model"):
            self.assertNotIn(never, names)
        for name in names:
            self.assertTrue(mechanisms.BY_NAME[name].evidence, name)

    def test_scheduler_set_is_the_registry_set_for_scheduled_jobs(self):
        self.assertEqual(BOOT_SCOPED, set(mechanisms.boot_scoped()) & set(JOBS))
        self.assertIn("memscan", BOOT_SCOPED)


class LatenessTests(unittest.TestCase):
    def test_pre_boot_evidence_is_due_now_however_young(self):
        s = _sched()
        now = BOOT + 60
        s.evidence_ts = {"boot": BOOT - 120}        # 3 min old against 6 h cadence
        self.assertEqual(s.lateness("boot", now), BOOT_FLOOR)

    def test_post_boot_attempt_restores_normal_lateness(self):
        s = _sched()
        now = BOOT + 600
        s.evidence_ts = {"boot": BOOT - 120}
        s.last_attempt["boot"] = BOOT + 300         # failed or not, it ran this boot
        self.assertLess(s.lateness("boot", now), 0.05)

    def test_really_stale_pre_boot_evidence_keeps_its_real_lateness(self):
        s = _sched()
        now = BOOT + 60
        s.evidence_ts = {"hidden": BOOT - 3000}     # 10x its 300 s cadence
        self.assertGreater(s.lateness("hidden", now), 9.0)

    def test_other_jobs_are_judged_by_age_alone(self):
        s = _sched()
        now = BOOT + 60
        s.evidence_ts = {"intel": BOOT - 120}
        self.assertLess(s.lateness("intel", now), 0.05)

    def test_unknown_boot_time_falls_back_to_age(self):
        s = _sched(boot_at=None)
        now = BOOT + 60
        s.evidence_ts = {"boot": BOOT - 120}
        self.assertLess(s.lateness("boot", now), 0.05)


class OrderingTests(unittest.TestCase):
    def _after_boot(self, s, now):
        s.next_run = {n: now - 1 for n in JOBS}
        # Shut down 10 minutes before boot: everything from just before it.
        s.evidence_ts = {n: BOOT - 600 for n in JOBS}

    def _sweep(self, s):
        """The main lane's cold-start order: pick, mark attempted, repeat."""
        now = BOOT + 60
        self._after_boot(s, now)
        order = []
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            while (name := s._due("main")) is not None:
                order.append(name)
                s.last_attempt[name] = now
                s.next_run[name] = now + 9e5
        return order

    def test_the_floor_moves_nothing_ahead_of_sysmon_ingestion(self):
        # Short-cadence jobs that are really late still lead (hidden, at 2x
        # its cadence, earns its place); the floor only reorders what follows.
        with_floor = self._sweep(_sched())
        without = self._sweep(_sched(boot_at=None))
        cut = without.index("sysmon") + 1
        self.assertEqual(with_floor[:cut], without[:cut])

    def test_boot_audits_run_before_long_cadence_non_boot_jobs(self):
        order = self._sweep(_sched())
        last_boot = max(order.index(n) for n in BOOT_SCOPED if n in order)
        for n in ("intel", "gaps", "attackmap", "webshell", "secrets", "toolchain"):
            if n in order:
                self.assertGreater(order.index(n), last_boot, n)

    def test_without_the_floor_the_startup_analysis_waits(self):
        # The regression this guards: the same cold start with no boot known
        # leaves the six-hourly startup analysis near the end of the sweep.
        with_floor = self._sweep(_sched())
        without = self._sweep(_sched(boot_at=None))
        self.assertLess(with_floor.index("boot"), without.index("boot") - 10)

    def test_governor_still_defers_governed_boot_audits(self):
        s = _sched()
        now = BOOT + 60
        s.next_run = {n: now + 9e5 for n in JOBS}
        s.next_run["memscan"] = now - 1
        s.evidence_ts = {n: now for n in JOBS}
        s.evidence_ts["memscan"] = BOOT - 60
        pressured = mock.patch("jarvis.core.governor.live_pressure",
                               return_value=(True, "CPU 93%"))
        with pressured, mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertIsNone(s._due("main"))
        with _no_pressure(), mock.patch.object(sched_mod.time, "time", return_value=now):
            self.assertEqual(s._due("main"), "memscan")


class ReadinessTests(unittest.TestCase):
    def _snaps(self, ts, **override):
        snaps = {n: {"ts": ts, "error": ""} for n in BOOT_SCOPED}
        snaps.update(override)
        return snaps

    def test_all_pre_boot_is_pending(self):
        r = _sched().boot_readiness(self._snaps(BOOT - 5))
        self.assertTrue(r["known"])
        self.assertFalse(r["ready"])
        self.assertEqual(r["pending"], sorted(BOOT_SCOPED))
        self.assertIsNone(r["ready_after_s"])

    def test_ready_once_every_boot_audit_has_a_clean_post_boot_result(self):
        snaps = self._snaps(BOOT + 100, memscan={"ts": BOOT + 420.5, "error": ""})
        r = _sched().boot_readiness(snaps)
        self.assertTrue(r["ready"])
        self.assertEqual(r["pending"], [])
        self.assertEqual(r["ready_after_s"], 420.5)

    def test_a_post_boot_error_is_failed_not_ready(self):
        snaps = self._snaps(BOOT + 100,
                            asep={"ts": BOOT + 200, "error": "PowerShell failed"})
        r = _sched().boot_readiness(snaps)
        self.assertFalse(r["ready"])
        self.assertEqual(r["failed"], ["asep"])

    def test_missing_or_malformed_snapshot_is_pending(self):
        snaps = self._snaps(BOOT + 100)
        del snaps["boot"]
        snaps["preos"] = {"ts": "garbage"}
        r = _sched().boot_readiness(snaps)
        self.assertEqual(r["pending"], ["boot", "preos"])

    def test_unknown_boot_is_never_reported_ready(self):
        r = _sched(boot_at=None).boot_readiness(self._snaps(BOOT + 100))
        self.assertFalse(r["known"])
        self.assertFalse(r["ready"])

    def test_daemon_restart_inside_one_boot_gives_the_same_answer(self):
        snaps = self._snaps(BOOT + 100)
        self.assertEqual(_sched().boot_readiness(snaps), _sched().boot_readiness(snaps))


class ServicePathTests(unittest.TestCase):
    def test_reliability_status_reports_boot_readiness_from_the_store(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "jarvis.db")
            store = Store(db)
            try:
                for n in BOOT_SCOPED:
                    store.save_snapshot(n, [])
                    store.db.execute("UPDATE snapshots SET ts=? WHERE kind=?",
                                     (BOOT - 50 if n == "boot" else BOOT + 50, n))
                store.db.commit()
            finally:
                store.close()
            s = Scheduler(db, ("wsl", "win"))
            s.boot_at = BOOT
            boot = s.reliability_status()["summary"]["boot"]
        self.assertEqual(boot["pending"], ["boot"])
        self.assertFalse(boot["ready"])


class StableBootTests(unittest.TestCase):
    """The boot reference must not move with WSL clock steps (374 s on 2026-10-27)."""

    def test_one_value_per_kernel_boot_across_clock_steps_and_restarts(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "j.db")
            with mock.patch.object(sched_mod, "_boot_id", return_value="boot-a"), \
                    mock.patch.object(sched_mod, "host_boot_time", return_value=1000.0):
                self.assertEqual(sched_mod.host_boot(db), 1000.0)
            # The clock stepped: btime now reads later. Same boot, same answer.
            with mock.patch.object(sched_mod, "_boot_id", return_value="boot-a"), \
                    mock.patch.object(sched_mod, "host_boot_time", return_value=1374.0):
                self.assertEqual(sched_mod.host_boot(db), 1000.0)
            # A new kernel boot takes a new reading.
            with mock.patch.object(sched_mod, "_boot_id", return_value="boot-b"), \
                    mock.patch.object(sched_mod, "host_boot_time", return_value=9000.0):
                self.assertEqual(sched_mod.host_boot(db), 9000.0)

    def test_without_a_boot_id_or_store_it_falls_back_to_btime(self):
        with mock.patch.object(sched_mod, "_boot_id", return_value=None), \
                mock.patch.object(sched_mod, "host_boot_time", return_value=5.0):
            self.assertEqual(sched_mod.host_boot("/nonexistent/dir/j.db"), 5.0)
        with mock.patch.object(sched_mod, "_boot_id", return_value="x"), \
                mock.patch.object(sched_mod, "host_boot_time", return_value=6.0):
            self.assertEqual(sched_mod.host_boot("/nonexistent/dir/j.db"), 6.0)


class FirstVerifiedTests(unittest.TestCase):
    """ready_after_s is fixed once reached; it must not creep with later runs."""

    def _store(self, d, receipts):
        db = os.path.join(d, "j.db")
        store = Store(db)
        try:
            for i, (job, at, coverage) in enumerate(receipts):
                store.db.execute(
                    "INSERT INTO defender_runs(run_id,job,observed_at,coverage,error,digest,"
                    "finding_count) VALUES(?,?,?,?,'','d',0)", (f"r{i}", job, at, coverage))
            for n in BOOT_SCOPED:
                store.save_snapshot(n, [])
                store.db.execute("UPDATE snapshots SET ts=? WHERE kind=?", (BOOT + 5000, n))
            store.db.commit()
        finally:
            store.close()
        return db

    def test_first_usable_receipt_not_the_latest_snapshot(self):
        receipts = [(n, BOOT + 100, "complete") for n in BOOT_SCOPED if n != "memscan"]
        receipts += [("memscan", BOOT + 50, "unavailable"),   # failed first: not usable
                     ("memscan", BOOT + 400, "partial"),
                     ("memscan", BOOT + 4000, "complete"),
                     ("boot", BOOT - 10, "complete")]          # before boot: ignored
        with tempfile.TemporaryDirectory() as d:
            db = self._store(d, receipts)
            s = Scheduler(db, ("wsl", "win"))
            s.boot_at = BOOT
            r = s.boot_readiness(Store(db).get_snapshots())
        self.assertTrue(r["ready"])
        self.assertEqual(r["ready_after_s"], 400.0)

    def test_value_is_cached_for_the_boot(self):
        receipts = [(n, BOOT + 100, "complete") for n in BOOT_SCOPED]
        with tempfile.TemporaryDirectory() as d:
            db = self._store(d, receipts)
            s = Scheduler(db, ("wsl", "win"))
            s.boot_at = BOOT
            snaps = Store(db).get_snapshots()
            first = s.boot_readiness(snaps)["ready_after_s"]
            store = Store(db)
            store.db.execute("DELETE FROM defender_runs")
            store.db.commit()
            store.close()
            self.assertEqual(s.boot_readiness(snaps)["ready_after_s"], first)

    def test_missing_receipts_fall_back_to_snapshot_time(self):
        with tempfile.TemporaryDirectory() as d:
            db = self._store(d, [])
            s = Scheduler(db, ("wsl", "win"))
            s.boot_at = BOOT
            r = s.boot_readiness(Store(db).get_snapshots())
        self.assertEqual(r["ready_after_s"], 5000.0)


class HostBootTimeTests(unittest.TestCase):
    def test_reads_btime(self):
        data = "cpu  1 2 3\nbtime 1793088383\nprocesses 9\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=data)):
            self.assertEqual(sched_mod.host_boot_time(), 1793088383.0)

    def test_unreadable_proc_stat_is_none(self):
        with mock.patch("builtins.open", side_effect=OSError("EPERM")):
            self.assertIsNone(sched_mod.host_boot_time())

    def test_malformed_btime_is_none(self):
        for data in ("btime\n", "btime soon\n", "cpu 1\n"):
            with mock.patch("builtins.open", mock.mock_open(read_data=data)):
                self.assertIsNone(sched_mod.host_boot_time(), data)

    def test_live_value_is_in_the_past(self):
        import time
        value = sched_mod.host_boot_time()
        if value is not None:
            self.assertLess(value, time.time())


if __name__ == "__main__":
    unittest.main()

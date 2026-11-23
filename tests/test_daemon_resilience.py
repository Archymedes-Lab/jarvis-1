"""Regression checks for the 2026-10-22 outage causes.

* The kernel's WSLInterop binfmt entry can be flushed by anything privileged on
  the VM; PowerShell must still start (through /init) and the bridge must say
  so without paging as an outage.
* Standby stops the monotonic clock with the VM; liveness must be judged on
  it, so a resume never reads as a stalled scheduler.
* A daemon pinned at its cgroup memory ceiling is slow in a way nothing else
  reports; resourcewatch names it with the measured numbers.
"""

import errno
import json
import os
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from jarvis.collectors.process import resourcewatch
from jarvis.core.store import Store
from jarvis.platform import windows as collect_windows
from jarvis.service import coverage, protection, scheduler


class _Result:
    def __init__(self, args, **kwargs):
        self.args = list(args)
        self.kwargs = kwargs
        self.stdout = b""
        self.returncode = 0


class InteropLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.binfmt = os.path.join(self.tmp.name, "binfmt_misc")
        os.makedirs(self.binfmt)
        self.init = os.path.join(self.tmp.name, "init")
        with open(self.init, "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(self.init, 0o755)
        self.patches = [
            patch.object(collect_windows, "BINFMT_DIR", self.binfmt),
            patch.object(collect_windows, "INTEROP_INIT", self.init),
            patch.object(collect_windows.host, "on_wsl", return_value=True),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _register(self, name="WSLInterop", state="enabled"):
        with open(os.path.join(self.binfmt, name), "w") as fh:
            fh.write(state + "\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n")

    def test_registered_entry_starts_the_program_directly(self):
        self._register()
        self.assertTrue(collect_windows.interop_binfmt_registered())
        self.assertEqual(collect_windows.interop_launcher(), [])
        self.assertEqual(collect_windows.interop_mode(), "direct")

    def test_late_entry_name_counts_as_registered(self):
        self._register("WSLInterop-late")
        self.assertEqual(collect_windows.interop_mode(), "direct")

    def test_disabled_or_missing_entry_falls_back_to_init(self):
        self.assertFalse(collect_windows.interop_binfmt_registered())
        self.assertEqual(collect_windows.interop_launcher(), [self.init])
        self.assertEqual(collect_windows.interop_mode(), "init")
        self._register(state="disabled")
        self.assertEqual(collect_windows.interop_mode(), "init")

    def test_missing_entry_without_init_is_broken_not_silent(self):
        os.chmod(self.init, 0o644)
        self.assertEqual(collect_windows.interop_launcher(), [])
        self.assertEqual(collect_windows.interop_mode(), "broken")

    def test_spawn_prefixes_init_when_binfmt_is_flushed(self):
        with patch.object(collect_windows.subprocess, "run", side_effect=_Result) as run:
            res = collect_windows.spawn(["/mnt/c/ps.exe", "-Command", "x"], timeout=3)
        self.assertEqual(res.args, [self.init, "/mnt/c/ps.exe", "-Command", "x"])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(res.kwargs["timeout"], 3)

    def test_spawn_retries_through_init_on_enoexec_race(self):
        self._register()
        calls = []

        def run(args, **kwargs):
            calls.append(list(args))
            if len(calls) == 1:
                raise OSError(errno.ENOEXEC, "Exec format error")
            return _Result(args, **kwargs)

        with patch.object(collect_windows.subprocess, "run", side_effect=run):
            res = collect_windows.spawn(["/mnt/c/ps.exe", "-Command", "x"])
        self.assertEqual(calls, [["/mnt/c/ps.exe", "-Command", "x"],
                                 [self.init, "/mnt/c/ps.exe", "-Command", "x"]])
        self.assertEqual(res.args[0], self.init)

    def test_spawn_does_not_retry_other_errors_or_loop(self):
        self._register()
        with patch.object(collect_windows.subprocess, "run",
                          side_effect=OSError(errno.ENOENT, "missing")):
            with self.assertRaises(OSError):
                collect_windows.spawn(["/mnt/c/ps.exe"])
        # Already through /init: a second ENOEXEC must surface, not recurse.
        os.remove(os.path.join(self.binfmt, "WSLInterop"))
        with patch.object(collect_windows.subprocess, "run",
                          side_effect=OSError(errno.ENOEXEC, "Exec format error")) as run:
            with self.assertRaises(OSError):
                collect_windows.spawn(["/mnt/c/ps.exe"])
        self.assertEqual(run.call_count, 1)

    def test_ps_json_reports_through_init_fallback(self):
        payload = {"ok": 1}
        import base64
        out = base64.b64encode(json.dumps(payload).encode())

        def run(args, **kwargs):
            self.assertEqual(args[0], self.init)
            return SimpleNamespace(stdout=out)

        with patch.object(collect_windows, "available", return_value=True), \
             patch.object(collect_windows, "_PS", "/mnt/c/ps.exe"), \
             patch.object(collect_windows.subprocess, "run", side_effect=run):
            self.assertEqual(collect_windows.ps_json("x"), payload)

    def test_bridge_status_names_the_flush_without_paging(self):
        from jarvis.response import alert
        with patch.object(collect_windows, "available", return_value=True), \
             patch.object(coverage.host, "native_windows", return_value=False):
            findings = coverage.bridge_status()
        self.assertEqual(findings[0]["severity"], "ok")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[1]["severity"], "medium")
        self.assertIn("binfmt_misc", findings[1]["title"])
        self.assertIn("systemd-binfmt", findings[1]["detail"])
        self.assertFalse(alert.is_outage(findings[1]))
        self._register()
        with patch.object(collect_windows, "available", return_value=True), \
             patch.object(coverage.host, "native_windows", return_value=False):
            self.assertEqual(len(coverage.bridge_status()), 1)

    def test_bridge_status_is_critical_when_nothing_can_start_windows(self):
        os.chmod(self.init, 0o644)
        with patch.object(collect_windows, "available", return_value=True), \
             patch.object(coverage.host, "native_windows", return_value=False):
            findings = coverage.bridge_status()
        self.assertEqual(findings[1]["severity"], "critical")


class _Sched:
    """A scheduler with real heartbeat fields and no threads."""

    hosts = ("wsl",)

    def __init__(self):
        self.heartbeat = time.time()
        self.fast_heartbeat = time.time()
        self.bulk_heartbeat = time.time()
        self.heartbeat_mono = time.monotonic()
        self.fast_heartbeat_mono = time.monotonic()
        self.bulk_heartbeat_mono = time.monotonic()
        self.current = None
        self.fast_current = None
        self.cold_start_pending = set()
        self.started_at = time.time()
        self.lock = threading.Lock()

    lane_age = scheduler.Scheduler.lane_age

    def is_alive(self):
        return True

    def fast_alive(self):
        return True

    def reliability_status(self, snapshots=None):
        return {"summary": {"recovering": []}}


class MonotonicLivenessTests(unittest.TestCase):
    def _health(self, sched):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = tmp + "/t.db"
            store = Store(db_path)
            try:
                store.save_snapshot("scan", [], 0.1, "")
            finally:
                store.close()
            return protection.health(db_path, sched, stamp=time.time())

    def test_a_resume_after_a_long_standby_is_not_a_stall(self):
        sched = _Sched()
        # Wall clock jumped 3 hours while the VM was frozen; the lanes could
        # not run in that time, so the monotonic twins are seconds old.
        sched.heartbeat -= 3 * 3600
        sched.fast_heartbeat -= 3 * 3600
        state = self._health(sched)
        self.assertTrue(state["live"])
        self.assertLess(state["progress_age"], 60)
        self.assertLess(state["fast_lane_age"], 60)

    def test_a_real_stall_is_still_a_stall(self):
        sched = _Sched()
        sched.heartbeat_mono -= 1000
        state = self._health(sched)
        self.assertFalse(state["live"])
        self.assertGreaterEqual(state["progress_age"], 900)
        sched = _Sched()
        sched.fast_heartbeat_mono -= 400
        self.assertFalse(self._health(sched)["live"])

    def test_fakes_without_monotonic_twins_keep_wall_clock_ages(self):
        sched = SimpleNamespace(heartbeat=time.time() - 50,
                                fast_heartbeat=time.time() - 20)
        self.assertAlmostEqual(scheduler.lane_age(sched, "main"), 50, delta=2)
        self.assertAlmostEqual(scheduler.lane_age(sched, "fast"), 20, delta=2)

    def test_watchdog_reads_lane_ages(self):
        sched = _Sched()
        sched.heartbeat -= 7200          # standby, not a stall
        self.assertLess(scheduler.lane_age(sched, "main"), 5)
        self.assertLess(scheduler.lane_age(sched, "fast"), 5)


class CgroupCeilingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "jarvis.db"))
        self.root = os.path.join(self.tmp.name, "cgroup")
        self.unit = os.path.join(self.root, "system.slice/jarvis.service")
        os.makedirs(self.unit)
        self.procfile = os.path.join(self.tmp.name, "cgroup.txt")
        with open(self.procfile, "w") as fh:
            fh.write("0::/system.slice/jarvis.service\n")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _write(self, current, high, events, anon=400, file=500, pressure=0.8):
        mib = 1024 ** 2
        for name, text in (("memory.current", str(current * mib)),
                           ("memory.high", str(high * mib) if high else "max"),
                           ("memory.max", "max"),
                           ("memory.events", "".join(f"{k} {v}\n" for k, v in events.items())),
                           ("memory.stat", f"anon {anon * mib}\nfile {file * mib}\nswapcached 0\n"),
                           ("memory.pressure",
                            f"some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n"
                            f"full avg10=0.00 avg60={pressure:.2f} avg300=0.00 total=1\n")):
            with open(os.path.join(self.unit, name), "w") as fh:
                fh.write(text)

    def _sample(self):
        data = resourcewatch.service_cgroup(root=self.root, procfile=self.procfile)
        return resourcewatch._cgroup_findings(self.store, data, time.time())

    def test_reads_the_unit_accounting(self):
        self._write(1470, 1536, {"low": 0, "high": 7464, "max": 0, "oom": 0, "oom_kill": 0})
        data = resourcewatch.service_cgroup(root=self.root, procfile=self.procfile)
        self.assertEqual(data["path"], "/system.slice/jarvis.service")
        self.assertEqual(data["high"], 1536 * 1024 ** 2)
        self.assertEqual(data["events"]["high"], 7464)
        self.assertEqual(data["stat"]["anon"], 400 * 1024 ** 2)
        self.assertAlmostEqual(data["pressure_full_avg60"], 0.8)

    def test_first_sample_only_records_then_ceiling_is_named(self):
        self._write(1470, 1536, {"high": 7000, "oom_kill": 0})
        self.assertEqual(self._sample(), [])
        self._write(1480, 1536, {"high": 7400, "oom_kill": 0})
        findings = self._sample()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("memory ceiling", findings[0]["title"])
        self.assertIn("400 times", findings[0]["detail"])
        self.assertIn("1536 MiB", findings[0]["detail"])
        self.assertIn("MemoryHigh", findings[0]["detail"])

    def test_brushing_the_ceiling_or_headroom_is_quiet(self):
        self._write(1470, 1536, {"high": 100, "oom_kill": 0})
        self._sample()
        self._write(1470, 1536, {"high": 120, "oom_kill": 0})   # 20 events: a brush
        self.assertEqual(self._sample(), [])
        self._write(600, 1536, {"high": 1000, "oom_kill": 0})   # many events, now well below
        self.assertEqual(self._sample(), [])

    def test_oom_kill_is_high(self):
        self._write(1500, 1536, {"high": 1, "oom_kill": 0})
        self._sample()
        self._write(300, 1536, {"high": 2, "oom_kill": 1})
        findings = self._sample()
        self.assertEqual([f["severity"] for f in findings], ["high"])
        self.assertIn("OOM-killed", findings[0]["title"])

    def test_no_limit_or_no_cgroup_is_silent(self):
        self._write(1470, None, {"high": 0, "oom_kill": 0})
        self._sample()
        self._write(1470, None, {"high": 0, "oom_kill": 0})
        self.assertEqual(self._sample(), [])
        self.assertIsNone(resourcewatch.service_cgroup(root=self.root,
                                                       procfile="/nonexistent"))
        self.assertEqual(resourcewatch._cgroup_findings(self.store, None, time.time()), [])

    def test_audit_survives_an_unreadable_cgroup(self):
        with patch.object(resourcewatch, "service_cgroup", side_effect=RuntimeError("boom")), \
             patch.object(resourcewatch.monitor, "collect_all", return_value=[]):
            findings = resourcewatch.audit(self.store, hosts=("wsl",))
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()


class HistoryVerifyTests(unittest.TestCase):
    """The daily whole-chain verification is its own bounded job; the 45 s
    native ingestion collector only reports when it is overdue."""

    def setUp(self):
        from pathlib import Path

        from jarvis.core.eventlog import EventLog
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(str(self.root / "j.db"))
        self.logdir = self.root / "log"
        self.log = EventLog(self.logdir, writer=True)
        from jarvis.core import event as event_mod
        events = [event_mod.make(host="H", sensor="s", channel="t", generation="g",
                                 record=i, source="test", source_event="1",
                                 time="2026-09-18T12:00:00Z", category="process",
                                 action="start", attrs={"i": i}) for i in (1, 2)]
        self.log.append(events, {"sensor": "s", "channel": "t"})
        seal = getattr(self.log, "seal", None)
        if callable(seal):
            seal(force=True)
        self.log.close()

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def test_ingestion_never_verifies_the_chain(self):
        from jarvis.collectors.telemetry import native
        from jarvis.core.eventlog import EventLog
        log = EventLog(self.logdir, writer=False)
        with patch.object(EventLog, "verify", side_effect=AssertionError("verify called")):
            findings = native._verify(self.store, log)
        self.assertEqual([f["severity"] for f in findings], ["medium"])
        self.assertIn("never been verified", findings[0]["detail"])
        self.store.set_meta(native.VERIFY_META, time.time() - 3600)
        with patch.object(EventLog, "verify", side_effect=AssertionError("verify called")):
            self.assertEqual(native._verify(self.store, log), [])
        self.store.set_meta(native.VERIFY_META, time.time() - native.VERIFY_OVERDUE - 1)
        with patch.object(EventLog, "verify", side_effect=AssertionError("verify called")):
            self.assertIn("h ago", native._verify(self.store, log)[0]["detail"])

    def test_verify_job_records_completion(self):
        from jarvis.collectors.telemetry import history_verify as native
        before = time.time()
        findings = native.verify_history(self.store, root=self.logdir)
        self.assertEqual([f["severity"] for f in findings], ["ok"])
        self.assertGreaterEqual(float(self.store.get_meta(native.VERIFY_META, 0)), before)
        self.assertGreaterEqual(float(self.store.get_meta(native.VERIFY_ATTEMPT_META, 0)), before)

    def test_killed_attempt_backs_off_then_retries(self):
        from jarvis.collectors.telemetry import history_verify as native
        from jarvis.core.eventlog import EventLog
        # A worker killed mid-verify leaves the attempt stamp newer than the
        # completion stamp.
        self.store.set_meta(native.VERIFY_META, time.time() - 2 * 86400)
        self.store.set_meta(native.VERIFY_ATTEMPT_META, time.time() - 120)
        with patch.object(EventLog, "verify", side_effect=AssertionError("verify called")):
            findings = native.verify_history(self.store, root=self.logdir)
        self.assertEqual([f["severity"] for f in findings], ["medium"])
        self.assertIn("did not finish", findings[0]["title"])
        self.store.set_meta(native.VERIFY_ATTEMPT_META, time.time() - native.VERIFY_RETRY - 1)
        findings = native.verify_history(self.store, root=self.logdir)
        self.assertEqual([f["severity"] for f in findings], ["ok"])

    def test_damage_is_critical_and_still_stamped(self):
        from jarvis.collectors.telemetry import history_verify as native
        seg = sorted((self.logdir / "segments").iterdir())[0]
        data = seg.read_bytes()
        seg.write_bytes(data[:-1] + (b"X" if data[-1:] != b"X" else b"Y"))
        findings = native.verify_history(self.store, root=self.logdir)
        self.assertEqual([f["severity"] for f in findings], ["critical"])
        self.assertIn("does not verify", findings[0]["title"])
        self.assertTrue(float(self.store.get_meta(native.VERIFY_META, 0)))

    def test_job_is_registered_in_the_bulk_lane(self):
        from jarvis.core import governor
        from jarvis.service import jobs, schedule, scheduler
        self.assertIn("history_verify", schedule.JOBS)
        self.assertIn("history_verify", scheduler.BULK)
        self.assertIn("history_verify", jobs.RUNNERS if hasattr(jobs, "RUNNERS") else jobs.JOBS)
        self.assertIn("history_verify", governor.GOVERNED_JOBS)
        from jarvis.service import reliability
        spec = reliability.build_specs({"history_verify": schedule.JOBS["history_verify"]})["history_verify"]
        self.assertGreaterEqual(spec.execution_timeout, 120)

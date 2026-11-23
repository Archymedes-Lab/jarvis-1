import subprocess
import threading
import time
import unittest
from unittest import mock

from jarvis.platform import interop_gate, windows
from jarvis.platform.interop_gate import Gate, Refused


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class GateTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.gate = Gate(clock=self.clock)

    def fail(self, n):
        for _ in range(n):
            self.gate.acquire(wait=0)
            self.gate.release(False)

    def test_bounded_concurrency_and_refusal_after_the_wait_budget(self):
        self.gate.acquire(wait=0)
        self.gate.acquire(wait=0)
        with self.assertRaises(Refused) as ctx:
            self.gate.acquire(wait=0)
        self.assertIn("no Windows interop slot", str(ctx.exception))
        self.gate.release(True)
        self.gate.acquire(wait=0)          # a slot came back
        self.assertEqual(self.gate.state()["refused"], 1)

    def test_a_waiter_gets_the_slot_a_finishing_launch_frees(self):
        gate = Gate()                      # real clock: the waiter really waits
        gate.acquire(wait=0)
        gate.acquire(wait=0)
        got = []
        t = threading.Thread(target=lambda: got.append(gate.acquire(wait=5)))
        t.start()
        time.sleep(0.1)
        gate.release(True)
        t.join(5)
        self.assertEqual(got, [False])
        self.assertEqual(gate.active, 2)

    def test_trips_after_consecutive_failures_and_refuses_while_open(self):
        self.fail(interop_gate.TRIP_CONSECUTIVE)
        st = self.gate.state()
        self.assertTrue(st["open"])
        self.assertEqual(st["backoff_s"], interop_gate.BACKOFF_START)
        with self.assertRaises(Refused) as ctx:
            self.gate.acquire(wait=0)
        self.assertIn("backing off", str(ctx.exception))

    def test_one_probe_after_backoff_success_closes(self):
        self.fail(interop_gate.TRIP_CONSECUTIVE)
        self.clock.t += interop_gate.BACKOFF_START + 1
        self.assertTrue(self.gate.acquire(wait=0))       # the probe
        with self.assertRaises(Refused):
            self.gate.acquire(wait=0)                     # only one probe at a time
        self.gate.release(True)
        st = self.gate.state()
        self.assertFalse(st["open"])
        self.assertEqual(st["backoff_s"], 0)
        self.assertFalse(self.gate.acquire(wait=0))

    def test_failed_probe_doubles_backoff_up_to_the_cap(self):
        self.fail(interop_gate.TRIP_CONSECUTIVE)
        seen = []
        for _ in range(8):
            self.clock.t += self.gate.backoff + 1
            self.assertTrue(self.gate.acquire(wait=0))
            self.gate.release(False)
            seen.append(self.gate.backoff)
        self.assertEqual(seen[:3], [60, 120, 240])
        self.assertEqual(max(seen), interop_gate.BACKOFF_MAX)

    def test_degraded_halves_concurrency_and_recovers(self):
        for ok in (True, False, True, False, False, False):
            self.gate.acquire(wait=0)
            self.gate.release(ok)
        st = self.gate.state()
        self.assertTrue(st["degraded"])
        self.assertEqual(st["limit"], interop_gate.DEGRADED_SLOTS)
        self.clock.t += interop_gate.WINDOW_S + 1          # old outcomes age out
        self.assertFalse(self.gate.state()["degraded"])

    def test_refusals_do_not_extend_the_backoff(self):
        self.fail(interop_gate.TRIP_CONSECUTIVE)
        until = self.gate.open_until
        for _ in range(5):
            with self.assertRaises(Refused):
                self.gate.acquire(wait=0)
        self.assertEqual(self.gate.open_until, until)

    def test_refused_is_an_oserror_for_existing_handlers(self):
        self.assertTrue(issubclass(Refused, OSError))


class SpawnTests(unittest.TestCase):
    def setUp(self):
        self.gate = Gate(clock=Clock())
        patches = [mock.patch.object(interop_gate, "GATE", self.gate),
                   mock.patch.object(windows.host, "on_wsl", return_value=True),
                   mock.patch.object(windows, "interop_launcher", return_value=[])]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_spawn(self, result=None, exc=None, **kw):
        with mock.patch.object(windows.subprocess, "run",
                               side_effect=exc, return_value=result) as run:
            try:
                return windows.spawn(["powershell.exe"], timeout=5, **kw), run
            except (OSError, subprocess.TimeoutExpired) as e:
                return e, run

    def test_slot_is_released_when_the_launch_times_out(self):
        out, _ = self.run_spawn(exc=subprocess.TimeoutExpired("powershell.exe", 5))
        self.assertIsInstance(out, subprocess.TimeoutExpired)
        self.assertEqual(self.gate.active, 0)
        self.assertEqual(self.gate.consecutive, 1)

    def test_empty_output_counts_only_when_output_was_expected(self):
        empty = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        self.run_spawn(result=empty)
        self.assertEqual(self.gate.consecutive, 0)
        self.run_spawn(result=empty, expect_output=True)
        self.assertEqual(self.gate.consecutive, 1)

    def test_open_gate_refuses_without_launching(self):
        self.gate.backoff, self.gate.open_until = 30.0, self.gate.clock() + 30
        out, run = self.run_spawn(result=subprocess.CompletedProcess([], 0, b"x", b""))
        self.assertIsInstance(out, Refused)
        run.assert_not_called()

    def test_ungated_launches_bypass_an_open_gate(self):
        self.gate.backoff, self.gate.open_until = 30.0, self.gate.clock() + 30
        out, run = self.run_spawn(result=subprocess.CompletedProcess([], 0, b"x", b""), gated=False)
        self.assertEqual(out.stdout, b"x")
        run.assert_called_once()

    def test_ps_json_records_the_refusal_and_does_not_retry_while_degraded(self):
        failed = []
        with mock.patch.object(windows, "available", return_value=True), \
                mock.patch.object(windows.collection, "failed",
                                  side_effect=lambda k, why: failed.append(why)):
            self.gate.backoff, self.gate.open_until = 30.0, self.gate.clock() + 30
            self.assertIsNone(windows.ps_json("1"))
            self.assertIn("backing off", failed[-1])
            # Degraded but not open: one launch, no immediate retry.
            self.gate.backoff, self.gate.open_until = 0.0, 0.0
            for _ in range(6):
                self.gate.outcomes.append((self.gate.clock(), False))
            empty = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
            with mock.patch.object(windows.subprocess, "run", return_value=empty) as run:
                self.assertIsNone(windows.ps_json("1"))
            run.assert_called_once()
            self.assertIn("not retried", failed[-1])


class CoverageFindingTests(unittest.TestCase):
    def test_degraded_gate_is_a_medium_non_outage_finding_and_healthy_is_silent(self):
        from jarvis.response import alert
        from jarvis.service import coverage
        gate = Gate(clock=Clock())
        with mock.patch.object(interop_gate, "GATE", gate):
            self.assertEqual(coverage._interop_gate_findings(), [])
            for _ in range(interop_gate.TRIP_CONSECUTIVE):
                gate.acquire(wait=0)
                gate.release(False)
            [f] = coverage._interop_gate_findings()
        self.assertEqual(f["severity"], "medium")
        self.assertIn("paused", f["detail"])
        self.assertFalse(alert.is_outage(f))


if __name__ == "__main__":
    unittest.main()

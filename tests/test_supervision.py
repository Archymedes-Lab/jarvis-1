"""Starting the daemon safely: one instance, stopped-on-purpose, and no restart loop."""

import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from jarvis.cli import parser as cli_parser
from jarvis.cli.commands import lifecycle
from jarvis.service import supervision as sup

HOUR = 3600


def state():
    return tempfile.mkdtemp(prefix="argus-sup-")


def free_port_name():
    return 41000 + os.getpid() % 900 + int(time.time() * 1000) % 50


class RestartBudgetTest(unittest.TestCase):
    def test_starts_up_to_the_limit_are_allowed_then_refused(self):
        d, t0 = state(), 1_000_000.0
        for i in range(5):
            ok, n = sup.record_start(d, now=t0 + i, max_starts=5)
            self.assertTrue(ok)
            self.assertEqual(n, i + 1)
        ok, n = sup.record_start(d, now=t0 + 10, max_starts=5)
        self.assertFalse(ok)
        self.assertEqual(n, 5)

    def test_a_refused_start_is_not_recorded_so_the_window_really_expires(self):
        d, t0 = state(), 1_000_000.0
        for i in range(3):
            sup.record_start(d, now=t0 + i, max_starts=3)
        for _ in range(20):                       # a watchdog hammering a crash-looping daemon
            self.assertFalse(sup.record_start(d, now=t0 + 100, max_starts=3)[0])
        self.assertTrue(sup.record_start(d, now=t0 + HOUR + 5, max_starts=3)[0],
                        "an hour after the last allowed start the daemon is tried again")

    def test_old_starts_stop_counting(self):
        d, t0 = state(), 1_000_000.0
        for i in range(5):
            sup.record_start(d, now=t0 + i, max_starts=5)
        ok, n = sup.record_start(d, now=t0 + HOUR + 10, max_starts=5)
        self.assertTrue(ok)
        self.assertEqual(n, 1)

    def test_a_damaged_state_file_does_not_stop_the_daemon_starting(self):
        d = state()
        with open(os.path.join(d, sup.STARTS_FILE), "w") as fh:
            fh.write("{not json")
        self.assertTrue(sup.record_start(d, now=5.0)[0])

    def test_the_limit_can_be_set_for_testing(self):
        with mock.patch.dict(os.environ, {"JARVIS_RESTART_LIMIT": "2"}):
            self.assertEqual(sup.limit(), 2)
        with mock.patch.dict(os.environ, {"JARVIS_RESTART_LIMIT": "nonsense"}):
            self.assertEqual(sup.limit(), sup.LIMIT)


class GateTest(unittest.TestCase):
    def run_gate(self, d, lock=lambda port: True, now=1_000_000.0):
        out = io.StringIO()
        return sup.gate(8787, state_dir=d, now=now, lock=lock, out=out), out.getvalue()

    def test_a_clean_start_goes_ahead_and_is_counted(self):
        d = state()
        code, _ = self.run_gate(d)
        self.assertIsNone(code)
        self.assertEqual(len(sup._read_starts(d)), 1)

    def test_a_second_instance_exits_quietly_and_costs_no_budget(self):
        d = state()
        for _ in range(50):                        # the watchdog firing for hours while the daemon runs
            code, text = self.run_gate(d, lock=lambda port: False)
            self.assertEqual(code, 0)
            self.assertIn("already running", text)
        self.assertEqual(sup._read_starts(d), [], "a duplicate must never use up the restart budget")
        self.assertIsNone(self.run_gate(d)[0], "so a real restart is still allowed afterwards")

    def test_stopped_on_purpose_is_respected_until_started_again(self):
        d = state()
        sup.mark_stopped(d)
        code, text = self.run_gate(d)
        self.assertEqual(code, 0)
        self.assertIn("stopped on purpose", text)
        self.assertEqual(sup._read_starts(d), [])
        self.assertTrue(sup.clear_stopped(d))
        self.assertIsNone(self.run_gate(d)[0])
        self.assertFalse(sup.clear_stopped(d), "clearing twice is harmless")

    def test_a_crash_loop_is_refused_with_a_reason_the_app_can_show(self):
        d = state()
        with mock.patch.dict(os.environ, {"JARVIS_RESTART_LIMIT": "2"}):
            self.assertIsNone(self.run_gate(d, now=1_000_000.0)[0])
            self.assertIsNone(self.run_gate(d, now=1_000_060.0)[0])
            code, text = self.run_gate(d, now=1_000_120.0)
        self.assertEqual(code, sup.EXIT_REFUSED)
        self.assertIn("will not be started again automatically", text)
        self.assertIn("did not stay up", sup.read_refusal(d))
        note = os.path.join(d, sup.REFUSED_NOTE)
        old = time.time() - 3 * HOUR
        os.utime(note, (old, old))
        self.assertEqual(sup.read_refusal(d), "", "an old note is not shown")

    def test_a_successful_start_clears_an_old_refusal_note(self):
        d = state()
        with open(os.path.join(d, sup.REFUSED_NOTE), "w") as fh:
            fh.write("old\n")
        self.assertIsNone(self.run_gate(d)[0])
        self.assertFalse(os.path.exists(os.path.join(d, sup.REFUSED_NOTE)))


@unittest.skipUnless(sys.platform.startswith("win"), "the machine-wide lock is a Windows mutex")
class InstanceLockTest(unittest.TestCase):
    def test_a_second_claim_on_the_same_port_is_refused_across_processes(self):
        port = free_port_name()
        code = ("import sys, time; sys.path.insert(0, %r)\n"
                "from jarvis.service import supervision as s\n"
                "print('held' if s.take_instance_lock(%d) else 'refused', flush=True)\n"
                "time.sleep(20)\n" % (os.getcwd(), port))
        holder = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            self.assertFalse(sup.take_instance_lock(port), "a different process must not get the lock")
            self.assertTrue(sup.take_instance_lock(port + 1000), "another port is independent")
        finally:
            holder.kill()
            holder.wait()

    def test_the_lock_is_released_when_the_owner_dies(self):
        port = free_port_name() + 2000
        code = "import sys; sys.path.insert(0, %r)\nfrom jarvis.service import supervision as s\nassert s.take_instance_lock(%d)\n" % (os.getcwd(), port)
        subprocess.run([sys.executable, "-c", code], check=True, timeout=60)
        self.assertTrue(sup.take_instance_lock(port), "a crashed daemon must not leave the port locked")


class CommandsTest(unittest.TestCase):
    def test_serve_accepts_supervised_and_stop_start_exist(self):
        p = cli_parser.build_parser()
        self.assertTrue(p.parse_args(["serve", "--supervised", "--port", "8800"]).supervised)
        self.assertFalse(p.parse_args(["serve"]).supervised)
        self.assertEqual(p.parse_args(["stop"]).cmd, "stop")
        self.assertEqual(p.parse_args(["start"]).cmd, "start")

    def test_a_refused_supervised_serve_never_opens_the_store(self):
        with mock.patch.object(sup, "gate", return_value=0), \
                mock.patch.object(cli_parser, "Store", side_effect=AssertionError("the store was opened")):
            self.assertEqual(cli_parser.main(["serve", "--supervised"]), 0)

    def test_stop_from_source_marks_the_marker_and_kills_nothing(self):
        d = state()
        with mock.patch.object(sup, "STATE_DIR", d), \
                mock.patch.object(lifecycle, "_hidden", side_effect=AssertionError("must not kill")), \
                mock.patch.object(lifecycle, "_compiled_name", return_value=""):
            self.assertEqual(lifecycle.cmd_stop(mock.Mock(), None), 0)
            self.assertTrue(sup.stopped_on_purpose(d))

    def test_stop_never_names_an_unrelated_program_to_kill(self):
        for name in ("python.exe", "pythonw.exe", "python3.12.exe"):
            with mock.patch.object(lifecycle, "self_executable", return_value="C:/x/" + name):
                self.assertEqual(lifecycle._compiled_name(), "")
        with mock.patch.object(lifecycle, "self_executable", return_value="C:/x/argus.exe"):
            self.assertEqual(lifecycle._compiled_name(), "argus.exe")

    def test_start_clears_the_marker(self):
        # Windows: the scheduled task is enough. The platform is pinned so the test does
        # not depend on the host it runs on.
        d = state()
        sup.mark_stopped(d)
        with mock.patch.object(sup, "STATE_DIR", d), \
                mock.patch.object(lifecycle, "sys", mock.Mock(platform="win32")), \
                mock.patch.object(lifecycle, "_hidden", return_value=mock.Mock(returncode=0)), \
                mock.patch.object(lifecycle.subprocess, "Popen", side_effect=AssertionError("task was enough")):
            args = mock.Mock(port=8787)
            self.assertEqual(lifecycle.cmd_start(args, None), 0)
        self.assertFalse(sup.stopped_on_purpose(d))

    def test_start_without_a_task_runs_the_daemon_supervised_and_clears_the_marker(self):
        d = state()
        sup.mark_stopped(d)
        with mock.patch.object(sup, "STATE_DIR", d), \
                mock.patch.object(lifecycle, "sys", mock.Mock(platform="linux")), \
                mock.patch.object(lifecycle, "_hidden", side_effect=AssertionError("no task off Windows")), \
                mock.patch.object(lifecycle, "self_executable", return_value="/usr/bin/python3"), \
                mock.patch.object(lifecycle.subprocess, "Popen") as popen:
            self.assertEqual(lifecycle.cmd_start(mock.Mock(port=8787), None), 0)
        command = popen.call_args.args[0]
        self.assertIn("--supervised", command, "a started daemon must pass the supervision gate")
        self.assertEqual(command[command.index("--port") + 1], "8787")
        self.assertFalse(sup.stopped_on_purpose(d))


if __name__ == "__main__":
    unittest.main()

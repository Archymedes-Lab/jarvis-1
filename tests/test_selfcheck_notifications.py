import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.response import alert
from jarvis.service import selfcheck


class SelfcheckNotificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'state.db')
        self.clock = patch.object(selfcheck, 'now', return_value=1000000)
        self.now = self.clock.start()
        self.conf = patch.object(alert, 'load_conf', return_value={})
        self.conf.start()
        self.enabled = patch.object(alert, 'enabled', return_value=True)
        self.enabled.start()
        self.sender = patch.object(alert, 'deliver', return_value='')
        self.send = self.sender.start()
        self.verdict = dict(healthy=False, problems=['stalled'], newest_kind='test',
                            newest_ts=999999, age=1, active_state='active', scope='system')

    def tearDown(self):
        self.sender.stop(); self.enabled.stop(); self.conf.stop(); self.clock.stop()
        self.tmp.cleanup()

    def notify(self, healthy=False):
        return selfcheck._notify(self.path, {**self.verdict, 'healthy': healthy})

    def test_persistent_outage_has_finite_escalation(self):
        self.notify(); self.notify()
        self.assertEqual(self.send.call_count, 1)
        for step in (3600, 18000, 64800):
            self.now.return_value += step
            self.notify(); self.notify()
        self.assertEqual(self.send.call_count, 4)
        self.now.return_value += 86400 * 30
        self.notify()
        self.assertEqual(self.send.call_count, 4)

    def test_undelivered_outage_recovery_resets_clock(self):
        self.send.return_value = 'unavailable'
        self.notify()
        self.now.return_value += 86400
        self.notify(healthy=True)
        self.send.return_value = ''
        self.notify()
        store = Store(self.path)
        try:
            self.assertEqual(int(store.get_meta('selfcheck_first_down')), self.now.return_value)
            self.assertEqual(int(store.get_meta('selfcheck_escalation')), 0)
        finally:
            store.close()

    def test_failed_recovery_retries_without_flooding(self):
        self.notify()
        self.send.return_value = 'unavailable'
        self.notify(healthy=True)
        self.notify(healthy=True)
        self.assertEqual(self.send.call_count, 2)
        self.now.return_value += 300
        self.send.return_value = ''
        self.notify(healthy=True); self.notify(healthy=True)
        self.assertEqual(self.send.call_count, 3)
        self.notify()
        self.assertEqual(self.send.call_count, 4)


class SelfcheckNotifySocketTests(unittest.TestCase):
    """systemctl children must never inherit the daemon's NOTIFY_SOCKET.

    The manager logs 'reception only permitted for main PID' for every such
    call; worse, a child notification could be mistaken for the daemon's own
    watchdog ping. Same strip as coverage._cmd.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_with_env(self, env, side_effect=None):
        from unittest.mock import patch
        seen = {}

        def fake_run(cmd, **kwargs):
            seen.update(kwargs.get("env") or {})
            seen["_cmd"] = cmd
            if isinstance(side_effect, Exception):
                raise side_effect
            return type("R", (), {"returncode": 0, "stdout": "active\n",
                                  "stderr": ""})()

        with patch.object(selfcheck.subprocess, "run", side_effect=fake_run):
            with patch.dict(os.environ, env, clear=False):
                rc, out, _ = selfcheck._run(["systemctl", "show", "x"], env=None)
        return rc, out, seen

    def test_notify_socket_stripped_from_inherited_environment(self):
        rc, out, seen = self.run_with_env(
            {"NOTIFY_SOCKET": "/run/systemd/notify",
             "WATCHDOG_USEC": "1000000", "WATCHDOG_PID": "206"})
        self.assertEqual((rc, out), (0, "active"))
        for key in ("NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"):
            self.assertNotIn(key, seen)

    def test_explicit_env_also_stripped(self):
        from unittest.mock import patch
        seen = {}

        def fake_run(cmd, **kwargs):
            seen.update(kwargs.get("env") or {})
            return type("R", (), {"returncode": 0, "stdout": "ok\n",
                                  "stderr": ""})()

        with patch.object(selfcheck.subprocess, "run", side_effect=fake_run):
            env = dict(os.environ, NOTIFY_SOCKET="/run/systemd/notify")
            rc, out, _ = selfcheck._run(["systemctl"], env=env)
            self.assertEqual((rc, out), (0, "ok"))
            self.assertNotIn("NOTIFY_SOCKET", seen)
            self.assertIn("PATH", seen)

    def test_spawn_failure_still_returns_error_tuple(self):
        rc, out, seen = self.run_with_env(
            {"NOTIFY_SOCKET": "/run/systemd/notify"},
            side_effect=OSError("no bus"))
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertNotIn("NOTIFY_SOCKET", seen)

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jarvis.collectors.telemetry import sysmon
from jarvis.core import collection
from jarvis.core.store import Store
from jarvis.platform import windows as collect_windows
from jarvis.service import coverage
from jarvis.service.protection import health

# Never ask the live Windows host for Sysmon's service state from a unit test;
# an empty answer judges nothing (sysmon._service_findings).
_status_patch = None


def setUpModule():
    global _status_patch
    from unittest import mock as _mock

    from jarvis.collectors.telemetry import sysmon as _sysmon
    _status_patch = _mock.patch.object(_sysmon, "status", return_value={})
    _status_patch.start()


def tearDownModule():
    _status_patch.stop()


class CollectionTests(unittest.TestCase):
    def test_daemon_health_commands_do_not_inherit_notify_authority(self):
        completed = SimpleNamespace(stdout="active\n")
        notify = {"NOTIFY_SOCKET": "/run/systemd/notify",
                  "WATCHDOG_USEC": "600000000", "WATCHDOG_PID": "123"}
        with patch.dict(coverage.os.environ, notify), \
             patch.object(coverage.subprocess, "run", return_value=completed) as run:
            self.assertEqual(coverage._cmd(["systemctl", "is-active", "x"]),
                             "active")
            child_env = run.call_args.kwargs["env"]
            for key in notify:
                self.assertNotIn(key, child_env)
                self.assertEqual(coverage.os.environ.get(key), notify[key])

    def test_two_enabled_service_managers_are_a_visibility_finding(self):
        def command(args, timeout=10):
            if args[:2] == ["systemctl", "--user"] and "is-active" in args:
                return "active"
            if args[:2] == ["systemctl", "--user"] and "is-enabled" in args:
                return "enabled"
            if args[:2] == ["systemctl", "is-active"]:
                return "active"
            if args[:2] == ["systemctl", "is-enabled"]:
                return "enabled"
            if "MainPID" in args:
                return "0"
            if args and args[0] == "loginctl":
                return "Linger=yes"
            return ""

        with patch.object(coverage.shutil, "which", return_value="/bin/systemctl"), \
             patch.object(coverage, "_cmd", side_effect=command):
            found = coverage.daemon_health()
        duplicate = [f for f in found if "two JARVIS" in f["title"]]
        self.assertEqual(len(duplicate), 1)
        self.assertEqual(duplicate[0]["severity"], "high")

    def test_nested_contexts_do_not_leak(self):
        with collection.observe() as outer:
            collection.succeeded('linux')
            with collection.observe() as inner:
                collection.failed('win', 'down')
            self.assertEqual(inner.status, 'unavailable')
            self.assertEqual(outer.status, 'complete')

    def test_bridge_failure_is_explicit_even_when_helper_returns_none(self):
        with collection.observe() as observation, patch.object(collect_windows, 'available', return_value=False):
            self.assertIsNone(collect_windows.ps_json('unused'))
        self.assertEqual(observation.status, 'unavailable')

    def test_failed_sysmon_query_preserves_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(str(Path(directory)/'test.db'))
            store.set_meta('sysmon_last_run', 50)
            # No native sensor for this case: force the PowerShell fallback path,
            # whose failed query must not advance the cursor.
            with patch.object(sysmon, '_native', return_value=None), \
                 patch.object(sysmon, 'status', return_value={'installed': True, 'readable': True}), \
                 patch.object(sysmon, '_fetch', return_value={}):
                with collection.observe() as observation:
                    result = sysmon.audit(store, incremental=True)
            self.assertEqual(int(store.get_meta('sysmon_last_run')), 50)
            self.assertEqual(observation.status, 'unavailable')
            self.assertEqual(result[0]['severity'], 'high')
            store.close()


class ProtectionHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name)/'state.db')
        self.store = Store(self.path)
        self.scheduler = SimpleNamespace(heartbeat=1000, current=None, hosts=('win',), is_alive=lambda: True)

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def record(self, kind, findings=None, error=''):
        with patch('jarvis.core.store.now', return_value=1000):
            self.store.save_snapshot(kind, findings or [], error=error)

    def test_live_is_not_protected_when_windows_is_blind(self):
        self.record('scan'); self.record('bridge', error='Windows unavailable'); self.record('sysmon')
        result = health(self.path, self.scheduler, 1010)
        self.assertTrue(result['live']); self.assertFalse(result['healthy'])

    def test_visibility_finding_blocks_false_green(self):
        self.record('scan'); self.record('bridge'); self.record('sysmon', [{'category':'visibility','severity':'high','title':'unreadable'}])
        self.assertFalse(health(self.path, self.scheduler, 1010)['protection_healthy'])

    def test_stale_and_missing_observations_are_not_healthy(self):
        self.assertFalse(health(self.path, self.scheduler, 1010)['healthy'])
        for kind in ('scan','bridge','sysmon','native'): self.record(kind)
        self.assertTrue(health(self.path, self.scheduler, 1010)['healthy'])
        self.assertFalse(health(self.path, self.scheduler, 1500)['healthy'])

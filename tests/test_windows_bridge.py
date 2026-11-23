import base64
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from jarvis.platform import windows as collect_windows


class BridgeTests(unittest.TestCase):
    def test_host_cpu_capacity_survives_process_collection(self):
        payload = {'logical_cpus': 16, 'procs': [
            {'pid': 0, 'name': 'System Idle Process', 'cpu': 5000},
            {'pid': 42, 'name': 'worker.exe', 'cpu': 100,
             'started': '2026-09-19T10:00:00.0000000Z'}],
                   'process_observed_at': '2026-09-19T10:01:00.0000000Z', 'conns': []}
        result = SimpleNamespace(stdout=base64.b64encode(json.dumps(payload).encode()))
        with patch.object(collect_windows, 'available', return_value=True), \
             patch.object(collect_windows.subprocess, 'run', return_value=result):
            processes = collect_windows.collect()
        self.assertEqual([p['logical_cpus'] for p in processes], [16, 16])
        self.assertEqual(processes[1]['cpu_seconds'], 100)
        self.assertEqual(processes[1]['started'], '2026-09-19T10:00:00.0000000Z')
        self.assertEqual(processes[1]['observed_at'], '2026-09-19T10:01:00.0000000Z')
        # PID 0 is still available for unattributed socket monitoring; only
        # the resource consumer excludes its idle-time counter.
        self.assertEqual(processes[0]['pid'], 0)

    def test_cached_path_on_unreadable_mount_is_not_available(self):
        with patch.object(collect_windows, '_PS', '/missing/powershell.exe'), \
             patch.object(collect_windows.os.path, 'isfile', return_value=False), \
             patch.object(collect_windows, 'ensure_interop', return_value=True):
            self.assertFalse(collect_windows.available())

    def test_readable_binary_still_requires_interop(self):
        with patch.object(collect_windows, '_PS', '/windows/powershell.exe'), \
             patch.object(collect_windows.os.path, 'isfile', return_value=True), \
             patch.object(collect_windows, 'ensure_interop', return_value=False):
            self.assertFalse(collect_windows.available())

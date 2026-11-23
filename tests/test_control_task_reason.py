"""A declared Argus task that fails verification says why, in the part a person reads.

2026-10-30: the reason was appended after the task's command line and then
cut at 90 characters, so the finding read "jarvis elevated broker → C:\\WINDOWS\\
System32\\conhost.exe --headless ..." and never said what failed.
"""

import unittest
from unittest import mock

from jarvis.collectors.persistence import control
from jarvis.platform.provenance import persistence

LONG = ('C:\\WINDOWS\\System32\\conhost.exe --headless "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\'
        'powershell.exe" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File '
        '"C:\\ProgramData\\Jarvis\\Broker\\jarvis-elevated-broker.ps1" -Run')


class TaskReason(unittest.TestCase):
    def run_audit(self, name, verdict):
        task = {"name": name, "path": "\\", "actions": [{"execute": LONG.split(" ", 1)[0], "arguments": LONG.split(" ", 1)[1]}]}
        with mock.patch.object(control, "ps_json", return_value={"tasks": [task]}), \
                mock.patch.object(control, "verified_maintenance_task", return_value=verdict):
            return [f for f in control.audit_windows() if f["title"].endswith("scheduled task")]

    def test_the_failed_check_leads_the_detail(self):
        name = sorted(persistence.CRITICAL_ON_MISMATCH)[0]
        out = self.run_audit(name, (False, "script hash differs from the release"))
        self.assertEqual(out[0]["severity"], "critical")
        self.assertIn("verification failed: script hash differs from the release", out[0]["detail"])
        self.assertTrue(out[0]["detail"].startswith(f"{name}: verification failed"), out[0]["detail"])

    def test_an_undeclared_task_reads_as_before(self):
        out = self.run_audit("some other task", (False, "not a declared task"))
        self.assertTrue(out[0]["detail"].startswith("some other task → "), out[0]["detail"])
        self.assertNotIn("verification failed", out[0]["detail"])


if __name__ == "__main__":
    unittest.main()

"""Windows-side outage handling (2026-10-12).

"JARVIS monitoring unavailable" was raised for a daemon that was running with
one required source degraded, and the reviver restarted daemons still in their
cold start. The native sensor's Sysmon reads timed out because every batch
re-ran an EventRecordID XPath predicate over the whole log.

These checks run the real PowerShell and C# on Windows, isolated from live
supervisor state (temporary -StateRoot, mocked delivery, stub endpoint). They
skip when Windows interop is unavailable, e.g. in the restricted sandbox.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
WORK_PARENT = "/mnt/c/Users/Public"


def _windows_path(path):
    return subprocess.run(["wslpath", "-w", str(path)], capture_output=True,
                          text=True, check=True, timeout=10).stdout.strip()


def _interop():
    if not (os.path.exists(POWERSHELL) and os.path.isdir(WORK_PARENT)):
        return False
    try:
        out = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", "'ok'"],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and "ok" in out.stdout


@unittest.skipUnless(_interop(), "Windows PowerShell interop unavailable")
class WindowsSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="jarvis-test-", dir=WORK_PARENT))
        self.addCleanup(shutil.rmtree, self.work, True)

    def _run(self, script, *args, timeout=240):
        out = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", _windows_path(script), *args],
            capture_output=True, text=True, timeout=timeout)
        return out.returncode, (out.stdout + out.stderr).replace("\r", "")

    def test_reviver_and_health_monitor_outage_decisions(self):
        for name in ("jarvis-reviver.ps1", "jarvis-health-monitor.ps1",
                     "jarvis-wake-watchdog.ps1"):
            shutil.copy(ROOT / name, self.work / name)
        harness = self.work / "supervisors.Tests.ps1"
        shutil.copy(ROOT / "tests" / "windows" / "supervisors.Tests.ps1", harness)
        scratch = self.work / "run"
        scratch.mkdir()
        rc, out = self._run(harness, "-Dir", _windows_path(self.work),
                            "-Work", _windows_path(scratch))
        self.assertEqual(rc, 0, out)
        self.assertIn("supervisor checks passed", out)

    def test_native_sensor_positional_resume(self):
        (self.work / "tests").mkdir()
        shutil.copy(ROOT / "windows-sensor" / "JarvisSensor.cs", self.work / "JarvisSensor.cs")
        for name in ("PositionResume.cs", "TimeoutRetry.cs"):
            shutil.copy(ROOT / "windows-sensor" / "tests" / name, self.work / "tests" / name)
        harness = self.work / "sensor.Tests.ps1"
        shutil.copy(ROOT / "tests" / "windows" / "sensor.Tests.ps1", harness)
        rc, out = self._run(harness, "-Dir", _windows_path(self.work))
        self.assertEqual(rc, 0, out)
        self.assertIn("position resume checks passed", out)
        self.assertIn("timeout retry checks passed", out)


if __name__ == "__main__":
    unittest.main()

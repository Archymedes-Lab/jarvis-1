"""A stale Windows-drive mount must be one diagnosis, not many mysteries.

Load-bearing invariants:

  * every /mnt/c reader consults the mount gate instead of hammering a sick
    mount with failing syscalls (the 60s native job especially);
  * a dead mount is reported as a dead mount — never as "sensor not
    installed", never as an uncaught traceback, never as silent coverage;
  * the manager-visible diagnosis names the fix (wsl --shutdown), because the
    trigger is a host transition (sleep/hibernate, wedged 9P), not an
    intrusion and not anything JARVIS wrote — JARVIS never touches another
    program's policy files.
"""

import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.platform import mounts


class GateTests(unittest.TestCase):
    def setUp(self):
        mounts.reset()
        self.addCleanup(mounts.reset)

    def test_errno_maps_to_verdicts(self):
        with mock.patch.object(mounts.os, "stat", side_effect=OSError(errno.EIO, "x")):
            self.assertEqual(mounts.state("/mnt/c"), mounts.STALE)
        mounts.reset()
        with mock.patch.object(mounts.os, "stat", side_effect=OSError(errno.ENOENT, "x")):
            self.assertEqual(mounts.state("/mnt/c"), mounts.MISSING)
        mounts.reset()
        with mock.patch.object(mounts.os, "stat", side_effect=OSError(errno.EPERM, "x")):
            self.assertEqual(mounts.state("/mnt/c"), mounts.RESTRICTED)
        mounts.reset()
        with mock.patch.object(mounts.os, "stat", return_value=object()):
            self.assertEqual(mounts.state("/mnt/c"), mounts.HEALTHY)

    def test_verdict_is_cached_briefly_then_rechecked(self):
        calls = []
        real = mounts._probe

        def probe(path):
            calls.append(path)
            return real(path)

        with mock.patch.object(mounts, "_probe", side_effect=probe):
            mounts.state("/mnt/c", now=1000.0)
            mounts.state("/mnt/c", now=1000.0 + 10.0)
            self.assertEqual(len(calls), 1)
            mounts.state("/mnt/c", now=1000.0 + 61.0)
            self.assertEqual(len(calls), 2)

    def test_gate_never_raises(self):
        with mock.patch.object(mounts.os, "stat", side_effect=RuntimeError("weird")):
            self.assertEqual(mounts.state("/mnt/c"), mounts.STALE)
        self.assertIn("wsl --shutdown", mounts.diagnose("/mnt/c"))

    def test_path_classification(self):
        self.assertTrue(mounts.under_windows_drive("/mnt/c/ProgramData/x"))
        self.assertTrue(mounts.under_windows_drive("/mnt/c"))
        self.assertFalse(mounts.under_windows_drive(str(Path.home() / "x")))
        self.assertFalse(mounts.under_windows_drive("/tmp/spool"))


class SpoolIngestTests(unittest.TestCase):
    def setUp(self):
        mounts.reset()
        self.addCleanup(mounts.reset)

    def test_stale_spool_returns_access_error_not_an_exception(self):
        from jarvis.platform.native import ingest
        with tempfile.TemporaryDirectory() as tmp:
            spool = Path(tmp) / "spool"
            spool.mkdir()
            with mock.patch.object(mounts, "under_windows_drive", return_value=True), \
                 mock.patch.object(mounts, "windows_drive", return_value=mounts.STALE), \
                 mock.patch.object(Path, "iterdir",
                                   side_effect=AssertionError("must not list a dead mount")):
                report = ingest.run(log=mock.Mock(), spool=spool)
            self.assertTrue(report["mount_stale"])
            self.assertIn("wsl --shutdown", report["access_error"])
            self.assertEqual(report["channels"], [])

    def test_eio_stat_is_mount_outage_not_missing_sensor(self):
        from jarvis.platform.native import ingest
        with tempfile.TemporaryDirectory() as tmp:
            spool = Path(tmp) / "spool"
            with mock.patch.object(Path, "stat",
                                    side_effect=OSError(errno.EIO, "stale")), \
                 mock.patch.object(mounts, "under_windows_drive", return_value=True):
                report = ingest.run(log=mock.Mock(), spool=spool)
            self.assertTrue(report["mount_stale"])
            self.assertIsNot(report["installed"], True)

    def test_legacy_listing_eio_is_caught(self):
        from jarvis.platform.native import ingest
        with tempfile.TemporaryDirectory() as tmp:
            spool = Path(tmp) / "spool"
            spool.mkdir()
            with mock.patch.object(Path, "iterdir",
                                    side_effect=OSError(errno.EIO, "stale")), \
                 mock.patch.object(ingest, "read_health", return_value=None), \
                 mock.patch.object(mounts, "under_windows_drive", return_value=True), \
                 mock.patch.object(mounts, "windows_drive", return_value=mounts.HEALTHY):
                report = ingest.run(log=mock.Mock(), spool=spool)
            self.assertTrue(report["mount_stale"])
            self.assertIn("wsl --shutdown", report["access_error"])


class NativeCollectorTests(unittest.TestCase):
    def setUp(self):
        mounts.reset()
        self.addCleanup(mounts.reset)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from jarvis.core.store import Store
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)

    def test_stale_mount_is_one_medium_finding_without_touching_spool(self):
        from jarvis.collectors.telemetry import native
        with mock.patch.object(mounts, "under_windows_drive", return_value=True), \
             mock.patch.object(mounts, "windows_drive", return_value=mounts.STALE), \
             mock.patch("jarvis.platform.native.ingest.run",
                        side_effect=AssertionError("must not list a dead mount")) as run, \
             mock.patch.object(native, "_open_writer",
                               side_effect=AssertionError("must not open writer")):
            # _open_writer is bypassed by the gate; patch to prove it.
            findings = native.audit(self.store, hosts=("win",),
                                    root=os.path.join(self.tmp.name, "eventlog"))
            run.assert_not_called()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("mount is stale", findings[0]["title"])
        self.assertIn("wsl --shutdown", findings[0]["detail"])

    def test_report_level_stale_mount_maps_to_the_same_finding(self):
        from jarvis.collectors.telemetry import native
        from jarvis.platform.native import ingest
        # Hermetic: the preflight would read this machine's real spool (absent
        # on any machine without the sensor, and in the renamed Argus tree).
        with mock.patch.object(mounts, "under_windows_drive", return_value=False), \
             mock.patch.object(ingest, "preflight", return_value={"installed": True}), \
             mock.patch.object(ingest, "run", return_value={
                 "installed": False, "mount_stale": True,
                 "access_error": mounts.stale_detail(), "channels": [],
                 "health": None, "batches": 0, "events": 0}):
            findings = native.audit(self.store, hosts=("win",),
                                    root=os.path.join(self.tmp.name, "eventlog"))
        self.assertEqual(len(findings), 1)
        self.assertIn("mount is stale", findings[0]["title"])


class CoverageAndToolchainTests(unittest.TestCase):
    def setUp(self):
        mounts.reset()
        self.addCleanup(mounts.reset)

    def test_visibility_names_the_stale_mount_once(self):
        from jarvis.service import coverage
        with mock.patch.object(mounts, "windows_drive", return_value=mounts.STALE):
            out = coverage.visibility()
        hit = [f for f in out if f["title"] == "Windows drive mount is stale"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "medium")
        self.assertIn("wsl --shutdown", hit[0]["detail"])

    def test_no_mount_finding_when_healthy(self):
        from jarvis.service import coverage
        with mock.patch.object(mounts, "windows_drive", return_value=mounts.HEALTHY):
            out = coverage.visibility()
        self.assertFalse([f for f in out if f["title"] == "Windows drive mount is stale"])

    def test_windows_profiles_walk_is_skipped_while_stale(self):
        from jarvis.collectors.host.toolchain import mcp
        with mock.patch.object(mounts, "windows_drive", return_value=mounts.STALE), \
             mock.patch("glob.glob",
                        side_effect=AssertionError("must not glob a dead mount")):
            self.assertEqual(mcp._windows_profiles(), [])


class HealthMonitorWordingTests(unittest.TestCase):
    def setUp(self):
        mounts.reset()
        self.addCleanup(mounts.reset)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _unreadable(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        return path

    def test_unreadable_state_names_mount_only_for_drive_paths(self):
        from jarvis.service import supervisors
        plain = self._unreadable(os.path.join(self.tmp.name, "s.json"))
        out = {f["title"]: f for f in supervisors.audit_health_monitor(plain, now=1_800_000_000)}
        f = out["the independent Windows monitor's state is unreadable"]
        self.assertNotIn("wsl --shutdown", f["detail"])
        with mock.patch.object(mounts, "under_windows_drive", return_value=True), \
             mock.patch.object(mounts, "windows_drive", return_value=mounts.STALE):
            out = {f["title"]: f for f in supervisors.audit_health_monitor(plain, now=1_800_000_000)}
        f = out["the independent Windows monitor's state is unreadable"]
        self.assertIn("wsl --shutdown", f["detail"])


if __name__ == "__main__":
    unittest.main()

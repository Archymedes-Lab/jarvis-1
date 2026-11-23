"""A deleted main executable is harmless only with current byte evidence."""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from jarvis.collectors.process import detect
from jarvis.platform import executable_identity, linux


class ReplacementEvidenceTests(unittest.TestCase):
    def setUp(self):
        scratch = os.path.join(os.path.expanduser("~"), ".cache", "jarvis-tests")
        os.makedirs(scratch, mode=0o700, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.exe = os.path.join(self.tmp.name, "worker")
        shutil.copy2(shutil.which("sleep"), self.exe)
        self.proc = subprocess.Popen([self.exe, "30"])
        self.addCleanup(self.proc.wait)
        self.addCleanup(self.proc.kill)
        time.sleep(0.2)

    def replace(self, source):
        fresh = self.exe + ".new"
        shutil.copy2(source, fresh)
        os.replace(fresh, self.exe)
        return os.readlink(f"/proc/{self.proc.pid}/exe")

    def test_identical_reinstall_is_evidence_but_raw_path_remains(self):
        mapped = self.replace(shutil.which("sleep"))
        self.assertTrue(executable_identity.replaced_identically(self.proc.pid, mapped))
        self.assertTrue(mapped.endswith(" (deleted)"))

    def test_changed_or_unreadable_replacement_fails_closed(self):
        mapped = self.replace(shutil.which("true"))
        self.assertFalse(executable_identity.replaced_identically(self.proc.pid, mapped))
        os.remove(self.exe)
        self.assertFalse(executable_identity.replaced_identically(self.proc.pid, mapped))

    def test_pid_identity_change_fails_closed(self):
        mapped = self.replace(shutil.which("sleep"))
        with mock.patch.object(executable_identity, "_start_time",
                               side_effect=["old", "new"]):
            self.assertFalse(executable_identity.replaced_identically(self.proc.pid, mapped))

    def test_installed_path_swap_during_read_fails_closed(self):
        mapped = self.replace(shutil.which("sleep"))
        digest = executable_identity._digest
        calls = 0

        def swap_after_read(fh):
            nonlocal calls
            value = digest(fh)
            calls += 1
            if calls == 2:
                fresh = self.exe + ".swapped"
                shutil.copy2(shutil.which("sleep"), fresh)
                os.replace(fresh, self.exe)
            return value

        with mock.patch.object(executable_identity, "_digest", side_effect=swap_after_read):
            self.assertFalse(executable_identity.replaced_identically(self.proc.pid, mapped))

    def test_oversized_replacement_fails_closed_without_hashing(self):
        mapped = self.replace(shutil.which("sleep"))
        with open(self.exe, "ab") as fh:
            fh.truncate(executable_identity.MAX_COMPARE_BYTES + 1)
        with mock.patch.object(executable_identity, "_digest") as digest:
            self.assertFalse(executable_identity.replaced_identically(self.proc.pid, mapped))
        digest.assert_not_called()

    def test_measured_sysmon_size_fits_bounded_comparison(self):
        measured_bytes = 31_693_824
        self.assertLessEqual(measured_bytes, executable_identity.MAX_COMPARE_BYTES)
        self.assertEqual(executable_identity.MAX_COMPARE_BYTES, 32 << 20)
        with tempfile.TemporaryFile() as fh:
            fh.truncate(measured_bytes)
            fh.seek(0)
            self.assertEqual(len(executable_identity._digest(fh)), 32)


class ScanReconciliationTests(unittest.TestCase):
    def test_process_scoring_requires_explicit_verified_linux_boolean(self):
        p = {"host": "wsl", "pid": 42, "fp": "known", "exe": "/opt/tool (deleted)",
             "name": "tool", "cmdline": "tool", "script": "", "conns": []}
        self.assertIn("deleted-binary", detect.traits(p))
        self.assertNotIn("deleted-binary", detect.traits({**p,
            "deleted_replaced_identically": True}))
        self.assertEqual(detect.assess(p, {"known"}, set())["severity"], "high")
        self.assertEqual(detect.assess({**p, "deleted_replaced_identically": True},
                                       {"known"}, set())["severity"], "low")
        self.assertIn("deleted-binary", detect.traits({**p,
            "host": "win", "deleted_replaced_identically": True}))
        self.assertIn("deleted-binary", detect.traits({**p, "exe": "/tmp/tool (deleted)",
            "deleted_replaced_identically": False}))

    def test_collector_limits_comparisons_and_keeps_unchecked_processes(self):
        pids = [42001 + i for i in range(linux.MAX_REPLACEMENT_CHECKS + 1)]
        status = "Name:\tworker\nUid:\t1000\nPPid:\t1\nVmRSS:\t1 kB\n"
        stat_line = "42001 (worker) S " + " ".join(["0"] * 30)

        def read(path, binary=False):
            if path.endswith("/status"):
                return status
            if path.endswith("/cmdline"):
                return b"worker\x00" if binary else ""
            if path.endswith("/stat"):
                return stat_line
            return b"" if binary else ""

        with mock.patch.object(linux.os, "listdir", return_value=[str(p) for p in pids]), \
             mock.patch.object(linux.os, "readlink", return_value="/opt/worker (deleted)"), \
             mock.patch.object(linux, "read_file", side_effect=read), \
             mock.patch.object(linux, "replaced_identically", return_value=True) as check:
            rows = linux.collect(with_sockets=False)
        self.assertEqual(len(rows), len(pids))
        self.assertEqual(check.call_count, linux.MAX_REPLACEMENT_CHECKS)
        self.assertTrue(all(r["deleted_replaced_identically"] for r in rows[:-1]))
        self.assertFalse(rows[-1]["deleted_replaced_identically"])
        self.assertIn("deleted-binary", detect.traits(rows[-1]))

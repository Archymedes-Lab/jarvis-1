"""Watchdog task verification from a sealed release built out of a staging clone.

2026-09-24: a narrow release named its staging clone as the checkout, so the
reviver and wake watchdog (installed with -RepoRoot <checkout>) read as
critical persistence. Arguments are pinned to the real checkout; script
fingerprints to the sealed release copy, so an unreleased edit in the
user-editable checkout (which the tasks self-copy from) is not accepted.
"""
import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.persistence import trusted_tasks as tt

LOCAL = r"C:\Users\chris\AppData\Local"
DATA = {"currentUser": "DESKTOP\\chris", "localAppData": LOCAL}


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.release = os.path.join(self.tmp.name, "release")
        self.checkout = os.path.join(self.tmp.name, "home", "jarvis")
        for root in (self.release, self.checkout):
            os.makedirs(root)
            with open(os.path.join(root, "jarvis-wake-watchdog.ps1"), "w") as fh:
                fh.write("# reviewed wake watchdog\n")
        patches = [mock.patch.object(tt, "REPO_ROOT", self.release),
                   mock.patch.object(tt, "SOURCE_ROOT", self.checkout)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def task(self, repo_root, script_root):
        return {"name": "jarvis wake watchdog", "user": "DESKTOP\\chris",
                "runLevel": "Limited", "logonType": "Interactive",
                "actions": [{"execute": "powershell.exe", "arguments": (
                    "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass "
                    f'-File "{LOCAL}\\WSLKeepalive\\jarvis-wake-watchdog.ps1" -Distro "Ubuntu" '
                    f'-RepoRoot "{repo_root}" -RecoverInterop true'),
                    "targetHash": tt.normalized_text_hash(
                        os.path.join(script_root, "jarvis-wake-watchdog.ps1"))}]}

    def test_task_installed_from_the_checkout_verifies_under_the_release(self):
        ok, why = tt.verified_maintenance_task(self.task(self.checkout, self.release), DATA)
        self.assertTrue(ok, why)

    def test_task_pointing_elsewhere_is_rejected(self):
        ok, why = tt.verified_maintenance_task(
            self.task(os.path.join(self.tmp.name, "staging"), self.release), DATA)
        self.assertFalse(ok)
        self.assertIn("arguments", why)

    def test_unreleased_edit_in_the_checkout_is_rejected(self):
        with open(os.path.join(self.checkout, "jarvis-wake-watchdog.ps1"), "a") as fh:
            fh.write("Invoke-Expression $payload\n")
        ok, why = tt.verified_maintenance_task(self.task(self.checkout, self.checkout), DATA)
        self.assertFalse(ok)
        self.assertIn("fingerprint", why)

    def test_missing_release_copy_is_rejected(self):
        os.unlink(os.path.join(self.release, "jarvis-wake-watchdog.ps1"))
        ok, _ = tt.verified_maintenance_task(self.task(self.checkout, self.checkout), DATA)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()

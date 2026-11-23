"""Nothing may assume this machine's account name (2026-10-27 QC).

Shipped code fell back to the user "chris" in four places: the Windows profile
JARVIS reads, the evidence collector's PowerShell history path, the resource
watcher's name for its own engine, and the root repair helper's /mnt/c mount
owner. On anyone else's machine each read the wrong profile, misnamed the
engine, or crashed (pwd.getpwnam('chris') raises KeyError).
"""
import importlib.machinery
import importlib.util
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.process import resourcewatch
from jarvis.platform import host

ROOT = Path(__file__).resolve().parents[1]


def profiles(root, *names):
    for name in names:
        (Path(root) / name / "AppData" / "Local").mkdir(parents=True)


class WindowsUserTests(unittest.TestCase):
    def resolve(self, users, login, env=None):
        with mock.patch.object(host, "KIND", "wsl"), \
                mock.patch.object(host, "users_dir", return_value=users), \
                mock.patch.dict(os.environ, env or {}, clear=True), \
                mock.patch("pwd.getpwuid", return_value=mock.Mock(pw_name=login)):
            return host.windows_user()

    def test_explicit_setting_wins(self):
        with tempfile.TemporaryDirectory() as d:
            profiles(d, "alice", "bob")
            self.assertEqual(self.resolve(d, "alice", {"JARVIS_WINDOWS_USER": "bob"}), "bob")
            self.assertEqual(self.resolve(d, "alice", {"WSL_USER": "bob"}), "bob")

    def test_linux_login_matching_a_profile(self):
        with tempfile.TemporaryDirectory() as d:
            # This machine's shape: the person plus a sandbox account.
            profiles(d, "chris", "CodexSandboxOffline", "Public", "Default")
            self.assertEqual(self.resolve(d, "chris"), "chris")

    def test_the_only_real_profile(self):
        with tempfile.TemporaryDirectory() as d:
            profiles(d, "Maria", "Public", "Default", "Default User")
            self.assertEqual(self.resolve(d, "maria-linux"), "Maria")

    def test_ambiguous_is_unknown_never_a_guess(self):
        with tempfile.TemporaryDirectory() as d:
            profiles(d, "alice", "bob")
            self.assertEqual(self.resolve(d, "carol"), "")

    def test_no_windows_drive_is_unknown(self):
        self.assertEqual(self.resolve("/nonexistent/Users", "chris"), "")
        self.assertEqual(self.resolve("", "chris"), "")

    def test_unknown_user_gives_no_profile_path(self):
        with mock.patch.object(host, "KIND", "wsl"), \
                mock.patch.object(host, "windows_user", return_value=""):
            path = host.local_appdata("Jarvis", "x.json")
        self.assertNotIn("chris", path)
        self.assertNotIn("\\Users\\\\", path)


class EngineNameTests(unittest.TestCase):
    def test_engine_is_named_wherever_it_is_installed(self):
        here = {"name": "python3", "exe": "/usr/bin/python3",
                "cmdline": f"python3 {resourcewatch._ENGINE_ROOT}jarvis/service/daemon.py"}
        sealed = {"name": "python3", "exe": "/usr/bin/python3",
                  "cmdline": "python3 -I /opt/jarvis/current/jarvis-release.py"}
        self.assertEqual(resourcewatch._owner(here), "jarvis engine")
        self.assertEqual(resourcewatch._owner(sealed), "jarvis engine")
        self.assertTrue(resourcewatch._ENGINE_ROOT.endswith("/"))


class RepairHelperTests(unittest.TestCase):
    def load(self):
        loader = importlib.machinery.SourceFileLoader(
            "jarvis_repair_under_test", str(ROOT / "systemd" / "jarvis-repair"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def test_mount_owner_is_the_sudo_caller(self):
        repair = self.load()
        with mock.patch.dict(os.environ, {"SUDO_UID": "1004", "SUDO_GID": "1005"}, clear=True):
            self.assertEqual(repair.mount_owner(), (1004, 1005))

    def test_without_sudo_or_as_root_it_refuses(self):
        repair = self.load()
        for env in ({}, {"SUDO_UID": "0", "SUDO_GID": "0"}, {"SUDO_UID": "x", "SUDO_GID": "1"}):
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertIsNone(repair.mount_owner(), env)


class NoFixedAccountTests(unittest.TestCase):
    def test_shipped_python_names_no_fixed_account(self):
        # Comments and docstrings may cite this machine; code may not.
        offenders = []
        for path in (ROOT / "jarvis").rglob("*.py"):
            if "/lab/" in path.as_posix():
                continue            # synthetic lab scenarios, not this machine
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if re.search(r"""["'][^"'#]*\bchris\b""", code):
                    offenders.append(f"{path.relative_to(ROOT)}:{n}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()

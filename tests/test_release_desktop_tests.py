"""Native Windows unit tests gate desktop artifact handoff, not the user's policy.

The subprocess fixture models actual compiler output and a failing test harness.
It verifies that no executable or receipt escapes after test failure, including
a policy-blocked harness. Real native execution is measured in the release job.
"""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.security.pe_fixture import synthetic_pe

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_desktop_test_builder", ROOT / "release/build_desktop.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class NativeWindowsTestGate(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.work = self.root / "work"
        self.out = self.root / "out"
        self.target = self.root / "target"
        self.calls = []
        self.test_exit = 0
        self.compiled = bytes(synthetic_pe(guard=True))

    def export(self, repo, ref, tree, paths):
        (tree / "desktop/ui").mkdir(parents=True)
        return "a" * 40

    def run_command(self, cmd, cwd, env=None):
        self.calls.append((list(cmd), cwd, env))
        if cmd == ["bun", "run", "build"]:
            (cwd / "dist").mkdir()
            (cwd / "dist/index.html").write_text("<html></html>")
        elif cmd[:2] == ["cargo", "build"]:
            dest = self.target / "release/argus-desktop.exe"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(self.compiled)
        elif cmd[:2] == ["cargo", "test"] and self.test_exit:
            raise subprocess.CalledProcessError(self.test_exit, cmd)

    def invoke(self):
        args = ["build_desktop.py", "--platform", "windows", "--version", "2026.11.09-13",
                "--out", str(self.out), "--work", str(self.work)]
        with mock.patch.object(BUILDER.sys, "argv", args), \
                mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": str(self.target)}), \
                mock.patch.object(BUILDER.rename, "export", side_effect=self.export), \
                mock.patch.object(BUILDER, "run", side_effect=self.run_command), \
                mock.patch.object(BUILDER.gate, "check_artifact", return_value=([], 1)):
            BUILDER.main()

    def test_success_tests_the_exported_release_before_handoff(self):
        self.invoke()
        cargo = [(cmd, cwd, env) for cmd, cwd, env in self.calls if cmd[0] == "cargo"]
        self.assertEqual([cmd[1] for cmd, _, _ in cargo], ["build", "test"])
        build, tests = cargo
        self.assertEqual(tests[1], self.work / "desktop")
        for key in ("RUSTFLAGS", "ARGUS_RELEASE", "CARGO_TARGET_DIR"):
            self.assertEqual(tests[2][key], build[2][key],
                             "the harness uses the shipped build's flags and version")
        for flag in ("--release", "--locked", "custom-protocol", "--test-threads=2"):
            self.assertIn(flag, tests[0])
        self.assertEqual((self.out / "argus-desktop-windows-x64.exe").read_bytes(), self.compiled)
        self.assertIn(BUILDER.WINDOWS_CFG_FLAG, build[2]["RUSTFLAGS"].split())
        self.assertTrue((self.out / "desktop-windows-build.json").is_file())

    def test_failed_or_blocked_harness_emits_no_artifact_or_receipt(self):
        for code in (1, 126, 130):
            with self.subTest(exit_code=code):
                self.test_exit = code
                # Each attempt needs a fresh UI build directory.
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    self.invoke()
                self.assertEqual(raised.exception.returncode, code)
                self.assertTrue((self.target / "release/argus-desktop.exe").is_file(),
                                "the app build succeeded; only its tests failed")
                self.assertEqual(list(self.out.iterdir()), [], "no releasable output after failed tests")

    def test_missing_mitigations_stop_the_build_before_tests_or_handoff(self):
        cases = {"no CFG": synthetic_pe(), "relocations stripped": synthetic_pe(guard=True, characteristics=0x23,
                 reloc=(0, 0)), "writable code": synthetic_pe(guard=True, text=0xE0000020),
                 "malformed": b"MZ synthetic compiler output"}
        for label, image in cases.items():
            with self.subTest(label):
                self.calls.clear()
                self.compiled = bytes(image)
                with self.assertRaises(SystemExit) as stopped:
                    self.invoke()
                self.assertIn("lacks exploit mitigations", str(stopped.exception))
                self.assertNotIn("test", [cmd[1] for cmd, _, _ in self.calls if cmd[0] == "cargo"])
                self.assertEqual(list(self.out.iterdir()) if self.out.exists() else [], [])

    def test_hardening_reads_the_real_header_parser(self):
        self.assertEqual(BUILDER.pe_hardening_problems(self.root / "missing.exe"),
                         ["headers unreadable (FileNotFoundError)"])
        path = self.root / "a.exe"
        path.write_bytes(bytes(synthetic_pe()))
        self.assertEqual(BUILDER.pe_hardening_problems(path), ["control_flow_guard"])
        path.write_bytes(bytes(synthetic_pe(guard=True)))
        self.assertEqual(BUILDER.pe_hardening_problems(path), [])


if __name__ == "__main__":
    unittest.main()

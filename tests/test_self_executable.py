"""Child processes must start the real program, not a python.exe that Nuitka invents."""

import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core import paths

ROOT = Path(__file__).resolve().parents[1]


class SelfExecutableTest(unittest.TestCase):
    def test_an_existing_sys_executable_is_used(self):
        self.assertEqual(paths.self_executable(), sys.executable)

    @unittest.skipUnless(sys.platform.startswith("win"), "asks Windows for the running program")
    def test_a_missing_sys_executable_falls_back_to_the_running_program(self):
        with mock.patch.object(sys, "executable", os.path.join(os.path.dirname(sys.executable), "no-such-python.exe")):
            got = paths.self_executable()
        self.assertTrue(os.path.exists(got), got)
        self.assertEqual(os.path.normcase(got), os.path.normcase(sys.executable))

    def test_nothing_launches_itself_through_bare_sys_executable(self):
        # The pattern that broke every collector worker in the compiled Windows build.
        bad = []
        for path in (ROOT / "jarvis").rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"\[\s*sys\.executable\s*,\s*[\"']-m[\"']", text):
                bad.append(str(path.relative_to(ROOT)))
        self.assertEqual(bad, [], "use jarvis.core.paths.self_executable() to start a copy of Argus")


if __name__ == "__main__":
    unittest.main()

"""UI tests, run through the one regression command.

The page's own inline functions execute under Node with stubbed browser
globals (functional UI testing without a browser binary): cards must
render honest state, escape untrusted text, and stay wired to the
endpoints. Skips only when Node is unavailable.
"""
import shutil
import subprocess
import unittest
from pathlib import Path

UI_DIR = Path(__file__).resolve().parent / "ui"


class DashboardUITests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node unavailable")
    def test_node_ui_suite_passes(self):
        cases = sorted(UI_DIR.glob("*.test.mjs"))
        self.assertTrue(cases, "no UI test files found")
        proc = subprocess.run(
            ["node", "--test", *[str(c) for c in cases]],
            capture_output=True, text=True,
            errors="replace", timeout=120, cwd=str(UI_DIR.parent.parent))
        self.assertEqual(
            proc.returncode, 0,
            f"node --test failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


if __name__ == "__main__":
    unittest.main()

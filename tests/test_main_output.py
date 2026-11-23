"""The daemon's entry point survives a console that cannot encode its output."""

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MainOutputTest(unittest.TestCase):
    def test_unencodable_output_is_replaced_not_fatal(self):
        # stdout forced to an ASCII-only encoding stands in for cp1252 + an arrow.
        code = ("import runpy, sys; sys.argv = ['jarvis', '--help'];"
                "print('dashboard \u2192 http://127.0.0.1:8787', flush=True)")
        env = {**os.environ, "PYTHONIOENCODING": "ascii", "PYTHONPATH": str(ROOT)}
        # Same guard the entry point applies, then the same print.
        probe = ("import sys\n"
                 "exec(open(%r).read().split('from .cli')[0])\n"
                 "print('dashboard \u2192 http://127.0.0.1:8787', flush=True)\n"
                 % str(ROOT / "jarvis" / "__main__.py"))
        done = subprocess.run([sys.executable, "-c", probe], env=env,
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("dashboard", done.stdout)
        # Without the guard the same print really does fail on this encoding.
        bare = subprocess.run([sys.executable, "-c", code], env=env,
                              capture_output=True, text=True, timeout=30)
        self.assertNotEqual(bare.returncode, 0)


if __name__ == "__main__":
    unittest.main()


class LauncherOutputTest(unittest.TestCase):
    """The compiled program starts from release/launcher.py, not jarvis/__main__.py."""

    def test_the_launcher_survives_an_unencodable_banner(self):
        probe = ("import sys\n"
                 "sys.path.insert(0, %r)\n"
                 "import launcher\n"
                 "launcher.never_die_on_output()\n"
                 "print('dashboard \u2192 http://127.0.0.1:8787', flush=True)\n"
                 % str(ROOT / "release"))
        env = {**os.environ, "PYTHONIOENCODING": "ascii"}
        done = subprocess.run([sys.executable, "-c", probe], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("dashboard", done.stdout)

    def test_main_applies_the_guard_before_anything_else(self):
        text = (ROOT / "release" / "launcher.py").read_text()
        body = text.split("def main():", 1)[1]
        self.assertTrue(body.lstrip().startswith("never_die_on_output()"))

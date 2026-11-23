"""V14: the one way work is handed to a UAC-elevated PowerShell
(jarvis/platform/elevation.py), used by the sensor, broker and posture paths.

Invariants under test:
  * nothing in the user-writable stage runs as is: each file is copied into a
    fresh administrator-only folder and matched against a hash fixed before
    the prompt; one changed file and the entry never runs;
  * arguments are data: switches stay switches, values arrive byte for byte
    (an apostrophe cannot end the literal), {trusted} names the checked copy;
  * the checked copy is removed afterwards;
  * the launcher starts the elevated shell on inline code, never a file.
"""

import base64
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from jarvis.platform import elevation
from jarvis.verify import static

POWERSHELL, WSLPATH = shutil.which("powershell.exe"), shutil.which("wslpath")


def winpath(path):
    return subprocess.run([WSLPATH, "-w", str(path)], capture_output=True, text=True,
                          check=True).stdout.strip()


def ps(script, timeout=90):
    encoded = base64.b64encode(("$ProgressPreference='SilentlyContinue';"
                                "Set-ExecutionPolicy -Scope Process Bypass -Force;" + script)
                               .encode("utf-16le")).decode("ascii")
    # WSL sometimes fails to start the Windows process at all (UtilAcceptVsock
    # timeouts under load); that says nothing about the script, so retry once.
    for _attempt in range(2):
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, text=True, errors="replace", timeout=timeout, cwd="/")
        if "UtilAcceptVsock" not in r.stderr:
            break
        time.sleep(5)
    return r.returncode, r.stdout.replace("\r", ""), r.stderr.replace("\r", "")


class RenderingTests(unittest.TestCase):
    def test_every_file_is_checked_before_the_entry_runs(self):
        code = elevation.inline_command("C:\\T\\s", {"a.ps1": "ab" * 32, "b.xml": "cd" * 32}, "a.ps1", ["-Install"])
        run_at = code.index("& (Join-Path $t 'a.ps1')")
        for name, digest in (("a.ps1", "ab" * 32), ("b.xml", "cd" * 32)):
            self.assertLess(code.index(digest), run_at, name)
        self.assertIn("$env:ProgramFiles", code)

    def test_arguments_are_rendered_as_data(self):
        code = elevation.inline_command("C:\\T\\s", {"a.ps1": "ab" * 32}, "a.ps1",
                                        ["-Install", "-User", "CORP\\O'Brien", "-Source", "{trusted}",
                                         "-PolicyPath", "{trusted}\\baseline.xml"])
        call = code[code.index("& (Join-Path $t 'a.ps1')"):]
        self.assertIn(" -Install ", call)
        self.assertIn("'CORP\\O''Brien'", call)
        self.assertIn("-Source $t ", call)
        self.assertIn("-PolicyPath (Join-Path $t 'baseline.xml')", call)

    def test_hashes_and_names_are_validated(self):
        for files in ({"a.ps1": "nothex"}, {"..\\a.ps1": "ab" * 32}, {"a'.ps1": "ab" * 32}):
            with self.subTest(files=files), self.assertRaises(ValueError):
                elevation.inline_command("C:\\T", files, next(iter(files)), [])
        # A TEMP under C:\Users\O'Brien is real: escaped, not refused.
        code = elevation.inline_command("C:\\Users\\O'Brien\\T", {"a.ps1": "ab" * 32}, "a.ps1", [])
        self.assertIn("'C:\\Users\\O''Brien\\T\\a.ps1'", code)

    def test_launcher_runs_inline_code_never_a_file(self):
        inner = "Write-Output 'x'"
        outer = elevation.launcher(inner)
        self.assertIn("-Verb RunAs", outer)
        encoded = re.search(r"'-EncodedCommand','([A-Za-z0-9+/=]+)'", outer).group(1)
        self.assertEqual(base64.b64decode(encoded).decode("utf-16le"), inner)
        self.assertEqual(static.RULES_BY_ID["S2"].check("jarvis/platform/elevation.py",
                                                        Path(elevation.__file__).read_text()), [])


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class BehaviourTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=os.path.expanduser("~/.cache"), prefix="elevation-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stage = self.tmp / "O'Brien stage"
        self.stage.mkdir()
        self.programfiles = self.tmp / "ProgramFiles"
        self.programfiles.mkdir()
        self.marker = self.tmp / "ran.txt"
        (self.stage / "entry.ps1").write_text(
            "param([switch]$Install,[string]$User,[string]$Source)\n"
            f"@(\"ran\", $Install, $User, $Source, $PSScriptRoot) -join '|' | Set-Content -LiteralPath '{winpath(self.marker)}'\n")
        (self.stage / "data.txt").write_text("data\n")
        self.hashes = {n: hashlib.sha256((self.stage / n).read_bytes()).hexdigest()
                       for n in ("entry.ps1", "data.txt")}

    def run_inner(self):
        inner = elevation.inline_command(winpath(self.stage), self.hashes, "entry.ps1",
                                         ["-Install", "-User", "CORP\\O'Brien", "-Source", "{trusted}"])
        # In this process: Windows resets ProgramFiles in any child process.
        return ps(f"$env:ProgramFiles='{winpath(self.programfiles)}';" + inner)

    def test_checked_copy_runs_with_its_arguments_and_is_removed(self):
        code, out, err = self.run_inner()
        self.assertEqual(code, 0, (out + err)[-500:])
        ran, install, user, source, root = self.marker.read_text().strip().split("|")
        self.assertEqual((ran, install, user), ("ran", "True", "CORP\\O'Brien"))
        self.assertEqual(source, root)
        self.assertTrue(root.startswith(winpath(self.programfiles / "Jarvis" / "Elevated")), root)
        self.assertEqual(list((self.programfiles / "Jarvis").rglob("*")), [], "checked copy left behind")

    def test_a_file_swapped_after_hashing_runs_nothing(self):
        (self.stage / "data.txt").write_text("swapped\n")
        code, out, err = self.run_inner()
        self.assertNotEqual(code, 0)
        self.assertIn("data.txt", out + err)
        self.assertFalse(self.marker.exists())
        self.assertEqual(list((self.programfiles / "Jarvis").rglob("*")), [], "checked copy left behind")


if __name__ == "__main__":
    unittest.main()

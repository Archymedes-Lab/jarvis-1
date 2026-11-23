"""Guards for the out-of-WSL watchdog.

jarvis-wake-watchdog.ps1 is the only layer that can bring JARVIS back when WSL itself
is down, and nothing else in this suite executes it. Two defects kept it dead
for five days while Task Scheduler still reported the task Ready:

  * the task was registered with `-RecoverInterop:True`, and under -File the
    [bool] binder rejects that, so every run exited 1 before its first
    statement -- including the statement that writes the log;
  * Get-UnitState indexed a pipeline result with [-1]. A pipeline emitting one
    line returns a bare string, so that took the last *character* of "active"
    and called ToLower() on a [char], which does not have it. The unit state
    read as empty and the watchdog restarted a healthy daemon every 5 minutes.

Both are shape errors a reader skims past, so they are asserted here.
"""

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WAKE = ROOT / "jarvis-wake-watchdog.ps1"


class WakeScriptTests(unittest.TestCase):
    def setUp(self):
        self.text = WAKE.read_text(encoding="utf-8", errors="replace")
        # The comments explaining these bugs quote the broken forms verbatim,
        # so the assertions have to look at code only.
        self.code = "\n".join(
            line for line in self.text.splitlines()
            if not line.lstrip().startswith("#"))

    def assertNotInCode(self, needle, why):
        hits = [i for i, line in enumerate(self.code.splitlines(), 1)
                if needle in line]
        self.assertEqual(hits, [], "%s (found on code line(s) %s)" % (why, hits))

    def test_recover_interop_is_not_passed_with_a_colon(self):
        """`-Name:Value` does not bind through -File; `-Name Value` does."""
        self.assertNotInCode("-RecoverInterop:",
                             "the colon form does not bind through -File")

    def test_recover_interop_is_a_string_parameter(self):
        """A [bool] parameter cannot take every form a task action carries."""
        self.assertIn("[string]$RecoverInterop", self.code)
        self.assertNotInCode("[bool]$RecoverInterop",
                             "a [bool] parameter cannot take every task form")

    def test_the_on_off_decision_is_made_from_the_parsed_value(self):
        """`if ($RecoverInterop)` is true for the string 'false'."""
        self.assertIn("$RecoverInteropOn", self.code)
        self.assertNotInCode("if ($RecoverInterop) {",
                             "a non-empty string is truthy, including 'false'")

    def test_unit_state_pipeline_is_wrapped_in_an_array_subexpression(self):
        # One line of output is one item, not an array; without @() the [-1]
        # below indexed a character. ConvertTo-UnitState is also exercised in
        # Windows PowerShell with single-line input (tests/windows/supervisors.Tests.ps1).
        self.assertIn('$lines = @(@("$text" -split "`n") | ForEach-Object {', self.code)
        self.assertIn("return ConvertTo-UnitState", self.code)

    def test_unit_state_is_cast_before_lowercasing(self):
        self.assertNotInCode("return $lines[-1].ToLower()",
                             "[char] has no ToLower() in Windows PowerShell")
        self.assertIn("$last = [string]$lines[-1]", self.code)

    def test_an_unreadable_state_does_not_trigger_a_restart(self):
        """'could not read' is not the same claim as 'the unit is stopped'."""
        self.assertIn("Get-UnitStateConfirmed", self.code)
        self.assertIn("not restarting on an unknown state", self.code)


@unittest.skipUnless(shutil.which("powershell.exe"),
                     "powershell.exe not reachable from here")
class PowerShellParseTests(unittest.TestCase):
    def test_every_shipped_powershell_script_parses(self):
        broken = []
        for script in sorted(ROOT.glob("*.ps1")):
            win = subprocess.run(["wslpath", "-w", str(script)],
                                 capture_output=True, text=True)
            path = win.stdout.strip() or str(script)
            cmd = (
                "$e=$null;$t=$null;"
                "[void][System.Management.Automation.Language.Parser]::ParseFile("
                "'%s',[ref]$t,[ref]$e);"
                "if($e){$e|ForEach-Object{$_.Extent.StartLineNumber.ToString()+': '"
                "+$_.Message}}" % path.replace("'", "''"))
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=120, cwd="/mnt/c")
            out = res.stdout.replace("\r", "").strip()
            if out:
                broken.append("%s\n    %s" % (script.name, out))
        self.assertEqual(broken, [], "PowerShell parse errors:\n  "
                         + "\n  ".join(broken))


if __name__ == "__main__":
    unittest.main()

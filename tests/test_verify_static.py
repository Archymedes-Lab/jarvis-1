"""The shipped rule engine (jarvis/verify/static.py): rules for the product's own
bug classes, each born from a real defect, each tied to a registered invariant.

Invariants under test:
  * every rule flags its planted defect at the right line and passes the
    corrected form, so a rule that silently stops matching is caught;
  * this tree has no violation of any rule, with no list of tolerated ones;
  * a copy without sources (a sourceless release) is "not applicable", never a pass;
  * every rule names an invariant the registry knows.
"""

import tempfile
import unittest
from pathlib import Path

from jarvis.verify import invariants, static

ROOT = Path(__file__).resolve().parents[1]


def hits(rule_id, path, source):
    rule = static.RULES_BY_ID[rule_id]
    return [line for line, _text in rule.check(path, source)]


class RuleTests(unittest.TestCase):
    def test_s1_windows_launch_outside_the_gate(self):
        bad = "import subprocess\nx = 1\nsubprocess.run([win._PS, '-Command', 'x'])\n"
        self.assertEqual(hits("S1", "jarvis/collectors/x.py", bad), [3])
        good = "import subprocess\nsubprocess.run(['ss', '-tnp'])\nwindows.spawn([_PS, '-Command', 'x'])\n"
        self.assertEqual(hits("S1", "jarvis/collectors/x.py", good), [])

    def test_s2_elevated_launch_of_a_script_file(self):
        # The pattern found in broker.py and posture/collect.py on 2026-10-30.
        py = ('x = 1\nlauncher = ("$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru "\n'
              '            "-ArgumentList \'-NoProfile\',\'-File\',\'" + script + "\'")\n')
        self.assertEqual(hits("S2", "jarvis/cli/x.py", py), [2])
        ps1 = ("$a = 1\nStart-Process -FilePath $ps -Verb RunAs -Wait `\n"
               "    -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script\n")
        self.assertEqual(hits("S2", "scripts/x.ps1", ps1), [2])
        inline = ("Start-Process -FilePath $ps -Verb RunAs -Wait `\n"
                  "    -ArgumentList '-NoProfile', '-EncodedCommand', $encoded\n"
                  "Get-FileHash -LiteralPath $f\n")
        self.assertEqual(hits("S2", "scripts/x.ps1", inline), [])
        # The broker.py shape: the -File argument built in one statement, the
        # elevated launch in another, in the same function.
        split = ("def elevated(stage, entry):\n"
                 "    argline = ','.join([\"-NoProfile\", \"-File\", f\"{stage}\\\\{entry}\"])\n"
                 "    script = f\"$p = Start-Process powershell.exe -Verb RunAs -ArgumentList {argline}\"\n"
                 "    return script\n"
                 "def other():\n"
                 "    return '-File'\n")
        self.assertEqual(hits("S2", "jarvis/cli/x.py", split), [3])
        inline_py = ("def elevated(inner):\n"
                     "    return f\"Start-Process powershell.exe -Verb RunAs -ArgumentList '-Command',{inner}\"\n"
                     "def checks():\n"
                     "    return 'Get-FileHash -LiteralPath x'\n")
        self.assertEqual(hits("S2", "jarvis/cli/x.py", inline_py), [])
        doc = '"""Never start Start-Process -Verb RunAs on a -File script."""\nx = 1\n'
        self.assertEqual(hits("S2", "jarvis/cli/x.py", doc), [])
        # Mentions in comments and docs are not launches.
        self.assertEqual(hits("S2", "scripts/x.ps1", "# via Start-Process -Verb RunAs -File x\n"), [])
        self.assertEqual(hits("S2", "scripts/x.ps1", "#Requires -RunAsAdministrator\n& x -File y\n"), [])

    def test_s3_shell_strings(self):
        bad = ("import os, subprocess\nsubprocess.run(cmd, shell=True)\nos.system('ls')\n"
               "os.popen('id')\nsubprocess.check_output(c, shell=False)\n")
        self.assertEqual(hits("S3", "jarvis/x.py", bad), [2, 3, 4])

    def test_s4_bare_powershell_in_a_cmd_launcher(self):
        bad = "@echo off\r\npowershell.exe -NoProfile -File \"%~dp0x.ps1\"\r\n@PowerShell -c 1\r\n"
        self.assertEqual(hits("S4", "x.cmd", bad), [2, 3])
        good = ("@echo off\r\nrem powershell is called by full path below\r\n"
                "\"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -File x.ps1\r\n")
        self.assertEqual(hits("S4", "x.cmd", good), [])


class EngineTests(unittest.TestCase):
    def test_this_tree_has_no_violation(self):
        report = static.run(ROOT)
        self.assertTrue(report["applicable"])
        self.assertGreater(report["files"], 100)
        self.assertEqual(report["violations"], [], "\n".join(
            f"{v['rule']} {v['path']}:{v['line']} {v['text']}" for v in report["violations"]))
        self.assertTrue(report["ok"])

    def test_a_planted_violation_fails_the_run_with_its_invariant(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "jarvis"
            pkg.mkdir()
            (pkg / "x.py").write_text("import os\nos.system('id')\n")
            report = static.run(tmp, package="jarvis")
        self.assertFalse(report["ok"])
        self.assertEqual([(v["rule"], v["invariant"], v["path"], v["line"]) for v in report["violations"]],
                         [("S3", "V14", "jarvis/x.py", 2)])

    def test_a_sourceless_copy_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "jarvis").mkdir()
            (Path(tmp) / "jarvis" / "x.pyc").write_bytes(b"\x00")
            report = static.run(tmp, package="jarvis")
        self.assertFalse(report["applicable"])
        self.assertTrue(report["ok"])          # neither a pass nor a failure
        self.assertEqual(report["files"], 0)

    def test_every_rule_names_a_registered_invariant(self):
        known = {i.id for i in invariants.INVARIANTS}
        for rule in static.RULES:
            with self.subTest(rule=rule.id):
                self.assertIn(rule.invariant, known)
                self.assertTrue(rule.summary)


if __name__ == "__main__":
    unittest.main()

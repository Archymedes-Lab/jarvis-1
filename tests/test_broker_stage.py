"""Elevated staging: retried, and the real error reaches the user (2026-10-27).

`jarvis broker sysmon-baseline` failed once with only "could not create a
staging folder on Windows" right after a daemon restart; the same call worked
seconds later and PowerShell's own error text had been thrown away.
"""
import base64
import subprocess
import unittest
from unittest import mock

from jarvis.cli.commands import broker as cli

CLIXML = ('#< CLIXML\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/'
          'powershell/2004/04"><Obj S="progress"/></Objs>')


def done(code, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class StageTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(cli.time, "sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)

    def test_transient_failure_is_retried(self):
        runs = [done(1, "", "interop refused"), done(0, "C:\\T\\jarvis-x-1\r\n")]
        with mock.patch.object(cli.subprocess, "run", side_effect=runs) as run:
            self.assertEqual(cli._make_stage("jarvis-x"), ("C:\\T\\jarvis-x-1", ""))
        self.assertEqual(run.call_count, 2)

    def test_exhaustion_reports_the_powershell_error_without_noise(self):
        runs = [done(1, "", CLIXML + "\nAccess to the path is denied.")] * cli.STAGE_TRIES
        with mock.patch.object(cli.subprocess, "run", side_effect=runs):
            stage, why = cli._make_stage("jarvis-x")
        self.assertEqual(stage, "")
        self.assertIn("Access to the path is denied.", why)
        self.assertIn(f"after {cli.STAGE_TRIES} tries", why)
        self.assertNotIn("CLIXML", why)

    def test_a_hung_call_is_bounded_and_retried(self):
        runs = [subprocess.TimeoutExpired("powershell", cli.STAGE_TIMEOUT_S),
                done(0, "C:\\T\\ok\n")]
        with mock.patch.object(cli.subprocess, "run", side_effect=runs) as run:
            self.assertEqual(cli._make_stage("p")[0], "C:\\T\\ok")
        self.assertEqual(run.call_args.kwargs["timeout"], cli.STAGE_TIMEOUT_S)

    def test_empty_output_is_not_a_folder(self):
        with mock.patch.object(cli.subprocess, "run", return_value=done(0, "  \n")):
            stage, why = cli._make_stage("p")
        self.assertEqual(stage, "")
        self.assertIn("no output", why)


class OutputTests(unittest.TestCase):
    def test_progress_is_silenced_at_the_source(self):
        encoded = cli._ps_args("Write-Output 1")[-1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertTrue(script.startswith("$ProgressPreference='SilentlyContinue';"))

    def test_clixml_lines_are_dropped_and_text_kept(self):
        self.assertEqual(cli._clean(CLIXML + "\napplied: hash ok\n"), "applied: hash ok")


if __name__ == "__main__":
    unittest.main()

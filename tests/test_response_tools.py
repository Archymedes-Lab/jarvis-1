import os
import subprocess
import tempfile
import unittest
from unittest import mock

from jarvis.response import tools


class ResponseToolTests(unittest.TestCase):
    def test_sha256_streams_a_file(self):
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(b"abc")
            fh.flush()
            self.assertEqual(
                tools.sha256(fh.name),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_defender_rejects_non_windows_path_without_running_powershell(self):
        with mock.patch.object(tools, "ps_json") as ps:
            result = tools.defender_scan("/tmp/file")
        self.assertIsNone(result["clean"])
        ps.assert_not_called()

    def test_defender_clean_result_is_not_confused_with_unavailable(self):
        with mock.patch.object(tools, "ps_json", return_value={
                "code": 0, "out": "Scan finished; found no threats", "threat": ""}) as ps:
            result = tools.defender_scan(r"C:\Windows\System32\notepad.exe")
        self.assertTrue(result["available"])
        self.assertTrue(result["clean"])
        self.assertIn("$exe=Join-Path", ps.call_args.args[0])

    def test_process_tree_identifies_the_current_process(self):
        result = tools.process_tree(os.getpid())
        self.assertTrue(result["available"])
        self.assertEqual(result["self"]["pid"], os.getpid())

    def test_yara_absence_is_unavailable_not_clean(self):
        with mock.patch.object(tools, "which", return_value=""):
            result = tools.yara_scan("/tmp/x", "/tmp/rules")
        self.assertFalse(result["available"])
        self.assertNotIn("clean", result)

    def test_yara_operational_error_is_explicit(self):
        with tempfile.NamedTemporaryFile() as target, tempfile.NamedTemporaryFile() as rules, \
             mock.patch.object(tools, "which", return_value="/usr/bin/yara"), \
             mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(
                 [], 2, stdout="", stderr="bad rule")):
            result = tools.yara_scan(target.name, rules.name)
        self.assertTrue(result["error"])
        self.assertEqual(result["matches"], [])


if __name__ == "__main__":
    unittest.main()

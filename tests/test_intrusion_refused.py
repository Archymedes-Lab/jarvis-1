"""The intrusion scan never re-opens a file Windows Security refused it.

Each refused open is logged by Windows as a blocked action ("your administrator
caused Windows Security to block this action"). Measured 2026-11-11 on the
owner's machine: the scan caused about 60 such records a day for one installer.

Invariants
  1. A refused file is listed once per pass as blocked by Windows, low, never as
     an unsigned program and never dropped.
  2. Its identity (path, size, write time) is remembered and handed to the next
     pass, which lists it without opening it; a changed file is opened again.
  3. The payload's marker stays the first line of the launched command.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host.intrusion import run
from jarvis.core.paths import load_win_script
from jarvis.core.store import Store

KEY = "C:\\Users\\u\\Downloads\\setup.exe|100|639000000000000000"


def answer(*items):
    return {"recentExe": list(items), "runmru": [], "threats": [], "detections": []}


def item(sig="BlockedByWindows", key=KEY, path="C:\\Users\\u\\Downloads\\setup.exe", sha=""):
    return {"path": path, "size": 100, "written": "2026-11-10T10:00:00", "sig": sig, "signer": "",
            "sha256": sha, "key": key}


class Refused(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        self.calls = []

    def scan(self, data):
        def fake(script, timeout=120, payload=None):
            self.calls.append((script, json.loads(payload)))
            return data
        with mock.patch.object(run, "ps_json", fake):
            return run.audit(self.store)

    def test_a_refused_file_is_listed_low_and_remembered(self):
        out = self.scan(answer(item()))
        blocked = [f for f in out if f["title"] == "recently written program Windows blocks"]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["severity"], "low")
        self.assertIn("setup.exe", blocked[0]["detail"])
        self.assertFalse([f for f in out if f["title"] == "recently written unsigned executable"])
        self.assertEqual(self.calls[0][1], {"refused": []})
        self.scan(answer(item()))
        self.assertEqual(self.calls[1][1], {"refused": [KEY]})          # handed to the next pass

    def test_a_file_no_longer_refused_is_forgotten_and_judged_normally(self):
        self.scan(answer(item()))
        out = self.scan(answer(item(sig="NotSigned", sha="ab" * 32, path="C:\\Users\\u\\AppData\\Local\\Temp\\setup.exe")))
        self.assertEqual([f["severity"] for f in out if f["title"] == "recently written unsigned executable"], ["high"])
        self.scan(answer())
        self.assertEqual(self.calls[-1][1], {"refused": []})

    def test_the_remembered_list_is_bounded_and_survives_a_corrupt_value(self):
        self.scan(answer(*[item(key=f"k{i}", path=f"C:\\Users\\u\\Downloads\\{i}.exe") for i in range(300)]))
        self.assertEqual(len(run._refused(self.store)), run.MAX_REFUSED)
        self.store.set_meta(run.REFUSED_META, "{broken")
        self.assertEqual(run._refused(self.store), [])

    def test_without_a_store_it_still_works(self):
        with mock.patch.object(run, "ps_json", return_value=answer(item())):
            out = run.audit()
        self.assertEqual(len([f for f in out if f["title"] == "recently written program Windows blocks"]), 1)

    def test_the_marker_is_the_first_line_of_the_launched_command(self):
        self.scan(answer())
        script = self.calls[0][0]
        self.assertTrue(script.startswith("# jarvis-intrusion-payload"))
        self.assertIn("$jarvisReq", script)


class Payload(unittest.TestCase):
    TEXT = load_win_script("intrusion.ps1")

    def test_refused_files_are_not_opened_again_and_a_refusal_is_detected_through_wrapping(self):
        self.assertIn("$refusedBefore.Contains($key)", self.TEXT)
        self.assertIn("LastWriteTimeUtc.Ticks", self.TEXT)
        self.assertIn("[UnauthorizedAccessException]", self.TEXT)
        self.assertIn("$ex = $ex.InnerException", self.TEXT)
        self.assertIn("Get-FileHash -Algorithm SHA256 -InputStream $fs", self.TEXT)
        self.assertIn("if (-not $denied) { $s = Get-AuthenticodeSignature", self.TEXT)


if __name__ == "__main__":
    unittest.main()

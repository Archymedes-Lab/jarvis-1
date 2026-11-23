"""Independent cursor task must remain a limited, fingerprinted user task."""

import tempfile
import unittest
from pathlib import Path

from jarvis.platform.provenance import persistence

ROOT = Path(__file__).resolve().parents[1]
TASK = persistence.BY_NAME["jarviscursorspeed"]
LOCAL = r"C:\Users\chris\AppData\Local"


class CursorTaskIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        source = Path(self.temp.name, TASK.release_script)
        source.parent.mkdir(parents=True)
        source.write_bytes((ROOT / TASK.release_script).read_bytes())
        self.digest = persistence.expected_hash(TASK, self.temp.name)

    def _live(self):
        return {
            "name": TASK.name, "user": r"DESKTOP\chris", "runLevel": "Limited",
            "logonType": "Interactive",
            "actions": [{
                "execute": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "arguments": persistence.expected_arguments(TASK, LOCAL, str(ROOT)),
                "targetHash": self.digest,
            }],
        }

    def _verify(self, live):
        return persistence.verify_task(
            live, {"currentUser": r"DESKTOP\chris", "localAppData": LOCAL},
            self.temp.name, str(ROOT))

    def test_exact_task_is_known(self):
        self.assertTrue(self._verify(self._live())[0])

    def test_modified_script_or_elevated_task_is_rejected(self):
        changed = self._live()
        changed["actions"][0]["targetHash"] = "0" * 64
        self.assertFalse(self._verify(changed)[0])
        elevated = self._live()
        elevated["runLevel"] = "Highest"
        self.assertFalse(self._verify(elevated)[0])

    def test_cursor_task_does_not_share_input_hook(self):
        self.assertNotEqual(TASK.release_script,
                            persistence.BY_NAME["jarvis input hook"].release_script)
        self.assertIn(r"\Jarvis\CursorSpeed\cursor-speed.ps1", TASK.args)


if __name__ == "__main__":
    unittest.main()

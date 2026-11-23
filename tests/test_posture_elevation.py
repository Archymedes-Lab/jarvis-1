"""V14 for the posture collector's elevated run (posture/collect.py elevated_data).

Before 2026-10-30 it wrote jarvis_posture.ps1 into the user's TEMP under a fixed
name and started an elevated shell on that file, so any same-user process could
pre-write or swap it; the result came back through a fixed-name file too.

Invariants under test:
  * the elevated shell is started on inline code carrying the SHA-256 of
    exactly the script written, never on a file (-File);
  * the script and its result live in a fresh, randomly named folder, which
    is removed afterwards;
  * a result left at the old fixed path is never read;
  * a declined prompt is an error, not an empty or stale result.
"""

import base64
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.host.posture import collect


class PostureElevationTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp(prefix="posture-elev-"))
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.launched = []

    def run_elevated(self, elevated_writes=True):
        def fake_run(argv, **kw):
            outer = argv[-1]
            self.launched.append(outer)
            encoded = re.search(r"'-EncodedCommand','([A-Za-z0-9+/=]+)'", outer).group(1)
            inner = base64.b64decode(encoded).decode("utf-16le")
            stage = re.search(r"Copy-Item -LiteralPath 'C:\\T\\([^\\']+)\\posture\.ps1'", inner).group(1)
            staged = self.temp / stage / "posture.ps1"
            self.assertIn(hashlib.sha256(staged.read_bytes()).hexdigest(), inner)
            if elevated_writes:
                blob = base64.b64encode(json.dumps({"ok": 1}).encode()).decode()
                (self.temp / stage / "posture.b64").write_text(blob)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(collect.collect_windows, "available", return_value=True), \
                mock.patch.object(collect, "_win_temp", return_value=("C:\\T", str(self.temp))), \
                mock.patch.object(collect.collect_windows, "interop_launcher", return_value=[]), \
                mock.patch.object(collect.subprocess, "run", side_effect=fake_run):
            return collect.elevated_data(timeout=5)

    def test_runs_inline_code_on_a_hashed_script_in_a_fresh_folder(self):
        data, err = self.run_elevated()
        self.assertEqual((data, err), ({"ok": 1}, ""))
        self.assertNotIn("'-File'", self.launched[0])
        self.assertEqual(list(self.temp.iterdir()), [], "stage left behind")

    def test_a_result_at_the_old_fixed_path_is_never_read(self):
        planted = base64.b64encode(json.dumps({"forged": 1}).encode()).decode()
        (self.temp / "jarvis_posture.b64").write_text(planted)
        data, err = self.run_elevated(elevated_writes=False)
        self.assertIsNone(data)
        self.assertIn("declined", err)
        self.assertEqual(sorted(p.name for p in self.temp.iterdir()), ["jarvis_posture.b64"])


if __name__ == "__main__":
    unittest.main()

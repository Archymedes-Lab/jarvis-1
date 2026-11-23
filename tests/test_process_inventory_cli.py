"""The live process list must expose every returned row and name source loss."""

import io
import json
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from unittest.mock import patch

from jarvis.cli.commands.data import cmd_procs
from jarvis.core import collection


class LiveProcessListTests(unittest.TestCase):
    def _run(self, windows_rows, limit=None, failed=False):
        args = Namespace(live=True, json=True, limit=limit, approved=None,
                         host="win")

        def collect():
            if failed:
                collection.failed("windows-processes", "query timed out")
            return windows_rows

        output = io.StringIO()
        with patch("jarvis.platform.windows.collect", side_effect=collect), \
                redirect_stdout(output):
            code = cmd_procs(args, None)
        return code, json.loads(output.getvalue())

    def test_live_list_does_not_default_to_baseline_limit_or_filter(self):
        rows = [{"host": "win", "pid": i + 4, "name": f"p{i}",
                 "exe": f"C:\\bin\\p{i}.exe", "started": f"t{i}",
                 "observed_at": "sample"} for i in range(85)]
        code, result = self._run(rows)
        self.assertEqual(code, 0)
        self.assertEqual(result["total"], 85)
        self.assertEqual(result["shown"], 85)
        self.assertEqual(len(result["processes"]), 85)
        self.assertEqual(result["sources"], {"win": 85})
        self.assertNotIn("cmdline", result["processes"][0])

    def test_failure_does_not_look_like_an_empty_machine(self):
        code, result = self._run([], failed=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["sources"], {"win": 0})
        self.assertTrue(result["errors"])

    def test_explicit_limit_reports_truncation(self):
        rows = [{"host": "win", "pid": i, "name": "p"} for i in range(3)]
        code, result = self._run(rows, limit=1)
        self.assertEqual(code, 0)
        self.assertEqual((result["shown"], result["total"]), (1, 3))


if __name__ == "__main__":
    unittest.main()

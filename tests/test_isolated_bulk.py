"""Heavy advisory parsers run beyond the scheduler's process boundary
(2026-10-29: the OSV refresh ran 1031 s in-process and froze the Argus daemon,
dashboard included). Each test names what it holds."""

import os
import subprocess
import sys
import unittest
from unittest import mock

from jarvis.core import mechanisms
from jarvis.core.paths import PACKAGE_DIR
from jarvis.service import collector_worker, scheduler


class Declarations(unittest.TestCase):
    def test_heavy_parsers_are_isolated_and_allowed(self):
        for name in ("osv", "distrovuln"):
            self.assertTrue(mechanisms.BY_NAME[name].isolated, name)
            self.assertIn(name, scheduler.ISOLATED)
            self.assertIn(name, collector_worker.ALLOWED)

    def test_every_isolated_job_is_allowed_in_the_worker(self):
        self.assertLessEqual(set(scheduler.ISOLATED), collector_worker.ALLOWED)

    def test_isolation_is_refused_in_the_main_lane(self):
        bad = mechanisms.Collector(**{**mechanisms.BY_NAME["osv"].__dict__, "lane": "main"})
        with mock.patch.object(mechanisms, "COLLECTORS", (bad,)):
            self.assertTrue(any("isolation is defined" in p for p in mechanisms.conformance(files=False)))


class ProcessBoundary(unittest.TestCase):
    def test_child_starts_from_the_package_root(self):
        seen = {}

        def fake_run(argv, **kw):
            seen.update(kw, argv=argv)
            return subprocess.CompletedProcess(argv, 0, '{"findings": [], "error": "", "status": "complete"}', "")
        with mock.patch("subprocess.run", fake_run):
            out = scheduler._isolated_job("osv", ("wsl",), "/tmp/db", 300)
        self.assertEqual(out, ([], "", "complete"))
        self.assertEqual(seen["cwd"], str(PACKAGE_DIR.parent))
        self.assertEqual(seen["argv"][1:4], ["-m", "jarvis.service.collector_worker", "osv"])

    def test_deadline_kills_and_says_so(self):
        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, kw["timeout"])
        with mock.patch("subprocess.run", slow):
            findings, error, status = scheduler._isolated_job("osv", ("wsl",), "/tmp/db", 300)
        self.assertEqual((findings, status), ([], "unavailable"))
        self.assertIn("300s process deadline", error)

    def test_worker_imports_from_a_neutral_working_directory(self):
        # The real child, launched as the scheduler launches it, from "/".
        r = subprocess.run([sys.executable, "-m", "jarvis.service.collector_worker"],
                           cwd=str(PACKAGE_DIR.parent), capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PYTHONPATH": ""})
        self.assertEqual(r.returncode, 2, r.stderr)          # usage error, but it imported
        r = subprocess.run([sys.executable, "-m", "jarvis.service.collector_worker"],
                           cwd="/", capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PYTHONPATH": ""})
        self.assertNotEqual(r.returncode, 2)                # from "/" it cannot import: why cwd matters


if __name__ == "__main__":
    unittest.main()

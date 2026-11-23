"""The bulk lane holds only work that never crosses into Windows (2026-10-11).

The main lane is where PowerShell-interop collectors run; the fast lane runs
the short watchdogs. A third lane calling PowerShell would add concurrent
powershell.exe processes on a host that already ran out of memory commit and
killed the WSL VM. So every bulk job, and the JARVIS modules it imports
directly, must not call PowerShell. Moving these jobs off the main lane cut its
measured steady-state duty from 94% to about 47%, and stale collectors fell
from 31 to 1 within four minutes of the deploy.
"""
import ast
import importlib
import inspect
import re
import unittest

from jarvis.service import scheduler
from jarvis.service.schedule import JOBS

# Job -> module whose audit the job runner calls (see jarvis/service/jobs.py).
RUNNER_MODULES = {
    "content": "jarvis.collectors.host.content",
    "evidence": "jarvis.collectors.telemetry.evidence",
    "rust_mirror": "jarvis.collectors.telemetry.mirror",
    "world": "jarvis.intel.worldwatch",
    "feeds": "jarvis.intel.feeds",
    "history_verify": "jarvis.collectors.telemetry.history_verify",
    "retention": "jarvis.collectors.telemetry.history_retention",
    "verify": "jarvis.service.verifyjob",
    "pkgverify": "jarvis.collectors.persistence.pkgverify",
    "distrovuln": "jarvis.intel.distrovuln",
    "appcode": "jarvis.collectors.appcode",
    "osv": "jarvis.intel.osv",
    "friday_defender": "jarvis.collectors.host.fridaydefender",
}
INTEROP = re.compile(r"\bps_json\b|\brun_ps\b|\b_ps\(|powershell(\.exe)?['\"]", re.I)


def _jarvis_imports(module):
    tree = ast.parse(inspect.getsource(module))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("jarvis"):
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                try:
                    importlib.import_module(full)
                    names.add(full)
                except ImportError:
                    names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names if a.name.startswith("jarvis"))
    return names


class BulkLaneTests(unittest.TestCase):
    def test_every_bulk_job_is_known_and_mapped(self):
        self.assertEqual(set(scheduler.BULK), set(RUNNER_MODULES))
        for name in scheduler.BULK:
            self.assertIn(name, JOBS)
            self.assertNotIn(name, scheduler.FAST)

    def test_runner_modules_match_the_job_table(self):
        # Each bulk job's runner line in jobs.py must still call the module
        # this test inspects; otherwise the PowerShell check below is moot.
        from jarvis.service import jobs
        source = inspect.getsource(jobs)
        feeds_runner = inspect.getsource(jobs._feeds)
        for name, path in RUNNER_MODULES.items():
            short = path.rsplit(".", 1)[1]
            line = re.search(rf'"{name}":\s*([^\n]+)', source).group(1)
            body = feeds_runner if line.startswith("_feeds") else line
            self.assertRegex(body, rf"\b{short}\.", f"{name} no longer runs {path}")

    def test_bulk_jobs_never_call_powershell(self):
        for name, path in RUNNER_MODULES.items():
            module = importlib.import_module(path)
            for dep in {path} | _jarvis_imports(module):
                try:
                    source = inspect.getsource(importlib.import_module(dep))
                except (TypeError, OSError, ImportError):
                    obj = importlib.import_module(dep.rsplit(".", 1)[0])
                    source = inspect.getsource(obj)
                hit = INTEROP.search(source)
                self.assertIsNone(hit, f"bulk job {name} reaches PowerShell via {dep}: "
                                       f"{hit.group(0) if hit else ''}")

    def test_lane_assignment(self):
        sched = scheduler.Scheduler.__new__(scheduler.Scheduler)
        for name in JOBS:
            lane = scheduler.Scheduler._lane_of(sched, name)
            expected = ("fast" if name in scheduler.FAST
                        else "frequent" if name in scheduler.FREQUENT
                        else "bulk" if name in scheduler.BULK else "main")
            self.assertEqual(lane, expected, name)
        self.assertEqual(scheduler.Scheduler._lane_of(sched, "sysmon"), "main")


if __name__ == "__main__":
    unittest.main()

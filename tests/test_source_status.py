"""V10: a health source reads "unavailable" only when its collection failed.

Measured 2026-10-30: the scan job read Windows processes successfully, but one
Sysmon start-event gap (a visibility finding) made the scheduler store the
synthetic error "collector coverage incomplete", and /api/health turned every
stored error into "unavailable". The partial branch was unreachable, so a
working collector was reported down. These checks drive the real
protection._state over generated snapshot rows.
"""

import ast
import json
import pathlib
import random
import unittest

from jarvis.core import incidents
from jarvis.service import protection

NOW = 1_800_000_000.0
LIMIT = 300
REAL_ERRORS = ("windows-processes: Windows interop backing off for 25 s after 4 failed launches",
               "windows: PowerShell failed or timed out",
               "isolated collector failed: killed")
VISIBILITY = {"category": "visibility", "severity": "high", "title": "X exists without a start event"}
PROCESS = {"category": "process", "severity": "low", "title": "proc"}
OK_VIS = {"category": "visibility", "severity": "ok", "title": "fine"}


def row(ts, error, findings):
    return ("scan", ts, error, json.dumps(findings))


class SourceStatusTests(unittest.TestCase):
    def test_coverage_gap_inside_a_successful_read_is_partial(self):
        s = protection._state(row(NOW - 10, incidents.COVERAGE_INCOMPLETE,
                                  [PROCESS, VISIBILITY]), LIMIT, NOW)
        self.assertEqual(s["status"], "partial")
        self.assertEqual(s["reason"], VISIBILITY["title"])

    def test_real_collection_failure_stays_unavailable(self):
        for err in REAL_ERRORS:
            s = protection._state(row(NOW - 10, err, [PROCESS]), LIMIT, NOW)
            self.assertEqual(s["status"], "unavailable", err)
            self.assertEqual(s["reason"], err)

    def test_marker_without_a_named_gap_is_not_softened(self):
        # The marker alone proves nothing was observed cleanly; keep it loud.
        s = protection._state(row(NOW - 10, incidents.COVERAGE_INCOMPLETE, [PROCESS]), LIMIT, NOW)
        self.assertEqual(s["status"], "unavailable")

    def test_stale_partial_is_stale(self):
        s = protection._state(row(NOW - LIMIT - 1, incidents.COVERAGE_INCOMPLETE,
                                  [PROCESS, VISIBILITY]), LIMIT, NOW)
        self.assertEqual(s["status"], "stale")

    def test_property_status_is_honest(self):
        """150 seeded cases: never complete with an error or a gap; unavailable
        exactly when the error is a real failure or an unexplained marker."""
        rng = random.Random(20261030)
        for i in range(150):
            err = rng.choice(("", incidents.COVERAGE_INCOMPLETE, *REAL_ERRORS))
            findings = [rng.choice((PROCESS, VISIBILITY, OK_VIS)) for _ in range(rng.randint(0, 3))]
            ts = NOW - rng.choice((5, LIMIT - 1, LIMIT + 1))
            s = protection._state(row(ts, err, findings), LIMIT, NOW)["status"]
            gap = VISIBILITY in findings
            ctx = f"case {i}: err={err!r} findings={findings} ts={ts}"
            if err or gap:
                self.assertNotEqual(s, "complete", ctx)
            real = err and err != incidents.COVERAGE_INCOMPLETE
            if real or (err and not gap):
                self.assertEqual(s, "unavailable", ctx)
            elif ts < NOW - LIMIT:
                self.assertEqual(s, "stale", ctx)
            elif gap:
                self.assertEqual(s, "partial", ctx)
            else:
                self.assertEqual(s, "complete", ctx)

    def test_scheduler_writes_the_shared_marker(self):
        # The scheduler stores the marker as a literal; it must be the same text
        # health compares against, or the partial branch silently dies again.
        src = pathlib.Path(__file__).resolve().parents[1] / "jarvis/service/scheduler.py"
        literals = {n.value for n in ast.walk(ast.parse(src.read_text()))
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        self.assertIn(incidents.COVERAGE_INCOMPLETE, literals)


if __name__ == "__main__":
    unittest.main()

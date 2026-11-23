"""Clock-step detection: stable, periodic backward steps, and unknown data."""

import io
import json
import subprocess
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from unittest.mock import patch

from jarvis.cli.commands.timeline import cmd_timeline
from jarvis.core.execution import clock_integrity as ci
from jarvis.platform import clock


def _series(n, step_at=(), step=-2.5):
    real, mono, out = 1000.0, 50.0, []
    for i in range(n):
        out.append((real, mono))
        real += 1.0 + (step if i in step_at else 0.0)
        mono += 1.0
    return out


class AnalyzeTests(unittest.TestCase):
    def test_steady_clock_is_stable_only_with_journal_evidence(self):
        s = _series(20)
        self.assertEqual(ci.analyze(s, journal_backward=0)["status"], "stable")
        self.assertEqual(ci.analyze(s, journal_backward=None)["status"], "unknown")

    def test_too_short_a_window_is_unknown_not_stable(self):
        self.assertEqual(ci.analyze(_series(3), journal_backward=0)["status"], "unknown")
        self.assertEqual(ci.analyze([], journal_backward=0)["status"], "unknown")

    def test_periodic_backward_steps_are_unstable_with_effects(self):
        r = ci.analyze(_series(70, step_at=(10, 40)), journal_backward=0)
        self.assertEqual((r["status"], r["backward_steps"]), ("unstable", 2))
        self.assertAlmostEqual(r["largest_step_s"], 2.5)
        self.assertTrue(r["effects"])

    def test_one_step_is_labelled_but_not_unstable(self):
        r = ci.analyze(_series(20, step_at=(5,)), journal_backward=0)
        self.assertEqual(r["status"], "stepped_once")

    def test_forward_step_is_recorded_but_not_backward(self):
        r = ci.analyze(_series(20, step_at=(4,), step=3.0), journal_backward=0)
        self.assertEqual(r["backward_steps"], 0)
        self.assertEqual(r["steps"][0]["direction"], "forward")

    def test_journal_alone_can_show_instability_when_sampling_missed_it(self):
        self.assertEqual(ci.analyze(_series(20), journal_backward=79)["status"], "unstable")

    def test_jitter_below_tolerance_and_bad_pairs_are_ignored(self):
        s = [(0.0, 0.0), (1.2, 1.0), (2.1, 2.0), (2.0, 2.0), ("x", 1), (3.0, 3.0), (4.0, 4.0)]
        self.assertEqual(ci.steps(s), [])

    def test_sample_list_is_bounded(self):
        big = _series(ci.MAX_SAMPLES + 300, step_at=(0,))
        self.assertEqual(ci.steps(big), [])   # the old step fell outside the bound


class PlatformTests(unittest.TestCase):
    def test_collect_is_bounded(self):
        calls = []
        out = clock.collect(10**6, clock=lambda: calls.append(1) or (0.0, 0.0),
                            sleep=lambda _s: None)
        self.assertEqual(len(out), clock.MAX_WATCH_S + 1)

    def _run(self, stdout="", code=0, exc=None):
        def runner(*a, **k):
            if exc:
                raise exc
            return subprocess.CompletedProcess(a, code, stdout, "")
        return clock.journal_backward_count(runner=runner)

    def test_journal_counts_matches_and_no_match_is_zero(self):
        self.assertEqual(self._run("x Time jumped backwards, rotating.\n" * 3), 3)
        self.assertEqual(self._run("", code=1), 0)

    def test_unreadable_journal_is_unknown_not_zero(self):
        self.assertIsNone(self._run(code=2))
        self.assertIsNone(self._run(exc=OSError("no journalctl")))


class CliTests(unittest.TestCase):
    def test_cli_exit_code_reports_instability(self):
        series = _series(70, step_at=(10, 40))
        args = Namespace(action="clock", json=True, limit=5, watch=65)
        buf = io.StringIO()
        with patch("jarvis.platform.clock.collect", return_value=series), \
                patch("jarvis.platform.clock.journal_backward_count", return_value=0), \
                redirect_stdout(buf):
            code = cmd_timeline(args, None)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(buf.getvalue())["status"], "unstable")


if __name__ == "__main__":
    unittest.main()

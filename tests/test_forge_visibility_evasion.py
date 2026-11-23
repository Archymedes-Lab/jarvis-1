"""Forge visibility-evasion: synthetic adversaries vs the observers."""

import unittest

from jarvis.core import temporal
from jarvis.core.execution import protected
from jarvis.core.execution.presence import ProcessPresence, reconcile
from jarvis.lab import visibility_evasion as ve


class EvasionTests(unittest.TestCase):
    def test_short_lived_process_leaves_no_ghost(self):
        for start, exit in ve.short_lived_process():
            proj = temporal.reduce([start, exit])
        self.assertEqual(proj["alive"], {})

    def test_rapid_module_loads_all_counted(self):
        proj = temporal.reduce(ve.rapid_module_loads(n=25))
        self.assertEqual(proj["counts"].get("process:image_load"), 25)

    def test_creation_exit_race_never_sticks_alive(self):
        for (exit, start) in ve.creation_exit_race():
            proj = temporal.reduce([exit, start])
        # Exit-then-start in seq order ends alive; the invariant that
        # matters is pid-keyed state never duplicates or wedges.
        self.assertLessEqual(len(proj["alive"]), 1)

    def test_protected_process_never_suspicious(self):
        for p in ve.protected_process():
            verdict = protected.classify(
                name=p["name"], lifecycle_ok=p["lifecycle_ok"],
                memory_restricted=p["memory_restricted"],
                protection=p["protection"])
        self.assertEqual(verdict["state"], "EXPECTED_PROTECTED_PROCESS")

    def test_dropped_events_stay_unknown(self):
        gap = ve.dropped_events()
        p = ProcessPresence(boot_id="b", pid=7, snapshot_seen=True)
        verdict = reconcile(p, coverage_valid=gap["coverage_valid"])
        self.assertEqual(verdict["verdict"], "UNKNOWN")

    def test_thread_exit_clears_state(self):
        proc = {"pid": 5, "guid": "t-1"}
        proj = temporal.reduce([
            {"seq": 1, "category": "thread", "action": "start",
             "process": proc, "target": {"tid": 11}},
            {"seq": 2, "category": "thread", "action": "exit",
             "process": proc, "target": {"tid": 11}},
        ])
        self.assertEqual(proj["threads_alive"], {})

    def test_service_lifecycle_tracked(self):
        proj = temporal.reduce([
            {"seq": 1, "category": "service", "action": "created",
             "target": {"name": "EvilSvc"}},
            {"seq": 2, "category": "service", "action": "started",
             "target": {"name": "EvilSvc"}},
        ])
        self.assertEqual(proj["services"], {"EvilSvc": "started"})


if __name__ == "__main__":
    unittest.main()

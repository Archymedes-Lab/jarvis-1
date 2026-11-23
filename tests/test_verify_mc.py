"""The model checker itself: it must find planted violations and report paths."""

import unittest

from jarvis.verify.mc import Model


def counter_model(limit, bad_at):
    def inc(s):
        return (s + 1,) if s < limit else ()
    return Model("counter", 0, [("inc", inc)], [("never reaches bad", lambda s: s != bad_at)],
                 max_states=1000)


class ModelCheckerTests(unittest.TestCase):
    def test_finds_a_planted_violation_with_the_shortest_path(self):
        r = counter_model(10, 4).check()
        self.assertFalse(r.ok)
        self.assertEqual(r.violated, "never reaches bad")
        self.assertEqual([s for _, s in r.counterexample], [1, 2, 3, 4])
        self.assertIn("VIOLATION", str(r))

    def test_exhausts_a_safe_model_and_counts_states(self):
        r = counter_model(10, 99).check()
        self.assertTrue(r.ok and r.exhausted)
        self.assertEqual(r.states, 11)
        self.assertEqual(r.transitions, 10)

    def test_bound_is_reported_not_hidden(self):
        m = counter_model(10_000, -1)
        m.max_states = 50
        r = m.check()
        self.assertTrue(r.ok)
        self.assertFalse(r.exhausted)
        self.assertIn("bound hit", str(r))

    def test_deadlock_detection_is_opt_in(self):
        m = counter_model(3, -1)
        self.assertEqual(m.check().deadlocks, 1)          # state 3 has no successor
        m.deadlock_free = True
        r = m.check()
        self.assertFalse(r.ok)
        self.assertEqual(r.violated, "deadlock")

    def test_reachable_returns_a_path_or_none(self):
        m = counter_model(5, -1)
        self.assertEqual([s for _, s in m.reachable(lambda s: s == 3)], [1, 2, 3])
        self.assertIsNone(m.reachable(lambda s: s == 42))


if __name__ == "__main__":
    unittest.main()

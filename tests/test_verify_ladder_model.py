"""V13: the response-ladder model (jarvis/verify/models/response_ladder.py)
drives the real defense.process, approve, undo and expire.

Invariants under test:
  * the shipped ladder exhausts its state space with no violation;
  * each planted defect in the authority path is found, with a short path:
    flags ignored, the cap ignored, an undo that reports success but leaves
    the rule in place;
  * a check leaves the real registry, clock and evidence capture as it found them.
"""

import unittest
from unittest import mock

from jarvis.response import defense
from jarvis.response.actions import base
from jarvis.verify.models import response_ladder as ladder


class LadderModelTests(unittest.TestCase):
    def test_the_shipped_ladder_has_no_reachable_violation(self):
        r = ladder.model().check()
        self.assertTrue(r.ok, str(r)[:2000])
        self.assertTrue(r.exhausted)
        self.assertGreater(r.states, 1000)

    def test_ignoring_the_flags_is_found(self):
        with mock.patch.object(defense, "_enabled", return_value=True):
            r = ladder.model().check()
        self.assertFalse(r.ok)
        self.assertIn("authority", r.violated + "".join(str(s) for _a, s in r.counterexample))

    def test_ignoring_the_cap_is_found(self):
        with mock.patch.object(ladder.ModelAction, "max_active", 0):
            r = ladder.model().check()
        self.assertFalse(r.ok)
        self.assertEqual(r.violated, "automatic actions within the cap")

    def test_an_undo_that_lies_is_found(self):
        def lying_undo(self, target, record):
            return True, "lifted"                     # says lifted, rule stays
        with mock.patch.object(ladder.ModelAction, "undo", lying_undo):
            r = ladder.model().check()
        self.assertFalse(r.ok)
        self.assertEqual(r.violated, "the world matches the ledger")

    def test_a_check_restores_what_it_replaced(self):
        before = (defense.time, defense._capture, dict(base._REGISTRY))
        ladder.model(max_states=50).check()
        self.assertIs(defense.time, before[0])
        self.assertIs(defense._capture, before[1])
        self.assertEqual(base._REGISTRY, before[2])
        self.assertNotIn(ladder.ACTION.id, base._REGISTRY)


if __name__ == "__main__":
    unittest.main()

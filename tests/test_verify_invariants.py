"""The invariant registry (jarvis/verify/invariants.py) is the single list of
what the verification framework guards.

Invariants under test:
  * every registered invariant has at least one executable check, and every
    check it names exists (property, model, rule, runtime monitor, test file);
  * every property, model and rule maps back to a registered invariant: no
    orphan check proves something nobody wrote down;
  * the table in docs/architecture/VERIFICATION-LADDER.md lists exactly the
    registered ids, so the document cannot drift from what runs.
"""

import re
import unittest
from pathlib import Path

from jarvis.verify import invariants

ROOT = Path(__file__).resolve().parents[1]


class RegistryTests(unittest.TestCase):
    def test_this_tree_conforms(self):
        self.assertEqual(invariants.conformance(ROOT), [])

    def test_ids_are_unique_and_ordered(self):
        ids = [i.id for i in invariants.INVARIANTS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids, key=lambda v: int(v[1:])))
        self.assertIn("V13", ids)
        self.assertIn("V14", ids)
        self.assertIn("V15", ids)

    def test_an_invariant_without_checks_is_a_problem(self):
        planted = invariants.INVARIANTS + (invariants.Invariant("V99", "nothing checks this", ()),)
        problems = invariants.conformance(ROOT, registry=planted)
        self.assertTrue(any("V99" in p and "no executable check" in p for p in problems), problems)

    def test_a_check_that_does_not_exist_is_a_problem(self):
        planted = invariants.INVARIANTS + (
            invariants.Invariant("V99", "names a missing rule", ("static:S99", "property:no such property")),)
        problems = invariants.conformance(ROOT, registry=planted)
        self.assertTrue(any("S99" in p for p in problems), problems)
        self.assertTrue(any("no such property" in p for p in problems), problems)

    def test_an_orphan_check_is_a_problem(self):
        # Drop V14 from the registry: its rules now prove an unwritten invariant.
        trimmed = tuple(i for i in invariants.INVARIANTS if i.id != "V14")
        problems = invariants.conformance(ROOT, registry=trimmed)
        self.assertTrue(any("V14" in p and "not registered" in p for p in problems), problems)

    def test_the_ladder_document_lists_exactly_the_registered_ids(self):
        doc = (ROOT / "docs" / "architecture" / "VERIFICATION-LADDER.md").read_text()
        table = set(re.findall(r"^\| (V\d+) \|", doc, re.M))
        self.assertEqual(table, {i.id for i in invariants.INVARIANTS})


if __name__ == "__main__":
    unittest.main()

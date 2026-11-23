"""Randomised properties over the pure engines (seeded, replayable; stdlib only).

The catalogue lives in jarvis/verify/properties.py so an installed copy can
re-run it; this runs the same catalogue under unittest, one case per property."""

import re
import unittest
from unittest import mock

from jarvis.response.actions import ban_source
from jarvis.verify import properties


class PropertyTests(unittest.TestCase):
    def test_catalogue_is_not_empty_and_names_invariants(self):
        self.assertGreaterEqual(len(properties.PROPERTIES), 11)
        for invariant, name, _gen, _prop in properties.PROPERTIES:
            self.assertRegex(invariant, r"^V\d+$")
            self.assertTrue(name)

    def test_every_property_holds(self):
        for invariant, name, gen, prop in properties.PROPERTIES:
            with self.subTest(invariant=invariant, name=name):
                result = properties.check(invariant, name, gen, prop)
                self.assertTrue(result["ok"], result["error"])
                self.assertEqual(result["cases"], properties.CASES)

    def test_v15_catches_the_unanchored_source_pattern(self):
        # The defect fixed on 2026-10-30: matching the first "from X in Nh"
        # let a guessed user name choose the banned address.
        v15 = [p for p in properties.PROPERTIES if p[0] == "V15"]
        self.assertEqual(len(v15), 1)
        with mock.patch.object(ban_source, "_SOURCE", re.compile(r"\bfrom (\S+) in \d+h\b")):
            result = properties.check(*v15[0])
        self.assertFalse(result["ok"])

    def test_a_failing_property_is_reported_not_raised(self):
        result = properties.check("V0", "always false", lambda g: g.int(0, 3),
                                  lambda v: v != 2)
        self.assertFalse(result["ok"])
        self.assertIn("case", result["error"])
        crash = properties.check("V0", "crashes", lambda g: 1, lambda v: 1 / 0)
        self.assertFalse(crash["ok"])
        self.assertIn("ZeroDivisionError", crash["error"])


if __name__ == "__main__":
    unittest.main()

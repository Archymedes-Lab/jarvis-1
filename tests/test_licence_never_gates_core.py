"""Core protection never depends on licence or payment state.

docs/commercial/LICENSING-STRATEGY.md: CDM vetoed a design that locks on-demand
checks until a licence is bought (core_gate 0.885, evidence 0.715) and Jev
judged keeping such a lock out of releases 0.82. This guards the rule at the
places a lock would have to live: no environment switch that requires a
licence, and no HTTP 402 (payment required) answer anywhere in the daemon,
its collectors or its response layer. Premium content (signed rule-pack
updates) may be licensed; protection may not.
"""

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'jarvis')
LOCK_SWITCH = re.compile(r'REQUIRE_LICEN[CS]E', re.I)
PAYMENT_REQUIRED = re.compile(r'(?<![\w.])402(?![\w.])')
PROTECTION = ('collectors', 'service', 'response', 'web', 'core', 'platform', 'intel')


def _sources():
    for top in PROTECTION:
        for dirpath, _dirs, files in os.walk(os.path.join(ROOT, top)):
            for name in files:
                if name.endswith('.py'):
                    path = os.path.join(dirpath, name)
                    with open(path, encoding='utf-8', errors='replace') as fh:
                        yield os.path.relpath(path, ROOT), fh.read()


# Interface copy that would tell a user payment unlocks the product or locks protection.
LOCK_WORDING = re.compile(r"only unlocks ARGUS|asks for a licence before|locked until you subscribe|"
                          r"licence (?:is )?(?:required|needed) (?:for|before|to use)", re.I)
UI_ROOTS = [os.path.join(os.path.dirname(ROOT), "desktop", "ui", "src"),
            os.path.join(ROOT, "web", "static")]


class LicenceNeverGatesCore(unittest.TestCase):
    def test_no_interface_copy_says_a_licence_unlocks_or_locks_protection(self):
        bad = []
        for root in UI_ROOTS:
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if name.endswith((".svelte", ".ts", ".json", ".js", ".html")):
                        path = os.path.join(dirpath, name)
                        with open(path, encoding="utf-8", errors="replace") as fh:
                            for n, line in enumerate(fh, 1):
                                if LOCK_WORDING.search(line):
                                    bad.append(f"{os.path.relpath(path, os.path.dirname(ROOT))}:{n}")
        self.assertEqual(bad, [])

    def test_the_copy_guard_detects_the_old_sentence(self):
        self.assertTrue(LOCK_WORDING.search("Your data stays on this computer; the licence only unlocks ARGUS-INSTINCT."))
        self.assertTrue(LOCK_WORDING.search("The assistant and checks are locked until you subscribe."))
        self.assertFalse(LOCK_WORDING.search("protection works the same with or without a licence."))

    def test_no_switch_makes_protection_require_a_licence(self):
        bad = [p for p, text in _sources() if LOCK_SWITCH.search(text)]
        self.assertEqual(bad, [], 'a licence switch would gate protection; gate premium content only')

    def test_no_protection_path_answers_payment_required(self):
        bad = []
        for path, text in _sources():
            for n, line in enumerate(text.splitlines(), 1):
                code = line.split('#', 1)[0]
                if PAYMENT_REQUIRED.search(code) and re.search(r'send_response|status|json|HTTP', code):
                    bad.append(f'{path}:{n}')
        self.assertEqual(bad, [], 'HTTP 402 on a protection path makes protection depend on payment')

    def test_the_guard_detects_the_vetoed_design(self):
        # Negative control: the shape of the vetoed lock is caught by both patterns.
        sample = ("if os.environ.get('ARGUS_REQUIRE_LICENSE') == '1' and not licensed:\n"
                  "    self.send_response(402)\n")
        self.assertTrue(LOCK_SWITCH.search(sample))
        self.assertTrue(PAYMENT_REQUIRED.search(sample.splitlines()[1]))


if __name__ == '__main__':
    unittest.main()

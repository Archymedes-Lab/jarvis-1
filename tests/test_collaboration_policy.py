"""Either cofounder can merge without removing the PR and CI boundaries.

The declaration is also checked against live GitHub readback when applied;
these checks prevent later policy edits from silently dropping other gates.
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CollaborationPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / ".github/rulesets/main.json").read_text())
        self.rules = {r["type"]: r for r in self.policy["rules"]}

    def test_no_second_cofounder_approval_is_required(self):
        rule = self.rules["pull_request"]["parameters"]
        self.assertEqual(rule["required_approving_review_count"], 0)
        self.assertFalse(rule["require_code_owner_review"])
        self.assertFalse(rule["require_last_push_approval"])

    def test_main_still_requires_prs_and_all_existing_ci_checks(self):
        self.assertEqual(self.policy["enforcement"], "active")
        self.assertEqual(self.policy["conditions"]["ref_name"],
                         {"include": ["~DEFAULT_BRANCH"], "exclude": []})
        self.assertIn("pull_request", self.rules)
        checks = self.rules["required_status_checks"]["parameters"]["required_status_checks"]
        self.assertEqual({c["context"] for c in checks}, {"python", "desktop-ui", "desktop-rust"})

    def test_no_new_bypass_deletion_or_force_push_permissions(self):
        self.assertEqual(self.policy["bypass_actors"], [])
        self.assertIn("deletion", self.rules)
        self.assertIn("non_fast_forward", self.rules)


if __name__ == "__main__":
    unittest.main()

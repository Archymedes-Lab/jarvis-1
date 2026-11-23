"""Public contributions must execute the real required jobs without authority.

PyYAML is the existing hash-pinned development parser, installed before CI's
unit suite. Parsing the actual workflow avoids treating commented YAML as a gate.
"""

import json
import re
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(yaml is None, "install the pinned development requirements-bench.txt")
class PublicContributorCI(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / ".github/workflows/ci.yml").read_text()
        self.workflow = yaml.safe_load(self.text)
        # YAML 1.1 treats the GitHub key `on` as true; both parsings are accepted.
        self.events = self.workflow.get("on", self.workflow.get(True))
        self.jobs = self.workflow["jobs"]
        policy = json.loads((ROOT / ".github/rulesets/main.json").read_text())
        checks = next(r for r in policy["rules"] if r["type"] == "required_status_checks")
        self.required = {c["context"] for c in checks["parameters"]["required_status_checks"]}

    def test_external_pr_updates_run_without_path_or_tag_filter_gaps(self):
        event = self.events["pull_request"]
        self.assertEqual(event["branches"], ["main"])
        self.assertEqual(set(event["types"]),
                         {"opened", "synchronize", "reopened", "ready_for_review"})
        self.assertFalse(set(event) & {"paths", "paths-ignore", "branches-ignore", "tags"})
        self.assertEqual(self.events["push"], {"branches": ["**"]})
        self.assertIn("workflow_dispatch", self.events)

    def test_no_privileged_event_or_secret_delegation(self):
        self.assertFalse(set(self.events) & {"pull_request_target", "workflow_run"})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertNotRegex(self.text, r"\$\{\{\s*secrets\.")
        for job in self.jobs.values():
            self.assertNotIn("secrets", job)
            self.assertNotIn("environment", job)
            self.assertNotIn("permissions", job)

    def test_required_jobs_cannot_skip_or_rename_a_failing_pr_check(self):
        self.assertEqual(self.required, {"python", "desktop-ui", "desktop-rust"})
        for name in self.required:
            job = self.jobs[name]
            self.assertNotIn("if", job, name)
            self.assertNotIn("name", job, name)
            self.assertNotIn("continue-on-error", job, name)
            self.assertNotIn("needs", job, name)
            for step in job["steps"]:
                self.assertNotIn("continue-on-error", step, name)

    def test_ephemeral_runners_and_bounded_job_time(self):
        for name, job in self.jobs.items():
            self.assertIn(job["runs-on"], {"ubuntu-24.04", "windows-2025"}, name)
            self.assertGreater(job["timeout-minutes"], 0)
            self.assertLessEqual(job["timeout-minutes"], 45)
        self.assertEqual(self.jobs["desktop-rust-windows"]["if"],
                         "startsWith(github.ref, 'refs/heads/test/windows-native/')")

    def test_checkouts_do_not_retain_tokens_or_override_the_pr_merge_ref(self):
        for job in self.jobs.values():
            for step in job["steps"]:
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)
                    self.assertNotIn("token", step["with"])
                    self.assertNotIn("ref", step["with"])

    def test_actions_remain_immutable_and_rust_pr_cache_cannot_write_main(self):
        for name, job in self.jobs.items():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^[\w./-]+@[0-9a-f]{40}$")
                if step.get("uses", "").startswith("actions/cache/save@") and name in self.required:
                    self.assertIn("github.ref == 'refs/heads/main'", step["if"])
                    self.assertIn("success()", step["if"])

    def test_required_jobs_still_run_the_product_and_release_safety_checks(self):
        commands = {name: "\n".join(s.get("run", "") for s in self.jobs[name]["steps"])
                    for name in self.required}
        for command in ("scripts/dev/static_gate.sh", "scripts/dev/standard_check.py",
                        "tests.test_release_gate", "tests.test_release_signing",
                        "python scripts/dev/ci_suite.py", "--floor scripts/security/atomic_floor.json"):
            self.assertIn(command, commands["python"])
        self.assertIn("bun run test", commands["desktop-ui"])
        self.assertIn("bun run build", commands["desktop-ui"])
        self.assertIn("cargo test --locked", commands["desktop-rust"])

    def test_untrusted_pr_metadata_is_not_interpolated_into_commands(self):
        for job in self.jobs.values():
            for step in job["steps"]:
                self.assertIsNone(re.search(
                    r"\$\{\{[^}]*github\.(?:event|head_ref)", step.get("run", "")))


if __name__ == "__main__":
    unittest.main()

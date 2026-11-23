"""CI minutes are a budget: the org has a $0 Actions budget with "stop usage" on, so spending
the included amount too fast stops every workflow until the next cycle. These checks keep the
workflows from quietly getting more expensive.

Measured 2026-11-05 (5 days): 52 CI runs, 20 of 30 commits ran CI twice (once for the push,
once for the pull request), and a cold release dry run cost about $1.
"""

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"

# Upper bounds for a hung job, about twice what the job needs (observed 2026-11-05). A job that
# hangs is billed until its timeout, so the ceiling is the most one runaway can cost.
CEILINGS = {
    "release.yml": {
        "server": 60, "server-install-test": 30, "desktop-linux": 60, "desktop-windows": 60,
        "engine-windows": 90, "windows-source-smoke": 15, "windows-setup": 20,
        "windows-install-test": 45, "verify": 45, "meta": 10, "draft": 20,
    },
}
GENERIC_CEILING = 60

# Lower bounds, from COLD builds on the 2-vCPU runners: a tag always builds cold, and a new
# dry-run branch does too (caches are scoped per branch). desktop-linux was cut to 30 minutes
# from a warm 4.6-minute run and the cold build was cancelled at the limit (run 42117983818).
# A timeout below what a cold build needs fails the release it was meant to protect.
FLOORS = {
    "release.yml": {"desktop-linux": 60, "engine-windows": 75, "server": 40, "desktop-windows": 30},
}


def _triggers(text):
    block = re.search(r"^on:\n((?:[ ]+.*\n|\n)+)", text, re.M)
    return set(re.findall(r"^  ([a-z_]+):", block.group(1), re.M)) if block else set()


def _jobs(text):
    body = text[text.index("\njobs:\n") + 6:]
    parts = re.split(r"^  ([a-z0-9-]+):\n", body, flags=re.M)
    return {name: section for name, section in zip(parts[1::2], parts[2::2])}


def _timeout(section):
    m = re.search(r"^    timeout-minutes: (\d+)", section, re.M)
    return int(m.group(1)) if m else None


class CiSpend(unittest.TestCase):
    def test_native_windows_proof_is_opt_in_and_uses_the_gated_builder(self):
        job = _jobs((WORKFLOWS / "ci.yml").read_text())["desktop-rust-windows"]
        condition = re.search(r"^    if: (.+)$", job, re.M)
        self.assertIsNotNone(condition, "an unconditional Windows job spends on every push")
        self.assertEqual(condition.group(1),
                         "startsWith(github.ref, 'refs/heads/test/windows-native/')")
        self.assertIn("runs-on: windows-2025", job)
        self.assertIn("python release/build_desktop.py --platform windows", job)
        self.assertNotIn("continue-on-error", job, "native test failures must fail the check")
        self.assertIn("steps.windows-cargo-cache.outputs.cache-hit != 'true'", job)

    def test_contributor_ci_preserves_push_checks_and_bounds_extra_events(self):
        text = (WORKFLOWS / "ci.yml").read_text()
        triggers = _triggers(text)
        # Push-only saved minutes but could not check outside forks. Keep ASES's
        # every-push gate and accept bounded main-PR runs for the public path.
        # Do not replace this with privileged events or an automatic schedule.
        self.assertEqual(triggers, {"push", "pull_request", "workflow_dispatch"})
        self.assertIn("branches: [main]", text)
        self.assertIn("types: [opened, synchronize, reopened, ready_for_review]", text)
        self.assertIn("cancel-in-progress: true", text)
        for name, section in _jobs(text).items():
            self.assertLessEqual(_timeout(section), 45, name)

    def test_a_newer_push_replaces_the_run_in_progress(self):
        text = (WORKFLOWS / "ci.yml").read_text()
        self.assertIn("cancel-in-progress: true", text)
        release = (WORKFLOWS / "release.yml").read_text()
        self.assertIn("cancel-in-progress: ${{ github.ref_type != 'tag' }}", release)

    def test_every_job_has_a_timeout_under_its_ceiling(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            ceilings = CEILINGS.get(path.name, {})
            for name, section in _jobs(path.read_text()).items():
                limit = _timeout(section)
                self.assertIsNotNone(limit, f"{path.name}:{name} has no timeout-minutes (default 360)")
                self.assertLessEqual(limit, ceilings.get(name, GENERIC_CEILING), f"{path.name}:{name}")

    def test_no_timeout_is_below_what_a_cold_build_needs(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            jobs = _jobs(path.read_text())
            for name, floor in FLOORS.get(path.name, {}).items():
                self.assertGreaterEqual(_timeout(jobs[name]), floor, f"{path.name}:{name}: a cold build is cancelled")

    def test_cargo_caches_are_keyed_by_content_and_saved_once(self):
        # 63 caches held 7.8 GB of the 10 GB repo limit, 6.7 GB of it cargo: the release builds
        # keyed theirs by commit (a new ~420 MB entry per commit) and CI saved a 640 MB copy per
        # branch. Past 10 GB GitHub evicts the oldest entries, including the compiler caches.
        release = (WORKFLOWS / "release.yml").read_text()
        keys = re.findall(r"^\s+key: (cargo-[^\n]+)$", release, re.M)
        self.assertGreaterEqual(len(keys), 4)
        for key in keys:
            self.assertNotIn("github.sha", key, "a per-commit key adds an entry per commit")
        for job in ("desktop-linux", "desktop-windows"):
            section = _jobs(release)[job]
            self.assertIn("id: cargo-cache", section, job)
            save = re.search(r"- name: Save compiled crates[^\n]*\n\s+if: ([^\n]+)\n", section)
            self.assertIsNotNone(save, job)
            self.assertIn("steps.cargo-cache.outputs.cache-hit != 'true'", save.group(1), job)

        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertNotIn("uses: actions/cache@", ci, "the combined action saves from every branch")
        save = re.search(r"- name: Save compiled crates[^\n]*\n\s+if: ([^\n]+)\n", ci)
        self.assertIsNotNone(save, "ci.yml saves the cargo cache in a step of its own")
        self.assertIn("github.ref == 'refs/heads/main'", save.group(1))
        self.assertIn("steps.cargo-cache.outputs.cache-hit != 'true'", save.group(1))

    def test_the_parsers_see_the_real_workflows(self):
        # Negative control: an empty parse would make the checks above pass for nothing.
        release = (WORKFLOWS / "release.yml").read_text()
        self.assertGreaterEqual(len(_jobs(release)), 10)
        self.assertEqual(_triggers(release), {"push"})
        self.assertEqual(_timeout(_jobs(release)["engine-windows"]) is not None, True)


if __name__ == "__main__":
    unittest.main()

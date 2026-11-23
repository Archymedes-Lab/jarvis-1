"""Promoting a verified dry run to a release (release/promote.py, .github/workflows/release.yml).

A tag on the commit of a successful dry run does not rebuild: it re-checks the dry run's
recorded builds and re-runs the same assemble + content gate under the tag's own name. The
default is the old behaviour (build cold); only a dry run that passes every check is reused,
and a dry run that exists but does not match is a refusal that names the tag to use.
"""

import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import promote  # noqa: E402

SHA = "0006f366a0c6e079d0193beacfdb455e3f25fe73"
RUN = {"id": 11, "head_sha": SHA, "head_branch": "release-test/dry", "event": "push",
       "status": "completed", "conclusion": "success", "actor": {"login": "chris"},
       "created_at": "2026-11-06T10:00:00Z"}
ARTIFACTS = {11: [{"name": "release-out", "expired": False}, {"name": "build-records", "expired": False}]}
VERSION = "2026.11.06-7"


def decide(runs=None, artifacts=None, actor="chris", allowed=(), version=VERSION, built=(VERSION, SHA)):
    return promote.decide(runs if runs is not None else [RUN], artifacts if artifacts is not None else ARTIFACTS,
                          sha=SHA, tag_version=version, actor=actor, allowed_actors=allowed,
                          read_record=lambda run_id: built)


class Decide(unittest.TestCase):
    def test_a_matching_successful_dry_run_is_promoted(self):
        d = decide()
        self.assertEqual((d.kind, d.run_id), ("promote", 11))

    def test_no_dry_run_of_the_commit_builds_cold(self):
        for runs in ([], [dict(RUN, head_sha="f" * 40)]):
            self.assertEqual(decide(runs=runs).kind, "build")

    def test_a_failed_or_unfinished_dry_run_is_never_reused(self):
        for patch in ({"conclusion": "failure"}, {"conclusion": "cancelled"}, {"status": "in_progress", "conclusion": None}):
            self.assertEqual(decide(runs=[dict(RUN, **patch)]).kind, "build", patch)

    def test_only_a_push_to_a_release_test_branch_counts(self):
        # Anyone can push other branches or dispatch other events; a dry run is a release-test/* push.
        for patch in ({"head_branch": "main"}, {"head_branch": "feature/x"}, {"event": "workflow_dispatch"},
                      {"head_branch": "release-testing"}):
            self.assertEqual(decide(runs=[dict(RUN, **patch)]).kind, "build", patch)

    def test_expired_or_missing_artifacts_build_cold(self):
        expired = {11: [{"name": "release-out", "expired": True}, {"name": "build-records", "expired": False}]}
        missing = {11: [{"name": "release-out", "expired": False}]}
        self.assertEqual(decide(artifacts=expired).kind, "build")
        self.assertEqual(decide(artifacts=missing).kind, "build")

    def test_a_dry_run_started_by_someone_else_builds_cold_unless_allowed(self):
        self.assertEqual(decide(actor="sonia").kind, "build")
        # The list names whose dry runs may be promoted (here the run was started by chris).
        self.assertEqual(decide(actor="sonia", allowed=("chris",)).kind, "promote")
        self.assertEqual(decide(actor="sonia", allowed=("sonia",)).kind, "build")

    def test_a_version_mismatch_is_a_refusal_that_names_the_tag_to_use(self):
        d = decide(version="2026.11.06-1")
        self.assertEqual(d.kind, "refuse")
        self.assertIn("v" + VERSION, d.reason)

    def test_records_of_another_commit_are_refused(self):
        self.assertEqual(decide(built=(VERSION, "e" * 40)).kind, "refuse")

    def test_the_newest_usable_dry_run_wins(self):
        older = dict(RUN, id=5, created_at="2026-11-05T10:00:00Z")
        arts = {**ARTIFACTS, 5: ARTIFACTS[11]}
        self.assertEqual(decide(runs=[older, RUN], artifacts=arts).run_id, 11)
        self.assertEqual(decide(runs=[RUN, older], artifacts=arts).run_id, 11)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class Stage(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.out, self.rec, self.stage = self.tmp / "release-out", self.tmp / "records", self.tmp / "stage"
        for d in (self.out, self.rec):
            d.mkdir()
        self.data = b"engine bytes"
        (self.out / "engine.zip").write_bytes(self.data)
        meta = {"engine.zip": {"bytes": len(self.data), "sha256": _sha(self.data)}}
        self.record = {"edition": "windows", "version": VERSION, "commit": SHA, "files": meta}
        (self.rec / "windows-build.json").write_text(json.dumps(self.record))
        self.manifest = {"version": VERSION, "tag": "release-test/dry", "commit": SHA, "files": meta}
        (self.out / "manifest.json").write_text(json.dumps(self.manifest))
        self.addCleanup(self._t.cleanup)

    def run_stage(self):
        return promote.stage(self.out, self.rec, self.stage, sha=SHA, version=VERSION)

    def test_recorded_files_and_their_records_are_staged_side_by_side(self):
        self.run_stage()
        self.assertEqual(sorted(p.name for p in self.stage.iterdir()), ["engine.zip", "windows-build.json"])

    def test_a_changed_file_is_refused(self):
        (self.out / "engine.zip").write_bytes(b"tampered")
        with self.assertRaises(SystemExit) as cm:
            self.run_stage()
        self.assertIn("engine.zip", str(cm.exception))

    def test_a_missing_file_is_refused(self):
        (self.out / "engine.zip").unlink()
        with self.assertRaises(SystemExit):
            self.run_stage()

    def test_a_record_of_another_version_or_commit_is_refused(self):
        for patch in ({"version": "2026.11.06-8"}, {"commit": "e" * 40}):
            (self.rec / "windows-build.json").write_text(json.dumps({**self.record, **patch}))
            with self.assertRaises(SystemExit, msg=str(patch)):
                self.run_stage()

    def test_a_manifest_that_disagrees_with_the_records_is_refused(self):
        # Two independent copies of the digests (the records, and the manifest the dry run gated):
        # changing only one of them is caught.
        other = {"engine.zip": {"bytes": 1, "sha256": "0" * 64}}
        (self.out / "manifest.json").write_text(json.dumps({**self.manifest, "files": other}))
        with self.assertRaises(SystemExit) as cm:
            self.run_stage()
        self.assertIn("manifest", str(cm.exception))

    def test_no_records_is_refused(self):
        (self.rec / "windows-build.json").unlink()
        with self.assertRaises(SystemExit):
            self.run_stage()

    def test_a_file_that_escapes_the_folder_is_refused(self):
        evil = {**self.record, "files": {"../outside.bin": self.record["files"]["engine.zip"]}}
        (self.rec / "windows-build.json").write_text(json.dumps(evil))
        with self.assertRaises(SystemExit):
            self.run_stage()


class Workflow(unittest.TestCase):
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text()

    def jobs(self):
        body = self.text[self.text.index("\njobs:\n") + 6:]
        parts = re.split(r"^  ([a-z0-9-]+):\n", body, flags=re.M)
        return {n: s for n, s in zip(parts[1::2], parts[2::2])}

    def test_every_build_and_test_job_is_skipped_when_a_dry_run_is_promoted(self):
        jobs = self.jobs()
        for name in ("server", "server-install-test", "desktop-linux", "desktop-windows", "engine-windows",
                     "windows-source-smoke", "windows-setup", "windows-install-test", "draft"):
            self.assertIn("needs.meta.outputs.promote_run == ''", jobs[name], name)
        # verify always runs: a promoted release passes the same static gate and unit suite.
        self.assertNotIn("promote_run", jobs["verify"])

    def test_the_promote_job_reassembles_and_drafts_with_least_privilege(self):
        job = self.jobs()["promote"]
        self.assertIn("needs.meta.outputs.promote_run != ''", job)
        self.assertIn("verify", re.search(r"needs: \[([^\]]*)\]", job).group(1))
        self.assertIn("actions: read", job)
        self.assertIn("contents: write", job)
        self.assertIn("gh run download", job)
        self.assertIn("release/promote.py stage", job)
        self.assertIn("release/assemble.py", job)       # the content gate runs again, under the tag's name
        self.assertIn("gh release create", job)
        self.assertIn("--draft", job)                    # still unsigned and unpublished
        self.assertNotIn("actions: write", job)

    def test_a_dry_run_keeps_the_build_records_for_seven_days(self):
        self.assertRegex(self.text, r"name: build-records\n\s+path: [^\n]*build\.json[^\n]*\n\s+retention-days: 7")

    def test_meta_can_read_runs_and_artifacts_but_nothing_else(self):
        meta = self.jobs()["meta"]
        self.assertIn("actions: read", meta)
        self.assertIn("release/promote.py find", meta)
        self.assertNotIn("write", meta)


if __name__ == "__main__":
    unittest.main()

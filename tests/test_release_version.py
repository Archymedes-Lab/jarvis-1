"""Release version ordering and the publish step's refusal to go backwards."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import publish  # noqa: E402
import versioning as v  # noqa: E402


class Ordering(unittest.TestCase):
    def ok(self, cand, live, **kw):
        v.check_ordering(cand, live, **kw)

    def refused(self, cand, live, **kw):
        with self.assertRaises(v.VersionError):
            v.check_ordering(cand, live, **kw)

    def test_newer_is_accepted(self):
        self.ok("2026.10.31", "2026.10.30")
        self.ok("v2026.11.01", "2026.10.30")
        self.ok("2026.10.31-2", "2026.10.31")
        self.ok("2026.10.31-10", "2026.10.31-9")  # numeric, not string, order

    def test_equal_is_refused(self):
        self.refused("2026.10.31", "2026.10.31")
        self.refused("2026.10.31", "2026.10.31-1")  # no suffix is the first release of the day
        self.refused("2026.10.31-2", "2026.10.31-2")

    def test_older_is_refused(self):
        self.refused("2026.10.29", "2026.10.30")
        self.refused("2026.10.31", "2026.10.31-2")
        self.refused("2026.10.31-9", "2026.10.31-10")
        self.refused("2025.12.31", "2026.01.01")

    def test_the_dotted_candidate_that_nearly_shipped(self):
        # 2026.10.29.1 is not a tag version, and it also sorts below the live 2026.10.30.
        self.refused("2026.10.29.1", "2026.10.30")
        self.refused("2026.10.29.1", "")
        self.assertLess(v.live_key("2026.10.29.1"), v.live_key("2026.10.30"))

    def test_legacy_dotted_versions_can_be_the_live_side(self):
        self.ok("2026.10.31", "2026.10.30")
        self.refused("2026.10.30", "2026.10.30")
        self.ok("2026.10.30-2", "2026.10.30")

    def test_nothing_live_accepts_any_valid_candidate(self):
        self.ok("2026.10.31", "")
        self.ok("2026.10.31", None)

    def test_malformed_candidates_are_refused(self):
        for bad in ("", "latest", "2026.10", "2026.13.01", "2026.02.30", "2026.10.31-00", "2026.10.31-01",
                    "2026.10.31.1", "2026-10-31", "v2026.1.5"):
            self.refused(bad, "2026.10.30")

    def test_dry_run_versions(self):
        # A dry run's -0 sorts before the day's first tag; -<run number> after it.
        self.ok("2026.11.03-0", "2026.10.30-2")
        self.refused("2026.10.31-0", "2026.10.31")
        self.ok("2026.11.04-412", "2026.11.04-411")
        self.ok("2026.11.04-412", "2026.11.03-0")

    def test_unorderable_live_version_fails_closed(self):
        self.refused("2026.11.01", "banana")

    def test_rollback_allows_equal_or_older_but_not_invalid(self):
        self.ok("2026.10.29", "2026.10.30", rollback=True)
        self.ok("2026.10.30", "2026.10.30", rollback=True)
        self.refused("2026.10.29.1", "2026.10.30", rollback=True)


class PublishRefuses(unittest.TestCase):
    """publish() must stop on ordering before it touches the site."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = Path(self.tmp.name) / "site"
        d = self.site / publish.DOWNLOADS
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps({"version": "2026.10.30", "files": {}}))
        self.release = Path(self.tmp.name) / "release"
        self.release.mkdir()
        self._check, self._pinned = publish.check.check, publish.pinned
        publish.check.check = lambda *a, **k: ([], {}, ("releaser", "SHA256:x"))
        publish.pinned = lambda: {"SHA256:x"}

    def tearDown(self):
        publish.check.check, publish.pinned = self._check, self._pinned
        self.tmp.cleanup()

    def attempt(self, version, **kw):
        (self.release / "manifest.json").write_text(json.dumps({"version": version, "tag": "v" + version}))
        manifest = self.site / publish.DOWNLOADS / "manifest.json"
        before = manifest.read_text()
        with self.assertRaises(SystemExit) as cm:
            publish.publish(self.release, self.site, "v" + version, **kw)
        self.assertEqual(manifest.read_text(), before, "a refused publish must leave the site untouched")
        return str(cm.exception)

    def test_older_equal_and_dotted_candidates_stop_before_the_site_changes(self):
        for version in ("2026.10.29", "2026.10.30", "2026.10.29.1"):
            self.assertIn("REFUSED", self.attempt(version), version)

    def test_live_version_is_read_from_the_sites_manifest(self):
        self.assertEqual(publish.live_version(self.site), "2026.10.30")
        self.assertEqual(publish.live_version(Path(self.tmp.name) / "nowhere"), "")


if __name__ == "__main__":
    unittest.main()


class PublishAuthor(unittest.TestCase):
    """Vercel blocked the 2026.11.03-0 deployment: its commit author was the
    made-up "argus-release", which has no Git account."""

    def test_the_site_commit_is_not_given_a_made_up_author(self):
        import publish
        src = Path(publish.__file__).read_text()
        self.assertNotIn("user.name=argus-release", src)
        self.assertNotIn("user.email=releases@", src)
        self.assertIn('"config", "user.email"', src)


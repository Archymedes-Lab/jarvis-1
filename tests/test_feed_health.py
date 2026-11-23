"""A failing threat feed is a coverage failure every run until it recovers.

Measured 2026-10-27: URLhaus, ThreatFox and MalwareBazaar answered "HTTP 410
Gone" from 2026-10-21 (abuse.ch has required an Auth-Key since 2025-06-30).
Each feed retries once a day, so only that one run mentioned it; the hourly
runs between recorded the feeds job as complete over six-day-old indicators.
"""
import io
import os
import tempfile
import unittest
from unittest import mock

from jarvis.core import collection
from jarvis.core.store import Store
from jarvis.intel import feeds
from jarvis.service import jobs


class AuthKeyTests(unittest.TestCase):
    def test_key_is_sent_only_to_abuse_ch(self):
        with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: "k-123"}):
            self.assertEqual(feeds._auth_headers("https://urlhaus.abuse.ch/downloads/csv/"),
                             {"Auth-Key": "k-123"})
            self.assertEqual(feeds._auth_headers("https://abuse.ch/x"), {"Auth-Key": "k-123"})
            for url in ("https://lists.blocklist.de/lists/all.txt",
                        "https://abuse.ch.evil.example/x", "https://notabuse.ch/x"):
                self.assertEqual(feeds._auth_headers(url), {}, url)

    def config(self, doc):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, True))
        path = os.path.join(d, "config.json")
        with open(path, "w") as fh:
            fh.write(doc)
        return mock.patch("jarvis.core.paths.CONFIG_PATH", path)

    def test_no_key_no_header(self):
        with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: ""}), self.config("{}"):
            self.assertEqual(feeds._auth_headers("https://threatfox.abuse.ch/export/csv/full/"), {})

    def test_key_from_config(self):
        with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: ""}), \
                self.config('{"abuse_ch_auth_key": " conf-key "}'):
            self.assertEqual(feeds.abusech_key(), "conf-key")

    def test_unreadable_or_odd_config_means_no_key(self):
        for doc in ("not json", "[]", "null"):
            with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: ""}), self.config(doc):
                self.assertEqual(feeds.abusech_key(), "", doc)

    def test_abuse_ch_feeds_are_identified_by_host(self):
        self.assertTrue(feeds.is_abusech("urlhaus-full"))
        self.assertTrue(feeds.is_abusech("malwarebazaar"))
        self.assertTrue(feeds.is_abusech("feodo"))
        self.assertFalse(feeds.is_abusech("blocklist-de"))
        self.assertFalse(feeds.is_abusech("no-such-feed"))


class KeyedExportTests(unittest.TestCase):
    """abuse.ch moved its exports to {platform}-api.abuse.ch with the key in the path
    (old URLs 410 Gone; new ones verified with a real key 2026-11-04)."""
    KEY = "secret-key-123"
    ABUSE = ("threatfox", "malwarebazaar", "urlhaus", "bazaar-full", "threatfox-full", "urlhaus-full")

    def test_the_six_abuse_ch_feeds_use_keyed_exports_and_store_only_the_placeholder(self):
        for name in self.ABUSE:
            url = feeds.FEEDS[name]["url"]
            self.assertIn("-api.abuse.ch/v2/files/exports/" + feeds.KEY_SLOT + "/", url, name)
        self.assertNotIn(feeds.KEY_SLOT, feeds.FEEDS["feodo"]["url"])

    def test_the_key_goes_into_the_request_path_only(self):
        seen = {}

        class Resp(io.BytesIO):
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def opener(req, timeout=None):
            seen["url"], seen["headers"] = req.full_url, dict(req.header_items())
            return Resp(b"# sha256_hash\nab\n")
        url = feeds.FEEDS["malwarebazaar"]["url"]
        with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: self.KEY}), \
                mock.patch.object(feeds.urllib.request, "urlopen", opener):
            feeds.fetch(url, 1000)
        self.assertIn("/exports/" + self.KEY + "/sha256_recent.txt", seen["url"])
        self.assertNotIn(self.KEY, url)                                  # the table keeps the slot
        self.assertFalse(any("auth-key" == k.lower() for k in seen["headers"]))

    def test_no_key_is_a_plain_error_and_nothing_is_requested(self):
        with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: ""}), \
                mock.patch("jarvis.core.paths.CONFIG_PATH", "/nonexistent/config.json"), \
                mock.patch.object(feeds.urllib.request, "urlopen", side_effect=AssertionError("requested")):
            with self.assertRaises(ValueError) as ctx:
                feeds.fetch(feeds.FEEDS["urlhaus"]["url"], 1000)
        self.assertIn("abuse_ch_auth_key", str(ctx.exception))

    def test_an_error_never_carries_the_key(self):
        def boom(req, timeout=None):
            raise OSError(f"connection reset while fetching {req.full_url}")
        with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: self.KEY}), \
                mock.patch.object(feeds.urllib.request, "urlopen", boom):
            with self.assertRaises(ValueError) as ctx:
                feeds.fetch(feeds.FEEDS["threatfox"]["url"], 1000)
        self.assertNotIn(self.KEY, str(ctx.exception))
        self.assertIn("<abuse.ch key>", str(ctx.exception))


class FeedsJobTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = os.path.join(self.dir.name, "j.db")
        store = Store(self.db)
        store.db.execute(
            "INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error) "
            "VALUES('urlhaus-full', 1, 0, 0, 0, 'HTTP Error 410: Gone')")
        store.db.execute(
            "INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error) "
            "VALUES('blocklist-de', 1, 10, 10, 10, '')")
        store.db.commit()
        store.close()

    def run_job(self, results, key=""):
        patches = [
            mock.patch.object(feeds, "refresh", return_value=list(results)),
            mock.patch.object(feeds, "refresh_attack", return_value={"name": "attack", "kept": 1}),
            mock.patch.object(feeds, "refresh_tranco", return_value={"name": "tranco", "kept": 1}),
            mock.patch.object(feeds, "prune"),
            mock.patch.object(feeds, "abusech_key", return_value=key),
            mock.patch("jarvis.core.retention.apply", return_value=[]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with collection.observe() as obs:
            findings = jobs._feeds(("wsl",), self.db)
        if isinstance(findings, tuple):
            findings = findings[0]
        return findings, obs

    def test_a_failure_from_an_earlier_run_still_makes_this_run_partial(self):
        # This run fetched nothing from abuse.ch (not due); the stored error stands.
        findings, obs = self.run_job([])
        self.assertEqual(obs.status, "partial")
        self.assertIn("feed:urlhaus-full", obs.error)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("urlhaus-full" in t or "feed failed" in t for t in titles), titles)
        text = " ".join(f["detail"] for f in findings)
        self.assertIn("Auth-Key", text)

    def test_with_a_key_configured_the_advice_is_not_given(self):
        findings, _obs = self.run_job([], key="k")
        text = " ".join(f["detail"] for f in findings)
        self.assertNotIn("auth.abuse.ch", text)
        self.assertIn("410", text)

    def test_recovery_clears_it(self):
        store = Store(self.db)
        store.db.execute("UPDATE feed_runs SET error='' WHERE name='urlhaus-full'")
        store.db.commit()
        store.close()
        findings, obs = self.run_job([{"name": "urlhaus-full", "kept": 5}])
        self.assertEqual(obs.status, "complete")
        self.assertFalse(any("failed" in f["title"] for f in findings))

    def test_the_key_never_appears_in_findings(self):
        with mock.patch.dict(os.environ, {feeds.ABUSECH_KEY_ENV: "SECRET-KEY-VALUE"}):
            findings, obs = self.run_job([{"name": "urlhaus-full",
                                           "error": "HTTP Error 403: Forbidden"}],
                                         key="SECRET-KEY-VALUE")
        blob = repr(findings) + obs.error
        self.assertNotIn("SECRET-KEY-VALUE", blob)


class ParseFailurePersistsTests(unittest.TestCase):
    def test_parse_failure_is_recorded_for_later_runs(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "j.db"))
            try:
                spec = {"url": "https://example.invalid/x", "max_bytes": 10,
                        "parse": mock.Mock(side_effect=ValueError("bad shape"))}
                with mock.patch.object(feeds, "fetch", return_value=b"x"):
                    r = feeds.ingest(store, "cins", spec)
                self.assertIn("parse failed", r["error"])
                self.assertIn("cins", feeds.failing(store))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()


class SmallCommits(unittest.TestCase):
    def test_ingest_commits_in_small_chunks(self):
        import hashlib
        rows = "\n".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(1, 5001))
        spec = {"url": "https://example.test/x", "max_bytes": 10 ** 7,
                "parse": lambda raw: [("sha256", line, "") for line in raw.decode().splitlines()]}
        commits = []
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "j.db"))
            real_commit = store.commit
            store.commit = lambda: (commits.append(1), real_commit())
            with mock.patch.object(feeds, "fetch", return_value=rows.encode()), \
                    mock.patch.object(feeds.time, "sleep"):
                r = feeds.ingest(store, "t", spec)
            n = store.db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            store.close()
        self.assertEqual(r.get("error"), None)
        self.assertEqual(n, 5000)
        self.assertGreaterEqual(len(commits), 5000 // feeds.WRITE_CHUNK)
        self.assertLessEqual(feeds.WRITE_CHUNK, 5000)

import io
import json
import os
import unittest
from unittest import mock

from jarvis.service import selfupdate as updates


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener(payload):
    calls = []

    def go(req, timeout=None):
        calls.append(req.full_url)
        if isinstance(payload, Exception):
            raise payload
        return Resp(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
    go.calls = calls
    return go


class UpdateTests(unittest.TestCase):
    def setUp(self):
        updates._cache.update(at=0.0, answer=None, ttl=0.0)

    def test_order_is_by_date_then_number_not_by_string(self):
        self.assertTrue(updates.is_newer("2026.11.04-0", "2026.11.03-0"))
        self.assertTrue(updates.is_newer("2026.11.03-2", "2026.11.03-1"))
        self.assertTrue(updates.is_newer("2026.11.03-10", "2026.11.03-9"))
        self.assertTrue(updates.is_newer("2026.11.03-2", "2026.11.03"))
        self.assertFalse(updates.is_newer("2026.11.03-0", "2026.11.03-0"))
        self.assertFalse(updates.is_newer("2026.11.03-0", "2026.11.03"))
        self.assertTrue(updates.is_newer("2026.11.03-2", "2026.11.03-0"))
        self.assertFalse(updates.is_newer("2026.11.02-5", "2026.11.03-0"))

    def test_a_version_that_is_not_a_release_never_counts_as_newer(self):
        for bad in ("", "dev", "latest", "2026.13.40", None):
            self.assertIsNone(updates.version_key(bad))
            self.assertFalse(updates.is_newer(bad, "2026.11.03-0"))
        self.assertFalse(updates.is_newer("2026.11.04-0", "dev"))

    def test_reads_the_newest_version_and_caches_it(self):
        o = opener({"version": "2026.11.09-0", "files": {}})
        a = updates.latest(now=1000, opener=o)
        self.assertEqual((a["latest"], a["error"], a["enabled"]), ("2026.11.09-0", "", True))
        updates.latest(now=2000, opener=o)
        self.assertEqual(len(o.calls), 1, "cached for hours")
        updates.latest(now=1000 + updates.CACHE_S + 1, opener=o)
        self.assertEqual(len(o.calls), 2)
        self.assertEqual(o.calls[0], updates.MANIFEST)

    def test_a_failure_is_quiet_keeps_the_last_answer_and_retries_sooner(self):
        updates.latest(now=0, opener=opener({"version": "2026.11.09-0"}))
        bad = opener(OSError("offline"))
        a = updates.latest(now=updates.CACHE_S + 1, opener=bad)
        self.assertEqual(a["latest"], "2026.11.09-0")
        self.assertIn("could not check", a["error"])
        updates.latest(now=updates.CACHE_S + 2, opener=bad)
        self.assertEqual(len(bad.calls), 1)
        updates.latest(now=updates.CACHE_S + 1 + updates.RETRY_S + 1, opener=bad)
        self.assertEqual(len(bad.calls), 2)

    def test_junk_is_refused(self):
        for payload in (b"<html>", {"version": "tomorrow"}, {"nope": 1}, [1], b"x" * (updates.MAX_BYTES + 5)):
            updates._cache.update(at=0.0, answer=None, ttl=0.0)
            a = updates.latest(now=1, opener=opener(payload))
            self.assertIsNone(a["latest"], payload if not isinstance(payload, bytes) else "bytes")
            self.assertIn("could not check", a["error"])

    def test_can_be_turned_off_and_makes_no_request(self):
        o = opener({"version": "2026.11.09-0"})
        with mock.patch.dict(os.environ, {"ARGUS_UPDATE_CHECK": "0"}):
            a = updates.latest(now=1, opener=o)
        self.assertFalse(a["enabled"])
        self.assertEqual(o.calls, [])

    def test_only_https_or_loopback_manifests(self):
        with mock.patch.dict(os.environ, {"ARGUS_UPDATE_MANIFEST": "http://evil.example/m.json"}):
            o = opener({"version": "2026.11.09-0"})
            a = updates.latest(now=1, opener=o)
        self.assertEqual(o.calls, [])
        self.assertIn("could not check", a["error"])
        with mock.patch.dict(os.environ, {"ARGUS_UPDATE_MANIFEST": "http://127.0.0.1:9/m.json"}):
            self.assertEqual(updates._manifest_url(), "http://127.0.0.1:9/m.json")

    def test_sends_nothing_about_the_machine(self):
        seen = {}

        def go(req, timeout=None):
            seen.update(req.header_items())
            return Resp(json.dumps({"version": "2026.11.09-0"}).encode())
        updates.latest(now=1, opener=go)
        self.assertEqual(sorted(k.lower() for k in seen), ["accept", "user-agent"])
        self.assertEqual(seen["User-agent"], "argus-update-check")


if __name__ == "__main__":
    unittest.main()

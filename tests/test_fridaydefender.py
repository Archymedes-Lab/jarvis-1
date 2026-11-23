"""Friday Defender reviews (jarvis/collectors/host/fridaydefender.py): each test
names the invariant it holds. A fake `friday` emits real headless JSONL, so the
review child, fingerprint, parser and redaction run for real; no model is called."""

import json
import os
import shutil
import stat
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from jarvis.collectors.host import fridaydefender as fd


class MetaStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=""):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


def fake_friday(directory, summary, status="completed", gap=False, touch=None):
    """An executable that behaves like `friday --json`: JSONL on stdout."""
    path = os.path.join(directory, "friday")
    records = [{"type": "session"}, {"type": "turn_start"}, {"type": "text", "text": "reviewing"},
               {"type": "turn_end", "status": status, "summary": summary}]
    lines = []
    for i, r in enumerate(records, 1):
        seq = i + (1 if gap and i > 2 else 0)
        lines.append(json.dumps({"v": 1, "seq": seq, "at": "2026-10-29T00:00:00Z", **r}))
    body = "\n".join(lines)
    script = textwrap.dedent(f"""\
        #!{sys.executable}
        import sys, os
        touch = {touch!r}
        if touch:
            open(os.path.join(sys.argv[sys.argv.index('-C') + 1], touch), 'w').write('x')
        assert '--defender' in sys.argv and '--json' in sys.argv
        print({body!r})
        """)
    with open(path, "w") as fh:
        fh.write(script)
    os.chmod(path, 0o755)
    return path


# A GitHub-token-shaped fake, assembled at runtime so no token literal is committed.
FAKE_TOKEN = "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789"
BLOCK = ('Done.\n<<<FINDINGS\n[{"title": "SQL built from request", "file": "app/db.py", "line": 12, '
         '"severity": "critical", "why": "user input concatenated", "fix": "use parameters"},'
         '{"title": "token in code ' + FAKE_TOKEN + '", "file": "cfg.py", "line": 3, '
         '"severity": "low", "why": "secret ' + FAKE_TOKEN + ' committed", "fix": "rotate"}]\n'
         'FINDINGS>>>')


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fridaydef-")
        self.root = os.path.join(self.tmp, "proj")
        os.makedirs(os.path.join(self.root, "app"))
        with open(os.path.join(self.root, "app", "db.py"), "w") as fh:
            fh.write("q = 'select ' + x\n")
        self.runs = os.path.join(self.tmp, "runs")
        self.consent = os.path.join(self.tmp, "consent.json")
        self.patches = [mock.patch.object(fd, "RUNS", self.runs), mock.patch.object(fd, "CONSENT", self.consent),
                        mock.patch.object(fd, "LOCK", os.path.join(self.tmp, "lock"))]
        for p in self.patches:
            p.start()
        self.patches.append(mock.patch.object(fd, "friday_provider", return_value=("anthropic", "m1")))
        self.patches[-1].start()
        self.store = MetaStore()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def grant(self, **kw):
        fd.write_consent({"v": 1, "granted_at": time.time(), "roots": [self.root], "budget": "0.10",
                          "provider": "anthropic", "model": "m1", "revoked": False, **kw}, self.consent)


class Consent(Fixture):
    def test_no_consent_only_asks(self):  # I1
        spawned = []
        with mock.patch.object(fd, "find_friday", return_value=None):
            out = fd.audit(self.store, spawn=lambda *a, **k: spawned.append(a))
        self.assertEqual([f["title"] for f in out], ["Friday Defender reviews are off"])
        self.assertIn("jarvis defender enable", out[0]["detail"])
        self.assertEqual(spawned, [])

    def test_consent_file_others_can_read_is_no_consent(self):  # I1
        self.grant()
        os.chmod(self.consent, 0o644)
        self.assertIsNone(fd.load_consent(self.consent))

    def test_revoked_consent_is_no_consent_and_daemon_cannot_grant(self):  # I1
        self.grant()
        fd.revoke("test", self.consent)
        self.assertIsNone(fd.load_consent(self.consent))
        self.assertEqual(stat.S_IMODE(os.stat(self.consent).st_mode), 0o600)


class Review(Fixture):
    def run_review(self, friday):
        fd.review(self.root, friday, "0.10", out_dir=self.runs, deadline=30)
        results = [f for f in os.listdir(self.runs) if f.endswith(".result.json")]
        self.assertEqual(len(results), 1)
        self.assertFalse([f for f in os.listdir(self.runs) if f.endswith(".jsonl")])   # I4: transcript gone
        with open(os.path.join(self.runs, results[0])) as fh:
            return json.load(fh)

    def test_findings_capped_redacted_and_relative(self):  # I3, I4
        r = self.run_review(fake_friday(self.tmp, BLOCK))
        self.assertEqual(r["status"], "completed")
        self.assertFalse(r["changed"])
        f = r["findings"]
        self.assertEqual((f[0]["severity"], f[0]["model_severity"]), ("medium", "critical"))
        blob = json.dumps(r)
        self.assertNotIn(FAKE_TOKEN, blob)
        self.assertIn("ghp_********", blob)

    def test_changed_folder_is_critical_and_withdraws_consent(self):  # I2
        self.grant()
        r = self.run_review(fake_friday(self.tmp, BLOCK, touch="planted.txt"))
        self.assertTrue(r["changed"])
        results, alarms = fd.collect(self.store, time.time(), runs=self.runs)
        self.assertEqual(alarms[0]["severity"], "critical")
        self.assertIsNone(fd.load_consent(self.consent))

    def test_sequence_gap_and_missing_block_are_incomplete(self):  # I6
        r = self.run_review(fake_friday(self.tmp, "no block here", gap=True))
        self.assertTrue(any("sequence gap" in p for p in r["problems"]))
        self.assertTrue(any("without a findings block" in p for p in r["problems"]))
        out = fd.result_findings({self.root: {**r, "at": time.time()}})
        self.assertEqual(out[0]["category"], "visibility")

    def test_budget_stop_is_reported_not_clean(self):  # I6
        r = self.run_review(fake_friday(self.tmp, BLOCK, status="iteration_limit"))
        out = fd.result_findings({self.root: {**r, "at": time.time()}})
        self.assertTrue(any(f["category"] == "visibility" and "incomplete" in f["title"] for f in out))
        self.assertTrue(any(f["title"] == "Defender review: SQL built from request" for f in out))

    def test_findings_are_bounded(self):  # I5
        many = "<<<FINDINGS\n" + json.dumps([{"title": f"t{i}", "severity": "low"} for i in range(50)]) + "\nFINDINGS>>>"
        self.assertEqual(len(fd.parse_findings(many, self.root)), fd.MAX_FINDINGS)


class Scheduling(Fixture):
    def test_one_review_at_a_time_and_weekly(self):  # I5
        self.grant()
        spawned = []

        class P:
            pid = os.getpid()                     # alive: the lock reads as running

        def spawn(argv, **kw):
            spawned.append(argv)
            return P()
        with mock.patch.object(fd, "find_friday", return_value="/bin/true"):
            fd.audit(self.store, spawn=spawn)
            fd.audit(self.store, spawn=spawn)    # still running: no second review
        self.assertEqual(len(spawned), 1)
        self.assertIn(self.root, spawned[0])
        os.remove(fd.LOCK)
        self.store.meta[fd.RESULTS_META] = json.dumps({self.root: {"at": time.time(), "status": "completed",
                                                                    "findings": []}})
        with mock.patch.object(fd, "find_friday", return_value="/bin/true"):
            fd.audit(self.store, spawn=spawn)    # reviewed this week: nothing new
        self.assertEqual(len(spawned), 1)

    def test_missing_friday_after_consent_is_not_observed(self):  # I6
        self.grant()
        with mock.patch.object(fd, "find_friday", return_value=None):
            out = fd.audit(self.store, spawn=lambda *a, **k: self.fail("must not spawn"))
        self.assertEqual(out[0]["category"], "visibility")


class ProviderAndContent(Fixture):
    def test_provider_change_pauses_reviews(self):  # I1
        self.grant()
        with mock.patch.object(fd, "find_friday", return_value="/bin/true"), \
                mock.patch.object(fd, "friday_provider", return_value=("openai", "gpt-x")):
            out = fd.audit(self.store, spawn=lambda *a, **k: self.fail("must not spawn"))
        self.assertIn("paused", out[0]["title"])
        self.assertIn("anthropic/m1", out[0]["detail"])

    def test_same_size_same_mtime_edit_is_detected(self):  # I2
        p = os.path.join(self.root, "app", "db.py")
        st = os.stat(p)
        before = fd.fingerprint(self.root)[0]
        with open(p, "w") as fh:
            fh.write("q = 'SELECT ' + x\n")             # same length
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertNotEqual(fd.fingerprint(self.root)[0], before)

    def test_provider_read_never_returns_keys(self):  # I4
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "settings.json"), "w") as fh:
                json.dump({"ARCHYMEDES_PROVIDER": "groq", "GROQ_MODEL": "llama", "GROQ_API_KEY": "not-a-real-key"}, fh)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ARCHYMEDES_PROVIDER", None)
                self.patches[-1].stop()
                try:
                    self.assertEqual(fd.friday_provider(d), ("groq", "llama"))
                finally:
                    self.patches[-1].start()
        finally:
            shutil.rmtree(d)


class Feed(unittest.TestCase):
    def test_feed_states(self):
        d = tempfile.mkdtemp()
        try:
            self.assertIn("not checked yet", fd.feed_findings(time.time(), d)[0]["title"])
            with open(os.path.join(d, "feed-state.json"), "w") as fh:
                json.dump({"schemaVersion": 1, "lastCheckedAt": (time.time() - 3 * 86400) * 1000}, fh)
            titles = [f["title"] for f in fd.feed_findings(time.time(), d)]
            self.assertIn("no signed Defender feed update is active", titles)
            self.assertIn("Defender knowledge feed not checked for over a day", titles)
            with open(os.path.join(d, "feed-state.json"), "w") as fh:
                json.dump({"schemaVersion": 1, "lastCheckedAt": time.time() * 1000, "sequence": 4,
                           "activeDigest": "a" * 64}, fh)
            self.assertEqual(fd.feed_findings(time.time(), d), [])
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()

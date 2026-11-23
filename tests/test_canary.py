"""Canary tokens and the tamper-evident journal (2026-10-12).

Covers: the append-only hash chain and its tamper detection; inert token
generation; the on-box fingerprint tripwire; owner-listener callback ingestion;
external anchoring with an injected submit; and the collector end to end. No
network, no real bait placed outside the temp dir, no attacker ever contacted.
"""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from jarvis.collectors.host import canary as canary_job
from jarvis.core import canary


class FakeStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key):
        return self.meta.get(key)

    def set_meta(self, key, value):
        self.meta[key] = value

    def commit(self):
        pass


class JournalChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.journal = canary.CanaryJournal(self.root)

    def test_append_and_verify_clean_chain(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        self.journal.append("trip", {"id": "a", "reason": "modified"})
        self.assertIsNone(self.journal.verify())
        head = self.journal.head()
        self.assertEqual(head["seq"], 2)
        self.assertNotEqual(head["hash"], canary.GENESIS)

    def test_edit_breaks_the_chain(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        self.journal.append("plant", {"id": "b", "kind": "credential"})
        recs = [json.loads(line) for line in
                self.journal.path.read_text().splitlines()]
        recs[0]["payload"]["id"] = "tampered"          # edit, keep the stored hash
        self.journal.path.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in recs) + "\n")
        broken = self.journal.verify()
        self.assertIsNotNone(broken)
        self.assertEqual(broken["seq"], 1)
        self.assertEqual(broken["reason"], "record altered")

    def test_deletion_breaks_the_chain(self):
        for i in range(3):
            self.journal.append("plant", {"id": str(i), "kind": "credential"})
        lines = self.journal.path.read_text().splitlines()
        del lines[1]                                    # drop the middle record
        self.journal.path.write_text("\n".join(lines) + "\n")
        broken = self.journal.verify()
        self.assertIsNotNone(broken)
        # The record that was seq 3 now sits where seq 2 is expected.
        self.assertEqual(broken["reason"], "sequence break")

    def test_reorder_breaks_the_chain(self):
        for i in range(3):
            self.journal.append("plant", {"id": str(i), "kind": "credential"})
        lines = self.journal.path.read_text().splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        self.journal.path.write_text("\n".join(lines) + "\n")
        self.assertIsNotNone(self.journal.verify())

    def test_corrupt_line_is_a_break_not_a_crash(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        # A non-UTF-8 byte and garbage appended by a clumsy tamperer.
        with open(self.journal.path, "ab") as fh:
            fh.write(b"\xff not json at all\n")
        broken = self.journal.verify()          # must not raise
        self.assertIsNotNone(broken)
        self.assertEqual(broken["reason"], "corrupt record")
        # State still enumerates the valid records without throwing.
        self.assertIn("a", self.journal.state()["tokens"])

    def test_record_hash_is_independent_of_key_order(self):
        rec = {"seq": 1, "at": 5, "kind": "plant", "prev": canary.GENESIS,
               "payload": {"b": 2, "a": 1}}
        h1 = canary.record_hash(rec)
        rec2 = {"payload": {"a": 1, "b": 2}, "prev": canary.GENESIS,
                "kind": "plant", "at": 5, "seq": 1, "hash": "ignored"}
        self.assertEqual(h1, canary.record_hash(rec2))


class TokenGenerationTests(unittest.TestCase):
    def test_file_decoy_captures_fingerprint(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("BEGIN OPENSSH PRIVATE KEY\n")
            path = fh.name
        self.addCleanup(os.unlink, path)
        token = canary.make_token("file_decoy", "ssh key", path=path)
        self.assertEqual(token["kind"], "file_decoy")
        self.assertIn("sha256", token["fingerprint"])
        self.assertEqual(token["fingerprint"]["size"], os.path.getsize(path))

    def test_doc_url_requires_owner_base_and_is_unique(self):
        with self.assertRaises(canary.CanaryError):
            canary.make_token("doc_url", "plan")                     # no base
        with self.assertRaises(canary.CanaryError):
            canary.make_token("doc_url", "plan", url_base="not-a-url")
        t1 = canary.make_token("doc_url", "plan", url_base="https://c.example.com/")
        t2 = canary.make_token("doc_url", "plan", url_base="https://c.example.com")
        self.assertTrue(t1["url"].startswith("https://c.example.com/c/"))
        self.assertNotEqual(t1["url"], t2["url"])        # unique per token
        self.assertEqual(t1["url"].count("://"), 1)      # points only at the owner

    def test_credential_is_fake_and_unique(self):
        t1 = canary.make_token("credential", "aws")
        t2 = canary.make_token("credential", "aws")
        self.assertTrue(t1["bait_value"].startswith("AKIA"))
        self.assertNotEqual(t1["bait_value"], t2["bait_value"])
        self.assertIn("secret_fp", t1)

    def test_unknown_kind_rejected(self):
        with self.assertRaises(canary.CanaryError):
            canary.make_token("bomb", "no")


class OnboxTripwireTests(unittest.TestCase):
    def _decoy(self, content="secret"):
        fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        fh.write(content)
        fh.close()
        self.addCleanup(lambda: os.path.exists(fh.name) and os.unlink(fh.name))
        return fh.name

    def test_untouched_decoy_does_not_trip(self):
        path = self._decoy()
        token = canary.make_token("file_decoy", "d", path=path)
        self.assertEqual(canary.onbox_trips({token["id"]: token}), [])

    def test_modified_decoy_trips(self):
        path = self._decoy("original")
        token = canary.make_token("file_decoy", "d", path=path)
        time.sleep(0.01)
        Path(path).write_text("CHANGED BY INTRUDER")
        os.utime(path, (time.time() + 5, time.time() + 5))
        trips = canary.onbox_trips({token["id"]: token})
        self.assertEqual(len(trips), 1)
        self.assertEqual(trips[0]["reason"], "modified")

    def test_same_size_same_mtime_edit_still_caught_by_hash(self):
        path = self._decoy("AAAA")
        token = canary.make_token("file_decoy", "d", path=path)
        st = os.stat(path)
        Path(path).write_text("BBBB")                    # same length
        os.utime(path, (st.st_atime, st.st_mtime))       # restore mtime
        trips = canary.onbox_trips({token["id"]: token})
        self.assertEqual([t["reason"] for t in trips], ["modified"])

    def test_removed_decoy_trips(self):
        path = self._decoy()
        token = canary.make_token("file_decoy", "d", path=path)
        os.unlink(path)
        trips = canary.onbox_trips({token["id"]: token})
        self.assertEqual(trips[0]["reason"], "removed")

    def test_access_is_weak_and_off_by_default(self):
        token = {"id": "x", "kind": "file_decoy", "path": "/decoy",
                 "created_at": 100, "fingerprint": {"sha256": "h", "size": 4,
                                                    "mtime": 200}}
        st = SimpleNamespace(st_size=4, st_mtime=200, st_atime=999)
        stat = lambda p: st
        reader = lambda p: b"same"
        # "same" hashes to something != "h", so without check_access this reads
        # as a (false) modification unless the hash matches; force the hash match:
        import hashlib
        token["fingerprint"]["sha256"] = hashlib.sha256(b"same").hexdigest()
        self.assertEqual(canary.onbox_trips({"x": token}, stat=stat,
                                            read_bytes=reader), [])
        trips = canary.onbox_trips({"x": token}, stat=stat, read_bytes=reader,
                                   check_access=True)
        self.assertEqual([t["reason"] for t in trips], ["accessed"])


class CallbackIngestionTests(unittest.TestCase):
    def _inbox(self, lines):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        for line in lines:
            fh.write(line + "\n")
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_wellformed_hit_parsed_metadata_only(self):
        inbox = self._inbox([json.dumps(
            {"hit_id": "h1", "token": "t1", "ip": "203.0.113.7",
             "ua": "curl/8", "at": 1000, "extra": "x" * 100})])
        hits = canary.read_callbacks(inbox)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["ip"], "203.0.113.7")
        self.assertNotIn("extra", hits[0])               # unknown fields dropped

    def test_malformed_lines_skipped_not_fatal(self):
        inbox = self._inbox([
            "not json", "{}", json.dumps({"hit_id": "h", "token": "t"}),
            json.dumps(["list", "not", "dict"])])
        hits = canary.read_callbacks(inbox)
        self.assertEqual([h["hit_id"] for h in hits], ["h"])

    def test_seen_hits_deduped(self):
        inbox = self._inbox([json.dumps({"hit_id": "h1", "token": "t"})])
        self.assertEqual(canary.read_callbacks(inbox, seen_hits={"h1"}), [])

    def test_oversized_line_skipped(self):
        inbox = self._inbox([json.dumps({"hit_id": "h", "token": "t",
                                         "ua": "z" * 9000})])
        self.assertEqual(canary.read_callbacks(inbox), [])

    def test_missing_inbox_is_empty(self):
        self.assertEqual(canary.read_callbacks(None), [])
        self.assertEqual(canary.read_callbacks("/no/such/inbox"), [])


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = canary.CanaryJournal(Path(self.tmp.name))

    def test_no_anchor_for_empty_chain(self):
        digest, err = canary.anchor_head(self.journal, submit=lambda d: (b"p", []))
        self.assertIsNone(digest)
        self.assertIsNone(err)

    def test_anchor_writes_proof_and_respects_interval(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        calls = []

        def submit(digest):
            calls.append(digest)
            return b"PROOF", ["cal"]

        digest, err = canary.anchor_head(self.journal, now=1000, submit=submit)
        self.assertIsNone(err)
        self.assertTrue((self.journal.anchors / f"{digest}.json").exists())
        self.assertEqual((self.journal.anchors / f"{digest}.ots").read_bytes(),
                         b"PROOF")
        last = {"hash": self.journal.head()["hash"], "at": 1000}
        # Same head, inside the interval: no second submit.
        d2, _ = canary.anchor_head(self.journal, now=1100, last=last, submit=submit)
        self.assertIsNone(d2)
        self.assertEqual(len(calls), 1)

    def test_submit_failure_stays_advisory(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})

        def boom(digest):
            raise RuntimeError("calendar unreachable")

        digest, err = canary.anchor_head(self.journal, now=1, submit=boom)
        self.assertIsNone(digest)
        self.assertEqual(err, "RuntimeError")

    def test_network_disabled_does_not_anchor(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        digest, err = canary.anchor_head(self.journal, network=False,
                                         submit=lambda d: (b"p", []))
        self.assertIsNone(digest)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "canary"

    def _decoy(self, content="BEGIN OPENSSH PRIVATE KEY"):
        p = Path(self.tmp.name) / "id_rsa"
        p.write_text(content)
        return str(p)

    def _titles(self, findings):
        return [f["title"] for f in findings]

    def test_empty_registry_reports_no_tokens(self):
        store = FakeStore()
        out = canary_job.audit(store, root=self.root, conf={}, now=1, network=False, events=[])
        self.assertIn("No canary tokens are planted", self._titles(out))
        self.assertTrue(json.loads(store.meta[canary_job.META])["chain_ok"])

    def test_armed_token_and_then_tripwire(self):
        decoy = self._decoy()
        canary.plant("file_decoy", "ssh key", path=decoy, root=self.root)
        store = FakeStore()
        out = canary_job.audit(store, root=self.root, conf={}, now=1, network=False, events=[])
        self.assertTrue(any("armed" in t for t in self._titles(out)))

        # An intruder edits the decoy; the next pass reports it and records one trip.
        Path(decoy).write_text("stolen")
        out = canary_job.audit(store, root=self.root, conf={}, now=2, network=False, events=[])
        self.assertTrue(any("was touched" in t or "was taken" in t
                            for t in self._titles(out)))
        journal = canary.CanaryJournal(self.root)
        trips = [r for r in journal.records() if r["kind"] == "trip"]
        self.assertEqual(len(trips), 1)

        # A second pass keeps reporting but does not append a duplicate trip.
        canary_job.audit(store, root=self.root, conf={}, now=3, network=False, events=[])
        trips = [r for r in canary.CanaryJournal(self.root).records()
                 if r["kind"] == "trip"]
        self.assertEqual(len(trips), 1)

    def test_callback_raises_critical_and_dedupes(self):
        token = canary.plant("doc_url", "merger plan",
                             url_base="https://c.example.com", root=self.root)
        inbox = Path(self.tmp.name) / "hits.jsonl"
        inbox.write_text(json.dumps(
            {"hit_id": "h1", "token": token["id"], "ip": "198.51.100.9",
             "ua": "Office", "at": 50}) + "\n")
        store = FakeStore()
        conf = {"callback_inbox": str(inbox)}
        out = canary_job.audit(store, root=self.root, conf=conf, now=1, network=False, events=[])
        crit = [f for f in out if f["severity"] == "critical"]
        self.assertTrue(crit)
        self.assertIn("opened off this machine", crit[0]["title"])
        self.assertIn("198.51.100.9", crit[0]["detail"])

        callbacks = [r for r in canary.CanaryJournal(self.root).records()
                     if r["kind"] == "callback"]
        self.assertEqual(len(callbacks), 1)
        # Same inbox again: no duplicate callback recorded.
        canary_job.audit(store, root=self.root, conf=conf, now=2, network=False, events=[])
        callbacks = [r for r in canary.CanaryJournal(self.root).records()
                     if r["kind"] == "callback"]
        self.assertEqual(len(callbacks), 1)

    def test_tampered_journal_is_critical_and_halts_writes(self):
        decoy = self._decoy()
        canary.plant("file_decoy", "ssh key", path=decoy, root=self.root)
        journal = canary.CanaryJournal(self.root)
        recs = journal.path.read_text().splitlines()
        obj = json.loads(recs[0])
        obj["payload"]["label"] = "nothing to see"       # edit, keep stored hash
        journal.path.write_text(json.dumps(obj, sort_keys=True) + "\n")
        before = journal.path.read_text()

        store = FakeStore()
        Path(decoy).write_text("stolen")                 # would trip if writing continued
        out = canary_job.audit(store, root=self.root, conf={}, now=1, network=False, events=[])
        titles = self._titles(out)
        self.assertIn("Canary journal was tampered with", titles)
        # Nothing appended to a chain that no longer verifies.
        self.assertEqual(journal.path.read_text(), before)
        self.assertFalse(json.loads(store.meta[canary_job.META])["chain_ok"])



def _ev(seq, action, path, image="C:\\Windows\\explorer.exe", category="file"):
    return {"seq": seq, "category": category, "action": action, "host": "win",
            "time": "2026-10-12T10:00:00Z", "target": {"type": "file", "path": path},
            "process": {"image": image}}


class PathAndMatcherTests(unittest.TestCase):
    def test_wsl_and_windows_paths_compare_equal(self):
        self.assertEqual(canary.norm_path("/mnt/c/Users/Chris/f.txt"),
                         canary.norm_path("C:\\Users\\chris\\F.TXT"))
        self.assertEqual(canary.norm_path("/home/chris/F"), "/home/chris/F")
        self.assertNotEqual(canary.norm_path("/home/chris/F"),
                            canary.norm_path("/home/chris/f"))

    def _active(self, path="/mnt/c/Users/chris/Documents/passwords.kdbx"):
        return {"t1": {"id": "t1", "kind": "file_decoy", "path": path}}

    def test_delete_and_overwrite_on_decoy_path(self):
        win = "C:\\Users\\chris\\Documents\\passwords.kdbx"
        trips = canary.match_file_events(
            [_ev(1, "delete", win), _ev(2, "create", win)], self._active())
        self.assertEqual([t["reason"] for t in trips], ["removed", "modified"])
        self.assertTrue(all(t["id"] == "t1" for t in trips))
        self.assertIn("explorer.exe", trips[0]["detail"])

    def test_copy_elsewhere_under_the_same_name(self):
        trips = canary.match_file_events(
            [_ev(5, "create", "C:\\Users\\Public\\stage\\passwords.kdbx")],
            self._active())
        self.assertEqual(trips[0]["reason"], "copied")
        self.assertEqual(trips[0]["seq"], 5)

    def test_ignored_events(self):
        events = [
            _ev(1, "create", "C:\\Users\\chris\\Documents\\notes.txt"),   # other file
            _ev(2, "dns_query", "passwords.kdbx", category="network"),      # not a file
            _ev(3, "raw_read", "C:\\Users\\chris\\Documents\\passwords.kdbx"),
            _ev(4, "delete", "C:\\Users\\chris\\Documents\\passwords.kdbx",
                image="/usr/bin/python3"),                                   # JARVIS itself
            "not an event",
        ]
        self.assertEqual(canary.match_file_events(
            events, self._active(), self_images={"/usr/bin/python3"}), [])

    def test_no_decoys_no_work(self):
        self.assertEqual(canary.match_file_events(
            [_ev(1, "delete", "C:\\x")], {"c": {"kind": "credential"}}), [])


class CoverageAndListenerTests(unittest.TestCase):
    def test_coverage_gap_per_class(self):
        active = {"t": {"kind": "file_decoy", "path": "/mnt/c/Users/chris/.ssh/id_backup"}}
        protect = {"ssh": ["C:\\Users\\chris\\.ssh"], "vault": ["/home/chris/vault"]}
        gaps = canary.coverage_gaps(protect, active)
        self.assertEqual([g["class"] for g in gaps], ["vault"])
        self.assertEqual(canary.coverage_gaps(None, active), [])
        self.assertEqual(len(canary.coverage_gaps(protect, {})), 2)

    def test_listener_states(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        beat = Path(tmp.name) / "beat"
        beat.write_text("x")
        now = os.stat(beat).st_mtime
        self.assertEqual(canary.listener_state(None, None)["status"], "unconfigured")
        self.assertEqual(canary.listener_state("inbox", None)["status"], "unverified")
        self.assertEqual(canary.listener_state("inbox", str(beat) + ".gone",
                                               now=now)["status"], "stale")
        self.assertEqual(canary.listener_state("inbox", str(beat), now=now + 10,
                                               max_age=900)["status"], "live")
        self.assertEqual(canary.listener_state("inbox", str(beat), now=now + 901,
                                               max_age=900)["status"], "stale")

    def test_notice_names_no_mechanism(self):
        text = canary.NOTICE.lower()
        for word in ("canary", "decoy", "token", "bait", "sysmon", "http"):
            self.assertNotIn(word, text)


class CollectorLaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "canary"
        self.decoy = Path(self.tmp.name) / "passwords.kdbx"
        self.decoy.write_text("decoy vault")
        canary.plant("file_decoy", "vault", path=str(self.decoy), root=self.root)

    def _audit(self, store, **kw):
        kw.setdefault("events", [])
        return canary_job.audit(store, root=self.root, now=10, network=False, **kw)

    def test_copy_event_is_reported_once_and_cursor_advances(self):
        store = FakeStore()
        copy = _ev(41, "create", "C:\\Users\\Public\\x\\passwords.kdbx")
        out = self._audit(store, conf={}, events=[copy])
        self.assertTrue(any(f["title"] == "Canary decoy was copied: vault" for f in out))
        self.assertEqual(json.loads(store.meta[canary_job.META])["event_cursor"], 41)
        # The same event delivered again records nothing new.
        self._audit(store, conf={}, events=[copy])
        trips = [r for r in canary.CanaryJournal(self.root).records() if r["kind"] == "trip"]
        self.assertEqual(len(trips), 1)
        # A second, different destination is new evidence.
        self._audit(store, conf={}, events=[_ev(42, "create", "D:\\usb\\passwords.kdbx")])
        trips = [r for r in canary.CanaryJournal(self.root).records() if r["kind"] == "trip"]
        self.assertEqual(len(trips), 2)

    def test_coverage_gap_and_dead_listener_are_findings(self):
        store = FakeStore()
        beat = Path(self.tmp.name) / "beat"           # never created: stale
        conf = {"protect": {"keys": [str(Path(self.tmp.name) / "keys")]},
                "callback_inbox": str(Path(self.tmp.name) / "hits.jsonl"),
                "listener_heartbeat": str(beat)}
        out = self._audit(store, conf=conf)
        titles = [f["title"] for f in out]
        self.assertIn("No canary beside protected data: keys", titles)
        self.assertIn("Canary callback listener is not reporting", titles)
        sev = {f["title"]: f["severity"] for f in out}
        self.assertEqual(sev["Canary callback listener is not reporting"], "high")

    def test_doc_canary_without_inbox_is_flagged(self):
        canary.plant("doc_url", "plan", url_base="https://c.example.com", root=self.root)
        out = self._audit(FakeStore(), conf={})
        self.assertIn("Document canaries have no callback inbox",
                      [f["title"] for f in out])

    def test_unreadable_event_log_degrades_to_a_finding(self):
        from unittest import mock

        from jarvis.core.eventlog import LogError
        store = FakeStore()
        store.set_meta(canary_job.META, json.dumps({"event_cursor": 5}))
        with mock.patch("jarvis.core.eventlog.EventLog",
                        side_effect=LogError("history unreadable")):
            out = canary_job.audit(store, root=self.root, conf={}, now=10,
                                   network=False)
        titles = [f["title"] for f in out]
        self.assertIn("Canary event-log lane could not read history", titles)
        self.assertTrue(any("armed" in t for t in titles))       # the job still ran
        meta = json.loads(store.meta[canary_job.META])
        self.assertEqual(meta["event_error"], "LogError")
        self.assertEqual(meta["event_cursor"], 5)                # never lost or reset

    def test_first_pass_starts_at_the_present(self):
        from unittest import mock
        store = FakeStore()
        log = mock.MagicMock(last_seq=977)
        with mock.patch("jarvis.core.eventlog.EventLog", return_value=log):
            canary_job.audit(store, root=self.root, conf={}, now=10, network=False)
        self.assertEqual(json.loads(store.meta[canary_job.META])["event_cursor"], 977)
        log.iter_events.assert_not_called()                      # no history replay


class CliTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.object(canary, "DEFAULT_ROOT", Path(self.tmp.name) / "canary")
        patch.start()
        self.addCleanup(patch.stop)
        conf = mock.patch("jarvis.cli.commands.canary._conf", return_value={})
        conf.start()
        self.addCleanup(conf.stop)

    def _run(self, *argv):
        import contextlib
        import io

        from jarvis.cli.commands import canary as cli
        parser = __import__("argparse").ArgumentParser()
        cli.add_parser(parser.add_subparsers())
        args = parser.parse_args(["canary", *argv])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = args.fn(args, FakeStore())
        return rc, buf.getvalue()

    def test_plant_list_retire_verify_notice(self):
        decoy = Path(self.tmp.name) / "id_backup"
        decoy.write_text("decoy")
        rc, out = self._run("plant", "file_decoy", "ssh", "backup", "--path", str(decoy))
        self.assertEqual(rc, 0)
        tid = out.split()[2]
        rc, out = self._run("list")
        self.assertIn("armed", out)
        self.assertIn("ssh backup", out)
        self.assertEqual(self._run("retire", tid)[0], 0)
        self.assertIn("retired", self._run("list")[1])
        self.assertEqual(self._run("verify"), (0, "journal verifies\n"))
        self.assertEqual(self._run("notice")[1].strip(), canary.NOTICE)
        rc, out = self._run("status", "--json")
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)["chain_ok"])

    def test_doc_url_refused_without_owner_base(self):
        rc, out = self._run("plant", "doc_url", "plan")
        self.assertEqual(rc, 1)
        self.assertIn("not planted", out)



class SysmonVisibilityTests(unittest.TestCase):
    XML = r"""<Sysmon><EventFiltering>
      <RuleGroup><FileCreate onmatch="include">
        <TargetFilename condition="contains">\Users\Public\</TargetFilename>
        <TargetFilename condition="end with">.kdbx</TargetFilename>
      </FileCreate></RuleGroup>
      <RuleGroup><FileCreate onmatch="exclude">
        <TargetFilename condition="contains">\Documents\</TargetFilename>
      </FileCreate></RuleGroup>
      <RuleGroup><FileDeleteDetected onmatch="include">
        <TargetFilename condition="begin with">C:\Users\chris\.ssh\</TargetFilename>
      </FileDeleteDetected></RuleGroup>
    </EventFiltering></Sysmon>"""

    def test_rules_and_visibility(self):
        rules = canary.file_event_rules(self.XML)
        self.assertEqual(len(rules["create"]), 2)       # exclude block not read
        self.assertEqual(len(rules["delete"]), 1)
        seen = canary.sysmon_visible
        self.assertEqual(seen("C:\\Users\\Public\\x.txt", rules),
                         {"create": True, "delete": False})
        self.assertEqual(seen("/mnt/c/Users/chris/Documents/v.KDBX", rules),
                         {"create": True, "delete": False})       # case-insensitive
        self.assertEqual(seen("/mnt/c/Users/chris/.ssh/id_backup", rules),
                         {"create": False, "delete": True})
        self.assertEqual(seen("C:\\Users\\chris\\Documents\\notes.txt", rules),
                         {"create": False, "delete": False})
        self.assertEqual(seen("/home/chris/.ssh/id_backup", rules),
                         {"create": False, "delete": False})      # Linux side

    def test_unparseable_config_covers_nothing(self):
        self.assertEqual(canary.file_event_rules("<not xml"),
                         {"create": [], "delete": []})

    def test_baseline_constant_matches_sysmon_policy(self):
        from jarvis.collectors.telemetry import sysmon_policy
        self.assertEqual(canary_job.SYSMON_BASELINE, sysmon_policy.BASELINE)

    def test_collector_names_unseen_decoys_by_label_only(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        decoy = Path(tmp.name) / "notes.txt"           # a Linux path: never in Sysmon
        decoy.write_text("d")
        root = Path(tmp.name) / "canary"
        canary.plant("file_decoy", "tax notes", path=str(decoy), root=root)
        out = canary_job.audit(FakeStore(), root=root, conf={}, now=1,
                               network=False, events=[])
        hit = [f for f in out if "outside Sysmon" in f["title"]]
        self.assertEqual(len(hit), 1)
        self.assertIn("tax notes", hit[0]["detail"])
        self.assertNotIn(str(decoy), hit[0]["detail"])  # location never disclosed
        self.assertEqual(hit[0]["severity"], "low")


if __name__ == "__main__":
    unittest.main()

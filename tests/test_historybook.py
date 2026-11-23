"""Isolated forensic invariants: retention, commit/ack, privacy and custody."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from jarvis.cli.commands.history import cmd_history
from jarvis.cli.parser import build_parser
from jarvis.core import event, historybook
from jarvis.core.eventlog import EventLog, LogCapacityError, LogError
from jarvis.platform.native import ingest
from tests.test_native import DIR, batch


def sample(n=1, time="2026-10-01T12:00:00Z"):
    return event.make(host="wsl", sensor="test", channel="test", generation="boot-1",
                      record=n, source="test", source_event=0, time=time,
                      category="sensor", action="state", process={"pid": n, "image": "/bin/test"},
                      raw={"fixture": "original source"})


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.logroot = self.root / "log"
        self.log = EventLog(self.logroot, writer=True)

    def tearDown(self):
        self.log.close()
        self.temp.cleanup()

    def append(self, n=1):
        return self.log.append([sample(n)], {"sensor": "test", "channel": "test", "sequence": n})

    def test_restarts_preserve_all_evidence_and_prune_never_deletes(self):
        for n in range(1, 4):
            self.append(n); self.log.seal(force=True)
        digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in self.log.segdir.iterdir()}
        self.assertEqual(self.log.prune(0), [])
        self.log.close()
        self.log = EventLog(self.logroot, writer=True)
        self.assertEqual([e["seq"] for e in self.log.iter_events()], [1, 2, 3])
        self.assertEqual(digests, {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in self.log.segdir.iterdir()})

    def test_capacity_refusal_does_not_change_bytes_cursor_or_sequence(self):
        self.append()
        old = self.log.active.read_bytes()
        cursor = dict(self.log.cursor("test", "test"))
        self.log.budget = self.log.active_bytes
        with self.assertRaises(LogCapacityError):
            self.append(2)
        self.assertEqual(old, self.log.active.read_bytes())
        self.assertEqual(cursor, self.log.cursor("test", "test"))
        self.assertEqual(self.log.last_seq, 1)

    def test_disk_reserve_refuses_without_reclaiming(self):
        with mock.patch("jarvis.core.eventlog.os.statvfs", return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)):
            with self.assertRaises(LogCapacityError): self.append()
        self.assertFalse(self.log.active.exists())

    def test_backward_wall_clock_cannot_delay_sealing_in_a_live_writer(self):
        self.append()
        with mock.patch("jarvis.core.eventlog.time.time", return_value=0), \
                mock.patch("jarvis.core.eventlog.time.monotonic", return_value=self.log._active_mono_at + 301):
            self.assertTrue(self.log.due())

    def test_native_exhaustion_does_not_ack_and_retry_commits_once(self):
        spool = self.root / "spool"
        channel = spool / DIR
        channel.mkdir(parents=True)
        (channel / f"{1:020d}.json").write_text(json.dumps(batch()))
        self.log.budget = 0
        with self.assertRaises(LogCapacityError):
            ingest.run(log=self.log, spool=spool)
        self.assertIsNone(self.log.cursor("sensor", batch()["channel"]))
        self.assertFalse((spool / "acks").exists())
        self.log.budget = 2 * 1024 ** 3
        result = ingest.run(log=self.log, spool=spool)
        self.assertEqual(result["events"], 1)
        self.assertTrue(list((spool / "acks").glob("*.json")))
        self.assertEqual(ingest.run(log=self.log, spool=spool)["events"], 0)

    def test_reader_index_rejects_mutation(self):
        with EventLog(self.logroot) as reader:
            with self.assertRaises(sqlite3.OperationalError):
                reader.db.execute("DELETE FROM meta")

    def test_query_pages_with_explicit_scan_exhaustion(self):
        self.log.append([sample(n) for n in range(1, 5)], {"sensor": "test", "channel": "test"})
        first = historybook.query(self.log, limit=2)
        self.assertTrue(first["truncated"])
        second = historybook.query(self.log, after=first["next_after"], limit=2)
        self.assertEqual([e["seq"] for e in first["events"] + second["events"]], [1, 2, 3, 4])
        empty = historybook.query(self.log, host="win", scan_limit=1)
        self.assertTrue(empty["truncated"])
        self.assertEqual(empty["events"], [])
        self.assertNotIn("raw", first["events"][0])

    def test_source_time_disagreement_never_reorders_ingest(self):
        self.log.append([sample(1, "2026-10-01T12:00:01Z"), sample(2, "2026-10-01T11:59:59Z")],
                        {"sensor": "test", "channel": "test"})
        r = historybook.query(self.log, since="2026-10-01T11:00:00Z")
        self.assertEqual([e["seq"] for e in r["events"]], [1, 2])
        with self.assertRaises(ValueError): historybook.query(self.log, since="2026-10-01")

    def test_pending_tail_is_not_reviewed_or_exported(self):
        self.append()
        with self.log.active.open("ab") as f: f.write(b'{"seq":2}\n{"torn":')
        with EventLog(self.logroot) as reader:
            self.assertEqual(len(historybook.query(reader)["events"]), 1)
            result = historybook.export_case(reader, self.root / "case")
        self.assertTrue(historybook.verify_case(self.root / "case", result["manifest_sha256"])["ok"])
        self.assertNotIn(b'torn', (self.root / "case/active.jsonl").read_bytes())

    def test_export_survives_source_removal_and_detects_tampering(self):
        self.append(); self.log.seal(force=True); self.append(2)
        case = self.root / "case"
        result = historybook.export_case(self.log, case)
        self.log.active.unlink()
        for p in self.log.segdir.iterdir(): p.unlink()
        self.assertTrue(historybook.verify_case(case, result["manifest_sha256"])["ok"])
        with (case / "active.jsonl").open("ab") as f: f.write(b' ')
        self.assertFalse(historybook.verify_case(case, result["manifest_sha256"])["ok"])

    def test_export_is_exclusive_and_interrupted_copy_cannot_verify(self):
        self.append()
        case = self.root / "case"
        with self.assertRaises(LogError): historybook.export_case(self.log, case, max_bytes=10)
        self.assertTrue(case.exists())
        self.assertFalse(historybook.verify_case(case)["ok"])
        with self.assertRaises(FileExistsError): historybook.export_case(self.log, case)

    def test_partial_segment_selection_still_preserves_original_bytes(self):
        for n in range(1, 4): self.append(n); self.log.seal(force=True)
        case = self.root / "case"
        r = historybook.export_case(self.log, case, after=1, until=2)
        self.assertEqual((case / "segments/000000000002.jseg").read_bytes(),
                         (self.log.segdir / "000000000002.jseg").read_bytes())
        self.assertTrue(historybook.verify_case(case, r["manifest_sha256"])["ok"])
        (case / "segments/000000000002.jseg").unlink()
        self.assertFalse(historybook.verify_case(case)["ok"])

    def test_independent_anchor_detects_consistent_manifest_rewrite(self):
        self.append()
        case = self.root / "case"
        r = historybook.export_case(self.log, case)
        m = json.loads((case / "manifest.json").read_text())
        m["created_at"] = "2030-01-01T00:00:00Z"
        (case / "manifest.json").write_text(json.dumps(m))
        self.assertTrue(historybook.verify_case(case)["ok"])
        self.assertFalse(historybook.verify_case(case, r["manifest_sha256"])["ok"])

    def test_case_traversal_and_symlinks_are_rejected(self):
        self.append()
        case = self.root / "case"
        historybook.export_case(self.log, case)
        m = json.loads((case / "manifest.json").read_text())
        m["files"]["../outside"] = {"sha256": "0" * 64, "bytes": 0}
        (case / "manifest.json").write_text(json.dumps(m))
        self.assertFalse(historybook.verify_case(case)["ok"])

    def test_snapshot_records_both_hosts_without_private_fields(self):
        self.log.close()
        rows = [{"host": h, "pid": n, "ppid": 1, "started": "2026-10-01T12:00:00Z",
                 "name": "test", "exe": "/bin/test", "cmdline": "secret-token", "user": "private", "conns": ["private"]}
                for n, h in enumerate(("wsl", "win"), 1)]
        historybook.record_snapshot(rows, ("wsl", "win"), 1000, root=self.logroot)
        self.log = EventLog(self.logroot, writer=True)
        events = list(self.log.iter_events())
        self.assertEqual(len(events), 3)
        self.assertNotIn("secret-token", json.dumps(events))
        self.assertNotIn("private", json.dumps(events))
        self.assertEqual({e["host"] for e in events}, {"wsl", "win"})
        self.assertTrue(all(e["action"] == "state" for e in events))

    def test_snapshot_lock_retry_exhaustion_preserves_existing_history(self):
        self.append()
        with mock.patch.object(historybook.time, "sleep") as sleep:
            with self.assertRaises(LogError):
                historybook.record_snapshot([], ("wsl",), 1000, self.logroot)
        self.assertEqual(sleep.call_count, historybook.LOCK_ATTEMPTS - 1)
        self.assertEqual(self.log.last_seq, 1)

    def test_snapshot_retry_success_and_process_count_bound(self):
        self.log.close()
        original = historybook.EventLog
        with mock.patch.object(historybook, "EventLog", side_effect=[LogError("busy"), original(self.logroot, writer=True)]), \
                mock.patch.object(historybook.time, "sleep"):
            historybook.record_snapshot([], ("wsl",), 1000, self.logroot)
        self.log = EventLog(self.logroot, writer=True)
        self.assertEqual(self.log.last_seq, 1)
        with self.assertRaises(LogError):
            historybook.record_snapshot([{}] * (historybook.MAX_PROCESSES + 1), ("wsl",), 1000, self.logroot)

    def test_cli_real_parser_and_case_failure_exit(self):
        parser = build_parser()
        args = parser.parse_args(["history", "query", "--log", str(self.logroot), "--limit", "1"])
        self.append()
        with mock.patch("builtins.print") as output:
            self.assertEqual(cmd_history(args, None), 0)
        self.assertEqual(len(json.loads(output.call_args.args[0])["events"]), 1)
        args = parser.parse_args(["history", "verify-case", "--case", str(self.root / "absent")])
        with mock.patch("builtins.print"): self.assertEqual(cmd_history(args, None), 2)

    def test_scheduled_scan_records_history_and_failure_keeps_scan_findings(self):
        from jarvis.core.store import Store
        from jarvis.service import jobs
        db = self.root / "service.db"
        Store(str(db)).close()
        res = {"ts": 1000, "processes": [{"host": "wsl", "pid": 22, "exe": "/bin/test"}],
               "findings": [{"host": "wsl", "pid": 22, "name": "test", "severity": "medium",
                             "unknown": False, "remotes": [], "cmdline": "", "exe": "/bin/test"}],
               "new_public_peers": []}
        with mock.patch.object(jobs.monitor, "scan", return_value=res), \
                mock.patch.object(jobs.reconcile, "processes", return_value=[]), \
                mock.patch.object(jobs.reconcile, "classify_snapshot", return_value=[]), \
                mock.patch.object(jobs.reconcile, "coverage_evidence", return_value={}), \
                mock.patch.object(jobs.sysmon_pressure, "audit", return_value={}):
            out = jobs._scan(("wsl",), str(db))
            self.assertEqual(out[0]["severity"], "medium")
            with EventLog(self.root / "eventlog") as log:
                self.assertEqual(log.last_seq, 2)
            with mock.patch.object(jobs.historybook, "record_snapshot", side_effect=LogCapacityError("full")):
                failed = jobs._scan(("wsl",), str(db))
            self.assertTrue(any(f["title"] == "Process history recording blocked" for f in failed))
            self.assertTrue(any(f["severity"] == "medium" and f["where"] == "/bin/test" for f in failed))

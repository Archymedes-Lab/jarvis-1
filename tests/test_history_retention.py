"""Event history retention (owner policy 2026-11-04): 30 days whole, then suspicious only.

Invariants under test:
  * nothing newer than KEEP_DAYS and never the newest segment is touched;
  * held events and suspicious events survive; only events no rule marks go;
  * the chain header and hash chain are unchanged and verify() still passes;
  * every reduction is recorded (compacted.jsonl / pruned.jsonl) and a tampered
    or half-applied compaction is reported, never silent;
  * bounded: a segment count and a time budget per run;
  * a hold is released only by an exact, recorded owner release.
"""
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from jarvis.collectors.telemetry import history_retention as retention
from jarvis.core import event
from jarvis.core.eventlog import DEFAULT_BUDGET, EventLog, LogError

OLD = "2026-08-01T12:00:00Z"
NOW = time.mktime(time.strptime("2026-11-04 12:00:00", "%Y-%m-%d %H:%M:%S"))


def ev(n, *, time=OLD, source="sysmon", category="network", action="connect", process=None, target=None):
    return event.make(host="win", sensor="test", channel="test", generation="g", record=n, source=source,
                      source_event=0, time=time, category=category, action=action,
                      process=process or {"pid": n, "image": "C:\\Program Files\\App\\app.exe"},
                      target=target, raw={})


def normal(n, time=OLD):
    return ev(n, time=time, target={"type": "endpoint", "ip": "151.101.1.1", "port": 443})


class FakeStore:
    """The two things retention reads from the daemon store."""

    def __init__(self, indicators=(), findings=()):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE indicators (kind TEXT, norm TEXT, status TEXT)")
        self.db.executemany("INSERT INTO indicators VALUES (?,?,'active')", indicators)
        self._findings = list(findings)
        self.meta = {}

    def get_snapshots(self):
        return {"sysmon": {"findings": self._findings}}

    def set_meta(self, k, v):
        self.meta[k] = v

    def commit(self):
        pass


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "log"
        self.log = EventLog(self.root, writer=True)
        self.n = 0

    def tearDown(self):
        self.log.close()
        self.temp.cleanup()

    def segment(self, events):
        self.log.append(events, {"sensor": "test", "channel": "test", "sequence": self.n})
        self.n += len(events)
        return self.log.seal(force=True)

    def seqs(self):
        return [e["seq"] for e in self.log.iter_events()]


class Compaction(Base):
    def test_only_kept_and_held_events_survive_and_the_chain_still_verifies(self):
        h = self.segment([normal(1), normal(2), normal(3), normal(4)])
        self.segment([normal(5)])                                   # newest stays
        self.log.hold(2, 2, "incident 7")
        before = json.loads(json.dumps(self.log.chain))
        r = self.log.compact(h["segment"], lambda e: e["seq"] == 4, "test")
        self.assertEqual((r["kept"], r["dropped"], r["action"]), (2, 2, "compacted"))
        self.assertEqual(self.seqs(), [2, 4, 5])
        self.assertEqual(self.log.chain, before)                    # headers untouched
        v = self.log.verify()
        self.assertTrue(v["ok"], v["problems"])
        self.assertEqual(v["compacted"], 1)
        rec = self.log._compacted()[h["segment"]]
        self.assertEqual(rec["original_payload_sha256"], h["payload_sha256"])
        self.assertEqual((rec["kept"], rec["dropped"]), (2, 2))

    def test_a_segment_with_nothing_suspicious_is_removed_and_recorded(self):
        h = self.segment([normal(1), normal(2)])
        self.segment([normal(3)])
        r = self.log.compact(h["segment"], lambda e: False, "test")
        self.assertEqual(r["action"], "removed")
        self.assertIn(h["segment"], self.log._pruned())
        self.assertEqual(self.seqs(), [3])
        self.assertTrue(self.log.verify()["ok"])

    def test_the_newest_segment_and_a_second_reduction_are_refused(self):
        h1 = self.segment([normal(1), normal(2)])
        h2 = self.segment([normal(3)])
        with self.assertRaises(LogError):
            self.log.compact(h2["segment"], lambda e: False, "test")
        self.log.compact(h1["segment"], lambda e: e["seq"] == 1, "test")
        with self.assertRaises(LogError):
            self.log.compact(h1["segment"], lambda e: False, "test")

    def test_a_tampered_compacted_segment_is_reported(self):
        import gzip
        h = self.segment([normal(1), normal(2)])
        self.segment([normal(3)])
        self.log.compact(h["segment"], lambda e: e["seq"] == 1, "test")
        path = self.log._segment_path(h["segment"])
        with gzip.open(path, "rb") as fh:
            header = fh.readline()
        with open(path, "wb") as raw:
            for part in (header, b'{"seq": 1, "forged": true}\n'):
                with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                    gz.write(part)
        v = self.log.verify()
        self.assertFalse(v["ok"])
        self.assertTrue(any("compacted payload altered" in p for p in v["problems"]), v["problems"])

    def test_a_record_without_the_rewritten_file_is_reported_not_silent(self):
        # A crash after the record and before the replace.
        h = self.segment([normal(1), normal(2)])
        self.segment([normal(3)])
        with open(self.log.compacted_path, "a") as fh:
            fh.write(json.dumps({"segment": h["segment"], "at": 1, "reason": "x", "kept": 1, "dropped": 1,
                                 "original_payload_sha256": h["payload_sha256"],
                                 "payload_sha256": "0" * 64, "payload_bytes": 1}) + "\n")
        v = self.log.verify()
        self.assertFalse(v["ok"])

    def test_a_segment_whose_header_differs_is_left_alone(self):
        h = self.segment([normal(1), normal(2)])
        self.segment([normal(3)])
        self.log.chain[0] = dict(self.log.chain[0], count=99)
        with self.assertRaises(LogError):
            self.log.compact(h["segment"], lambda e: False, "test")
        self.assertTrue(self.log._segment_path(h["segment"]).exists())


class Holds(Base):
    def test_release_needs_an_exact_match_and_both_stay_on_record(self):
        self.log.hold(1, 100, "owner preservation")
        rec = self.log.hold_records()[0]
        with self.assertRaises(LogError):
            self.log.release_hold(1, 99, rec["at"], "owner")
        self.log.release_hold(1, 100, rec["at"], "owner")
        self.assertEqual(self.log.holds(), [])
        lines = [json.loads(x) for x in Path(self.log.holds_path).read_text().splitlines()]
        self.assertEqual(len(lines), 2)
        self.log.hold(1, 100, "again")                               # a new hold still counts
        self.assertEqual(len(self.log.holds()), 1)


class Policy(unittest.TestCase):
    def test_suspicious_events_are_named(self):
        reg = ev(1, category="registry", action="value_set",
                 target={"type": "registry", "name": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"})
        self.assertEqual(retention.keep_reason(reg), "autostart registry change")
        staged = ev(2, category="process", action="start",
                    process={"pid": 2, "image": "C:\\Users\\a\\AppData\\Local\\Temp\\x.exe"})
        self.assertEqual(retention.keep_reason(staged), "program run from a staging folder")
        self.assertIn("tampering", retention.keep_reason(ev(3, action="remote_thread")))
        self.assertEqual(retention.keep_reason(ev(4, source="jarvis-outage-record", category="sensor",
                                                  action="state")), "ARGUS outage record")
        self.assertEqual(retention.keep_reason(dict(normal(5), seq=5), cited={5}), "cited by a finding")
        bad = normal(6)
        self.assertEqual(retention.keep_reason(bad, known={("ipv4", "151.101.1.1")}), "known indicator (ipv4)")

    def test_routine_events_are_not_kept(self):
        self.assertIsNone(retention.keep_reason(normal(1)))
        self.assertIsNone(retention.keep_reason(ev(2, source="defender", category="protection", action="health")))
        other_reg = ev(3, category="registry", action="value_set",
                       target={"type": "registry", "name": "HKCU\\Software\\App\\Settings\\Theme"})
        self.assertIsNone(retention.keep_reason(other_reg))

    def test_a_rule_check_that_fails_keeps_the_event(self):
        start = ev(1, category="process", action="start", process={"pid": 1, "image": "C:\\Windows\\x.exe"})

        def broken(*a):
            raise RuntimeError("bad pattern")
        self.assertIn("kept", retention.keep_reason(start, match=broken))
        self.assertEqual(retention.keep_reason(start, match=lambda *a: [("rule", "x")]), "detection rule")


class LineageAndSummary(Base):
    def test_a_kept_events_process_start_and_its_parent_start_stay(self):
        parent = ev(1, category="process", action="start",
                    process={"pid": 1, "guid": "P", "image": "C:\\Windows\\explorer.exe"})
        child = ev(2, category="process", action="start",
                   process={"pid": 2, "guid": "C", "image": "C:\\Windows\\cmd.exe"}, )
        child = dict(child, parent={"guid": "P", "pid": 1, "image": "C:\\Windows\\explorer.exe"})
        bad = ev(3, process={"pid": 2, "guid": "C", "image": "C:\\Windows\\cmd.exe"},
                 target={"type": "endpoint", "ip": "6.6.6.6"})
        noise = normal(4)
        self.segment([parent, child, bad, noise])
        self.segment([normal(5)])
        s = retention.run(FakeStore(indicators=[("ipv4", "6.6.6.6")]), self.log, now=NOW)
        self.assertEqual(self.seqs(), [2, 3, 5])                 # the child start and the bad connection
        self.assertEqual(s["reasons"].get("process lineage of a kept event"), 1)

    def test_dropped_events_leave_a_bounded_summary(self):
        h = self.segment([normal(i) for i in range(1, 40)])
        self.segment([normal(99)])
        retention.run(FakeStore(), self.log, now=NOW)
        rec = [json.loads(x) for x in Path(self.log.pruned_path).read_text().splitlines()][-1]
        summ = rec["dropped_summary"]
        self.assertEqual(rec["segment"], h["segment"])
        self.assertEqual(summ["events"], 39)
        self.assertEqual(summ["destinations"], {"151.101.1.1": 39})
        self.assertLessEqual(len(summ["programs"]), retention.SUMMARY_TOP)


class Run(Base):
    def test_window_bound_indicators_and_cited_findings(self):
        old = self.segment([normal(1), ev(2, target={"type": "endpoint", "ip": "6.6.6.6"}), normal(3)])
        recent = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - 86400))
        fresh = self.segment([normal(4, time=recent), normal(5, time=recent)])
        self.segment([normal(6, time=recent)])
        store = FakeStore(indicators=[("ipv4", "6.6.6.6")], findings=[{"seq": 3, "title": "x"}])
        s = retention.run(store, self.log, now=NOW)
        self.assertEqual((s["candidates"], s["segments"], s["kept"], s["dropped"]), (1, 1, 2, 1))
        self.assertEqual(self.seqs(), [2, 3, 4, 5, 6])
        self.assertNotIn(fresh["segment"], self.log._compacted())
        self.assertIn(old["segment"], self.log._compacted())
        self.assertTrue(self.log.verify()["ok"])

    def test_bounded_by_segment_count_and_time(self):
        for i in range(5):
            self.segment([normal(10 * i + 1), normal(10 * i + 2)])
        self.segment([normal(99)])
        s = retention.run(FakeStore(), self.log, now=NOW, max_segments=2)
        self.assertEqual(s["segments"], 2)
        ticks = iter([0, 0, 1000, 1000, 1000])
        s = retention.run(FakeStore(), self.log, now=NOW, budget_s=10, clock=lambda: next(ticks))
        self.assertEqual(s["segments"], 1)

    def test_a_fully_held_segment_is_not_even_read(self):
        self.segment([normal(1), normal(2)])
        h2 = self.segment([normal(3), normal(4)])
        self.segment([normal(5)])
        self.log.hold(1, 2, "owner preservation")
        names = [c["segment"] for c in retention.candidates(self.log, NOW)]
        self.assertEqual(names, [h2["segment"]])           # the held one is skipped, the next is not

    def test_a_held_range_survives_a_run(self):
        self.segment([normal(1), normal(2), normal(3)])
        self.segment([normal(4)])
        self.log.hold(1, 3, "owner preservation")
        retention.run(FakeStore(), self.log, now=NOW)
        self.assertEqual(self.seqs(), [1, 2, 3, 4])

    def test_budget_default_is_six_gib(self):
        self.assertEqual(DEFAULT_BUDGET, 6 * 1024 ** 3)


if __name__ == "__main__":
    unittest.main()


class ReleaseCommand(Base):
    def run_cli(self, *argv, tty=True, answer="release"):
        from unittest import mock

        from jarvis.cli.parser import build_parser
        args = build_parser().parse_args(["timeline", *argv, "--log", str(self.root)])
        self.log.close()
        with mock.patch("sys.stdin.isatty", return_value=tty), mock.patch("builtins.input", return_value=answer):
            code = args.fn(args, None)
        self.log = EventLog(self.root, writer=True)
        return code

    def test_release_needs_a_terminal_and_the_typed_word(self):
        self.log.hold(1, 50, "owner preservation")
        at = self.log.hold_records()[0]["at"]
        self.assertEqual(self.run_cli("release-hold", "--first", "1", "--last", "50", "--at", repr(at), tty=False), 2)
        self.assertEqual(self.run_cli("release-hold", "--first", "1", "--last", "50", "--at", repr(at), answer="yes"), 1)
        self.assertEqual(len(self.log.holds()), 1)
        self.assertEqual(self.run_cli("release-hold", "--first", "1", "--last", "50", "--at", repr(at)), 0)
        self.assertEqual(self.log.holds(), [])

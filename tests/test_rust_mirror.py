import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from jarvis.collectors.telemetry import mirror
from jarvis.core import event, runtime
from jarvis.core.eventlog import EventLog
from jarvis.core.store import Store
from jarvis.service import protection

needs_binary = unittest.skipUnless(
    runtime.available(), "optional Rust binary is not built")


def ev(record):
    return event.make(
        host="WINBOX", sensor="sensor", device="device", boot="boot-1",
        channel="Microsoft-Windows-Sysmon/Operational", generation="gen",
        record=record, source="sysmon", source_event=1,
        time="2026-09-22T10:00:00Z", received="2026-09-22T10:00:01Z",
        category="process", action="start",
        process={"pid": record, "guid": f"{{g{record}}}", "image": r"C:\x.exe"})


class FakeLog:
    """An authoritative log whose retained history starts at `first`."""

    def __init__(self, first, last):
        self.events = [dict(ev(n), seq=n) for n in range(first, last + 1)]

    def iter_events(self, after=0):
        return (e for e in self.events if e["seq"] > after)

    def stats(self):
        return {"last_seq": self.events[-1]["seq"] if self.events else 0}


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.logdir = Path(self.temp.name) / "eventlog"
        self.store = Path(self.temp.name) / "rust"
        self.log = EventLog(self.logdir, writer=True)
        self.addCleanup(self.log.close)

    def commit(self, first, last):
        self.log.append([ev(n) for n in range(first, last + 1)],
                        {"sensor": "sensor", "channel": "c", "status": "complete"})

    def test_absent_binary_is_explicit_and_not_scored(self):
        with mock.patch.object(runtime, "binary", return_value=None):
            state = runtime.mirror(self.log, root=self.store)
        self.assertFalse(state["ok"])
        self.assertEqual(state["error"], "binary_absent")
        (finding,) = mirror.findings(state)
        self.assertEqual((finding["category"], finding["severity"]),
                         ("visibility", "low"))

    @needs_binary
    def test_mirror_is_contiguous_across_bounded_batches(self):
        self.commit(1, 5)
        cursors = []
        for _ in range(3):
            state = runtime.mirror(self.log, root=self.store, max_events=2)
            self.assertTrue(state["ok"], state)
            cursors.append(state["cursor"])
        self.assertEqual(cursors, [2, 4, 5])
        self.assertEqual(state["behind"], 0)
        verified = runtime.verify_store(root=self.store)
        self.assertEqual((verified["last_seq"], verified["last_source_seq"]), (5, 5))

    @needs_binary
    def test_idle_run_still_verifies_the_store(self):
        self.commit(1, 2)
        runtime.mirror(self.log, root=self.store)
        with mock.patch.object(runtime, "verify_store",
                               wraps=runtime.verify_store) as verify:
            state = runtime.mirror(self.log, root=self.store)
        self.assertTrue(state["ok"])
        self.assertEqual(state["mirrored"], 0)
        verify.assert_called_once()

    @needs_binary
    def test_replayed_events_are_rejected_without_changing_the_store(self):
        self.commit(1, 3)
        runtime.mirror(self.log, root=self.store)
        before = runtime.verify_store(root=self.store)
        replay = [dict(e, source_seq=e["seq"]) for e in self.log.iter_events()]
        result = runtime.persist(replay, root=self.store)
        self.assertEqual(result["error"], "rejected")
        self.assertIn("does not advance", result["detail"])
        self.assertEqual(runtime.verify_store(root=self.store)["head"], before["head"])

    @needs_binary
    def test_one_invalid_event_persists_nothing(self):
        bad = dict(ev(2), source_seq=2, category="nonsense")
        result = runtime.persist([dict(ev(1), source_seq=1), bad], root=self.store)
        self.assertEqual(result["error"], "rejected")
        self.assertEqual(result["rejected_index"], 1)
        self.assertEqual(runtime.verify_store(root=self.store)["segments"], 0)
        peek, _ = runtime._store_call("cursor", str(self.store))
        self.assertIsNone(peek["last_source_seq"])

    @needs_binary
    def test_retention_gap_is_reported_not_bridged(self):
        runtime.mirror(FakeLog(1, 2), root=self.store)
        state = runtime.mirror(FakeLog(6, 8), root=self.store)
        self.assertTrue(state["ok"], state)
        self.assertEqual((state["gap_events"], state["cursor"]), (3, 8))
        (finding,) = mirror.findings(state)
        self.assertEqual(finding["severity"], "medium")
        self.assertIn("3 events", finding["detail"])

    @needs_binary
    def test_tampered_store_is_a_high_integrity_finding(self):
        self.commit(1, 3)
        runtime.mirror(self.log, root=self.store)
        segment = next((self.store / "segments").iterdir())
        data = bytearray(segment.read_bytes())
        data[-1] ^= 0xFF
        segment.write_bytes(bytes(data))
        state = runtime.mirror(self.log, root=self.store)
        self.assertFalse(state["ok"])
        (finding,) = mirror.findings(state)
        self.assertEqual((finding["category"], finding["severity"]),
                         ("tampering", "high"))

    @needs_binary
    def test_budget_prunes_old_segments_and_mirroring_continues(self):
        for n in range(1, 5):
            self.commit(n, n)
            runtime.mirror(self.log, root=self.store)
        state = runtime.mirror(self.log, root=self.store, budget=1)
        self.assertTrue(state["ok"], state)
        self.assertEqual(state["pruned_segments"], 3)
        self.commit(5, 5)
        state = runtime.mirror(self.log, root=self.store, budget=1)
        self.assertEqual((state["ok"], state["cursor"]), (True, 5))
        verified = runtime.verify_store(root=self.store)
        self.assertEqual((verified["segments"], verified["last_source_seq"]), (5, 5))

    @needs_binary
    def test_a_deleted_store_is_not_silently_rebuilt(self):
        db_path = os.path.join(self.temp.name, "state.db")
        store = Store(db_path)
        self.addCleanup(store.close)
        self.commit(1, 3)
        self.assertEqual(mirror.audit(store, root=self.logdir,
                                      mirror_root=self.store), [])
        self.assertEqual(mirror.summary(store)["cursor"], 3)
        shutil.rmtree(self.store)
        for _ in range(2):      # stays paused, and the reference survives
            (finding,) = mirror.audit(store, root=self.logdir,
                                      mirror_root=self.store)
            self.assertEqual((finding["category"], finding["severity"]),
                             ("tampering", "high"))
            self.assertEqual(mirror.summary(store)["expected_cursor"], 3)
        self.assertFalse((self.store / "chain.jsonl").exists())

    def test_job_records_summary_for_health(self):
        db_path = os.path.join(self.temp.name, "state.db")
        store = Store(db_path)
        try:
            with mock.patch.object(runtime, "binary", return_value=None):
                mirror.audit(store, root=self.logdir, mirror_root=self.store)
            self.assertEqual(mirror.summary(store)["error"], "binary_absent")
        finally:
            store.close()


class HealthTests(unittest.TestCase):
    def test_health_reads_the_recorded_mirror_without_verifying(self):
        scheduler = SimpleNamespace(
            hosts=("wsl",), current=None, fast_current=None,
            heartbeat=time.time(), fast_heartbeat=time.time(),
            is_alive=lambda: True, fast_alive=lambda: True,
            reliability_status=lambda: {"summary": {}})
        with tempfile.TemporaryDirectory() as tmp:
            db_path = tmp + "/t.db"
            store = Store(db_path)
            try:
                store.save_snapshot("scan", [], 0.1, "")
                store.set_meta(mirror.META, json.dumps(
                    {"ok": True, "runtime": "rust", "cursor": 7,
                     "at": int(time.time()) - 30}))
                store.commit()
            finally:
                store.close()
            with mock.patch.object(runtime, "verify_store",
                                   side_effect=AssertionError("O(store) in HTTP")):
                state = protection.health(db_path, scheduler)
        storage = state["runtime"]["storage"]
        self.assertEqual((storage["ok"], storage["cursor"]), (True, 7))
        self.assertGreaterEqual(storage["age_s"], 30)


if __name__ == "__main__":
    unittest.main()

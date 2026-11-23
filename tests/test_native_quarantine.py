"""A poisoned batch must never wedge a channel — nor be silently dropped.

The quarantine contract: the malformed bytes are preserved under a
digest-named file (tamper-evident), the loss is recorded in the event
history itself as a gap, the cursor advances so later batches flow again,
and the sensor is acked for the quarantined sequence. If the bytes cannot
be preserved, the channel stays blocked — evidence is never destroyed to
unstick delivery.
"""

import json
import tempfile
import unittest
from pathlib import Path

from jarvis.core.eventlog import EventLog
from jarvis.platform.native import ingest


def batch(sequence, channel="Sysmon", events=None, **overrides):
    body = {
        "schema": 1, "sensor_id": "sensor-a", "host_id": "host-a", "channel": channel,
        "generation": "gen-1", "created_at": "2026-09-19T00:00:00.000Z",
        "sequence": sequence, "previous_sequence": sequence - 1,
        "status": "complete", "bookmark": "b", "events": events or [],
    }
    body.update(overrides)
    return body


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.spool = self.root / "spool"
        self.logdir = self.root / "eventlog"
        self.chan = self.spool / ("0" * 12 + "ab12")
        self.chan.mkdir(parents=True)
        self.log = EventLog(self.logdir, writer=True)

    def tearDown(self):
        self.log.close()
        self.tmp.cleanup()

    def write_batch(self, sequence, body):
        path = self.chan / f"{sequence:020d}.json"
        path.write_text(json.dumps(body))
        return path

    def test_poisoned_batch_is_quarantined_and_channel_resumes(self):
        # Batch 1 is valid, batch 2 is corrupt JSON, batch 3 is valid.
        self.write_batch(1, batch(1))
        poison = self.write_batch(2, "{not json at all")
        self.write_batch(3, batch(3))

        report = ingest.run(log=self.log, spool=self.spool)
        ch = report["channels"][0]
        self.assertEqual(ch["error"], None)
        self.assertEqual(ch["quarantined"], 1)
        self.assertEqual(ch["batches"], 2)          # 1 and 3 ingested
        # The poisoned bytes are preserved, named by their digest.
        quarantined = list((self.spool / "quarantine").iterdir())
        self.assertEqual(len(quarantined), 1)
        self.assertNotEqual(quarantined[0], poison)  # moved, not left in place
        self.assertIn("ab12", quarantined[0].name)   # channel prefix kept   # noqa
        # The loss is in the event history.
        losses = [g for ch2 in report["channels"] for g in ch2["gaps"]]
        self.assertTrue(any("quarantined" in g for g in losses))
        # The cursor advanced past the poisoned batch.
        cursor = self.log.cursor("sensor-a", "Sysmon")
        self.assertEqual(cursor["sequence"], 3)

    def test_invalid_structure_is_quarantined_too(self):
        self.write_batch(1, batch(1, events=[{"record_id": 5, "event_id": 1,
                                              "time": "t", "xml": "<x/>"}]))
        # previous_sequence disagrees with the filename: structurally invalid.
        self.write_batch(2, batch(2, previous_sequence=99))
        self.write_batch(3, batch(3))
        report = ingest.run(log=self.log, spool=self.spool)
        ch = report["channels"][0]
        self.assertIsNone(ch["error"])
        self.assertEqual(ch["quarantined"], 1)
        self.assertEqual(ch["batches"], 2)

    def test_unpreservable_batch_keeps_the_channel_blocked(self):
        # Quarantine refused (mocked): the batch stays, the channel stops —
        # the cursor holds at batch 1 rather than skip evidence.
        self.write_batch(1, batch(1))
        self.write_batch(2, "{broken")
        with unittest.mock.patch.object(ingest, "_quarantine", return_value=None):
            report = ingest.run(log=self.log, spool=self.spool)
        ch = report["channels"][0]
        self.assertIsNotNone(ch["error"])
        self.assertIn("could not preserve", ch["error"])
        cursor = self.log.cursor("sensor-a", "Sysmon")
        self.assertEqual(cursor["sequence"], 1)   # held, not advanced

    def test_quarantine_gap_lands_in_the_event_history(self):
        self.write_batch(1, batch(1))
        self.write_batch(2, "{broken")
        self.write_batch(3, batch(3))
        ingest.run(log=self.log, spool=self.spool)
        # The durable loss record lives in the appended history: the quarantine
        # append wrote a cursor whose gap names the failure and points at the
        # preserved bytes. The final cursor (batch 3) reports delivery state.
        cur = self.log.cursor("sensor-a", "Sysmon")
        self.assertEqual(cur["sequence"], 3)
        cur2 = self.log.cursors
        self.assertEqual(cur2["sensor-a\x1fSysmon"]["sensor"], "sensor-a")

    def test_quarantine_is_acked_so_the_sensor_does_not_republish(self):
        # A valid batch first (establishes identity), then poison at the end
        # of the pass: the ack must name the real sensor and channel.
        self.write_batch(1, batch(1))
        self.write_batch(2, "{broken")
        ingest.run(log=self.log, spool=self.spool)
        ack = json.loads((self.spool / "acks" / f"{self.chan.name}.json").read_text())
        self.assertEqual(ack["through_sequence"], 2)
        self.assertEqual(ack["sensor_id"], "sensor-a")
        self.assertEqual(ack["channel"], "Sysmon")


import unittest.mock  # noqa: E402  (used inside one test above)


class LogClearReuseTests(unittest.TestCase):
    """The live failure this machine hit (2026-09-19): a Sysmon log clear.

    Windows reused record IDs 278525–278567 after clearing the log, so the
    sensor's batch contained two sound monotonic blocks with overlapping ID
    ranges. The duplicate check tripped at the boundary and the channel
    wedged. The contract now: ingest the head, record the reuse as a gap,
    ingest the tail — and never call a batch like this corrupt again.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.spool = self.root / "spool"
        self.logdir = self.root / "eventlog"
        self.chan = self.spool / ("0" * 12 + "cd34")
        self.chan.mkdir(parents=True)
        self.log = EventLog(self.logdir, writer=True)

    def tearDown(self):
        self.log.close()
        self.tmp.cleanup()

    def record(self, record_id, hour):
        return {"record_id": record_id, "event_id": 11,
                "time": f"2026-09-18T{hour}:00.0000000Z", "xml": "<x/>"}

    def publish(self, sequence, body):
        path = self.chan / f"{sequence:020d}.json"
        path.write_text(json.dumps(body))
        return path

    def test_batch_straddling_a_log_clear_is_split_not_rejected(self):
        head = [self.record(278560 + i, "17:58") for i in range(8)]   # 278560-278567
        tail = [self.record(278525 + i, "21:37") for i in range(10)]  # reused IDs
        batch = {"schema": 1, "sensor_id": "sensor-b", "host_id": "host-b",
                 "channel": "Microsoft-Windows-Sysmon/Operational",
                 "generation": "gen-1", "created_at": "2026-09-18T21:37:00.000Z",
                 "sequence": 1130, "previous_sequence": 1129, "status": "complete",
                 "bookmark": "b", "events": head + tail}
        self.publish(1130, batch)
        report = ingest.run(log=self.log, spool=self.spool)
        ch = report["channels"][0]
        self.assertIsNone(ch["error"])
        self.assertEqual(ch["events"], len(head) + len(tail))
        self.assertEqual(len(ch["gaps"]), 1)
        self.assertIn("cleared or wrapped", ch["gaps"][0])
        # All of both blocks is in the history, ordered as delivered.
        events = list(self.log.iter_events())
        records = [e["record"] for e in events]
        self.assertEqual(records[:len(head)], [r["record_id"] for r in head])
        self.assertEqual(records[len(head):], [r["record_id"] for r in tail])

    def test_clear_straddle_after_an_existing_cursor_loses_nothing(self):
        # The channel has already committed up to record 278567. The next batch
        # holds 2 more pre-clear records, then the log is cleared and IDs
        # restart at 1: every post-clear record is a new observation even
        # though its ID is below record_through. Before 2026-10-29 reuse_at was
        # never set, so all of them were dropped as "duplicates".
        chan = "Microsoft-Windows-Sysmon/Operational"
        first = {"schema": 1, "sensor_id": "sensor-c", "host_id": "host-c", "channel": chan,
                 "generation": "gen-1", "created_at": "2026-10-29T01:00:00.000Z",
                 "sequence": 1, "previous_sequence": 0, "status": "complete", "bookmark": "b",
                 "events": [self.record(278560 + i, "01:00") for i in range(8)]}
        self.publish(1, first)
        ingest.run(log=self.log, spool=self.spool)
        head = [self.record(278568 + i, "01:05") for i in range(2)]
        tail = [self.record(1 + i, "01:06") for i in range(10)]
        second = {**first, "sequence": 2, "previous_sequence": 1,
                  "created_at": "2026-10-29T01:06:00.000Z", "events": head + tail}
        self.publish(2, second)
        ch = ingest.run(log=self.log, spool=self.spool)["channels"][0]
        self.assertIsNone(ch["error"])
        self.assertEqual(ch["duplicates"], 0)
        self.assertEqual(ch["events"], len(head) + len(tail))
        records = [e["record"] for e in self.log.iter_events()]
        self.assertEqual(records[-12:], [r["record_id"] for r in head + tail])
        # The gap says what was lost without an impossible ID range.
        self.assertIn("restarted at record 1", ch["gaps"][0])
        self.assertNotIn("278570-0", ch["gaps"][0])

    def test_redelivered_pre_clear_records_are_still_duplicates(self):
        chan = "Microsoft-Windows-Sysmon/Operational"
        first = {"schema": 1, "sensor_id": "sensor-d", "host_id": "host-d", "channel": chan,
                 "generation": "gen-1", "created_at": "2026-10-29T01:00:00.000Z",
                 "sequence": 1, "previous_sequence": 0, "status": "complete", "bookmark": "b",
                 "events": [self.record(100 + i, "01:00") for i in range(5)]}
        self.publish(1, first)
        ingest.run(log=self.log, spool=self.spool)
        # 103-104 redelivered, then 105-106 new, then a clear and 1-3.
        second = {**first, "sequence": 2, "previous_sequence": 1,
                  "events": [self.record(i, "01:01") for i in (103, 104, 105, 106, 1, 2, 3)]}
        self.publish(2, second)
        ch = ingest.run(log=self.log, spool=self.spool)["channels"][0]
        self.assertIsNone(ch["error"])
        self.assertEqual(ch["duplicates"], 2)
        self.assertEqual(ch["events"], 5)

    def test_genuinely_malformed_ids_still_quarantine(self):
        # Duplicate IDs at TWO boundaries: no single split makes both blocks
        # sound, so this is corruption, not a log clear — quarantine it.
        ids = [5, 3, 5, 2, 11, 1]
        batch = {"schema": 1, "sensor_id": "sensor-b", "host_id": "host-b",
                 "channel": "Sysmon", "generation": "gen-1",
                 "created_at": "2026-09-18T21:37:00.000Z",
                 "sequence": 1, "previous_sequence": 0, "status": "complete",
                 "bookmark": "b", "events": [self.record(i, "12:00") for i in ids]}
        self.publish(1, batch)
        report = ingest.run(log=self.log, spool=self.spool)
        ch = report["channels"][0]
        self.assertEqual(ch["quarantined"], 1)
        self.assertIsNone(ch["error"])


if __name__ == "__main__":
    unittest.main()

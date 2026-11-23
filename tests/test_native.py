import gzip
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.telemetry import native as native_job
from jarvis.collectors.telemetry import sysmon
from jarvis.core import collection
from jarvis.core import event as event_mod
from jarvis.core.eventlog import EventLog, LogError
from jarvis.core.store import Store
from jarvis.platform.native import ingest, normalize
from jarvis.platform.native.store import BatchError, validate

# Never ask the live Windows host for Sysmon's service state from a unit test;
# an empty answer judges nothing (sysmon._service_findings).
_status_patch = None


def setUpModule():
    global _status_patch
    from unittest import mock as _mock

    from jarvis.collectors.telemetry import sysmon as _sysmon
    _status_patch = _mock.patch.object(_sysmon, "status", return_value={})
    _status_patch.start()


def tearDownModule():
    _status_patch.stop()

SYSMON = normalize.SYSMON
DIR = "461b8df16acfb5cc"


def sysmon_xml(eid, **data):
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name='Microsoft-Windows-Sysmon'/>"
            f"<EventID>{eid}</EventID></System><EventData>{fields}</EventData></Event>")


def record(rid, eid=1, xml=None):
    return {"record_id": rid, "event_id": eid, "time": "2026-09-18T12:00:00Z",
            "mono_ms": 1000 + rid,
            "xml": xml or sysmon_xml(eid, UtcTime="2026-09-18 12:00:00.123",
                                     ProcessGuid="{g-%d}" % rid, ProcessId=str(rid),
                                     Image=r"C:\x\a.exe")}


def batch(sequence=1, events=None, generation="gen-1", gap=None, channel=SYSMON):
    return {"schema": 2, "sensor_id": "sensor", "device_id": "device", "boot_id": "89",
            "host_id": "HOST", "channel": channel, "generation": generation,
            "sequence": sequence, "previous_sequence": sequence - 1,
            "created_at": "2026-09-18T12:00:00Z", "bookmark": "record:1",
            "status": "complete", "gap": gap,
            "events": events if events is not None else [record(sequence)]}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.spool = self.root / "spool"
        (self.spool / DIR).mkdir(parents=True)
        self.logdir = self.root / "log"
        self.log = EventLog(self.logdir, writer=True)

    def tearDown(self):
        self.log.close()
        self.temp.cleanup()

    def publish(self, value, name=None):
        seq = value["sequence"] if isinstance(value, dict) else name
        path = self.spool / DIR / f"{seq:020d}.json"
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path

    def run_ingest(self):
        return ingest.run(log=self.log, spool=self.spool)

    def reopen(self):
        self.log.close()
        self.log = EventLog(self.logdir, writer=True)

    def events(self):
        return list(EventLog(self.logdir).iter_events())


class BatchValidationTests(unittest.TestCase):
    def test_optional_sensor_read_time_is_validated_and_preserved(self):
        newer = record(1)
        newer["read_time"] = "2026-09-18T12:00:01Z"
        value = batch(events=[newer])
        validate(value)
        normalized = normalize.normalize(newer, value)
        self.assertEqual(normalized["received"], newer["read_time"])
        self.assertEqual(normalized["attrs"]["_received_basis"], "sensor_read")
        for bad in ("invalid", "2026-09-18T12:00:01"):
            newer["read_time"] = bad
            with self.assertRaises(BatchError):
                validate(value)

    def test_legacy_event_time_fallback_is_explicit(self):
        value = batch()
        normalized = normalize.normalize(value["events"][0], value)
        self.assertEqual(normalized["received"], value["events"][0]["time"])
        self.assertEqual(normalized["attrs"]["_received_basis"],
                         "event_time_fallback")

    def test_duplicate_record_inside_batch_is_rejected(self):
        with self.assertRaises(BatchError):
            validate(batch(events=[record(1), record(1)]))

    def test_schema_one_batches_still_validate(self):
        old = batch()
        old["schema"] = 1
        for key in ("device_id", "boot_id"):
            old.pop(key)
        validate(old)


class IngestTests(Fixture):
    def test_schema_two_health_avoids_spool_directory_enumeration(self):
        self.publish(batch())
        (self.spool / "health.json").write_text(json.dumps({
            "schema": 2, "sensor_id": "sensor", "time": "2026-09-18T12:00:00Z",
            "channels": {SYSMON: {"status": "complete", "last_sequence": 1}},
        }))
        with mock.patch.object(Path, "iterdir",
                               side_effect=AssertionError("must not enumerate DrvFS")):
            report = self.run_ingest()
        self.assertEqual(report["events"], 1)
        self.assertEqual(report["channels"][0]["channel"], SYSMON)

    def test_manifest_missing_batch_is_a_delivery_error_not_empty_success(self):
        (self.spool / "health.json").write_text(json.dumps({
            "schema": 2, "sensor_id": "sensor", "time": "2026-09-18T12:00:00Z",
            "channels": {SYSMON: {"status": "complete", "last_sequence": 1}},
        }))
        report = self.run_ingest()
        self.assertIn("could not preserve", report["channels"][0]["error"])
        self.assertGreater(report["channels"][0]["backlog"], 0)

    def test_spool_io_error_is_distinct_from_not_installed(self):
        with mock.patch.object(Path, "stat", side_effect=OSError(5, "I/O error")):
            report = self.run_ingest()
        self.assertIsNone(report["installed"])
        self.assertTrue(report["access_error"])

    def test_replay_after_restart_is_idempotent(self):
        self.publish(batch())
        self.assertEqual(self.run_ingest()["events"], 1)
        self.reopen()
        self.assertEqual(self.run_ingest()["events"], 0)
        self.assertEqual(len(self.events()), 1)

    def test_missing_batch_holds_the_cursor(self):
        self.publish(batch(1))
        self.publish(batch(3))
        ch = self.run_ingest()["channels"][0]
        self.assertIn("batch 2 is missing", ch["error"])
        self.assertEqual(self.log.cursor("sensor", SYSMON)["sequence"], 1)

    def test_committed_batch_replaced_in_spool_is_refused(self):
        self.publish(batch(1))
        self.run_ingest()
        changed = batch(1)
        changed["bookmark"] = "record:9"
        self.publish(changed)
        self.assertIn("replaced", self.run_ingest()["channels"][0]["error"])

    def test_generation_change_requires_a_gap(self):
        self.publish(batch(1))
        self.run_ingest()
        self.publish(batch(2, generation="gen-2"))
        self.assertIn("generation", self.run_ingest()["channels"][0]["error"])
        self.publish(batch(2, generation="gen-2", gap="Event log cleared"))
        result = self.run_ingest()["channels"][0]
        self.assertIsNone(result["error"])
        self.assertEqual(result["gaps"], ["Event log cleared"])

    def test_redelivered_record_in_same_generation_is_not_counted_twice(self):
        self.publish(batch(1, [record(1), record(2)]))
        self.publish(batch(2, [record(2), record(3)]))
        result = self.run_ingest()["channels"][0]
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual([e["record"] for e in self.events()], [1, 2, 3])

    def test_corrupt_batch_is_quarantined_and_the_channel_resumes(self):
        # Policy change (2026-09-19): a batch that fails validation is
        # preserved under quarantine/ and recorded as a gap in the event
        # history, so the channel resumes. Blocking delivery forever on one
        # poisoned file starved every later batch of the same evidence stream
        # — and the file's bytes are kept either way.
        self.publish(batch(1))
        self.publish("{", name=2)
        self.publish(batch(3))
        ch = self.run_ingest()["channels"][0]
        self.assertIsNone(ch["error"])
        self.assertEqual(ch["quarantined"], 1)
        self.assertEqual(ch["batches"], 2)          # batches 1 and 3 ingested
        self.assertTrue(any("quarantined" in g for g in ch["gaps"]))
        self.assertEqual(self.log.cursor("sensor", SYSMON)["sequence"], 3)
        self.assertEqual(len(list((self.spool / "quarantine").iterdir())), 1)

    def test_acknowledgement_names_the_exact_batch(self):
        path = self.publish(batch(1))
        self.run_ingest()
        ack = json.loads((self.spool / "acks" / f"{DIR}.json").read_text())
        self.assertEqual(ack["through_sequence"], 1)
        import hashlib
        self.assertEqual(ack["digest"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_spool_starting_after_batch_one_is_recorded_as_a_gap(self):
        self.publish(batch(5))
        ch = self.run_ingest()["channels"][0]
        self.assertIn("never received", ch["gaps"][0])

    def test_continuous_coverage_boundary_survives_later_complete_batches(self):
        broken = batch(1, gap="records were overwritten")
        broken["status"] = "partial"
        broken["created_at"] = "2026-09-18T12:01:00Z"
        healthy = batch(2)
        healthy["created_at"] = "2026-09-18T12:02:00Z"
        self.publish(broken)
        self.publish(healthy)
        self.run_ingest()
        cursor = self.log.cursor("sensor", SYSMON)
        self.assertEqual(cursor["continuous_since"], "2026-09-18T12:01:00Z")
        self.assertEqual(cursor["status"], "complete")

    def test_reboot_resets_continuous_coverage_to_first_new_boot_event(self):
        first = batch(1)
        first["boot_id"] = "boot-1"
        second = batch(2, [record(
            2, xml=sysmon_xml(1, UtcTime="2026-09-18 13:00:00.000",
                              ProcessGuid="{g-2}", ProcessId="2",
                              Image=r"C:\x\a.exe"))])
        second["boot_id"] = "boot-2"
        second["events"][0]["time"] = "2026-09-18T13:00:00Z"
        self.publish(first)
        self.publish(second)
        self.run_ingest()
        cursor = self.log.cursor("sensor", SYSMON)
        self.assertEqual(cursor["boot"], "boot-2")
        self.assertEqual(cursor["continuous_since"], "2026-09-18T13:00:00.000Z")

    def test_no_spool_means_not_installed(self):
        report = ingest.run(log=self.log, spool=self.root / "absent")
        self.assertFalse(report["installed"])


class EventLogTests(Fixture):
    def append(self, n=3, sequence=1):
        events = [normalize.normalize(record(i), batch(sequence)) for i in range(1, n + 1)]
        return self.log.append(events, {"sensor": "sensor", "channel": SYSMON,
                                        "sequence": sequence, "generation": "gen-1"})

    def test_uncommitted_tail_is_invisible_and_truncated(self):
        self.append()
        with open(self.logdir / "active.jsonl", "ab") as fh:
            fh.write(b'{"seq": 4, "v": 1}\n{"seq": 5')        # crash mid-batch
        self.assertEqual(len(self.events()), 3)
        self.reopen()
        self.assertEqual(self.log.last_seq, 3)
        self.assertEqual(self.append(1, 2), (4, 4))

    def test_sealed_history_verifies_and_detects_edits(self):
        self.append()
        self.log.seal(force=True)
        self.append(2, 2)
        self.log.seal(force=True)
        self.assertTrue(self.log.verify()["ok"])
        seg = self.logdir / "segments" / "000000000001.jseg"
        with gzip.open(seg, "rb") as fh:
            header, payload = fh.readline(), fh.read()
        with open(seg, "wb") as raw:
            for part in (header, payload.replace(b"a.exe", b"b.exe")):
                with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                    gz.write(part)
        problems = self.log.verify()["problems"]
        self.assertTrue(any("payload altered" in p for p in problems))

    def test_deleted_segment_is_not_mistaken_for_retention(self):
        self.append()
        self.log.seal(force=True)
        self.append(1, 2)
        self.log.seal(force=True)
        (self.logdir / "segments" / "000000000001.jseg").unlink()
        self.assertTrue(any("missing" in p for p in self.log.verify()["problems"]))

    def test_history_retention_never_deletes_even_without_holds(self):
        for s in range(1, 4):
            self.append(2, s)
            self.log.seal(force=True)
        self.log.hold(1, 2, "incident")
        removed = self.log.prune(budget=0)
        self.assertEqual(removed, [])
        result = self.log.verify()
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(self.log.missing(), [])
        self.assertEqual([e["seq"] for e in self.log.iter_events()], [1, 2, 3, 4, 5, 6])

    def test_anchor_detects_a_rewritten_history(self):
        self.append()
        self.log.seal(force=True)
        head = self.log.head()
        self.assertTrue(self.log.verify(anchor=head)["anchored"])
        self.assertFalse(self.log.verify(anchor=dict(head, hash="0" * 64))["ok"])

    def test_interrupted_seal_is_completed_on_open(self):
        self.append()
        header = self.log.seal(force=True)
        # Simulate a crash after the segment rename, before the chain line.
        chain = self.logdir / "chain.jsonl"
        chain.write_text("")
        self.reopen()
        self.assertEqual(self.log.chain[-1]["hash"], header["hash"])
        self.assertTrue(self.log.verify()["ok"])

    def test_cursor_and_sequence_survive_sealing(self):
        self.append()
        self.log.seal(force=True)
        self.reopen()
        self.assertEqual(self.log.last_seq, 3)
        self.assertEqual(self.log.cursor("sensor", SYSMON)["sequence"], 1)

    def test_second_writer_is_refused(self):
        with self.assertRaises(LogError):
            EventLog(self.logdir, writer=True)

    def test_lineage_and_sightings(self):
        parent = normalize.normalize(record(1), batch(1))
        child_xml = sysmon_xml(1, UtcTime="2026-09-18 12:00:01.000", ProcessGuid="{child}",
                               ProcessId="7", Image=r"C:\x\b.exe", ParentProcessGuid="{g-1}",
                               ParentProcessId="1", Hashes="SHA256=ABCDEF")
        child = normalize.normalize(record(2, xml=child_xml), batch(1))
        self.log.append([parent, child], {"sensor": "sensor", "channel": SYSMON,
                                          "sequence": 1, "generation": "gen-1"})
        self.assertEqual([p["guid"] for p in self.log.ancestry("{child}")], ["{child}", "{g-1}"])
        self.assertEqual(self.log.sighting("sha256", "abcdef")["count"], 1)
        self.reopen()
        self.log.rebuild_index()
        self.assertEqual(self.log.children("{g-1}")[0]["guid"], "{child}")


class NormalizeTests(unittest.TestCase):
    def test_process_access_uses_capitalised_guid_fields(self):
        xml = sysmon_xml(10, UtcTime="2026-09-18 12:00:00.000", SourceProcessGUID="{src}",
                         SourceImage=r"C:\t\dump.exe", TargetProcessGUID="{lsass}",
                         TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010")
        ev = normalize.normalize(record(1, 10, xml), batch())
        self.assertEqual((ev["category"], ev["action"]), ("process", "access"))
        self.assertEqual(ev["process"]["guid"], "{src}")
        self.assertEqual(ev["target"]["guid"], "{lsass}")
        self.assertEqual(ev["target"]["access"], "0x1010")
        self.assertEqual(ev["time"], "2026-09-18T12:00:00.000Z")

    def test_unknown_event_is_kept_with_its_fields(self):
        ev = normalize.normalize(record(1, 4242, sysmon_xml(4242, Anything="x")), batch())
        self.assertEqual((ev["category"], ev["action"]), ("unknown", "event_4242"))
        self.assertEqual(ev["attrs"]["Anything"], "x")
        self.assertIn("<EventID>4242", ev["raw"])

    def test_unparseable_record_is_kept_raw(self):
        ev = ingest._event(record(1, 1, "<Event><broken"), batch())
        self.assertEqual(ev["category"], "unknown")
        self.assertIn("_normalize_error", ev["attrs"])
        event_mod.validate(ev)

    def test_defender_detection(self):
        xml = sysmon_xml(1116, **{"Threat Name": "Trojan:Win32/X", "Path": r"file:_C:\a.exe",
                                  "Process Name": r"C:\Windows\explorer.exe"})
        ev = normalize.normalize(record(1, 1116, xml), batch(channel=normalize.DEFENDER))
        self.assertEqual((ev["category"], ev["action"]), ("malware", "detected"))
        self.assertEqual(ev["target"]["name"], "Trojan:Win32/X")


class SysmonConsumerTests(Fixture):
    def setUp(self):
        super().setUp()
        self.store = Store(str(self.root / "j.db"))
        # These fixtures exercise the ordinary incremental consumer with
        # historical event timestamps. Rule-change replay has its own tests.
        self.store.set_meta("sysmon_thread_rules", sysmon.THREAD_RULES)

    def tearDown(self):
        self.store.db.close()
        super().tearDown()

    def feed(self, *records):
        self.publish(batch(1, list(records)))
        self.run_ingest()

    def audit(self):
        # The native path may ask for the service state, never for events:
        # the PowerShell event query is the fallback this must not use.
        with mock.patch.object(sysmon, "_fetch", side_effect=AssertionError("fallback used")), \
                mock.patch.object(sysmon, "status", return_value={}):
            return sysmon.audit(self.store, hosts=("win",), incremental=True,
                                eventlog=self.logdir)

    def test_lsass_read_from_the_event_log(self):
        xml = sysmon_xml(10, UtcTime="2026-09-18 12:00:00.000", SourceProcessGUID="{s}",
                         SourceImage=r"C:\t\dump.exe", TargetImage=r"C:\Windows\System32\lsass.exe",
                         GrantedAccess="0x1010")
        self.feed(record(1, 10, xml))
        titles = [(f["severity"], f["title"]) for f in self.audit()]
        self.assertIn(("critical", "dump.exe opened LSASS memory"), titles)
        self.assertEqual(int(self.store.get_meta("sysmon_eventlog_seq")), 1)
        # The next run starts after the consumed offset.
        self.assertIn("delivered 0 events", " ".join(f["title"] for f in self.audit()))

    def test_rule_replay_reads_only_remote_thread_events(self):
        self.feed(record(1, 1), record(2, 8, sysmon_xml(
            8, UtcTime="2026-09-18 12:00:00.000",
            SourceImage=r"C:\Windows\System32\csrss.exe",
            TargetImage=r"C:\x\example.exe",
            StartAddress="0x00007FFB2EBF6400")))
        since = 1_789_632_000  # 2026-09-17; fixed historical fixture window
        result = sysmon._native(self.store, self.logdir, since=since, event_ids={8})
        self.assertIsNotNone(result)
        self.assertEqual([e["id"] for e in result[0]["events"]], [8])

    def test_driver_queue_drops_are_telemetry_loss(self):
        desc = ("Events dropped from driver queue:  ProcessCreate:87 RegistryEvent:53563. "
                "DriverQueueSize: 50000, 46591536 bytes.")
        self.feed(record(1, 255, sysmon_xml(255, UtcTime="2026-09-18 12:00:00.000",
                                           ID="QUEUE", Description=desc)))
        loss = [f for f in self.audit() if f["category"] == "telemetry loss"]
        self.assertEqual(loss[0]["severity"], "high")
        self.assertIn("53650 events lost", loss[0]["detail"])

    def test_stale_sensor_falls_back_to_the_query(self):
        self.feed(record(1))
        with mock.patch.object(sysmon, "now", return_value=time.time() + 3600), \
             mock.patch.object(sysmon, "status", return_value={"installed": True, "readable": True}), \
             mock.patch.object(sysmon, "_fetch", return_value={"events": [], "complete": True}) as q:
            sysmon.audit(self.store, hosts=("win",), incremental=True, eventlog=self.logdir)
        q.assert_called_once()


class NativeJobTests(Fixture):
    def setUp(self):
        super().setUp()
        self.log.close()
        self.store = Store(str(self.root / "j.db"))

    def tearDown(self):
        self.store.db.close()
        super().tearDown()

    def audit(self, spool=None):
        return native_job.audit(self.store, hosts=("win",), spool=spool or self.spool,
                                root=self.logdir)

    def health(self, age=0, **extra):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age))
        (self.spool / "health.json").write_text(json.dumps(dict({"time": stamp}, **extra)))

    def test_missing_sensor_is_a_visibility_finding(self):
        titles = [f["title"] for f in self.audit(self.root / "absent")]
        self.assertEqual(titles, ["The native Windows sensor is not installed"])

    def test_unreachable_spool_is_unavailable_not_not_installed(self):
        report = {"spool": str(self.spool), "installed": None,
                  "access_error": "[Errno 5] Input/output error", "health": None,
                  "channels": [], "batches": 0, "events": 0, "sealed": None,
                  "pruned": []}
        with collection.observe() as observation, \
             mock.patch.object(ingest, "run", return_value=report):
            found = self.audit()
        self.assertEqual(observation.status, "unavailable")
        self.assertEqual(found[0]["title"], "The native sensor spool is unreachable")
        self.assertNotIn("not installed", found[0]["title"].lower())

    def test_stale_health_and_disabled_channel(self):
        self.health(age=900, channels={normalize.TASKS: {
            "status": "unavailable", "reason": "InvalidOperationException: Event channel is disabled"}})
        found = {f["title"]: f for f in self.audit()}
        self.assertEqual(found["The native sensor has stopped reporting"]["severity"], "high")
        self.assertIn("wevtutil sl", found["The sensor cannot read TaskScheduler"]["detail"])

    def test_gap_is_reported_for_a_week(self):
        self.health()
        self.publish(batch(4))
        self.audit()
        again = [f for f in self.audit() if f["category"] == "telemetry loss"]
        self.assertEqual(len(again), 1)


if __name__ == "__main__":
    unittest.main()

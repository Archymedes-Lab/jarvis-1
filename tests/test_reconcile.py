import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jarvis.collectors.telemetry import reconcile
from jarvis.core import event
from jarvis.core.eventlog import EventLog
from jarvis.platform.native.normalize import SYSMON


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace("+00:00", "Z")


class ProcessReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "eventlog"
        self.log = EventLog(self.root, writer=True)
        self.addCleanup(self.log.close)
        self.now = time.time()

    def ev(self, record, pid, guid, started, action="start"):
        return event.make(
            host="WINBOX", sensor="sensor", device="device", boot="boot-7",
            channel=SYSMON, generation="generation", record=record,
            source="sysmon", source_event=1 if action == "start" else 5,
            time=iso(started), received=iso(self.now), category="process",
            action=action, process={"pid": pid, "guid": guid, "image": r"C:\x\worker.exe"})

    def dropped(self, record, count, at):
        return event.make(
            host="WINBOX", sensor="sensor", device="device", boot="boot-7",
            channel=SYSMON, generation="generation", record=record,
            source="sysmon", source_event=255, time=iso(at), received=iso(self.now),
            category="sensor", action="error",
            attrs={"Description": f"Events dropped from driver queue: ProcessCreate:{count}."})

    def commit(self, events, *, created=None, continuous=None, status="complete", gap=None):
        created = self.now if created is None else created
        continuous = self.now - 300 if continuous is None else continuous
        self.log.append(events, {
            "sensor": "sensor", "channel": SYSMON, "sequence": 1,
            "generation": "generation", "status": status, "gap": gap,
            "created_at": iso(created), "continuous_since": iso(continuous),
            "host": "WINBOX", "device": "device", "boot": "boot-7",
        })

    def snapshot(self, pid=42, started=None, observed=None):
        return [{"host": "win", "pid": pid, "name": "worker.exe",
                 "exe": r"C:\x\worker.exe", "started": iso(started or self.now - 60),
                 "observed_at": iso(observed or self.now)}]

    def test_snapshot_process_without_start_event_is_visibility_evidence(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 80)])
        findings = reconcile.processes(self.snapshot(), self.now, self.root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "temporal-process-start-missing")
        self.assertIn("boot-7:42", findings[0]["subject_id"])

    def test_missing_start_names_policy_attribution(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 80)])
        findings = reconcile.processes(
            self.snapshot(), self.now, self.root,
            policy={"event1": "filtered", "excludes": ["Image x"]})
        self.assertIn("likely Sysmon ProcessCreate filtering",
                      findings[0]["detail"])

    def test_driver_queue_loss_attributes_unmatched_missing_start(self):
        self.commit([self.ev(1, 7, "{first}", self.now - 80),
                     self.dropped(2, 12, self.now - 70)])
        findings = reconcile.processes(
            self.snapshot(), self.now, self.root,
            policy={"event1": "full"})
        self.assertIn("driver-queue loss", findings[0]["detail"])
        self.assertIn("dropped ProcessCreate", findings[0]["detail"])
        self.assertIn("12 observed this boot", findings[0]["detail"])

    def test_coverage_evidence_exposes_loss_without_raw_events(self):
        self.commit([self.ev(1, 7, "{first}", self.now - 80),
                     self.dropped(2, 12, self.now - 70)])
        evidence = reconcile.coverage_evidence(self.now, self.root)
        self.assertEqual(evidence["status"], "observed")
        self.assertEqual(evidence["boot"], "boot-7")
        self.assertEqual(evidence["dropped_process_create"], 12)
        self.assertNotIn("events", evidence)

    def test_exact_instance_match_is_consistent(self):
        started = self.now - 60
        self.commit([self.ev(1, 42, "{worker}", started)])
        self.assertEqual(reconcile.processes(self.snapshot(started=started), self.now, self.root), [])

    def test_pid_reuse_does_not_match_a_different_execution(self):
        self.commit([self.ev(1, 42, "{old}", self.now - 180)])
        findings = reconcile.processes(self.snapshot(started=self.now - 60), self.now, self.root)
        self.assertEqual(findings[0]["rule_id"], "temporal-process-start-missing")

    def test_recorded_exit_conflicts_with_live_exact_instance(self):
        started = self.now - 90
        self.commit([self.ev(1, 42, "{worker}", started),
                     self.ev(2, 42, "{worker}", self.now - 30, action="exit")])
        findings = reconcile.processes(self.snapshot(started=started), self.now, self.root)
        self.assertEqual(findings[0]["rule_id"], "temporal-process-exit-conflict")

    def test_exit_after_snapshot_does_not_create_a_race_false_positive(self):
        started = self.now - 90
        snapshot_at = self.now - 30
        self.commit([self.ev(1, 42, "{worker}", started),
                     self.ev(2, 42, "{worker}", self.now - 20, action="exit")])
        self.assertEqual(reconcile.processes(
            self.snapshot(started=started, observed=snapshot_at), self.now, self.root), [])

    def test_process_before_continuous_coverage_is_unknown(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 20)],
                    continuous=self.now - 30)
        self.assertEqual(reconcile.processes(
            self.snapshot(started=self.now - 60), self.now, self.root), [])

    def test_previous_boot_continuity_does_not_accuse_early_boot_process(self):
        # The first retained event in boot-7 is newer than this snapshot
        # process. Continuity inherited from an earlier boot cannot make the
        # absent ProcessCreate a discrepancy.
        self.commit([self.ev(1, 7, "{first}", self.now - 40)],
                    continuous=self.now - 3600)
        self.assertEqual(reconcile.processes(
            self.snapshot(started=self.now - 60), self.now, self.root), [])
        verdict = reconcile.classify_snapshot(
            self.snapshot(started=self.now - 60), self.now, self.root)[0]
        self.assertEqual(verdict["label"], "UNKNOWN")

    def kernel(self, name, started):
        return {"host": "win", "pid": 4, "name": name, "exe": "",
                "started": iso(started), "observed_at": iso(self.now)}

    def test_previous_boot_shutdown_tail_does_not_set_boundary(self):
        # The sensor labels the unread shutdown tail of the previous boot with
        # the new boot id. A start older than this boot's kernel processes
        # cannot belong to it, so it must not open continuity for boot-time
        # processes whose ProcessCreate Sysmon never delivered.
        self.commit([self.ev(1, 7, "{tail}", self.now - 200),
                     self.ev(2, 8, "{first}", self.now - 40),
                     self.dropped(3, 5, self.now - 39)],
                    continuous=self.now - 200)
        boot = [self.kernel("Registry", self.now - 120)] + \
            self.snapshot(started=self.now - 60)
        self.assertEqual(reconcile.processes(boot, self.now, self.root), [])
        evidence = reconcile.coverage_evidence(self.now, self.root, snapshot=boot)
        self.assertAlmostEqual(evidence["continuous_since"], self.now - 40, delta=1)
        self.assertEqual(evidence["dropped_process_create"], 5)

    def test_boot_floor_never_hides_a_gap_after_the_first_boot_start(self):
        self.commit([self.ev(1, 7, "{tail}", self.now - 200),
                     self.ev(2, 8, "{first}", self.now - 90)],
                    continuous=self.now - 200)
        boot = [self.kernel("Registry", self.now - 120)] + \
            self.snapshot(started=self.now - 60)
        findings = reconcile.processes(boot, self.now, self.root)
        self.assertEqual([f["rule_id"] for f in findings],
                         ["temporal-process-start-missing"])

    def test_boot_floor_requires_imageless_kernel_process(self):
        impostor = dict(self.kernel("Registry", self.now - 30), exe=r"C:\x\Registry")
        self.assertIsNone(reconcile.boot_floor([impostor]))
        self.assertIsNone(reconcile.boot_floor([]))

    def test_kernel_minimal_processes_are_unknown_not_missing(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 80)])
        vm = self.kernel("vmmemWSL", self.now - 60)
        self.assertEqual(reconcile.processes([vm], self.now, self.root), [])
        self.assertEqual(reconcile.classify_snapshot(
            [vm], self.now, self.root)[0]["label"], "UNKNOWN")

    def test_named_impostor_of_kernel_process_is_still_judged(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 80)])
        impostor = dict(self.kernel("vmmemWSL", self.now - 60),
                        exe=r"C:\Users\x\vmmemWSL")
        findings = reconcile.processes([impostor], self.now, self.root)
        self.assertEqual(len(findings), 1)

    def test_stale_or_gapped_stream_cannot_contradict_snapshot(self):
        self.commit([self.ev(1, 7, "{other}", self.now - 400)], created=self.now - 400)
        self.assertEqual(reconcile.processes(self.snapshot(), self.now, self.root), [])


class ProcessLookupIndexTests(unittest.TestCase):
    """The 60s scan resolves every live PID via process_instances(host, pid).

    At ~300k rows that lookup was a full table scan plus sort per PID
    (17s for ~280 processes). The composite index must exist and the exact
    query must seek it; verdict semantics are pinned by the tests above.
    """

    def test_host_pid_index_exists_on_fresh_writer_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = EventLog(Path(tmp) / "eventlog", writer=True)
            try:
                rows = log.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' "
                    "AND tbl_name='processes'").fetchall()
            finally:
                log.close()
        self.assertIn("processes_host_pid", {r[0] for r in rows})

    def test_process_instances_query_seeks_instead_of_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = EventLog(Path(tmp) / "eventlog", writer=True)
            try:
                plan = log.db.execute(
                    "EXPLAIN QUERY PLAN SELECT * FROM processes "
                    "WHERE host=? AND pid=? ORDER BY start_seq DESC LIMIT 32",
                    ("win", 4)).fetchall()
            finally:
                log.close()
        detail = " ".join(" ".join(str(v) for v in tuple(row)) for row in plan)
        self.assertIn("SEARCH", detail)
        self.assertNotIn("SCAN", detail)


if __name__ == "__main__":
    unittest.main()

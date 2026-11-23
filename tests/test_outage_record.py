"""The outage record: transitions, durability and the Windows lifecycle read.

Invariants (docs/architecture/LANE-FAIRNESS-AND-OUTAGE-RECORD.md): times come
from evidence; a spooled transition is never lost to a busy writer and never
duplicated by a crash between the append and the spool rewrite; record
numbers only grow; the record carries no command lines.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core.eventlog import EventLog
from jarvis.service import outages
from jarvis.service.outages import FAILING, STALE, UP, OutageRecorder, collector_state
from jarvis.service.reliability import build_specs

TEST_ROOT = Path(os.path.expanduser("~/.cache/jarvis-tests"))


def specs(**intervals):
    return build_specs({name: (interval, name) for name, interval in intervals.items()})


class Base(unittest.TestCase):
    def setUp(self):
        TEST_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.spool = Path(self.tmp.name) / "outages"
        self.log = Path(self.tmp.name) / "eventlog"

    def recorder(self, **kw):
        kw.setdefault("boot_time", 1.0)
        kw.setdefault("process_start", 2_000_000.0)
        return OutageRecorder(spool_dir=self.spool, log_root=self.log, **kw)

    def logged(self):
        with EventLog(self.log) as log:
            return [e for e in log.iter_events() if e.get("sensor") == outages.SENSOR]


class StateTests(unittest.TestCase):
    def test_stale_starts_at_twice_the_interval_after_the_last_result(self):
        self.assertEqual(collector_state({"ts": 1000.0}, 300, 2000.0), (STALE, 1600.0))

    def test_failing_and_up(self):
        self.assertEqual(collector_state({"ts": 1000.0, "error": "x"}, 300, 1100.0)[0], FAILING)
        self.assertEqual(collector_state({"ts": 1000.0}, 300, 1100.0)[0], UP)

    def test_no_result_is_stale_with_unknown_start(self):
        self.assertEqual(collector_state({}, 300, 1100.0), (STALE, None))


class TransitionTests(Base):
    def test_outage_opens_and_closes_with_evidence_times(self):
        r = self.recorder()
        sp = specs(audio=300)
        r.observe(sp, {"audio": {"ts": 1000.0}}, now=1100.0)          # up: nothing
        opened = r.observe(sp, {"audio": {"ts": 1000.0}}, now=5000.0)   # stale since 1600
        self.assertEqual([(x["transition"], x["start"]) for x in opened], [("start", 1600.0)])
        closed = r.observe(sp, {"audio": {"ts": 5200.0}}, now=5210.0)
        self.assertEqual(closed[0]["transition"], "end")
        self.assertEqual((closed[0]["start"], closed[0]["end"]), (1600.0, 5200.0))
        self.assertEqual(closed[0]["duration_s"], 3600.0)

    def test_an_open_outage_survives_a_restart(self):
        sp = specs(audio=300)
        self.recorder().observe(sp, {"audio": {"ts": 1000.0}}, now=5000.0)
        again = self.recorder()                      # new process
        self.assertEqual(again.observe(sp, {"audio": {"ts": 1000.0}}, now=6000.0), [])
        closed = again.observe(sp, {"audio": {"ts": 7000.0}}, now=7001.0)
        self.assertEqual((closed[0]["start"], closed[0]["end"]), (1600.0, 7000.0))

    def test_failing_cause_is_short_and_carried(self):
        r = self.recorder()
        rec = r.observe(specs(sysmon=600),
                        {"sysmon": {"ts": 1000.0, "error": "capped " * 100}}, now=1010.0)
        self.assertEqual(rec[0]["state"], FAILING)
        self.assertLessEqual(len(rec[0]["cause"]), outages.MAX_CAUSE)

    def test_coverage_and_report_are_not_collectors(self):
        r = self.recorder()
        self.assertEqual(r.observe(specs(coverage=600, report=300), {}, now=10_000.0), [])

    def test_observe_never_raises(self):
        r = self.recorder()
        self.assertEqual(r.observe({"x": object()}, {"x": "not a dict"}, now=1.0), [])


class FlushTests(Base):
    def test_spooled_transitions_reach_the_hash_chained_log(self):
        r = self.recorder()
        r.observe(specs(audio=300), {"audio": {"ts": 1000.0}}, now=5000.0)
        self.assertEqual(r.flush(), (1, ""))
        events = self.logged()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual((ev["category"], ev["action"]), ("sensor", "state"))
        self.assertEqual(ev["target"], {"subject": "collector:audio"})
        self.assertEqual(ev["attrs"]["state"], STALE)
        self.assertNotIn("cmdline", json.dumps(ev))
        self.assertEqual(r._pending(), [])

    def test_a_busy_writer_keeps_the_spool_for_the_next_pass(self):
        r = self.recorder()
        r.observe(specs(audio=300), {"audio": {"ts": 1000.0}}, now=5000.0)
        holder = EventLog(self.log, writer=True)
        try:
            with mock.patch.object(outages, "LOCK_DELAY_S", 0.0):
                appended, error = r.flush()
        finally:
            holder.close()
        self.assertEqual(appended, 0)
        self.assertIn("another process", error)
        self.assertEqual(len(r._pending()), 1)
        self.assertEqual(r.flush(), (1, ""))
        self.assertEqual(len(self.logged()), 1)

    def test_crash_after_the_append_never_duplicates(self):
        r = self.recorder()
        r.observe(specs(audio=300), {"audio": {"ts": 1000.0}}, now=5000.0)
        real_replace = os.replace

        def crash(src, dst):
            if str(dst).endswith("pending.jsonl"):
                raise OSError("power lost")
            return real_replace(src, dst)
        with mock.patch.object(outages.os, "replace", side_effect=crash):
            self.assertEqual(r.flush()[0], 0)
        self.assertEqual(len(r._pending()), 1)          # spool still holds it
        again = self.recorder()                          # restarted process
        self.assertEqual(again.flush(), (0, ""))         # cursor says committed
        self.assertEqual(len(self.logged()), 1)
        self.assertEqual(again._pending(), [])

    def test_record_numbers_never_reuse_a_committed_one(self):
        r = self.recorder()
        r.observe(specs(audio=300), {"audio": {"ts": 1000.0}}, now=5000.0)
        r.flush()
        (self.spool / "state.json").unlink()             # state lost
        again = self.recorder()
        again.observe(specs(hidden=300), {"hidden": {"ts": 1000.0}}, now=5000.0)
        self.assertEqual(again.flush(), (1, ""))
        self.assertEqual(len(self.logged()), 2)

    def test_spool_overflow_is_recorded_as_a_counted_gap(self):
        r = self.recorder()
        with mock.patch.object(outages, "SPOOL_MAX", 1):
            r.observe(specs(audio=300, hidden=300), {}, now=5000.0)
            self.assertEqual(r.flush(), (2, ""))
        subjects = [e["target"]["subject"] for e in self.logged()]
        self.assertIn("monitor:outage-record", subjects)
        dropped = [e for e in self.logged() if e["target"]["subject"] == "monitor:outage-record"]
        self.assertEqual(dropped[0]["attrs"]["count"], 1)

    def test_torn_final_spool_line_is_ignored(self):
        r = self.recorder()
        r.observe(specs(audio=300), {"audio": {"ts": 1000.0}}, now=5000.0)
        with open(self.spool / "pending.jsonl", "a") as fh:
            fh.write('{"record": 99, "subj')
        self.assertEqual(len(r._pending()), 1)


class HeartbeatTests(Base):
    def test_restart_gap_is_recorded_with_vm_cause(self):
        (self.spool).mkdir(parents=True, exist_ok=True)
        (self.spool / "heartbeat").write_text("1000.0\n")
        r = self.recorder(boot_time=1500.0, process_start=1600.0)
        rec = r.tick(now=1610.0, mono=5.0)
        self.assertEqual(rec[0]["subject"], "monitor:jarvis")
        self.assertEqual((rec[0]["start"], rec[0]["end"]), (1000.0, 1600.0))
        self.assertEqual(rec[0]["cause"], "WSL VM restarted")

    def test_daemon_only_restart(self):
        self.spool.mkdir(parents=True, exist_ok=True)
        (self.spool / "heartbeat").write_text("1000.0\n")
        rec = self.recorder(boot_time=500.0, process_start=1600.0).tick(now=1610.0, mono=5.0)
        self.assertEqual(rec[0]["cause"], "daemon restarted")

    def test_frozen_vm_is_a_pause_not_a_restart(self):
        r = self.recorder()
        r.tick(now=10_000.0, mono=100.0)
        rec = r.tick(now=10_000.0 + 4 * 3600, mono=120.0)    # wall jumped, mono did not
        self.assertEqual(rec[0]["cause"], "WSL VM paused (host standby or sleep)")
        self.assertEqual(rec[0]["duration_s"], 4 * 3600.0)

    def test_steady_beats_record_nothing(self):
        r = self.recorder()
        r.tick(now=10_000.0, mono=100.0)
        self.assertEqual(r.tick(now=10_020.0, mono=120.0), [])


class WindowsTests(Base):
    ROWS = [
        {"log": "Microsoft-Windows-Hyper-V-Worker-Admin", "id": 18590, "record": 10,
         "provider": "Microsoft-Windows-Hyper-V-Worker", "time": "2026-10-10T21:51:16Z",
         "line": "'37E63802-A2FA-45BA-987B-6327CB3921A6' has encountered a fatal error."},
        {"log": "Application", "id": 1000, "record": 7, "provider": "Application Error",
         "time": "2026-10-10T21:51:17Z", "line": "Faulting application name: wsl.exe, version"},
        {"log": "Application", "id": 1000, "record": 8, "provider": "Application Error",
         "time": "2026-10-10T21:52:00Z", "line": "Faulting application name: notepad.exe"},
    ]

    def test_lifecycle_records_carry_the_windows_record_identity(self):
        r = self.recorder()
        recs = r.read_windows(runner=lambda script: {"rows": self.ROWS, "failed": []})
        kinds = sorted(x["transition"] for x in recs)
        self.assertEqual(kinds, ["vm_fatal", "wsl_process_crash"])
        fatal = [x for x in recs if x["transition"] == "vm_fatal"][0]
        self.assertEqual(fatal["windows_record"], 10)
        self.assertEqual(fatal["vm"], "37E63802-A2FA-45BA-987B-6327CB3921A6")
        self.assertEqual(r.state["windows"]["Application"], 8)   # unrelated crash skipped, cursor moved

    def test_same_id_from_another_provider_is_not_a_host_event(self):
        r = self.recorder()
        rows = [{"log": "System", "id": 12, "record": 3, "time": "2026-10-10T20:00:00Z",
                 "provider": "Microsoft-Windows-UserModePowerService", "line": "Process ..."},
                {"log": "System", "id": 12, "record": 4, "time": "2026-10-10T20:01:00Z",
                 "provider": "Microsoft-Windows-Kernel-General", "line": "The operating system started"}]
        recs = r.read_windows(runner=lambda s: {"rows": rows, "failed": []})
        self.assertEqual([(x["transition"], x["windows_record"]) for x in recs], [("host_boot", 4)])
        self.assertEqual(r.state["windows"]["System"], 4)

    def test_a_reread_does_not_duplicate(self):
        r = self.recorder()
        run = lambda script: {"rows": self.ROWS, "failed": []}  # noqa: E731
        r.read_windows(runner=run)
        self.assertEqual(r.read_windows(runner=run), [])

    def test_stop_error_names_the_bug_check_and_not_a_vm(self):
        r = self.recorder()
        rows = [{"log": "System", "id": 1001, "record": 97700, "time": "2026-10-30T18:17:06Z",
                 "provider": "Microsoft-Windows-WER-SystemErrorReporting",
                 "line": "The computer has rebooted from a bugcheck.  The bugcheck was: 0x00020001 "
                         "(0x0000000000000011, 0x00000000003a8b1a, 0x0000000000001007, "
                         "0xffffe80000c4af00). A dump was saved in: C:\\WINDOWS\\Minidump\\"
                         "103026-21578-01.dmp. Report Id: a42c40a3-0b69-48fb-a98a-c7b6423b03ef."},
                {"log": "System", "id": 1001, "record": 97701, "time": "2026-10-30T18:18:00Z",
                 "provider": "Microsoft-Windows-WER-SystemErrorReporting", "line": "garbled"}]
        recs = r.read_windows(runner=lambda s: {"rows": rows, "failed": []})
        self.assertEqual([x["transition"] for x in recs], ["host_bugcheck", "host_bugcheck"])
        self.assertIn("0x20001 HYPERVISOR_ERROR (0x0000000000000011", recs[0]["cause"])
        self.assertNotIn("vm", recs[0])
        self.assertEqual(recs[1]["cause"], "Windows restarted after a stop error")
        self.assertLessEqual(len(recs[0]["cause"]), outages.MAX_CAUSE)

    def test_cursor_reaches_the_script(self):
        r = self.recorder()
        r.state["windows"] = {"System": 41}
        seen = {}
        r.read_windows(runner=lambda script: seen.setdefault("s", script) and None)
        self.assertIn('{"System": 41}', seen["s"])
        self.assertFalse(r.status["windows"]["ok"])

    def test_unreachable_windows_is_reported_not_invented(self):
        r = self.recorder()
        self.assertEqual(r.read_windows(runner=lambda script: None), [])
        self.assertFalse(r.status["windows"]["ok"])
        self.assertEqual(r._pending(), [])

    def test_unreadable_log_is_reported(self):
        r = self.recorder()
        r.read_windows(runner=lambda s: {"rows": [], "failed": ["Microsoft-Windows-Hyper-V-Worker-Admin"]})
        self.assertFalse(r.status["windows"]["ok"])


if __name__ == "__main__":
    unittest.main()

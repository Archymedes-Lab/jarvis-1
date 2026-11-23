"""The start history: every program that has started, so a process too short
for the once-a-minute scan can still be judged against "has this exact program
run here before?" (collectors/telemetry/sysmon_linux/history.py on Linux, the
event log's sightings on Windows, judged by web/procidentity.py)."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.telemetry.sysmon_linux import history
from jarvis.collectors.telemetry.sysmon_linux import run as sysmon_run
from jarvis.core.store import Store
from jarvis.web import procidentity as pid

NOW = 1_800_000_000
SHA = "ab" * 32


def start(image, sha=SHA, at=NOW, **extra):
    return {"id": 1, "Image": image, "Hashes": f"SHA1={'0' * 40},SHA256={sha.upper()}",
            "UtcTime": at, "CommandLine": "secret --token=x", "User": "root", **extra}


class RecordTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = str(Path(tmp.name) / "jarvis.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.at = lambda e: e["UtcTime"]

    def rows(self):
        return [tuple(r) for r in self.store.db.execute(
            "SELECT host, image, sha256, name, first_seen, last_seen, count FROM start_images ORDER BY image")]

    def test_starts_are_folded_into_one_row_per_image_and_hash(self):
        events = [start("/usr/bin/date", at=NOW), start("/usr/bin/date", at=NOW - 50),
                  start("/usr/bin/date", sha="cd" * 32, at=NOW), {"id": 3, "Image": "/usr/bin/curl"},
                  start("-"), {"id": 1, "Image": "/usr/bin/nohash", "UtcTime": NOW}]
        self.assertEqual(history.record(self.store, events, self.at), 4)
        self.assertEqual(self.rows(), [
            ("wsl", "/usr/bin/date", SHA, "date", NOW - 50, NOW, 2),
            ("wsl", "/usr/bin/date", "cd" * 32, "date", NOW, NOW, 1),
            ("wsl", "/usr/bin/nohash", "", "nohash", NOW, NOW, 1)])

    def test_nothing_but_image_hash_name_and_times_is_kept(self):
        history.record(self.store, [start("/usr/bin/date")], self.at)
        dump = "\n".join(self.store.db.iterdump())
        self.assertNotIn("secret", dump)
        self.assertNotIn("root", dump)

    def test_recording_start_is_set_once(self):
        with mock.patch.object(history, "now", return_value=NOW):
            history.record(self.store, [start("/a")], self.at)
        with mock.patch.object(history, "now", return_value=NOW + 999):
            history.record(self.store, [start("/b")], self.at)
        self.assertEqual(int(self.store.get_meta(history.SINCE_KEY)), NOW)

    def test_the_table_is_bounded_by_dropping_the_least_recently_seen(self):
        with mock.patch.object(history, "MAX_ROWS", 3):
            history.record(self.store, [start(f"/bin/p{i}", at=NOW + i) for i in range(5)], self.at)
        self.assertEqual([r[1] for r in self.rows()], ["/bin/p2", "/bin/p3", "/bin/p4"])


class CollectorTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Store(str(Path(tmp.name) / "jarvis.db"))
        self.addCleanup(self.store.close)
        for name, value in (("state", lambda: (True, True)), ("read_since", lambda since: ("", True, "")),
                            ("_parse", lambda text: [start("/usr/bin/date", at="2027-01-15 08:00:00.000")])):
            patcher = mock.patch.object(sysmon_run, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def count(self):
        return self.store.db.execute("SELECT count(*) FROM start_images").fetchone()[0]

    def test_only_the_scheduled_incremental_pass_records(self):
        sysmon_run.audit(self.store, incremental=False)
        self.assertEqual(self.store.db.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='start_images'").fetchone()[0], 0)
        sysmon_run.audit(self.store, incremental=True)
        self.assertEqual(self.count(), 1)

    def test_a_failed_write_is_a_finding_and_the_audit_still_reports(self):
        with mock.patch.object(history, "record", side_effect=sqlite3.OperationalError("locked")):
            out = sysmon_run.audit(self.store, incremental=True)
        titles = [f.get("title", "") for f in out]
        self.assertIn("Linux start history not recorded this pass", titles)
        self.assertTrue(any("delivered" in t for t in titles), "the audit's own findings survive")


class StartVerdictTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = str(Path(tmp.name) / "jarvis.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.store.db.execute("INSERT INTO procs(fp, host, name, exe, first_seen, last_seen, approved) "
                              "VALUES('f1', 'wsl', 'sleep', '/usr/bin/sleep', ?, ?, 0)", (NOW - 9e6, NOW))
        self.store.commit()
        self.index = str(Path(tmp.name) / "index.db")
        db = sqlite3.connect(self.index)
        db.execute("CREATE TABLE processes (guid TEXT, host TEXT, pid INTEGER, sha256 TEXT, started TEXT,"
                   " start_seq INTEGER)")
        db.execute("CREATE TABLE sightings (kind TEXT, value TEXT, first_seq INTEGER, first_time TEXT,"
                   " last_seq INTEGER, last_time TEXT, count INTEGER, PRIMARY KEY(kind, value))")
        db.execute("INSERT INTO sightings VALUES('image', 'c:\\program files\\app\\tool.exe', 1,"
                   " '2026-01-01T00:00:00Z', 1, '2026-01-01T00:00:00Z', 9)")
        db.commit()
        db.close()
        self.history = pid.HashHistory(self.index)
        self.addCleanup(self.history.close)

    def judge(self, since):
        if since is not None:
            with mock.patch.object(history, "now", return_value=since):
                history.record(self.store, [start("/usr/bin/date", at=NOW - 9e5),
                                            start("/usr/local/bin/today", sha="ef" * 32, at=NOW - 60)],
                               lambda e: e["UtcTime"])
        linux = pid.LinuxStarts(self.path)
        self.addCleanup(linux.close)
        return pid.Judge(self.path, history=self.history, linux=linux, wall=lambda: NOW)

    def test_a_mature_history_tells_familiar_from_first_runs(self):
        j = self.judge(since=NOW - 3 * 86400)
        self.assertEqual(j.judge_start("lin", "date", "/usr/bin/date", SHA), ["system", "same", "known"])
        self.assertEqual(j.judge_start("lin", "today", "/usr/local/bin/today", "ef" * 32),
                         ["system", "new", "recent"])
        self.assertEqual(j.judge_start("lin", "never", "/usr/bin/never", "99" * 32), ["system", "new", "new"])

    def test_a_young_history_says_unknown_never_new(self):
        j = self.judge(since=NOW - 3600)
        self.assertEqual(j.judge_start("lin", "never", "/usr/bin/never", "99" * 32),
                         ["system", "unknown", "unknown"])
        j = self.judge(since=None)              # nothing recorded yet: no table at all
        self.assertEqual(j.judge_start("lin", "never", "/usr/bin/never", "99" * 32)[1:], ["unknown", "unknown"])

    def test_a_familiar_name_from_temp_is_moved_whatever_the_history(self):
        j = self.judge(since=NOW - 3 * 86400)
        self.assertEqual(j.judge_start("lin", "sleep", "/tmp/x/sleep")[:2], ["temp", "moved"])

    def test_windows_starts_use_the_event_log_image_sightings(self):
        j = self.judge(since=None)
        self.assertEqual(j.judge_start("win", "tool.exe", "C:\\Program Files\\App\\tool.exe")[1], "same")
        self.assertEqual(j.judge_start("win", "new.exe", "C:\\Program Files\\App\\new.exe")[1], "new")


if __name__ == "__main__":
    unittest.main()

"""The /procs identity check: places, path verdicts against the scan baseline,
hash verdicts against the event log, and the rules that keep a masquerade from
fading. The store and event-log index are real SQLite files built here."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from jarvis.web import procidentity as pid

NOW = 1_800_000_000
OLD = NOW - 30 * 86400            # established
TODAY = NOW - 3600                # within RECENT_S


def make_store(path, rows):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE procs (fp TEXT PRIMARY KEY, host TEXT, name TEXT, exe TEXT, script TEXT,"
               " cmdline TEXT, user TEXT, first_seen INTEGER, last_seen INTEGER, seen_count INTEGER,"
               " approved INTEGER, note TEXT)")
    for i, (host, name, exe, first, approved) in enumerate(rows):
        db.execute("INSERT INTO procs VALUES(?,?,?,?,'','','',?,?,1,?,'')",
                   (f"fp{i}", host, name, exe, first, first, approved))
    db.commit()
    db.close()


def make_index(path, processes, sightings):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE processes (guid TEXT PRIMARY KEY, host TEXT, pid INTEGER, image TEXT,"
               " sha256 TEXT, cmdline TEXT, user TEXT, parent_guid TEXT, started TEXT, start_seq INTEGER,"
               " ended TEXT, end_seq INTEGER, first_seq INTEGER, last_seq INTEGER)")
    db.execute("CREATE TABLE sightings (kind TEXT, value TEXT, first_seq INTEGER, first_time TEXT,"
               " last_seq INTEGER, last_time TEXT, count INTEGER, PRIMARY KEY(kind, value))")
    for i, (p, sha, started) in enumerate(processes):
        db.execute("INSERT INTO processes(guid,host,pid,sha256,started,start_seq) VALUES(?,?,?,?,?,?)",
                   (f"g{i}", "PC", p, sha, started, i))
    for sha, first in sightings:
        db.execute("INSERT INTO sightings VALUES('sha256',?,1,?,1,?,1)", (sha, first, first))
    db.commit()
    db.close()


BASELINE = [
    ("win", "svchost.exe", "C:\\WINDOWS\\System32\\svchost.exe", OLD, 0),
    ("win", "lsass.exe", "", OLD, 0),                                 # path never readable
    ("win", "msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\150.0.1.2\\msedge.exe", OLD, 0),
    ("win", "tool.exe", "C:\\Windows\\System32\\tool.exe", OLD, 0),
    ("win", "tool.exe", "C:\\Users\\me\\AppData\\Local\\Temp\\tool.exe", OLD, 0),  # old, never approved
    ("win", "helper.exe", "C:\\Windows\\System32\\helper.exe", OLD, 0),
    ("win", "helper.exe", "C:\\Users\\me\\bin\\helper.exe", OLD, 1),               # approved by the owner
    ("win", "fresh.exe", "C:\\Users\\me\\fresh.exe", TODAY, 0),
    ("win", "app.exe", "C:\\Users\\me\\AppData\\Local\\Programs\\App\\app.exe", OLD, 0),
    ("wsl", "python3", "/usr/bin/python3.12", OLD, 0),
    ("wsl", "Relay(41)", "/init", OLD, 0),
]


class Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = str(Path(tmp.name) / "jarvis.db")
        self.index = str(Path(tmp.name) / "index.db")
        make_store(self.store, BASELINE)
        make_index(self.index,
                   [(500, "aa" * 32, "2027-01-15T08:00:00.000Z"), (500, "bb" * 32, "2027-01-15T07:00:00.000Z"),
                    (600, None, "2027-01-15T08:00:00.000Z")],
                   [("aa" * 32, "2026-12-01T00:00:00Z"), ("cc" * 32, "2027-01-15T07:00:00Z")])
        self.history = pid.HashHistory(self.index)
        self.addCleanup(self.history.close)
        self.judge = pid.Judge(self.store, history=self.history, wall=lambda: NOW)


class PlaceTests(unittest.TestCase):
    def test_windows_places(self):
        cases = {
            "C:\\Windows\\System32\\svchost.exe": "system",
            "c:/windows/explorer.exe": "system",
            "C:\\Windows\\Temp\\x.exe": "temp",
            "C:\\Program Files\\App\\a.exe": "program",
            "C:\\Program Files (x86)\\App\\a.exe": "program",
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe": "program",
            "C:\\ProgramData\\Evil\\x.exe": "other",
            "C:\\Users\\me\\AppData\\Local\\Temp\\x.exe": "temp",
            "C:\\Users\\me\\Downloads\\x.exe": "temp",
            "C:\\Users\\Public\\x.exe": "temp",
            "C:\\Users\\me\\AppData\\Roaming\\x.exe": "user",
            "D:\\Games\\x.exe": "other",
            "Registry": "kernel",
            "": "unknown",
        }
        for path, expected in cases.items():
            self.assertEqual(pid.place("win", path), expected, path)

    def test_linux_places(self):
        cases = {
            "/usr/bin/python3.12": "system", "/init": "system", "/opt/x/bin/y": "system",
            "/home/me/.local/bin/x": "user", "/tmp/go-build1/x": "temp", "/dev/shm/x": "temp",
            "/memfd:payload (deleted)": "fileless", "/usr/sbin/sshd (deleted)": "deleted",
            "/srv/x": "other", "": "unknown",
        }
        for path, expected in cases.items():
            self.assertEqual(pid.place("lin", path), expected, path)

    def test_versions_fold_so_an_update_in_place_is_the_same_path(self):
        a = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\150.0.1.2\\msedge.exe"
        b = "C:\\PROGRAM FILES (X86)\\Microsoft\\Edge\\Application\\151.0.4129.93\\msedge.exe"
        self.assertEqual(pid.fold("win", a), pid.fold("win", b))
        self.assertEqual(pid.fold("lin", "/usr/bin/python3.12"), pid.fold("lin", "/usr/bin/python3.13"))
        self.assertNotEqual(pid.fold("win", a), pid.fold("win", "C:\\Users\\me\\msedge.exe"))


class PathVerdictTests(Fixture):
    def path(self, host, name, exe):
        return self.judge.judge(host, name, exe)[1]

    def test_same_similar_and_case(self):
        self.assertEqual(self.path("win", "SVCHOST.EXE", "c:\\windows\\system32\\svchost.exe"), "same")
        self.assertEqual(self.path("win", "msedge.exe",
                                   "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\151.0.9.9\\msedge.exe"),
                         "same")
        self.assertEqual(self.path("win", "msedge.exe", "C:\\Program Files\\Other\\msedge.exe"), "similar")
        self.assertEqual(self.path("lin", "python3", "/usr/bin/python3.13"), "same")
        self.assertEqual(self.path("lin", "Relay(97)", "/init"), "same")

    def test_a_familiar_name_from_an_unfamiliar_place_is_moved(self):
        self.assertEqual(self.path("win", "app.exe", "C:\\ProgramData\\x\\app.exe"), "moved")
        self.assertEqual(self.path("lin", "python3", "/tmp/python3"), "moved")

    def test_core_windows_names_must_run_from_the_system_place(self):
        # lsass has no recorded path at all; the rule still holds.
        self.assertEqual(self.path("win", "lsass.exe", "C:\\Windows\\System32\\lsass.exe"), "unknown")
        self.assertEqual(self.path("win", "lsass.exe", "C:\\Users\\me\\lsass.exe"), "moved")
        self.assertEqual(self.path("win", "svchost.exe", "C:\\Users\\Public\\svchost.exe"), "moved")

    def test_a_system_name_in_a_user_writable_place_never_fades_without_approval(self):
        # tool.exe ran from Temp a month ago and was never approved: still moved.
        self.assertEqual(self.path("win", "tool.exe", "C:\\Users\\me\\AppData\\Local\\Temp\\tool.exe"), "moved")
        # helper.exe's user-folder copy was approved by the owner.
        self.assertEqual(self.path("win", "helper.exe", "C:\\Users\\me\\bin\\helper.exe"), "same")

    def test_new_names_and_names_with_only_recent_paths_are_new(self):
        self.assertEqual(self.path("win", "never.exe", "C:\\Users\\me\\never.exe"), "new")
        self.assertEqual(self.path("win", "fresh.exe", "C:\\Users\\me\\fresh.exe"), "new")

    def test_unknown_stays_unknown(self):
        self.assertEqual(self.path("win", "svchost.exe", ""), "unknown")
        broken = pid.Judge("/nonexistent/jarvis.db", history=self.history, wall=lambda: NOW)
        self.assertEqual(broken.judge("win", "svchost.exe", "C:\\Users\\Public\\svchost.exe")[1], "unknown")
        self.assertEqual(broken.state()["baseline"], "unavailable")

    def test_kernel_processes_have_no_file_and_are_not_flagged(self):
        self.assertEqual(self.judge.judge("win", "Registry", "Registry")[:2], ["kernel", "same"])


class HashVerdictTests(Fixture):
    def test_known_recent_new_and_unknown(self):
        self.assertEqual(self.judge.judge("win", "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "aa" * 32)[2],
                         "known")
        recent = pid.Judge(self.store, history=self.history,
                           wall=lambda: pid._iso_ms("2027-01-15T09:00:00Z") / 1000)
        self.assertEqual(recent.judge("win", "x.exe", "", "cc" * 32)[2], "recent")
        self.assertEqual(self.judge.judge("win", "x.exe", "", "dd" * 32)[2], "new")
        self.assertEqual(self.judge.judge("win", "x.exe", "", "")[2], "unknown")
        self.assertEqual(self.judge.judge("lin", "x", "/usr/bin/x", "aa" * 32)[2], "unknown",
                         "there is no Linux hash history to compare with")

    def test_recorded_hash_matches_the_exact_run_by_start_time(self):
        created = pid._iso_ms("2027-01-15T08:00:00.500Z")
        self.assertEqual(self.judge.recorded_hash("win", 500, created), "aa" * 32)
        self.assertEqual(self.judge.recorded_hash("win", 500, created + 3_600_000), "", "a reused pid")
        self.assertEqual(self.judge.recorded_hash("win", 600, created), "", "a start without a hash")
        self.assertEqual(self.judge.recorded_hash("lin", 500, created), "")

    def test_an_unreadable_index_gives_unknown(self):
        judge = pid.Judge(self.store, history=pid.HashHistory("/nonexistent/index.db"), wall=lambda: NOW)
        self.assertEqual(judge.recorded_hash("win", 500, 0), "")
        self.assertEqual(judge.judge("win", "x.exe", "", "aa" * 32)[2], "unknown")


class IndexKeyTests(unittest.TestCase):
    def test_the_lookup_key_is_the_event_logs_own(self):
        from jarvis.core import eventlog
        for kind in ("image", "sha256"):
            for value in ("C:\\Windows\\System32\\CMD.EXE", " AB" + "cd" * 31 + " ", "x.", ""):
                self.assertEqual(pid.index_key(value), eventlog._norm(kind, value))


class CacheTests(Fixture):
    def test_the_baseline_is_rebuilt_only_after_its_period(self):
        now = [0.0]
        loads = []

        def loader(path):
            loads.append(path)
            return pid.load_baseline(path)
        judge = pid.Judge(self.store, history=self.history, clock=lambda: now[0], wall=lambda: NOW, loader=loader)
        judge.judge("win", "svchost.exe", "C:\\Windows\\System32\\svchost.exe")
        judge.judge("win", "svchost.exe", "C:\\Windows\\System32\\svchost.exe")
        now[0] += pid.CACHE_S + 1
        judge.judge("win", "svchost.exe", "C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(len(loads), 2)
        self.assertEqual(judge.generation, 2)

    def test_verdict_words_are_all_from_the_documented_sets(self):
        places = {"system", "program", "user", "temp", "kernel", "fileless", "deleted", "other", "unknown"}
        for host, name, exe, *_ in BASELINE + [("win", "zz.exe", "Q:\\zz.exe", 0, 0)]:
            h = "lin" if host == "wsl" else host
            where, path, sha = self.judge.judge(h, name, exe)
            self.assertIn(where, places)
            self.assertIn(path, {"same", "similar", "moved", "new", "unknown"})
            self.assertIn(sha, {"known", "recent", "new", "unknown"})


if __name__ == "__main__":
    unittest.main()

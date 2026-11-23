"""Who was at the controls when a beep played (collectors/host/beepcheck.py).

Invariants:
  P1 injected input, another session or a remote-control program near a beep
     is "remote" (high, filed as a security threat), whatever else is true
  P2 a beep with only physical input is "local"; with nobody for 5 min and no
     input it is "unattended"
  P3 no input record covering the moment is "unknown", never "local"
  P4 a hook restart between beats (counters reset) is "unknown", never a delta
"""

import sqlite3
import unittest

from jarvis.collectors.host import beepcheck
from jarvis.response import categories

T = 1_800_000_000


class FakeStore:
    def __init__(self, beats):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE input_beats (ts, real_keys, injected_keys, real_clicks, injected_clicks,"
                        " real_moves, injected_moves, injected_keyups, injected_move_bursts)")
        self.db.executemany("INSERT INTO input_beats VALUES (?,?,?,?,?,?,?,?,?)", beats)


def beat(ts, real=(0, 0, 0), inj=(0, 0, 0)):
    return (ts, real[0], inj[0], real[1], inj[1], real[2], inj[2], 0, 0)


def finding(sev, title, detail, where, category="audio"):
    return {"severity": sev, "title": title, "detail": detail, "where": where, "category": category}


class InputTests(unittest.TestCase):
    def test_delta_between_the_beats_that_bracket_the_window(self):
        st = FakeStore([beat(T - 60, (100, 10, 500)), beat(T + 5, (102, 12, 900))])
        got = beepcheck.input_around(st, T)
        self.assertEqual((got["real"], got["injected"]), (2 + 2 + 400, 0))

    def test_no_covering_beat_or_a_hook_restart_is_unknown(self):
        self.assertIsNone(beepcheck.input_around(FakeStore([beat(T + 5)]), T))
        restart = FakeStore([beat(T - 60, (100, 10, 500)), beat(T + 5, (3, 0, 20))])
        self.assertIsNone(beepcheck.input_around(restart, T))


class VerdictTests(unittest.TestCase):
    none = {"sessions": [], "tools": [], "error": ""}

    def test_physical_input_only_is_local(self):
        v, _ = beepcheck.verdict({"idle_s": 0}, {"real": 50, "injected": 0}, self.none)
        self.assertEqual(v, "local")

    def test_injected_input_session_or_tool_is_remote_whatever_else(self):
        for inputs, present in (({"real": 50, "injected": 3}, self.none),
                                ({"real": 50, "injected": 0}, {**self.none, "sessions": ["rdp-tcp#0 (eve, Active)"]}),
                                ({"real": 50, "injected": 0}, {**self.none, "tools": ["anydesk"]}),
                                (None, {**self.none, "tools": ["teamviewer"]})):
            with self.subTest(inputs=inputs, present=present):
                self.assertEqual(beepcheck.verdict({"idle_s": 0}, inputs, present)[0], "remote")

    def test_nobody_present_is_unattended_and_no_record_is_unknown(self):
        self.assertEqual(beepcheck.verdict({"idle_s": 900}, {"real": 0, "injected": 0}, self.none)[0], "unattended")
        self.assertEqual(beepcheck.verdict({"idle_s": 0}, None, self.none)[0], "unknown")


class PresenceTests(unittest.TestCase):
    def test_console_and_service_sessions_are_not_other_people(self):
        data = {"sessions": [{"name": "services", "user": "", "state": "Disc"},
                             {"name": "console", "user": "chris", "state": "Active"},
                             {"name": "rdp-tcp#3", "user": "eve", "state": "Active"},
                             {"name": "rdp-tcp", "user": "65536", "state": "Listen"}],
                "procs": ["explorer", "anydesk", "rdpclip"]}
        p = beepcheck.presence(data)
        self.assertEqual(p["sessions"], ["rdp-tcp#3 (eve, Active)"])
        self.assertEqual(p["tools"], ["anydesk", "rdpclip"])
        # A session seen now says nothing about a beep from hours ago.
        old = beepcheck.findings(FakeStore([beat(T - 60), beat(T + 5, real=(0, 2, 400))]),
                                 [{"ts": T, "app": "x", "fg": "y", "idle_s": 0}], p, now=T + 7200, finding=finding)
        self.assertEqual([f["severity"] for f in old], ["low"])
        fresh = beepcheck.findings(FakeStore([beat(T - 60), beat(T + 5, real=(0, 2, 400))]),
                                   [{"ts": T, "app": "x", "fg": "y", "idle_s": 0}], p, now=T + 60, finding=finding)
        self.assertEqual(fresh[0]["severity"], "high")
        lone = beepcheck.presence({"sessions": [], "procs": ["rdpclip"]})
        self.assertEqual(lone["tools"], [])                 # the clipboard helper alone is no session
        self.assertIsNone(beepcheck.presence(None))


class FindingTests(unittest.TestCase):
    def test_remote_is_a_high_threat_and_local_only_counts(self):
        st = FakeStore([beat(T - 60, inj=(0, 0, 0)), beat(T + 5, real=(0, 2, 400), inj=(5, 0, 0))])
        out = beepcheck.findings(st, [{"ts": T, "app": "system sounds", "fg": "WindowsTerminal", "idle_s": 0}],
                                 {"sessions": [], "tools": [], "error": ""}, now=T + 60, finding=finding)
        high = [f for f in out if f["severity"] == "high"]
        self.assertEqual(len(high), 1)
        self.assertIn("injected input", high[0]["detail"])
        self.assertEqual(categories.of_finding(high[0], "audio"), "threat")
        st2 = FakeStore([beat(T - 60), beat(T + 5, real=(0, 2, 400))])
        out2 = beepcheck.findings(st2, [{"ts": T, "app": "system sounds", "fg": "WindowsTerminal", "idle_s": 0}],
                                  {"sessions": [], "tools": [], "error": ""}, now=T + 60, finding=finding)
        self.assertEqual([f["severity"] for f in out2], ["low"])
        self.assertIn("1 with only physical input", out2[0]["detail"])


if __name__ == "__main__":
    unittest.main()

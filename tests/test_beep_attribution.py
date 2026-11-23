"""Who made a short beep (2026-11-03).

Four real double 50 ms Beep() tones since 10-29 were never attributed: the
listener's handle snapshot runs after a tone that short has ended. Two signals
close that gap:

* the elevated broker's kernel trace of \\Device\\Beep opens (beeptrace.ps1 +
  collectors/host/beeptrace.py) names the caller, however short the tone and
  even when the caller is elevated;
* the unelevated listener records the foreground window's process tree as the
  likely source, always labelled as an inference.

These tests cover the Python side (parsing, matching, health, wording,
storage). The PowerShell side is in tests/test_beeptrace_script.py.
"""
import importlib
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import audiowatch, beeptrace
from jarvis.core.paths import win_script
from jarvis.core.store import Store
from jarvis.platform import broker
from tests.test_sound_listener import NOW, Base, line

ingest = importlib.import_module("jarvis.collectors.host.inputwatch.ingest")
ONSET_MS = (NOW - 60) * 1000


def opened(ms=ONSET_MS - 40, pid=17760, **over):
    row = {"ms": ms, "pid": pid, "path": r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe",
           "name": "powershell", "start": NOW - 3600, "user": r"LAPTOP\chris", "via": "live",
           "sig": "Valid", "signer": "Microsoft Windows"}
    row.update(over)
    return row


def output(opens=(), **over):
    data = {"version": 1, "boot": NOW - 9000, "mode": "filtered", "op": "is",
            "session_started": NOW - 8000, "fresh_session": False, "runs": 30, "parsed": len(opens),
            "breaches": 0, "parse_failures": 0, "etl_bytes": 8192, "etl_capped": False,
            "files_parsed": 1, "dropped_files": 0, "canary_checked": True, "canary_seen": True,
            "identity_failures": 0, "rows_dropped": 0, "run_seconds": 4, "errors": [],
            "opens": list(opens)}
    data.update(over)
    return data


def trace(opens=(), **over):
    parsed, why = beeptrace.parse(output(opens, **over))
    assert parsed is not None, why
    return parsed


def finding(severity, title, detail, category="audio"):
    return {"severity": severity, "title": title, "detail": detail, "category": category}


class ParseTests(unittest.TestCase):
    def test_a_well_formed_inventory_is_kept(self):
        t = trace([opened(), opened(ms=ONSET_MS + 300)])
        self.assertEqual(len(t["opens"]), 2)
        self.assertEqual(t["opens"][0]["name"], "powershell")

    def test_any_malformed_row_rejects_the_whole_output(self):
        for bad in (opened(pid=0), opened(ms=True), opened(via="guess"),
                    opened(via="unresolved"), opened(start=-1), "row"):
            parsed, why = beeptrace.parse(output([opened(), bad]))
            self.assertIsNone(parsed, bad)
            self.assertIn("malformed row", why)

    def test_unknown_format_mode_and_bounds_are_refused(self):
        self.assertIsNone(beeptrace.parse(output(version=2))[0])
        self.assertIsNone(beeptrace.parse(output(mode="unfiltered"))[0])
        self.assertIsNone(beeptrace.parse(output([opened()] * 501))[0])
        self.assertIsNone(beeptrace.parse(output(breaches=-1))[0])
        self.assertIsNone(beeptrace.parse(output(canary_seen="yes"))[0])
        self.assertIsNone(beeptrace.parse([])[0])

    def test_unresolved_opener_carries_no_identity(self):
        t = trace([opened(via="unresolved", start=0, path="", name="", user="", sig="unknown",
                          signer="")])
        self.assertIn("exited before it could be named", beeptrace.describe(t["opens"]))

    def test_control_characters_are_stripped(self):
        t = trace([opened(name="power\x1bshell\n")])
        self.assertEqual(t["opens"][0]["name"], "powershell")


class MatchTests(unittest.TestCase):
    def row(self, **over):
        r = {"sys": 1, "ms": ONSET_MS, "dur_ms": 680}
        r.update(over)
        return r

    def test_open_just_before_the_onset_and_the_second_pulse_both_match(self):
        t = trace([opened(), opened(ms=ONSET_MS + 400)])
        self.assertEqual(len(beeptrace.callers(self.row(), t)), 2)

    def test_opens_far_from_the_tone_do_not_match(self):
        t = trace([opened(ms=ONSET_MS - 5000), opened(ms=ONSET_MS + 680 + 2000)])
        self.assertEqual(beeptrace.callers(self.row(), t), [])

    def test_app_sessions_and_missing_traces_never_match(self):
        t = trace([opened()])
        self.assertEqual(beeptrace.callers(self.row(sys=0), t), [])
        self.assertEqual(beeptrace.callers(self.row(), None), [])

    def test_describe_names_each_process_once(self):
        text = beeptrace.describe(trace([opened(), opened(ms=ONSET_MS + 400)])["opens"])
        self.assertEqual(text.count("powershell ("), 1)
        self.assertIn("pid 17760", text)


class HealthTests(unittest.TestCase):
    def titles(self, t, why=""):
        return {f["title"]: f for f in beeptrace.health(t, why, finding)}

    def test_healthy_trace_is_quiet(self):
        self.assertEqual(self.titles(trace([opened()])), {})

    def test_not_installed_is_a_low_visibility_gap(self):
        got = self.titles(None, "the elevated broker is not installed")
        self.assertEqual(got["Beep() caller trace not running"]["severity"], "low")
        self.assertIn("jarvis broker install", got["Beep() caller trace not running"]["detail"])

    def test_failed_or_drifted_job_is_medium(self):
        got = self.titles(None, "the broker's copy of beeptrace.ps1 differs from this checkout")
        self.assertEqual(got["Beep() caller trace unavailable"]["severity"], "medium")

    def test_a_refused_filter_is_reported_not_hidden(self):
        got = self.titles(trace(mode="refused", errors=["the kernel filter was not applied"]))
        self.assertIn("Beep() caller trace refused: kernel filter not applied", got)

    def test_a_missing_canary_means_the_trace_is_blind(self):
        got = self.titles(trace(canary_seen=False))
        self.assertEqual(got["Beep() caller trace is blind"]["severity"], "medium")

    def test_an_unchecked_canary_is_not_called_blind(self):
        self.assertEqual(self.titles(trace(canary_checked=False, canary_seen=None)), {})

    def test_breaches_and_lost_windows_are_reported(self):
        got = self.titles(trace(breaches=3, parse_failures=1, etl_capped=True))
        self.assertIn("Beep() caller trace logged other files", got)
        self.assertIn("a file at its size cap", got["Beep() caller trace incomplete"]["detail"])


class TracedFindingTests(Base):
    def findings(self, t, *records):
        self.feed(*records)
        return {f["title"]: f for f in audiowatch.sound_findings(self.store, now=NOW, trace=t)}

    def test_a_short_unattributed_tone_is_named_by_the_trace(self):
        got = self.findings(trace([opened(), opened(ms=ONSET_MS + 400)]),
                            line(caller="none visible", caller_blocked_new=27, dur_ms=680, pulses=2))
        f = got["beep-like sound from powershell (Beep() call, kernel trace)"]
        self.assertIn("kernel file trace recorded powershell (pid 17760", f["detail"])
        self.assertIn("called Beep()", f["detail"])

    def test_the_listener_naming_wins_over_the_trace(self):
        got = self.findings(trace([opened(pid=999, name="other")]),
                            line(caller="found", caller_pid=8316, caller_app="powershell"))
        self.assertIn("beep-like sound from powershell (Beep() call)", got)
        self.assertNotIn("other", json.dumps(got))

    def test_without_a_matching_open_nothing_is_attributed(self):
        got = self.findings(trace([opened(ms=ONSET_MS - 60_000)]), line(caller="none"))
        self.assertIn("beep-like sound from the system sounds session", got)

    def test_audit_attributes_through_the_broker_trace(self):
        self.feed(line(ts=int(__import__("time").time()) - 60,
                       ms=(int(__import__("time").time()) - 60) * 1000, caller="none visible",
                       caller_blocked_new=3))
        onset = self.rows()[0]["ms"]
        with mock.patch.object(beeptrace, "load", return_value=(trace([opened(ms=onset - 30)]), "")), \
                mock.patch.object(audiowatch, "ps_json", return_value=None), \
                mock.patch.object(audiowatch.collection, "failed"):
            titles = [f["title"] for f in audiowatch.audit(self.store)]
        self.assertIn("beep-like sound from powershell (Beep() call, kernel trace)", titles)

    def test_audit_reports_trace_health_even_when_core_audio_fails(self):
        with mock.patch.object(beeptrace, "load", return_value=(None, "the elevated broker is not installed")), \
                mock.patch.object(audiowatch, "ps_json", return_value=None), \
                mock.patch.object(audiowatch.collection, "failed"):
            titles = [f["title"] for f in audiowatch.audit(self.store)]
        self.assertIn("Beep() caller trace not running", titles)


class LikelySourceTests(Base):
    def test_single_candidate_is_stored_and_labelled_an_inference(self):
        self.feed(line(caller="none visible", caller_blocked_new=27, likely_pid=17760, likely_n=1,
                       likely_list="powershell:17760", likely_app="powershell",
                       likely_start="2026-11-03T08:14:56Z"))
        row = self.rows()[0]
        self.assertEqual((row["likely_pid"], row["likely_app"]), (17760, "powershell"))
        got = {f["title"]: f for f in audiowatch.sound_findings(self.store, now=NOW)}
        title = "beep-like sound from the system sounds session, likely powershell (inferred, not traced)"
        self.assertIn("inferred and not proven", got[title]["detail"])
        self.assertIn("not who called", got[title]["detail"])

    def test_several_candidates_are_listed_and_none_is_named(self):
        self.feed(line(caller="none", likely_n=3,
                       likely_list="powershell:17760 powershell:5716 powershell:10788"))
        got = [f["title"] for f in audiowatch.sound_findings(self.store, now=NOW)]
        self.assertTrue(any("likely one of 3" in t for t in got), got)

    def test_inference_is_refused_where_it_does_not_belong(self):
        self.feed(line(caller="found", caller_pid=8316, likely_pid=1, likely_n=1),   # caller known
                  line(sys=0, pid=9768, app="firefox", known=1, likely_pid=1, likely_n=1),  # app session
                  line(caller="none", likely_pid=17760, likely_n=3),                   # pid with several
                  line(caller="none", likely_n=99),                                    # over bound
                  line(caller="none", likely_pid=-1, likely_n=1),
                  line(caller="none", likely_pid=17760, likely_n=1, likely_list="x" * 500))
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["likely_list"]), 160)

    def test_old_hook_lines_without_the_fields_still_store(self):
        self.feed(line(caller="none"))
        self.assertEqual(self.rows()[0]["likely_n"], 0)

    def test_old_table_gains_the_columns(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE sound_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER "
                       "NOT NULL, ms INTEGER NOT NULL, sound TEXT NOT NULL, source TEXT NOT NULL, "
                       "dur_ms INTEGER NOT NULL, peak REAL NOT NULL)")
            db.commit()
            db.close()
            old = Store(path)
            cols = {r[1] for r in old.db.execute("PRAGMA table_info(sound_events)")}
            old.close()
        self.assertTrue({"likely_pid", "likely_app", "likely_start", "likely_list", "likely_n"} <= cols)


class WiringTests(unittest.TestCase):
    def test_broker_runs_and_fingerprints_the_job(self):
        self.assertEqual(broker.SCRIPTS["beeptrace"], "beeptrace.ps1")
        self.assertTrue(os.path.exists(win_script("beeptrace.ps1")))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "jarvis-elevated-broker.ps1"), encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r"beeptrace = @\{ script = 'beeptrace.ps1';\s+timeout = (\d+) \}", text)
        self.assertIsNotNone(m)
        self.assertLessEqual(int(m.group(1)), 120)

    def test_hook_reports_the_inference_only_where_nothing_was_found(self):
        with open(win_script("inputhook.ps1"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertEqual(src.count("Likely(t.FgPid)"), 1)
        line_ = next(x for x in src.splitlines() if "Likely(t.FgPid)" in x)
        self.assertIn('"none visible" : "none"', line_)


if __name__ == "__main__":
    unittest.main()

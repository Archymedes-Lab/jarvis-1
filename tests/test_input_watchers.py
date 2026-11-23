"""Input watcher inventory (Win32k audit trace via the elevated broker)."""

import unittest
from pathlib import Path

from jarvis.collectors.host.inputwatch import watchers
from jarvis.platform import broker

ROOT = Path(__file__).resolve().parent.parent


def row(**kw):
    base = {"kind": "hook", "type": "13", "pid": 4242, "start": 1_700_000_000,
            "path": r"C:\Users\u\AppData\Roaming\x\agent.exe", "via": "live",
            "sig": "NotSigned", "signer": "", "first": 1_700_000_100,
            "last": 1_700_000_100, "count": 1, "lib": "", "failed": False,
            "visible_windows": None}
    base.update(kw)
    return base


def sev(r, own=()):
    f = watchers.classify(r, own)
    return f and f["severity"]


class ClassifyTests(unittest.TestCase):
    def test_unsigned_keyboard_hook_has_the_keylogger_shape(self):
        f = watchers.classify(row())
        self.assertEqual(f["severity"], "high")
        self.assertIn("agent.exe is watching every keyboard event", f["title"])
        self.assertIn("not proof", f["detail"])

    def test_script_host_signature_does_not_vouch_for_the_script(self):
        r = row(path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                sig="Valid", signer="Microsoft Windows")
        self.assertEqual(sev(r), "high")
        self.assertIn("script host", watchers.classify(r)["detail"])

    def test_jarvis_hook_is_recognised_by_supervised_pid_only(self):
        ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        self.assertEqual(sev(row(path=ps, sig="Valid"), own=[4242]), "ok")
        # The same image under another pid is not JARVIS, whatever it claims.
        self.assertEqual(sev(row(path=ps, sig="Valid", pid=5000), own=[4242]), "high")

    def test_briefly_running_watcher_keeps_its_severity(self):
        # A keylogger that captures for minutes and exits between broker runs
        # is still a keylogger; the inventory reports it once, marked exited.
        f = watchers.classify(row(exited=True))
        self.assertEqual(f["severity"], "high")
        self.assertIn("since exited", f["detail"])

    def test_null_hook_library_is_not_shown(self):
        self.assertNotIn("NULL", watchers.classify(row(lib="NULL"))["detail"])

    def test_unsigned_mouse_tracker_is_medium(self):
        self.assertEqual(sev(row(type="14")), "medium")

    def test_signed_software_is_named_without_score_weight(self):
        self.assertEqual(sev(row(sig="Valid", signer="Discord Inc.")), "low")
        self.assertEqual(sev(row(sig="Valid", path=r"C:\Program Files\Logi\x.exe")), "ok")

    def test_unidentified_process_is_a_visibility_gap(self):
        f = watchers.classify(row(path="", via="unresolved", start=0))
        self.assertEqual(f["severity"], "medium")
        self.assertIn("visibility gap", f["detail"])
        self.assertEqual(sev(row(path="", type="14")), "low")

    def test_ambiguous_hook_types_are_low_even_unsigned(self):
        self.assertEqual(sev(row(type="2")), "low")
        self.assertEqual(sev(row(type="3")), "low")

    def test_hooks_that_do_not_see_input_or_failed_are_ignored(self):
        self.assertIsNone(watchers.classify(row(type="-1")))    # WH_MSGFILTER
        self.assertIsNone(watchers.classify(row(failed=True)))

    def test_winevent_hooks_are_listed_without_keylogger_weight(self):
        # SetWinEventHook sees focus and window changes, never keystrokes.
        f = watchers.classify(row(kind="winevent", type="any"))
        self.assertEqual(f["severity"], "low")
        self.assertIn("not keystrokes", f["detail"])
        self.assertEqual(sev(row(kind="winevent", type="any", sig="Valid",
                                 path=r"C:\Windows\explorer.exe")), "ok")
        self.assertIsNone(watchers.classify(row(kind="winevent", type="any", path="", start=0)))

    def test_fast_key_state_polling_has_the_keylogger_shape(self):
        # The kernel writes 1003 only for >= 1 call/ms between key events, so a
        # row is already a fast poller; unsigned means the keylogger shape.
        f = watchers.classify(row(kind="poll", type="getasynckeystate", calls=6021, ms=94))
        self.assertEqual(f["severity"], "high")
        self.assertIn("6021 key-state calls in 94 ms", f["detail"])
        self.assertIn("agent.exe is watching every keyboard event", f["title"])
        # Signed OS components poll too (Explorer, input method editors): named, no weight.
        self.assertEqual(sev(row(kind="poll", type="getasynckeystate", sig="Valid",
                                 path=r"C:\Windows\explorer.exe")), "ok")

    def test_only_background_raw_input_sinks_count(self):
        sink = row(kind="rawinput", type="1/6/256", visible_windows=0)
        f = watchers.classify(sink)
        self.assertEqual(f["severity"], "high")
        self.assertIn("no visible window", f["detail"])
        self.assertIsNone(watchers.classify(row(kind="rawinput", type="1/6/0")))
        self.assertIsNone(watchers.classify(row(kind="rawinput", type="1/6/257")))  # removal
        self.assertIsNone(watchers.classify(row(kind="rawinput", type="1/5/256")))  # gamepad
        self.assertEqual(sev(row(kind="rawinput", type="1/2/4096")), "medium")      # EXINPUTSINK mouse


class AuditTests(unittest.TestCase):
    def test_unavailable_broker_is_stated_not_clean(self):
        # Blind to keyboard hooks is medium and a coverage failure (2026-10-27:
        # a broker timeout read as a complete run with a low note for hours).
        from jarvis.core import collection
        with collection.observe() as obs:
            out = watchers.audit(result=(None, "the elevated broker is not installed"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("not seen", out[0]["detail"])
        self.assertIn("inputaudit", obs.error)

    def test_summary_always_carries_the_polling_blind_spot(self):
        data = {"boot": 1000, "session_started": 1100, "watchers": [], "parse_failures": 0}
        out = watchers.audit(result=(data, ""), clock=2000)
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertIn("GetAsyncKeyState", out[0]["detail"])
        self.assertIn("0 process", out[0]["title"])
        # An older broker script (keyword 0x400) never sees 1003: say so, do not
        # describe the kernel gate as if polling were covered.
        self.assertIn("invisible until the broker is reinstalled", out[0]["detail"])
        data["polling_logged"] = True
        out = watchers.audit(result=(data, ""), clock=2000)
        self.assertIn("one call per millisecond", out[0]["detail"])
        self.assertNotIn("invisible", out[0]["detail"])

    def test_capped_trace_is_reported_as_lost_coverage(self):
        data = {"boot": 1, "session_started": 2, "watchers": [], "polling_logged": True,
                "etl_bytes": 128 << 20, "etl_capped": True}
        out = watchers.audit(result=(data, ""), clock=10)
        self.assertTrue(any("size cap" in f["title"] and f["severity"] == "medium" for f in out))

    def test_dropped_backlog_and_overflow_are_reported_not_silent(self):
        base = {"boot": 1, "session_started": 2, "watchers": [], "polling_logged": True}
        out = watchers.audit(result=(dict(base), ""), clock=10)
        self.assertEqual([f["severity"] for f in out], ["ok"])          # a clean queue adds nothing
        out = watchers.audit(result=(dict(base, dropped_files=2, dropped_bytes=200 << 20,
                                          dropped_retries=1), ""), clock=10)
        drop = next(f for f in out if "dropped" in f["title"])
        self.assertEqual(drop["severity"], "medium")
        self.assertIn("200 MB", drop["detail"])
        self.assertIn("3 times", drop["detail"])
        titles = {f["title"]: f["severity"] for f in watchers.audit(
            result=(dict(base, backlog_files=1, overflow=4, identity_failures=1), ""), clock=10)}
        self.assertEqual(titles["input audit is catching up"], "low")
        self.assertEqual(titles["part of the input audit was not kept"], "low")

    def test_retry_limit_matches_the_script(self):
        text = (ROOT / "jarvis/platform/win/inputaudit.ps1").read_text(encoding="utf-8")
        self.assertIn(f"$MaxTries = {watchers.MAX_TRACE_TRIES} ", text)

    def test_late_trace_start_and_parse_failures_are_reported(self):
        data = {"boot": 1000, "session_started": 1000 + 3600, "watchers": [],
                "parse_failures": 2}
        titles = [f["title"] for f in watchers.audit(result=(data, ""), clock=9000)]
        self.assertTrue(any("early in this boot" in t for t in titles))
        self.assertTrue(any("could not be read" in t for t in titles))

    def test_own_hook_is_not_counted_as_a_watcher(self):
        data = {"boot": 1, "session_started": 2,
                "watchers": [row(pid=7, sig="Valid"), row(type="14", pid=7, sig="Valid"),
                             row(pid=9, sig="Valid", signer="Discord Inc.")]}
        out = watchers.audit(own_pids=[7], result=(data, ""), clock=10)
        self.assertIn("1 process", out[-1]["title"])

    def test_summary_counts_processes_not_watchers(self):
        data = {"boot": 1, "session_started": 2,
                "watchers": [row(pid=5), row(pid=5, type="14"),
                             row(pid=5, kind="rawinput", type="1/6/256"),
                             row(pid=6, type="-1")]}          # not an input watcher
        out = watchers.audit(result=(data, ""), clock=10)
        self.assertIn("1 process", out[-1]["title"])

    def test_polling_events_without_a_row_are_not_lost(self):
        data = {"boot": 1, "session_started": 2, "watchers": [], "polling_events": 3}
        out = watchers.audit(result=(data, ""), clock=10)
        self.assertTrue(any("not attributed" in f["title"] and f["severity"] == "medium"
                            for f in out))
        # Attributed polling rows carry the finding; no second unattributed one.
        data["watchers"] = [row(kind="poll", type="getasynckeystate", calls=900, ms=120)]
        out = watchers.audit(result=(data, ""), clock=10)
        self.assertFalse(any("not attributed" in f["title"] for f in out))
        self.assertIn("1 process", out[-1]["title"])

    def test_winevent_hook_holders_are_reported_low_with_their_trust(self):
        rows = [row(kind="winevent", type="any", pid=10, path=r"C:\Program Files\NVDA\nvda.exe",
                    sig="Valid", signer="NV Access"),
                row(kind="winevent", type="any", pid=11, path=r"C:\Users\u\AppData\Local\Temp\s.exe",
                    sig="NotSigned")]
        out = watchers.audit(result=({"watchers": rows}, ""), clock=1767225700)
        hit = [f for f in out if "window-event hooks" in f["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "low")
        self.assertIn("nvda.exe", hit[0]["detail"])
        self.assertIn("Unsigned or unidentified: s.exe", hit[0]["detail"])
        self.assertNotIn("keystroke", hit[0]["title"])

    def test_winevent_watchers_do_not_count_as_input_watchers(self):
        data = {"boot": 1, "session_started": 2,
                "watchers": [row(kind="winevent", type="any", pid=8, sig="Valid")]}
        out = watchers.audit(result=(data, ""), clock=10)
        self.assertIn("0 process", out[-1]["title"])

    def test_malformed_rows_are_skipped(self):
        data = {"boot": 1, "session_started": 2, "watchers": [None, "x", {"kind": "hook", "type": "z"}]}
        self.assertEqual(len(watchers.audit(result=(data, ""), clock=10)), 1)


class BrokerWiringTests(unittest.TestCase):
    def test_job_is_registered_on_both_sides(self):
        self.assertEqual(broker.SCRIPTS["inputaudit"], "inputaudit.ps1")
        text = (ROOT / "jarvis-elevated-broker.ps1").read_text(encoding="utf-8")
        self.assertIn("inputaudit = @{ script = 'inputaudit.ps1'", text)

    def test_script_reports_exited_watchers_seen_this_run(self):
        text = (ROOT / "jarvis/platform/win/inputaudit.ps1").read_text(encoding="utf-8")
        self.assertIn("@($gone)", text)
        self.assertIn("$touched.ContainsKey($row.key)", text)

    def test_script_traces_the_keyword_that_carries_polling_and_filters_by_id(self):
        text = (ROOT / "jarvis/platform/win/inputaudit.ps1").read_text(encoding="utf-8")
        self.assertIn("$Keyword = '0x1400'", text)
        self.assertIn("EventID=1003", text)
        self.assertIn("-FilterXPath $WantIds", text)
        self.assertIn("-max $CapMB", text)

    def test_script_keeps_no_input_content(self):
        text = (ROOT / "jarvis/platform/win/inputaudit.ps1").read_text(encoding="utf-8")
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for forbidden in ("CommandLine", "MainWindowTitle", "GetAsyncKeyState(", "vkCode"):
            self.assertNotIn(forbidden, code)
        # Only JARVIS's own session is ever stopped or started.
        self.assertNotRegex(code, r"logman\.exe\s+(stop|start|delete)\s+(?!\$Name)")


if __name__ == "__main__":
    unittest.main()

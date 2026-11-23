import importlib
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host.inputwatch import analysis, forensics
from jarvis.core.store import Store
from jarvis.core.util import now
from jarvis.response.reporting import email_ui, emails, triage

# The package re-exports the ingest function under the module's name.
ingest_mod = importlib.import_module("jarvis.collectors.host.inputwatch.ingest")


def _key(ms, kind="key", **over):
    rec = {"ts": ms // 1000, "kind": kind, "injected": 1, "lower_il": 1,
           "class": "character", "fg": "msrdc:24044", "ms": ms,
           "burst": "B1", "seq": 0, "vk": 81, "vk_name": "VK_Q", "scan": 16,
           "key_name": "Q", "chr": "q" if kind == "key" else "",
           "redacted": 0, "mods": "", "flags": "0x12", "extended": 0,
           "alt_down": 0, "extra": "0x0", "event_tick": 1}
    rec.update(over)
    return rec


def _burst(ms, **over):
    rec = {"ts": ms // 1000, "kind": "inject-burst", "burst": "B1",
           "ms_start": ms, "ms_end": ms + 31, "events": 2, "downs": 1, "ups": 1,
           "printable": 1, "redacted": 0, "text": "q",
           "composition": {"upper": 0, "lower": 1, "digit": 0, "space": 0, "symbol": 0},
           "lower_il": 1, "extra_values": ["0x0"], "unmatched": [],
           "fg": "msrdc:24044", "fg_title": "Ubuntu", "fg_class": "RAIL_WINDOW",
           "focus_class": "", "fg_process": {
               "pid": 24044, "name": "msrdc", "il": "medium", "appcontainer": 0,
               "started_ms_before": 900000, "path": r"C:\Program Files\WSL\msrdc.exe"},
           "ms_since_real_key": 240000, "ms_since_real_click": 3000,
           "ms_since_real_move": 800, "dropped_total": 0,
           "candidates": [
               {"pid": 7, "name": "TextInputHost", "il": "low", "appcontainer": 1,
                "started_ms_before": 4000000, "path": r"C:\Windows\SystemApps\TextInputHost.exe",
                "why": "lower-integrity"},
               {"pid": 8, "name": "firefox", "il": "untrusted", "appcontainer": 0,
                "started_ms_before": 5000000, "path": "firefox.exe", "why": "lower-integrity"},
               {"pid": 9, "name": "firefox", "il": "untrusted", "appcontainer": 0,
                "started_ms_before": 5000000, "path": "firefox.exe", "why": "lower-integrity"}]}
    rec.update(over)
    return rec


class InputForensicsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Store(os.path.join(self._tmp.name, "jarvis.db"))
        self.addCleanup(self.store.close)
        self.jsonl = os.path.join(self._tmp.name, "input.jsonl")

    def _drain(self, records):
        with open(self.jsonl, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        with mock.patch.object(ingest_mod, "_paths", return_value=("x", self.jsonl)):
            return ingest_mod.ingest(self.store)

    def _audit(self):
        with mock.patch.object(analysis, "ingest", lambda store: 0):
            return analysis.audit(self.store, hours=24, pids=[1], supervised=True)

    def _injected(self):
        return [f for f in self._audit() if f["title"].startswith(("1 injected", "2 injected"))]

    def test_keyless_events_are_low_but_any_real_key_stays_high(self):
        ms = (now() - 60) * 1000
        none = dict(vk=255, vk_name="VK_NONE", scan=0, key_name="", chr="",
                    lower_il=0, extra="0x4321DCBA")
        self._drain([_key(ms, **none)])
        self.assertEqual([f["severity"] for f in self._injected()], ["low"])
        self._drain([_key(ms + 5, seq=1, lower_il=0)])     # a real 'q' joins the group
        self.assertEqual([f["severity"] for f in self._injected()], ["high"])

    def test_keyless_from_lower_integrity_stays_critical(self):
        ms = (now() - 60) * 1000
        self._drain([_key(ms, vk=255, vk_name="VK_NONE", scan=0, chr="")])
        self.assertEqual([f["severity"] for f in self._injected()], ["critical"])

    def test_exact_non_printable_media_key_is_not_charged_twice(self):
        ms = (now() - 60) * 1000
        key = _key(ms, vk=0xB3, vk_name="VK_0xB3", scan=0, chr="",
                   key_name="", lower_il=0, fg="WindowsTerminal:1520")
        control = {"ts": ms // 1000, "kind": "control-key",
                   "control": "media-play-pause", "class": "media-play-pause",
                   "injected": 1, "lower_il": 0, "fg": "WindowsTerminal:1520"}
        self._drain([key, control])
        findings = self._audit()
        duplicate = next(f for f in findings if f["where"] == "input_events"
                         and "media control" in f["title"])
        self.assertEqual(duplicate["severity"], "low")
        self.assertEqual(next(f for f in findings if f["title"] ==
                              "media play/pause was injected by software")["severity"], "medium")
        self.assertEqual(self.store.db.execute(
            "SELECT COUNT(*) FROM input_events").fetchone()[0], 1)
        self.assertEqual(self.store.db.execute(
            "SELECT COUNT(*) FROM control_events").fetchone()[0], 1)

    def test_unmatched_printable_and_lower_integrity_media_keys_stay_serious(self):
        ms = (now() - 60) * 1000
        control = {"ts": ms // 1000, "kind": "control-key",
                   "control": "media-play-pause", "injected": 1,
                   "lower_il": 0, "fg": "WindowsTerminal:1520"}
        base = dict(vk=0xB3, vk_name="VK_0xB3", scan=0, chr="",
                    key_name="", lower_il=0, fg="WindowsTerminal:1520")
        for change, expected in (({"fg": "OtherWindow:1"}, "high"),
                                 ({"chr": "x"}, "high"),
                                 ({"lower_il": 1}, "critical")):
            with self.subTest(change=change):
                self.store.db.execute("DELETE FROM input_events")
                self.store.db.execute("DELETE FROM control_events")
                self._drain([_key(ms, **(base | change)), control])
                key_findings = [f for f in self._audit()
                                if f["where"] == "input_events" and
                                f["title"].startswith("1 injected")]
                self.assertEqual([f["severity"] for f in key_findings], [expected])

    def test_the_exact_injected_character_is_named_with_its_context(self):
        ms = (now() - 60) * 1000
        self._drain([_key(ms), _key(ms + 31, kind="key-up", seq=1), _burst(ms)])

        finding = next(f for f in self._audit() if f["severity"] == "critical")

        self.assertIn("'q' U+0071 LATIN SMALL LETTER Q", finding["title"])
        text = "\n".join(finding["forensics"])
        self.assertIn("VK_Q (0x51), scan 0x10", text)
        self.assertIn("spelled 'q'", text)
        self.assertIn(r"C:\Program Files\WSL\msrdc.exe", text)
        self.assertIn("TextInputHost pid 7 · low integrity · AppContainer", text)
        self.assertIn("firefox ×2 sandboxed", text)
        self.assertIn("WSLg window host", text)
        self.assertIn("nobody was typing", text)

    def test_key_ups_are_evidence_not_extra_findings(self):
        ms = (now() - 60) * 1000
        self._drain([_key(ms), _key(ms + 31, kind="key-up", seq=1), _burst(ms)])

        injected = [f for f in self._audit() if "injected" in f["title"]
                    and f["category"] == "input" and f["severity"] != "ok"]

        self.assertEqual(len(injected), 1)

    def test_real_punctuation_and_digit_timestamps_are_not_reported_as_injected(self):
        for kind, cls in (("punct-key", "slash-question"), ("digit-key", "digit-3")):
            self.store.db.execute(
                "INSERT INTO input_events(ts,kind,lower_il,class,fg) VALUES(?,?,?,?,?)",
                (now() - 60, kind, 0, cls, "WindowsTerminal:1"))

        titles = [f["title"] for f in self._audit()]

        self.assertFalse([t for t in titles if t.startswith(("1 injected slash",
                                                             "1 injected digit"))])

    def test_events_from_before_forensic_capture_say_so_instead_of_guessing(self):
        self.store.db.execute(
            "INSERT INTO input_events(ts,kind,lower_il,class,fg) VALUES(?,?,?,?,?)",
            (now() - 60, "key", 1, "character", "msrdc:24044"))

        finding = next(f for f in self._audit() if f["severity"] == "critical")

        self.assertIn("cannot be recovered", finding["forensics"][0])
        self.assertNotIn("nobody was typing", "\n".join(finding["forensics"]))

    def test_a_redacted_burst_reports_composition_not_text(self):
        ms = (now() - 60) * 1000
        self._drain([_key(ms, vk=-1, vk_name="", scan=-1, key_name="", chr="",
                          redacted=1),
                     _burst(ms, printable=14, redacted=1, text="",
                            composition={"upper": 2, "lower": 8, "digit": 3,
                                         "space": 0, "symbol": 1})])

        text = "\n".join(next(f for f in self._audit()
                              if f["severity"] == "critical")["forensics"])

        self.assertIn("14 printable characters redacted", text)
        self.assertIn("password manager", text)

    def test_a_lone_surrogate_from_vk_packet_does_not_break_the_drain(self):
        ms = (now() - 60) * 1000
        self._drain([_key(ms, vk=231, vk_name="VK_PACKET", chr="\ud83d",
                          scan=0xD83D), _burst(ms, text="\U0001f600")])

        row = self.store.db.execute("SELECT record FROM input_events").fetchone()

        self.assertIn("U+D83D", json.loads(row["record"])["chr"])

    def test_known_sender_signatures_are_read_from_extra_info(self):
        notes = forensics._interpret(
            [_key(1, extra="0xFFC3D44F")], {"extra_values": ["0xFFC3D44F"]}, "notepad:1")

        self.assertTrue(any("AutoHotkey" in n for n in notes))

    def test_ctrl_v_is_named_as_a_paste(self):
        rec = _key(1, vk=0x56, vk_name="VK_V", chr="\x16", mods="ctrl")

        self.assertTrue(forensics.character(rec).startswith("ctrl+V (paste)"))

    def test_emails_carry_the_full_reconstruction(self):
        lines = [f"line {n} " + "x" * 80 for n in range(30)]
        finding = {"category": "input", "severity": "critical", "host": "win",
                   "title": "1 injected character 'q' while msrdc:1 had focus",
                   "detail": "d", "where": "input_events", "forensics": lines}
        t = triage.classify(finding, "input")

        text = "\n".join(emails._text_group(t["owner"], [(finding, "input", t, "")]))
        html = email_ui.finding_card(finding, "input", t, show_detail=False)

        self.assertIn(lines[-1], text)
        self.assertIn(lines[-1], html)


class HookScriptTests(unittest.TestCase):
    def setUp(self):
        from jarvis.collectors.host.inputwatch.common import HOOK_PS1
        with open(HOOK_PS1, encoding="utf-8") as fh:
            self.src = fh.read()

    def test_only_injected_events_are_captured_in_full(self):
        body = self.src.split("static IntPtr KbProc", 1)[1].split("static IntPtr MsProc", 1)[0]
        for call in re.finditer(r"Capture\(d, (true|false)\);", body):
            before = body[:call.start()]
            self.assertTrue(before.rstrip().endswith(("WindowInjectedKeys++;",
                                                      "InjectedKeyUps++;")), call.group(0))

    def test_long_bursts_are_redacted_by_default(self):
        self.assertIn("[int]$RedactBurstOver = 6", self.src)


if __name__ == "__main__":
    unittest.main()

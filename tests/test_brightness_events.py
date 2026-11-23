"""Brightness changes are recorded as control events and reported honestly.

The brightness hotkey on a laptop never reaches the keyboard hook (ACPI), and
Windows moves the level itself, so a brightness change must be a low-severity
timeline lead with idle context, never the medium "no key behind it" claim
that the volume rule makes.
"""
import importlib
import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host.inputwatch import analysis, forensics
from jarvis.core.paths import load_win_script
from jarvis.core.store import Store
from jarvis.core.util import now

ingest_mod = importlib.import_module("jarvis.collectors.host.inputwatch.ingest")


class BrightnessEventTests(unittest.TestCase):
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

    def _line(self, **over):
        rec = {"ts": now() - 30, "kind": "control-state", "control": "brightness",
               "from": 100, "to": 60, "display": "DISPLAYLGD07254", "idle_s": 2,
               "keyed": 0, "key_gap_ms": 999999, "fg": "explorer:1234"}
        rec.update(over)
        return rec

    def _titles(self):
        return {f["title"]: f for f in analysis._control_findings(self.store)}

    def test_a_brightness_line_is_stored_with_panel_and_idle_context(self):
        self._drain([self._line()])
        row = self.store.db.execute("SELECT * FROM control_events").fetchone()
        self.assertEqual(row["control"], "brightness")
        self.assertEqual(row["detail"], "DISPLAYLGD07254 100 -> 60  idle 2s")
        self.assertEqual(row["keyed"], 0)
        self.assertEqual(row["fg"], "explorer:1234")

    def test_an_unknown_idle_value_is_left_out_rather_than_invented(self):
        self._drain([self._line(idle_s=-1)])
        row = self.store.db.execute("SELECT detail FROM control_events").fetchone()
        self.assertEqual(row["detail"], "DISPLAYLGD07254 100 -> 60")

    def test_a_brightness_change_is_low_and_never_the_unkeyed_volume_claim(self):
        self._drain([self._line()])
        out = self._titles()
        self.assertEqual(out["display brightness changed"]["severity"], "low")
        self.assertNotIn("the volume changed with no key press behind it", out)
        detail = out["display brightness changed"]["detail"]
        self.assertIn("not attributed", detail)
        self.assertIn("1 while someone was actively using", detail)

    def test_idle_changes_are_counted_separately_from_active_ones(self):
        self._drain([self._line(idle_s=600, ts=now() - 90),
                     self._line(idle_s=1, to=80, ts=now() - 20)])
        detail = self._titles()["display brightness changed"]["detail"]
        self.assertIn("2 change(s)", detail)
        self.assertIn("1 while someone was actively using", detail)

    def test_brightness_does_not_dilute_the_volume_bookkeeping(self):
        self._drain([self._line(),
                     {"ts": now() - 10, "kind": "control-state", "control": "volume",
                      "from": 40, "to": 55, "muted": 0, "was_muted": 0,
                      "keyed": 0, "key_gap_ms": 999999, "fg": "chrome:9"}])
        out = self._titles()
        self.assertEqual(out["the volume changed with no key press behind it"]["severity"],
                         "medium")
        self.assertIn("1 unkeyed change(s)",
                      out["the volume changed with no key press behind it"]["detail"])

    def test_the_forensic_timeline_shows_the_brightness_change(self):
        ts = now() - 30
        self._drain([self._line(ts=ts)])
        lines = forensics._surroundings(self.store, ts)
        self.assertTrue(any("brightness DISPLAYLGD07254 100 -> 60" in line for line in lines))

    def test_hook_script_samples_brightness_off_the_hook_thread(self):
        src = load_win_script("inputhook.ps1")
        # Read through WMI on the host's worker thread; the hook thread must not block.
        sampler = src.split("static void SampleBrightness()", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("WmiMonitorBrightness", src)
        worker = src.split("static void Worker()", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn('Step("brightness", SampleBrightness)', worker)
        self.assertIn('\\"control\\":\\"brightness\\"', sampler)
        # Idle context comes from the system-wide last-input clock.
        self.assertIn("GetLastInputInfo", src)
        self.assertIn('\\"idle_s\\":', sampler)
        # A dead provider stops the sampler instead of polling forever.
        self.assertIn("if (_brightFailures >= 30) return;", sampler)


if __name__ == "__main__":
    unittest.main()

"""Exa threat research 2026-10-29 additions to collectors/process/evasion.py:
the BYOVD ASR rule state and mandatory-profile hive (NTUSER.MAN) persistence.
audit() takes the payload evasion.ps1 would return, so no Windows is needed."""

import re
import unittest

from jarvis.collectors.process import evasion
from jarvis.core.paths import load_win_script

BASE = {"hvciRunning": True, "blocklistValue": 1, "drivers": [], "ads": [], "manHives": [], "manUnreadable": 0}


def run(**over):
    return evasion.audit({**BASE, **over})


def titled(findings, text):
    return [f for f in findings if text in f["title"]]


class AsrRule(unittest.TestCase):
    def test_each_action_maps_to_a_stated_severity(self):
        cases = {1: ("ok", "blocks"), 2: ("low", "only audits"), 6: ("low", "only warns"),
                 0: ("medium", "switched off"), -1: ("low", "not enabled")}
        for action, (sev, words) in cases.items():
            f = titled(run(asrByovd=action), "ASR rule against exploited signed drivers")
            self.assertEqual(len(f), 1, action)
            self.assertEqual(f[0]["severity"], sev, action)
            self.assertIn(words, f[0]["title"], action)

    def test_unreadable_preferences_are_not_observed_never_ok(self):
        out = run(asrByovd=-2)
        self.assertFalse(titled(out, "ASR rule against"))
        vis = titled(out, "ASR rule state not observed")
        self.assertEqual(vis[0]["category"], "visibility")

    def test_missing_key_reads_as_unknown(self):
        data = dict(BASE)
        out = evasion.audit(data)
        self.assertTrue(titled(out, "ASR rule state not observed"))


class MandatoryProfile(unittest.TestCase):
    def test_man_hive_is_high_with_evidence(self):
        out = run(manHives=[{"path": r"C:\Users\bob\NTUSER.MAN", "size": 262144,
                             "written": "2026-10-28T21:00:00Z"}])
        f = titled(out, "mandatory profile hive")
        self.assertEqual(f[0]["severity"], "high")
        self.assertIn("NTUSER.MAN", f[0]["detail"])
        self.assertEqual(f[0]["where"], r"C:\Users\bob\NTUSER.MAN")

    def test_single_object_from_powershell_is_handled(self):
        # ConvertTo-Json collapses a one-element array into an object.
        out = run(manHives={"path": r"C:\Users\a\NTUSER.MAN", "size": 1, "written": "x"})
        self.assertEqual(len(titled(out, "mandatory profile hive")), 1)

    def test_unreadable_profiles_are_said(self):
        out = run(manUnreadable=3)
        f = titled(out, "some user profiles not checked")
        self.assertEqual(f[0]["category"], "visibility")
        self.assertIn("3 profile", f[0]["detail"])

    def test_clean_machine_reports_no_man_hive(self):
        self.assertFalse(titled(run(), "mandatory profile hive"))


class Payload(unittest.TestCase):
    def test_script_collects_both_fields_read_only(self):
        ps = load_win_script("evasion.ps1")
        self.assertIn("56a863a9-875e-4185-98a7-b882c64b5ce5", ps)
        self.assertIn("NTUSER.MAN", ps)
        self.assertIn("$o.asrByovd = -2", ps)          # unknown until read
        # Read-only: the new code may read Defender preferences, never change them.
        self.assertFalse(re.search(r"Set-MpPreference|Add-MpPreference|Remove-Item|Set-ItemProperty", ps))


if __name__ == "__main__":
    unittest.main()

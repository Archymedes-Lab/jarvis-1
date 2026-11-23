"""Autostart findings name the evidence in full (live campaign 2026-11-11, cases 12 and 13).

A Winlogon value cut at 100 characters lost the program that was added, and a COM
library path cut at 80 lost its file name: the finding was raised but did not say
what to look at.
"""
import unittest
from unittest import mock

from jarvis.collectors.persistence import asep

STAGE = "C:\\Users\\RUNNERADMIN\\AppData\\Local\\Temp\\some-long-staging-folder-name-0123456789\\"


def run(data):
    base = {"winlogon": {}, "comHijack": [], "lsa": {}, "procs": []}
    base.update(data)
    with mock.patch.object(asep, "ps_json", return_value=base):
        return asep.audit()


class Winlogon(unittest.TestCase):
    def test_an_extended_userinit_names_the_added_program(self):
        val = "C:\\Windows\\system32\\userinit.exe," + STAGE + "implant-13.exe,"
        f = [f for f in run({"winlogon": {"userinit": val}}) if f["title"] == "Winlogon userinit modified"][0]
        self.assertEqual(f["severity"], "critical")
        self.assertIn(STAGE + "implant-13.exe", f["detail"])
        self.assertTrue(f["detail"].startswith("userinit runs " + STAGE))

    def test_a_replaced_value_is_shown_and_the_stock_value_raises_nothing(self):
        f = [f for f in run({"winlogon": {"shell": STAGE + "shell.exe"}}) if "shell modified" in f["title"]][0]
        self.assertIn(STAGE + "shell.exe", f["detail"])
        self.assertFalse([f for f in run({"winlogon": {"userinit": "C:\\Windows\\system32\\userinit.exe,"}})
                          if "modified" in f["title"]])


class Com(unittest.TestCase):
    def test_the_whole_library_path_is_named(self):
        path = STAGE + "hijack-12.dll"
        f = [f for f in run({"comHijack": [{"clsid": "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}", "dll": path,
                                            "path": path, "exists": False}]})
             if f["title"] == "suspicious per-user COM registration"][0]
        self.assertEqual(f["severity"], "critical")
        self.assertIn("hijack-12.dll", f["detail"])


if __name__ == "__main__":
    unittest.main()

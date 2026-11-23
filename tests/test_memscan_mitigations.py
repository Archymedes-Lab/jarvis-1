import unittest
from unittest import mock

from jarvis.collectors.process import memscan


class SystemMitigationTests(unittest.TestCase):
    def titles(self, system):
        data = {"memory": {}, "system": system, "mitigations": []}
        with mock.patch.object(memscan, "_run", return_value=(data, "")):
            return sorted(f["title"] for f in memscan.audit()
                          if f["category"] == "mitigations")

    def test_unset_cfg_is_the_windows_default_on_but_unset_aslr_and_cet_are_off(self):
        self.assertEqual(self.titles({"cfg": "NOTSET", "aslr": "NOTSET", "cet": "NOTSET"}),
                         ["system-wide CET / hardware shadow stack is not enforced",
                          "system-wide mandatory ASLR (ForceRelocateImages) is not enforced"])

    def test_explicit_off_is_reported_for_every_mitigation(self):
        self.assertEqual(len(self.titles({"cfg": "OFF", "aslr": "OFF", "cet": "OFF"})), 3)

    def test_all_on_reports_nothing(self):
        self.assertEqual(self.titles({"cfg": "ON", "aslr": "ON", "cet": "ON"}), [])


class EmbeddedRuntimeTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        memscan._EMBEDDED.clear()

    def exe(self, body):
        import os
        path = os.path.join(self.tmp.name, "app.exe")
        with open(path, "wb") as fh:
            fh.write(body)
        return path

    def verdict(self, body, signed):
        path = self.exe(body)
        with mock.patch.object(memscan, "_wsl_path", return_value=path), \
             mock.patch.object(memscan, "_authenticode_valid", return_value=signed):
            return memscan._embedded_runtime("C:\\x\\app.exe")

    def test_markers_found_across_chunk_boundaries(self):
        path = self.exe(b"x" * 10 + b"singlefilehost" + b"y" * 40 + b"System.Private.CoreLib"
                        + b"z" * 7 + b"CLRJitAttachState")
        self.assertTrue(memscan._has_markers(path, chunk=16))
        self.assertFalse(memscan._has_markers(self.exe(b"singlefilehost only"), chunk=16))

    def test_signed_single_file_app_is_explained_unsigned_is_not(self):
        body = b"singlefilehost System.Private.CoreLib CLRJitAttachState"
        self.assertEqual(self.verdict(body, True), memscan.SINGLE_FILE_RUNTIME)
        memscan._EMBEDDED.clear()
        self.assertEqual(self.verdict(body, False), "")
        memscan._EMBEDDED.clear()
        self.assertEqual(self.verdict(b"plain", True), "")

    def test_non_windows_path_is_ignored(self):
        self.assertEqual(memscan._embedded_runtime(""), "")
        self.assertEqual(memscan._embedded_runtime("/usr/bin/x"), "")

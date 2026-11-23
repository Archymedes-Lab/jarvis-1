import time
import unittest
from unittest import mock

from jarvis.intel import hunt


def _row(norm):
    return {'norm': norm, 'context': 'ctx', 'source_url': 'u'}


class CheckPathsTest(unittest.TestCase):
    def run_paths(self, rows, signed):
        with mock.patch.object(hunt, '_active', return_value=rows), \
             mock.patch('os.path.lexists', return_value=True), \
             mock.patch('os.path.isdir', return_value=False), \
             mock.patch('os.path.isfile', return_value=True), \
             mock.patch.object(hunt, '_microsoft_signed',
                               side_effect=lambda p: set(p) & signed) as sig:
            return hunt.check_paths(None), sig

    def test_signed_stock_binary_is_not_reported(self):
        out, _ = self.run_paths([_row('C:\\\\Windows\\\\System32\\\\rundll32.exe'),
                                 _row('C:\\Windows\\explorer.exe')],
                                {'C:\\Windows\\System32\\rundll32.exe',
                                 'C:\\Windows\\explorer.exe'})
        self.assertEqual(out, [])

    def test_unsigned_windows_drop_is_reported(self):
        out, _ = self.run_paths([_row('C:\\Windows\\cloudflared.exe')], set())
        self.assertEqual(len(out), 1)

    def test_signed_binary_in_writable_dir_is_still_reported(self):
        out, sig = self.run_paths([_row('C:\\Windows\\Temp\\dbghelp.dll')],
                                  {'C:\\Windows\\Temp\\dbghelp.dll'})
        self.assertEqual(len(out), 1)
        self.assertEqual(sig.call_args[0][0], set())


class CheckProcessesTest(unittest.TestCase):
    def setUp(self):
        self.seen = time.time()          # a process that ran just now

    def rows(self, *procs):
        store = mock.MagicMock()
        store.db.execute.return_value = [
            {"name": n, "exe": e, "host": h, "cmdline": "", "last_seen": self.seen}
            for n, e, h in procs]
        return store

    def run_check(self, store, signed=()):
        hit = {"norm": "onedrivesetup.exe", "context": "c", "source_url": "u"}
        with mock.patch.object(hunt, "_active", return_value=[hit]), \
             mock.patch.object(hunt, "_microsoft_signed", side_effect=lambda p: set(p) & set(signed)):
            return hunt.check_processes(store)

    def test_microsoft_signed_binary_is_not_reported(self):
        exe = r"C:\Users\me\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"
        self.assertEqual(self.run_check(self.rows(("OneDriveSetup.exe", exe, "win")), signed={exe}), [])

    def test_unverifiable_binary_is_still_high(self):
        exe = r"C:\Users\me\AppData\Local\Temp\OneDriveSetup.exe"
        out = self.run_check(self.rows(("OneDriveSetup.exe", exe, "win")))
        self.assertEqual([f["severity"] for f in out], ["high"])

    def test_writeup_name_in_the_real_install_location_is_medium(self):
        # Measured: Microsoft's self-deleting OneDrive updater, named on a Splunk
        # detection page; gone before its signature could be read.
        exe = r"C:\Users\me\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"
        out = self.run_check(self.rows(("OneDriveSetup.exe", exe, "win")))
        self.assertEqual([f["severity"] for f in out], ["medium"])

    def test_a_match_last_seen_days_ago_is_history(self):
        exe = r"C:\Users\me\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"
        self.seen = time.time() - 5 * 86400
        out = self.run_check(self.rows(("OneDriveSetup.exe", exe, "win")))
        self.assertEqual([f["severity"] for f in out], ["low"])
        dropped = r"C:\Users\me\AppData\Local\Temp\OneDriveSetup.exe"
        out = self.run_check(self.rows(("OneDriveSetup.exe", dropped, "win")))
        self.assertEqual([f["severity"] for f in out], ["high"])   # dropped copies never age

    def test_name_without_a_path_is_low(self):
        out = self.run_check(self.rows(("OneDriveSetup.exe", "", "win")))
        self.assertEqual([f["severity"] for f in out], ["low"])


if __name__ == '__main__':
    unittest.main()

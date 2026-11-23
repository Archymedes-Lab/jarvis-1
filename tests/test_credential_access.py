import unittest

from jarvis.collectors.host.intrusion import credentials as c
from jarvis.collectors.host.intrusion.run import PS_INTRUSION

STORE = r"C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Login Data"


def proc(name, cmd, exe=r"C:\Windows\System32\esentutl.exe", pid=4242):
    return {"name": name, "cmd": cmd, "exe": exe, "pid": pid}


class CredentialAccessTests(unittest.TestCase):
    def run_check(self, readers, ok=True):
        return c.credential_findings({"credReadersOk": ok, "credReaders": readers,
                                      "credAccess": [{"path": STORE}]})

    def test_copying_the_password_store_is_high(self):
        out = self.run_check([proc("esentutl.exe", f'esentutl /y "{STORE}" /d C:\\Temp\\x')])
        self.assertEqual([(f["severity"], f["title"]) for f in out], [("high", c.TITLE)])
        self.assertIn("Login Data", out[0]["detail"])
        self.assertEqual(out[0]["where"], r"C:\Windows\System32\esentutl.exe")

    def test_the_browser_itself_is_not_a_thief(self):
        out = self.run_check([proc("chrome.exe", f'chrome.exe --type=utility "{STORE}"')])
        self.assertEqual(out[0]["severity"], "ok")

    def test_the_collector_is_not_flagged_for_its_own_command_line(self):
        # The payload returns at most 400 characters of each command line, and
        # powershell.exe -Command puts the script right after the flags.
        own = ("powershell.exe -NoProfile -NonInteractive -Command " + PS_INTRUSION)[:400]
        out = self.run_check([proc("powershell.exe", own + " " + STORE)])
        self.assertEqual(out[0]["severity"], "ok")
        self.assertIn(c.PAYLOAD_MARKER, PS_INTRUSION)

    def test_a_word_inside_a_longer_name_is_not_a_store(self):
        out = self.run_check([proc("app.exe", r"app.exe C:\data\CookiesPolicy.txt --LocalStateless")])
        self.assertEqual(out[0]["severity"], "ok")

    def test_firefox_and_cookie_databases_are_stores_too(self):
        out = self.run_check([proc("python.exe", r"python steal.py C:\p\Profiles\x\logins.json C:\p\cookies.sqlite")])
        self.assertIn("cookies.sqlite, logins.json", out[0]["detail"])

    def test_an_unreadable_process_list_is_not_reported_clean(self):
        out = self.run_check([], ok=False)
        self.assertEqual(out[0]["severity"], "low")
        self.assertIn("unavailable", out[0]["title"])


class StagingDedupeTests(unittest.TestCase):
    def test_temp_searched_twice_reports_a_file_once(self):
        from unittest import mock

        from jarvis.collectors.host.intrusion import run
        item = {"path": r"C:\Users\me\AppData\Local\Temp\x.tmp.js", "sig": "NotSigned",
                "written": "2026-09-02T02:48:42", "sha256": "ab" * 32}
        data = {"recentExe": [item, dict(item, path=item["path"].upper())], "credReadersOk": True}
        with mock.patch.object(run, "ps_json", return_value=data):
            out = run.audit()
        staged = [f for f in out if f["title"] == "recently written unsigned executable"]
        self.assertEqual(len(staged), 1)


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch

from jarvis.collectors.host import posture
from jarvis.collectors.host.posture import run as posture_run


def titles(consolehost):
    data = {"consolehost": consolehost, "hotfix": [{"id": "KB1", "on": "2026-09-01"}]}
    with patch.object(posture_run, "ps_json", return_value=data), \
         patch.object(posture_run.broker, "result", return_value=(None, "not in tests")):
        return [f["title"] for f in posture.audit()]


class ConsoleHostTests(unittest.TestCase):
    FLASH = "Background monitors can flash terminal windows"

    def test_let_windows_decide_is_flagged(self):
        self.assertIn(self.FLASH, titles({"console": "", "terminal": ""}))

    def test_conhost_is_clean_case_insensitively(self):
        self.assertNotIn(self.FLASH, titles({"console": posture.CONHOST.lower(), "terminal": posture.CONHOST}))

    def test_unread_setting_is_not_guessed(self):
        self.assertNotIn(self.FLASH, titles(None))


if __name__ == "__main__":
    unittest.main()

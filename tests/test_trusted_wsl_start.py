"""The installer's 'WSL jarvis 24x7' task is trusted only by its exact definition."""
import unittest

from jarvis.collectors.persistence.trusted_tasks import verified_maintenance_task

DATA = {"currentUser": "DESKTOP\\chris"}


def task(**over):
    t = {"name": "WSL jarvis 24x7", "user": "DESKTOP\\chris", "runLevel": "Limited",
         "logonType": "Interactive",
         "actions": [{"execute": "wsl.exe", "arguments": "-d Ubuntu --exec /bin/true"}]}
    t.update(over)
    return t


class WslStartTaskTests(unittest.TestCase):
    def test_installer_definition_verifies(self):
        self.assertTrue(verified_maintenance_task(task(), DATA)[0])
        full = task(actions=[{"execute": "C:\\Windows\\System32\\wsl.exe",
                              "arguments": "-d Ubuntu --exec /bin/true"}])
        self.assertTrue(verified_maintenance_task(full, DATA)[0])

    def test_any_deviation_stays_untrusted(self):
        bad = [
            task(actions=[{"execute": "C:\\Users\\chris\\AppData\\wsl.exe",
                           "arguments": "-d Ubuntu --exec /bin/true"}]),
            task(actions=[{"execute": "wsl.exe", "arguments": "-d Ubuntu --exec /tmp/x"}]),
            task(actions=[{"execute": "wsl.exe", "arguments": "-d Ubuntu --exec /bin/true; curl x"}]),
            task(actions=[{"execute": "powershell.exe", "arguments": "-d Ubuntu --exec /bin/true"}]),
            task(actions=[{"execute": "wsl.exe", "arguments": "-d Ubuntu --exec /bin/true"},
                          {"execute": "cmd.exe", "arguments": "/c evil"}]),
            task(runLevel="Highest"),
            task(user="DESKTOP\\someoneelse"),
            task(logonType="Password"),
        ]
        for t in bad:
            self.assertFalse(verified_maintenance_task(t, DATA)[0], t)


if __name__ == "__main__":
    unittest.main()

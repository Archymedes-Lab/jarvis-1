"""The daemon keeps systemd's notify socket to itself (2026-10-29: collector
children inherited NOTIFY_SOCKET and pinged systemd, which NotifyAccess=main
rejected and logged on JARVIS and Argus)."""

import os
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from jarvis.service import sdnotify


class Capture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "notify")
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.server.bind(self.path)
        self.server.settimeout(2)
        self.env = mock.patch.dict(os.environ, {"NOTIFY_SOCKET": self.path, "WATCHDOG_USEC": "900000000"})
        self.env.start()
        sdnotify._CAPTURED.clear()
        sdnotify._SOCK = None

    def tearDown(self):
        self.env.stop()
        sdnotify._CAPTURED.clear()
        sdnotify._SOCK = None
        self.server.close()

    def test_children_do_not_inherit_but_the_daemon_still_notifies(self):
        sdnotify.capture()
        self.assertNotIn("NOTIFY_SOCKET", os.environ)
        self.assertNotIn("WATCHDOG_USEC", os.environ)
        child = subprocess.run([sys.executable, "-c", "import os; print(os.environ.get('NOTIFY_SOCKET'))"],
                               capture_output=True, text=True)
        self.assertEqual(child.stdout.strip(), "None")
        self.assertTrue(sdnotify.available())
        self.assertEqual(sdnotify.watchdog_usec(), 900000000)
        sdnotify.ready()
        self.assertEqual(self.server.recv(64), b"READY=1")

    def test_without_capture_behaviour_is_unchanged(self):
        self.assertTrue(sdnotify.available())
        sdnotify.watchdog()
        self.assertEqual(self.server.recv(64), b"WATCHDOG=1")


if __name__ == "__main__":
    unittest.main()

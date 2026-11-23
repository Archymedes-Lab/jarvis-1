"""Egress is approved once per program, never learned silently."""

import os
import tempfile
import unittest

from jarvis.collectors.telemetry import sysmon_linux
from jarvis.core import egress
from jarvis.core.store import Store
from jarvis.response import questions


def conn(image="/opt/tool/cloudflared", ip="93.184.216.34"):
    return {"id": 3, "Image": image, "DestinationIp": ip, "DestinationPort": "443"}


class EgressBaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)

    def egress(self):
        return [(f["severity"], f["title"]) for f in sysmon_linux._rules([conn()], store=self.store)
                if f["title"].startswith(egress.TITLE)]

    def test_unknown_program_is_asked_about(self):
        self.assertEqual(self.egress(), [("medium", "outbound connections from cloudflared")])
        prompt, yes, no = questions._phrase({"title": "outbound connections from cloudflared",
                                             "detail": "1 public destination(s): 93.184.216.34 — x"}, "sysmon_linux")
        self.assertIn("Should cloudflared reach the internet?", prompt)

    def test_yes_silences_and_no_escalates(self):
        egress.decide(self.store, "wsl", "cloudflared", egress.EXPECTED)
        self.assertEqual(self.egress(), [])
        egress.decide(self.store, "wsl", "cloudflared", egress.UNEXPECTED)
        self.assertEqual(self.egress(), [("high", "outbound connections from cloudflared")])

    def test_program_name_is_parsed_only_from_egress_titles(self):
        self.assertEqual(egress.program_of("outbound connections from node"), "node")
        self.assertEqual(egress.program_of("scheduled task"), "")

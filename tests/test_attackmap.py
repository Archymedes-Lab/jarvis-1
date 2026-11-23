"""Coverage is proven by the detectors firing, and a silent break is loud."""

import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.service import attackmap


class ProbeTests(unittest.TestCase):
    def test_every_probe_fires_in_the_real_detector(self):
        for tid, (probe, _jobs) in attackmap.PROBES.items():
            with self.subTest(tid=tid):
                fired, what = probe()
                self.assertTrue(fired, f"{tid}: {what}")
        for label, probe in attackmap.PRECISION.items():
            with self.subTest(guard=label):
                self.assertTrue(probe()[0])


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)
        self.store.db.executemany(
            "INSERT INTO attack_techniques(tid,name,tactics,platforms,updated) VALUES(?,?,?,?,0)",
            [("T1055", "Process Injection", "stealth,privilege-escalation", "Windows,Linux"),
             ("T1053", "Scheduled Task/Job", "persistence", "Windows"),
             ("T1999", "Nothing Looks", "impact", "Linux"),
             ("T1055.001", "sub", "stealth", "Windows"),
             ("T1583", "Acquire Infrastructure", "resource-development", "PRE")])

    def levels(self, live, fired=True):
        probes = {"T1055": (lambda: (fired, "probe"), ("sysmon",))}
        with mock.patch.object(attackmap, "PROBES", probes), \
             mock.patch.object(attackmap, "_live", return_value=live):
            out, data = attackmap.measure(self.store)
        return {r["tid"]: r["level"] for r in data["techniques"]}, out, data

    def test_proven_and_live_is_validated_mapped_is_claimed_rest_blind(self):
        levels, _out, data = self.levels(live=["sysmon"])
        self.assertEqual(levels, {"T1055": "validated", "T1053": "claimed", "T1999": "blind"})
        self.assertEqual(data["tactics"]["stealth"]["validated"], 1)
        self.assertNotIn("resource-development", data["tactics"])

    def test_a_proven_rule_behind_a_dead_collector_is_only_claimed(self):
        self.assertEqual(self.levels(live=[])[0]["T1055"], "claimed")

    def test_a_probe_that_stops_firing_is_a_high_regression(self):
        levels, out, _data = self.levels(live=["sysmon"], fired=False)
        self.assertEqual(levels["T1055"], "regressed")
        self.assertIn(("high", "detection regressed: T1055"), [(f["severity"], f["title"]) for f in out])

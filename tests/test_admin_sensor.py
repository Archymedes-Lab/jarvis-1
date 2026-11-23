"""Without the administrator sensor, affected jobs say so and coverage is never full."""

import unittest
from unittest import mock

from jarvis.core import mechanisms
from jarvis.platform import admin_sensor, broker

LABELS = {j: j.title() for j in mechanisms.admin_sensor_jobs()} | {"scan": "Processes"}


class ElevatedHonestyTest(unittest.TestCase):
    def test_every_affected_job_is_named_with_the_one_reason(self):
        out = admin_sensor.merge_blind([], LABELS, is_absent=True)
        self.assertEqual({e["job"] for e in out}, set(mechanisms.admin_sensor_jobs()))
        self.assertTrue(all(e["reason"] == "Needs administrator sensor" for e in out))
        self.assertNotIn("scan", {e["job"] for e in out}, "jobs that need no sensor are not accused")

    def test_a_job_already_stale_or_failing_gets_the_real_reason_and_keeps_its_state(self):
        blind = [{"job": "native", "label": "Native", "freshness": "FRESH", "error": True},
                 {"job": "scan", "label": "Processes", "freshness": "STALE", "error": False}]
        admin_sensor.merge_blind(blind, LABELS, is_absent=True)
        native = next(b for b in blind if b["job"] == "native")
        self.assertEqual(native["reason"], "Needs administrator sensor")
        self.assertTrue(native["error"] and native["freshness"] == "FRESH")
        self.assertEqual([b["job"] for b in blind].count("native"), 1, "no duplicate entry")
        scan = next(b for b in blind if b["job"] == "scan")
        self.assertNotIn("reason", scan, "a stale job that needs no sensor is not accused")

    def test_nothing_is_reported_once_the_sensor_is_installed(self):
        self.assertEqual(admin_sensor.merge_blind([], LABELS, is_absent=False), [])

    def test_unavailable_and_limited_are_distinguished(self):
        levels = {e["job"]: e["level"] for e in admin_sensor.merge_blind([], LABELS, is_absent=True)}
        self.assertEqual(levels["fwaudit"], "unavailable")
        self.assertEqual(levels["memscan"], "limited")

    def test_the_broker_gives_the_same_reason_when_it_is_missing(self):
        with mock.patch.object(broker, "installed", return_value=False):
            data, why = broker.result(next(iter(broker.SCRIPTS)))
        self.assertIsNone(data)
        self.assertTrue(why.startswith("Needs administrator sensor"), why)

    def test_linux_is_never_accused(self):
        with mock.patch("sys.platform", "linux"):
            self.assertFalse(admin_sensor.absent())


if __name__ == "__main__":
    unittest.main()

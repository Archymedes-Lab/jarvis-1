"""The eight-stage native telemetry chain: where delivery stands, named.

The directive's Monitoring requirement: installed, running, producing,
arriving, ingested, gaps, integrity, fresh must be independently observable,
and a broken stage must say where — "sensor works" is not one state.
"""
import json
import unittest

from jarvis.core import telemetry


def report(**over):
    base = {
        "spool": "/spool", "installed": True,
        "health": {"status": "complete", "age": 4.0},
        "channels": [{"directory": "0" * 16, "batches": 3, "events": 120,
                      "gaps": [], "error": None, "backlog": 0,
                      "last_sequence": 1180}],
        "batches": 3, "events": 120,
    }
    base.update(over)
    return base


class StageTests(unittest.TestCase):
    def setUp(self):
        self.now = 2_000_000_000

    def collect(self, rep, verify_at=None, limit=180):
        return telemetry.collect(rep, verify_at=verify_at,
                                 freshness_limit=limit, now=self.now)

    def test_every_stage_ok_on_a_healthy_chain(self):
        chain = self.collect(report(), verify_at=self.now - 60)
        self.assertEqual({s for s in chain["stages"]}, set(telemetry.STAGES))
        for name, st in chain["stages"].items():
            self.assertEqual(st["state"], "ok", f"{name}: {st['detail']}")

    def test_dead_sensor_breaks_running_and_leaves_producing_unknown(self):
        chain = self.collect(report(health=None))
        self.assertEqual(chain["stages"]["running"]["state"], "down")
        # No health file: whether it reads channels is unknown, not down.
        self.assertEqual(chain["stages"]["producing"]["state"], "unknown")
        # installed is about the spool, not the service: still ok
        self.assertEqual(chain["stages"]["installed"]["state"], "ok")

    def test_sensor_reporting_failure_is_producing_down(self):
        chain = self.collect(report(health={"status": "unavailable",
                                            "reason": "channel read failed",
                                            "age": 5.0}))
        self.assertEqual(chain["stages"]["running"]["state"], "ok")
        self.assertEqual(chain["stages"]["producing"]["state"], "down")

    def test_stuck_batches_break_arriving_and_ingested(self):
        stuck = report(batches=0, events=0,
                       channels=[{"directory": "0" * 16, "batches": 0,
                                  "events": 0, "gaps": [], "error": None,
                                  "backlog": 57, "last_sequence": 0}])
        chain = self.collect(stuck)
        self.assertEqual(chain["stages"]["arriving"]["state"], "down")
        self.assertEqual(chain["stages"]["ingested"]["state"], "down")
        self.assertEqual(chain["backlog"], 57)

    def test_a_gap_degrades_but_does_not_blind(self):
        rep = report(channels=[{"directory": "0" * 16, "batches": 1,
                                "events": 40,
                                "gaps": ["record IDs reset within batch 1130: "
                                         "the event log was cleared or wrapped"],
                                "error": None, "backlog": 0,
                                "last_sequence": 1130}])
        chain = self.collect(rep)
        self.assertEqual(chain["stages"]["gaps"]["state"], "degraded")
        self.assertIn("cleared or wrapped", chain["stages"]["gaps"]["detail"])
        self.assertEqual(chain["gaps"], 1)
        # Delivery itself still worked
        self.assertEqual(chain["stages"]["ingested"]["state"], "ok")

    def test_unverified_chain_is_degraded_not_ok(self):
        chain = self.collect(report(), verify_at=None)
        self.assertEqual(chain["stages"]["integrity"]["state"], "degraded")

    def test_quarantine_is_counted(self):
        rep = report(channels=[{"directory": "0" * 16, "batches": 1,
                                "events": 10, "gaps": ["g"], "error": None,
                                "backlog": 0, "last_sequence": 5,
                                "quarantined": 1}])
        chain = self.collect(rep)
        self.assertEqual(chain["quarantined"], 1)

    def test_parse_marks_a_silent_job_not_current(self):
        chain = self.collect(report())
        raw = json.dumps(chain)
        fresh = telemetry.parse(raw, now=self.now + 10)
        self.assertTrue(fresh["current"])
        silent = telemetry.parse(raw, now=self.now + telemetry.STALE + 1)
        self.assertFalse(silent["current"])
        self.assertIsNone(telemetry.parse("not json"))
        self.assertIsNone(telemetry.parse(json.dumps({"no": "stages"})))


if __name__ == "__main__":
    unittest.main()

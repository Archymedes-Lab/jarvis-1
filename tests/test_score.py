import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.response import alert
from jarvis.response.reporting import cadence, score
from jarvis.response.reporting import notifications as n
from jarvis.service.schedule import JOBS

NOW = 2_000_000_000
CONF = {"resend_api_key": "test", "alert_to": "owner@example.test",
        "alert_from": "jarvis@example.test", "alert_digest_interval": 60}


def snaps(overrides=None, error_jobs=(), stale_jobs=()):
    """Every scored job current and clean, with per-job findings overridden."""
    out = {}
    for job, (interval, _label) in JOBS.items():
        ts = NOW - (interval * 3 + 600 if job in stale_jobs else 1)
        out[job] = {"ts": ts, "findings": [], "error": "boom" if job in error_jobs else ""}
    for job, findings in (overrides or {}).items():
        out[job]["findings"] = findings
    return out


def f(sev, cat="thing", title="t"):
    return {"category": cat, "severity": sev, "title": title, "where": "", "host": "win"}


class ScoreTests(unittest.TestCase):
    def area(self, result, name):
        return next(a for a in result["areas"] if a["name"] == name)

    def test_every_scheduled_job_is_scored_or_deliberately_unscored(self):
        mapped = set(score.AREA_OF) | set(score.UNSCORED)
        self.assertEqual(sorted(set(JOBS) - mapped), [], "jobs with no area")
        self.assertEqual(sorted(mapped - set(JOBS)), [], "areas name jobs that do not exist")

    def test_clean_and_fully_observed_is_100(self):
        r = score.compute(snaps(), JOBS, NOW)
        self.assertEqual((r["score"], r["grade"], r["coverage"]), (100, "secure", 100))

    def test_a_critical_lowers_its_area_and_the_total(self):
        r = score.compute(snaps({"secrets": [f("critical")]}), JOBS, NOW)
        self.assertEqual(self.area(r, "Data & privacy")["score"], 44)
        self.assertLess(r["score"], 100)
        self.assertEqual(r["next_steps"][0]["job"], "secrets")

    def test_low_findings_are_inventory_not_risk(self):
        r = score.compute(snaps({"control": [f("low")] * 50}), JOBS, NOW)
        self.assertEqual(r["score"], 100)

    def test_per_process_churn_is_not_scored(self):
        r = score.compute(snaps({"scan": [f("critical", cat="process")]}), JOBS, NOW)
        self.assertEqual(r["score"], 100)

    def test_one_noisy_collector_is_capped(self):
        noisy = score.compute(snaps({"sysmon_linux": [f("medium")] * 500}), JOBS, NOW)
        five = score.compute(snaps({"sysmon_linux": [f("medium")] * 5}), JOBS, NOW)
        self.assertEqual(noisy["score"], five["score"])

    def test_blindness_is_not_safety(self):
        blind = score.compute(snaps(error_jobs=("secrets", "spy", "pixel", "sniffing", "geo", "privacy")), JOBS, NOW)
        self.assertIsNone(self.area(blind, "Data & privacy")["score"])
        self.assertLess(blind["coverage"], 100)
        self.assertLess(blind["score"], 100)

    def test_stale_collectors_count_as_unobserved(self):
        r = score.compute(snaps(stale_jobs=("posture",)), JOBS, NOW)
        self.assertEqual(self.area(r, "OS hardening")["blind"], [{"job": "posture", "state": "stale"}])
        self.assertLess(r["score"], 100)

    def test_text_bar(self):
        self.assertEqual(score.bar(0, 10), "[----------]")
        self.assertEqual(score.bar(55, 10), "[######----]")
        self.assertEqual(score.bar(100, 10), "[##########]")


class ScoreHistoryAndEmailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        for job, s in snaps({"secrets": [f("critical", title="API key in plaintext")]}).items():
            self.store.save_snapshot(job, s["findings"], 0.1, s["error"])
        self.sender = patch.object(alert, "send_email", return_value="")
        self.send = self.sender.start()

    def tearDown(self):
        self.sender.stop()
        self.store.close()
        self.tmp.cleanup()

    def test_change_is_only_reported_against_a_point_near_24h_ago(self):
        self.store.set_meta(score.HISTORY_META, "[[%d, 50], [%d, 70]]" % (NOW - 3600, NOW))
        self.assertIsNone(score.change_since(self.store, 86400, NOW))
        self.store.set_meta(score.HISTORY_META, "[[%d, 50], [%d, 70]]" % (NOW - 86400, NOW))
        self.assertEqual(score.change_since(self.store, 86400, NOW), 20)

    def test_digest_emails_carry_the_bar(self):
        with patch("time.time", return_value=NOW):
            score.record(self.store, JOBS)
            n.dispatch(self.store, CONF, "intrusion", [f("critical", "intrusion", "new staging")])
        body = self.send.call_args[0][2]
        self.assertIn("SECURITY HEALTH [", body)
        self.assertIn("Data & privacy", body)

    def test_daily_health_email_when_the_full_advisory_is_off(self):
        conf = {**CONF, "report_daily_enabled": False, "report_hour": 0}
        with patch.object(alert, "load_conf", return_value=conf), \
             patch("time.time", return_value=NOW):
            cadence.run(self.store, JOBS)
            cadence.run(self.store, JOBS)   # same day: not sent twice
        subjects = [c[0][1] for c in self.send.call_args_list]
        health = [s for s in subjects if "security health" in s]
        self.assertEqual(len(health), 1)
        self.assertIn("%", health[0])
        html = next(c.kwargs["html"] for c in self.send.call_args_list
                    if "security health" in c[0][1])
        self.assertIn("Security health", html)

    def test_daily_health_email_can_be_turned_off(self):
        conf = {**CONF, "report_daily_enabled": False, "report_hour": 0,
                "health_email_enabled": False}
        with patch.object(alert, "load_conf", return_value=conf), \
             patch("time.time", return_value=NOW):
            cadence.run(self.store, JOBS)
        self.assertFalse(any("security health" in c[0][1] for c in self.send.call_args_list))

    def test_dashboard_state_includes_the_score(self):
        from types import SimpleNamespace

        from jarvis.web import server
        path = self.store.path
        state = server.build_state(path, SimpleNamespace(current=None, next_run={}))
        self.assertIn("score", state["security"])
        self.assertEqual(len(state["security"]["areas"]), len(score.AREAS))


if __name__ == "__main__":
    unittest.main()

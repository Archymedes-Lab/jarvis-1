"""A coverage verdict contradicted by newer evidence must not keep charging.

Coverage's snapshot keeps each verdict until its own next run; under load a
mid catch-up "stale" verdict outlived the recovery by 20+ minutes. Genuine
blindness must still count, because the scorer judges freshness itself.
"""
import unittest

from jarvis.response.reporting import score

JOBS = {"coverage": (600, "coverage"), "geo": (900, "geo"), "sysmon": (600, "sysmon")}
NOW = 100_000


def verdict(target, title="is stale"):
    return {"category": "collectors", "severity": "high",
            "title": f"collector '{target}' {title}", "detail": "", "about_collector": target}


def snaps(geo_ts, geo_error="", cov_ts=NOW - 600, sysmon_ts=NOW - 30):
    return {
        "coverage": {"ts": cov_ts, "error": "", "findings": [verdict("geo")]},
        "geo": {"ts": geo_ts, "error": geo_error, "findings": []},
        "sysmon": {"ts": sysmon_ts, "error": "", "findings": []},
    }


class SupersededVerdictTests(unittest.TestCase):
    def test_newer_clean_result_supersedes_the_verdict(self):
        s = snaps(geo_ts=NOW - 60)
        self.assertTrue(score._superseded(s["coverage"]["findings"][0],
                                          s["coverage"]["ts"], s, JOBS, NOW))

    def test_collector_still_stale_keeps_the_verdict_and_stays_blind(self):
        s = snaps(geo_ts=NOW - 5000)
        f = s["coverage"]["findings"][0]
        self.assertFalse(score._superseded(f, s["coverage"]["ts"], s, JOBS, NOW))

    def test_newer_but_failing_result_keeps_the_verdict(self):
        s = snaps(geo_ts=NOW - 60, geo_error="PowerShell failed or timed out")
        self.assertFalse(score._superseded(s["coverage"]["findings"][0],
                                           s["coverage"]["ts"], s, JOBS, NOW))

    def test_result_older_than_the_verdict_keeps_it(self):
        s = snaps(geo_ts=NOW - 700)          # in window, but before coverage ran
        self.assertFalse(score._superseded(s["coverage"]["findings"][0],
                                           s["coverage"]["ts"], s, JOBS, NOW))

    def test_untagged_or_unknown_findings_are_never_dropped(self):
        s = snaps(geo_ts=NOW - 60)
        for f in ({"severity": "high", "title": "x"}, verdict("not_a_job")):
            self.assertFalse(score._superseded(f, s["coverage"]["ts"], s, JOBS, NOW))

    def test_compute_stops_charging_a_recovered_collector(self):
        stale_view = score.compute(snaps(geo_ts=NOW - 5000), JOBS, NOW)
        recovered = score.compute(snaps(geo_ts=NOW - 60), JOBS, NOW)
        area = {a["name"]: a for a in recovered["areas"]}["Monitoring"]
        self.assertEqual(area["open"].get("high", 0), 0)
        self.assertGreater(recovered["score"], stale_view["score"])
        # the genuinely stale case is still blind, not just penalised
        self.assertTrue(any(b["job"] == "geo" for a in stale_view["areas"] for b in a["blind"]))


if __name__ == "__main__":
    unittest.main()

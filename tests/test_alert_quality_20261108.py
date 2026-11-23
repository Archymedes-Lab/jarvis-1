"""Alert quality, QC-ARGUS-1-2026-10-27 blocker 3 (docs/security/ALERT-QUALITY-2026-11-08.md).

Invariants:
  * one underlying problem is one finding: a ledger note about a finding its
    own job still lists is low and names it (`restates`); the original keeps
    its severity and carries the age / recurrence (`ledger` field);
  * visibility is never lost: a ledger row whose original is not listed (job
    failing, title drifted, no snapshots given) keeps its full severity and is
    flagged `orphan`; a stale row stays medium;
  * a blocklist hit alone is never critical; critical needs an independent
    second signal; a lone hit stays visible (high / medium);
  * Argus's own coverage gaps are not findings about the machine: they leave
    the findings list, totals, pulse, metrics and autopilot, never moved the
    score, and are all listed in /api/coverage `intel_gaps`.
"""

import tempfile
import time
import unittest
from pathlib import Path

from jarvis.core.store import Store
from jarvis.intel import hunt
from jarvis.response import alert, ledger
from jarvis.response.reporting import score
from jarvis.service import autopilot, coveragemap, jobs
from jarvis.service.schedule import JOBS

DAY = 86400
NOW = 2_000_000_000

SECRET = {"category": "tracked", "title": "OpenAI API key in plaintext", "detail": "d",
          "where": "/home/u/app/e2e.ts:3", "host": "wsl", "severity": "critical"}
GAP = {"category": "coverage gap", "title": "T1001 Data Obfuscation", "severity": "high",
       "detail": "no collector checks this — mentioned in 7 intelligence documents; "
                 "this is a detection coverage gap, not observed activity on this host",
       "where": "", "host": "wsl"}


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "j.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.store.set_meta("ledger_backfilled", "1")

    def sent(self, f, job, days_ago, reopen=False):
        key = alert.finding_key(f)
        self.store.ledger_sent(key, f, job, "", NOW - days_ago * DAY)
        if reopen:
            self.store.ledger_cleared(key, NOW - days_ago * DAY + 10)
            self.store.ledger_sent(key, f, job, "", NOW - days_ago * DAY + 20)
        self.store.commit()
        return key

    @staticmethod
    def snap(findings, error=""):
        return {"ts": NOW, "duration": 0.1, "error": error, "findings": findings}

    def audit(self, snapshots):
        return [f for f in ledger.audit(self.store, job_ts={"secrets": NOW}, now_ts=NOW,
                                        snapshots=snapshots) if f["severity"] != "ok"]


class LedgerAttachesInsteadOfRestating(_StoreCase):
    def test_an_overdue_listed_finding_is_one_problem_not_two(self):
        key = self.sent(SECRET, "secrets", 16)
        out = self.audit({"secrets": self.snap([SECRET])})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "low")
        self.assertEqual(out[0]["restates"], key)
        self.assertFalse(out[0]["orphan"])
        self.assertTrue(out[0]["title"].startswith("unresolved for 16d"))
        # The ageing signal moves onto the original, whose severity is untouched.
        annotated = ledger.annotate([SECRET], "secrets", ledger.open_rows(self.store), NOW)
        self.assertEqual(annotated[0]["severity"], "critical")
        self.assertEqual(annotated[0]["ledger"]["state"], "overdue")
        self.assertEqual(annotated[0]["ledger"]["age"], "16d")
        self.assertEqual(annotated[0]["ledger"]["deadline_days"], 2)

    def test_a_recurring_listed_finding_is_annotated_as_recurring(self):
        self.sent(SECRET, "secrets", 3, reopen=True)
        out = self.audit({"secrets": self.snap([SECRET])})
        self.assertEqual([(f["severity"], f["orphan"]) for f in out], [("low", False)])
        ann = ledger.annotate([SECRET], "secrets", ledger.open_rows(self.store), NOW)[0]["ledger"]
        self.assertEqual((ann["state"], ann["reopened"], ann["cleared"]), ("recurring", 1, 1))

    def test_an_original_that_is_no_longer_listed_keeps_full_severity(self):
        self.sent(SECRET, "secrets", 16)
        other = dict(SECRET, where="/elsewhere")
        out = self.audit({"secrets": self.snap([other])})
        self.assertEqual([(f["severity"], f["orphan"], f["restates"]) for f in out],
                         [("critical", True, "")])

    def test_a_failing_collector_does_not_count_as_listing_the_original(self):
        self.sent(SECRET, "secrets", 16)
        out = self.audit({"secrets": self.snap([SECRET], error="timeout")})
        self.assertEqual(out[0]["severity"], "critical")
        self.assertTrue(out[0]["orphan"])

    def test_a_finding_of_another_job_is_not_the_original(self):
        self.sent(SECRET, "secrets", 16)
        out = self.audit({"toolchain": self.snap([SECRET])})
        self.assertEqual(out[0]["severity"], "critical")

    def test_without_snapshots_every_row_stands_on_its_own(self):
        self.sent(SECRET, "secrets", 16)
        out = [f for f in ledger.audit(self.store, now_ts=NOW) if f["severity"] != "ok"]
        self.assertEqual(out[0]["severity"], "critical")
        self.assertTrue(out[0]["orphan"])

    def test_a_stale_row_stays_medium_and_unverified(self):
        self.sent(SECRET, "secrets", 16)
        out = [f for f in ledger.audit(self.store, job_ts={"secrets": NOW - 20 * DAY}, now_ts=NOW,
                                       snapshots={"secrets": self.snap([SECRET])})
               if f["severity"] != "ok"]
        self.assertEqual([(f["severity"], f["title"].split(":")[0]) for f in out],
                         [("medium", "unverified since it was reported")])

    def test_cleared_and_not_yet_overdue_rows_add_no_annotation_state(self):
        self.sent(SECRET, "secrets", 1)
        ann = ledger.annotate([SECRET], "secrets", ledger.open_rows(self.store), NOW)[0]
        self.assertEqual(ann["ledger"]["state"], "open")
        self.store.ledger_cleared(alert.finding_key(SECRET), NOW)
        self.store.commit()
        self.assertNotIn("ledger", ledger.annotate([SECRET], "secrets", ledger.open_rows(self.store), NOW)[0])

    def test_the_scheduler_job_passes_snapshots(self):
        # The real service path: jobs._ledger reads snapshots from the store.
        real_now = int(time.time())
        self.store.ledger_sent(alert.finding_key(SECRET), SECRET, "secrets", "", real_now - 16 * DAY)
        self.store.save_snapshot("secrets", [SECRET], 0.1, "")
        self.store.commit()
        out = [f for f in jobs._ledger(("wsl",), self.path) if f["severity"] != "ok"]
        self.assertEqual([(f["severity"], f["orphan"]) for f in out], [("low", False)])


class BlocklistNeedsASecondSignal(unittest.TestCase):
    def test_grades(self):
        g = hunt.grade_ip_hit
        self.assertEqual(g("threatfox", "high", "45.155.205.7")[0], "high")
        self.assertEqual(g("threatfox", "high", "45.155.205.7",
                           ["its image runs from a temp or download folder"])[0], "critical")
        self.assertEqual(g("feodo", "high", "45.155.205.7", in_flagged_network=True)[0], "critical")
        self.assertEqual(g("threatfox", "medium", "45.155.205.7")[0], "medium")
        self.assertEqual(g("blocklist-de", "high", "45.155.205.7", ["x"])[0], "medium")
        # Shared provider infrastructure never reaches critical, even corroborated.
        self.assertEqual(g("threatfox", "high", "142.251.38.238", ["x"])[0], "medium")
        self.assertEqual(g("cins", "high", "35.190.43.134")[0], "medium")

    def test_range_and_address_hits_of_one_peer_to_peer_process_are_one_finding(self):
        rows = [{"ip": f"85.203.46.{i}", "port": 6881, "pname": "btweb.exe", "label": "x",
                 "feed": "threatfox", "src": "u", "host": "win", "severity": "high",
                 "qualifier": "listed command-and-control", "reasons": []} for i in range(10)]
        rows += [{"ip": f"91.204.224.{i}", "port": 6881, "pname": "btweb.exe", "label": "hijacked network",
                  "feed": "spamhaus-drop", "src": "u", "host": "win", "severity": "high",
                  "qualifier": "flagged network", "network": "91.204.224.0/22", "reasons": []}
                 for i in range(7)]
        out = hunt.collapse_peer_hits(rows)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "high")
        self.assertIn("btweb.exe contacted 17 listed IPs (0 corroborated)", out[0]["title"])


class CoverageGapsAreNotMachineFindings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "j.db")
        store = Store(self.path)
        try:
            store.save_snapshot("gaps", [GAP, dict(GAP, title="T1480 Execution Guardrails", severity="medium"),
                                         dict(GAP, category="not observable", title="T1082 x", severity="low")],
                                0.1, "")
            store.save_snapshot("secrets", [SECRET], 0.1, "")
            store.commit()
        finally:
            store.close()

    def test_the_predicate(self):
        self.assertTrue(alert.is_coverage_gap(GAP))
        self.assertFalse(alert.is_coverage_gap(SECRET))
        self.assertFalse(alert.is_coverage_gap(None))

    def test_state_lists_them_apart_and_counts_only_the_machine(self):
        from jarvis.service.scheduler import Scheduler
        from jarvis.web.server import build_state
        state = build_state(self.path, Scheduler(self.path, ("wsl",)))
        cats = {f.get("category") for f in state["findings"]}
        self.assertNotIn("coverage gap", cats)
        self.assertNotIn("not observable", cats)
        self.assertEqual(state["totals"], {"critical": 1})
        self.assertEqual(state["worst"], "critical")
        self.assertEqual(state["coverage_gaps"]["total"], 3)
        self.assertEqual(state["coverage_gaps"]["by_priority"], {"high": 1, "medium": 1, "low": 1})

    def test_coverage_view_lists_every_gap_with_its_priority(self):
        out = coveragemap.build(self.path)
        gaps = out["intel_gaps"]
        self.assertEqual(gaps["total"], 3)
        self.assertEqual([(g["tid"], g["priority"]) for g in gaps["items"]][0], ("T1001", "high"))
        self.assertEqual(gaps["by_kind"]["coverage gap"], {"high": 1, "medium": 1})

    def test_autopilot_does_not_investigate_them(self):
        store = Store(self.path)
        try:
            found = autopilot.current_findings(store)
        finally:
            store.close()
        self.assertEqual({job for _f, job in found.values()}, {"secrets"})

    def test_they_never_moved_the_score(self):
        now = int(time.time())
        snaps = {"secrets": {"ts": now, "error": "", "findings": [SECRET]},
                 "gaps": {"ts": now, "error": "", "findings": [GAP] * 20}}
        with_gaps = score.compute(snaps, JOBS, now=now)
        without = score.compute({"secrets": snaps["secrets"]}, JOBS, now=now)
        self.assertEqual(with_gaps["areas"], without["areas"])

    def test_pulse_and_metrics_leave_them_out(self):
        from jarvis.service.scheduler import Scheduler
        from jarvis.web import metrics, stream
        sched = Scheduler(self.path, ("wsl",))
        pulse = stream.build(self.path, sched)
        self.assertNotIn("coverage gap", {u.get("category") for u in pulse.get("urgent", [])})
        body = metrics.render(self.path, sched)
        self.assertIn('jarvis_findings_open{severity="high"} 0', body)
        self.assertIn('jarvis_findings_open{severity="critical"} 1', body)


if __name__ == "__main__":
    unittest.main()

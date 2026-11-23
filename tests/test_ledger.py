"""The record of what was reported, and what became of it."""

import json
import os
import tempfile
import unittest

from jarvis.core.store import Store
from jarvis.response import ledger

DAY = 86400


class LedgerStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.f = {"category": "staging", "title": "a thing", "detail": "d",
                  "where": "/w", "host": "win", "severity": "high"}

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmp.name)

    def test_a_cleared_row_is_kept_not_deleted(self):
        self.store.ledger_sent("k", self.f, "intrusion")
        self.store.ledger_cleared("k")
        rows = self.store.ledger_rows()
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["cleared_at"])

    def test_a_send_after_a_clear_counts_as_a_reopen(self):
        self.store.ledger_sent("k", self.f, "intrusion")
        self.store.ledger_cleared("k")
        self.store.ledger_sent("k", self.f, "intrusion")
        row = self.store.ledger_rows()[0]
        self.assertEqual(row["reopened"], 1)
        self.assertEqual(row["clear_count"], 1)
        self.assertEqual(row["cleared_at"], 0)

    def test_the_worst_severity_ever_seen_is_remembered(self):
        self.store.ledger_sent("k", dict(self.f, severity="critical"), "j")
        self.store.ledger_sent("k", dict(self.f, severity="low"), "j")
        row = self.store.ledger_rows()[0]
        self.assertEqual(row["severity"], "low")
        self.assertEqual(row["worst_sev"], "critical")

    def test_clearing_twice_only_counts_the_first(self):
        self.store.ledger_sent("k", self.f, "j")
        self.store.ledger_cleared("k")
        self.store.ledger_cleared("k")
        self.assertEqual(self.store.ledger_rows()[0]["clear_count"], 1)

    def test_a_real_send_heals_an_imported_row_that_had_no_host(self):
        self.store.ledger_sent("k", dict(self.f, host=""), "j")
        self.assertEqual(self.store.ledger_rows()[0]["host"], "")
        self.store.ledger_sent("k", self.f, "j")
        self.assertEqual(self.store.ledger_rows()[0]["host"], "win")

    def test_a_send_without_a_host_does_not_erase_a_known_one(self):
        self.store.ledger_sent("k", self.f, "j")
        self.store.ledger_sent("k", dict(self.f, host=""), "j")
        self.assertEqual(self.store.ledger_rows()[0]["host"], "win")


class ClassifyTests(unittest.TestCase):
    NOW = 1_000_000

    def _row(self, **kw):
        row = {"key": "k", "title": "t", "job": "secrets", "severity": "high",
               "first_sent": self.NOW - 3 * DAY, "last_sent": self.NOW - DAY,
               "cleared_at": 0, "reopened": 0, "clear_count": 0,
               "sent_count": 3, "locus": "", "host": "wsl"}
        row.update(kw)
        return row

    def test_an_open_row_whose_job_still_runs_is_outstanding(self):
        states = ledger.classify(
            [self._row()], job_ts={"secrets": self.NOW}, now_ts=self.NOW)
        self.assertEqual(len(states["outstanding"]), 1)

    def test_an_open_row_whose_job_has_not_run_since_is_unverified(self):
        states = ledger.classify(
            [self._row()], job_ts={"secrets": self.NOW - 2 * DAY},
            now_ts=self.NOW)
        self.assertEqual(len(states["stale"]), 1)
        self.assertEqual(len(states["outstanding"]), 0)

    def test_a_reopened_row_outranks_a_merely_outstanding_one(self):
        states = ledger.classify(
            [self._row(reopened=2)], job_ts={"secrets": self.NOW},
            now_ts=self.NOW)
        self.assertEqual(len(states["recurring"]), 1)

    def test_a_cleared_row_is_resolved_regardless_of_job_timing(self):
        states = ledger.classify(
            [self._row(cleared_at=self.NOW - 100)], job_ts={}, now_ts=self.NOW)
        self.assertEqual(len(states["resolved"]), 1)

    def test_without_job_timestamps_open_rows_read_as_outstanding(self):
        states = ledger.classify([self._row()], job_ts=None, now_ts=self.NOW)
        self.assertEqual(len(states["outstanding"]), 1)

    def test_overdue_is_measured_against_the_severity_deadline(self):
        old = self._row(severity="critical", first_sent=self.NOW - 5 * DAY)
        fresh = self._row(severity="low", first_sent=self.NOW - 5 * DAY)
        self.assertTrue(ledger.overdue(old, self.NOW))
        self.assertFalse(ledger.overdue(fresh, self.NOW))

    def test_a_resolved_row_is_never_overdue(self):
        row = self._row(severity="critical", first_sent=self.NOW - 90 * DAY,
                        cleared_at=self.NOW)
        self.assertFalse(ledger.overdue(row, self.NOW))


class BackfillTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmp.name)

    def _state(self, entries):
        self.store.set_meta("alert_state", json.dumps(entries))

    def test_sent_alerts_are_imported_with_their_real_counts_and_dates(self):
        self._state({"present|token in plaintext|/x": {
            "first": 1000, "last_sent": 5000, "count": 12,
            "sev": "critical", "job": "secrets"}})
        self.assertEqual(ledger.backfill(self.store), 1)
        row = self.store.ledger_rows()[0]
        self.assertEqual(row["sent_count"], 12)
        self.assertEqual(row["first_sent"], 1000)
        self.assertEqual(row["last_sent"], 5000)
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["title"], "token in plaintext")
        self.assertEqual(row["locus"], "/x")

    def test_alerts_still_inside_the_persistence_gate_are_not_imported(self):
        self._state({"a|never mailed|/x": {"first": 1, "pending": 1,
                                           "count": 0, "job": "secrets"}})
        self.assertEqual(ledger.backfill(self.store), 0)
        self.assertEqual(self.store.ledger_rows(), [])

    def test_the_import_runs_once_and_does_not_resurrect_cleared_rows(self):
        self._state({"a|t|/x": {"first": 1, "last_sent": 2, "count": 3,
                                "sev": "high", "job": "j"}})
        ledger.backfill(self.store)
        self.store.ledger_cleared("a|t|/x")
        self.assertEqual(ledger.backfill(self.store), 0)
        self.assertTrue(self.store.ledger_rows()[0]["cleared_at"])

    def test_imported_rows_carry_no_invented_host(self):
        self._state({"dropped file|x exists here: C:\\Windows\\a.exe|https://i":
                     {"first": 1, "last_sent": 2, "count": 3, "sev": "high",
                      "job": "hunt"}})
        ledger.backfill(self.store)
        self.assertEqual(self.store.ledger_rows()[0]["host"], "")


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmp.name)

    def test_an_empty_ledger_says_so_rather_than_claiming_a_clean_backlog(self):
        out = ledger.audit(self.store)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "ok")
        self.assertIn("no alerts have been sent", out[0]["title"])

    def test_a_recurrence_is_reported_individually(self):
        f = {"category": "c", "title": "the thing", "detail": "d",
             "where": "/w", "host": "wsl", "severity": "high"}
        self.store.ledger_sent("k", f, "backdoor")
        self.store.ledger_cleared("k")
        self.store.ledger_sent("k", f, "backdoor")
        titles = [x["title"] for x in ledger.audit(self.store)]
        self.assertTrue(any("come back" in t for t in titles), titles)

    def test_every_ledger_finding_is_in_the_nopage_category(self):
        from jarvis.response.alert import NOPAGE_CATEGORIES
        # Structural: a ledger finding that paged would be mailed, recorded in
        # the ledger, and become another unresolved alert.
        self.assertIn("ledger", NOPAGE_CATEGORIES)
        for f in ledger.audit(self.store):
            self.assertEqual(f["category"], "ledger")


if __name__ == "__main__":
    unittest.main()

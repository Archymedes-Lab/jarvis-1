import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jarvis.cli.commands.incidents import cmd_incidents
from jarvis.core import incidents, retention
from jarvis.core.store import Store


def finding(**values):
    return {"category": "credentials", "title": "untrusted reader", "host": "win",
            "where": "browser store", "detail": "metadata only", "severity": "high", **values}


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "test.db")
        self.store = Store(self.path)
        self.addCleanup(lambda: self.store.close())
        self.serial = 0

    def record(self, findings, **values):
        self.serial += 1
        defaults = {"observed_at": self.serial * 100, "run_id": f"run-{self.serial}"}
        return self.store.record_observation("intrusion", findings, **{**defaults, **values})

    def one(self):
        key = incidents.identity("intrusion", finding())
        return incidents.detail(self.store.db, key)

    def test_receipt_survives_restart_and_is_independent_of_email(self):
        self.record([finding()])
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(self.one()["state"], "active")
        self.assertEqual(self.one()["first_seen"], 100)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM alert_ledger").fetchone()[0], 0)
        self.assertEqual(self.store.db.execute("PRAGMA synchronous").fetchone()[0], 2)

    def test_visibility_loss_preserves_original_evidence_and_does_not_resolve(self):
        self.record([finding()])
        self.record([], coverage="unavailable", error="sensor unavailable")
        item = self.one()
        self.assertEqual(item["state"], "unobserved")
        self.assertEqual(item["last_seen"], 100)
        self.assertEqual(item["evidence"], finding())
        self.assertEqual(item["seen_count"], 1)
        self.assertEqual(item["transitions"][0]["previous_state"], "active")

    def test_clean_scan_is_not_verified_remediation_and_return_is_counted(self):
        self.record([finding()])
        self.record([])
        self.assertEqual(self.one()["state"], "not_observed")
        self.assertIn("resolution unverified", self.one()["transitions"][0]["reason"])
        self.record([finding()])
        item = self.one()
        self.assertEqual(item["state"], "active")
        self.assertEqual(item["recurrences"], 1)
        self.assertEqual(item["seen_count"], 2)

    def test_telemetry_return_is_not_counted_as_threat_recurrence(self):
        self.record([finding()])
        self.record([], coverage="unavailable")
        self.record([finding()])
        self.assertEqual(self.one()["recurrences"], 0)

    def test_blind_pass_does_not_flip_every_already_absent_incident(self):
        self.record([finding()])
        self.record([])
        before = self.one()["transitions_total"]
        receipt = self.record([], coverage="unavailable", error="bridge down")
        item = self.one()
        self.assertEqual(item["state"], "not_observed")
        self.assertEqual(item["transitions_total"], before)
        self.assertEqual(receipt["coverage"], "unavailable")
        self.assertEqual(incidents.overview(self.store.db)["sources"][0]["coverage"],
                         "unavailable")

    def test_partial_scan_can_add_positive_evidence_but_cannot_clear_others(self):
        other = finding(where="another store")
        self.record([finding(), other])
        self.record([finding()], coverage="partial")
        self.assertEqual(self.one()["state"], "active")
        missing = incidents.detail(self.store.db, incidents.identity("intrusion", other))
        self.assertEqual(missing["state"], "unobserved")

    def test_explicit_visibility_findings_override_claimed_complete_collection(self):
        self.record([finding()])
        receipt = self.record([finding(category="visibility", title="log is unreadable")])
        self.assertEqual(receipt["coverage"], "partial")
        self.assertEqual(self.one()["state"], "unobserved")

    def test_sources_and_hosts_never_clear_each_others_incidents(self):
        self.record([finding(), finding(host="wsl")])
        self.store.record_observation("another-job", [], observed_at=150)
        self.assertEqual(incidents.overview(self.store.db)["counts"]["active"], 2)
        self.record([finding(host="wsl")])
        self.assertEqual(self.one()["state"], "not_observed")
        self.assertEqual(incidents.overview(self.store.db)["counts"]["active"], 1)

    def test_identical_replay_is_idempotent_conflicting_replay_rolls_back(self):
        self.record([finding()], run_id="stable", observed_at=100)
        duplicate = self.record([finding()], run_id="stable", observed_at=100)
        self.assertTrue(duplicate["duplicate"])
        with self.assertRaisesRegex(ValueError, "different evidence"):
            self.record([], run_id="stable", observed_at=100)
        self.assertEqual(self.one()["seen_count"], 1)
        self.assertEqual(self.one()["transitions_total"], 1)

    def test_out_of_order_observation_cannot_clear_a_newer_threat(self):
        self.record([finding()], observed_at=200)
        with self.assertRaisesRegex(ValueError, "out-of-order"):
            self.record([], observed_at=100)
        self.assertEqual(self.one()["state"], "active")

    def test_duplicate_findings_count_once_and_keep_worst_severity(self):
        self.record([finding(), finding(severity="low"), finding()])
        self.assertEqual(self.one()["seen_count"], 1)
        self.assertEqual(self.one()["severity"], "high")
        self.record([finding(severity="medium")])
        self.assertEqual(self.one()["worst_severity"], "high")
        self.assertEqual(self.one()["severity"], "medium")
        self.assertEqual(self.one()["transitions_total"], 2)

    def test_stable_rule_and_subject_ids_survive_display_text_changes(self):
        first = finding(rule_id="credential-access-v1", subject_id="process-guid-123")
        second = {**first, "title": "better wording", "where": "new display text"}
        self.assertEqual(incidents.identity("intrusion", first), incidents.identity("intrusion", second))
        self.assertNotEqual(incidents.identity("intrusion", first),
                            incidents.identity("intrusion", {**first, "subject_id": "different-process"}))

    def test_failed_transition_write_rolls_back_receipt_and_projection(self):
        self.record([finding()])
        self.store.db.execute(
            "CREATE TRIGGER reject_transition BEFORE INSERT ON defender_transitions "
            "BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.record([], coverage="unavailable")
        self.assertEqual(self.one()["state"], "active")
        count = self.store.db.execute("SELECT COUNT(*) FROM defender_runs").fetchone()[0]
        self.assertEqual(count, 1)

    def test_incomplete_receipt_transaction_is_rolled_back_after_reopen(self):
        self.store.db.execute("BEGIN IMMEDIATE")
        incidents.record(self.store.db, "intrusion", [finding()],
                         run_id="uncommitted", observed_at=100)
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(incidents.overview(self.store.db)["total"], 0)
        self.assertEqual(incidents.overview(self.store.db)["sources"], [])

    def test_record_does_not_discard_unrelated_pending_writes(self):
        self.store.db.execute("INSERT INTO meta VALUES('pending','preserve')")
        with self.assertRaisesRegex(RuntimeError, "pending writes"):
            self.record([finding()])
        self.store.commit()
        self.assertEqual(self.store.get_meta("pending"), "preserve")

    def test_repeated_evidence_updates_details_without_growing_transition_history(self):
        self.record([finding()])
        self.record([finding(detail="updated metadata")])
        self.assertEqual(self.one()["evidence"]["detail"], "updated metadata")
        self.assertEqual(self.one()["transitions_total"], 1)
        self.assertEqual(self.one()["transitions"][0]["evidence"]["detail"], "metadata only")

    def test_retention_keeps_latest_coverage_and_transition_receipts(self):
        self.record([finding()])  # first observation; retained
        self.record([finding()])  # redundant receipt; removable
        self.record([])           # transition; retained
        self.record([])           # latest coverage; retained
        with patch("jarvis.core.retention.now", return_value=100 * 86400):
            retention.apply(self.store)
        kept = [r[0] for r in self.store.db.execute("SELECT run_id FROM defender_runs ORDER BY sequence")]
        self.assertEqual(kept, ["run-1", "run-3", "run-4"])
        self.assertEqual(self.one()["transitions_total"], 2)

    def test_retention_removes_only_old_derived_dormant_coverage_flips(self):
        self.record([finding()], observed_at=100)
        self.record([], observed_at=200)
        key = incidents.identity("intrusion", finding())
        incidents._transition(self.store.db, key, "run-2", 300,
                              "not_observed", "unobserved", "coverage incomplete",
                              incidents.encode(finding()))
        with patch("jarvis.core.retention.now", return_value=10 * 86400):
            removed = {r["name"]: r["rows"] for r in retention.apply(self.store)}
        self.assertEqual(removed["incident-coverage-flaps"], 1)
        edges = [(r[0], r[1]) for r in self.store.db.execute(
            "SELECT previous_state,state FROM defender_transitions ORDER BY sequence")]
        self.assertEqual(edges, [("", "active"), ("active", "not_observed")])

    def test_queries_are_bounded_and_unknown_ids_do_not_match(self):
        self.record([finding(where=str(i)) for i in range(4)])
        result = incidents.overview(self.store.db, limit=2)
        self.assertEqual(len(result["incidents"]), 2)
        self.assertEqual(result["total"], 4)
        self.assertTrue(result["truncated"])
        self.assertIsNone(incidents.detail(self.store.db, "' OR 1=1 --"))

    def test_cli_returns_structured_history_without_collecting(self):
        self.record([finding()])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cmd_incidents(SimpleNamespace(incident_id=None, limit=5, json=True), self.store)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["counts"]["active"], 1)

    def test_invalid_payload_never_creates_a_receipt(self):
        for findings in (None, {}, [None], ["text"]):
            with self.subTest(findings=findings), self.assertRaises(ValueError):
                self.record(findings)
        for stamp in (float("nan"), float("inf"), -1, True):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                self.record([], observed_at=stamp)
        self.assertEqual(incidents.overview(self.store.db)["sources"], [])

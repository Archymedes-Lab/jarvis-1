import os
import tempfile
import unittest

from jarvis.core import retention
from jarvis.core.store import Store
from jarvis.core.util import now

DAY = 86400


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Store(os.path.join(self._tmp.name, "jarvis.db"))
        self.addCleanup(self.store.close)

    def _event(self, severity, age_days, kind="proc"):
        self.store.db.execute(
            "INSERT INTO events(ts,host,severity,kind) VALUES(?,?,?,?)",
            (now() - age_days * DAY, "wsl", severity, kind))
        self.store.commit()

    def _severities(self):
        return sorted(r[0] for r in
                      self.store.db.execute("SELECT severity FROM events"))

    def test_critical_events_are_never_aged_out(self):
        self._event("critical", 3650)

        retention.apply(self.store)

        self.assertEqual(self._severities(), ["critical"])

    def test_severity_tiers_keep_serious_events_longer_than_routine_ones(self):
        for sev in ("low", "medium", "high", "critical"):
            self._event(sev, 30)

        retention.apply(self.store)

        # 30 days is past the low tier (14d) but inside medium (60d).
        self.assertEqual(self._severities(), ["critical", "high", "medium"])

    def test_recent_low_severity_events_survive(self):
        self._event("low", 1)

        retention.apply(self.store)

        self.assertEqual(self._severities(), ["low"])

    def test_plan_reports_without_deleting_anything(self):
        self._event("low", 90)

        rows = {r["name"]: r["rows"] for r in retention.plan(self.store)}

        self.assertEqual(rows["events-low"], 1)
        self.assertEqual(self._severities(), ["low"])

    def test_approved_baseline_entries_are_kept_however_stale(self):
        for approved in (0, 1):
            self.store.db.execute(
                "INSERT INTO procs(fp,host,name,first_seen,last_seen,approved)"
                " VALUES(?,?,?,?,?,?)",
                ("fp%d" % approved, "wsl", "x", 0, now() - 3650 * DAY,
                 approved))
        self.store.commit()

        retention.apply(self.store)

        kept = self.store.db.execute(
            "SELECT approved FROM procs").fetchall()
        self.assertEqual([r[0] for r in kept], [1])

    def test_writeup_indicators_are_never_pruned_by_age(self):
        for i, source in enumerate(("exa", "urlhaus")):
            self.store.db.execute(
                "INSERT INTO indicators(kind,value,norm,first_seen,"
                "last_seen,status,source,source_url) VALUES(?,?,?,?,?,?,?,'')",
                ("ip", "1.2.3.%d" % i, "1.2.3.%d" % i,
                 0, now() - 3650 * DAY, "retired", source))
        self.store.commit()

        retention.apply(self.store)

        left = [r[0] for r in
                self.store.db.execute("SELECT source FROM indicators")]
        self.assertEqual(left, ["exa"])

    def test_active_indicators_are_not_removed_only_retired_ones(self):
        self.store.db.execute(
            "INSERT INTO indicators(kind,value,norm,first_seen,last_seen,"
            "status,source,source_url) "
            "VALUES('ip','9.9.9.9','9.9.9.9',0,?,'active','x','')",
            (now() - 3650 * DAY,))
        self.store.commit()

        retention.apply(self.store)

        self.assertEqual(
            self.store.db.execute(
                "SELECT COUNT(*) FROM indicators").fetchone()[0], 1)

    def test_days_override_applies_to_every_policy(self):
        self._event("high", 30)

        rows = {r["name"]: r["rows"] for r in
                retention.plan(self.store,
                               {p.name: 7 for p in retention.POLICIES})}

        self.assertEqual(rows["events-high"], 1)

    def test_indexes_are_created_and_creation_is_idempotent(self):
        retention.ensure_indexes(self.store)
        retention.ensure_indexes(self.store)

        names = {r[0] for r in self.store.db.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("idx_events_sev_ts", names)

    def test_tiered_delete_uses_an_index_rather_than_scanning(self):
        retention.ensure_indexes(self.store)
        plan = self.store.db.execute(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM events "
            "WHERE ts < ? AND severity = 'low'", (now(),)).fetchall()

        self.assertIn("idx_events_sev_ts", " ".join(str(r[-1]) for r in plan))

    def test_db_size_reports_reclaimable_space(self):
        size = retention.db_size(self.store)

        self.assertGreater(size["bytes"], 0)
        self.assertGreaterEqual(size["free_bytes"], 0)


class ServerWiringTests(unittest.TestCase):
    """The feeds job calls retention; a missing import there only fails at
    run time, inside a background thread, where it is easy to miss."""

    def test_server_module_binds_retention(self):
        from jarvis.service import jobs

        self.assertIs(jobs.retention, retention)


if __name__ == "__main__":
    unittest.main()

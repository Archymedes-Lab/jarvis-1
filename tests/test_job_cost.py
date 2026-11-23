"""Collectors whose cost grew with history stay flat (measured 2026-11-02, scripts/dev/job_cost.py).

- resources: the per-table breakdown (a dbstat walk of the whole database) is rebuilt
  daily or when the file changed by a tenth; the total size is fresh every run.
- scan: only the fingerprints running now are looked up; the answers equal those of
  the old full-table load.
"""

import os
import random
import tempfile
import unittest

from jarvis.collectors.process import resourcewatch as rw
from jarvis.core.store import Store


class DatabaseProfile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "j.db"))
        self.addCleanup(self.store.close)
        self.size = os.path.getsize(self.store.path)

    def walking_forbidden(self):
        class NoWalk:
            def execute(_self, *a, **k):
                raise AssertionError("the breakdown was rebuilt")
        real, self.store.db = self.store.db, NoWalk()
        self.addCleanup(setattr, self.store, "db", real)

    def test_first_run_builds_the_breakdown_and_says_when(self):
        p = rw._database_profile(self.store, None, now_ts=1000.0)
        self.assertTrue(p["tables"])
        self.assertEqual((p["tables_at"], p["tables_bytes"], p["bytes"]), (1000.0, self.size, self.size))

    def test_a_fresh_breakdown_is_reused_and_the_size_stays_current(self):
        first = rw._database_profile(self.store, None, now_ts=1000.0)
        self.walking_forbidden()
        again = rw._database_profile(self.store, first, now_ts=1000.0 + rw.TABLES_MAX_AGE_S - 1)
        self.assertEqual(again["tables"], first["tables"])
        self.assertEqual(again["tables_at"], 1000.0)
        self.assertEqual(again["bytes"], self.size)

    def test_a_day_old_or_resized_breakdown_is_rebuilt(self):
        first = rw._database_profile(self.store, None, now_ts=1000.0)
        old = rw._database_profile(self.store, first, now_ts=1000.0 + rw.TABLES_MAX_AGE_S)
        self.assertEqual(old["tables_at"], 1000.0 + rw.TABLES_MAX_AGE_S)
        shrunk = dict(first, tables_bytes=int(self.size / (1 - rw.TABLES_CHANGE) + 10))
        self.assertEqual(rw._database_profile(self.store, shrunk, now_ts=1001.0)["tables_at"], 1001.0)

    def test_unusable_previous_profiles_rebuild_instead_of_crashing(self):
        for prev in (None, {}, "junk", {"tables": [], "tables_at": 1}, {"tables": [{"name": "x"}], "tables_at": "1"}):
            p = rw._database_profile(self.store, prev, now_ts=50.0)
            self.assertEqual(p["tables_at"], 50.0, prev)

    def test_a_failed_walk_reports_no_breakdown_not_a_stale_one(self):
        class Broken:
            def execute(_self, *a, **k):
                raise RuntimeError("no dbstat")
        real, self.store.db = self.store.db, Broken()
        try:
            p = rw._database_profile(self.store, {"tables": [{"name": "old", "bytes": 1}], "tables_at": 1.0,
                                                  "tables_bytes": 1}, now_ts=9e9)
        finally:
            self.store.db = real
        self.assertEqual((p["tables"], p["tables_at"]), ([], None))
        self.assertEqual(p["bytes"], self.size)


class FingerprintLookup(unittest.TestCase):
    def test_answers_equal_the_full_table_load_including_chunk_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "j.db"))
            rnd = random.Random(7)
            fps = [f"fp{i:05d}" for i in range(1300)]
            for fp in fps:
                store.upsert_proc({"fp": fp, "host": "wsl", "name": "n", "exe": "/x", "cmdline": "c", "user": "u"},
                                  approved=rnd.choice((0, 1)))
            store.commit()
            for fp in rnd.sample(fps, 40):
                store.set_approved(fp, rnd.choice((0, 1, 2)))
            old_known = store.known_fps()
            old_approved = {r["fp"] for r in store.list_procs(approved=1, limit=100000)}
            running = rnd.sample(fps, 1100) + [f"new{i}" for i in range(30)] + fps[:5]   # >2 chunks, dups, unknown
            known, approved = store.fp_status(running, chunk=500)
            self.assertEqual(known, {f for f in running if f in old_known})
            self.assertEqual(approved, {f for f in running if f in old_approved})
            self.assertEqual(store.fp_status([]), (set(), set()))
            store.close()


if __name__ == "__main__":
    unittest.main()

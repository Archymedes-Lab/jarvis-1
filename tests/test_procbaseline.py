"""The /procs change lens: the name baseline (web/procbaseline.py). The page
rules that use it are tested in tests/test_procs_page.py.

The lens must say "never seen" only when a baseline exists and lacks the
name, say "unknown" when there is no baseline, leak nothing but names, times
and counts, and cost one cached query however many viewers ask."""

import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from jarvis.core.store import Store
from jarvis.web import procbaseline

NOW = 2_000_000_000


class BaselineBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "jarvis.db")
        Store(self.db).close()
        rows = [
            # fp, host, name, exe, script, cmdline, user, first, last, count, approved
            ("a1", "win", "MsMpEng.exe", r"C:\ProgramData\Defender\MsMpEng.exe", "", "SECRET-CMD", "SYSTEM", NOW - 90 * 86400, NOW, 400, 1),
            ("a2", "win", "msmpeng.exe", r"C:\Other\MsMpEng.exe", "", "SECRET-CMD-2", "SYSTEM", NOW - 30 * 86400, NOW, 100, 0),
            ("b1", "win", "fresh.exe", r"C:\Users\x\fresh.exe", "", "token=abc123", "chris", NOW - 3600, NOW, 2, 0),
            ("c1", "wsl", "systemd", "/usr/lib/systemd/systemd", "", "", "root", NOW - 60 * 86400, NOW, 900, 0),
            ("d1", "other", "ignored", "", "", "", "", NOW, NOW, 1, 0),
            ("e1", "wsl", "Relay(46877)", "/init", "", "", "root", NOW - 20 * 86400, NOW - 86400, 1, 0),
            ("e2", "wsl", "Relay(512)", "/init", "", "", "root", NOW - 10 * 86400, NOW, 1, 0),
        ]
        with sqlite3.connect(self.db) as c:
            c.executemany("INSERT INTO procs (fp, host, name, exe, script, cmdline, user, first_seen, last_seen, seen_count, approved) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def tearDown(self):
        self.tmp.cleanup()

    def test_names_are_grouped_per_view_host(self):
        d = procbaseline.build(self.db, now=NOW)
        self.assertTrue(d["ok"])
        win, lin = d["hosts"]["win"], d["hosts"]["lin"]
        self.assertEqual(win["rows"], 2)
        self.assertEqual(lin["rows"], 2, "systemd plus every Relay(<pid>) folded into one name")
        self.assertEqual(lin["names"]["relay(#)"], [NOW - 20 * 86400, NOW, 2, 0])
        first, last, count, approved = win["names"]["msmpeng.exe"]
        self.assertEqual(first, NOW - 90 * 86400, "earliest first-seen across fingerprints")
        self.assertEqual(count, 500, "sightings summed across fingerprints")
        self.assertEqual(approved, 1)
        self.assertIn("systemd", lin["names"])
        self.assertNotIn("ignored", json.dumps(d), "hosts the views do not show are dropped")
        self.assertIn("msmpeng.exe", d["watch"]["win"])

    def test_only_names_times_and_counts_leave_the_daemon(self):
        blob = json.dumps(procbaseline.build(self.db, now=NOW))
        for secret in ("SECRET-CMD", "token=abc123", r"C:\\ProgramData", "/usr/lib/systemd", "chris", "SYSTEM", "a1"):
            self.assertNotIn(secret, blob)

    def test_unreadable_baseline_is_reported_not_empty_and_calm(self):
        d = procbaseline.build(os.path.join(self.tmp.name, "missing", "nope.db"), now=NOW)
        self.assertFalse(d["ok"])
        self.assertIn("unreadable", d["reason"])
        self.assertEqual(d["hosts"]["win"]["rows"], 0)

    def test_the_live_query_shape_is_bounded(self):
        t = time.perf_counter()
        procbaseline.build(self.db, now=NOW)
        self.assertLess(time.perf_counter() - t, 1.0)


class CacheTests(unittest.TestCase):
    def test_one_rebuild_per_period(self):
        calls, clock = [], [0.0]
        cache = procbaseline.Cache(ttl=300, clock=lambda: clock[0], builder=lambda db: calls.append(db) or {"n": len(calls)})
        self.assertEqual(cache.get("x")["n"], 1)
        clock[0] = 299
        self.assertEqual(cache.get("x")["n"], 1)
        clock[0] = 301
        self.assertEqual(cache.get("x")["n"], 2)
        self.assertEqual(len(calls), 2)

    def test_readers_are_not_blocked_by_a_rebuild(self):
        clock, gate, started = [0.0], threading.Event(), threading.Event()

        def slow(db):
            started.set()
            gate.wait(5)
            return {"v": "new"}

        cache = procbaseline.Cache(ttl=10, clock=lambda: clock[0], builder=lambda db: {"v": "old"})
        cache.get("x")
        cache.builder = slow
        clock[0] = 20
        t = threading.Thread(target=cache.get, args=("x",))
        t.start()
        started.wait(5)
        began = time.perf_counter()
        self.assertEqual(cache.get("x")["v"], "old", "served the cached copy while another caller rebuilds")
        self.assertLess(time.perf_counter() - began, 0.5)
        gate.set()
        t.join(5)
        self.assertEqual(cache.get("x")["v"], "new")

    def test_route_is_registered_same_origin(self):
        src = (Path(__file__).resolve().parents[1] / "jarvis" / "web" / "server.py").read_text()
        block = src[src.index('url.path == "/api/procs/baseline"'):][:500]
        self.assertIn("_same_origin", block)
        self.assertIn('"/static/procs-model.js"', src)


if __name__ == "__main__":
    unittest.main()

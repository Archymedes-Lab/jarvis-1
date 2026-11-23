"""Lean memory (2026-11-06): freed heap goes back to the kernel, SQLite connections
stop pinning hundreds of megabytes, and none of it can stop a job or a request.

Measured before the change on a copy of the live store (scripts/dev/daemon_memory.py):
a daemon-shaped workload peaked at 814-891 MB and kept 169-231 MB anonymous; after,
111-149 MB and 37-49 MB. These tests keep the mechanism and its failure paths.
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from jarvis.core import memory
from jarvis.core import store as store_mod
from jarvis.core.store import Store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GLIBC = sys.platform.startswith("linux") and bool(memory._glibc())


class Fresh(unittest.TestCase):
    def setUp(self):
        self._saved = (memory._libc, memory._last)

    def tearDown(self):
        memory._libc, memory._last = self._saved


class TrimTests(Fresh):
    def test_off_glibc_both_calls_are_quiet_no_ops(self):
        memory._libc = False
        self.assertFalse(memory.trim(force=True))
        self.assertFalse(memory.limit_arenas())

    def test_trim_is_rate_limited_unless_forced(self):
        libc = mock.Mock()
        memory._libc, memory._last = libc, 0.0
        clock = iter([100.0, 101.0, 106.0, 106.5]).__next__
        self.assertTrue(memory.trim(clock=clock))
        self.assertFalse(memory.trim(clock=clock))          # 1 s later: skipped
        self.assertTrue(memory.trim(clock=clock))           # past MIN_INTERVAL_S
        self.assertTrue(memory.trim(force=True, clock=clock))
        self.assertEqual(libc.malloc_trim.call_count, 3)
        libc.malloc_trim.assert_called_with(0)

    def test_a_failing_libc_call_never_raises(self):
        libc = mock.Mock()
        libc.malloc_trim.side_effect = OSError("gone")
        libc.mallopt.side_effect = OSError("gone")
        memory._libc = libc
        self.assertFalse(memory.trim(force=True))
        self.assertFalse(memory.limit_arenas())

    def test_limit_arenas_asks_glibc_for_two(self):
        libc = mock.Mock()
        libc.mallopt.return_value = 1
        memory._libc = libc
        self.assertTrue(memory.limit_arenas())
        libc.mallopt.assert_called_once_with(memory.M_ARENA_MAX, 2)

    @unittest.skipUnless(GLIBC, "needs glibc")
    def test_trim_really_returns_freed_heap_to_the_kernel(self):
        # Behaviour, not mirroring: a child frees many page-sized malloc blocks from
        # several threads (as the lanes do with SQLite pages) and reads RssAnon
        # before and after trim. Without the trim glibc keeps them resident.
        child = r'''
import ctypes, json, sys, threading
sys.path.insert(0, ROOT)
from jarvis.core import memory
libc = ctypes.CDLL("libc.so.6"); libc.malloc.restype = ctypes.c_void_p
libc.free.argtypes = [ctypes.c_void_p]
def anon():
    return next(int(l.split()[1]) for l in open("/proc/self/status") if l.startswith("RssAnon")) // 1024
def churn():
    blocks = [libc.malloc(4200) for _ in range(12000)]
    for b in blocks: ctypes.memset(b, 1, 4200)
    keep = blocks[-1]
    for b in blocks[:-1]: libc.free(b)       # the last one pins the heap top
t = [threading.Thread(target=churn) for _ in range(4)]; [x.start() for x in t]; [x.join() for x in t]
before = anon(); memory.trim(force=True); after = anon()
print(json.dumps({"before": before, "after": after}))
'''.replace("ROOT", repr(ROOT))
        out = subprocess.run([sys.executable, "-I", "-c", child], capture_output=True, text=True, timeout=120)
        r = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertGreater(r["before"], 150, r)             # ~4 x 50 MB freed but resident
        self.assertLess(r["after"], r["before"] / 2, r)


class StoreTests(unittest.TestCase):
    def test_connections_are_small_and_still_durable(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "j.db"))
            try:
                q = lambda p: st.db.execute(f"PRAGMA {p}").fetchone()[0]  # noqa: E731
                self.assertEqual(q("cache_size"), -store_mod.CACHE_KIB)
                self.assertLessEqual(store_mod.CACHE_KIB, 8192)
                self.assertEqual(q("mmap_size"), 0)
                # Memory is not bought with durability or reader concurrency.
                self.assertEqual(q("journal_mode"), "wal")
                self.assertEqual(q("synchronous"), 2)         # FULL
                self.assertEqual(q("busy_timeout"), 10000)
            finally:
                st.close()

    def test_a_small_cache_still_reads_a_large_store_correctly(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "j.db")
            st = Store(path)
            try:
                st.db.execute("CREATE TABLE big (k INTEGER PRIMARY KEY, v TEXT)")
                st.db.executemany("INSERT INTO big VALUES (?, ?)",
                                  ((i, "x" * 200) for i in range(60000)))   # ~13 MB > 4 MiB cache
                st.db.commit()
            finally:
                st.close()
            st = Store(path)
            try:
                n, total = st.db.execute("SELECT count(*), sum(length(v)) FROM big").fetchone()
                self.assertEqual((n, total), (60000, 60000 * 200))
            finally:
                st.close()


class ServicePathTests(unittest.TestCase):
    def test_a_lane_trims_after_a_job_even_when_the_job_raised(self):
        from jarvis.service.schedule import JOBS
        from jarvis.service.scheduler import Scheduler
        from tests.test_frequent_lane import _no_pressure, _quiet_pipeline
        with tempfile.TemporaryDirectory() as d:
            s = Scheduler(os.path.join(d, "j.db"), ("wsl", "win"))
            s.cold_start_pending.clear()
            s.next_run = {n: time.time() + 9e5 for n in JOBS}
            first = next(n for n in JOBS if s._lane_of(n) == "frequent")
            calls, stop = [], threading.Event()

            def run_once(store, name):
                calls.append(name)
                if len(calls) == 1:
                    raise sqlite3.OperationalError("database is locked")
                stop.set()
                return [], ""

            real_due = s._due

            def due(lane=None):
                if stop.is_set():
                    raise SystemExit
                if len(calls) == 1:
                    s.next_run[first] = time.time() - 1
                return real_due(lane)

            s.next_run[first] = time.time() - 1
            a, b, c = _quiet_pipeline()
            with a, b, c, _no_pressure(), \
                    mock.patch("jarvis.service.scheduler.LANE_ERROR_PAUSE_S", 0), \
                    mock.patch("jarvis.service.scheduler.notifications.deliver"), \
                    mock.patch("jarvis.service.scheduler.memory.trim") as trim, \
                    mock.patch.object(s, "_due", side_effect=due), \
                    mock.patch.object(s, "run_once", side_effect=run_once):
                t = threading.Thread(target=s._lane, args=("frequent",), daemon=True)
                t.start()
                t.join(10)
            self.assertEqual(calls, [first, first])
            self.assertEqual(trim.call_count, 2)             # after the failure and the success

    def test_a_request_trims_even_when_closing_the_connection_fails(self):
        from jarvis.web import server
        h = server.Handler.__new__(server.Handler)
        with mock.patch("http.server.BaseHTTPRequestHandler.finish", side_effect=OSError("reset")), \
                mock.patch("jarvis.web.server.memory.trim") as trim:
            with self.assertRaises(OSError):
                h.finish()
        trim.assert_called_once_with()

    def test_serve_caps_arenas_before_starting_any_thread(self):
        from jarvis.web import server
        order = []

        def scheduler(*_a, **_k):
            order.append("scheduler")
            raise RuntimeError("stop before any thread starts")

        with mock.patch("jarvis.web.server.memory.limit_arenas", side_effect=lambda: order.append("arenas")), \
                mock.patch("jarvis.web.server.Scheduler", side_effect=scheduler), \
                mock.patch("jarvis.platform.privilege.drop_ambient"), \
                mock.patch("jarvis.web.server.sdnotify.capture"):
            with self.assertRaises(RuntimeError):
                server.serve(":memory:", 0, ("wsl",))
        self.assertEqual(order, ["arenas", "scheduler"])

if __name__ == "__main__":
    unittest.main()

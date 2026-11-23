"""The live process feed and its stream: read-only, metadata only, bounded,
demand-driven, and never calm when blind.

The Windows helper is replaced by a fake process that plays recorded frames
(the real helper was measured against Win32_Process on 2026-10-23: 299 of 299
shared processes matched on parent, name, session and creation time). The
Linux reader runs against a fake /proc tree.
"""

import importlib.util
import io
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from jarvis.core.paths import load_win_script
from jarvis.platform import procfeed, proclinux
from jarvis.web import procview, server

ROOT = Path(__file__).resolve().parent.parent


class FakeHelper:
    """A helper process that writes `lines` and then ends (or blocks)."""

    def __init__(self, lines, block=False):
        self._lines = [(json.dumps(x) if not isinstance(x, (bytes, str)) else x) for x in lines]
        self._block = threading.Event() if block else None
        self.stdin = io.BytesIO()
        self.closed_stdin = False
        self.killed = False
        self.returncode = None
        self.stdout = self

    def readline(self, limit=-1):
        if self._lines:
            line = self._lines.pop(0)
            return (line if isinstance(line, bytes) else line.encode()) + b"\n"
        if self._block is not None:
            self._block.wait(5)
        self.returncode = 0
        return b""

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self._block is not None:
            self._block.set()
        self.returncode = 0
        return 0

    def kill(self):
        self.killed = True


def _closing(helper):
    original = helper.stdin.close

    def close():
        helper.closed_stdin = True
        original()
    helper.stdin.close = close
    return helper


ROW_A = ["10:1000", 10, 4, "a.exe", 1000, 0.0, 2048, 1]
ROW_B = ["11:2000", 11, 10, "b.exe", 2000, 1.5, 4096, 1]


def wait_for(cond, timeout=10.0):
    # Generous on purpose: these are bounds under a loaded host, not latency
    # claims; a feed that never reaches the state still fails. Monotonic: this
    # host's wall clock steps by ~9 s (WSL clock fight), which made wall-clock
    # waits give up after under a second (measured 2026-10-23).
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


class LinuxReaderTests(unittest.TestCase):
    def make_proc(self, tmp, entries):
        for pid, stat in entries.items():
            d = Path(tmp) / str(pid)
            d.mkdir()
            (d / "stat").write_bytes(stat)
        (Path(tmp) / "self").mkdir()

    def stat(self, pid, comm, ppid, ut, st, start, rss):
        rest = ["S", str(ppid)] + ["0"] * 9 + [str(ut), str(st)] + ["0"] * 6 + [str(start), "0", str(rss)]
        return f"{pid} ({comm}) {' '.join(rest)}".encode()

    def test_parses_names_with_spaces_and_parentheses(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.make_proc(tmp, {7: self.stat(7, "a b) (c", 1, 5, 5, 300, 10)})
            rows = proclinux.read_linux(tmp, hz=100, boot_ms=1_000_000, page_kb=4)
        (row,) = rows.values()
        self.assertEqual(row[:5], ["7:1003000", 7, 1, "a b) (c", 1_003_000])
        self.assertEqual(row[5], 10)          # cumulative ticks until diff()
        self.assertEqual(row[6], 40)

    def test_vanished_and_malformed_entries_are_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.make_proc(tmp, {7: b"garbage without parens", 8: self.stat(8, "ok", 1, 0, 0, 0, 1)})
            (Path(tmp) / "9").mkdir()           # exited between listdir and open
            rows = proclinux.read_linux(tmp, hz=100, boot_ms=0, page_kb=4)
        self.assertEqual([r[1] for r in rows.values()], [8])

    def test_diff_cpu_births_exits_updates_and_pid_reuse(self):
        prev = {"5:100": ["5:100", 5, 1, "x", 100, 0, 1000, -1]}
        proclinux.diff({}, prev, 0.5, 100, 2)
        cur = {"5:100": ["5:100", 5, 1, "x", 100, 50, 1000, -1],
               "5:900": ["5:900", 5, 1, "x", 900, 0, 500, -1]}   # same pid, new process
        added, exited, updated = proclinux.diff(prev, cur, 0.5, 100, 2)
        self.assertEqual([r[0] for r in added], ["5:900"])
        self.assertEqual(exited, [])
        self.assertEqual(updated, [["5:100", 50.0, 1000]])     # 50 ticks / (0.5 s * 100 * 2)
        nxt = {"5:900": ["5:900", 5, 1, "x", 900, 0, 500, -1]}
        _, exited, _ = proclinux.diff(cur, nxt, 0.5, 100, 2)
        self.assertEqual(exited, ["5:100"])

    def test_small_changes_are_not_sent(self):
        prev = {"5:1": ["5:1", 5, 1, "x", 1, 0, 100000, -1]}
        proclinux.diff({}, prev, 0.5, 100, 1)
        cur = {"5:1": ["5:1", 5, 1, "x", 1, 0, 100500, -1]}
        self.assertEqual(proclinux.diff(prev, cur, 0.5, 100, 1)[2], [])


class FeedCase(unittest.TestCase):
    def feed(self, helpers, **kw):
        made = []

        def spawn():
            if not helpers:
                raise OSError("no more helpers")
            h = helpers.pop(0)
            if isinstance(h, Exception):
                raise h
            made.append(_closing(h))
            return h
        f = procfeed.Feed(windows_enabled=True, linux_enabled=False, spawn=spawn, **kw)
        f.made = made
        self.addCleanup(f.stop)
        return f


class FeedTests(FeedCase):
    def test_nothing_runs_until_a_viewer_arrives(self):
        f = self.feed([FakeHelper([], block=True)])
        time.sleep(0.1)
        self.assertFalse(f.running)
        self.assertEqual(f.made, [])
        self.assertEqual(f.status()["sources"]["win"]["state"], "idle")

    def test_frames_build_the_table_and_reach_viewers(self):
        f = self.feed([FakeHelper([
            {"k": "hello", "events": "sysmon"},
            {"k": "snap", "p": [ROW_A]},
            {"k": "d", "t": 1, "a": [ROW_B], "x": [], "u": [["10:1000", 3.0, 3000]]},
            {"k": "ev", "t": 2, "pid": 99, "ppid": 10, "name": "short.exe"},
        ], block=True)])
        f.acquire()
        self.assertTrue(wait_for(lambda: "11:2000" in f.tables["win"]))
        self.assertEqual(f.tables["win"]["10:1000"][5:7], [3.0, 3000])
        src = f.status()["sources"]["win"]
        self.assertEqual((src["state"], src["events"]), ("live", "sysmon"))
        seq, frames = f.snapshot()
        snap = json.loads(frames[0])
        self.assertEqual(sorted(r[0] for r in snap["p"]), ["10:1000", "11:2000"])
        kinds = [json.loads(t)["k"] for _, t in f._ring]
        self.assertIn("ev", kinds)

    def test_only_metadata_crosses_to_the_viewer(self):
        # The helper's 9th field is the image path: kept for the judge, never sent.
        with_path = ROW_A + ["C:\\secret\\path --token=abc"]
        malformed = ["12:3000", "12", 4, "c.exe", 3000, 0.0, 1, 1, "x", "extra"]
        f = self.feed([FakeHelper([
            {"k": "snap", "p": [with_path, ROW_B, malformed]},
            {"k": "ev", "pid": 5, "ppid": 4, "name": "x", "cmd": "secret --token=abc",
             "path": "C:\\secret\\x.exe", "sha256": "ab" * 32},
            {"k": "exec", "cmd": "taskkill /pid 4"},
            "not json at all",
        ], block=True)])
        f.acquire()
        self.assertTrue(wait_for(lambda: any(json.loads(t)["k"] == "ev" for _, t in f._ring)))
        text = " ".join(t for _, t in f._ring) + " ".join(f.snapshot()[1])
        for secret in ("token", "taskkill", "secret", "ab" * 32):
            self.assertNotIn(secret, text)
        self.assertEqual(sorted(f.tables["win"]), ["10:1000", "11:2000"])
        self.assertEqual(f.paths["win"]["10:1000"], "C:\\secret\\path --token=abc")
        snap = json.loads(f.snapshot()[1][0])
        self.assertTrue(all(len(r) == 9 and r[8] is None for r in snap["p"]), "not judged is null")

    def test_helper_exit_is_reported_with_its_reason_and_restarts_are_capped(self):
        helpers = [FakeHelper([{"k": "snap", "p": [ROW_A]}]) for _ in range(procfeed.RESTARTS + 2)]
        f = self.feed(helpers)
        orig = procfeed.Feed._windows_loop

        def fast_loop(self, stop):
            self_wait = stop.wait
            stop.wait = lambda t=None: self_wait(0.01)
            return orig(self, stop)
        procfeed.Feed._windows_loop = fast_loop
        self.addCleanup(setattr, procfeed.Feed, "_windows_loop", orig)
        f.acquire()
        self.assertTrue(wait_for(lambda: "failed" in f.sources["win"]["reason"], timeout=20))
        st = f.status()["sources"]["win"]
        self.assertEqual(st["state"], "unavailable")
        self.assertEqual(len(f.made), procfeed.RESTARTS)
        self.assertEqual(f.tables["win"], {})          # no rows from a dead helper

    def test_helper_that_cannot_start_is_unavailable_not_silent(self):
        f = self.feed([OSError("powershell not found")])
        f.acquire()
        self.assertTrue(wait_for(lambda: f.sources["win"]["state"] == "unavailable"))
        self.assertIn("did not start", f.sources["win"]["reason"])

    def test_a_silent_source_reads_stale(self):
        now = [100.0]
        f = self.feed([FakeHelper([{"k": "snap", "p": [ROW_A]}], block=True)], clock=lambda: now[0])
        f.acquire()
        self.assertTrue(wait_for(lambda: f.sources["win"]["state"] == "live"))
        self.assertEqual(f.status()["sources"]["win"]["state"], "live")
        now[0] += procfeed.STALE_S + 0.1
        self.assertEqual(f.status()["sources"]["win"]["state"], "stale")

    def test_last_viewer_leaving_stops_the_helper_after_the_linger(self):
        old = procfeed.LINGER_S
        procfeed.LINGER_S = 0.2
        self.addCleanup(setattr, procfeed, "LINGER_S", old)
        f = self.feed([FakeHelper([{"k": "snap", "p": [ROW_A]}], block=True)])
        f.acquire()
        self.assertTrue(wait_for(lambda: f._helper is not None))
        helper = f._helper
        f.release()
        self.assertTrue(wait_for(lambda: not f.running))
        self.assertTrue(helper.closed_stdin, "the helper is told to stop by closing stdin")
        self.assertEqual(f.tables["win"], {})
        self.assertEqual(f.sources["win"]["state"], "idle")

    def test_a_viewer_returning_during_the_linger_keeps_the_same_helper(self):
        old = procfeed.LINGER_S
        procfeed.LINGER_S = 1.5
        self.addCleanup(setattr, procfeed, "LINGER_S", old)
        f = self.feed([FakeHelper([{"k": "snap", "p": [ROW_A]}], block=True),
                       FakeHelper([], block=True)])
        f.acquire()
        self.assertTrue(wait_for(lambda: f._helper is not None))
        f.release()
        f.acquire()
        time.sleep(2.0)
        self.assertTrue(f.running)
        self.assertEqual(len(f.made), 1)

    def test_a_lagging_viewer_is_resynchronised_not_left_wrong(self):
        f = self.feed([FakeHelper([], block=True)])
        with f._lock:
            for i in range(procfeed.RING + 5):
                f._push({"k": "status", "i": i})
        self.assertIsNone(f.frames_after(1, 0.01))
        seq, frames = f.frames_after(f._seq - 1, 0.01)
        self.assertEqual(len(frames), 1)


class FakeJudge:
    """Path words from a table, and a hash history that is slow on purpose."""

    def __init__(self, recorded=None):
        self.recorded = recorded or {}
        self.lookups = 0

    def judge(self, host, name, path, sha256=""):
        where = "temp" if "\\temp\\" in path.lower() else ("system" if path else "unknown")
        verdict = "moved" if where == "temp" else ("same" if path else "unknown")
        return [where, verdict, "known" if sha256 else "unknown"]

    def judge_start(self, host, name, path, sha256=""):
        return self.judge(host, name, path, sha256)

    def recorded_hash(self, host, pid, created_ms):
        self.lookups += 1
        return self.recorded.get(pid, "")

    def state(self):
        return {"baseline": "ok"}


def frames_of(feed, kind):
    return [json.loads(t) for _, t in list(feed._ring) if json.loads(t)["k"] == kind]


class IdentityTests(FeedCase):
    def test_verdicts_follow_rows_and_hash_lookups_run_after(self):
        row = ROW_A + ["C:\\Windows\\System32\\a.exe"]
        judge = FakeJudge(recorded={10: "cd" * 32})
        f = self.feed([FakeHelper([{"k": "snap", "p": [row]}], block=True)], identity=judge)
        f.acquire()
        self.assertTrue(wait_for(lambda: f.idents["win"].get("10:1000") == ["system", "same", "known"]))
        words = [i[1] for fr in frames_of(f, "i") for i in fr["i"]]
        self.assertEqual(words[0], ["system", "same", "pending"], "path first, hash after")
        self.assertEqual(json.loads(f.snapshot()[1][0])["p"][0][8], ["system", "same", "known"])
        self.assertNotIn("cd" * 32, " ".join(t for _, t in f._ring))

    def test_a_missing_recorded_hash_is_looked_up_once_not_every_refresh(self):
        judge = FakeJudge()
        f = self.feed([FakeHelper([{"k": "snap", "p": [ROW_A]}], block=True)], identity=judge)
        f.acquire()
        self.assertTrue(wait_for(lambda: (f.idents["win"].get("10:1000") or ["", "", ""])[2] == "unknown"))
        sent = len(frames_of(f, "i"))
        with f._lock:
            f._queue(f._fast, ("row", "win", "10:1000"))     # what a refresh does
        time.sleep(0.5)
        self.assertEqual(judge.lookups, 1)
        self.assertEqual(len(frames_of(f, "i")), sent, "an unchanged verdict is not re-sent")

    def test_a_sysmon_start_lends_its_hash_to_the_row_and_its_event_is_judged(self):
        judge = FakeJudge()
        f = self.feed([FakeHelper([
            {"k": "snap", "p": [ROW_A]},
            {"k": "ev", "t": 5, "pid": 11, "ppid": 10, "name": "b.exe",
             "path": "C:\\Users\\x\\AppData\\Local\\Temp\\b.exe", "sha256": "EF" * 32},
            {"k": "d", "t": 6, "a": [ROW_B + [""]], "x": [], "u": []},
        ], block=True)], identity=judge)
        f.acquire()
        self.assertTrue(wait_for(lambda: f.idents["win"].get("11:2000") == ["temp", "moved", "known"]))
        ev = frames_of(f, "ev")[0]
        self.assertEqual((ev["name"], ev["i"]), ("b.exe", ["temp", "moved", "known"]))
        self.assertNotIn("path", ev)
        self.assertEqual(judge.lookups, 1, "only ROW_A needed the event log")

    def test_a_failing_judge_is_counted_and_the_feed_keeps_going(self):
        class Broken(FakeJudge):
            def judge(self, *a):
                raise RuntimeError("bug")
        f = self.feed([FakeHelper([{"k": "snap", "p": [ROW_A]},
                                   {"k": "d", "t": 1, "a": [ROW_B], "x": [], "u": []}], block=True)],
                      identity=Broken())
        f.acquire()
        self.assertTrue(wait_for(lambda: "11:2000" in f.tables["win"] and f.status()["identity"]["errors"]))
        self.assertEqual(f.sources["win"]["state"], "live")


class HandoffTests(FeedCase):
    def setUp(self):
        old = procfeed.RENEW_S, procfeed.HANDOFF_S
        procfeed.RENEW_S, procfeed.HANDOFF_S = 0.3, 1.0
        self.addCleanup(lambda: (setattr(procfeed, "RENEW_S", old[0]), setattr(procfeed, "HANDOFF_S", old[1])))

    def test_the_successor_takes_over_without_a_gap(self):
        first = FakeHelper([{"k": "snap", "p": [ROW_A]}], block=True)
        second = FakeHelper([{"k": "snap", "p": [ROW_A, ROW_B]}], block=True)
        f = self.feed([first, second, FakeHelper([], block=True)])
        f.acquire()
        self.assertTrue(wait_for(lambda: "11:2000" in f.tables["win"]))
        self.assertIs(f._helper, second)
        self.assertTrue(wait_for(lambda: first.closed_stdin), "the old helper is told to stop")
        states = [json.loads(t)["sources"]["win"]["state"] for _, t in f._ring if json.loads(t)["k"] == "status"]
        self.assertNotIn("unavailable", states)
        self.assertEqual(len(f._restarts["win"]), 1, "a renewal is not a failure")

    def test_a_silent_successor_is_dropped_and_the_current_helper_kept(self):
        first = FakeHelper([{"k": "snap", "p": [ROW_A]}], block=True)
        mute = FakeHelper([], block=True)
        f = self.feed([first, mute])
        f.acquire()
        self.assertTrue(wait_for(lambda: mute.closed_stdin, timeout=10))
        self.assertIs(f._helper, first)
        self.assertFalse(f._active.renewable)
        self.assertEqual(list(f.tables["win"]), ["10:1000"])
        self.assertEqual(f.sources["win"]["state"], "live")

    def test_frames_from_the_replaced_helper_are_ignored(self):
        f = self.feed([FakeHelper([], block=True)])
        old, new = procfeed._Helper(FakeHelper([]), 0), procfeed._Helper(FakeHelper([]), 0)
        with f._lock:
            f._active = new
        old.proc = FakeHelper([{"k": "snap", "p": [ROW_B]}])
        f._pump(old, threading.Event())
        self.assertEqual(f.tables["win"], {})


class FakeFollower:
    def __init__(self, starts, fail=False):
        self._starts, self.fail = starts, fail
        self.opened = self.closed = False

    def open(self):
        if self.fail:
            raise OSError("no journalctl")
        self.opened = True

    def starts(self, stop):
        yield from self._starts
        stop.wait(5)

    def exit_code(self):
        return 0

    def close(self):
        self.closed = True


class LinuxStartsTests(unittest.TestCase):
    def feed(self, follower, rows, **kw):
        tables = [dict(rows)]
        f = procfeed.Feed(windows_enabled=False, linux_enabled=True, follower=lambda: follower,
                          linux_reader=lambda: {k: list(v) for k, v in tables[-1].items()},
                          exe_reader=lambda pid: "", **kw)
        self.addCleanup(f.stop)
        f.tables_seq = tables
        return f

    def test_a_short_lived_start_reaches_viewers_without_its_path_or_hash(self):
        start = {"pid": 77, "ppid": 1, "name": "dropper", "path": "/dev/shm/dropper", "sha256": "aa" * 32}
        f = self.feed(FakeFollower([start]), {})
        f.acquire()
        self.assertTrue(wait_for(lambda: frames_of(f, "ev")))
        ev = frames_of(f, "ev")[0]
        self.assertEqual((ev["h"], ev["pid"], ev["name"]), ("lin", 77, "dropper"))
        self.assertNotIn("shm", json.dumps(ev))
        self.assertEqual(f.sources["lin"]["events"], "sysmon")

    def test_a_root_process_borrows_its_path_from_the_start_event(self):
        start = {"pid": 9, "ppid": 1, "name": "agent", "path": "/usr/sbin/agent", "sha256": ""}
        row = ["9:500", 9, 1, "agent", 500, 0, 100, -1]
        follower = FakeFollower([start])
        f = self.feed(follower, {})
        f.acquire()
        self.assertTrue(wait_for(lambda: frames_of(f, "ev")))
        f.tables_seq.append({"9:500": row})
        self.assertTrue(wait_for(lambda: f.paths["lin"].get("9:500") == "/usr/sbin/agent"))

    def test_a_follower_that_cannot_start_is_reported_and_capped(self):
        f = self.feed(FakeFollower([], fail=True), {})
        orig = procfeed.Feed._linux_starts_loop

        def fast(self, stop):
            real = stop.wait
            stop.wait = lambda t=None: real(0.01)
            return orig(self, stop)
        procfeed.Feed._linux_starts_loop = fast
        self.addCleanup(setattr, procfeed.Feed, "_linux_starts_loop", orig)
        f.acquire()
        self.assertTrue(wait_for(lambda: "failed" in f.sources["lin"]["events"]))
        self.assertEqual(f.sources["lin"]["state"], "live", "the /proc table is unaffected")

    def test_stopping_closes_the_follower(self):
        follower = FakeFollower([])
        f = self.feed(follower, {})
        f.acquire()
        self.assertTrue(wait_for(lambda: f._follower is follower))
        f.stop()
        self.assertTrue(follower.closed)


class ParseStartTests(unittest.TestCase):
    LINE = ('<Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID></System><EventData>'
            '<Data Name="UtcTime">2026-10-24 16:12:47.997</Data><Data Name="ProcessId">1876</Data>'
            '<Data Name="Image">/usr/bin/readlink</Data><Data Name="CommandLine">readlink --secret</Data>'
            '<Data Name="User">chris</Data><Data Name="Hashes">SHA256=4C6117AE99ADF14E90EE49C860CA6F827DB657423D0D0B3E4F6EB29D39DAEBE0</Data>'
            '<Data Name="ParentProcessId">1874</Data></EventData></Event>')

    def test_a_start_gives_ids_path_and_hash_only(self):
        start = proclinux.parse_start(self.LINE)
        self.assertEqual(start, {"pid": 1876, "ppid": 1874, "path": "/usr/bin/readlink", "name": "readlink",
                                 "sha256": "4c6117ae99adf14e90ee49c860ca6f827db657423d0d0b3e4f6eb29d39daebe0"})
        self.assertNotIn("secret", json.dumps(start))

    def test_other_events_and_broken_lines_are_ignored(self):
        self.assertIsNone(proclinux.parse_start(self.LINE.replace("<EventID>1<", "<EventID>3<")))
        self.assertIsNone(proclinux.parse_start(self.LINE.replace(">1876<", ">x<")))
        self.assertIsNone(proclinux.parse_start("garbage"))

    def test_exe_path_of_a_missing_process_is_unknown(self):
        self.assertEqual(proclinux.exe_path(1, proc="/nonexistent"), "")
        self.assertTrue(proclinux.exe_path(os.getpid()))


class StreamTests(unittest.TestCase):
    class Feed:
        def __init__(self, behind=False):
            self.acquired = self.released = 0
            self.behind = behind
            self.snaps = 0

        def acquire(self):
            self.acquired += 1

        def release(self):
            self.released += 1

        def snapshot(self):
            self.snaps += 1
            return 5, ['{"k":"snap","h":"win","p":[]}']

        def frames_after(self, seq, timeout):
            return None if self.behind else (seq + 1, ['{"k":"d"}'])

    def test_snapshot_then_frames_then_release(self):
        feed, out = self.Feed(), []
        t = [0.0]

        def clock():
            t[0] += 1
            return t[0]
        procview.run(feed, out.append, clock=clock, lifetime=3)
        body = b"".join(out)
        self.assertTrue(body.startswith(b"retry: 2000\n\ndata: {\"k\":\"snap\""))
        self.assertIn(b"data: {\"k\":\"d\"}", body)
        self.assertEqual((feed.acquired, feed.released), (1, 1))

    def test_behind_the_ring_means_a_fresh_snapshot(self):
        feed, out = self.Feed(behind=True), []
        t = [0.0]

        def clock():
            t[0] += 1
            return t[0]
        procview.run(feed, out.append, clock=clock, lifetime=3)
        self.assertGreater(feed.snaps, 1)

    def test_a_viewer_that_left_releases_the_feed_even_on_error(self):
        feed = self.Feed()

        def write(chunk):
            raise BrokenPipeError
        with self.assertRaises(BrokenPipeError):
            procview.run(feed, write)
        self.assertEqual(feed.released, 1)
        feed2 = self.Feed()
        procview.run(feed2, lambda c: None, gone=lambda: True)
        self.assertEqual(feed2.released, 1)

    def test_streams_are_bounded(self):
        taken = 0
        while procview.acquire_slot():
            taken += 1
        try:
            self.assertEqual(taken, procview.MAX_STREAMS)
        finally:
            for _ in range(taken):
                procview.release_slot()


class WiringTests(unittest.TestCase):
    def test_page_and_script_are_served_under_the_strict_coverage_policy(self):
        self.assertIn("/procs", server.COVERAGE_ASSETS)
        self.assertIn("/static/procs.js", server.COVERAGE_ASSETS)
        self.assertIn("script-src 'self'", server.Handler.CSP_COVERAGE)
        html = (ROOT / "jarvis/web/static/procs.html").read_text()
        self.assertNotIn("<script>", html)            # no inline script under that policy
        self.assertNotIn("http", html.replace("http-equiv", ""))

    @unittest.skipUnless(importlib.util.find_spec("jarvis.collectors.process.assemblies"),
                         "this tree has no own-assembly collector to register with")
    def test_helper_is_a_recognised_jarvis_script_with_no_sensitive_api(self):
        from jarvis.collectors.process import assemblies
        self.assertIn("procfeed.ps1", assemblies.OWN_SCRIPTS)
        idents, compiles, hashes = assemblies._script_facts("procfeed.ps1")
        self.assertEqual(compiles, 1)
        import hashlib
        launched = hashlib.sha256(load_win_script("procfeed.ps1").encode()).hexdigest()
        self.assertIn(launched, hashes, "the -Command text must match the reviewed hash")
        self.assertEqual(assemblies.sensitive(sorted(idents)), [])
        self.assertEqual(assemblies.offensive(sorted(idents)), [])

    def test_helper_reads_no_command_line_and_takes_no_commands(self):
        text = load_win_script("procfeed.ps1")
        self.assertNotIn("CommandLine", text)
        self.assertIn("(ProcessId|ParentProcessId|Image|UtcTime|Hashes)", text)
        # Paths come from SystemProcessIdInformation by id: no process is opened.
        for verb in ("Kill(", "OpenProcess", "TerminateProcess", "Start-Process", "GetProcessById"):
            self.assertNotIn(verb, text)


if __name__ == "__main__":
    unittest.main()

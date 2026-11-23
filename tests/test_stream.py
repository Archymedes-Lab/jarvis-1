import http.client
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.response import acknowledge
from jarvis.service.schedule import JOBS
from jarvis.web import stream
from jarvis.web.server import Handler
from tests import _apiauth


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


def _pulse(version, **extra):
    return {"ok": True, "version": version, **extra}


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "j.db")

    def _save(self, job, findings, error=""):
        store = Store(self.db)
        try:
            store.save_snapshot(job, findings, 1.0, error)
        finally:
            store.close()

    def test_never_run_collectors_are_blind_not_clean(self):
        pulse = stream.build(self.db, None)
        self.assertTrue(pulse["ok"])
        blind = {b["job"] for b in pulse["blind"]}
        self.assertEqual(blind, set(JOBS))
        self.assertIsNone(pulse["healthy"])   # no scheduler: unknown, never healthy

    def test_failing_collector_is_blind_even_when_fresh(self):
        self._save("scan", [], error="bridge down")
        blind = {b["job"]: b for b in stream.build(self.db, None)["blind"]}
        self.assertTrue(blind["scan"]["error"])

    def test_urgent_findings_listed_worst_first_with_acknowledged_last(self):
        crit = {"severity": "critical", "title": "ransom note", "category": "x"}
        high = {"severity": "high", "title": "odd listener", "category": "x"}
        self._save("hunt", [high, crit, {"severity": "medium", "title": "m"},
                            {"severity": "ok", "title": "clean"}])
        pulse = stream.build(self.db, None)
        self.assertEqual([u["title"] for u in pulse["urgent"]], ["ransom note", "odd listener"])
        self.assertEqual(pulse["worst"], "critical")
        self.assertEqual(pulse["totals"], {"critical": 1, "high": 1, "medium": 1})

        store = Store(self.db)
        try:
            acknowledge.acknowledge(store, crit, "hunt", "owner test", confirmed_by=acknowledge.TERMINAL)
        finally:
            store.close()
        pulse = stream.build(self.db, None)
        self.assertEqual([u["title"] for u in pulse["urgent"]], ["odd listener", "ransom note"])
        self.assertTrue(pulse["urgent"][1]["acknowledged"])

    def test_urgent_items_carry_their_category_for_plain_wording(self):
        self._save("hunt", [{"severity": "high", "title": "odd listener", "category": "remote"},
                            {"severity": "critical", "title": "no category"}])
        by = {u["title"]: u for u in stream.build(self.db, None)["urgent"]}
        self.assertEqual(by["odd listener"]["category"], "remote")
        self.assertEqual(by["no category"]["category"], "")   # absent: empty, never invented

    def test_version_ignores_timestamp_but_tracks_content(self):
        a = stream.build(self.db, None, stamp=1_000_000)
        b = stream.build(self.db, None, stamp=1_000_000)
        self.assertEqual(a["version"], b["version"])
        self._save("hunt", [{"severity": "high", "title": "new"}])
        c = stream.build(self.db, None, stamp=1_000_000)
        self.assertNotEqual(a["version"], c["version"])

    def test_failure_is_reported_not_raised(self):
        with patch("jarvis.web.stream.Store", side_effect=OSError("disk gone")):
            pulse = stream.build(self.db, None)
        self.assertFalse(pulse["ok"])
        self.assertEqual(pulse["error"], "OSError")
        self.assertIn("version", pulse)


class HubTests(unittest.TestCase):
    def test_rebuilds_at_most_once_per_period_for_all_clients(self):
        calls = []
        clock = Clock()
        hub = stream.Hub("db", None, period=5, clock=clock,
                         builder=lambda db, s: calls.append(1) or _pulse(str(len(calls))))
        for _ in range(10):
            hub.latest()
        self.assertEqual(len(calls), 1)
        clock.t = 4.9
        hub.latest()
        self.assertEqual(len(calls), 1)
        clock.t = 5.0
        self.assertEqual(hub.latest()["version"], "2")

    def test_stream_slots_are_bounded_and_returned(self):
        hub = stream.Hub("db", None, max_streams=2, builder=lambda d, s: _pulse("v"))
        self.assertTrue(hub.acquire())
        self.assertTrue(hub.acquire())
        self.assertFalse(hub.acquire())
        hub.release()
        self.assertTrue(hub.acquire())


class RunStreamTests(unittest.TestCase):
    def _run(self, versions, lifetime=100, keepalive=15, period=5):
        """Drive run_stream on a fake clock; each sleep advances it and the
        next hub read returns the next version."""
        clock = Clock()
        seq = iter(versions)
        current = {"v": next(seq)}
        hub = stream.Hub("db", None, period=period, clock=clock,
                         builder=lambda d, s: _pulse(current["v"]))
        out = []

        def sleep(seconds):
            clock.t += seconds
            current["v"] = next(seq, current["v"])

        sent = stream.run_stream(hub, out.append, clock=clock, sleep=sleep,
                                 lifetime=lifetime, keepalive=keepalive)
        return sent, b"".join(out).decode()

    def test_sends_on_connect_and_only_on_change(self):
        sent, text = self._run(["a", "a", "a", "b", "b"], lifetime=40)
        self.assertEqual(sent, 2)
        self.assertTrue(text.startswith("retry: "))
        self.assertEqual(text.count("event: pulse"), 2)
        self.assertIn("id: a\n", text)
        self.assertIn("id: b\n", text)

    def test_keepalive_when_nothing_changes(self):
        sent, text = self._run(["a"], lifetime=40, keepalive=15)
        self.assertEqual(sent, 1)
        self.assertGreaterEqual(text.count(": keepalive"), 2)

    def test_a_beat_is_an_event_the_page_can_see_and_a_keepalive_is_not(self):
        for beat, want in ((False, b": keepalive\n\n"), (True, stream.BEAT)):
            hub = stream.Hub("db", None, builder=lambda d, s: {"version": "same"})
            out, ticks = [], iter(range(0, 1000, 3))
            stop = threading.Event()

            def sleep(_s):
                if len(out) >= 4:
                    stop.set()

            stream.run_stream(hub, out.append, stop=stop, clock=lambda: next(ticks), sleep=sleep,
                              keepalive=5, beat=beat)
            self.assertIn(want, out)
            self.assertEqual(sum(1 for chunk in out if chunk.startswith(b"id:")), 1)   # state sent once
        self.assertTrue(stream.BEAT.startswith(b"event: beat\n"))

    def test_lifetime_bounds_the_stream(self):
        sent, _ = self._run(["a"], lifetime=20)
        self.assertEqual(sent, 1)   # returned instead of looping forever

    def test_departed_client_ends_the_stream(self):
        hub = stream.Hub("db", None, builder=lambda d, s: _pulse("a"))

        def write(_):
            raise BrokenPipeError

        with self.assertRaises(OSError):
            stream.run_stream(hub, write, sleep=lambda s: None)

    def test_hangup_noticed_without_a_failing_write(self):
        hub = stream.Hub("db", None, builder=lambda d, s: _pulse("a"))
        checks = iter([False, False, True])
        sent = stream.run_stream(hub, lambda b: None, gone=lambda: next(checks),
                                 sleep=lambda s: None)
        self.assertEqual(sent, 1)

    def test_peer_closed_on_real_socket(self):
        import socket
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.assertFalse(stream.peer_closed(a))
        b.close()
        self.assertTrue(stream.peer_closed(a))

    def test_frame_is_one_sse_event(self):
        text = stream.frame({"version": "v1", "score": 91, "title": "a\nb"}).decode()
        self.assertTrue(text.endswith("\n\n"))
        data = [line for line in text.splitlines() if line.startswith("data: ")]
        self.assertEqual(len(data), 1)   # newlines in values stay JSON-escaped
        self.assertEqual(json.loads(data[0][6:])["score"], 91)


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.pulse = _pulse("v1", score=91)
        self.hub = stream.Hub("db", None, max_streams=1,
                              builder=lambda d, s: self.pulse)
        old = Handler.hub
        Handler.hub = self.hub
        self.addCleanup(setattr, Handler, "hub", old)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _get(self, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path, headers={**_apiauth.grant(self), **(headers or {})})
        return conn, conn.getresponse()

    def test_pulse_is_plain_json(self):
        conn, r = self._get("/api/pulse")
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.read())["score"], 91)
        conn.close()

    def test_cross_site_stream_refused_before_taking_a_slot(self):
        conn, r = self._get("/api/stream", {"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status, 403)
        conn.close()
        self.assertTrue(self.hub.acquire())     # the only slot is still free
        self.hub.release()

    def test_rebinding_host_refused(self):
        conn, r = self._get("/api/stream", {"Host": "evil.example:8787"})
        self.assertEqual(r.status, 403)
        conn.close()

    def test_stream_delivers_pulse_then_refuses_past_the_bound(self):
        conn, r = self._get("/api/stream", {"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/event-stream"))
        lines = []
        # Monotonic deadlines: this host's wall clock steps by ~9 s (the WSL
        # clock fight), which failed this test about two runs in three while
        # the stream itself was correct (measured 2026-10-23).
        deadline = time.monotonic() + 5
        while "event: pulse" not in lines and time.monotonic() < deadline:
            lines.append(r.fp.readline().decode().rstrip("\n"))
        self.assertIn("event: pulse", lines)

        conn2, r2 = self._get("/api/stream")
        self.assertEqual(r2.status, 503)
        conn2.close()

        r.close()                   # client leaves -> slot returns
        conn.close()
        deadline = time.monotonic() + stream.PERIOD_S + 5
        while not self.hub.acquire():
            self.assertLess(time.monotonic(), deadline, "stream slot never released")
            time.sleep(0.2)
        self.hub.release()


if __name__ == "__main__":
    unittest.main()

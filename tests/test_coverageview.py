import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from jarvis.core.paths import STATIC_DIR
from jarvis.core.store import Store
from jarvis.service import attackmap, coveragemap
from jarvis.service.schedule import JOBS
from jarvis.web import server
from tests import _apiauth


class SourcesTests(unittest.TestCase):
    def test_probe_jobs_win_over_free_text(self):
        self.assertEqual(coveragemap.sources("T1055", "anything — else"), ["sysmon", "memscan"])

    def test_mapped_words_resolve_to_real_jobs_only(self):
        self.assertEqual(coveragemap.sources("T9998", "control / startup — boot and logon autostart"),
                         ["control", "boot"])
        self.assertEqual(coveragemap.sources("T9997", "detect — obfuscated command lines"), ["scan"])
        self.assertEqual(coveragemap.sources("T9999", "nonsense / words — nothing"), [])
        for job in coveragemap.sources("T1014", "hidden / evasion — rootkit detection"):
            self.assertIn(job, JOBS)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "t.db")
        store = Store(self.db)
        store.set_meta(attackmap.META, json.dumps({
            "at": 100, "totals": {"validated": 1, "claimed": 1, "blind": 1, "regressed": 0, "total": 3},
            "tactics": {"execution": {"validated": 1, "claimed": 1, "blind": 1, "regressed": 0, "total": 3}},
            "techniques": [
                {"tid": "T1059", "name": "Interpreter", "tactics": ["execution"], "level": "validated",
                 "evidence": "encoded command; live via scan"},
                {"tid": "T1204", "name": "User Execution", "tactics": ["execution"], "level": "claimed",
                 "evidence": "intrusion — user execution artefacts"},
                {"tid": "T1106", "name": "Native API", "tactics": ["execution"], "level": "blind",
                 "evidence": "hidden — must never be linked while blind"}]}))
        store.save_snapshot("scan", [{"severity": "high", "title": "x"}, {"severity": "low", "title": "y"},
                                     {"severity": "bogus", "title": "z"}])
        store.commit()
        store.close()

    def test_levels_sources_and_collector_state_come_from_the_stored_evidence(self):
        data = coveragemap.build(self.db)
        by_tid = {t["tid"]: t for t in data["techniques"]}
        self.assertEqual(by_tid["T1059"]["sources"][0], "scan")             # its own collector first
        self.assertEqual(by_tid["T1204"]["sources"][0], "intrusion")        # its own collector first
        self.assertEqual(by_tid["T1106"]["sources"], [])          # blind is never drawn as fed
        by_job = {c["job"]: c for c in data["collectors"]}
        self.assertEqual(set(by_job), set(JOBS))
        self.assertEqual(by_job["scan"]["state"], "current")
        self.assertEqual(by_job["scan"]["findings"], {"critical": 0, "high": 1, "medium": 0, "low": 1})
        self.assertEqual(by_job["scan"]["techniques"], ["T1059"])
        self.assertEqual(by_job["hidden"]["state"], "missing")    # no snapshot is not a clean collector
        self.assertEqual(by_job["hidden"]["techniques"], [])
        self.assertEqual(data["totals"]["total"], 3)
        self.assertEqual(data["running"], [])

    def probed_map(self, **row):
        store = Store(self.db)
        tech = {"tid": "T1059", "name": "Interpreter", "tactics": ["execution"],
                "level": "validated", "evidence": "powershell -enc; live via scan",
                "fired": True, "what": "powershell -enc", **row}
        store.set_meta(attackmap.META, json.dumps({
            "at": 100, "totals": {"validated": 1, "claimed": 0, "blind": 0, "regressed": 0, "total": 1},
            "tactics": {"execution": {"validated": 1, "claimed": 0, "blind": 0, "regressed": 0, "total": 1}},
            "techniques": [tech]}))
        store.commit()
        store.close()

    def test_a_validated_tile_follows_its_collector_between_map_measurements(self):
        self.probed_map()
        fresh = coveragemap.build(self.db)
        self.assertEqual(fresh["techniques"][0]["level"], "validated")
        self.assertEqual(fresh["totals"]["validated"], 1)
        later = time.time() + JOBS["scan"][0] * 10 + 600          # the collector went quiet
        stale = coveragemap.build(self.db, now=later)
        tech = stale["techniques"][0]
        self.assertEqual(tech["level"], "claimed")
        self.assertIn("not reporting now", tech["evidence"])
        self.assertEqual((stale["totals"]["validated"], stale["totals"]["claimed"]), (0, 1))
        self.assertEqual(stale["tactics"]["execution"]["validated"], 0)   # numbers match the tiles
        self.assertEqual(stale["totals"]["total"], 1)

    def test_a_probe_that_fired_becomes_validated_once_its_collector_reports(self):
        self.probed_map(level="claimed", evidence="powershell -enc fires, but scan not reporting")
        self.assertEqual(coveragemap.build(self.db)["techniques"][0]["level"], "validated")

    def test_liveness_never_promotes_what_the_probe_did_not_prove(self):
        for row in ({"level": "regressed", "fired": False},
                    {"level": "claimed", "fired": None, "what": None},      # mapped, no probe
                    {"level": "claimed", "fired": False}):
            self.probed_map(**row)
            self.assertEqual(coveragemap.build(self.db)["techniques"][0]["level"], row["level"], row)
        burst = sorted(attackmap.CONTEXT_ONLY)[0]
        self.probed_map(tid=burst, level="claimed")
        self.assertEqual(coveragemap.build(self.db)["techniques"][0]["level"], "claimed")

    def test_a_map_stored_before_probe_results_keeps_its_levels(self):
        later = time.time() + JOBS["scan"][0] * 10 + 600
        data = coveragemap.build(self.db, now=later)            # setUp's rows carry no "fired"
        self.assertEqual({t["tid"]: t["level"] for t in data["techniques"]},
                         {"T1059": "validated", "T1204": "claimed", "T1106": "blind"})
        self.assertEqual(data["totals"], {"validated": 1, "claimed": 1, "blind": 1,
                                          "regressed": 0, "total": 3})

    def test_stale_collector_is_reported_stale_and_running_comes_from_the_scheduler(self):
        scheduler = mock.Mock()
        scheduler.wake_phase.return_value = {"current": ["scan"]}
        later = time.time() + JOBS["scan"][0] * 10 + 600
        data = coveragemap.build(self.db, scheduler, now=later)
        scan = next(c for c in data["collectors"] if c["job"] == "scan")
        self.assertEqual(scan["state"], "stale")
        self.assertTrue(scan["running"])

    def test_unmeasured_map_and_broken_scheduler_are_empty_not_errors(self):
        empty = os.path.join(self.tmp.name, "empty.db")
        Store(empty).close()
        scheduler = mock.Mock()
        scheduler.wake_phase.side_effect = RuntimeError("down")
        data = coveragemap.build(empty, scheduler)
        self.assertEqual((data["techniques"], data["totals"], data["running"]), ([], {}, []))
        self.assertTrue(all(c["state"] == "missing" for c in data["collectors"]))


class UptimeTests(unittest.TestCase):
    NOW = 2_000_000_000.0

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "u.db")
        self.store = Store(self.db)
        self.addCleanup(self.store.close)
        self.interval = JOBS["scan"][0]
        self.n = 0

    def receipts(self, job, start, end, step, coverage="complete"):
        t = start
        while t <= end:
            self.n += 1
            self.store.db.execute(
                "INSERT INTO defender_runs(run_id,job,observed_at,coverage,error,digest,finding_count) "
                "VALUES(?,?,?,?,?,?,0)", (f"r{self.n}", job, t, coverage, "", "d"))
            t += step
        self.store.commit()

    def up(self, job="scan"):
        per, fleet = coveragemap.uptime(self.store, self.NOW)
        return per.get(job), fleet

    def test_unbroken_receipts_read_fully_up(self):
        self.receipts("scan", self.NOW - 3 * 86400, self.NOW, self.interval)
        up, fleet = self.up()
        self.assertEqual(up["pct24"], 1.0)
        self.assertEqual(up["pct7d"], 1.0)
        self.assertEqual(up["longest_gap_s"], 0)
        self.assertEqual(up["buckets"], [1.0] * 24)
        self.assertEqual(fleet["tracked"], 1)

    def test_a_silent_stretch_is_counted_as_down_not_smoothed_over(self):
        # Ran every interval, then nothing for six hours (the WSL VM frozen), then again.
        self.receipts("scan", self.NOW - 86400, self.NOW - 10 * 3600, self.interval)
        self.receipts("scan", self.NOW - 4 * 3600, self.NOW, self.interval)
        up, _ = self.up()
        grace = max(self.interval * 2, self.interval + 300)
        silent = 6 * 3600 - grace
        self.assertAlmostEqual(up["pct24"], 1 - silent / 86400, delta=0.01)
        self.assertAlmostEqual(up["longest_gap_s"], silent, delta=self.interval + 1)
        self.assertEqual(up["buckets"][0], 1.0)
        self.assertLess(min(up["buckets"][14:19]), 0.5)

    def test_partial_and_unavailable_runs_do_not_keep_a_collector_up(self):
        self.receipts("scan", self.NOW - 86400, self.NOW - 3600, self.interval)
        self.receipts("scan", self.NOW - 3600 + 1, self.NOW, self.interval, coverage="partial")
        self.receipts("scan", self.NOW - 3000, self.NOW, self.interval, coverage="unavailable")
        up, _ = self.up()
        self.assertEqual(up["runs24"]["partial"] > 0 and up["runs24"]["unavailable"] > 0, True)
        self.assertLess(up["buckets"][-1], 0.5)
        self.assertLess(up["pct24"], 1.0)

    def test_time_before_the_first_receipt_is_unknown_not_up_or_down(self):
        self.receipts("scan", self.NOW - 2 * 3600, self.NOW, self.interval)
        up, fleet = self.up()
        self.assertEqual(up["buckets"][:21], [None] * 21)
        self.assertEqual(up["pct24"], 1.0)
        self.assertAlmostEqual(up["observed_s"], 2 * 3600, delta=1)
        self.assertEqual(fleet["partial_history"], 1)

    def test_a_collector_that_stopped_decays_and_one_never_run_has_no_figure(self):
        self.receipts("scan", self.NOW - 86400, self.NOW - 12 * 3600, self.interval)
        up, fleet = self.up()
        self.assertLess(up["pct24"], 0.55)
        self.assertEqual(up["buckets"][-1], 0.0)
        per, _ = coveragemap.uptime(self.store, self.NOW)
        self.assertNotIn("hidden", per)
        self.assertEqual(fleet["of"], len(JOBS))

    def test_no_receipts_at_all_is_none_not_a_perfect_score(self):
        per, fleet = coveragemap.uptime(self.store, self.NOW)
        self.assertEqual((per, fleet), ({}, None))

    def test_a_technique_is_up_while_any_one_of_its_collectors_is(self):
        # scan covers the first half of the day, control the second; together they cover it all.
        ci = JOBS["control"][0]
        self.receipts("scan", self.NOW - 86400, self.NOW - 43200, self.interval)
        self.receipts("control", self.NOW - 43200, self.NOW, ci)
        _per, _fleet, segs = coveragemap._collect(self.store, self.NOW)
        both = coveragemap._technique_uptime(["scan", "control"], segs, self.NOW)
        alone = coveragemap._technique_uptime(["scan"], segs, self.NOW)
        self.assertGreater(both, 0.95)
        self.assertLess(alone, 0.6)
        self.assertGreater(both, alone)

    def test_a_technique_with_no_collector_or_no_history_has_no_uptime(self):
        self.receipts("scan", self.NOW - 3600, self.NOW, self.interval)
        _per, _fleet, segs = coveragemap._collect(self.store, self.NOW)
        self.assertIsNone(coveragemap._technique_uptime([], segs, self.NOW))
        self.assertIsNone(coveragemap._technique_uptime(["hidden"], segs, self.NOW))

    def test_build_serves_it_and_refreshes_after_the_cache_window(self):
        self.receipts("scan", self.NOW - 86400, self.NOW, self.interval)
        first = coveragemap.build(self.db, now=self.NOW)
        scan = next(c for c in first["collectors"] if c["job"] == "scan")
        self.assertEqual(scan["uptime"]["pct24"], 1.0)
        self.assertIsNone(next(c for c in first["collectors"] if c["job"] == "hidden")["uptime"])
        self.assertEqual(first["uptime"]["tracked"], 1)
        later = self.NOW + 6 * 3600
        again = coveragemap.build(self.db, now=later)
        self.assertLess(next(c for c in again["collectors"] if c["job"] == "scan")["uptime"]["pct24"], 0.8)


class LiveTests(unittest.TestCase):
    """The compact state the page is kept live by (coveragemap.live)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, "live.db")
        self.store = Store(self.db)
        self.addCleanup(self.store.close)
        self.store.set_meta(attackmap.META, json.dumps({
            "at": 100, "totals": {}, "tactics": {"execution": {}},
            "techniques": [{"tid": "T1059", "name": "Interpreter", "tactics": ["execution"],
                            "level": "validated", "evidence": "x; live via scan",
                            "fired": True, "what": "x"}]}))
        self.store.save_snapshot("scan", [{"severity": "high", "title": "a"},
                                          {"severity": "critical", "title": "b"},
                                          {"severity": "low", "title": "c"}])
        self.store.commit()
        coveragemap._live_cache.clear()

    def test_every_collector_is_listed_with_its_run_state_and_serious_findings(self):
        state = coveragemap.live(self.db)
        self.assertTrue(state["ok"])
        self.assertEqual(set(state["c"]), set(JOBS))
        ts, freshness, serious = state["c"]["scan"]
        self.assertEqual((freshness, serious), ("current", 2))
        self.assertAlmostEqual(ts, time.time(), delta=5)
        self.assertEqual(state["c"]["hidden"], [0, "missing", 0])      # never ran: not quiet
        self.assertEqual(state["map_at"], 100)
        self.assertLess(len(json.dumps(state)), 6000)                  # it has to stay cheap to push

    def test_version_tracks_change_and_ignores_the_clock(self):
        now = time.time()
        first = coveragemap.live(self.db, now=now)
        self.assertEqual(coveragemap.live(self.db, now=now + 1)["version"], first["version"])
        # A second run, possibly stamped in the same second as the first.
        self.store.save_snapshot("scan", [{"severity": "high", "title": "a"}], duration=1.25)
        self.store.commit()
        again = coveragemap.live(self.db, now=now + 2)
        self.assertNotEqual(again["version"], first["version"])
        self.assertEqual(again["c"]["scan"][2], 1)                     # counted again for the new run

    def test_levels_move_when_a_pane_would_change_between_map_measurements(self):
        fresh = coveragemap.live(self.db)
        stale = coveragemap.live(self.db, now=time.time() + JOBS["scan"][0] * 10 + 600)
        self.assertEqual(stale["c"]["scan"][1], "stale")
        self.assertNotEqual(stale["levels"], fresh["levels"])
        self.assertNotEqual(stale["version"], fresh["version"])

    def test_running_comes_from_the_scheduler_and_a_broken_one_is_empty(self):
        scheduler = mock.Mock()
        scheduler.wake_phase.return_value = {"current": ["scan"]}
        self.assertEqual(coveragemap.live(self.db, scheduler)["running"], ["scan"])
        scheduler.wake_phase.side_effect = RuntimeError("down")
        self.assertEqual(coveragemap.live(self.db, scheduler)["running"], [])

    def test_ingest_is_the_sensor_figure_or_absent_never_invented(self):
        self.assertIsNone(coveragemap.live(self.db)["ingest"])
        for value, want in (
                ({"at": 50, "stages": {"ingested": {"detail": "141 events committed to the history"}}},
                 {"events": 141, "at": 50}),
                ({"at": 50, "stages": {"ingested": {"detail": "nothing new"}}}, None),
                ("not json", None)):
            self.store.set_meta("native_delivery", value if isinstance(value, str) else json.dumps(value))
            self.store.commit()
            self.assertEqual(coveragemap.live(self.db)["ingest"], want, value)

    def test_an_unreadable_database_is_a_failed_state_not_an_exception_or_a_new_file(self):
        missing = os.path.join(self.tmp.name, "absent.db")
        state = coveragemap.live(missing)
        self.assertFalse(state["ok"])
        self.assertIn("version", state)
        self.assertFalse(os.path.exists(missing))                      # read-only: it creates nothing

    def test_it_reads_through_a_read_only_connection(self):
        before = os.stat(self.db).st_mtime_ns
        with mock.patch.object(coveragemap, "Store") as store:
            coveragemap.live(self.db)
            store.assert_not_called()
        self.assertEqual(os.stat(self.db).st_mtime_ns, before)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db = os.path.join(self.tmp.name, "t.db")
        Store(db).close()
        handler = type("H", (server.Handler,), {"db_path": db, "scheduler": None,
                                                "log_message": lambda *a: None})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://localhost:{self.httpd.server_address[1]}"

    def get(self, path):
        try:
            req = urllib.request.Request(self.base + path, headers=_apiauth.grant(self))
            with urllib.request.urlopen(req, timeout=10) as res:
                return res.status, dict(res.headers), res.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_page_scripts_and_api_are_served_same_origin_only(self):
        for path in server.COVERAGE_ASSETS:
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            csp = headers["Content-Security-Policy"]
            self.assertIn("script-src 'self'", csp)
            self.assertNotIn("https:", csp)
            self.assertNotIn("script-src 'unsafe-inline'", csp)
            self.assertTrue(body)
        status, _headers, body = self.get("/api/coverage")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["collectors"]), len(JOBS))

    def stream(self, headers=None):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=5)
        conn.request("GET", "/api/coverage/stream",
                     headers={**_apiauth.grant(self), **(headers or {})})
        self.addCleanup(conn.close)
        return conn.getresponse()

    def test_live_state_is_served_and_streamed_within_bounds(self):
        status, _headers, body = self.get("/api/coverage/live")
        self.assertEqual(status, 200)
        self.assertEqual(set(json.loads(body)["c"]), set(JOBS))

        self.assertEqual(self.stream({"Sec-Fetch-Site": "cross-site"}).status, 403)

        open_streams = []
        beat = mock.patch.object(coveragemap, "LIVE_BEAT_S", 0.3)
        beat.start()
        self.addCleanup(beat.stop)
        for _ in range(coveragemap.LIVE_STREAMS):
            res = self.stream({"Sec-Fetch-Site": "same-origin"})
            self.assertEqual(res.status, 200)
            self.assertTrue(res.getheader("Content-Type").startswith("text/event-stream"))
            open_streams.append(res)
        # Monotonic: the wall clock here steps by ~9 s (WSL clock fight).
        lines, deadline = [], time.monotonic() + 5
        while "event: pulse" not in lines and time.monotonic() < deadline:
            lines.append(open_streams[0].fp.readline().decode().rstrip("\n"))
        self.assertIn("event: pulse", lines)
        # Nothing changes in this empty database, so the next thing sent is the
        # heartbeat the page uses to tell quiet from dead.
        while "event: beat" not in lines and time.monotonic() < deadline:
            lines.append(open_streams[0].fp.readline().decode().rstrip("\n"))
        self.assertIn("event: beat", lines)
        self.assertEqual(lines.count("event: pulse"), 1)   # the state itself was not re-sent
        self.assertEqual(self.stream().status, 503)        # every slot taken: refused, not queued
        for res in open_streams:
            res.close()

    def test_the_page_has_the_controls_its_script_drives(self):
        page = self.get("/coverage")[2].decode()
        script = self.get("/static/coverage.js")[2].decode()
        import re
        for ident in sorted(set(re.findall(r"\$\('([a-z]+)'\)", script))):
            self.assertIn(f'id="{ident}"', page, ident)
        self.assertIn('data-theme="light"', page)           # both themes are styled
        self.assertIn("prefers-reduced-motion", page)

    def test_page_loads_no_inline_or_foreign_script(self):
        _status, _headers, body = self.get("/coverage")
        page = body.decode()
        self.assertEqual(page.count("<script"), 2)
        self.assertIn('<script src="/static/session.js"></script>', page)
        self.assertIn('<script type="module" src="/static/coverage.js"></script>', page)
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)

    def test_vendored_engine_matches_its_pin_and_a_modified_one_is_refused(self):
        name, _ctype, digest = server.COVERAGE_ASSETS["/static/vendor/three.module.min.js"]
        with open(STATIC_DIR / name, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest)
        tampered = dict(server.COVERAGE_ASSETS)
        tampered["/static/vendor/three.module.min.js"] = (name, _ctype, "0" * 64)
        with mock.patch.object(server, "COVERAGE_ASSETS", tampered):
            status, _headers, body = self.get("/static/vendor/three.module.min.js")
        self.assertEqual(status, 500)
        self.assertIn(b"pinned hash", body)

    def test_leaflet_as_the_release_build_ships_it_is_still_served(self):
        """The build removes leaflet's sourceMappingURL comment (the release policy denies it),
        which changes the file's hash; the shipped copy must still pass the pin or /geo has no map."""
        route = "/static/vendor/leaflet/leaflet.js"
        name, ctype, _digest = server.COVERAGE_ASSETS[route]
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
        import build_server
        raw = (STATIC_DIR / name).read_bytes().replace(bytes([13, 10]), bytes([10]))
        shipped = build_server.SOURCE_MAP_COMMENT.sub(b"", raw)
        self.assertNotIn(b"sourceMappingURL=", shipped)
        self.assertIn(hashlib.sha256(shipped).hexdigest(), server.COVERAGE_ASSETS[route][2])
        self.assertIn(hashlib.sha256(raw).hexdigest(), server.COVERAGE_ASSETS[route][2])

    def test_unknown_static_path_is_not_served(self):
        self.assertEqual(self.get("/static/../server.py")[0], 404)
        self.assertEqual(self.get("/static/dashboard.html")[0], 404)


if __name__ == "__main__":
    unittest.main()

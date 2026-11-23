"""The Link Plane: no connection is silent without a recorded reconnect or
an exhausted budget that names the owner (docs/architecture/LINK-PLANE-PROMPT.md).

    L2  violations() is empty under every modelled failure sequence
    L3  at most BUDGET attempts per window, with backoff; every attempt recorded
    L4  last_ok moves only on fresh good evidence; a failed attempt never rewrites it
    L6  no action during a hold (cold start, resume grace, owner pause)
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from jarvis.service import links
from jarvis.service.links import (
    BACKOFF,
    BUDGET,
    DEGRADED,
    NA,
    SILENT,
    UP,
    WINDOW_S,
    LinkPlane,
)

T0 = 1_800_000_000.0


def evidence(now, **over):
    """A healthy Windows machine, every link just verified."""
    snaps = {job: {"ts": now - 10, "error": "", "findings": []}
             for job in ("bridge", "input_hook", "native", "sysmon", "sysmon_linux")}
    ev = {"windows": True, "snapshots": snaps,
          "lanes": {"fast": 5.0, "frequent": 10.0, "main": 20.0, "bulk": 60.0},
          "tasks": {"health-monitor": now - 30, "reviver": now - 5,
                    "connectivity-guard": now - 40, "elevated-broker": now - 600},
          "dead_man": {"configured": True, "failures": 0, "last_ok": now - 30},
          "channels": ["notify"],
          "phone": {"applicable": True, "paired": 1, "pending": 0, "relay_ok": True,
                    "relay_error": "", "phones": [{"dev": "abc", "name": "iPhone", "state": "active",
                                                   "push": True, "last_seen": now - 100}]}}
    ev.update(over)
    return ev


class EvaluationTests(unittest.TestCase):
    def test_every_link_is_up_on_a_healthy_machine(self):
        plane = LinkPlane()
        plane.tick(evidence(T0), T0)
        self.assertEqual({s["state"] for s in plane.statuses.values()}, {UP})
        self.assertEqual(plane.violations(T0), [])
        self.assertEqual(plane.findings(T0)[0]["severity"], "ok")

    def test_windows_links_are_not_applicable_without_a_windows_host(self):
        plane = LinkPlane()
        plane.tick(evidence(T0, windows=False, lanes={}, tasks={}), T0)
        self.assertEqual(plane.statuses["windows-bridge"]["state"], NA)
        self.assertEqual(plane.statuses["reviver"]["state"], NA)
        self.assertEqual(plane.statuses["lane:fast"]["state"], NA)
        self.assertEqual(plane.statuses["sysmon-linux"]["state"], UP)

    def test_missing_evidence_is_silent_never_up(self):
        ev = evidence(T0)
        del ev["snapshots"]["native"]
        plane = LinkPlane()
        plane.tick(ev, T0)
        st = plane.statuses["native-sensor"]
        self.assertEqual(st["state"], SILENT)
        self.assertEqual(st["reason"], "no result on record")

    def test_a_failing_fresh_result_is_degraded_and_rotation_tightens(self):
        ev = evidence(T0)
        ev["snapshots"]["sysmon"]["error"] = "collector coverage incomplete"
        ev["snapshots"]["sysmon_linux"]["findings"] = [
            {"title": "Sysmon journal rotated past the last read position", "severity": "medium"}]
        plane = LinkPlane()
        plane.tick(ev, T0)
        self.assertEqual(plane.statuses["sysmon-windows"]["state"], DEGRADED)
        self.assertEqual(plane.statuses["sysmon-linux"]["state"], DEGRADED)
        self.assertTrue(plane.statuses["sysmon-linux"]["tighten"])
        # Degraded is a low finding, not a reconnect: the job is still running.
        self.assertEqual(plane.tick(ev, T0 + 1)["actions"], [])

    def test_only_a_fresh_rotation_degrades_linux_sysmon(self):
        ev = evidence(T0)
        rot = {"title": "Sysmon journal rotated past the last read position", "severity": "medium"}
        ev["snapshots"]["sysmon_linux"]["findings"] = [{**rot, "seen_at": T0 - 86000}]
        plane = LinkPlane()
        plane.tick(ev, T0)
        self.assertEqual(plane.statuses["sysmon-linux"]["state"], UP)       # yesterday's hit
        ev["snapshots"]["sysmon_linux"]["findings"] = [{**rot, "seen_at": T0 - 10}]
        plane.tick(ev, T0 + 1)
        self.assertEqual(plane.statuses["sysmon-linux"]["state"], DEGRADED)  # this pass

    def test_task_state_files(self):
        ev = evidence(T0, tasks={"reviver": T0 - 120, "health-monitor": 0})
        plane = LinkPlane()
        plane.tick(ev, T0)
        self.assertEqual(plane.statuses["reviver"]["state"], SILENT)
        self.assertEqual(plane.statuses["health-monitor"]["state"], SILENT)
        self.assertEqual(plane.statuses["connectivity-guard"]["state"], NA)
        self.assertEqual(plane.statuses["elevated-broker"]["state"], NA)

    def test_alert_channels_and_dead_man(self):
        plane = LinkPlane()
        plane.tick(evidence(T0, channels=[], dead_man={"configured": True, "failures": 5,
                                                       "last_error": "HTTP 503"}), T0)
        self.assertEqual(plane.statuses["alert-channels"]["state"], SILENT)
        self.assertEqual(plane.statuses["dead-man"]["state"], SILENT)
        plane.tick(evidence(T0, dead_man={}), T0 + 1)
        self.assertEqual(plane.statuses["dead-man"]["state"], NA)

    def test_phone_relay_states(self):
        plane = LinkPlane()
        plane.tick(evidence(T0, phone={"applicable": True, "paired": 0}), T0)
        self.assertEqual(plane.statuses["phone-relay"]["state"], DEGRADED)
        self.assertIn("no phone is paired", plane.statuses["phone-relay"]["reason"])
        plane.tick(evidence(T0, phone={"applicable": True, "paired": 1, "relay_ok": False,
                                       "relay_error": "URLError", "phones": []}), T0 + 1)
        self.assertEqual(plane.statuses["phone-relay"]["state"], SILENT)
        plane.tick(evidence(T0, phone={"applicable": True, "paired": 1, "pending": 1, "relay_ok": True,
                                       "phones": []}), T0 + 2)
        self.assertIn("not activated on the relay", plane.statuses["phone-relay"]["reason"])
        deaf = {"applicable": True, "paired": 1, "pending": 0, "relay_ok": True,
                "phones": [{"dev": "abc", "name": "Pixel", "state": "active", "push": True,
                            "last_seen": T0 - 3 * 86400}]}
        plane.tick(evidence(T0, phone=deaf), T0 + 3)
        self.assertEqual(plane.statuses["phone-relay"]["state"], DEGRADED)
        self.assertIn("Pixel", plane.statuses["phone-relay"]["reason"])
        nopush = {"applicable": True, "paired": 1, "pending": 0, "relay_ok": True,
                  "phones": [{"dev": "abc", "name": "Pixel", "state": "active", "push": False,
                              "last_seen": T0 - 10}]}
        plane.tick(evidence(T0, phone=nopush), T0 + 4)
        self.assertEqual(plane.statuses["phone-relay"]["state"], UP)
        self.assertIn("without push", plane.statuses["phone-relay"]["note"])


class CoverageTests(unittest.TestCase):
    def test_link_findings_never_mark_the_watchdogs_run_partial(self):
        from jarvis.core import incidents
        plane = LinkPlane()
        now = T0 + 300
        ev = evidence(now, channels=[], tasks={"reviver": T0 - 900})
        ev["snapshots"]["bridge"]["ts"] = T0 - 900
        plane.tick(ev, now)
        found = plane.findings(now)
        self.assertTrue(any(f["severity"] != "ok" for f in found))
        self.assertTrue(all(f.get("about_collector") for f in found if f["severity"] != "ok"))
        self.assertEqual(incidents.coverage_status(found), "complete")
        about = {f["title"]: f["about_collector"] for f in found if f["severity"] != "ok"}
        self.assertEqual(about["connection silent: windows-bridge"], "bridge")
        self.assertEqual(about["connection lost: alert-channels"], "link:alert-channels")


class ReconnectPolicyTests(unittest.TestCase):
    """A bridge that stays dead for two hours: attempts, backoff, exhaustion,
    the owner finding, and the invariant at every tick."""

    def _dead_bridge(self, now):
        ev = evidence(now)
        ev["snapshots"]["bridge"] = {"ts": T0 - 10, "error": "", "findings": []}
        return ev

    def test_bounded_attempts_with_backoff_then_exhausted(self):
        plane = LinkPlane()
        attempts = []
        now = T0
        while now < T0 + 2 * 3600:
            now += 20.0
            result = plane.tick(self._dead_bridge(now), now)
            self.assertEqual(plane.violations(now), [], f"violation at +{now - T0:.0f}s")
            for link, action in result["actions"]:
                attempts.append(now)
                plane.attempted(link.name, action, "no live interop socket under /run/WSL", now)
        # Three attempts in the first hour; after that the budget is spent and
        # the plane says so instead of hammering.
        first_hour = [t for t in attempts if t < T0 + WINDOW_S]
        self.assertEqual(len(first_hour), BUDGET)
        gaps = [b - a for a, b in zip(first_hour, first_hour[1:])]
        self.assertTrue(all(g >= BACKOFF[i + 1] for i, g in enumerate(gaps)), gaps)
        st = plane.statuses["windows-bridge"]
        self.assertTrue(st["exhausted"])
        titles = {f["title"]: f for f in plane.findings(now)}
        key = "connection lost: windows-bridge (reconnect budget used)"
        self.assertIn(key, titles)
        self.assertEqual(titles[key]["severity"], "high")
        self.assertIn("wsl --shutdown", titles[key]["detail"])
        # The window slides: an hour after the first attempt, a new one is allowed.
        self.assertLessEqual(len(attempts), BUDGET * 2 + 1)

    def test_recovery_clears_attempts_and_exhaustion(self):
        plane = LinkPlane()
        now = T0 + 200
        plane.tick(self._dead_bridge(now), now)
        plane.attempted("windows-bridge", links.INTEROP, "", now)
        plane.attempted("windows-bridge", links.INTEROP, "", now + 200)
        plane.attempted("windows-bridge", links.INTEROP, "", now + 900)
        plane.tick(self._dead_bridge(now + 901), now + 901)
        self.assertTrue(plane.statuses["windows-bridge"]["exhausted"])
        plane.tick(evidence(now + 1000), now + 1000)
        st = plane.statuses["windows-bridge"]
        self.assertEqual(st["state"], UP)
        self.assertFalse(st["exhausted"])
        self.assertEqual(st["attempts"], 0)
        self.assertEqual(st["last_ok"], now + 1000 - 10)

    def test_a_decided_action_never_reported_back_becomes_a_violation(self):
        plane = LinkPlane()
        now = T0 + 300
        result = plane.tick(self._dead_bridge(now), now)
        self.assertEqual(len(result["actions"]), 1)
        self.assertEqual(plane.violations(now), [])
        plane.tick(self._dead_bridge(now + 60), now + 60)
        self.assertEqual(plane.violations(now + 60), [])
        plane.tick(self._dead_bridge(now + links.PENDING_GRACE_S + 1), now + links.PENDING_GRACE_S + 1)
        self.assertEqual(plane.violations(now + links.PENDING_GRACE_S + 1), ["windows-bridge"])

    def test_hold_suppresses_actions_but_not_evaluation(self):
        plane = LinkPlane()
        now = T0 + 300
        result = plane.tick(self._dead_bridge(now), now, hold=True)
        self.assertEqual(result["actions"], [])
        self.assertEqual(plane.statuses["windows-bridge"]["state"], SILENT)
        # No attempt was possible, so it is not a violation either: the hold
        # is the daemon's own cold start or resume grace.
        result = plane.tick(self._dead_bridge(now + 20), now + 20)
        self.assertEqual([link.name for link, _ in result["actions"]], ["windows-bridge"])

    def test_links_without_an_action_are_findings_never_violations(self):
        plane = LinkPlane()
        now = T0
        for _ in range(10):
            now += 60
            plane.tick(evidence(now, channels=[], lanes={"fast": 400.0, "main": 20.0, "bulk": 60.0}), now)
            self.assertEqual(plane.violations(now), [])
        titles = {f["title"]: f["severity"] for f in plane.findings(now)}
        self.assertEqual(titles["connection lost: alert-channels"], "high")
        self.assertEqual(titles["connection lost: lane:fast"], "high")

    def test_last_ok_never_moves_on_failure(self):
        plane = LinkPlane()
        plane.tick(evidence(T0), T0)
        ok = plane.statuses["reviver"]["last_ok"]
        for i in range(1, 40):
            now = T0 + i * 20
            plane.tick(evidence(now, tasks={"reviver": T0 - 10}), now)
            for link, action in plane.tick(evidence(now, tasks={"reviver": T0 - 10}), now)["actions"]:
                plane.attempted(link.name, action, "task did not start", now)
        self.assertEqual(ok, T0 - 5)                       # the evidence time, not the clock
        self.assertEqual(plane.statuses["reviver"]["last_ok"], ok)
        self.assertEqual(plane.statuses["reviver"]["state"], SILENT)
        self.assertEqual(plane.statuses["reviver"]["last_attempt"]["error"], "task did not start")

    def test_state_round_trips_and_stays_bounded(self):
        plane = LinkPlane()
        now = T0 + 300
        plane.tick(self._dead_bridge(now), now)
        for i in range(20):
            plane.attempted("windows-bridge", links.INTEROP, "x" * 400, now + i)
        raw = plane.dump()
        self.assertLessEqual(len(raw), links.STATE_MAX_BYTES)
        again = LinkPlane().load(raw)
        self.assertEqual(again.state["links"]["windows-bridge"]["attempts"],
                         plane.state["links"]["windows-bridge"]["attempts"][-BUDGET:])
        self.assertEqual(LinkPlane().load("not json").state["links"], {})
        self.assertEqual(LinkPlane().load("").state["links"], {})


class EvidenceGatheringTests(unittest.TestCase):
    def test_relay_probe_is_rate_limited_and_cached_in_state(self):
        plane = LinkPlane()
        calls = []

        def phone(now):
            calls.append(now)
            return {"applicable": True, "paired": 1, "pending": 0, "relay_ok": False,
                    "relay_error": "URLError", "phones": []}

        with patch("jarvis.platform.host.has_windows", return_value=False), \
             patch("jarvis.response.alert.load_conf", return_value={}):
            ev1 = links.gather_evidence({}, T0, plane=plane, windows=False, phone=phone)
            ev2 = links.gather_evidence({}, T0 + 60, plane=plane, windows=False, phone=phone)
            ev3 = links.gather_evidence({}, T0 + links.RELAY_PROBE_EVERY_S + 1, plane=plane,
                                        windows=False, phone=phone)
        self.assertEqual(len(calls), 2)
        self.assertEqual(ev1["phone"]["relay_ok"], False)
        self.assertEqual(ev2["phone"], ev1["phone"])
        # The first failure's time is kept so silence is measured from it.
        self.assertEqual(ev3["phone"]["relay_since"], T0)
        self.assertTrue(plane.dirty)

    def test_gather_never_raises_and_reads_task_files(self):
        plane = LinkPlane()
        with tempfile.TemporaryDirectory() as tmp:
            reviver = os.path.join(tmp, "reviver.json")
            with open(reviver, "w") as fh:
                json.dump({"checkedAt": int(T0) - 3}, fh)
            broken = os.path.join(tmp, "broken.json")
            with open(broken, "w") as fh:
                fh.write("{not json")
            with patch("jarvis.service.supervisors.REVIVER_STATE", reviver), \
                 patch("jarvis.service.supervisors.health_monitor_state_path", return_value=broken), \
                 patch("jarvis.service.connectivity.STATE", os.path.join(tmp, "absent.json")), \
                 patch("jarvis.platform.broker.installed", return_value=False), \
                 patch("jarvis.response.alert.load_conf", side_effect=OSError("boom")):
                ev = links.gather_evidence({}, T0, plane=plane, windows=True,
                                           phone=lambda now: {"applicable": False, "reason": "test"})
        self.assertEqual(ev["tasks"]["reviver"], int(T0) - 3)
        self.assertEqual(ev["tasks"]["health-monitor"], 0)      # present, unreadable: silent
        self.assertNotIn("connectivity-guard", ev["tasks"])      # absent: not applicable
        self.assertEqual(ev["channels"], [])
        # The Windows state files are cached for a minute, then re-read.
        with patch("jarvis.service.supervisors.read_state", side_effect=AssertionError("read")), \
             patch("jarvis.response.alert.load_conf", return_value={}):
            ev2 = links.gather_evidence({}, T0 + 30, plane=plane, windows=True,
                                        phone=lambda now: {"applicable": False, "reason": "test"})
        self.assertEqual(ev2["tasks"], ev["tasks"])
        with patch("jarvis.service.supervisors.read_state", return_value=None), \
             patch("jarvis.service.supervisors.health_monitor_state_path", return_value="/nonexistent"), \
             patch("jarvis.service.supervisors.REVIVER_STATE", "/nonexistent-2"), \
             patch("jarvis.service.connectivity.STATE", "/nonexistent-3"), \
             patch("jarvis.platform.broker.installed", return_value=False), \
             patch("jarvis.response.alert.load_conf", return_value={}):
            ev3 = links.gather_evidence({}, T0 + links.TASK_CACHE_S + 1, plane=plane, windows=True,
                                        phone=lambda now: {"applicable": False, "reason": "test"})
        self.assertEqual(ev3["tasks"], {})

    def test_a_dead_lane_thread_is_silent_and_the_watchdogs_view_inherits_lane_ages(self):
        class Dead:
            def is_alive(self):
                return False

        class Sched:
            fast_thread = Dead()
            bulk_thread = None

            def is_alive(self):
                return True

            def lane_age(self, lane):
                return 12.0

        plane = LinkPlane()
        with patch("jarvis.response.alert.load_conf", return_value={}):
            ev = links.gather_evidence({}, T0, scheduler=Sched(), plane=plane, windows=False,
                                       phone=lambda now: {"applicable": False, "reason": "t"})
        plane.tick(ev, T0)
        self.assertEqual(plane.statuses["lane:fast"]["state"], SILENT)
        self.assertEqual(plane.statuses["lane:fast"]["reason"], "lane thread died")
        self.assertEqual(plane.statuses["lane:main"]["state"], UP)
        self.assertEqual(plane.statuses["lane:bulk"]["state"], NA)
        # The watchdogs job (no scheduler handle) reads the persisted lane ages.
        other = LinkPlane().load(plane.dump())
        with patch("jarvis.response.alert.load_conf", return_value={}):
            ev2 = links.gather_evidence({}, T0 + 30, plane=other, windows=False,
                                        phone=lambda now: {"applicable": False, "reason": "t"})
        self.assertEqual(ev2["lanes"]["fast"], float("inf"))
        self.assertEqual(ev2["lanes"]["main"], 12.0)
        # A supervisor that stopped ticking makes every lane read as silent.
        with patch("jarvis.response.alert.load_conf", return_value={}):
            ev3 = links.gather_evidence({}, T0 + 2000, plane=other, windows=False,
                                        phone=lambda now: {"applicable": False, "reason": "t"})
        self.assertGreater(ev3["lanes"]["main"], 900)

    def test_relay_probe_reports_only_reachability(self):
        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b"{}"

        seen = {}

        def opener(req, timeout):
            seen["url"] = req.full_url
            seen["method"] = req.get_method()
            seen["timeout"] = timeout
            return Resp()

        self.assertEqual(links.relay_probe("https://relay.example/", opener), "")
        self.assertEqual(seen, {"url": "https://relay.example/v1/vapid", "method": "GET",
                                "timeout": links.RELAY_PROBE_TIMEOUT_S})

        def down(req, timeout):
            raise OSError("no route")

        self.assertEqual(links.relay_probe("https://relay.example", down), "OSError")


class SchedulerIntegrationTests(unittest.TestCase):
    """The scheduler ticks the plane from supervise_once, persists its state
    and runs actions off the supervisor thread."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = os.path.join(self._tmp.name, "s.db")

    def test_supervise_once_ticks_persists_and_dispatches(self):
        from jarvis.core.store import Store
        from jarvis.service.scheduler import Scheduler
        sched = Scheduler(self.db, ("wsl", "win"))
        sched.started_at = time.time() - 10_000            # past the cold-start hold
        sched.cold_start_pending = set()
        performed = []
        sched._link_action = lambda link, action: performed.append((link.name, action)) or ""
        now = time.time()
        snaps = {job: {"ts": now - 5, "error": "", "findings": []}
                 for job in ("input_hook", "native", "sysmon", "sysmon_linux")}
        snaps["bridge"] = {"ts": now - 1000, "error": "", "findings": []}
        ev = evidence(now, snapshots=snaps)
        with patch("jarvis.service.links.gather_evidence", return_value=ev):
            sched.supervise_once(snaps)
            deadline = time.monotonic() + 5
            while not performed and time.monotonic() < deadline:
                time.sleep(0.05)
            deadline = time.monotonic() + 5
            while sched._link_busy.locked() and time.monotonic() < deadline:
                time.sleep(0.05)
        self.assertEqual(performed, [("windows-bridge", links.INTEROP)])
        st = sched.links.statuses["windows-bridge"]
        self.assertEqual(st["state"], SILENT)
        store = Store(self.db)
        try:
            saved = json.loads(store.get_meta(links.META, "{}"))
        finally:
            store.close()
        self.assertEqual(len(saved["links"]["windows-bridge"]["attempts"]), 1)
        self.assertIn("links", sched.reliability_status(snaps))
        self.assertEqual(sched.reliability_status(snaps)["links"]["silent"], ["windows-bridge"])
        # A new process seeds from the persisted state.
        again = Scheduler(self.db, ("wsl", "win"))
        self.assertEqual(len(again.links.state["links"]["windows-bridge"]["attempts"]), 1)

    def test_hold_during_resume_grace_and_cold_start(self):
        from jarvis.service.scheduler import Scheduler
        sched = Scheduler(self.db, ("wsl",))
        now = time.time()
        self.assertTrue(sched._links_hold(now))             # cold start
        sched.cold_start_pending = set()
        self.assertFalse(sched._links_hold(now))
        sched.resumed_at = now - 10
        self.assertTrue(sched._links_hold(now))
        sched.resumed_at = now - links.RESUME_GRACE_S - 1
        self.assertFalse(sched._links_hold(now))

    def test_queue_action_forces_the_job_and_task_action_is_bounded(self):
        from jarvis.service import schedule as schedule_mod
        from jarvis.service.scheduler import Scheduler
        sched = Scheduler(self.db, ("wsl", "win"))
        # The schedule is derived from this host's domains; a plain Linux CI
        # runner has no Windows "native" job, so give the scheduler one.
        with patch.dict("jarvis.service.scheduler.JOBS", {"native": schedule_mod.ALL_JOBS["native"]}):
            self.assertEqual(sched._link_action(links.BY_NAME["native-sensor"], links.QUEUE), "")
        self.assertIn("native", sched.forced)
        with patch.dict("jarvis.service.scheduler.JOBS", clear=True):
            self.assertEqual(sched._link_action(links.BY_NAME["native-sensor"], links.QUEUE), "unknown job")
        scripts = []
        with patch("jarvis.platform.windows.ps_json",
                   side_effect=lambda script, timeout=60: scripts.append(script) or {"ok": False, "error": "Access is denied"}):
            err = sched._link_action(links.BY_NAME["reviver"], links.TASK)
        self.assertEqual(err, "Access is denied")
        self.assertIn("$n='jarvis reviver'", scripts[0])
        self.assertIn("$stop=$true", scripts[0])          # no age known: silent long enough
        self.assertIn("Stop-ScheduledTask", scripts[0])
        self.assertNotIn("Unregister", scripts[0])
        # Merely late (inside twice the budget): start only, never stop a running loop.
        sched.links.statuses["reviver"] = {"age": 70.0}
        with patch("jarvis.platform.windows.ps_json",
                   side_effect=lambda script, timeout=60: scripts.append(script) or {"ok": True}):
            self.assertEqual(sched._link_action(links.BY_NAME["reviver"], links.TASK), "")
        self.assertIn("$stop=$false", scripts[1])
        with patch("jarvis.platform.windows.ps_json", return_value=None):
            self.assertEqual(sched._link_action(links.BY_NAME["reviver"], links.TASK),
                             "PowerShell gave no answer")


class OutageRecordTests(unittest.TestCase):
    def test_note_spools_a_link_event(self):
        from jarvis.service import outages
        with tempfile.TemporaryDirectory() as tmp:
            rec = outages.OutageRecorder(spool_dir=tmp, log_root=os.path.join(tmp, "log"))
            records = rec.note("link:reviver", "reconnect", T0, action="task", outcome="ok")
        self.assertEqual(records[0]["subject"], "link:reviver")
        self.assertEqual(records[0]["outcome"], "ok")


if __name__ == "__main__":
    unittest.main()

"""The root-owned restart gate (scripts/repair/jarvis-restart-gate) and how the
restart autopsy trusts its records.

Gate invariants:
    G1  a restart is refused unless the gate itself observes the stated fault:
        unit-down while systemd says the unit runs, or health-silent while the
        daemon answers its health endpoint, is refused
    G2  bounded: at most MAX_PER_HOUR automatic restarts an hour
    G3  owner restarts need a person at a terminal
    G4  the decision is recorded before acting; failing to record refuses
    G5  only the fixed argument shape is accepted
Autopsy side:
    A1  a gate restart is explained only by an "allowed" gate record carrying
        the InvocationID of the instance that stopped
    A2  a gate log that root does not own, or that others can write, is not
        trusted
"""

import http.server
import importlib.machinery
import importlib.util
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from jarvis.collectors.host import restarts as R
from tests.test_restarts import INV, T, judge, proc, restart_job, tail

GATE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "repair" / "jarvis-restart-gate"


def load_gate():
    loader = importlib.machinery.SourceFileLoader("jarvis_restart_gate", str(GATE_PATH))
    spec = importlib.util.spec_from_loader("jarvis_restart_gate", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


G = load_gate()


def never():
    raise AssertionError("the health probe must not run for this decision")


class Decide(unittest.TestCase):
    def test_unit_down_is_refused_while_systemd_says_it_runs(self):
        for state in ("active", "activating", "reloading"):
            self.assertEqual(G.decide("wake-watchdog", "unit-down", state, never, 0, False)[0], "refused")

    def test_unit_down_is_allowed_when_it_is_down_or_unreadable(self):
        for state in ("inactive", "failed", "deactivating", ""):
            self.assertEqual(G.decide("wake-watchdog", "unit-down", state, never, 0, False)[0], "allowed")

    def test_health_silent_is_refused_while_the_daemon_answers(self):
        self.assertEqual(G.decide("reviver", "health-silent", "active", lambda: True, 0, False),
                         ("refused", "the daemon answers its health endpoint and reports itself live"))

    def test_health_silent_is_allowed_when_it_does_not_answer(self):
        self.assertEqual(G.decide("reviver", "health-silent", "active", lambda: False, 0, False)[0], "allowed")
        self.assertEqual(G.decide("reviver", "health-silent", "failed", never, 0, False)[0], "allowed")

    def test_rate_limit(self):
        self.assertEqual(G.decide("reviver", "unit-down", "failed", never, G.MAX_PER_HOUR, False)[0],
                         "rate-limited")
        self.assertEqual(G.decide("reviver", "unit-down", "failed", never, G.MAX_PER_HOUR - 1, False)[0],
                         "allowed")

    def test_owner_needs_a_terminal_and_both_owner_words(self):
        self.assertEqual(G.decide("owner", "owner", "active", never, 99, True)[0], "allowed")
        self.assertEqual(G.decide("owner", "owner", "active", never, 0, False)[0], "refused")
        self.assertEqual(G.decide("reviver", "owner", "active", never, 0, True)[0], "refused")
        self.assertEqual(G.decide("owner", "unit-down", "failed", never, 0, True)[0], "refused")


class Main(unittest.TestCase):
    def test_only_the_fixed_shape_is_accepted(self):
        for argv in (["g"], ["g", "--actor", "reviver"],
                     ["g", "--actor", "reviver", "--reason", "unit-down", "--x", "y"],
                     ["g", "--actor", "attacker", "--reason", "unit-down"],
                     ["g", "--actor", "reviver", "--reason", "because"],
                     ["g", "--reason", "unit-down", "--reason", "unit-down"]):
            self.assertEqual(G.main(argv), 2, argv)

    def test_refuses_without_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        self.assertEqual(G.main(["g", "--actor", "reviver", "--reason", "unit-down"]), 1)

    def test_record_appends_durably_and_failure_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "gate.jsonl")
            G.record({"ts": 1, "decision": "allowed"}, log)
            G.record({"ts": 2, "decision": "refused"}, log)
            with open(log) as fh:
                self.assertEqual([json.loads(x)["ts"] for x in fh], [1, 2])
            with self.assertRaises(OSError):
                G.record({"ts": 3}, os.path.join(d, "missing-dir", "gate.jsonl"))

    def test_recent_allowed_counts_automatic_restarts_in_the_last_hour(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "gate.jsonl")
            with open(log, "w") as fh:
                for rec in ({"ts": 500, "decision": "allowed", "actor": "reviver"},
                            {"ts": 4000, "decision": "allowed", "actor": "reviver"},
                            {"ts": 4100, "decision": "refused", "actor": "reviver"},
                            {"ts": 4200, "decision": "allowed", "actor": "owner"}):
                    fh.write(json.dumps(rec) + "\n")
                fh.write("{not json\n")
            self.assertEqual(G.recent_allowed(4300, log), 1)

    def test_lineage_reads_this_process(self):
        names = G.lineage(os.getpid())
        self.assertTrue(names and names[0].startswith("python"), names)


class HealthProbe(unittest.TestCase):
    def serve(self, status, body):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_port}/api/health"

    def test_a_degraded_503_that_reports_live_is_alive(self):
        url = self.serve(503, json.dumps({"service": "JARVIS", "live": True, "healthy": False}).encode())
        self.assertTrue(G.is_alive(url, 5))

    def test_answering_but_not_live_is_not_alive(self):
        url = self.serve(503, json.dumps({"service": "JARVIS", "live": False}).encode())
        self.assertFalse(G.is_alive(url, 5))

    def test_another_service_or_garbage_is_not_alive(self):
        self.assertFalse(G.is_alive(self.serve(200, b'{"service": "other", "live": true}'), 5))
        self.assertFalse(G.is_alive(self.serve(200, b"<html>"), 5))

    def test_nothing_listening_is_not_alive(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertFalse(G.is_alive(f"http://127.0.0.1:{port}/api/health", 2))


def gate_lineage(t=T):
    return [proc(t - 6, 600, "/usr/bin/sudo", "sudo -n /usr/local/sbin/jarvis-restart-gate --actor reviver "
                 "--reason health-silent", ppid=26677, guid="{sudo}"),
            proc(t - 5, 601, "/usr/bin/python3.12", "/usr/bin/python3 -I /usr/local/sbin/jarvis-restart-gate "
                 "--actor reviver --reason health-silent", ppid=600, user="root", guid="{gate}",
                 parent_guid="{sudo}", parent_image="/usr/bin/sudo"),
            proc(t - 0.1, 602, "/usr/bin/systemctl", "/usr/bin/systemctl restart jarvis.service", ppid=601,
                 user="root", cwd="/", parent_guid="{gate}", parent_image="/usr/bin/python3.12")]


class AutopsyTrustsOnlyRootGateRecords(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "gate.jsonl")
        self.addCleanup(self.dir.cleanup)
        self.orig = R.gate_record

    def tearDown(self):
        R.gate_record = self.orig

    def use_log(self, records, uid=0, mode=0o100644):
        with open(self.log, "w") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        fake = lambda p: SimpleNamespace(st_uid=uid, st_mode=mode)   # noqa: E731
        R.gate_record = lambda inv: self.orig(inv, self.log, fake)

    def test_allowed_record_for_this_instance_explains_it(self):
        self.use_log([{"ts": T - 5, "actor": "reviver", "reason": "health-silent", "decision": "allowed",
                       "why": "running but did not answer its health endpoint twice", "invocation": INV}])
        out, ledger, _ = judge(restart_job(), gate_lineage() + tail())
        self.assertEqual((ledger[0]["verdict"], ledger[0]["actor"]), ("explained", "reviver via restart gate"))
        self.assertEqual(out, [])

    def test_record_for_another_instance_does_not(self):
        self.use_log([{"ts": T - 5, "actor": "reviver", "decision": "allowed", "invocation": "0" * 32}])
        out, ledger, _ = judge(restart_job(), gate_lineage() + tail())
        self.assertEqual(ledger[0]["verdict"], "unexplained")
        self.assertEqual(out[0]["severity"], "high")

    def test_a_refused_record_does_not(self):
        self.use_log([{"ts": T - 5, "actor": "reviver", "decision": "refused", "invocation": INV}])
        _out, ledger, _ = judge(restart_job(), gate_lineage() + tail())
        self.assertEqual(ledger[0]["verdict"], "unexplained")

    def test_a_log_the_desktop_user_owns_or_can_write_is_not_trusted(self):
        good = [{"ts": T - 5, "actor": "reviver", "decision": "allowed", "invocation": INV}]
        for uid, mode in ((1000, 0o100644), (0, 0o100666), (0, 0o100664)):
            self.use_log(good, uid=uid, mode=mode)
            _out, ledger, _ = judge(restart_job(), gate_lineage() + tail())
            self.assertEqual(ledger[0]["verdict"], "unexplained", (uid, oct(mode)))
            self.assertIn("cannot be trusted", ledger[0]["evidence"])

    def test_a_missing_gate_log_is_unexplained(self):
        R.gate_record = lambda inv: self.orig(inv, os.path.join(self.dir.name, "absent.jsonl"))
        _out, ledger, _ = judge(restart_job(), gate_lineage() + tail())
        self.assertEqual(ledger[0]["verdict"], "unexplained")
        self.assertIn("does not exist", ledger[0]["evidence"])


if __name__ == "__main__":
    unittest.main()


class GateAwareRestarters(unittest.TestCase):
    """The restarters try the gate first; without it their fallback must still
    be attributed, and only to the restarter the command names."""

    def gated(self, actor, t=T):
        cmd = ("bash -lc if [ -x /usr/local/sbin/jarvis-restart-gate ]; then exec sudo -n "
               f"/usr/local/sbin/jarvis-restart-gate --actor {actor} --reason health-silent; fi; "
               "systemctl restart jarvis.service 2>/dev/null || sudo -n systemctl restart jarvis.service")
        return [proc(t - 3, 26680, "/usr/bin/bash", cmd, ppid=26677, guid="{bash}"),
                proc(t - 3, 26680, "/usr/bin/sudo", "sudo -n systemctl restart jarvis.service", ppid=26677,
                     guid="{sudo}"),
                proc(t - 0.04, 26764, "/usr/bin/systemctl", "systemctl restart jarvis.service", ppid=26762,
                     user="root")]

    def test_fallback_is_attributed_to_the_named_restarter(self):
        _out, ledger, _ = judge(restart_job(), self.gated("reviver") + tail(),
                                lambda: ([("reviver", T - 2, "active but silent for 95s")], ""))
        self.assertEqual((ledger[0]["verdict"], ledger[0]["actor"]), ("explained", "reviver"))

    def test_a_claim_by_a_different_restarter_does_not_count(self):
        _out, ledger, _ = judge(restart_job(), self.gated("reviver") + tail(),
                                lambda: ([("wake-watchdog", T - 2, "inactive")], ""))
        self.assertEqual(ledger[0]["verdict"], "unexplained")

    def test_the_shipped_scripts_use_exactly_the_recognised_form(self):
        root = GATE_PATH.parent.parent.parent
        for script, actor in (("jarvis-wake-watchdog.ps1", "wake-watchdog"), ("quickstart.ps1", "quickstart")):
            text = (root / script).read_text(encoding="utf-8-sig")
            cmd = text.split("--exec bash -lc '", 1)[1].split("'", 1)[0]
            self.assertTrue(R.WINDOWS_GATED_RE.match("bash -lc " + cmd), script)
            self.assertIn(f"--actor {actor} ", cmd)
        reviver = (root / "jarvis-reviver.ps1").read_text(encoding="utf-8-sig")
        line = next(x for x in reviver.splitlines() if x.strip().startswith("$cmd = "))
        cmd = line.split('"', 1)[1].rsplit('"', 1)[0]
        for reason in ("unit-down", "health-silent"):
            self.assertTrue(R.WINDOWS_GATED_RE.match("bash -lc " + cmd.replace("$reason", reason)))

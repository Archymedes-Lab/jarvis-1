"""Dashboard wiring: continuity systems on the page, functionally tested.

/api/state must carry the new systems with the shapes the page renders;
an endpoint that drops them silently would leave the new cards dark while
everything looks fine. /api/geo must carry the accuracy-aware view.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from jarvis.core.store import Store
from jarvis.service.scheduler import Scheduler
from jarvis.web.server import Handler, build_state
from tests import _apiauth


class DashboardStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "state.db")
        store = Store(self.path)
        store.save_snapshot("scan", [], 0.1, "")
        store.close()
        self.scheduler = Scheduler(self.path, ("wsl",))

    def test_state_carries_continuity_with_shapes_the_page_renders(self):
        state = build_state(self.path, self.scheduler)
        cont = state["continuity"]
        self.assertIn("freshness", cont["invariants"])
        self.assertIn("pressured", cont["governor"])
        self.assertIn("reason", cont["governor"])
        self.assertIsInstance(cont["activity"], list)

    def test_activity_chains_are_bounded_for_the_page(self):
        findings = [{
            "host": "win", "job": "sysmon", "severity": "high",
            "title": f"finding {i}", "subject_id": "edge-1",
            "last_seen": 1000.0 + i} for i in range(20)]
        store = Store(self.path)
        try:
            store.save_snapshot("sysmon", findings, 0.1, "")
        finally:
            store.close()
        state = build_state(self.path, self.scheduler)
        chains = state["continuity"]["activity"]
        self.assertEqual(len(chains), 1)
        self.assertLessEqual(len(chains[0]["members"]), 6)

    def test_state_survives_an_empty_store(self):
        empty = str(Path(self.tmp.name) / "empty.db")
        Store(empty).close()
        sched = Scheduler(empty, ("wsl",))
        state = build_state(empty, sched)
        self.assertIn("continuity", state)
        self.assertEqual(state["continuity"]["activity"], [])

    def test_http_state_serves_continuity(self):
        handler = Handler.__new__(Handler)
        handler.db_path = self.path
        handler.scheduler = self.scheduler
        handler.headers = {"Host": "localhost:8787", **_apiauth.grant(self)}
        handler._send = Mock()
        handler.path = "/api/state"
        handler.do_GET()
        status, body = handler._send.call_args.args
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIn("invariants", payload["continuity"])
        self.assertIn("activity", payload["continuity"])

    def test_http_geo_serves_view(self):
        handler = Handler.__new__(Handler)
        handler.db_path = self.path
        handler.scheduler = self.scheduler
        handler.headers = {"Host": "localhost:8787", **_apiauth.grant(self)}
        handler._send = Mock()
        handler.path = "/api/geo"
        handler.do_GET()
        status, body = handler._send.call_args.args
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIn(payload["view"]["mode"], ("street", "city", "globe"))

    def test_state_reads_current_accelerator_probe(self):
        store = Store(self.path)
        try:
            store.set_meta("accelerator_probe_v2",
                           json.dumps({"functional": True, "openvino": {
                               "validation": {"ok": True,
                                              "execution_devices": ["GPU.0"]}}}))
            store.commit()
        finally:
            store.close()
        state = build_state(self.path, self.scheduler)
        accel = state["performance"]["accelerator"]
        self.assertTrue(accel.get("functional"))
        self.assertEqual(accel["openvino"]["validation"]["execution_devices"],
                         ["GPU.0"])


if __name__ == "__main__":
    unittest.main()

"""Phases 2/3/4/7 regression checks: temporal feed, shared state, runtime, ML worker.

Load-bearing invariants: one ordered feed serves many consumers without
rescans; one expensive read serves many collectors; Rust absence never
breaks the engine; GPU is used only when measured with shared-RAM
headroom intact.
"""
import tempfile
import threading
import time
import unittest
from unittest import mock

from jarvis.core import mlworker, runtime, state, temporal
from jarvis.core.store import Store
from jarvis.service import protection as protection_mod


def _ev(seq, category, action, **kw):
    ev = {"seq": seq, "category": category, "action": action,
          "host": "win", "time": "2026-09-20T10:00:00Z"}
    ev.update(kw)
    return ev


class TemporalFeedTests(unittest.TestCase):
    def test_full_taxonomy_moves_shared_projection(self):
        events = [
            _ev(1, "process", "start",
                process={"pid": 1, "guid": "{a}", "image": "a.exe"}),
            _ev(2, "file", "create", target={"path": r"C:\x\a.lnk"}),
            _ev(3, "file", "delete", target={"path": r"C:\x\old.tmp"}),
            _ev(4, "registry", "value_set", target={"key": r"HKLM\Run\X"}),
            _ev(5, "driver", "load", target={"path": r"C:\d.sys"}),
            _ev(6, "wmi", "filter"), _ev(7, "wmi", "consumer"),
            _ev(8, "wmi", "binding"),
            _ev(9, "protection", "disabled"),
            _ev(10, "malware", "detected"),
            _ev(11, "task", "registered", target={"name": "X"}),
            _ev(12, "sensor", "error"),
            _ev(13, "process", "image_load"),
        ]
        out = temporal.reduce(events)
        self.assertIn(r"C:\x\a.lnk", out["files"])
        self.assertIn(r"C:\x\old.tmp", out["file_deletes"])
        self.assertIn(r"HKLM\Run\X", out["registry"])
        self.assertIn(r"C:\d.sys", out["drivers"])
        self.assertEqual(sum(out["wmi"].values()), 3)
        self.assertEqual(out["protection"]["disabled"], 1)
        self.assertEqual(out["malware"]["detected"], 1)
        self.assertEqual(out["sensors"]["error"], 1)
        self.assertEqual(out["proc_signals"]["process:image_load"], 1)
        self.assertEqual(out["counts"]["sensor:error"], 1)

    def test_detectors_share_one_feed_without_rescan(self):
        events = [
            _ev(1, "process", "start",
                process={"pid": 1, "guid": "{a}", "image": "a.exe"}),
            _ev(2, "file", "create",
                target={"path": r"C:\Users\x\AppData\Roaming\Startup\a.lnk"}),
            _ev(3, "task", "registered", target={"name": "Updater"}),
        ]
        proj = temporal.reduce(events)
        found = temporal.detectors(events, proj)
        kinds = {f["detector"] for f in found}
        self.assertIn("persistence-chain-shape", kinds)
        for f in found:
            self.assertTrue(f["seqs"])
            self.assertIn(f["severity"], ("high", "medium", "low"))

    def test_protection_disabled_detector_names_evidence(self):
        events = [_ev(4, "protection", "disabled")]
        found = temporal.detectors(events)
        self.assertTrue(any(f["detector"] == "protection-disabled"
                            for f in found))

    def test_project_sorts_by_seq(self):
        proc = {"pid": 1, "guid": "{z}", "image": "z.exe"}
        out = temporal.project([_ev(2, "process", "exit", process=proc),
                                _ev(1, "process", "start", process=proc)])
        self.assertEqual(out["alive"], {})


class SharedStateTests(unittest.TestCase):
    def tearDown(self):
        state.clear()

    def test_socket_table_shared_across_consumers(self):
        state.clear()
        calls = []

        def _read():
            calls.append(1)
            return {1: {"state": "LISTEN"}}
        first = state.get_socket_table(_read)
        second = state.get_socket_table(_read)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)
        self.assertEqual(state.stats()["socket_hits"], 1)

    def test_generic_provider_shares_one_read(self):
        state.clear()
        calls = []

        def _read():
            calls.append(1)
            return {"v": 1}
        self.assertEqual(state.get("net:test", _read), {"v": 1})
        self.assertEqual(state.get("net:test", _read), {"v": 1})
        self.assertEqual(len(calls), 1)

    def test_linux_socket_table_uses_shared_cache(self):
        from jarvis.platform import linux as linux_mod
        state.clear()
        first = linux_mod.socket_table()
        stats = state.stats()
        self.assertGreaterEqual(stats["socket_misses"], 1)
        second = linux_mod.socket_table()
        self.assertEqual(first, second)

    def test_simultaneous_consumers_share_one_cold_read(self):
        state.clear()
        calls = []
        barrier = threading.Barrier(3)

        def _read():
            calls.append(1)
            time.sleep(0.02)
            return {1: {"state": "LISTEN"}}

        def _consumer():
            barrier.wait()
            state.get_socket_table(_read)

        threads = [threading.Thread(target=_consumer) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=1)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(calls), 1)


class RuntimeBridgeTests(unittest.TestCase):
    def test_metrics_never_raise_and_name_runtime(self):
        out = runtime.metrics()
        self.assertIn(out.get("runtime"), ("rust", "python"))
        self.assertIn("pressured", out)

    def test_defer_contract_matches_governor(self):
        from jarvis.core import governor as governor_mod
        for job, pressured in (("intel", True), ("scan", True),
                               ("intel", False)):
            out = runtime.should_defer(job, pressured)
            self.assertEqual(out["defer"],
                             governor_mod.should_defer(job, pressured))

    def test_rust_binary_is_optional(self):
        with mock.patch.object(runtime, "_RUNTIME_CANDIDATES", ()):
            out = runtime.metrics()
        self.assertEqual(out["runtime"], "python")
        self.assertEqual(out["rust_status"], "binary_absent")

    def test_nonzero_rust_probe_falls_back_with_visible_status(self):
        subprocess_result = mock.Mock(
            returncode=3, stdout="false\n", stderr="failure")
        with mock.patch.object(runtime, "binary", return_value="/tmp/runtime"), \
                mock.patch.object(runtime.subprocess, "run",
                                  return_value=subprocess_result):
            out = runtime.should_defer("intel", True)
        self.assertEqual(out["runtime"], "python")
        self.assertTrue(out["defer"])
        self.assertEqual(out["rust_status"], "nonzero_exit")

    def test_invalid_rust_metrics_do_not_override_runtime_identity(self):
        subprocess_result = mock.Mock(
            returncode=0,
            stdout='{"runtime":"forged","pressured":"yes"}', stderr="")
        with mock.patch.object(runtime, "binary", return_value="/tmp/runtime"), \
                mock.patch.object(runtime.subprocess, "run",
                                  return_value=subprocess_result):
            out = runtime.metrics()
        self.assertEqual(out["runtime"], "python")
        self.assertEqual(out["rust_status"], "invalid_output")

    def test_rust_store_persists_and_reopens(self):
        if not runtime.available():
            self.skipTest("optional Rust binary is not built")
        event = {"v": 1, "id": "event-1", "host": "win", "sensor": "test",
                 "channel": "test", "generation": "g1", "time": "now",
                 "source": "test", "category": "process", "action": "start",
                 "record": 1}
        with tempfile.TemporaryDirectory() as tmp:
            written = runtime.persist([event], root=tmp)
            verified = runtime.verify_store(root=tmp)
        self.assertTrue(written["ok"])
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["segments"], 1)
        self.assertEqual(verified["last_seq"], 1)


class MLWorkerTests(unittest.TestCase):
    def setUp(self):
        mlworker.clear()

    def _inv(self, gpu=True, ollama=True):
        return {"openvino": {"installed": gpu,
                             "devices": ["CPU", "GPU"] if gpu else ["CPU"],
                             "validation": {"ok": gpu}},
                "ollama": {"reachable": ollama, "models": []}}

    def test_unmeasured_gpu_falls_back_to_cpu(self):
        out = mlworker.submit("embeddings", {"text": "hello world"},
                              inventory=self._inv(gpu=False),
                              mem_available_mb=8000.0)
        self.assertEqual(out["backend"], "cpu")
        self.assertIn("vector", out)

    def test_no_runtime_uses_deterministic_path(self):
        out = mlworker.submit("anomaly_scoring",
                              {"value": 10.0, "median": 0.0, "mad": 1.0},
                              inventory=self._inv(gpu=False, ollama=False))
        self.assertEqual(out["backend"], "none")
        self.assertGreaterEqual(out["score"], 0.0)

    def test_pressure_defers_waitable_work_with_bound(self):
        out = mlworker.submit("embeddings", {"text": "x"},
                              inventory=self._inv(),
                              mem_available_mb=8000.0,
                              governor_pressured=True)
        self.assertEqual(out["backend"], "deferred")
        self.assertEqual(mlworker.stats()["queued"], 1)
        drained = mlworker.drain()
        self.assertEqual(drained["queued"], 0)
        self.assertEqual(drained["executed"], 0)
        self.assertIn("resubmission", drained["reason"])

    def test_queue_sheds_rather_than_growing_unbounded(self):
        for _ in range(mlworker.QUEUE_LIMIT + 5):
            mlworker.submit("embeddings", {"text": "x"},
                            inventory=self._inv(), mem_available_mb=8000.0,
                            governor_pressured=True)
        self.assertLessEqual(mlworker.stats()["queued"],
                             mlworker.QUEUE_LIMIT)
        self.assertGreaterEqual(mlworker.stats()["dropped"], 1)

    def test_anomaly_never_equates_load_with_compromise(self):
        out = mlworker.submit("anomaly_scoring",
                              {"value": 95.0, "median": 20.0, "mad": 5.0},
                              inventory=self._inv(gpu=False),
                              mem_available_mb=8000.0)
        self.assertIn("supporting evidence", out["reason"])

    def test_validated_gpu_result_is_used(self):
        measured = {"score": 0.65, "reason": "validated GPU graph",
                    "execution_devices": ["GPU.0"]}
        with mock.patch.object(mlworker, "_try_openvino_gpu",
                               return_value=measured):
            out = mlworker.submit("tracking_classifier",
                                  {"url": "https://x.example/login",
                                   "signals": "beacon canvas"},
                                  inventory=self._inv(),
                                  mem_available_mb=8000.0, model_mb=100.0)
        self.assertEqual(out["backend"], "gpu")
        self.assertEqual(out["execution_devices"], ["GPU.0"])

    def test_gpu_execution_failure_falls_back_loudly(self):
        with mock.patch.object(mlworker, "_try_openvino_gpu",
                               return_value=None):
            out = mlworker.submit("tracking_classifier",
                                  {"url": "https://x.example/login"},
                                  inventory=self._inv(),
                                  mem_available_mb=8000.0)
        self.assertEqual(out["backend"], "cpu")
        self.assertIn("failed execution", out["reason"])

    def test_service_composition_wires_gpu_executor(self):
        from jarvis.service import jobs  # noqa: F401
        self.assertTrue(mlworker.stats()["gpu_executor_configured"])


    def test_health_exposes_runtime_and_mlworker(self):
        class _Sched:
            hosts = ("wsl",)
            current = None
            fast_current = None
            heartbeat = time.time()
            fast_heartbeat = time.time()

            def is_alive(self):
                return True

            def fast_alive(self):
                return True

            def reliability_status(self, snapshots=None):
                return {"summary": {"recovering": []}}

        with tempfile.TemporaryDirectory() as tmp:
            db_path = tmp + "/t.db"
            store = Store(db_path)
            try:
                store.save_snapshot("scan", [], 0.1, "")
            finally:
                store.close()
            state = protection_mod.health(db_path, _Sched(), stamp=time.time())
        self.assertIn("runtime", state)
        self.assertIn("mlworker", state)
        self.assertIn(state["runtime"].get("runtime"), ("rust", "python"))


if __name__ == "__main__":
    unittest.main()

"""Execution Intelligence regression checks: success, failure, interruption."""

import unittest

from jarvis.core.execution import adapter, escalate, impossible, kernel_contract
from jarvis.core.execution.presence import ProcessPresence, reconcile


def _verified(pid=5172):
    return ProcessPresence(boot_id="boot-1", pid=pid, guid="g-5172",
                           kernel_create_seen=True, etw_start_seen=True,
                           sysmon_create_seen=True, snapshot_seen=True,
                           thread_activity_seen=True, image_activity_seen=True,
                           cpu_activity_seen=True, network_activity_seen=True)


class PresenceTests(unittest.TestCase):
    def test_verified_process_needs_creation_snapshot_and_activity(self):
        verdict = reconcile(_verified())
        self.assertEqual(verdict["verdict"], "VERIFIED_PROCESS")
        self.assertEqual(verdict["label"], "VERIFIED")
        self.assertGreaterEqual(verdict["confidence"], 0.85)

    def test_cross_view_mismatch_threads_without_snapshot(self):
        p = ProcessPresence(boot_id="boot-1", pid=9336,
                            kernel_create_seen=True, etw_start_seen=True,
                            snapshot_seen=False, thread_activity_seen=True)
        verdict = reconcile(p)
        self.assertEqual(verdict["verdict"], "CROSS_VIEW_MISMATCH")
        self.assertEqual(verdict["severity"], "high")

    def test_unexplained_process_snapshot_without_creation(self):
        p = ProcessPresence(boot_id="boot-1", pid=4242, snapshot_seen=True,
                            image_activity_seen=True)
        verdict = reconcile(p, coverage_valid=True, sysmon_policy="full")
        self.assertEqual(verdict["verdict"], "UNEXPLAINED_PROCESS")
        self.assertIn("log wrap", verdict["reasons"][0])

    def test_stale_coverage_never_confirms_hiding(self):
        p = ProcessPresence(boot_id="boot-1", pid=4242, snapshot_seen=True)
        verdict = reconcile(p, coverage_valid=False)
        self.assertEqual(verdict["verdict"], "UNKNOWN")
        self.assertEqual(verdict["confidence"], 0.2)

    def test_clean_exit_is_not_a_mismatch(self):
        p = ProcessPresence(boot_id="boot-1", pid=100,
                            kernel_create_seen=True, kernel_exit_seen=True,
                            etw_start_seen=True, etw_stop_seen=True)
        verdict = reconcile(p)
        self.assertEqual(verdict["verdict"], "VERIFIED_EXIT")

    def test_interrupted_stream_stays_unknown_not_exited(self):
        # Creation seen, snapshot missed, no residual activity, but the
        # stream was gapped mid-boot: must not claim EXITED as fact.
        p = ProcessPresence(boot_id="boot-1", pid=101,
                            sysmon_create_seen=True)
        verdict = reconcile(p, coverage_valid=False)
        self.assertEqual(verdict["verdict"], "UNKNOWN")

    def test_exit_with_current_snapshot_is_contradiction_not_verified(self):
        p = ProcessPresence(boot_id="boot-1", pid=101,
                            kernel_create_seen=True, kernel_exit_seen=True,
                            snapshot_seen=True)
        self.assertEqual(reconcile(p)["verdict"], "CROSS_VIEW_MISMATCH")
        self.assertEqual(reconcile(p, coverage_valid=False)["verdict"],
                         "UNKNOWN")

    def test_interrupted_stream_does_not_assert_activity_mismatch(self):
        p = ProcessPresence(boot_id="boot-1", pid=101,
                            sysmon_create_seen=True,
                            cpu_activity_seen=True)
        self.assertEqual(reconcile(p, coverage_valid=False)["verdict"],
                         "UNKNOWN")

    def test_pid_reuse_key_includes_boot_and_start(self):
        a = ProcessPresence(boot_id="boot-1", pid=4, started="t0")
        b = ProcessPresence(boot_id="boot-2", pid=4, started="t0")
        self.assertNotEqual(a.key(), b.key())
        g = ProcessPresence(boot_id="boot-1", pid=4, guid="abc",
                            started="t0")
        self.assertTrue(g.key().startswith("guid:"))

    def test_retry_exhaustion_explained_process_stays_unexplained(self):
        # A filtered Sysmon policy explains the gap mechanism but the
        # verdict must remain UNEXPLAINED_PROCESS, never downgraded to ok.
        p = ProcessPresence(boot_id="boot-1", pid=77, snapshot_seen=True)
        verdict = reconcile(p, coverage_valid=True,
                            sysmon_policy="filtered")
        self.assertEqual(verdict["verdict"], "UNEXPLAINED_PROCESS")
        self.assertNotEqual(verdict["severity"], "ok")


class ImpossibleTests(unittest.TestCase):
    def test_cpu_without_process_is_visibility_anomaly(self):
        out = impossible.cpu_without_process(
            [{"key": "k-unknown", "pid": 9999, "cpu_pct": 42.0,
              "sample": "s1"}],
            known_keys={"k-known"})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["detector"], "visibility-anomaly")

    def test_thread_without_start_is_cross_view_anomaly(self):
        out = impossible.thread_without_start(
            [{"pid": 555, "key": "k-555", "thread_count": 3}],
            start_keys={"k-other"})
        self.assertEqual(out[0]["detector"], "cross-view-anomaly")

    def test_known_instances_raise_nothing(self):
        out = impossible.check_all(
            samples=[{"key": "k1", "pid": 1}],
            threads=[{"key": "k1", "pid": 1, "thread_count": 1}],
            connections=[{"key": "k1", "pid": 1}],
            images=[{"key": "k1", "pid": 1}],
            known_keys={"k1"}, start_keys={"k1"})
        self.assertEqual(out, [])

    def test_network_orphan_is_critical(self):
        out = impossible.network_without_process(
            [{"key": "ghost", "pid": 31337, "remote": "203.0.113.7:443"}],
            known_keys=set())
        self.assertEqual(out[0]["severity"], "critical")


class EscalationTests(unittest.TestCase):
    def test_no_discrepancy_means_cheap_only(self):
        decision = escalate.decide([{"key": "k1",
                                     "verdict": "VERIFIED_PROCESS",
                                     "severity": "ok"}])
        self.assertEqual(decision["deep"], [])
        self.assertEqual(len(decision["cheap"]), 1)

    def test_mismatch_escalates_selected_pid_only(self):
        decision = escalate.decide([
            {"key": "k-bad", "verdict": "CROSS_VIEW_MISMATCH",
             "severity": "high"},
            {"key": "k-good", "verdict": "VERIFIED_PROCESS",
             "severity": "ok"},
        ])
        self.assertEqual(len(decision["deep"]), 1)
        self.assertEqual(decision["deep"][0]["key"], "k-bad")

    def test_pressure_defers_deep_work(self):
        decision = escalate.decide(
            [{"key": "k-bad", "verdict": "UNEXPLAINED_PROCESS",
              "severity": "medium"}],
            pressured=True)
        self.assertEqual(decision["deep"], [])
        self.assertEqual(len(decision["deferred"]), 1)

    def test_budget_exhaustion_defers_remainder(self):
        verdicts = [{"key": f"k-{i}", "verdict": "CROSS_VIEW_MISMATCH",
                     "severity": "high"} for i in range(7)]
        decision = escalate.decide(verdicts, limit=5)
        self.assertEqual(len(decision["deep"]), 5)
        self.assertEqual(len(decision["deferred"]), 2)

    def test_deep_forensic_trace_needs_human_authorization(self):
        decision = escalate.decide(
            [{"key": "k-bad", "verdict": "CROSS_VIEW_MISMATCH",
              "severity": "high"}])
        self.assertEqual(decision["gated"], [])
        authorized = escalate.decide(
            [{"key": "k-bad", "verdict": "CROSS_VIEW_MISMATCH",
              "severity": "high"}],
            human_authorized_pids=["k-bad"])
        self.assertEqual(len(authorized["gated"]), 1)


class KernelContractTests(unittest.TestCase):
    def test_supported_manifest_passes(self):
        manifest = {"callbacks": [
            "PsSetCreateProcessNotifyRoutineEx",
            "PsSetCreateThreadNotifyRoutine",
            "PsSetLoadImageNotifyRoutine",
            "ObRegisterCallbacks"],
            "techniques": [], "model": False, "database": False,
            "http": False, "arbitrary_commands": False,
            "memory": {}, "ring_buffer_events": 8192}
        self.assertEqual(kernel_contract.validate_manifest(manifest), [])

    def test_hooks_and_patchguard_violations_rejected(self):
        manifest = {"callbacks": ["PsSetCreateProcessNotifyRoutineEx"],
                    "techniques": ["ssdt_hook", "dkom_modify"],
                    "memory": {"writable_executable": True,
                               "dynamic_code": True,
                               "writes_executable_memory": True},
                    "model": True, "http": True,
                    "ring_buffer_events": 1 << 20}
        errors = kernel_contract.validate_manifest(manifest)
        self.assertGreaterEqual(len(errors), 6)

    def test_ring_event_needs_boot_and_seq(self):
        self.assertTrue(kernel_contract.validate_event(
            {"type": "process_create", "pid": 1}))
        self.assertEqual(kernel_contract.validate_event(
            {"type": "process_create", "pid": 1, "boot_id": "b",
             "seq": 7}), [])


class AdapterTests(unittest.TestCase):
    def test_adapter_folds_existing_sources(self):
        p = adapter.build_presence(
            boot_id="b", pid=5172, guid="g", started="t",
            kernel_events=(), etw_events=("start",),
            sysmon_creates={5172}, snapshot_pids={5172},
            thread_pids={5172}, image_pids={5172},
            cpu_pids={5172}, network_pids=set())
        verdict = reconcile(p)
        self.assertEqual(verdict["verdict"], "VERIFIED_PROCESS")
        self.assertIsNotNone(adapter.to_finding(
            reconcile(adapter.build_presence(
                boot_id="b", pid=9, snapshot_pids={9})),
            host="win"))

    def test_verified_processes_produce_no_finding(self):
        self.assertIsNone(adapter.to_finding(reconcile(
            ProcessPresence(boot_id="b", pid=1, guid="g",
                            kernel_create_seen=True, etw_start_seen=True,
                            sysmon_create_seen=True, snapshot_seen=True,
                            thread_activity_seen=True))))


if __name__ == "__main__":
    unittest.main()

"""Execution planes: memory, threads, modules, sampling, CLR, ledger."""

import unittest

from jarvis.core.execution import (
    baseline,
    causal,
    deltas,
    dotnet,
    fingerprint,
    forensic,
    ledger,
    memory,
    modules,
    panel,
    sampling,
    schedule,
    threads,
    visibility_score,
    watch,
)


class MemoryTests(unittest.TestCase):
    def test_private_rwx_flagged(self):
        out = memory.flags([{"base": "0x1", "perms": "RWX",
                             "backing": "private"}])
        self.assertEqual(out[0]["flag"], "private-rwx")

    def test_protection_delta_recorded(self):
        out = memory.deltas([{"base": "0x1", "perms": "RW"}],
                            [{"base": "0x1", "perms": "RX"}])
        self.assertEqual(out[0]["change"], "protection-changed")

    def test_activation_sequence_cites_chain(self):
        out = memory.activation_sequence([
            {"region": "0x1", "kind": "allocated", "perms": "RW"},
            {"region": "0x1", "kind": "written"},
            {"region": "0x1", "kind": "protection", "before": "RW", "after": "RX"},
            {"region": "0x1", "kind": "thread_start"}])
        self.assertEqual(out[0]["pattern"], "activation-sequence")

    def test_activation_requires_order_write_and_exact_permissions(self):
        prefix = [{"region": "0x1", "kind": "allocated", "perms": "RW"}]
        thread = {"region": "0x1", "kind": "thread_start"}
        protection = {"region": "0x1", "kind": "protection",
                      "before": "RW", "after": "RX"}
        self.assertEqual(memory.activation_sequence(prefix + [protection, thread]), [])
        self.assertEqual(memory.activation_sequence(prefix + [thread,
                         {"region": "0x1", "kind": "written"}, protection]), [])
        self.assertEqual(memory.activation_sequence(prefix + [
            {"region": "0x1", "kind": "written"},
            {"region": "0x1", "kind": "protection",
             "before": "RW", "after": "RWX"}, thread]), [])


class ThreadModuleTests(unittest.TestCase):
    def test_explosion_is_transition_not_verdict(self):
        out = threads.anomalies(
            threads=[{"tid": i} for i in range(83)], baseline_band=(6, 10))
        self.assertEqual(out[0]["detector"], "thread-explosion")

    def test_module_hash_change_is_delta(self):
        out = modules.diff({"b": {"path": "x", "hash": "a"}},
                           {"b": {"path": "x", "hash": "b"}})
        self.assertEqual(out[0]["change"], "module_hash_changed")


class SamplingTests(unittest.TestCase):
    def test_unknown_shift_detected(self):
        base = {"modules": {"signed": 0.98, "unknown": 0.02}}
        cur = {"modules": {"signed": 0.77, "unknown": 0.23}}
        self.assertIsNotNone(sampling.deviation(base, cur))
        self.assertIsNone(sampling.deviation(base, base))


class FingerprintTests(unittest.TestCase):
    def test_band_exit_flagged(self):
        out = fingerprint.compare({"threads": 8, "threads_band": (6, 10)},
                                  {"threads": 83})
        self.assertEqual(out[0]["field"], "threads")


class DotnetTests(unittest.TestCase):
    def test_temp_dynamic_load_flagged(self):
        out = dotnet.assembly_anomalies(
            [{"name": "a", "path": "C:\\Temp\\x.dll", "dynamic": True}])
        self.assertIn("temp-path", out[0]["reasons"])

    def test_jit_burst_after_idle(self):
        self.assertTrue(dotnet.runtime_anomalies(jit_per_window=142))

    def test_sample_resolves_to_method(self):
        ranges = [{"start": "0x1000", "end": "0x1100",
                   "assembly": "Pay.dll", "type": "T",
                   "method": "ProcessAsync"}]
        self.assertEqual(dotnet.resolve_sample("0x1050", ranges)["method"],
                         "ProcessAsync")
        self.assertIsNone(dotnet.resolve_sample("0x9999", ranges))

    def test_snapshot_needs_authorization(self):
        self.assertFalse(dotnet.snapshot_request(
            "DOTNET_ANOMALY")["authorized"])
        self.assertTrue(dotnet.snapshot_request(
            "DOTNET_ANOMALY", human_authorized=True)["authorized"])


class LedgerBaselineTests(unittest.TestCase):
    def test_chain_links_and_values_stay_digested(self):
        c = ledger.build(global_seq=1, entity_id="e", change_type="t",
                         prev_digest=ledger.digest("a"),
                         cur_digest=ledger.digest("b"))
        self.assertEqual(len(c["integrity_hash"]), 64)
        self.assertEqual(len(c["previous_state_digest"]), 16)
        self.assertNotEqual(c["previous_state_digest"], "a")

    def test_labels_rank_context(self):
        self.assertEqual(baseline.label(seen_before=False), "FIRST_SEEN")
        self.assertEqual(baseline.label(within_bands=False,
                                        corroborated=True), "ANOMALOUS")
        self.assertEqual(baseline.label(), "EXPECTED")


class WatchScoreForensicTests(unittest.TestCase):
    def test_silent_stream_with_activity_is_high(self):
        hit = watch.contradiction(events_per_min=0, cpu_active=True)
        self.assertEqual(hit["severity"], "high")

    def test_restricted_not_failed(self):
        score = visibility_score.entity_score(
            {"lifecycle": 1.0, "memory": "restricted", "clr": "na"})
        self.assertEqual(score["score"], 100.0)

    def test_forensic_gated(self):
        self.assertFalse(forensic.plan(authorized=False)["authorized"])
        plan = forensic.plan(authorized=True)
        self.assertIn("return to LEVEL 1", plan["steps"][-1])


class SchedulePanelTests(unittest.TestCase):
    def test_lifecycle_is_event_driven(self):
        self.assertEqual(schedule.interval("process"), 0.0)
        self.assertGreater(schedule.interval("temperature"), 0)

    def test_pressure_backs_off_reconciliation(self):
        idle = schedule.interval("reconciliation")
        self.assertGreater(schedule.interval("reconciliation",
                                             pressured=True), idle)

    def test_panel_states_observation_not_verdict(self):
        text = panel.render(pid="7284", image="powershell.exe",
                            identity={"signer": "Microsoft"},
                            views={"kernel creation": True,
                                   "sysmon event 1": False},
                            execution={"cpu": "2.1%"},
                            confidence=0.41,
                            state="CROSS-VIEW PROCESS ANOMALY")
        self.assertIn("PROCESS 7284", text)
        self.assertIn("41%", text)
        self.assertNotIn("ROOTKIT", text)


class CausalDeltaTests(unittest.TestCase):
    def test_chain_orders_one_instance(self):
        proc = {"pid": 1, "guid": "g1"}
        other = {"pid": 2, "guid": "g2"}
        events = [
            {"seq": 3, "category": "network", "action": "connect",
             "process": proc, "time": "t3"},
            {"seq": 1, "category": "file", "action": "write",
             "process": proc, "time": "t1"},
            {"seq": 2, "category": "file", "action": "write",
             "process": other, "time": "t2"},
        ]
        out = causal.chain(events, "guid:g1")
        self.assertEqual([c["seq"] for c in out], [1, 3])

    def test_deltas_fire_beyond_threshold(self):
        self.assertEqual(deltas.delta({"temperature": 57},
                                      {"temperature": 57}), {})
        self.assertIn("temperature", deltas.delta({"temperature": 57},
                                                  {"temperature": 63}))


if __name__ == "__main__":
    unittest.main()

"""Phase 1 + Phase 22 regression checks: perception states and invariants.

Load-bearing security invariants: JARVIS must never present an
uncorroborated observation as verified reality, never show false green on
unknown health, never apply a patch without exact authorization, and never
claim a response succeeded without independent verification.
"""
import json
import time
import unittest
from unittest import mock

from jarvis.collectors.host.veil import correlation as veil_correlation
from jarvis.collectors.telemetry import reconcile, sysmon_policy, sysmon_pressure
from jarvis.core import (
    activity,
    confidence,
    governor,
    invariants,
    mlroute,
    perception,
    state,
    temporal,
)
from jarvis.lab import candidates as forge_candidates
from jarvis.lab import soak
from jarvis.service import geosecurity


class PerceptionTests(unittest.TestCase):
    def test_reconciled_requires_both_sources_and_identity(self):
        v = perception.classify(event_present=True, snapshot_present=True,
                                identity_match=True)
        self.assertEqual(v["state"], perception.RECONCILED)
        self.assertEqual(v["label"], perception.VERIFIED)
        self.assertEqual(v["confidence"], 1.0)

    def test_snapshot_without_event_under_coverage_is_unobserved(self):
        v = perception.classify(event_present=False, snapshot_present=True,
                                coverage_valid=True)
        self.assertEqual(v["state"], perception.UNOBSERVED)
        self.assertEqual(v["label"], perception.UNRECONCILED)
        self.assertGreaterEqual(v["confidence"], 0.5)

    def test_snapshot_without_covering_stream_is_unknown_not_a_finding(self):
        v = perception.classify(event_present=False, snapshot_present=True,
                                coverage_valid=False)
        self.assertEqual(v["label"], perception.UNKNOWN)
        self.assertLess(v["confidence"], 0.5)

    def test_event_without_snapshot_is_observed_not_verified(self):
        v = perception.classify(event_present=True, snapshot_present=False)
        self.assertEqual(v["state"], perception.OBSERVED)
        self.assertNotEqual(v["label"], perception.VERIFIED)

    def test_chrome_example_verified_vs_unreconciled(self):
        good = perception.classify(event_present=True, snapshot_present=True,
                                   identity_match=True)
        bad = perception.classify(event_present=False, snapshot_present=True,
                                  coverage_valid=True)
        self.assertEqual(good["label"], "VERIFIED")
        self.assertEqual(bad["label"], "UNRECONCILED")


class ReconcilePerceptionTests(unittest.TestCase):
    def test_classify_snapshot_marks_unknown_when_no_stream(self):
        import tempfile
        from pathlib import Path

        from jarvis.core.eventlog import EventLog
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "eventlog"
            EventLog(root, writer=True).close()
            snap = [{"host": "win", "pid": 42, "name": "chrome.exe",
                     "exe": r"C:\x\chrome.exe",
                     "started": "2026-09-20T10:00:00Z",
                     "observed_at": "2026-09-20T10:05:00Z"}]
            verdicts = reconcile.classify_snapshot(snap, time.time(), root)
            self.assertEqual(len(verdicts), 1)
            self.assertEqual(verdicts[0]["label"], perception.UNKNOWN)


class InvariantTests(unittest.TestCase):
    def test_startup_requires_engine_health_and_ui(self):
        self.assertFalse(invariants.startup(
            ui_openable=False, engine_exists=True, health_known=True,
            elapsed_seconds=5)["ok"])
        self.assertFalse(invariants.startup(
            ui_openable=True, engine_exists=True, health_known=False,
            elapsed_seconds=5)["ok"])
        self.assertTrue(invariants.startup(
            ui_openable=True, engine_exists=True, health_known=True,
            elapsed_seconds=5)["ok"])

    def test_ui_failure_must_not_disable_engine(self):
        bad = invariants.protection(ui_failed=True, engine_active=False)
        self.assertFalse(bad["ok"])
        good = invariants.protection(ui_failed=True, engine_active=True)
        self.assertTrue(good["ok"])

    def test_stale_collector_without_recovery_fails(self):
        self.assertFalse(invariants.freshness(
            stale_mandatory=True, recovery_active=False)["ok"])
        self.assertTrue(invariants.freshness(
            stale_mandatory=True, recovery_active=True)["ok"])

    def test_patch_requires_exact_hash_authorization(self):
        self.assertFalse(invariants.repair(
            patch_hash="abc", authorized_hash="def")["ok"])
        self.assertFalse(invariants.repair(
            patch_hash="abc", authorized_hash="")["ok"])
        self.assertTrue(invariants.repair(
            patch_hash="abc", authorized_hash="abc")["ok"])

    def test_success_claim_requires_verification(self):
        self.assertFalse(invariants.evidence(
            response_claimed_success=True,
            independently_verified=False)["ok"])
        self.assertTrue(invariants.evidence(
            response_claimed_success=True,
            independently_verified=True)["ok"])

    def test_noncritical_work_yields_under_pressure(self):
        self.assertFalse(invariants.performance(
            host_pressured=True, noncritical_running=True)["ok"])
        self.assertTrue(invariants.performance(
            host_pressured=True, noncritical_running=False)["ok"])

    def test_precise_location_and_interaction_stay_local(self):
        self.assertFalse(invariants.privacy(
            precise_location_exfiltrated=True)["ok"])
        self.assertFalse(invariants.privacy(
            interaction_content_exfiltrated=True)["ok"])
        self.assertTrue(invariants.privacy()["ok"])

    def test_evaluate_all_reports_each_invariant(self):
        out = invariants.evaluate_all(
            startup=dict(ui_openable=True, engine_exists=True,
                         health_known=True, elapsed_seconds=3),
            protection=dict(ui_failed=False, engine_active=True),
            freshness=dict(stale_mandatory=False, recovery_active=False),
            repair=dict(patch_hash="", authorized_hash=""),
            evidence=dict(response_claimed_success=False,
                          independently_verified=False),
            performance=dict(host_pressured=False, noncritical_running=False),
            privacy=dict())
        self.assertTrue(out["ok"])
        for name in ("startup", "protection", "freshness", "repair",
                     "evidence", "performance", "privacy"):
            self.assertIn(name, out)


class GovernorTests(unittest.TestCase):
    def test_pressured_host_pauses_noncritical_keeps_tier0(self):
        d = governor.decide(cpu_pct=88.0, user_active_compiling=True,
                            queue_depth=0, telemetry_backlog=0)
        self.assertTrue(d["pressured"])
        self.assertIn("deep threat hunt", d["pause"])
        self.assertIn("native telemetry", d["keep"])
        self.assertNotIn("native telemetry", d["pause"])

    def test_idle_host_on_ac_may_resume(self):
        d = governor.decide(cpu_pct=3.0, queue_depth=0, telemetry_backlog=0,
                            on_ac=True)
        self.assertFalse(d["pressured"])
        self.assertEqual(d["pause"], [])

    def test_never_pauses_tier0(self):
        for cpu in (0, 50, 99):
            d = governor.decide(cpu_pct=float(cpu))
            for tier0 in governor.TIER_0:
                self.assertNotIn(tier0, d["pause"])

    def test_attribution_shares_sum_to_one(self):
        out = governor.attribution({"jarvis engine": 1.4, "other": 8.6},
                                   {"jarvis engine": 233_000_000,
                                    "other": 767_000_000})
        total_cpu = sum(v["cpu_share"] for v in out.values())
        total_rss = sum(v["rss_share"] for v in out.values())
        self.assertAlmostEqual(total_cpu, 1.0, places=3)
        self.assertAlmostEqual(total_rss, 1.0, places=3)


class SharedStateTests(unittest.TestCase):
    def test_second_consumer_reuses_first_read(self):
        state.clear()
        calls = []

        def _read():
            calls.append(1)
            return [{"pid": 1}]
        first = state.get_processes(("wsl",), _read, with_sockets=True)
        second = state.get_processes(("wsl",), _read, with_sockets=True)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)
        self.assertEqual(state.stats()["hits"], 1)

    def test_socket_key_does_not_leak_attribution(self):
        state.clear()
        full = [{"pid": 1, "conns": [{"ip": "1.1.1.1"}]}]
        got = state.get_processes(("wsl",), lambda: full, with_sockets=True)
        other = state.get_processes(("wsl",), lambda: [{"pid": 9}],
                                    with_sockets=False)
        # Different cache keys: socket-less read never receives sockets
        # silently from the socket-full entry.
        self.assertNotEqual(got, other)


class TemporalTests(unittest.TestCase):
    def _ev(self, seq, category, action, **kw):
        ev = {"seq": seq, "category": category, "action": action,
              "host": "win", "time": "2026-09-20T10:00:00Z"}
        ev.update(kw)
        return ev

    def test_start_then_exit_leaves_no_alive(self):
        proc = {"pid": 42, "guid": "{a}", "image": r"C:\x\a.exe"}
        events = [self._ev(1, "process", "start", process=proc),
                  self._ev(2, "process", "exit", process=proc)]
        out = temporal.reduce(events)
        self.assertEqual(out["alive"], {})
        self.assertEqual(out["counts"]["process:start"], 1)

    def test_one_feed_serves_many_consumers_without_rescan(self):
        proc = {"pid": 7, "guid": "{b}", "image": r"C:\x\b.exe"}
        events = [self._ev(1, "process", "start", process=proc),
                  self._ev(2, "network", "connect",
                            target={"ip": "1.1.1.1", "port": 443}),
                  self._ev(3, "network", "dns_query",
                            target={"query": "Example.COM."})]
        out = temporal.reduce(events)
        self.assertIn("guid:{b}", out["alive"])
        self.assertIn("1.1.1.1:443", out["peers"])
        self.assertIn("example.com", out["dns"])

    def test_unknown_actions_pass_through_without_moving_state(self):
        events = [self._ev(1, "sensor", "error")]
        out = temporal.reduce(events)
        self.assertEqual(out["alive"], {})
        self.assertEqual(out["counts"]["sensor:error"], 1)

    def test_truncation_is_reported_not_silent(self):
        events = [self._ev(i, "sensor", "error") for i in range(1, 20)]
        out = temporal.reduce(events, limit=5)
        self.assertTrue(out["truncated"])
        self.assertEqual(out["events_folded"], 5)


class ActivityTests(unittest.TestCase):
    def test_same_host_subject_and_window_correlate(self):
        base = {"host": "win", "job": "sysmon", "severity": "high",
                "title": "suspicious", "subject_id": "edge-1",
                "last_seen": 1000.0}
        other = dict(base, job="network", title="external peer",
                     last_seen=1100.0)
        chains = activity.correlate([base, other])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["count"], 2)
        self.assertTrue(chains[0]["causal"])

    def test_different_hosts_never_join(self):
        a = {"host": "win", "job": "sysmon", "severity": "high",
             "title": "a", "last_seen": 1000.0}
        b = dict(a, host="wsl", title="b")
        self.assertEqual(len(activity.correlate([a, b])), 2)

    def test_no_invented_causality_without_edge(self):
        a = {"host": "win", "job": "sysmon", "severity": "low",
             "title": "a", "where": "x", "last_seen": 1000.0}
        b = {"host": "win", "job": "geo", "severity": "low",
             "title": "b", "where": "y", "last_seen": 1100.0}
        chains = activity.correlate([a, b])
        # Distinct subjects in the same window stay separate; grouping
        # requires a shared subject or explicit edge.
        self.assertEqual(len(chains), 2)
        self.assertFalse(any(c["causal"] for c in chains))


class GovernorDeferTests(unittest.TestCase):
    def test_only_governed_jobs_defer(self):
        self.assertTrue(governor.should_defer("intel", True))
        self.assertTrue(governor.should_defer("secrets", True))
        self.assertFalse(governor.should_defer("scan", True))
        self.assertFalse(governor.should_defer("native", True))
        self.assertFalse(governor.should_defer("bridge", True))
        self.assertFalse(governor.should_defer("intel", False))

    def test_tier0_never_in_governed_set(self):
        for job in ("scan", "bridge", "native", "coverage", "watchdogs"):
            self.assertNotIn(job, governor.GOVERNED_JOBS)

    def test_live_pressure_never_raises(self):
        pressured, reason = governor.live_pressure()
        self.assertIsInstance(pressured, bool)
        self.assertTrue(isinstance(reason, str) and reason)


class SysmonPolicyTests(unittest.TestCase):
    def test_full_policy_without_excludes(self):
        dump = ("Event ProcessCreate\n  Rule name: -\n  EventType: Include\n"
                "Event FileCreate\n")
        self.assertEqual(sysmon_policy.parse(dump)["event1"], "full")

    def test_filtered_policy_lists_excludes(self):
        dump = ("Event ProcessCreate\n  Exclude Image C:\\Windows\\x.exe\n"
                "Event FileCreate\n")
        verdict = sysmon_policy.parse(dump)
        self.assertEqual(verdict["event1"], "filtered")
        self.assertTrue(verdict["excludes"])

    def test_current_sysmon_format_counts_process_create_filters(self):
        dump = ("Rule configuration (version 4.50):\n"
                " - ProcessCreate onmatch: exclude combine rules using 'Or'\n"
                "    CommandLine filter: begin with value: 'wermgr.exe'\n"
                "    Image filter: is value: 'conhost.exe'\n"
                " - FileCreate onmatch: exclude\n"
                "    Image filter: is value: 'other.exe'\n")
        verdict = sysmon_policy.parse(dump)
        self.assertEqual(verdict["event1"], "filtered")
        self.assertEqual(verdict["mode"], "exclude")
        self.assertEqual(verdict["rule_count"], 2)
        self.assertEqual(len(verdict["excludes"]), 2)
        self.assertEqual(verdict["field_counts"],
                         {"CommandLine": 1, "Image": 1})

    def test_exact_image_exclusion_attributes_gap_without_guessing(self):
        policy = {"event1": "filtered", "mode": "exclude", "rules": [{
            "field": "Image", "condition": "is",
            "value": r"C:\Windows\System32\conhost.exe"}]}
        cause = sysmon_policy.gap_cause(
            policy, process={"exe": r"c:\windows\system32\CONHOST.exe"})
        self.assertIn("matched active", cause)
        self.assertIn("conhost.exe", cause)

    def test_policy_summary_drops_raw_rule_values(self):
        policy = {"event1": "filtered", "mode": "exclude",
                  "detail": "x", "rule_count": 1,
                  "field_counts": {"Image": 1}, "source": "elevated_broker",
                  "rules": [{"value": r"C:\private\tool.exe"}],
                  "excludes": [r"Image value C:\private\tool.exe"]}
        safe = sysmon_policy.summary(policy)
        self.assertNotIn("rules", safe)
        self.assertNotIn("excludes", safe)

    def test_unreadable_config_is_unknown_not_clean(self):
        self.assertEqual(sysmon_policy.parse(None)["event1"], "unknown")

    def test_gap_cause_names_filtering_vs_loss_vs_unknown(self):
        self.assertIn("filtering", sysmon_policy.gap_cause(
            {"event1": "filtered"}))
        self.assertIn("queue", sysmon_policy.gap_cause(
            {"event1": "full"}, dropped_process_create=True))
        self.assertIn("wrap", sysmon_policy.gap_cause({"event1": "full"}))
        self.assertIn("unknown", sysmon_policy.gap_cause(
            {"event1": "unknown"}).lower())

    def test_measured_loss_beats_generic_filter_suspicion(self):
        cause = sysmon_policy.gap_cause(
            {"event1": "filtered", "mode": "exclude", "rules": []},
            dropped_process_create=81,
            process={"exe": r"C:\Windows\System32\unmatched.exe"})
        self.assertIn("driver-queue loss", cause)
        self.assertIn("81 observed this boot", cause)

    def test_audit_accepts_only_fresh_verified_broker_result(self):
        data = {"installed": True, "exit_code": 0, "error": "",
                "dump": "Event ProcessCreate\n  Rule name: -\n"}
        with mock.patch.object(sysmon_policy.broker, "result",
                               return_value=(data, "")):
            verdict = sysmon_policy.audit(now=1000)
        self.assertEqual(verdict["event1"], "full")
        self.assertEqual(verdict["source"], "elevated_broker")

    def test_broker_failure_is_unknown_not_clean(self):
        with mock.patch.object(
                sysmon_policy.broker, "result",
                return_value=(None, "staged script differs from checkout")):
            verdict = sysmon_policy.audit(now=1000)
        self.assertEqual(verdict["event1"], "unknown")
        self.assertEqual(verdict["source"], "unavailable")
        self.assertIn("differs", verdict["detail"])


class SysmonPressureTests(unittest.TestCase):
    def test_aggregate_broker_evidence_is_bounded_and_typed(self):
        data = {
            "ok": True, "boot": "2026-09-21T11:08:52Z",
            "retained_registry_events": 227,
            "by_rule": [{"name": "rule-a", "count": 49}] * 30,
            "by_image": [{"name": "services.exe", "count": 49}],
            "drops": [{"at": "2026-09-21T11:09:22Z",
                       "counts": {"RegistryEvent": 53558,
                                  "ProcessCreate": 81},
                       "driver_queue_size": 50000}],
            "truncated": False,
        }
        with mock.patch.object(sysmon_pressure.broker, "result",
                               return_value=(data, "")):
            out = sysmon_pressure.audit(now=1000)
        self.assertEqual(out["status"], "observed")
        self.assertEqual(out["drops"][0]["counts"]["RegistryEvent"], 53558)
        self.assertLessEqual(len(out["by_rule"]), 20)
        self.assertNotIn("raw_events", out)

    def test_unavailable_broker_is_unknown_not_zero_loss(self):
        with mock.patch.object(sysmon_pressure.broker, "result",
                               return_value=(None, "stale")):
            out = sysmon_pressure.audit(now=1000)
        self.assertEqual(out, {"status": "unknown", "detail": "stale"})

    def test_malformed_counts_do_not_escape(self):
        data = {"ok": True, "retained_registry_events": 1,
                "drops": [{"counts": {"RegistryEvent": "many"}}]}
        with mock.patch.object(sysmon_pressure.broker, "result",
                               return_value=(data, "")):
            out = sysmon_pressure.audit(now=1000)
        self.assertEqual(out["drops"][0]["counts"], {})


class HealthWiringTests(unittest.TestCase):
    def test_health_exposes_invariants_governor_perception_keys(self):
        import tempfile

        from jarvis.core.store import Store
        from jarvis.service import protection as protection_mod

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
        for key in ("invariants", "governor", "perception"):
            self.assertIn(key, state)
        self.assertIn("freshness", state["invariants"])


class GeoViewTests(unittest.TestCase):
    def test_tight_fix_opens_street(self):
        v = geosecurity.view({"status": "ok", "lat": 1.0, "lon": 2.0,
                              "accuracy_m": 15})
        self.assertEqual(v["mode"], "street")

    def test_loose_fix_opens_city(self):
        v = geosecurity.view({"status": "ok", "lat": 1.0, "lon": 2.0,
                              "accuracy_m": 5000})
        self.assertEqual(v["mode"], "city")

    def test_no_position_is_globe_without_marker(self):
        v = geosecurity.view({"status": "denied"})
        self.assertEqual(v["mode"], "globe")
        self.assertIsNone(v["tile_center"])

    def test_tile_center_never_carries_exact_position(self):
        v = geosecurity.view({"status": "ok", "lat": 1.234567, "lon": 2.345678,
                              "accuracy_m": 15})
        self.assertNotEqual((v["tile_center"]["lat"], v["tile_center"]["lon"]),
                            (1.234567, 2.345678))
        self.assertAlmostEqual(v["tile_center"]["lat"], 1.23, places=2)

    def test_state_payload_carries_view(self):
        import tempfile

        from jarvis.core.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp + "/t.db")
            try:
                payload = geosecurity.state(store)
            finally:
                store.close()
        self.assertIn("view", payload)
        self.assertIn(payload["view"]["mode"], ("street", "city", "globe"))


class SoakTests(unittest.TestCase):
    def _samples(self, rss_slope_day=0.0, n=48, step=3600):
        base = 1_000_000.0
        return [{"at": base + i * step,
                 "rss_mb": 220.0 + rss_slope_day * (i * step) / 86400.0,
                 "fds": 40, "threads": 8, "db_mb": 100.0,
                 "spool_mb": 2.0, "event_lag_s": 0.1, "cpu_pct": 1.5}
                for i in range(n)]

    def test_flat_ram_passes(self):
        out = soak.analyze(self._samples(rss_slope_day=0.0))
        self.assertTrue(out["ok"], out["problems"])
        self.assertAlmostEqual(out["metrics"]["rss_mb"]["slope_per_day"], 0.0)

    def test_leaking_ram_fails_against_budget(self):
        out = soak.analyze(self._samples(rss_slope_day=400.0))
        self.assertFalse(out["ok"])
        self.assertTrue(any("rss_mb" in p for p in out["problems"]))

    def test_warmup_settling_is_not_a_leak(self):
        samples = self._samples()
        samples[0]["rss_mb"] = 120.0  # cold allocator, excluded from the fit
        out = soak.analyze(samples)
        self.assertTrue(out["ok"], out["problems"])

    def test_no_samples_is_not_a_pass(self):
        self.assertFalse(soak.analyze([])["ok"])

    def test_fd_ceiling_is_absolute(self):
        samples = self._samples()
        for s in samples:
            s["fds"] = 600
        out = soak.analyze(samples)
        self.assertFalse(out["ok"])


class VeilCorrelationTests(unittest.TestCase):
    def _report(self, top="https://shop.example",
                egress=("https://shop.example", "https://tracker.example"),
                listeners=("mousemove", "pointermove", "scroll", "input", "keydown"),
                surfaces=("canvas", "webgl", "audio", "fonts"),
                transports=("beacon",)):
        return {"top_origin": top, "egress_origins": list(egress),
                "listeners": {k: 3 for k in listeners},
                "surfaces": {k: 2 for k in surfaces},
                "transports": {k: 1 for k in transports}}

    def test_single_sighting_is_observation_not_a_finding(self):
        verdicts = veil_correlation.aggregate([self._report()])
        self.assertEqual(verdicts["https://shop.example"]["sightings"], 1)
        self.assertEqual(veil_correlation.findings(verdicts), [])

    def test_repeated_pattern_becomes_one_corroborated_finding(self):
        verdicts = veil_correlation.aggregate([self._report() for _ in range(4)])
        found = veil_correlation.findings(verdicts)
        self.assertEqual(len(found), 1)
        self.assertIn("https://shop.example", found[0]["where"])
        self.assertGreater(found[0]["detail"].count("4"), 0)

    def test_confidence_grows_with_corroboration_but_never_certain(self):
        few = veil_correlation.aggregate([self._report()])
        many = veil_correlation.aggregate([self._report() for _ in range(50)])
        c_few = few["https://shop.example"]["confidence"]
        c_many = many["https://shop.example"]["confidence"]
        self.assertLess(c_few, c_many)
        self.assertLessEqual(c_many, veil_correlation.CONFIDENCE_CAP)
        self.assertLess(c_many, 1.0)

    def test_malformed_reports_are_skipped_never_errors(self):
        verdicts = veil_correlation.aggregate(
            [None, {}, {"top_origin": "not-a-url"}, self._report()])
        self.assertEqual(list(verdicts), ["https://shop.example"])

    def test_no_content_crosses_the_boundary(self):
        blob = json.dumps(veil_correlation.aggregate(
            [self._report() for _ in range(3)]))
        for token in ("coordinate", "keystroke", "cookie", "password", "text="):
            self.assertNotIn(token, blob.lower())


class ForgeCandidateTests(unittest.TestCase):
    def test_closeable_gap_becomes_synthetic_candidate(self):
        out = forge_candidates.candidates(
            [("T9999", 6, "no collector checks this", "Example technique")])
        self.assertEqual(len(out), 1)
        cand = out[0]
        self.assertEqual(cand["safety"], "synthetic")
        self.assertEqual(cand["status"], "candidate")
        self.assertEqual(cand["technique"], "T9999")
        self.assertIn("no OS", cand["expected_telemetry"])

    def test_known_scenarios_propose_nothing(self):
        gaps = [("T9999", 6, "no collector checks this", "Example")]
        out = forge_candidates.candidates(gaps, known_ids=["forge-t9999"])
        self.assertEqual(out, [])

    def test_most_discussed_technique_first(self):
        out = forge_candidates.candidates([
            ("T0001", 1, "why", "Low"), ("T0002", 9, "why", "High")])
        self.assertEqual(out[0]["technique"], "T0002")

    def test_candidate_is_proposal_not_coverage(self):
        out = forge_candidates.candidates([("T9999", 2, "why", "X")])
        self.assertNotIn("validated", json.dumps(out).lower().replace(
            "validation", ""))


class ConfidenceTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(confidence.level(0.9), "high")
        self.assertEqual(confidence.level(0.6), "medium")
        self.assertEqual(confidence.level(0.2), "low")
        self.assertEqual(confidence.level(0.0), "unknown")
        self.assertEqual(confidence.level(None), "unknown")
        self.assertEqual(confidence.level("bogus"), "unknown")
        self.assertEqual(confidence.level(2.0), "unknown")

    def test_combine_needs_no_input_silence(self):
        self.assertEqual(confidence.combine([]), 0.0)

    def test_inference_caps_below_certainty(self):
        self.assertLess(confidence.combine([0.9, 0.9, 0.9]), 1.0)
        self.assertLessEqual(confidence.combine([0.9, 0.9]),
                             confidence.INFERENCE_CAP)

    def test_verified_observation_may_reach_full(self):
        self.assertEqual(confidence.combine([1.0], verified=True), 1.0)

    def test_autonomy_matrix(self):
        act = confidence.decide(0.9, impact="low", reversible=True)
        self.assertEqual(act["decision"], "act")
        self.assertEqual(
            confidence.decide(0.6, impact="low")["decision"], "observe")
        # Uncertain or high-impact always asks.
        self.assertEqual(
            confidence.decide(0.9, impact="high")["decision"], "ask")
        self.assertEqual(
            confidence.decide(0.9, impact="low",
                              reversible=False)["decision"], "ask")
        self.assertEqual(confidence.decide(0.2)["decision"], "ask")
        self.assertEqual(confidence.decide(None)["decision"], "ask")

    def test_perception_verified_maps_to_high(self):
        verdict = perception.classify(event_present=True, snapshot_present=True,
                                      identity_match=True)
        self.assertEqual(confidence.level(verdict["confidence"]), "high")
        gate = confidence.decide(verdict["confidence"], impact="low",
                                 reversible=True)
        self.assertEqual(gate["decision"], "act")

    def test_veil_capped_never_auto_acts(self):
        verdicts = veil_correlation.aggregate(
            [{"top_origin": "https://s.example",
              "egress_origins": ["https://s.example", "https://t.example"],
              "listeners": {"mousemove": 1},
              "surfaces": {"canvas": 1, "webgl": 1, "audio": 1, "fonts": 1},
              "transports": {"beacon": 1}} for _ in range(50)])
        score = verdicts["https://s.example"]["confidence"]
        self.assertEqual(confidence.level(score), "medium")
        self.assertNotEqual(
            confidence.decide(score, impact="low")["decision"], "act")


class MLRouteTests(unittest.TestCase):
    def _inv(self, gpu=True, ollama=True):
        return {"gpus": [{"name": "Intel(R) UHD Graphics"}],
                "openvino": {"installed": gpu,
                             "devices": ["CPU", "GPU"] if gpu else ["CPU"],
                             "validation": {"ok": gpu}},
                "ollama": {"reachable": ollama, "models": []}}

    def test_unmeasured_gpu_means_cpu_never_hope(self):
        out = mlroute.route("embeddings", self._inv(gpu=False),
                            mem_available_mb=8000.0)
        self.assertEqual(out["backend"], "cpu")

    def test_openvino_gpu_does_not_depend_on_ollama(self):
        out = mlroute.route("embeddings", self._inv(ollama=False),
                            mem_available_mb=8000.0)
        self.assertEqual(out["backend"], "gpu")

    def test_no_gpu_or_ollama_means_deterministic_path(self):
        out = mlroute.route("embeddings", self._inv(gpu=False, ollama=False),
                            mem_available_mb=8000.0)
        self.assertEqual(out["backend"], "none")

    def test_unsuitable_tasks_stay_on_cpu(self):
        out = mlroute.route("repair_drafting", self._inv(),
                            mem_available_mb=8000.0)
        self.assertEqual(out["backend"], "cpu")

    def test_measured_gpu_suitable_task_with_headroom_routes_gpu(self):
        out = mlroute.route("phishing_classifier", self._inv(),
                            mem_available_mb=8000.0, model_mb=500.0)
        self.assertEqual(out["backend"], "gpu")

    def test_shared_ram_headroom_is_load_bearing(self):
        out = mlroute.route("embeddings", self._inv(),
                            mem_available_mb=8000.0, model_mb=7500.0)
        self.assertEqual(out["backend"], "cpu")
        self.assertIn("headroom", out["reason"])

    def test_pressure_defers_waitable_work(self):
        out = mlroute.route("embeddings", self._inv(),
                            mem_available_mb=8000.0,
                            governor_pressured=True)
        self.assertEqual(out["backend"], "deferred")

    def test_pressure_without_wait_option_falls_back_to_cpu(self):
        out = mlroute.route("anomaly_scoring", self._inv(),
                            mem_available_mb=8000.0,
                            governor_pressured=True, deferrable=False)
        self.assertEqual(out["backend"], "cpu")

    def test_unknown_inventory_means_no_runtime_not_cpu(self):
        # Unknown inventory measures no model runtime at all: the honest
        # answer is the deterministic path, not an assumed CPU model.
        self.assertEqual(mlroute.route("embeddings", None)["backend"], "none")
        self.assertEqual(mlroute.route("embeddings", {})["backend"], "none")

    def test_backends_names_measured_devices_only(self):
        self.assertTrue(mlroute.backends(self._inv())["openvino_gpu"])
        self.assertFalse(mlroute.backends(self._inv(gpu=False))["openvino_gpu"])


if __name__ == "__main__":
    unittest.main()

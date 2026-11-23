"""Detector health diagnosis: failures are named, coverage follows evidence,
and recovery needs a fresh valid result, not a restart."""

import os
import tempfile
import unittest

from jarvis.core.store import Store
from jarvis.service import detectorhealth as dh
from jarvis.service import reliability
from jarvis.service.schedule import ALL_JOBS, applicable

NOW = 1_000_000
IV = 300


def snap(age=10, findings=(), error=""):
    return {"ts": NOW - age, "findings": list(findings), "error": error}


def assess(s, status=None):
    return dh.assess("x", s, IV, status, now=NOW)


class StateTests(unittest.TestCase):
    def test_fresh_empty_result_is_healthy_not_unknown(self):
        d = assess(snap())
        self.assertEqual((d["state"], d["coverage"]), (dh.HEALTHY, dh.VERIFIED))
        self.assertEqual(d["findings"], 0)

    def test_no_result_is_never_healthy(self):
        for s in (None, {}, {"ts": 0, "findings": []}):
            d = assess(s)
            self.assertEqual((d["state"], d["coverage"]), (dh.NEVER_RAN, dh.BLIND))
            self.assertIsNone(d["last_success"])

    def test_crash_timeout_and_unknown_errors_are_failing(self):
        for err in ("RuntimeError: boom", "timed out after 45s", "Traceback ..."):
            self.assertEqual(assess(snap(error=err))["state"], dh.FAILING, err)

    def test_permission_denied_is_restricted_and_partial(self):
        d = assess(snap(error="Access is denied"))
        self.assertEqual((d["state"], d["coverage"]), (dh.RESTRICTED, dh.PARTIAL))
        self.assertIn("not allowed", d["reason"])

    def test_missing_dependency_is_not_a_compromise_verdict(self):
        d = assess(snap(error="auditctl: command not found"))
        self.assertEqual(d["state"], dh.MISSING_DEP)
        self.assertIn("does not mean anything is wrong", d["impact"])

    def test_genuine_missing_programs_stay_missing_dependencies(self):
        for err in ("auditctl: command not found", "native sensor: not installed",
                    "ModuleNotFoundError: No module named 'psutil'",
                    "'sysmon' is not recognized as an internal or external command",
                    "exec: \"docker\": executable file not found in %PATH%",
                    "The term 'Get-Foo' is not recognized as the name of a cmdlet"):
            self.assertEqual(assess(snap(error=err))["state"], dh.MISSING_DEP, err)

    def test_ambiguous_not_found_is_a_failure_not_a_missing_component(self):
        # A data file, process or HTTP 404 that "was not found" is a broken
        # run, not proof that optional software is absent.
        for err in ("FileNotFoundError: [Errno 2] No such file or directory: 'state.db'",
                    "process not found", "HTTP 404 Not Found", "baseline file not found"):
            d = assess(snap(error=err))
            self.assertEqual(d["state"], dh.FAILING, err)
            self.assertEqual(d["coverage"], dh.BLIND)
            self.assertIn(err.split(":")[0][:12], d["error"])    # the evidence stays visible

    def test_unsupported_configuration(self):
        self.assertEqual(assess(snap(error="not supported on this platform"))["state"], dh.UNSUPPORTED)

    def test_malformed_output_is_untrusted_and_blind(self):
        for bad in ({"ts": NOW - 5, "findings": "oops", "error": ""},
                    {"ts": NOW - 5, "findings": [1, "x"], "error": ""}):
            d = assess(bad)
            self.assertEqual((d["state"], d["coverage"]), (dh.MALFORMED, dh.BLIND))
            self.assertIsNone(d["findings"])

    def test_detection_window_follows_each_detectors_own_interval(self):
        self.assertEqual(dh.assess("a", snap(age=2 * IV), IV, now=NOW)["state"], dh.LATE)
        self.assertEqual(dh.assess("a", snap(age=2 * IV + 1), IV, now=NOW)["state"], dh.STALE)
        # A slower detector with the same age is still fine.
        self.assertEqual(dh.assess("b", snap(age=2 * IV + 1), 3600, now=NOW)["state"], dh.HEALTHY)

    def test_stale_result_keeps_its_timestamp_but_loses_coverage(self):
        d = assess(snap(age=5000))
        self.assertEqual((d["state"], d["coverage"]), (dh.STALE, dh.BLIND))
        self.assertEqual(d["last_success"], NOW - 5000)

    def test_timestamp_in_the_future_is_never_healthy(self):
        # Clock skew or a forged timestamp must not read as "just ran".
        d = assess({"ts": NOW + 10_000, "findings": [], "error": ""})
        self.assertNotEqual(d["state"], dh.HEALTHY)
        self.assertEqual(d["coverage"], dh.BLIND)

    def test_zero_or_missing_interval_is_never_healthy(self):
        for interval in (0, -5):
            d = dh.assess("x", snap(age=1), interval, now=NOW)
            self.assertNotEqual(d["state"], dh.HEALTHY, interval)

    def test_every_state_has_a_plain_reason_and_a_coverage_class(self):
        for state, (why, impact, _action) in dh._EXPLAIN.items():
            self.assertTrue(why and impact, state)
            self.assertIn(dh._COVERAGE.get(state, dh.BLIND), (dh.VERIFIED, dh.PARTIAL, dh.BLIND, dh.NA))
        # only a healthy detector is ever "verified"
        self.assertEqual([s for s in dh._EXPLAIN if dh._COVERAGE.get(s) == dh.VERIFIED], [dh.HEALTHY])

    def test_failed_run_does_not_report_a_last_success(self):
        self.assertIsNone(assess(snap(error="boom"))["last_success"])

    def test_repeated_failure_escalates_the_advice(self):
        d = assess(snap(error="boom"), {"failure_count": 3})
        self.assertIn("3 times in a row", d["reason"])


class RecoveryTests(unittest.TestCase):
    def test_restart_state_alone_is_not_recovery(self):
        d = assess(snap(age=5000), {"recovery_state": "retrying", "last_failure": NOW - 20})
        self.assertFalse(d["recovery_confirmed"])
        self.assertEqual(d["recovery_state"], "retrying")

    def test_fresh_result_older_than_the_failure_is_not_confirmation(self):
        d = assess(snap(age=100), {"last_failure": NOW - 50})
        self.assertFalse(d["recovery_confirmed"])

    def test_fresh_valid_result_after_the_failure_confirms(self):
        d = assess(snap(age=5), {"last_failure": NOW - 50})
        self.assertTrue(d["recovery_confirmed"])

    def test_fresh_but_failing_or_malformed_never_confirms(self):
        self.assertFalse(assess(snap(age=5, error="boom"), {"last_failure": NOW - 50})["recovery_confirmed"])
        self.assertFalse(assess({"ts": NOW - 5, "findings": "x", "error": ""})["recovery_confirmed"])


class ReportTests(unittest.TestCase):
    JOBS = {"a": (300, "A"), "b": (300, "B"), "coverage": (300, "cov")}

    def test_coverage_counts_follow_evidence_and_skip_non_evidence_jobs(self):
        rep = dh.report(self.JOBS, {"a": snap(), "b": snap(age=9000)}, now=NOW)
        self.assertEqual(rep["total"], 2)
        self.assertEqual(rep["counts"], {dh.VERIFIED: 1, dh.PARTIAL: 0, dh.BLIND: 1})
        self.assertEqual(rep["attention"], ["b"])
        self.assertIn("not evidence of an attack", rep["summary"])

    def test_losing_a_detector_lowers_coverage_and_recovery_restores_it(self):
        before = dh.report(self.JOBS, {"a": snap(), "b": snap()}, now=NOW)["counts"][dh.VERIFIED]
        lost = dh.report(self.JOBS, {"a": snap(), "b": snap(age=9000)}, now=NOW)["counts"][dh.VERIFIED]
        back = dh.report(self.JOBS, {"a": snap(), "b": snap(age=1)}, now=NOW)["counts"][dh.VERIFIED]
        self.assertEqual((before, lost, back), (2, 1, 2))

    def test_inapplicable_detectors_are_listed_but_not_counted_as_blind(self):
        rep = dh.report(self.JOBS, {"a": snap(), "b": snap()},
                        not_applicable={"win_thing": "no Windows domain here"}, now=NOW)
        self.assertEqual(rep["counts"][dh.BLIND], 0)
        self.assertEqual(rep["total"], 2)
        self.assertTrue(any(d["state"] == dh.NOT_APPLICABLE for d in rep["detectors"]))

    def test_all_healthy_summary(self):
        rep = dh.report(self.JOBS, {"a": snap(), "b": snap()}, now=NOW)
        self.assertEqual(rep["attention"], [])
        self.assertIn("All 2 detectors", rep["summary"])

    def test_environment_matrix_never_reports_absent_domains_as_blind(self):
        # Simulates platform layouts through the schedule's own applicability
        # rules; it does not run on those operating systems.
        for windows, linux in ((True, False), (False, True), (True, True)):
            jobs, absent = applicable(windows, linux, ALL_JOBS)
            rep = dh.report(jobs, {}, not_applicable=absent, now=NOW)
            expected = len([j for j in jobs if j not in reliability.NON_EVIDENCE_JOBS])
            self.assertEqual(rep["total"], expected)
            for d in rep["detectors"]:
                if d["id"] in absent:
                    self.assertEqual(d["coverage"], dh.NA)
                else:
                    self.assertEqual(d["state"], dh.NEVER_RAN)
            self.assertEqual(rep["counts"][dh.VERIFIED], 0)

    def test_no_machine_specific_paths_in_the_module(self):
        with open(dh.__file__, encoding="utf-8") as fh:
            src = fh.read()
        for token in ("C:\\Users", "/home/", "ineza"):
            self.assertNotIn(token, src)


class ExplanationFieldTests(unittest.TestCase):
    """Each detector says what it checks, how much the overall status leans on it, and how to audit it by hand."""

    def setUp(self):
        self.rep = dh.report(applicable(True, True, ALL_JOBS)[0], {}, now=NOW)

    def test_every_scheduled_detector_carries_the_explanation_fields(self):
        for d in self.rep["detectors"]:
            self.assertTrue(d["what"], d["id"])
            self.assertIn(d["criticality"], ("critical", "high", "medium", "low"), d["id"])
            self.assertTrue(d["affects_status"], d["id"])
            self.assertIn("command", d)

    def test_a_high_criticality_check_says_the_overall_status_depends_on_it(self):
        scan = next(d for d in self.rep["detectors"] if d["id"] == "scan")
        self.assertEqual(scan["criticality"], "high")
        self.assertTrue(scan["affects_status"].startswith("Yes."))
        self.assertEqual(scan["command"], "scan")                 # the hand-run command comes from the declaration

    def test_low_importance_checks_do_not_claim_the_status_depends_on_them(self):
        low = [d for d in self.rep["detectors"] if d["criticality"] == "low"]
        for d in low:
            self.assertNotIn("not reliable", d["affects_status"])

    def test_inapplicable_detectors_keep_the_same_keys_with_no_dependency_claim(self):
        jobs, absent = applicable(False, True, ALL_JOBS)
        rep = dh.report(jobs, {}, not_applicable=absent, now=NOW)
        na = [d for d in rep["detectors"] if d["state"] == dh.NOT_APPLICABLE]
        self.assertTrue(na)
        for d in na:
            self.assertEqual(d["affects_status"], "")
            self.assertEqual(d["command"], "")
            self.assertIn("what", d)

    def test_the_explanation_fields_never_change_the_state_or_coverage(self):
        # Adding explanation must not alter how health is derived.
        for d in self.rep["detectors"]:
            self.assertEqual(d["state"], dh.NEVER_RAN)
            self.assertEqual(d["coverage"], dh.BLIND)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def rep(self, snaps):
        return dh.report({"a": (300, "A")}, snaps, now=NOW)

    def test_history_records_transitions_once_and_keeps_the_error(self):
        self.assertEqual(dh.record_transitions(self.store, self.rep({"a": snap()}), NOW), [])
        bad = self.rep({"a": snap(error="Access is denied")})
        self.assertEqual(len(dh.record_transitions(self.store, bad, NOW)), 1)
        self.assertEqual(dh.record_transitions(self.store, bad, NOW + 5), [])
        back = dh.record_transitions(self.store, self.rep({"a": snap()}), NOW + 9)
        self.assertEqual(back[0]["state"], dh.HEALTHY)
        self.assertTrue(back[0]["recovery_confirmed"])
        states = [e["state"] for e in dh.history(self.store, "a")]
        self.assertEqual(states, [dh.RESTRICTED, dh.HEALTHY])
        self.assertIn("denied", dh.history(self.store)[0]["error"].lower())

    def test_history_is_bounded(self):
        for i in range(dh.HISTORY_MAX + 50):
            err = "boom" if i % 2 == 0 else ""
            dh.record_transitions(self.store, self.rep({"a": snap(error=err)}), NOW + i)
        self.assertLessEqual(len(dh.history(self.store)), dh.HISTORY_MAX)


if __name__ == "__main__":
    unittest.main()

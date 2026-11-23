"""The reasoning workflow: advisory limits, budgets, explicit gaps."""

import io
import json
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from unittest.mock import patch

from jarvis.cli.commands.reason import cmd_reason
from jarvis.core.reasoning import corpus, engine
from jarvis.core.reasoning.vocab import Observation as O
from jarvis.core.reasoning.vocab import Subject
from jarvis.response import jev, reasoning


def subj(key, facts, **kw):
    base = dict(host="win", label=key, signature="none", path_class="user_writable", age_days=3)
    base.update(kw)
    return Subject(key=key, observations=[O(f, "t") for f in facts], **base)


def fake_call(benign=0.1, no_reason=0.9, arch="keylogger", conf=0.9):
    def call(state, questions, timeout=0):
        fake_call.seen = (state, questions)
        answers = {"benign": {"type": "noul", "noul": benign},
                   "no_reason": {"type": "noul", "noul": no_reason},
                   "archetype": {"type": "choice", "choice": arch, "confidence": conf,
                                 "probabilities": {k: 1.0 if k == arch else 0.0
                                                   for k in questions["archetype"]["criteria"]}}}
        if "concealed" in questions:
            answers["concealed"] = {"type": "noul", "noul": 0.8}
        return {"answers": answers}
    return call


def gather_with(subjects, coverage=None):
    return lambda hosts, deep=False: (subjects, coverage or {"windows-processes": "complete"})


class ComposeTests(unittest.TestCase):
    def row(self, facts, **kw):
        s = subj("k", facts, **kw)
        return engine.assess(s), s

    def answers(self, **kw):
        return fake_call(**kw)(None, {"archetype": {"criteria": {"keylogger": ""}}})["answers"]

    def test_advice_never_changes_a_verdict_or_a_depth(self):
        for facts in (["cap.keyboard.hook"], ["conceal.contradiction"],
                      ["cap.keyboard.hook", "egress.external", "persist.autostart"]):
            r, _ = self.row(facts)
            before = (r["verdict"], r["observation_depth"], r["response_level"])
            for benign in (0.0, 0.5, 1.0):
                a = reasoning.compose(r, self.answers(benign=benign, no_reason=1 - benign))
                self.assertNotIn("suggested_depth", a)
                self.assertEqual((r["verdict"], r["observation_depth"], r["response_level"]), before)

    def test_disagreement_note_when_advisory_finds_a_flagged_chain_plausible(self):
        r, _ = self.row(["cap.keyboard.hook", "egress.external", "persist.autostart"])
        a = reasoning.compose(r, self.answers(benign=0.8))
        self.assertIn("plausible for ordinary software", a["disagreement"])
        self.assertNotIn("disagreement", reasoning.compose(r, self.answers(benign=0.1)))

    def test_dual_use_row_gets_a_note_only_when_advisory_sees_no_ordinary_reason(self):
        r, _ = self.row(["cap.screen.capture", "cap.input.injection"], signature="valid",
                        publisher="TeamViewer", path_class="program_files")
        self.assertEqual(r["verdict"], "EXPECTED_DUAL_USE")
        self.assertIn("no ordinary reason", reasoning.compose(r, self.answers(benign=0.1, no_reason=0.9))["disagreement"])
        self.assertNotIn("disagreement", reasoning.compose(r, self.answers(benign=0.5, no_reason=0.5)))

    def test_low_confidence_archetype_is_dropped_and_bad_numbers_are_ignored(self):
        r, _ = self.row(["cap.keyboard.hook"])
        a = reasoning.compose(r, {"benign": {"noul": True}, "no_reason": {"noul": "x"},
                                  "archetype": {"choice": "rat", "confidence": 0.2}})
        self.assertIsNone(a["archetype"])
        self.assertIsNone(a["benign_probability"])
        self.assertIsNone(a["no_ordinary_reason_probability"])


class AdviseTests(unittest.TestCase):
    def test_only_fixed_vocabulary_features_are_sent(self):
        s = subj("SECRET-KEY", ["cap.keyboard.hook", "conceal.deleted_image"], label="C:\\Users\\x\\evil.exe",
                 publisher="Hidden Vendor")
        r = engine.assess(s)
        reasoning.advise(r, s, call=fake_call())
        state, questions = fake_call.seen
        blob = json.dumps(state)
        for secret in ("SECRET-KEY", "evil.exe", "Hidden Vendor", "C:\\\\Users"):
            self.assertNotIn(secret, blob)
        self.assertIn("concealed", questions)               # verdict-specific question
        self.assertNotIn("deterministic_verdict", state)    # the advisory stays independent

    def test_unavailable_or_failing_service_is_explicit_and_harmless(self):
        s = subj("k", ["cap.keyboard.hook"])
        r = engine.assess(s)

        def boom(*a, **k):
            raise jev.JevError("request failed: URLError")
        a = reasoning.advise(r, s, call=boom)
        self.assertFalse(a["available"])
        self.assertEqual(a["fallback"], "deterministic verdict only")
        self.assertEqual(r["verdict"], "UNEXPLAINED_CAPABILITY")

    def test_real_client_rejects_malformed_remote_answers(self):
        q = {"chain": {"type": "noul", "instructions": "x", "criteria": {}}}
        with self.assertRaises(jev.JevError):
            jev._validate_answer("chain", q["chain"], {"type": "noul", "noul": 7})
        with self.assertRaises(jev.JevError):
            jev._validate_answer("chain", q["chain"], {"type": "choice"})


class WorkflowTests(unittest.TestCase):
    def test_verdicts_are_unchanged_by_advice_and_budget_is_enforced(self):
        subs = [subj(f"k{i}", ["cap.keyboard.hook"]) for i in range(reasoning.MAX_ADVISED + 3)]
        subs.append(subj("chain", ["cap.screen.capture", "persist.autostart", "egress.beacon"]))
        rep = reasoning.run(gather=gather_with(subs), call=fake_call(), clock=lambda: 1)
        self.assertEqual(rep["advisory"]["calls"], reasoning.MAX_ADVISED)
        verdicts = {r["key"]: r["verdict"] for r in rep["focus"]}
        self.assertEqual(verdicts["chain"], "SUSPECT_CHAIN")
        self.assertTrue(all(v in ("UNEXPLAINED_CAPABILITY", "SUSPECT_CHAIN") for v in verdicts.values()))
        # Advice on every advised row, yet no depth moved: unexplained rows stay at depth 1.
        self.assertEqual({r["observation_depth"] for r in rep["focus"] if r["verdict"] == "UNEXPLAINED_CAPABILITY"}, {1})
        over = [r for r in rep["focus"] if r.get("advice", {}).get("reason", "").startswith("advisory budget")]
        self.assertTrue(over)

    def test_no_jev_flag_makes_no_remote_call(self):
        def never(*a, **k):
            raise AssertionError("remote call made")
        rep = reasoning.run(gather=gather_with([subj("k", ["cap.keyboard.hook"])]), use_jev=False,
                            call=never)
        self.assertEqual(rep["advisory"]["calls"], 0)
        self.assertNotIn("advice", rep["focus"][0])

    def test_quiet_machine_still_states_gaps_and_partial_sources(self):
        rep = reasoning.run(gather=gather_with([subj("a", [])], {"keyboard-hooks": "unavailable",
                                                                  "windows-processes": "complete"}),
                            use_jev=False)
        self.assertEqual(rep["focus"], [])
        self.assertEqual(rep["coverage_incomplete"], ["keyboard-hooks"])
        self.assertTrue(rep["not_connected"])
        self.assertIn("not that the machine is clean", rep["reading"])

    def test_plan_executes_nothing_and_forensic_depth_waits_for_a_human(self):
        s = subj("evdev", ["cap.keyboard.evdev", "conceal.deleted_image"], host="wsl")
        rep = reasoning.run(gather=gather_with([s]), use_jev=False)
        self.assertTrue(rep["plan"]["executes_nothing"])
        self.assertEqual(rep["plan"]["awaiting_human_authorization"], ["evdev"])
        self.assertEqual(rep["plan"]["gated"], [])           # no automatic L6

    def test_hard_bounds_on_examined_subjects(self):
        many = [subj(f"s{i}", []) for i in range(3000)]
        rep = reasoning.run(gather=gather_with(many), use_jev=False)
        self.assertEqual(rep["subjects_examined"], 3000)
        self.assertLessEqual(len(rep["focus"]), 50)

    def test_explain_names_what_jarvis_cannot_see(self):
        info = reasoning.explain("keylogger")
        self.assertEqual(info["observability"]["keyboard polling"][0], "blind")
        self.assertIsNone(reasoning.explain("nonsense"))

    def test_advisory_authority_is_declared_none(self):
        rep = reasoning.run(gather=gather_with([]), use_jev=False)
        self.assertIn("none", rep["advisory"]["authority"])


class CalibrateTests(unittest.TestCase):
    def test_calibrate_groups_cases_and_reports_separability_honestly(self):
        def call(state, questions, timeout=0):
            bad = "cap.credential.store" in state["capture_kinds"] or state["path_class"] != "program_files"
            return {"answers": {"benign": {"type": "noul", "noul": 0.1 if bad else 0.5},
                                "no_reason": {"type": "noul", "noul": 0.9 if bad else 0.3},
                                "archetype": {"type": "choice", "choice": "keylogger", "confidence": 0.9,
                                              "probabilities": {}}}}
        r = reasoning.calibrate(call=call)
        self.assertEqual(r["cases"], len(corpus.POSITIVES) + len(corpus.LOOKALIKES))
        self.assertIsNotNone(r["summary"]["control.benign"])
        self.assertIn("not evidence about real spyware", r["reading"])

    def test_calibrate_counts_unavailable_service_instead_of_inventing_scores(self):
        def down(*a, **k):
            raise jev.JevError("no API key configured")
        r = reasoning.calibrate(call=down)
        self.assertEqual((r["cases"], r["failures"]), (0, len(corpus.POSITIVES) + len(corpus.LOOKALIKES)))
        self.assertFalse(r["controls_and_explained_separable_on_benign"])


class CliTests(unittest.TestCase):
    def run_cli(self, **kw):
        args = Namespace(action="spyware", name=None, host="win", deep=False, no_jev=True, limit=5,
                         json=True)
        for k, v in kw.items():
            setattr(args, k, v)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cmd_reason(args, None)
        return code, buf.getvalue()

    def test_exit_code_reflects_flagged_verdicts_only(self):
        for facts, code in (([], 0), (["cap.keyboard.hook"], 0),
                            (["cap.keyboard.hook", "egress.external", "persist.autostart"], 1)):
            with patch("jarvis.intel.spyware_evidence.gather", gather_with([subj("s", facts)])):
                self.assertEqual(self.run_cli()[0], code, facts)

    def test_selftest_and_explain_modes(self):
        code, out = self.run_cli(action="selftest")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["false_positives"], [])
        self.assertEqual(self.run_cli(action="explain", name="nope")[0], 2)
        self.assertEqual(self.run_cli(action="explain", name="rat")[0], 0)


if __name__ == "__main__":
    unittest.main()

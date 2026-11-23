"""The plan paragraph: model colour beside deterministic facts, never instead.

Rules inherited from the voice module: only facts it was given, no invented
numbers, no claims that JARVIS acted, no reassurance while work waits. The
deterministic brief is the fallback in every failure mode, and the flag
defaults off like every other model feature.
"""

import json
import unittest
from unittest import mock

from jarvis.response import llm
from jarvis.response.reporting import voice

ON = {"email_voice": True, "plan_voice": True}


class PlanNoteTests(unittest.TestCase):
    def test_off_by_default_never_calls_the_model(self):
        item = _item()
        with mock.patch.object(llm, "chat") as chat:
            note, by_model = voice.plan_note({}, item, _health())
        chat.assert_not_called()
        self.assertFalse(by_model)
        self.assertIn("Biggest gain", note)

    def test_example_lines_pass_the_rules_they_teach(self):
        for asked, answered in voice.PLAN_EXAMPLES:
            facts = json.loads(asked)
            with self.subTest(note=answered):
                self.assertTrue(voice._within_rules(answered, facts))
                self.assertIsNone(voice._PLAN_CLAIM.search(answered))

    def test_accepted_model_paragraph_is_used(self):
        good = ("Data & privacy is where the four points wait, and keys belong in a "
                "vault rather than on the counter.")
        with mock.patch.object(llm, "chat", return_value=(good, "")):
            note, by_model = voice.plan_note(ON, _item(), _health())
        self.assertTrue(by_model)
        self.assertEqual(note, good)

    def test_claiming_action_is_rejected(self):
        for claim in ("I have queued the encryption for you.",
                      "I will fix Data & privacy next.",
                      "Consider it handled — four points gained."):
            with self.subTest(claim=claim), \
                 mock.patch.object(llm, "chat", return_value=(claim, "")):
                note, by_model = voice.plan_note(ON, _item(), _health())
        self.assertFalse(by_model)
        self.assertIn("Biggest gain", note)

    def test_invented_number_is_rejected(self):
        # 12 appears nowhere in the facts (gain 4, score 47, area 11) — the
        # number rule must catch it spelled out just as surely as in digits.
        with mock.patch.object(llm, "chat",
                               return_value=("Twelve points wait in Data & privacy.", "")):
            note, by_model = voice.plan_note(ON, _item(), _health())
        self.assertFalse(by_model)
        self.assertIn("Biggest gain", note)

    def test_model_failure_falls_back(self):
        with mock.patch.object(llm, "chat", return_value=("", "offline")):
            note, by_model = voice.plan_note(ON, _item(), _health())
        self.assertFalse(by_model)
        self.assertIn("Biggest gain", note)

    def test_facts_carry_only_the_protocol_gain_and_area_score(self):
        facts = voice.plan_facts(_item(), _health())
        self.assertEqual(facts["area"], "Data & privacy")
        self.assertEqual(facts["protocol_gain_points"], 4)
        self.assertEqual(facts["score_percent"], 47)
        # The example lines must also satisfy the number rule against the
        # facts the plan_facts shape produces — the validator is the same one.
        for asked, answered in voice.PLAN_EXAMPLES:
            with self.subTest(note=answered):
                self.assertTrue(voice._within_rules(answered, json.loads(asked)))


def _item():
    class P:
        id = "plaintext-secrets"
        title = "Move the plaintext API keys out of files"

    return {"protocol": P(), "state": "ready", "open": 3,
            "blockers": [], "blocker_titles": [],
            "question": None, "declined": False,
            "score_now": 47, "score_after": 51}   # gain 4 — see plan facts test


def _health():
    return {"score": 47, "grade": "at risk",
            "areas": [{"name": "Data & privacy", "score": 11, "open": {},
                       "jobs": 5, "observed": 5, "blind": []}]}


if __name__ == "__main__":
    unittest.main()

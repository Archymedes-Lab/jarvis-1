"""The score coach: how to raise the number, computed from the real code.

The coach must never invent: every gain it names has to come from
protocols.evaluate()'s projection, and a blind area has to be named rather
than silently dropped. The model-status intent must not generate.
"""

import os
import tempfile
import time
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import assistant, llm, protocols
from jarvis.service.schedule import JOBS


def _now():
    """Fresh snapshots are stamped with wall-clock time, so must the tests be."""
    return int(time.time())


SEV_FINDING = {"category": "data at rest", "severity": "critical", "host": "win",
               "title": "OpenAI API key in plaintext", "detail": "x", "where": "f"}


def snaps(overrides=None):
    now = _now()
    out = {}
    for job, (interval, _label) in JOBS.items():
        out[job] = {"ts": now - 1, "findings": [], "error": ""}
    for job, findings in (overrides or {}).items():
        out[job]["findings"] = findings
    return out


class ScoreCoachTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        for job, s in snaps().items():
            self.store.save_snapshot(job, s["findings"], 0.1, s["error"])

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_clean_machine_says_so(self):
        text = assistant.score_coach(self.store, JOBS, now=_now())
        self.assertIn("Every protocol is complete", text)

    def test_gains_are_named_with_their_projection(self):
        self.store.save_snapshot("secrets", [SEV_FINDING], 0.1, "")
        text = assistant.score_coach(self.store, JOBS, now=_now())
        self.assertIn("Move the plaintext API keys out of files", text)
        self.assertIn("+", text)                      # some gain is named
        self.assertIn("jarvis brief", text)           # the way to start
        # The gain must equal the real projection, not a made-up number.
        state = {i["protocol"].id: i for i in
                 protocols.evaluate(self.store, JOBS, _now())}
        gain = state["plaintext-secrets"]["score_after"] - state["plaintext-secrets"]["score_now"]
        self.assertIn(f"+{gain}", text)

    def test_blind_collectors_are_named_not_hidden(self):
        stale = _now() - 86400
        self.store.db.execute("UPDATE snapshots SET ts=? WHERE kind='posture'", (stale,))
        self.store.commit()
        text = assistant.score_coach(self.store, JOBS)
        self.assertIn("not reporting", text)
        self.assertIn("posture", text)

    def test_answer_routes_the_coach_intents_without_a_model(self):
        self.store.save_snapshot("secrets", [SEV_FINDING], 0.1, "")
        with mock.patch.object(assistant, "_ollama") as model, \
             mock.patch.object(llm, "chat") as chat:
            result = assistant.answer(self.store, "how do I raise my score?",
                                      conf={}, jobs=JOBS)
        self.assertEqual(result["source"], "builtin")
        self.assertIn("Move the plaintext API keys", result["answer"])
        model.assert_not_called()
        chat.assert_not_called()


class OllamaContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.store.save_snapshot("secrets", [SEV_FINDING], 0.1, "")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_model_context_carries_score_areas_and_plan_not_just_findings(self):
        captured = {}

        def fake_chat(conf, system, user, **kwargs):
            captured["user"] = user
            return "ok", ""

        with mock.patch.object(llm, "chat", side_effect=fake_chat):
            assistant._ollama(self.store, "what matters most?", {}, jobs=JOBS)
        user = captured["user"]
        self.assertIn("<DATA>", user)
        self.assertIn('"score"', user)
        self.assertIn('"areas"', user)
        self.assertIn('"plan"', user)
        self.assertIn("OpenAI API key in plaintext", user)
        # The data block stays bounded: worst findings are capped at 8.
        self.assertLessEqual(user.count('"title"'), 9)


if __name__ == "__main__":
    unittest.main()

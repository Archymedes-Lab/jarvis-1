import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import assistant, llm
from jarvis.service.schedule import JOBS


class AssistantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "test.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_known_score_does_not_call_a_model(self):
        with mock.patch.object(assistant, "_ollama") as model:
            result = assistant.answer(self.store, "what is my score?", jobs=JOBS)
        self.assertEqual(result["source"], "builtin")
        self.assertIn("Security score:", result["answer"])
        model.assert_not_called()

    def test_confirm_only_returns_an_explicit_command(self):
        result = assistant.answer(self.store, "confirm it")
        self.assertEqual(result["source"], "builtin")
        self.assertIn("jarvis ack", result["answer"])

    def test_open_question_uses_read_only_ollama_path(self):
        with mock.patch.object(assistant, "_ollama", return_value=("analysis", "ollama")):
            result = assistant.answer(self.store, "could these two findings be related?")
        self.assertEqual((result["answer"], result["source"]), ("analysis", "ollama"))

    def test_open_question_requests_a_fuller_answer_budget(self):
        # 2026-09-24: the ask persona's cap was raised from 70 to 110 words;
        # num_predict must be raised to match or replies get cut mid-sentence.
        with mock.patch.object(llm, "chat", return_value=("A fuller answer.", "")) as chat:
            assistant._ollama(self.store, "what should i watch?", {})
        self.assertEqual(chat.call_args.kwargs.get("num_predict"), 170)

    def test_open_question_prefers_the_larger_email_model_over_the_dashboard_default(self):
        # Measured live 2026-09-24: llama3.2:1b (the dashboard default) broke
        # persona on open questions with thin context; llama3.2:3b did not.
        with mock.patch.object(llm, "chat", return_value=("A fuller answer.", "")) as chat:
            assistant._ollama(self.store, "what should i watch?",
                              {"ollama_model": "llama3.2:1b", "email_voice_model": "llama3.2:3b"})
        self.assertEqual(chat.call_args.kwargs.get("model"), "llama3.2:3b")

    def test_open_question_falls_back_to_the_dashboard_model_when_nothing_else_is_set(self):
        with mock.patch.object(llm, "chat", return_value=("A fuller answer.", "")) as chat:
            assistant._ollama(self.store, "what should i watch?", {"ollama_model": "qwen3:4b"})
        self.assertEqual(chat.call_args.kwargs.get("model"), "qwen3:4b")

    def test_ask_model_override_wins_over_the_email_model(self):
        with mock.patch.object(llm, "chat", return_value=("A fuller answer.", "")) as chat:
            assistant._ollama(self.store, "what should i watch?",
                              {"ask_model": "custom:model", "email_voice_model": "llama3.2:3b"})
        self.assertEqual(chat.call_args.kwargs.get("model"), "custom:model")

    def test_concurrent_open_question_is_refused_not_queued(self):
        with llm.LOCK, mock.patch.object(llm, "_request") as request:
            text, source = assistant._ollama(self.store, "could these be related?", {})
        self.assertEqual(source, "busy")
        request.assert_not_called()

    def test_model_failure_releases_the_lock(self):
        with mock.patch.object(llm, "_request", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                llm.chat({}, "system", "user")
        self.assertFalse(llm.LOCK.locked())

    def test_windows_loopback_bridge_is_used_when_wsl_loopback_is_separate(self):
        reply = {"message": {"content": "Local evidence explanation"}}
        with mock.patch.object(llm, "_open",
                               side_effect=llm.urllib.error.URLError("offline")), \
             mock.patch.object(llm, "ps_json", return_value=reply) as bridge:
            text, source = assistant._ollama(self.store, "what links these?", {
                "ollama_model": "qwen3:4b-instruct"})
        self.assertEqual((text, source), ("Local evidence explanation", "ollama"))
        bridge.assert_called_once()

    def test_bridge_error_is_reported_not_treated_as_an_answer(self):
        with mock.patch.object(llm, "_open",
                               side_effect=llm.urllib.error.URLError("offline")), \
             mock.patch.object(llm, "ps_json", return_value={"_jarvis_error": "refused"}):
            text, error = llm.chat({}, "system", "user")
        self.assertEqual((text, error), ("", "refused"))


if __name__ == "__main__":
    unittest.main()


class SpokenFactsTests(unittest.TestCase):
    def test_facts_are_grounded_and_live_alerts_mark_urgency(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "t.db"))
            try:
                calm = assistant.spoken_facts(store, JOBS)
                live = assistant.spoken_facts(store, JOBS, live_alerts=2)
            finally:
                store.close()
        self.assertEqual(calm["email"], "spoken dashboard briefing")
        self.assertFalse(calm["urgent"])
        self.assertNotIn("jarvis_is_handling", calm)
        self.assertTrue(live["urgent"])
        self.assertEqual(live["top_findings"], [])


class WakeGreetingTests(unittest.TestCase):
    """While collectors are re-checked after a wake, JARVIS says so and gives
    the last verified score, never a partial sweep's figure."""

    JOBS = {"posture": (600, "p"), "sysmon": (600, "s")}

    def setUp(self):
        from jarvis.response.reporting import score
        self.score = score
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "test.db"))
        t = 1_000_000
        for job in self.JOBS:
            self._snap(job, t)
        score.record(self.store, self.JOBS, t)                 # verified 100
        self.wake = t + 4 * 3600
        score.open_wake_window(self.store, self.wake)
        self._snap("posture", self.wake + 10)                  # sysmon still pending

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _snap(self, job, at):
        self.store.db.execute(
            "INSERT INTO snapshots(kind,ts,duration,error,payload) VALUES(?,?,?,?,?) "
            "ON CONFLICT(kind) DO UPDATE SET ts=excluded.ts, error=excluded.error, "
            "payload=excluded.payload", (job, at, 1.0, "", "[]"))
        self.store.db.commit()

    def test_greeting_reports_re_checking_and_the_verified_score(self):
        text = assistant.greeting(self.store, self.JOBS, self.wake + 20)["text"]
        self.assertIn("re-checking my collectors (1 of 2 current)", text)
        self.assertIn("last fully verified score was 100%", text)
        self.assertNotIn("Security stands at", text)

    def test_greeting_is_live_once_every_collector_reported(self):
        self._snap("sysmon", self.wake + 30)
        text = assistant.greeting(self.store, self.JOBS, self.wake + 40)["text"]
        self.assertIn("Security stands at 100%", text)

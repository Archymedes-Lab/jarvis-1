"""Model guardrails: absolute safety claims cannot reach the user.

Directive-derived invariant: absence of alerts never establishes absence
of compromise, so model text claiming certainty about safety is false
green by construction. These tests pin the preamble contract and every
scrubbed phrasing, plus the assistant wiring that applies both.
"""
import unittest
from unittest import mock

from jarvis.response import assistant, guardrails


class ScrubTests(unittest.TestCase):
    def test_absolute_claims_are_downgraded(self):
        for text in ("You are 100% safe now.",
                     "The machine is completely secure.",
                     "There are no threats.",
                     "Your system is clean.",
                     "Nothing to worry about."):
            out = guardrails.scrub(text)
            self.assertNotEqual(out, text)
            for token in ("100%", "completely secure", "no threats",
                          "system is clean", "nothing to worry about"):
                self.assertNotIn(token, out.lower())

    def test_ordinary_prose_passes_through(self):
        text = ("Two medium findings are open; the oldest is 3 days old. "
                "Run jarvis coverage -v to inspect them.")
        self.assertEqual(guardrails.scrub(text), text)

    def test_empty_and_none_are_safe(self):
        self.assertEqual(guardrails.scrub(""), "")
        self.assertEqual(guardrails.scrub(None), "")

    def test_preamble_forbids_false_green_and_harm(self):
        for token in ("absence of alerts", "human approval", "wiping disks",
                      "disabling protection", "firmware"):
            self.assertIn(token, guardrails.PREAMBLE)


class AssistantWiringTests(unittest.TestCase):
    def test_model_text_is_scrubbed_before_it_reaches_the_user(self):
        with mock.patch.object(assistant.llm, "chat",
                               return_value=("You are 100% safe.", "")):
            import tempfile

            from jarvis.core.store import Store
            with tempfile.TemporaryDirectory() as tmp:
                store = Store(f"{tmp}/t.db")
                try:
                    text, source = assistant._ollama(store, "am I safe?", {})
                finally:
                    store.close()
        self.assertEqual(source, "ollama")
        self.assertNotIn("100%", text)

    def test_preamble_reaches_the_model_system_prompt(self):
        seen = {}
        with mock.patch.object(
                assistant.llm, "chat",
                side_effect=lambda c, s, u, **k: (seen.update(system=s),
                                                  ("ok", ""))[1]):
            import tempfile

            from jarvis.core.store import Store
            with tempfile.TemporaryDirectory() as tmp:
                store = Store(f"{tmp}/t.db")
                try:
                    assistant._ollama(store, "hi", {})
                finally:
                    store.close()
        self.assertIn("absence of alerts", seen["system"])

    def _prompt_for(self, question):
        seen = {}
        with mock.patch.object(
                assistant.llm, "chat",
                side_effect=lambda c, s, u, **k: (seen.update(system=s, user=u), ("ok", ""))[1]), \
                mock.patch.object(assistant.llm, "cooling_down", return_value=False):
            import tempfile

            from jarvis.core.store import Store
            with tempfile.TemporaryDirectory() as tmp:
                store = Store(f"{tmp}/t.db")
                try:
                    assistant._ollama(store, question, {})
                finally:
                    store.close()
        return seen

    def test_general_topic_gets_the_short_prompt_with_the_preamble(self):
        seen = self._prompt_for("explain ransomware in simple words")
        self.assertNotIn("<DATA>", seen["user"])
        self.assertIn("absence of alerts", seen["system"])

    def test_questions_without_a_general_topic_keep_this_computers_data(self):
        for q in ("hi", "what matters most?", "is my laptop hacked by ransomware?"):
            with self.subTest(q):
                seen = self._prompt_for(q)
                self.assertIn("<DATA>", seen["user"])
                self.assertIn("absence of alerts", seen["system"])


if __name__ == "__main__":
    unittest.main()

import os
import tempfile
import unittest

from jarvis.core.store import Store
from jarvis.response import assistant
from jarvis.response import knowledge as kb


class KnowledgeTests(unittest.TestCase):
    def test_common_questions_get_the_right_entry(self):
        cases = {
            "What is phishing?": "Phishing is",
            "how do i make a strong password": "long, different password",
            "Should I use two-factor authentication?": "second proof",
            "I got hit by ransomware, should I pay the ransom?": "Do not pay",
            "do I need antivirus on Windows": "Windows Defender",
            "Is public wifi safe?": "shared with strangers",
            "someone called saying they are Microsoft support": "",
            "what is a VPN": "hides your internet traffic",
            "I think I was hacked what should I do": "change the password",
        }
        for question, expect in cases.items():
            got = kb.lookup(question)
            if expect:
                self.assertIn(expect, got, question)

    def test_unrelated_or_empty_questions_get_nothing_not_a_guess(self):
        for q in ("", "   ", "what is the capital of France", "tell me a joke", "vpnx", "unphishing"):
            self.assertEqual(kb.lookup(q), "", q)

    def test_whole_words_only(self):
        self.assertEqual(kb.lookup("my pet is a vpnish"), "")

    def test_every_entry_is_plain_short_and_safe(self):
        ids = set()
        for entry_id, phrases, answer in kb.ENTRIES:
            self.assertNotIn(entry_id, ids)
            ids.add(entry_id)
            self.assertTrue(phrases and answer.strip())
            self.assertLessEqual(len(answer.split()), 90, entry_id)
            low = answer.lower()
            for banned in ("disable your antivirus", "turn off your antivirus", "turn off the firewall to",
                           "format the", "reinstall windows", "pay the ransom.", "ollama", "llama"):
                self.assertNotIn(banned, low, f"{entry_id}: {banned}")
            self.assertNotRegex(answer, r"\bJARVIS\b")

    def test_the_assistant_answers_without_any_model(self):
        store = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
        try:
            out = assistant.answer(store, "what is phishing", conf={}, jobs={})
            self.assertEqual(out["source"], "knowledge")
            self.assertIn("Phishing is", out["answer"])
            simple = assistant.answer(store, "what is phishing", conf={}, jobs={}, level="simple")
            self.assertIn("Phishing is", simple["answer"])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()

"""JARVIS's protocols: ordered, question-gated, and verified by fresh collector runs."""

import os
import tempfile
import time
import unittest

from jarvis.core.store import Store
from jarvis.response import assistant, protocols
from jarvis.response.reporting import emails, score

SCHEDULE = {"posture": (7200, "posture"), "evasion": (7200, "evasion")}
SECURE_BOOT_OFF = {"category": "platform integrity", "severity": "high", "host": "win",
                   "title": "Secure Boot is off"}
NOT_ENCRYPTED = {"category": "data at rest", "severity": "high", "host": "win",
                 "title": "the system drive C: is not encrypted"}
HVCI_OFF = {"category": "evasion", "severity": "high", "host": "win",
            "title": "Memory Integrity (HVCI) is OFF"}


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def observe(self, posture=(), evasion=()):
        self.store.save_snapshot("posture", list(posture))
        self.store.save_snapshot("evasion", list(evasion))

    def states(self):
        return {i["protocol"].id: i for i in protocols.evaluate(self.store, SCHEDULE)}

    def test_secure_boot_comes_first_and_asks_before_giving_steps(self):
        self.observe([SECURE_BOOT_OFF, NOT_ENCRYPTED], [HVCI_OFF])
        items = self.states()
        self.assertEqual(items["secure-boot"]["state"], protocols.READY)
        self.assertEqual(items["disk-encryption"]["state"], protocols.BLOCKED)
        self.assertEqual(items["memory-integrity"]["state"], protocols.BLOCKED)
        text = "\n".join(protocols.render(items["secure-boot"]))
        self.assertIn("A question first", text)
        self.assertNotIn("UEFI Firmware Settings", text)

    def test_no_answer_withholds_steps_and_yes_releases_them(self):
        self.observe([SECURE_BOOT_OFF])
        ok, message = protocols.answer(self.store, "secure-boot", "no")
        self.assertTrue(ok)
        self.assertIn("signed", message)
        item = self.states()["secure-boot"]
        self.assertEqual(item["state"], protocols.WAITING)
        self.assertNotIn("UEFI Firmware Settings", "\n".join(protocols.render(item)))

        protocols.answer(self.store, "secure-boot", "yes")
        item = self.states()["secure-boot"]
        self.assertEqual(item["state"], protocols.READY)
        self.assertIn("UEFI Firmware Settings", "\n".join(protocols.render(item)))

    def test_questions_are_asked_one_at_a_time(self):
        self.observe([NOT_ENCRYPTED])
        _, message = protocols.answer(self.store, "disk-encryption", "yes")
        self.assertIn("backed up", message)
        protocols.answer(self.store, "disk-encryption", "yes")
        _, message = protocols.answer(self.store, "disk-encryption", "yes")
        self.assertIn("steps are yours", message)
        self.assertFalse(protocols.answer(self.store, "disk-encryption", "yes")[0])

    def test_done_needs_a_fresh_run_without_the_finding(self):
        self.observe([NOT_ENCRYPTED])
        items = self.states()
        self.assertEqual(items["secure-boot"]["state"], protocols.DONE)
        self.assertEqual(items["disk-encryption"]["state"], protocols.READY)

    def test_a_stale_collector_cannot_mark_a_protocol_done(self):
        self.observe([NOT_ENCRYPTED])
        stale = int(time.time()) - 86400
        self.store.db.execute("UPDATE snapshots SET ts=?", (stale,))
        self.store.commit()
        items = self.states()
        self.assertEqual(items["secure-boot"]["state"], protocols.UNVERIFIED)
        self.assertEqual(items["disk-encryption"]["state"], protocols.BLOCKED)

    def test_blocked_protocol_still_shows_its_steps_when_asked_in_full(self):
        self.observe([SECURE_BOOT_OFF, NOT_ENCRYPTED])
        for _ in protocols.BY_ID["disk-encryption"].questions:
            protocols.answer(self.store, "disk-encryption", "yes")
        item = self.states()["disk-encryption"]
        full, brief = protocols.render(item, full=True), protocols.render(item, full=False)
        self.assertIn("Manage BitLocker", "\n".join(full))
        self.assertIn("First: Switch on Secure Boot", "\n".join(full))
        self.assertNotIn("Manage BitLocker", "\n".join(brief))

    def test_projected_score_is_the_real_score_without_those_findings(self):
        self.observe([SECURE_BOOT_OFF, NOT_ENCRYPTED], [HVCI_OFF])
        item = self.states()["secure-boot"]
        expected = score.compute(
            {"posture": {"ts": int(time.time()), "findings": [NOT_ENCRYPTED]},
             "evasion": {"ts": int(time.time()), "findings": [HVCI_OFF]}}, SCHEDULE)["score"]
        self.assertEqual(item["score_after"], expected)
        self.assertGreater(item["score_after"], item["score_now"])
        _, all_done = protocols.projected_all(self.store, SCHEDULE)
        self.assertGreater(all_done, item["score_after"])

    def test_the_email_carries_the_whole_protocol_including_its_steps(self):
        self.observe([SECURE_BOOT_OFF, NOT_ENCRYPTED])
        state = protocols.evaluate(self.store, SCHEDULE)
        result = score.compute(self.store.get_snapshots(), SCHEDULE)
        _s, text, html = emails.health(result, None, self.store.get_snapshots(),
                                       int(time.time()), self.store, protocol_state=state)
        for expected in ("Switch on Secure Boot", "Answer first",
                         "UEFI Firmware Settings", "Caution:",
                         "Queued after this: Encrypt the system drive"):
            self.assertIn(expected, text)
        self.assertIn("JARVIS briefing", html)
        self.assertIn("jarvis brief yes secure-boot", html)

    def test_the_email_gives_bitlocker_its_manual_steps_and_its_command_route(self):
        self.observe([NOT_ENCRYPTED])
        lines = protocols.email_lines(self.states()["disk-encryption"])
        joined = "\n".join(lines)
        for expected in ("Manage BitLocker", "recovery key", "Encrypt used disk space only",
                         "manage-bde -on C:", "Caution:"):
            self.assertIn(expected, joined)

    def test_assistant_still_answers_what_to_do_next(self):
        self.observe([SECURE_BOOT_OFF])
        answer = assistant.answer(self.store, "what should I do next?", conf={}, jobs=SCHEDULE)
        self.assertEqual(answer["source"], "builtin")
        self.assertIn("Secure Boot", answer["answer"])

    def test_nothing_to_raise_when_every_protocol_is_done(self):
        self.observe()
        self.assertIsNone(protocols.next_briefing(self.store, SCHEDULE))


    def test_greeting_leads_with_status_then_the_pending_protocol_question(self):
        self.observe([SECURE_BOOT_OFF])
        greeting = assistant.greeting(self.store, SCHEDULE)
        lines = greeting["text"].splitlines()
        self.assertTrue(lines[1].startswith("Security stands at"))
        self.assertIn("Switch on Secure Boot", greeting["text"])
        self.assertEqual(greeting["pending"]["protocol"], "secure-boot")

        protocols.answer(self.store, "secure-boot", "no")
        greeting = assistant.greeting(self.store, SCHEDULE)
        self.assertIsNone(greeting["pending"])
        self.assertIn("Still waiting on this", greeting["text"])

    def test_greeting_warns_first_when_monitoring_is_blind(self):
        self.observe([SECURE_BOOT_OFF])
        self.store.db.execute("UPDATE snapshots SET ts=? WHERE kind='evasion'",
                              (int(time.time()) - 86400,))
        self.store.commit()
        lines = assistant.greeting(self.store, SCHEDULE)["text"].splitlines()
        self.assertIn("not reporting (evasion)", lines[1])

    def test_greeting_salutation_follows_the_clock(self):
        for hour, expected in ((8, "Good morning."), (14, "Good afternoon."),
                               (20, "Good evening."), (1, "Working late, I see.")):
            with self.subTest(hour=hour):
                moment = time.mktime((2026, 9, 16, hour, 0, 0, 0, 0, -1))
                self.assertEqual(assistant._salutation(moment), expected)

if __name__ == "__main__":
    unittest.main()


class ActionPlanTests(unittest.TestCase):
    """The on-request email: every manual task, steps by hand, notes by model."""

    ON = {"email_voice": True}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.store.save_snapshot("posture", [SECURE_BOOT_OFF, NOT_ENCRYPTED])
        self.store.save_snapshot("evasion", [HVCI_OFF])

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def plan(self, reply):
        from unittest import mock

        from jarvis.response import llm
        state = protocols.evaluate(self.store, SCHEDULE)
        result = score.compute(self.store.get_snapshots(), SCHEDULE)
        with mock.patch.object(llm, "chat", return_value=reply):
            return emails.action_plan(result, state, self.store.get_snapshots(),
                                      int(time.time()), self.store, self.ON)

    def test_every_task_arrives_in_order_with_all_its_steps(self):
        _s, text, _h, _n = self.plan(("", "offline"))
        order = [text.index(t) for t in ("Task 1 · Switch on Secure Boot",
                                         "Task 2 · Bring Memory Integrity",
                                         "Task 3 · Encrypt the system drive")]
        self.assertEqual(order, sorted(order))
        for step in (*protocols.BY_ID["secure-boot"].steps,
                     *protocols.BY_ID["disk-encryption"].steps):
            self.assertIn(step, text)

    def test_model_notes_are_marked_and_counted(self):
        subject, text, html, personalized = self.plan(("A worthwhile trip into the firmware.", ""))
        self.assertIn("[local model] A worthwhile trip into the firmware.", text)
        self.assertIn("— local model", html)
        self.assertGreaterEqual(personalized, 3)
        self.assertIn("action plan", subject)

    def test_model_offline_falls_back_to_hand_written_briefs(self):
        _s, text, _h, personalized = self.plan(("", "offline"))
        self.assertEqual(personalized, 0)
        self.assertIn(protocols.BY_ID["secure-boot"].brief, text)
        self.assertNotIn("[local model]", text)

    def test_a_blocked_task_is_never_urged_on_today(self):
        from unittest import mock

        from jarvis.response import llm
        from jarvis.response.reporting import voice
        blocked = self.states_by_id()["disk-encryption"]
        with mock.patch.object(llm, "chat", return_value=("Encrypt it right now.", "")):
            note, by_model = voice.task_note(self.ON, blocked)
        self.assertFalse(by_model)
        self.assertEqual(note, protocols.BY_ID["disk-encryption"].brief)

    def test_a_note_claiming_the_task_is_done_is_rejected(self):
        from unittest import mock

        from jarvis.response import llm
        from jarvis.response.reporting import voice
        ready = self.states_by_id()["secure-boot"]
        for claim in ("Secure Boot is now switched on, a hurdle cleared.",
                      "With that done, the boot chain is checked.",
                      "A trio of features waits on this."):
            with self.subTest(claim=claim), \
                 mock.patch.object(llm, "chat", return_value=(claim, "")):
                self.assertEqual(voice.task_note(self.ON, ready)[1], False)

    def test_task_examples_pass_the_rules_they_teach(self):
        import json

        from jarvis.response.reporting import voice
        for asked, answered in voice.TASK_EXAMPLES:
            facts = json.loads(asked)
            with self.subTest(note=answered):
                self.assertTrue(voice._within_rules(answered, facts))
                self.assertIsNone(voice._DONE.search(answered))

    def test_findings_a_task_resolves_are_not_listed_twice(self):
        _s, text, _h, _n = self.plan(("", "offline"))
        self.assertEqual(text.count("Secure Boot is off"), 1)

    def states_by_id(self):
        return {i["protocol"].id: i for i in protocols.evaluate(self.store, SCHEDULE)}

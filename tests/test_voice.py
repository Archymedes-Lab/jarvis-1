"""The model may colour an email, never change what it says."""

import unittest
from unittest import mock

from jarvis.response import llm
from jarvis.response.reporting import emails, triage, voice

ON = {"email_voice": True}


def facts(action=1, confirm=0, urgent=False):
    counts = {triage.YOU_DO: action, triage.YOU_CONFIRM: confirm, triage.JARVIS: 2}
    health = {"score": 43, "grade": "at risk"}
    return voice.facts_for("daily security health", counts, urgent, health, -2,
                           top=["OpenAI API key in plaintext"])


class AcceptanceTests(unittest.TestCase):
    def test_short_in_character_prose_with_known_numbers_passes(self):
        self.assertTrue(voice.acceptable(
            "Your score sits at 43, and one matter needs your hands. Tea first, perhaps.",
            facts()))

    def test_invented_number_is_rejected(self):
        self.assertFalse(voice.acceptable("I found 7 threats.", facts()))

    def test_punctuation_is_not_mistaken_for_a_number(self):
        self.assertTrue(voice.acceptable("One matter — only one — needs you.", facts()))

    def test_commands_links_and_markup_are_rejected(self):
        for text in ("Run `chmod 600 ~/.env` at once.", "Just sudo it.",
                     "See https://example.com for more.", "<b>Hello</b>",
                     "Try jarvis ack abcd1234 when ready."):
            with self.subTest(text=text):
                self.assertFalse(voice.acceptable(text, facts()))

    def test_reassurance_is_rejected_while_something_needs_you(self):
        self.assertFalse(voice.acceptable("All clear today.", facts(action=1)))
        self.assertFalse(voice.acceptable("All is right with the world once more.", facts(action=1)))
        self.assertTrue(voice.acceptable("All clear today.", facts(action=0)))

    def test_unproven_alarm_and_gendered_address_are_rejected(self):
        self.assertFalse(voice.acceptable("You have been hacked.", facts()))
        self.assertFalse(voice.acceptable("Good morning, sir.", facts()))

    def test_spelled_out_invented_number_is_rejected(self):
        self.assertFalse(voice.acceptable("Seven matters await you.", facts()))
        self.assertTrue(voice.acceptable("This one would not keep.", facts()))

    def test_restated_severity_and_lists_are_rejected(self):
        self.assertFalse(voice.acceptable("Both of which are critical.", facts()))
        self.assertFalse(voice.acceptable("What to do: - rotate the key", facts()))

    def test_score_direction_must_match_the_facts(self):
        falling = facts()                                            # down 2 points
        self.assertFalse(voice.acceptable("The score has climbed to 43.", falling))
        self.assertTrue(voice.acceptable("The score has slipped to 43.", falling))
        rising = voice.facts_for("daily security health", {}, False,
                                 {"score": 81, "grade": "good"}, 3)
        self.assertFalse(voice.acceptable("A modest dip to 81.", rising))
        flat = voice.facts_for("daily security health", {}, False, {"score": 81, "grade": "good"})
        self.assertFalse(voice.acceptable("The score improved to 81.", flat))
        self.assertTrue(voice.acceptable("The score rests at 81.", flat))

    def test_hyperbole_and_casual_gendered_address_are_rejected(self):
        self.assertFalse(voice.acceptable("A precipitous fall, I'm afraid.", facts()))
        self.assertFalse(voice.acceptable("Still a good show, old chap.", facts(action=0)))

    def test_claims_of_action_or_past_warnings_are_rejected(self):
        for text in ("I've taken matters into my own hands with the API key.",
                     "I have secured Remote Desktop.",
                     "Both of which I had previously cautioned about.",
                     "Shall I take care of it for you?"):
            with self.subTest(text=text):
                self.assertFalse(voice.acceptable(text, facts()))

    def test_idiomatic_claims_of_remediation_are_rejected(self):
        # Measured 2026-09-24 (live llama3.2:3b, widened cap): findings that
        # were only listed, not fixed, described as "neatly filed away".
        for text in ("The SSH server and guest account have been neatly filed away.",
                     "Those two are tidied away for good.",
                     "Consider it squared away."):
            with self.subTest(text=text):
                self.assertFalse(voice.acceptable(text, facts()))

    def test_trend_is_given_in_words(self):
        self.assertEqual(facts()["score_trend"], "down 2 points")
        self.assertEqual(voice._trend(1), "up 1 point")

    def test_examples_satisfy_the_rules_they_teach(self):
        for asked, answered in voice.EXAMPLES:
            with self.subTest(note=answered):
                self.assertTrue(voice.acceptable(answered, voice.json.loads(asked)))

    def test_overlong_text_is_rejected(self):
        self.assertFalse(voice.acceptable("word " * 80, facts()))

    def test_widened_cap_still_has_a_boundary(self):
        # 2026-09-24: MAX_WORDS/MAX_CHARS were raised for a richer voice; the
        # gate must still reject text past the new line, not just the old one.
        self.assertTrue(voice.acceptable("word " * voice.MAX_WORDS, facts()))
        self.assertFalse(voice.acceptable("word " * (voice.MAX_WORDS + 1), facts()))


class OpenerTests(unittest.TestCase):
    def test_off_by_default_never_calls_the_model(self):
        with mock.patch.object(llm, "chat") as chat:
            line, by_model = voice.opener({}, facts(), "2026-09-15")
        chat.assert_not_called()
        self.assertFalse(by_model)
        self.assertIn(line, voice._FALLBACK["needs_you"])

    def test_accepted_model_line_is_used(self):
        with mock.patch.object(llm, "chat", return_value=('"One matter needs you."', "")):
            self.assertEqual(voice.opener(ON, facts()), ("One matter needs you.", True))

    def test_rejected_or_failed_model_line_falls_back(self):
        for reply in (("You were hacked.", ""), ("", "offline"), ("", llm.BUSY)):
            with self.subTest(reply=reply), mock.patch.object(llm, "chat", return_value=reply):
                line, by_model = voice.opener(ON, facts(urgent=True))
                self.assertFalse(by_model)
                self.assertIn(line, voice._FALLBACK["urgent"])

    def test_fallback_is_stable_for_a_day(self):
        self.assertEqual(voice.fallback(facts(), "2026-09-15"), voice.fallback(facts(), "2026-09-15"))

    def test_fallback_lines_do_not_trip_their_own_checks(self):
        for situation, lines in voice._FALLBACK.items():
            state = facts(action=0) if situation == "quiet" else facts(urgent=situation == "urgent")
            for line in lines:
                with self.subTest(line=line):
                    self.assertTrue(voice.acceptable(line, state))


class EmailTests(unittest.TestCase):
    def test_model_line_opens_the_email_but_the_report_is_unchanged(self):
        finding = {"category": "present", "severity": "critical", "host": "wsl",
                   "title": "OpenAI API key in plaintext", "where": "/h/.env:1"}
        ordered = [("a", {"finding": finding, "job": "secrets", "tag": "NEW",
                          "first": 0, "level": 0})]
        plain = emails.digest(ordered, True, None, None, 7200)
        with mock.patch.object(llm, "chat", return_value=("Forgive the hour.", "")):
            voiced = emails.digest(ordered, True, None, None, 7200, conf=ON)
        self.assertEqual(plain[0], voiced[0])                      # subject
        self.assertIn("Forgive the hour.", voiced[1])
        self.assertIn("Forgive the hour.", voiced[2])
        self.assertIn("written by the local model", voiced[2])
        self.assertIn("$ chmod 600 /h/.env", voiced[1])
        lines, voiced_lines = plain[1].split("\n"), voiced[1].split("\n")
        mood = lines.index("These need you now.")
        # Only the opener differs: the plain part above it and the report below it do not.
        self.assertEqual(lines[:mood + 1], voiced_lines[:mood + 1])
        self.assertEqual(lines[mood + 3:], voiced_lines[mood + 3:])

    def test_model_text_is_escaped_in_html(self):
        with mock.patch.object(voice, "acceptable", return_value=True), \
             mock.patch.object(llm, "chat", return_value=("Tom & Jerry", "")):
            _s, _t, html = emails.digest([], False, None, None, 7200, conf=ON)
        self.assertIn("Tom &amp; Jerry", html)


class VarietyTests(unittest.TestCase):
    class Store:
        def __init__(self):
            self.meta = {}

        def get_meta(self, key, default=None):
            return self.meta.get(key, default)

        def set_meta(self, key, value):
            self.meta[key] = value

    def test_style_examples_satisfy_the_rules_they_teach(self):
        for name, _direction, (asked, answered) in voice.STYLES:
            with self.subTest(style=name):
                self.assertTrue(voice.acceptable(answered, voice.json.loads(asked)))

    def test_a_repeated_line_is_refused_and_another_style_is_tried(self):
        store = self.Store()
        line = "One matter needs you, and the score sits at 43."
        with mock.patch.object(llm, "chat", return_value=(line, "")):
            self.assertEqual(voice.opener(ON, facts(), "d1", store=store), (line, True))
        replies = iter([(line, ""), ("A single task is ready for your hands.", "")])
        with mock.patch.object(llm, "chat", side_effect=lambda *a, **k: next(replies)) as chat:
            got, by_model = voice.opener(ON, facts(), "d2", store=store)
        self.assertEqual((got, by_model), ("A single task is ready for your hands.", True))
        self.assertEqual(chat.call_count, 2)
        self.assertIn("style", voice.json.loads(store.meta[voice.RECENT_META]))

    def test_fallbacks_rotate_away_from_recent_lines(self):
        store = self.Store()
        seen = [voice.opener({}, facts(), "same-day", store=store)[0] for _ in range(4)]
        self.assertEqual(len(set(seen)), 4)
        for line in seen:
            self.assertIn(line, voice._FALLBACK["needs_you"])

    def test_styles_never_repeat_the_last_one_and_interrupts_stay_serious(self):
        f = facts()
        first = voice.styles_for(f, "d")[0][0]
        self.assertNotEqual(voice.styles_for(f, "d", last_style=first)[0][0], first)
        urgent = facts(urgent=True)
        for day in ("a", "b", "c", "d"):
            for name, *_rest in voice.styles_for(urgent, day):
                self.assertIn(name, ("mission control", "sidekick", "field report"))

    def test_measured_gloom_and_misattributed_counts_are_rejected(self):
        f = dict(facts(action=9), new_since_last_briefing=1)
        self.assertFalse(voice.acceptable(
            "A sombre morning, the score stuck at 43, a worrying state of affairs.", f))
        self.assertFalse(voice.acceptable("Nine new matters await your attention.", f))
        self.assertTrue(voice.acceptable("One new matter since last time, nine on the list.", f))

    def test_offline_model_is_asked_once(self):
        with mock.patch.object(llm, "chat", return_value=("", "offline")) as chat:
            voice.opener(ON, facts(), "d", store=self.Store())
        self.assertEqual(chat.call_count, 1)


if __name__ == "__main__":
    unittest.main()


class SpokenTests(unittest.TestCase):
    def setUp(self):
        voice._spoken_cache.clear()

    def spoken(self, live=0):
        f = facts(urgent=bool(live))
        f["email"] = "spoken dashboard briefing"
        return f

    def test_examples_and_fallbacks_satisfy_the_rules(self):
        for asked, answered in voice.SPOKEN_EXAMPLES:
            view = voice.json.loads(asked)
            with self.subTest(line=answered):
                self.assertTrue(voice._within_rules(answered, view))
                self.assertFalse(voice._contradicts_trend(answered, view))
                self.assertIsNone(voice._SPOKEN_EXTRA.search(answered))
        for situation, lines in voice._SPOKEN_FALLBACK.items():
            state = facts(action=0) if situation == "quiet" else facts(urgent=situation == "urgent")
            for line in lines:
                with self.subTest(line=line):
                    self.assertTrue(voice.acceptable(line, state))

    def test_on_by_default_and_the_line_is_checked(self):
        with mock.patch.object(llm, "chat", return_value=("One matter needs you, splendid.", "")):
            self.assertEqual(voice.spoken_opener({}, self.spoken()),
                             ("One matter needs you, splendid.", True))
        voice._spoken_cache.clear()
        with mock.patch.object(llm, "chat", return_value=("You are all clear.", "")):
            line, by_model = voice.spoken_opener({}, self.spoken())
        self.assertFalse(by_model)
        self.assertIn(line, voice._SPOKEN_FALLBACK["needs_you"])

    def test_live_alert_skips_the_model(self):
        with mock.patch.object(llm, "chat") as chat:
            line, by_model = voice.spoken_opener({}, self.spoken(live=1))
        chat.assert_not_called()
        self.assertFalse(by_model)
        self.assertIn(line, voice._SPOKEN_FALLBACK["urgent"])

    def test_opt_out_and_busy_model_never_wait(self):
        with mock.patch.object(llm, "chat") as chat:
            voice.spoken_opener({"dashboard_voice": False}, self.spoken())
        chat.assert_not_called()
        with mock.patch.object(llm, "chat", return_value=("", llm.BUSY)) as chat:
            _line, by_model = voice.spoken_opener({}, self.spoken())
        self.assertFalse(by_model)
        self.assertEqual(chat.call_args.kwargs.get("wait", 0), 0)

    def test_counts_are_not_shown_to_the_model_or_repeatable_by_it(self):
        f = self.spoken()
        f["needs_your_action"], f["needs_your_confirmation"] = 5, 10
        with mock.patch.object(llm, "chat", return_value=("Five and ten ticks closer.", "")) as chat:
            _line, by_model = voice.spoken_opener({}, f)
        self.assertFalse(by_model)
        sent = voice.json.loads(chat.call_args.args[2])
        self.assertNotIn("needs_your_action", sent)
        self.assertTrue(sent["work_waiting_for_the_user"])

    def test_same_facts_reuse_the_line(self):
        with mock.patch.object(llm, "chat", return_value=("Splendid to see you.", "")) as chat:
            voice.spoken_opener({}, self.spoken(), now=1000)
            voice.spoken_opener({}, self.spoken(), now=1300)
        self.assertEqual(chat.call_count, 1)

    def test_invented_intruders_rescues_and_gloom_are_rejected(self):
        for text in ("It seems someone's been playing with the system.",
                     "Reinforcements are on the way.",
                     "Our friends are up to something.",
                     "A bit of a mess, I must sound the alarm.",
                     "Progress is a slow, stubborn thing.",
                     "Now, about that pressing matter..."):
            voice._spoken_cache.clear()
            with self.subTest(text=text), mock.patch.object(llm, "chat", return_value=(text, "")):
                self.assertFalse(voice.spoken_opener({}, self.spoken())[1])

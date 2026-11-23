"""Cascade tests: local-first routing with Jev escalation and fallback.

Invariants: confident local votes decide locally without network; doubt
escalates to Jev with metadata-only state; total failure falls back
deterministically. Content asymmetry pinned: the local leg may see full
context (loopback), the Jev leg never does.
"""
import unittest
from unittest import mock

from jarvis.response import cascade


def _local(text, err="", ready=True):
    ping = ("model_loaded", 0.1) if ready else ("offline", 0.0)
    return (mock.patch("jarvis.response.cascade.llm_mod.ping",
                       return_value=ping),
            mock.patch("jarvis.response.cascade.llm_mod.chat",
                       return_value=(text, err)))


class ParseTests(unittest.TestCase):
    def test_strict_vote_shapes(self):
        self.assertEqual(cascade._parse_vote("YES 92"),
                         {"vote": True, "confidence": 0.92})
        self.assertEqual(cascade._parse_vote("no 10"),
                         {"vote": False, "confidence": 0.10})
        for bad in ("", "YES", "MAYBE 80", "YES 101", "YES high",
                    "Sure thing"):
            self.assertIsNone(cascade._parse_vote(bad))

    def test_out_of_range_confidence_is_doubt(self):
        self.assertIsNone(cascade._parse_vote("YES 1000"))


class RouteTests(unittest.TestCase):
    def test_confident_local_vote_decides_without_network(self):
        ping, chat = _local("YES 95\nClear match.")
        with ping, chat, mock.patch(
                "jarvis.response.cascade.jev_mod._call") as jev:
            out = cascade.ask_yesno("Q?", "full context", {"k": 1}, {})
        self.assertEqual(out["route"], "local")
        self.assertTrue(out["vote"])
        jev.assert_not_called()

    def test_uncertain_local_vote_escalates_to_jev(self):
        ping, chat = _local("YES 55\nUnclear.")
        payload = {"model": "jev-1.13.0",
                   "answers": {"q": {"type": "noul", "noul": 0.8}}, "usage": {}}
        with ping, chat, mock.patch(
                "jarvis.response.cascade.jev_mod._call",
                return_value=payload) as jev:
            out = cascade.ask_yesno("Q?", "ctx", {"k": 1}, {})
        self.assertEqual(out["route"], "jev")
        self.assertTrue(out["vote"])
        self.assertEqual(out["probability"], 0.8)
        self.assertNotIn("confidence", out)
        self.assertNotIn("band", out)
        jev.assert_called_once()

    def test_unparseable_local_vote_escalates(self):
        ping, chat = _local("Probably yes, I think.")
        with ping, chat, mock.patch(
                "jarvis.response.cascade.jev_mod._call",
                return_value={"answers": {"q": {"noul": 0.2}}}):
            out = cascade.ask_yesno("Q?", "ctx", {}, {})
        self.assertEqual(out["route"], "jev")
        self.assertFalse(out["vote"])

    def test_local_down_uses_jev_directly(self):
        ping, chat = _local("", "busy", ready=True)
        with ping, chat, mock.patch(
                "jarvis.response.cascade.jev_mod._call",
                return_value={"answers": {"q": {"noul": 0.9}}}):
            out = cascade.ask_yesno("Q?", "ctx", {}, {})
        self.assertEqual(out["route"], "jev")

    def test_offline_model_skips_to_jev_without_chat(self):
        ping, chat = _local("YES 99", ready=False)
        with ping, chat as chat_mock, mock.patch(
                "jarvis.response.cascade.jev_mod._call",
                return_value={"answers": {"q": {"noul": 0.9}}}):
            out = cascade.ask_yesno("Q?", "ctx", {}, {})
        chat_mock.assert_not_called()
        self.assertEqual(out["route"], "jev")

    def test_both_down_falls_back_deterministically(self):
        ping, chat = _local("", "offline")
        with ping, chat, mock.patch(
                "jarvis.response.cascade.jev_mod._call",
                side_effect=cascade.jev_mod.JevError("down")):
            out = cascade.ask_yesno("Q?", "ctx", {}, {})
        self.assertEqual(out["route"], "fallback")
        self.assertIsNone(out["vote"])
        self.assertTrue(out["advisory_only"])


class AsymmetryTests(unittest.TestCase):
    def test_jev_leg_carries_redacted_text_only(self):
        seen = {}
        ping, chat = _local("YES 40\nUnsure.")
        with ping, chat, mock.patch(
                "jarvis.response.cascade.jev_mod._call",
                side_effect=lambda s, q: seen.update(state=s) or
                {"answers": {"q": {"noul": 0.5}}}):
            cascade.judge_proposal(
                {"title": "t", "problem": "login with password=hunter2 at "
                                          "https://shop.example/private-cart",
                 "evidence": ["x"], "key": "k"}, {})
        blob = str(seen["state"])
        # Best-effort redaction: credentials and URL content are masked.
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("private-cart", blob)
        # Bounded: truncation holds on every text field.
        self.assertLessEqual(len(seen["state"]["problem"]), 500)

    def test_local_leg_may_see_full_context(self):
        seen = {}
        ping, chat = _local("NO 95\nClear.")
        with ping, chat as chat_mock:
            chat_mock.side_effect = lambda c, s, u, **k: (
                seen.update(user=u) or ("NO 95\nClear.", ""))
            cascade.judge_proposal(
                {"title": "t", "problem": "detail here",
                 "evidence": [], "key": "k"}, {})
        self.assertIn("detail here", seen["user"])

    def test_proposal_recommendations(self):
        ping, chat = _local("YES 95\nClear.")
        with ping, chat:
            out = cascade.judge_proposal({"title": "t"}, {})
        self.assertEqual(out["recommendation"], "investigate")
        self.assertEqual(out["judgment"], "proposal")

    def test_empty_patch_short_circuits_without_calls(self):
        with mock.patch(
                "jarvis.response.cascade.llm_mod.ping") as ping, mock.patch(
                "jarvis.response.cascade.jev_mod._call") as jev:
            out = cascade.validate_patch({"patch_draft": "  "}, {})
        ping.assert_not_called()
        jev.assert_not_called()
        self.assertEqual(out["recommendation"], "no patch draft")


if __name__ == "__main__":
    unittest.main()

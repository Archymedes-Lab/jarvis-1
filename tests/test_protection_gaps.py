"""Regressions for PROTECTION-REVIEW-2026-10-21: F1 channel finding, F4 peer
collapse, C1 answer-route authority and unacknowledgeable guard findings."""

import unittest
from unittest import mock

from jarvis.intel import hunt
from jarvis.response import acknowledge, alert, questions


class ChannelFindingTests(unittest.TestCase):
    def test_unconfigured_mail_is_a_critical_daemon_finding(self):
        out = alert.channel_findings({})
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["severity"], out[0]["category"]), ("critical", "daemon"))
        self.assertIn("key, sender, recipient", out[0]["detail"])
        self.assertFalse(acknowledge.can_acknowledge(out[0]))

    def test_configured_mail_reports_nothing(self):
        conf = {"resend_api_key": "re_x", "alert_from": "a@b", "alert_to": "c@d"}
        self.assertEqual(alert.channel_findings(conf), [])


def hit(ip, pname="btweb.exe", sev="critical", feed="blocklist-de", host="win"):
    return {"ip": ip, "port": 1, "pname": pname, "label": "attacking host", "feed": feed,
            "src": "u", "host": host, "severity": sev,
            "qualifier": "known attacker" if sev == "critical" else "threat-intelligence",
            "reasons": []}


class PeerCollapseTests(unittest.TestCase):
    def test_one_listed_peer_reads_as_before(self):
        out = hunt.collapse_peer_hits([hit("1.2.3.4")])
        self.assertEqual(out[0]["title"], "contacted a known attacker IP: 1.2.3.4")

    def test_many_peers_of_one_process_become_one_finding_with_a_count(self):
        hits = [hit(f"10.0.0.{i}") for i in range(1, 233)] + [hit("9.9.9.9", sev="medium", feed="cins")]
        out = hunt.collapse_peer_hits(hits)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "critical")
        self.assertIn("btweb.exe contacted 233 listed IPs (232 corroborated)", out[0]["title"])
        self.assertIn("blocklist-de, cins", out[0]["detail"])
        self.assertIn("10.0.0.1:1", out[0]["detail"])

    def test_a_few_listed_peers_stay_individual_findings(self):
        # Jev (advisory, 0.52) worried a real C2 contact could hide behind a noisy
        # client; a process with up to five listed peers is never collapsed.
        out = hunt.collapse_peer_hits([hit(f"5.5.5.{i}", "svc.exe") for i in range(1, 6)])
        self.assertEqual(len(out), 5)
        self.assertTrue(all(o["title"].startswith("contacted a known attacker IP") for o in out))

    def test_processes_and_hosts_are_kept_apart(self):
        # Six listed peers for a.exe on win collapse; the rest stay individual.
        out = hunt.collapse_peer_hits([hit(f"1.1.1.{i}", "a.exe") for i in range(1, 7)]
                                      + [hit("3.3.3.3", "b.exe"), hit("4.4.4.4", "a.exe", host="wsl")])
        self.assertEqual(len(out), 3)
        self.assertTrue(any("a.exe contacted 6 listed IPs" in o["title"] for o in out))


class AnswerAuthorityTests(unittest.TestCase):
    def test_no_answer_proposes_and_never_approves(self):
        finding = {"category": "c2 match", "severity": "critical", "title": "t", "detail": "d",
                   "where": "", "host": "win"}
        action = mock.Mock(title="Block it")
        store = mock.Mock()
        with mock.patch.object(questions.acknowledge, "resolve", return_value=(finding, "hunt")), \
             mock.patch.object(questions.acknowledge, "load", return_value={}), \
             mock.patch.object(questions.alert, "load_conf", return_value={}), \
             mock.patch.object(questions.defense, "decide", return_value=("propose", action, {"ip": "1.2.3.4"})), \
             mock.patch.object(questions.defense, "_propose",
                               return_value=("abc12345", {"preview": "Block 1.2.3.4."}, True)), \
             mock.patch.object(questions.defense, "approve") as approve:
            ok, text = questions.answer(store, "abc12345", "no")
        self.assertTrue(ok)
        self.assertIn("proposed", text)
        self.assertIn("jarvis defend approve abc12345", text)
        approve.assert_not_called()


class UnacknowledgeableTests(unittest.TestCase):
    def test_tamper_and_visibility_findings_cannot_be_acknowledged(self):
        for cat in ("tamper", "tampering", "visibility", "daemon", "collectors"):
            self.assertFalse(acknowledge.can_acknowledge(
                {"category": cat, "severity": "high", "title": "t"}), cat)
        self.assertTrue(acknowledge.can_acknowledge(
            {"category": "attack surface", "severity": "high", "title": "t"}))


if __name__ == "__main__":
    unittest.main()

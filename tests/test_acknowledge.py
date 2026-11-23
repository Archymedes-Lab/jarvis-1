import os
import tempfile
import unittest

from jarvis.core.store import Store
from jarvis.response import acknowledge as ack
from jarvis.response.reporting import score, triage
from jarvis.service.schedule import JOBS

NOW = 2_000_000_000


def f(sev="high", title="account hidden from the sign-in screen: CodexSandbox",
      category="accounts", detail="hidden from view", where="Winlogon"):
    return {"category": category, "severity": sev, "title": title, "detail": detail,
            "where": where, "host": "win"}


class AcknowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_a_reason_is_required(self):
        with self.assertRaises(ValueError):
            ack.acknowledge(self.store, f(), "backdoor", "  ", now=NOW)

    def test_outages_cannot_be_acknowledged(self):
        outage = f("high", "the Windows monitor's email path is failing", "daemon")
        with self.assertRaises(ValueError):
            ack.acknowledge(self.store, outage, "watchdogs", "noise", now=NOW)

    def test_acknowledged_until_it_expires(self):
        ack.acknowledge(self.store, f(), "backdoor", "Codex sandbox account", days=30, now=NOW)
        acks = ack.load(self.store)
        self.assertTrue(ack.is_acknowledged(acks, f(), "backdoor", NOW + 29 * 86400))
        self.assertFalse(ack.is_acknowledged(acks, f(), "backdoor", NOW + 30 * 86400))

    def test_a_worse_recurrence_is_not_covered(self):
        ack.acknowledge(self.store, f("medium"), "backdoor", "expected", now=NOW)
        acks = ack.load(self.store)
        self.assertTrue(ack.is_acknowledged(acks, f("low"), "backdoor", NOW))
        self.assertFalse(ack.is_acknowledged(acks, f("critical"), "backdoor", NOW))

    def test_only_the_confirmed_finding_is_covered(self):
        ack.acknowledge(self.store, f(detail="entry A"), "control", "mine", now=NOW)
        acks = ack.load(self.store)
        self.assertFalse(ack.is_acknowledged(acks, f(detail="entry B"), "control", NOW))
        self.assertFalse(ack.is_acknowledged(acks, f(detail="entry A"), "backdoor", NOW))

    def test_ids_ignore_timestamps_and_pids_in_the_detail(self):
        a = f(detail="dwm.exe 2026-09-14 22:22:28 created a thread [last seen 2026-09-14 23:23:42]")
        b = f(detail="dwm.exe 2026-09-15 09:01:02 created a thread [last seen 2026-09-15 11:00:00]")
        self.assertEqual(ack.finding_id(a, "sysmon"), ack.finding_id(b, "sysmon"))

    def test_revoke(self):
        fid, _ = ack.acknowledge(self.store, f(), "backdoor", "mine", now=NOW)
        self.assertIsNotNone(ack.revoke(self.store, fid))
        self.assertEqual(ack.load(self.store), {})

    def _snaps(self, finding):
        snaps = {job: {"ts": NOW - 1, "findings": [], "error": ""} for job in JOBS}
        snaps["backdoor"]["findings"] = [finding]
        return snaps

    def _area(self, result):
        return next(a for a in result["areas"] if a["name"] == "Persistence & access")

    def test_accepted_finding_is_charged_as_low_and_stays_visible(self):
        snaps = self._snaps(f())
        before = score.compute(snaps, JOBS, NOW)
        ack.acknowledge(self.store, f(), "backdoor", "Codex sandbox", now=NOW)
        acks = ack.load(self.store)
        after = score.compute(snaps, JOBS, NOW, acks)
        self.assertGreater(after["score"], before["score"])
        self.assertEqual(self._area(after)["score"], 100)
        self.assertEqual(self._area(after)["open"], {"low": 1})
        self.assertEqual(after["acknowledged"], 1)
        self.assertEqual(snaps["backdoor"]["findings"][0]["severity"], "high")
        self.assertFalse(any(s["job"] == "backdoor" for s in after["next_steps"]))
        self.assertEqual(triage.current(snaps, acks=acks, now=NOW), [])

    def test_acceptance_stops_lowering_on_worse_expiry_or_a_different_finding(self):
        ack.acknowledge(self.store, f("medium"), "backdoor", "expected", days=30, now=NOW)
        acks = ack.load(self.store)
        for label, finding, when in (
                ("worse", f("high"), NOW),
                ("expired", f("medium"), NOW + 30 * 86400),
                ("different", f("medium", detail="another account"), NOW)):
            with self.subTest(label):
                snaps = self._snaps(finding)
                self.assertEqual(score.compute(snaps, JOBS, when, acks)["score"],
                                 score.compute(snaps, JOBS, when)["score"])

    def test_confirm_cards_show_the_ack_command(self):
        from jarvis.response.reporting import email_ui
        t = triage.classify(f(), "backdoor")
        card = email_ui.finding_card(f(), "backdoor", t)
        self.assertIn(f"jarvis ack {t['id']}", card)

    def _digest_after_confirming(self, confirmations_apply):
        from unittest.mock import patch

        from jarvis.response import alert
        from jarvis.response.reporting import notifications
        conf = {"resend_api_key": "k", "alert_to": "a@b.c", "alert_from": "j@b.c",
                "alert_digest_interval": 60, "alert_min_severity": "medium"}
        finding = f("medium", "autostart registry entry", "persistence", "entry A", "HKCU Run")
        real = ack.is_acknowledged
        gate = real if confirmations_apply else (lambda *a, **k: False)
        with patch.object(alert, "send_email", return_value="") as send, \
             patch.object(ack, "is_acknowledged", side_effect=gate):
            with patch("time.time", return_value=NOW):
                notifications.dispatch(self.store, conf, "control", [finding])
                ack.acknowledge(self.store, finding, "control", "my audio driver", now=NOW)
            with patch("time.time", return_value=NOW + 4000):
                notifications.dispatch(self.store, conf, "control", [finding])
            with patch("time.time", return_value=NOW + 4200):   # digest interval has passed
                notifications.flush(self.store, conf)
            return send.call_count

    def test_a_confirmed_change_is_not_emailed(self):
        self.assertEqual(self._digest_after_confirming(confirmations_apply=True), 0)

    def test_the_same_change_is_emailed_without_the_confirmation(self):
        self.assertGreater(self._digest_after_confirming(confirmations_apply=False), 0)

if __name__ == "__main__":
    unittest.main()

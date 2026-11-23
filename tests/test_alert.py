import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.core.store import Store
from jarvis.response import alert
from jarvis.response.reporting import advisory, notifications

CONF = {
    "resend_api_key": "test-key",
    "alert_from": "jarvis@example.test",
    "alert_to": "owner@example.test",
}


class AdvisoryReportTests(unittest.TestCase):
    def test_gaps_do_not_page_or_falsely_clear_after_reclassification(self):
        import json
        finding = {"category": "coverage gap", "severity": "high",
                   "title": "T1003", "detail": "missing coverage", "where": ""}
        self.store.set_meta(alert.STATE_META, json.dumps({alert.finding_key(finding): {
            "job": "gaps", "first": 1, "last_sent": 1, "count": 2}}))
        with patch.object(alert, "send_email") as send:
            notifications.dispatch(self.store, CONF, "gaps", [finding], "")
            notifications.dispatch(self.store, CONF, "gaps", [finding], "")
        send.assert_not_called()
        self.assertEqual(json.loads(self.store.get_meta(alert.STATE_META)), {})

    def test_collector_outages_still_page(self):
        finding = {"category": "collectors", "severity": "high",
                   "title": "collector 'scan' is stale", "detail": "no results", "where": ""}
        # Once it has lasted: restart-length outages are not worth an email.
        with patch.object(alert, "send_email", return_value="") as send, \
                patch("time.time", return_value=1_000_000):
            notifications.dispatch(self.store, CONF, "coverage", [finding], "")
            send.assert_not_called()
        with patch.object(alert, "send_email", return_value="") as send, \
                patch("time.time", return_value=1_000_000 + notifications.OUTAGE_CONFIRM_S):
            notifications.dispatch(self.store, CONF, "coverage", [finding], "")
        send.assert_called_once()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tempdir.name, "jarvis.db"))

    def tearDown(self):
        self.store.close()
        self.tempdir.cleanup()

    def test_sender_always_uses_jarvis_display_name(self):
        self.assertEqual(
            alert.branded_sender({"alert_from": "jarvis@example.test"}),
            "JARVIS <jarvis@example.test>",
        )
        self.assertEqual(
            alert.branded_sender({"alert_from": "Old Name <alerts@example.test>"}),
            "JARVIS <alerts@example.test>",
        )

    def test_report_prioritizes_actions_and_keeps_process_details_local(self):
        self.store.save_snapshot("coverage", [{
            "category": "visibility", "severity": "medium", "host": "wsl",
            "title": "running unprivileged", "detail": "some views are hidden",
            "where": "sudo jarvis coverage",
        }])
        self.store.save_snapshot("posture", [{
            "category": "defense", "severity": "high", "host": "win",
            "title": "ASR rules are not enforcing", "detail": "audit only",
            "where": "Defender",
        }, {
            "category": "defense", "severity": "ok", "host": "win",
            "title": "Defender real-time protection is on", "detail": "",
            "where": "Defender",
        }])
        self.store.save_snapshot("scan", [{
            "category": "process", "severity": "high", "host": "wsl",
            "title": "private-process", "detail": "SECRET_ON_COMMAND_LINE",
            "where": "/tmp/private",
        }])

        sent = {}

        def capture(_conf, subject, body, html=None):
            sent.update(subject=subject, body=body, html=html)
            return ""

        jobs = {
            "scan": (60, "scan"),
            "coverage": (600, "coverage"),
            "posture": (7200, "posture"),
            "report": (18000, "report"),
        }
        with patch("jarvis.response.alert.load_conf", return_value=CONF), \
             patch("jarvis.response.alert.send_email", side_effect=capture):
            result = advisory.advisory_report(self.store, jobs)

        self.assertEqual(result[0]["severity"], "ok")
        self.assertTrue(sent["subject"].startswith("[JARVIS]"))
        # The subject carries what moved since the last report, so two
        # consecutive reports do not read identically in the inbox.
        self.assertIn("security report", sent["subject"])
        self.assertIn("first report", sent["subject"])
        self.assertIn("JARVIS SECURITY ADVISORY", sent["body"])
        self.assertIn("WHAT CHANGED", sent["body"])
        self.assertIn("SEE FOR YOURSELF", sent["body"])
        self.assertIn("JARVIS · DAILY SECURITY ADVISORY", sent["html"])
        self.assertIn("SECURE NEXT", sent["body"])
        self.assertIn("ASR rules are not enforcing", sent["body"])
        self.assertIn("Add-MpPreference", sent["body"])
        self.assertIn("running unprivileged", sent["body"])
        self.assertIn("Defender real-time protection is on", sent["body"])
        self.assertNotIn("SECRET_ON_COMMAND_LINE", sent["body"])
        self.assertNotIn("SECRET_ON_COMMAND_LINE", sent["html"])
        self.assertIn("Current findings by protection layer", sent["html"])
        self.assertIn("Optional deeper AI assessment", sent["html"])
        self.assertTrue(self.store.get_meta(alert.REPORT_OK_META))

    def test_report_surfaces_missing_delivery_configuration(self):
        with patch("jarvis.response.alert.load_conf", return_value={}):
            result = advisory.advisory_report(
                self.store, {"report": (18000, "report")})
        self.assertEqual(result[0]["severity"], "medium")
        self.assertIn("not configured", result[0]["title"])


if __name__ == "__main__":
    unittest.main()

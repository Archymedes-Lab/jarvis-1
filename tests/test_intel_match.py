import os
import tempfile
import unittest

from jarvis.collectors.telemetry import sysmon
from jarvis.core.store import Store
from jarvis.core.util import now


class PersistentIndicatorRevetTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tempdir.name, "jarvis.db"))

    def tearDown(self):
        self.store.close()
        self.tempdir.cleanup()

    def test_sysmon_ignores_newly_denied_domain_already_in_database(self):
        stamp = now()
        self.store.db.execute(
            "INSERT INTO indicators(kind,value,norm,confidence,topic,context,"
            "source_url,first_seen,last_seen,status,source) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("domain", "chatgpt.com", "chatgpt.com", "medium", "test",
             "old extraction", "https://example.test", stamp, stamp,
             "active", "exa"),
        )

        findings = sysmon._correlate(
            self.store, {"ab.chatgpt.com": {"browser.exe"}}, {})

        self.assertEqual(findings, [])

    def test_extracted_domain_lead_does_not_claim_critical_certainty(self):
        stamp = now()
        self.store.db.execute(
            "INSERT INTO indicators(kind,value,norm,confidence,topic,context,"
            "source_url,first_seen,last_seen,status,source) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("domain", "tenant.cloudapp.azure.com",
             "tenant.cloudapp.azure.com", "medium", "test", "old extraction",
             "https://example.test", stamp, stamp, "active", "exa"),
        )

        findings = sysmon._correlate(
            self.store, {"tenant.cloudapp.azure.com": {"browser.exe"}}, {})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("threat-intelligence domain", findings[0]["title"])


if __name__ == "__main__":
    unittest.main()

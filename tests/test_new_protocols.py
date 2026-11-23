"""The new protocols must resolve the findings this machine actually has.

Each resolve pattern is matched against the exact titles the collectors emit;
a typo'd pattern would silently make a protocol verify nothing. Ordering
matters too: pick_next raises the first ready item, so the highest-value
protocol must come first.
"""

import os
import tempfile
import unittest

from jarvis.core.store import Store
from jarvis.response import protocols
from jarvis.service.schedule import JOBS

# Exact titles from the live snapshots these protocols must resolve.
SECRETS = [("secrets", "OpenAI API key in plaintext"),
           ("secrets", "Anthropic API key in plaintext"),
           ("secrets", "GitHub token in plaintext (+1 more location)"),
           ("secrets", "JSON web token in plaintext (+1 more location)"),
           ("secrets", "private key block (unknown) stored locally"),
           ("secrets", "private key block (unencrypted) stored locally"),
           ("secrets", "generic secret assignment in plaintext"),
           ("secrets", "generic secret assignment in plaintext (+2 more locations)")]
BOOT = [("boot", "task ran at boot")]
BACKDOOR = [("backdoor", "account hidden from the sign-in screen: CodexSandboxOffline"),
            ("backdoor", "account hidden from the sign-in screen: CodexSandboxOnline")]
SYSMON = [("sysmon", "Sysmon dropped events before logging them")]
INTERNET = [("internet", "application listening beyond loopback")]
FIREWALL = [("firewall", "permissive inbound rule")]
CONTROL = [("control", "autostart registry entry"),
           ("control", "custom systemd service")]


def finding(job, title):
    return {"category": "protocol-test", "severity": "high", "host": "win",
            "title": title, "detail": "", "where": job}


class NewProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def observe(self, pairs):
        by_job = {}
        for job, title in pairs:
            by_job.setdefault(job, []).append(finding(job, title))
        for job, fs in by_job.items():
            self.store.save_snapshot(job, fs, 0.1, "")
        # Snapshots are stamped with wall-clock time; the score's freshness
        # window is interval-based, so fresh test snapshots are fine as-is.

    def _seed_all(self):
        """Every scored job fresh and clean, so projections run on a real base."""
        for job, (interval, _label) in JOBS.items():
            self.store.save_snapshot(job, [], 0.1, "")

    def items(self):
        return {i["protocol"].id: i for i in protocols.evaluate(self.store, JOBS)}

    def test_every_collector_title_is_resolved_by_some_protocol(self):
        for pairs in (SECRETS, BOOT, BACKDOOR, SYSMON, INTERNET, FIREWALL, CONTROL):
            for job, title in pairs:
                covered = any(p.fixes(job, {"title": title}) for p in protocols.PROTOCOLS)
                self.assertTrue(covered, f"no protocol resolves {job}: {title}")

    def test_plaintext_secrets_covers_every_secret_title(self):
        self.observe(SECRETS)
        item = self.items()["plaintext-secrets"]
        self.assertEqual(item["open"], len(SECRETS))

    def test_boot_tasks_counts_every_boot_finding(self):
        self.observe(BOOT)
        self.assertEqual(self.items()["boot-tasks"]["open"], 1)

    def test_hidden_accounts_protocol(self):
        self.observe(BACKDOOR)
        item = self.items()["hidden-accounts"]
        self.assertEqual(item["state"], protocols.READY)
        self.assertEqual(item["open"], 2)

    def test_projection_uses_the_real_scoring_code(self):
        self._seed_all()
        self.observe(SECRETS + BOOT)
        items = self.items()
        self.assertGreater(items["plaintext-secrets"]["score_after"],
                           items["plaintext-secrets"]["score_now"])
        # Doing every protocol must beat doing one.
        _, all_done = protocols.projected_all(self.store, JOBS)
        self.assertGreater(all_done, items["plaintext-secrets"]["score_after"])

    def test_high_value_protocols_come_before_the_old_three(self):
        # pick_next returns the first READY item in PROTOCOLS order; the new
        # protocols were placed first because they carry the larger gains.
        self.observe(SECRETS + BOOT + BACKDOOR)
        item = protocols.pick_next(list(self.items().values()))
        self.assertIsNotNone(item)
        self.assertIn(item["protocol"].id,
                      ("plaintext-secrets", "boot-tasks", "hidden-accounts"))


if __name__ == "__main__":
    unittest.main()

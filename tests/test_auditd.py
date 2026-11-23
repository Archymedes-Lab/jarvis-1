import unittest
from unittest.mock import patch

from jarvis.collectors.telemetry import auditd


class AuditdWsl2Tests(unittest.TestCase):
    def _audit(self, **kw):
        defaults = dict(
            state=(True, False, 0, "fallback"),   # installed, not running
            is_wsl=True,
            rejected=True,
            enabled_rc=1,                          # disabled
        )
        defaults.update(kw)
        with patch.object(auditd, "state", return_value=defaults["state"]), \
             patch.object(auditd, "_is_wsl", return_value=defaults["is_wsl"]), \
             patch.object(auditd, "_auditd_start_rejected_by_kernel",
                          return_value=defaults["rejected"]), \
             patch.object(auditd, "_sysmon_linux_running",
                          return_value=" Sysmon for Linux (eBPF) is running and covers this."), \
             patch.object(auditd, "_run",
                          return_value=("", defaults["enabled_rc"])), \
             patch.object(auditd, "_service_failed", return_value=False):
            return auditd.audit(hosts=("wsl",))

    def test_wsl2_not_running_is_medium_not_high_and_gives_no_enable_advice(self):
        out = self._audit()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("WSL2 kernel", out[0]["title"])
        self.assertNotIn("enable --now", out[0]["detail"])
        self.assertIn("Sysmon for Linux", out[0]["detail"])

    def test_stays_medium_after_reset_failed_clears_the_failed_state(self):
        # is-failed=inactive, is-enabled=disabled, but the journal still proves it
        out = self._audit(rejected=True, enabled_rc=1)
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("cannot run on this WSL2 kernel", out[0]["title"])
        # nothing to disable anymore, so no disable command
        self.assertNotIn("disable --now", out[0]["detail"])

    def test_wsl2_without_journal_evidence_still_medium(self):
        out = self._audit(rejected=False)
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("usually block", out[0]["title"])

    def test_still_enabled_and_failing_gets_the_cleanup_command(self):
        out = self._audit(rejected=True, enabled_rc=0)  # is-enabled -> enabled
        self.assertIn("disable --now auditd", out[0]["detail"])

    def test_non_wsl_not_running_stays_high(self):
        out = self._audit(is_wsl=False)
        self.assertEqual(out[0]["severity"], "high")
        self.assertIn("not running", out[0]["title"])


if __name__ == "__main__":
    unittest.main()

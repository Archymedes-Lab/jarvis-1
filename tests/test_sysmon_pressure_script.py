import re
import unittest

from jarvis.core.paths import win_script

SCRIPT = win_script("sysmon_pressure.ps1").read_text(encoding="utf-8")
BROKER_TIMEOUT_S = 120


class SysmonPressureScriptTests(unittest.TestCase):
    """The elevated broker kills this probe at 120s. Get-WinEvent rendered
    every message and measured 230s for 14.6k events, so the probe never
    finished; the EventLogReader path measured 2.3s for the same query."""

    def test_reads_records_without_message_rendering(self):
        self.assertIn("EventLogReader", SCRIPT)
        code = "\n".join(line for line in SCRIPT.splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertNotIn("Get-WinEvent", code)
        self.assertNotIn("ToXml", code)
        self.assertNotIn("$event.Message", code)

    def test_has_a_time_budget_inside_the_broker_timeout(self):
        budget = int(re.search(r"\$BudgetSeconds\s*=\s*(\d+)", SCRIPT).group(1))
        self.assertLess(budget, BROKER_TIMEOUT_S)
        self.assertIn("$result.truncated = $true", SCRIPT)

    def test_output_stays_aggregate_only(self):
        # Rule and image names only: no registry targets, values or users.
        for field in ("TargetObject", "Details", "Properties[6]", "Properties[7]"):
            self.assertNotIn(field, SCRIPT)
        for key in ("retained_registry_events", "by_rule", "by_image", "drops",
                    "truncated", "boot"):
            self.assertIn(key, SCRIPT)

    def test_reader_is_disposed(self):
        self.assertIn("$reader.Dispose()", SCRIPT)
        self.assertIn("$event.Dispose()", SCRIPT)


if __name__ == "__main__":
    unittest.main()

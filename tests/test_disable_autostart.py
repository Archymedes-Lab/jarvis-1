import unittest
from unittest import mock

from jarvis.response.actions.disable_autostart import DisableAutostart


class DisableAutostartTests(unittest.TestCase):
    def setUp(self):
        self.action = DisableAutostart()

    def test_only_structured_control_targets_match(self):
        finding = {"host": "win", "severity": "critical", "category": "persistence",
                   "response_target": {"kind": "task", "name": "Bad", "path": "\\"}}
        self.assertEqual(self.action.match(finding, "control"), finding["response_target"])
        self.assertIsNone(self.action.match(finding, "boot"))
        self.assertIsNone(self.action.match({**finding, "response_target": None}, "control"))

    def test_only_critical_target_is_auto_eligible(self):
        self.assertTrue(self.action.auto_eligible({"severity": "critical"}, "control", {}))
        self.assertFalse(self.action.auto_eligible({"severity": "high"}, "control", {}))

    def test_apply_keeps_powershell_output_as_undo_record(self):
        record = {"kind": "task", "name": "Bad", "path": "\\", "wasEnabled": True}
        with mock.patch.object(self.action, "_run",
                               return_value={"ok": True, "record": record,
                                             "detail": "scheduled task disabled"}):
            ok, saved, detail = self.action.apply(
                {"kind": "task", "name": "Bad", "path": "\\"}, None)
        self.assertTrue(ok, detail)
        self.assertEqual(saved, record)

    def test_undo_rejects_missing_record_without_powershell(self):
        with mock.patch.object(self.action, "_run") as run:
            ok, _ = self.action.undo({}, {})
        self.assertFalse(ok)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

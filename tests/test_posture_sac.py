"""Smart App Control state in the posture attack-surface section."""

import unittest

from jarvis.collectors.host.posture.sections import _attack_surface


def titles(d):
    return {f["title"]: f for f in _attack_surface(d)}


class SmartAppControlTests(unittest.TestCase):
    def base(self, **over):
        d = {"smb1": "Disabled", "rdp": {"denied": "1"}, "winrm": "Stopped",
             "smartscreen_shell": "1"}
        d.update(over)
        return d

    def test_off_is_medium_with_the_settings_path(self):
        # The owner's machine on 2026-10-21 read 0.
        f = titles(self.base(sac=0))["Smart App Control is off"]
        self.assertEqual(f["severity"], "medium")
        self.assertIn("Smart App Control", f["where"])

    def test_on_reports_nothing(self):
        self.assertNotIn("Smart App Control is off", titles(self.base(sac=1)))
        self.assertFalse(any("Smart App Control" in t for t in titles(self.base(sac=1))))

    def test_evaluation_is_low_and_says_it_blocks_nothing_yet(self):
        f = titles(self.base(sac=2))["Smart App Control is in evaluation mode"]
        self.assertEqual(f["severity"], "low")
        self.assertIn("blocks nothing yet", f["detail"])

    def test_unreadable_is_visibility_not_off(self):
        f = titles(self.base(sac=None))["Smart App Control state is not readable"]
        self.assertEqual(f["category"], "visibility")
        self.assertIn("not off", f["detail"])


if __name__ == "__main__":
    unittest.main()

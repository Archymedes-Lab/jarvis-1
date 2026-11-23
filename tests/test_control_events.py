import os
import tempfile
import unittest

from jarvis.collectors.host.inputwatch import analysis
from jarvis.core.store import Store
from jarvis.core.util import now


class ControlActivationTests(unittest.TestCase):
    """A control that moves with no key behind it is the impersonation tell."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Store(os.path.join(self._tmp.name, "jarvis.db"))
        self.addCleanup(self.store.close)

    def _event(self, kind, control="volume", detail="", injected=0,
               lower_il=0, keyed=-1, gap=-1, fg="", age=60):
        self.store.db.execute(
            "INSERT INTO control_events(ts,kind,control,detail,injected,"
            "lower_il,keyed,key_gap_ms,fg) VALUES(?,?,?,?,?,?,?,?,?)",
            (now() - age, kind, control, detail, injected, lower_il, keyed,
             gap, fg))
        self.store.commit()

    def _titles(self, findings):
        return {f["title"]: f["severity"] for f in findings}

    def test_a_volume_change_with_no_key_is_reported(self):
        self._event("control-state", detail="42 -> 55", keyed=0, gap=999999,
                    fg="chrome:900")

        out = self._titles(analysis._control_findings(self.store))

        self.assertEqual(
            out["the volume changed with no key press behind it"], "medium")

    def test_a_volume_change_that_followed_a_key_is_not_reported(self):
        self._event("control-key", control="volume-up")
        self._event("control-state", detail="42 -> 45", keyed=1, gap=120)

        out = self._titles(analysis._control_findings(self.store))

        self.assertNotIn("the volume changed with no key press behind it", out)

    def test_an_injected_control_key_outranks_an_unkeyed_change(self):
        self._event("control-key", control="volume-down", injected=1)

        out = self._titles(analysis._control_findings(self.store))

        self.assertEqual(out["a control key was injected by software"], "high")

    def test_media_only_without_lower_integrity_is_medium(self):
        self._event("control-key", control="media-play-pause", injected=1)
        out = self._titles(analysis._control_findings(self.store))
        self.assertEqual(out["media play/pause was injected by software"], "medium")

    def test_other_or_lower_integrity_controls_keep_high(self):
        self._event("control-key", control="media-play-pause", injected=1)
        self._event("control-key", control="launch-app1", injected=1)
        out = self._titles(analysis._control_findings(self.store))
        self.assertEqual(out["a control key was injected by software"], "high")
        self.store.db.execute("DELETE FROM control_events")
        self._event("control-key", control="media-play-pause", injected=1, lower_il=1)
        out = self._titles(analysis._control_findings(self.store))
        self.assertEqual(out["a control key was injected by software"], "high")

    def test_a_lower_integrity_injection_is_named_as_such(self):
        self._event("control-key", control="volume-mute", injected=1,
                    lower_il=1)

        hit = [f for f in analysis._control_findings(self.store)
               if "injected by software" in f["title"]][0]

        self.assertIn("lower-integrity", hit["detail"])

    def test_real_key_presses_are_logged_without_being_flagged(self):
        self._event("control-key", control="volume-up", injected=0)

        out = self._titles(analysis._control_findings(self.store))

        self.assertNotIn("a control key was injected by software", out)
        self.assertEqual(out["control activations are being logged"], "ok")

    def test_silence_is_stated_rather_than_left_blank(self):
        out = self._titles(analysis._control_findings(self.store))

        self.assertEqual(out["no control activations recorded"], "ok")

    def test_events_outside_the_window_are_not_counted(self):
        self._event("control-state", keyed=0, age=48 * 3600)

        out = self._titles(analysis._control_findings(self.store, hours=24))

        self.assertIn("no control activations recorded", out)


class PunctuationTimestampTests(unittest.TestCase):
    """A phantom key is only diagnosable if you know exactly when it happened."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Store(os.path.join(self._tmp.name, "jarvis.db"))
        self.addCleanup(self.store.close)

    def _key(self, kind="punct-key", cls="period-greater", fg="notepad:1",
             age=30):
        self.store.db.execute(
            "INSERT INTO input_events(ts,kind,lower_il,class,fg) "
            "VALUES(?,?,0,?,?)", (now() - age, kind, cls, fg))
        self.store.commit()

    def test_an_injected_punctuation_key_is_critical(self):
        self._key(kind="key")

        out = analysis._punct_findings(self.store)

        self.assertEqual(out[0]["severity"], "critical")
        self.assertIn("synthesised", out[0]["detail"])

    def test_a_real_punctuation_press_is_recorded_without_alarm(self):
        self._key()

        out = analysis._punct_findings(self.store)

        self.assertEqual(out[0]["severity"], "ok")
        self.assertIn("none injected", out[0]["detail"])

    def test_the_finding_names_the_window_it_happened_in(self):
        self._key(fg="chrome:4242")

        self.assertIn("chrome:4242", analysis._punct_findings(self.store)[0]["detail"])

    def test_no_punctuation_activity_produces_no_finding(self):
        self.assertEqual(analysis._punct_findings(self.store), [])


class DigitTimestampTests(unittest.TestCase):
    """Digit presses are timestamped so a phantom '3' can be located."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = Store(os.path.join(self._tmp.name, "jarvis.db"))
        self.addCleanup(self.store.close)

    def _key(self, kind="digit-key", cls="digit-3", fg="notepad:1", age=30):
        self.store.db.execute(
            "INSERT INTO input_events(ts,kind,lower_il,class,fg) "
            "VALUES(?,?,0,?,?)", (now() - age, kind, cls, fg))
        self.store.commit()

    def test_an_injected_digit_key_is_critical(self):
        self._key(kind="key")

        out = analysis._digit_findings(self.store)

        self.assertEqual(out[0]["severity"], "critical")
        self.assertIn("digit-3", out[0]["detail"])
        self.assertIn("synthesised", out[0]["detail"])

    def test_a_real_digit_press_is_recorded_without_alarm(self):
        self._key()

        out = analysis._digit_findings(self.store)

        self.assertEqual(out[0]["severity"], "ok")
        self.assertIn("none injected", out[0]["detail"])
        self.assertIn("digit-3", out[0]["detail"])

    def test_the_finding_names_the_window_it_happened_in(self):
        self._key(fg="WindowsTerminal:9924")

        self.assertIn("WindowsTerminal:9924",
                      analysis._digit_findings(self.store)[0]["detail"])

    def test_no_digit_activity_produces_no_finding(self):
        self.assertEqual(analysis._digit_findings(self.store), [])


if __name__ == "__main__":
    unittest.main()

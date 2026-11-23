"""Scoring of guest evidence against the positive controls."""

import unittest

from jarvis.lab import spyware_controls as sc

CONTROL = {c.id: c for c in sc.ALL}


def evidence(kinds=(), *, path_class="user_writable", sig="none", latency=1.0, cleaned=True, **extra):
    return {"status": "ran", "latency_s": latency, "cleaned": cleaned,
            "subject": {"key": "k", "host": "wsl", "label": "agent", "signature": sig,
                        "path_class": path_class,
                        "observations": [{"kind": k, "source": "guest"} for k in kinds]}, **extra}


class EvaluateTests(unittest.TestCase):
    def test_expected_facts_and_verdict_are_detected(self):
        r = sc.evaluate(CONTROL["L01-deleted-image"], evidence(["conceal.deleted_image"]))
        self.assertEqual((r["outcome"], r["verdict"]), ("detected", "VISIBILITY_CONTRADICTION"))

    def test_missing_fact_is_a_miss_even_if_the_verdict_matches_by_luck(self):
        r = sc.evaluate(CONTROL["L04-keyboard-reader-deleted"], evidence(["conceal.deleted_image"]))
        self.assertEqual(r["outcome"], "missed")
        self.assertEqual(r["missing_kinds"], ["cap.keyboard.evdev"])

    def test_wrong_verdict_is_a_miss(self):
        r = sc.evaluate(CONTROL["L03-keyboard-device-reader"], evidence([]))
        self.assertEqual(r["outcome"], "missed")

    def test_clean_control_must_stay_quiet(self):
        self.assertEqual(sc.evaluate(CONTROL["L07-clean-process"], evidence([], path_class="os"))["outcome"], "clean_ok")
        r = sc.evaluate(CONTROL["L07-clean-process"], evidence(["conceal.deleted_image"]))
        self.assertEqual(r["outcome"], "false_positive")

    def test_blind_spot_control_passes_only_when_it_is_still_blind(self):
        self.assertEqual(sc.evaluate(CONTROL["W04-key-state-polling"], evidence([]))["outcome"], "blind_confirmed")
        r = sc.evaluate(CONTROL["W04-key-state-polling"], evidence(["cap.keyboard.hook"]))
        self.assertEqual(r["outcome"], "blind_spot_closed")      # a sensor improved; the register is stale

    def test_windows_hook_chain_expects_persistence_too(self):
        r = sc.evaluate(CONTROL["W01-hook-autostart-unsigned"],
                        evidence(["cap.keyboard.hook", "persist.autostart", "conceal.no_ui"]))
        self.assertEqual(r["outcome"], "detected")

    def test_depth_three_needs_a_human(self):
        r = sc.evaluate(CONTROL["L04-keyboard-reader-deleted"],
                        evidence(["cap.keyboard.evdev", "conceal.deleted_image"]))
        self.assertEqual((r["outcome"], r["depth"], r["needs_human"]), ("detected", 3, True))

    def test_slow_detection_and_uncleaned_emulator_are_problems(self):
        r = sc.evaluate(CONTROL["L01-deleted-image"], evidence(["conceal.deleted_image"], latency=99.0))
        self.assertTrue(r["too_slow"])
        s = sc.summarize([r, sc.evaluate(CONTROL["L01-deleted-image"],
                                         evidence(["conceal.deleted_image"], cleaned=False))])
        self.assertFalse(s["passed"])
        self.assertEqual(len(s["problems"]), 2)

    def test_skipped_and_error_are_never_passes(self):
        skipped = sc.evaluate(CONTROL["L05-microphone-capture-device"],
                              {"status": "skipped", "reason": "guest offers no sound device"})
        err = sc.evaluate(CONTROL["L01-deleted-image"], {"status": "error", "reason": "x"})
        none = sc.evaluate(CONTROL["L01-deleted-image"], {"status": "ran", "subject": None})
        self.assertEqual((skipped["outcome"], err["outcome"], none["outcome"]), ("skipped", "error", "error"))
        s = sc.summarize([skipped])
        self.assertEqual(s["counts"], {"skipped": 1})
        self.assertIn("gaps", s["reading"])
        self.assertFalse(sc.summarize([err])["passed"])


class UntrustedEvidenceTests(unittest.TestCase):
    def test_unknown_kinds_bad_types_and_oversize_are_dropped(self):
        raw = {"key": "k" * 500, "signature": "trusted!", "path_class": "x" * 99, "age_days": "3",
               "observations": [{"kind": "cap.made.up"}, "junk", {"kind": "conceal.deleted_image"}] +
                               [{"kind": "cap.keyboard.evdev"}] * 500}
        s = sc.subject_from_evidence(raw)
        self.assertEqual(len(s.key), sc.MAX_TEXT)
        self.assertEqual((s.signature, s.age_days), ("unknown", None))
        self.assertLessEqual(len(s.observations), sc.MAX_OBS)
        self.assertNotIn("cap.made.up", [o.kind for o in s.observations])
        self.assertIsNone(sc.subject_from_evidence("string"))

    def test_incomplete_guest_observations_are_not_evidence(self):
        raw = {"observations": [{"kind": "conceal.deleted_image", "complete": False}]}
        r = sc.evaluate(CONTROL["L01-deleted-image"], {"status": "ran", "subject": raw})
        self.assertEqual(r["outcome"], "missed")


class DefinitionTests(unittest.TestCase):
    def test_every_control_states_its_safety_telemetry_and_recovery(self):
        ids = [c.id for c in sc.ALL]
        self.assertEqual(len(ids), len(set(ids)))
        for c in sc.ALL:
            self.assertEqual(c.safety, "isolated_emulation")
            self.assertTrue(c.telemetry and c.recovery and c.human_protection, c.id)
            self.assertGreater(c.max_latency_s, 0)
            if c.known_blind:
                self.assertEqual(c.expect_verdict, "NO_SIGNAL")

    def test_every_linux_emulator_exists_in_the_guest_asset(self):
        from jarvis.lab.guest import emu_linux
        for c in sc.by_platform("linux"):
            self.assertIn(c.emulator, emu_linux.MODES, c.id)

    def test_guest_emulators_never_read_device_data_or_use_the_network(self):
        from pathlib import Path
        text = (Path(sc.__file__).parent / "guest" / "emu_linux.py").read_text()
        for banned in ("socket", "urllib", "requests", ".read(4", "os.read(", "http", "connect("):
            self.assertNotIn(banned, text.replace("open(\"/usr/bin/sleep\", \"rb\") as src", ""), banned)


if __name__ == "__main__":
    unittest.main()

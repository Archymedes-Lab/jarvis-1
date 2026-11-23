"""Invariants of the spyware / covert-process reasoning engine."""

import itertools
import json
import unittest

from jarvis.core.reasoning import corpus, engine, knowledge, vocab
from jarvis.core.reasoning.vocab import Observation as O
from jarvis.core.reasoning.vocab import Subject

RANK = {"NO_SIGNAL": 0, "EXPECTED_DECLARED": 1, "EXPECTED_DUAL_USE": 2,
        "UNEXPLAINED_CAPABILITY": 3, "SUSPECT_CHAIN": 4, "VISIBILITY_CONTRADICTION": 5}


def subj(facts, **kw):
    base = dict(key="k", host="win", signature="none", path_class="user_writable", age_days=5)
    base.update(kw)
    return Subject(observations=[O(f, "t") for f in facts], **base)


class CorpusTests(unittest.TestCase):
    def test_every_positive_control_is_flagged_and_no_lookalike_is(self):
        r = corpus.selftest()
        self.assertEqual(r["missed"], [])
        self.assertEqual(r["false_positives"], [])
        self.assertEqual(r["expectation_drift"], [])

    def test_only_full_chain_is_flagged_for_a_single_capability(self):
        self.assertEqual(engine.assess(subj(["cap.keyboard.hook"]))["verdict"],
                         "UNEXPLAINED_CAPABILITY")
        self.assertEqual(engine.assess(subj(["cap.keyboard.hook", "egress.external"]))["verdict"],
                         "UNEXPLAINED_CAPABILITY")


class HonestyTests(unittest.TestCase):
    def test_stale_or_incomplete_observations_are_unknown_not_evidence(self):
        s = Subject(key="k", observations=[
            O("cap.keyboard.hook", "etw", fresh=False), O("egress.external", "net", complete=False),
            O("conceal.contradiction", "views", fresh=False)])
        r = engine.assess(s)
        self.assertEqual(r["verdict"], "NO_SIGNAL")
        self.assertEqual(r["degraded_sources"], ["etw", "net", "views"])

    def test_no_signal_still_lists_what_cannot_be_seen(self):
        r = engine.assess(subj([]))
        self.assertIn("keyboard polling", r["blind_mechanisms"])
        self.assertIn("screen capture (BitBlt/DXGI duplication)", r["blind_mechanisms"])

    def test_unknown_kinds_are_ignored_not_trusted(self):
        self.assertEqual(engine.assess(subj(["cap.made.up", "conceal.contradiction "]))["verdict"],
                         "NO_SIGNAL")

    def test_identity_weakness_alone_never_raises_a_verdict(self):
        for sig, path, age in itertools.product(("none", "invalid"), ("temp", "user_writable"), (0, 1)):
            r = engine.assess(subj([], signature=sig, path_class=path, age_days=age))
            self.assertEqual(r["verdict"], "NO_SIGNAL")
            self.assertEqual(r["reasons"], [])

    def test_no_verdict_claims_malice_or_authorizes_action(self):
        for _, s, _ in corpus.POSITIVES + corpus.LOOKALIKES:
            r = engine.assess(s)
            text = json.dumps(r).lower()
            self.assertNotIn("malicious", text.replace("not intent", ""))
            self.assertLessEqual(r["response_level"], 2)


class ExplanationTests(unittest.TestCase):
    def _obs(self, **kw):
        return subj(["cap.screen.capture", "cap.audio.mic"], **kw)

    def test_explanation_needs_valid_signature_exact_publisher_and_path(self):
        ok = dict(signature="valid", publisher="Zoom Video Communications, Inc.",
                  path_class="program_files")
        self.assertEqual(engine.assess(self._obs(**ok))["verdict"], "EXPECTED_DECLARED")
        for change in ({"signature": "invalid"}, {"signature": "unknown"},
                       {"publisher": "Zoom Video Communications Inc Fake"},
                       {"publisher": "Zoom"}, {"path_class": "temp"}):
            r = engine.assess(self._obs(**{**ok, **change}))
            self.assertEqual(r["verdict"], "UNEXPLAINED_CAPABILITY", change)

    def test_explained_product_is_not_a_chain_but_concealment_still_counts(self):
        ok = dict(signature="valid", publisher="OBS Project", path_class="program_files")
        base = ["cap.screen.capture", "persist.autostart", "egress.beacon", "stage.local_buffer"]
        self.assertEqual(engine.assess(subj(base, **ok))["verdict"], "EXPECTED_DECLARED")
        self.assertEqual(engine.assess(subj(base + ["conceal.deleted_image"], **ok))["verdict"],
                         "VISIBILITY_CONTRADICTION")

    def test_capability_outside_the_category_is_unexplained(self):
        ok = dict(signature="valid", publisher="OBS Project", path_class="program_files")
        r = engine.assess(subj(["cap.screen.capture", "cap.credential.store"], **ok))
        self.assertEqual(r["unexplained"], ["cap.credential.store"])
        self.assertEqual(r["verdict"], "UNEXPLAINED_CAPABILITY")

    def test_dual_use_asks_the_owner(self):
        r = engine.assess(subj(["cap.screen.capture", "cap.input.injection"], signature="valid",
                               publisher="TeamViewer", path_class="program_files"))
        self.assertEqual(r["verdict"], "EXPECTED_DUAL_USE")
        self.assertTrue(any("confirm you installed" in x for x in r["reasons"]))


class LinuxOsComponentTests(unittest.TestCase):
    """Found live 2026-09-30: the isolated lab's clean-guest baseline flagged the real
    systemd-logind daemon for reading a keyboard event device — exactly its documented
    job (HandlePowerKey/HandleLidSwitch). Linux has no Authenticode equivalent, so
    identity rests on the kernel-verified exe path, never a self-reported name alone."""

    def test_named_daemon_from_the_os_path_explains_only_its_specific_capability(self):
        r = engine.assess(subj(["cap.keyboard.evdev"], host="wsl", label="systemd-logind",
                               path_class="os", signature="unknown"))
        self.assertEqual(r["verdict"], "EXPECTED_DECLARED")
        self.assertTrue(any("linux_os_component" in x for x in r["reasons"]))
        self.assertFalse(any("valid signature" in x for x in r["reasons"]))

    def test_same_name_outside_the_os_path_is_not_explained(self):
        r = engine.assess(subj(["cap.keyboard.evdev"], host="wsl", label="systemd-logind",
                               path_class="user_writable", signature="unknown"))
        self.assertEqual(r["verdict"], "UNEXPLAINED_CAPABILITY")

    def test_capability_outside_the_daemons_specific_list_is_unexplained(self):
        r = engine.assess(subj(["cap.keyboard.evdev", "cap.credential.store"], host="wsl",
                               label="systemd-logind", path_class="os", signature="unknown"))
        self.assertEqual(r["unexplained"], ["cap.credential.store"])
        self.assertEqual(r["verdict"], "UNEXPLAINED_CAPABILITY")

    def test_an_unlisted_os_path_daemon_is_not_explained(self):
        r = engine.assess(subj(["cap.keyboard.evdev"], host="wsl", label="some-other-daemon",
                               path_class="os", signature="unknown"))
        self.assertEqual(r["verdict"], "UNEXPLAINED_CAPABILITY")

    def test_every_linux_os_component_name_is_a_recognized_system_name(self):
        for name in knowledge.LINUX_OS_COMPONENTS:
            self.assertIn(name, vocab.LINUX_SYSTEM_NAMES, name)


class ScriptHostAndOwnTests(unittest.TestCase):
    def test_signed_script_host_is_never_explained_by_its_signature(self):
        r = engine.assess(subj(["cap.keyboard.hook"], signature="valid", publisher="Microsoft Windows",
                               path_class="os", runs_script=True))
        self.assertEqual(r["verdict"], "UNEXPLAINED_CAPABILITY")
        self.assertTrue(any("script host" in x for x in r["reasons"]))
        plain = engine.assess(subj(["cap.keyboard.hook"], signature="valid",
                                   publisher="Microsoft Windows", path_class="os"))
        self.assertEqual(plain["verdict"], "EXPECTED_DECLARED")

    def test_only_the_declared_jarvis_component_is_explained_and_only_for_its_own_kinds(self):
        own = dict(runs_script=True, declared=vocab.JARVIS_COMPONENT)
        self.assertEqual(engine.assess(subj(["cap.keyboard.hook"], **own))["verdict"],
                         "EXPECTED_DECLARED")
        r = engine.assess(subj(["cap.keyboard.hook", "cap.audio.mic"], **own))
        self.assertEqual(r["unexplained"], ["cap.audio.mic"])
        # Concealment still counts against a declared component.
        r = engine.assess(subj(["cap.keyboard.hook", "conceal.deleted_image"], **own))
        self.assertEqual(r["verdict"], "VISIBILITY_CONTRADICTION")


class MonotonicityTests(unittest.TestCase):
    def test_adding_unexplained_evidence_never_lowers_the_verdict(self):
        kinds = list(vocab.KINDS)
        base = ["cap.keyboard.hook"]
        for extra in kinds:
            before = RANK[engine.assess(subj(base))["verdict"]]
            after = RANK[engine.assess(subj(base + [extra]))["verdict"]]
            self.assertGreaterEqual(after, before, extra)

    def test_concealment_alone_is_enough_and_needs_no_capture(self):
        for k in vocab.STRONG_CONCEAL:
            self.assertEqual(engine.assess(subj([k]))["verdict"], "VISIBILITY_CONTRADICTION")
        self.assertEqual(engine.assess(subj(["conceal.no_ui"]))["verdict"], "NO_SIGNAL")


class DepthAndBoundsTests(unittest.TestCase):
    def test_forensic_depth_is_proposed_only_and_needs_a_human(self):
        r = engine.assess(subj(["cap.keyboard.evdev", "conceal.deleted_image"]))
        self.assertEqual((r["observation_depth"], r["depth_needs_human"]), (3, True))
        chain = engine.assess(subj(["cap.keyboard.hook", "egress.external", "persist.autostart"]))
        self.assertEqual((chain["observation_depth"], chain["depth_needs_human"]), (2, False))

    def test_input_is_bounded(self):
        s = subj(["cap.keyboard.hook"] * 10000 + ["conceal.contradiction"])
        # The contradiction sits beyond the bound and must not be read.
        self.assertEqual(engine.assess(s)["verdict"], "UNEXPLAINED_CAPABILITY")
        many = [subj([], key=str(i)) for i in range(5000)]
        self.assertLessEqual(len(engine.assess_all(many, limit=50)), 50)

    def test_assess_all_orders_worst_first(self):
        rows = engine.assess_all([subj([], key="a"), subj(["conceal.contradiction"], key="b"),
                                  subj(["cap.keyboard.hook"], key="c")])
        self.assertEqual([r["key"] for r in rows], ["b", "c", "a"])


class AdvisoryFeatureTests(unittest.TestCase):
    ALLOWED = {"capture_kinds", "explained_kinds", "stages_present", "concealment", "signature",
               "path_class", "declared_category", "image_age_band", "has_visible_window",
               "blind_mechanism_count"}

    def test_features_are_fixed_vocabulary_without_names_paths_or_publishers(self):
        s = subj(["cap.keyboard.hook", "egress.external"], key="SECRET-KEY", label="C:\\Users\\me\\x.exe",
                 publisher="Some Vendor", signature="valid")
        f = engine.jev_features(engine.assess(s), s)
        self.assertEqual(set(f), self.ALLOWED)
        blob = json.dumps(f)
        for secret in ("SECRET-KEY", "C:\\\\Users", "Some Vendor", "x.exe"):
            self.assertNotIn(secret, blob)

    def test_unlisted_enum_values_collapse_to_unknown(self):
        s = subj(["cap.keyboard.hook"], signature="totally-valid", path_class="C:\\evil")
        f = engine.jev_features(engine.assess(s), s)
        self.assertEqual((f["signature"], f["path_class"]), ("unknown", "unknown"))


class KnowledgeTests(unittest.TestCase):
    def test_every_archetype_and_category_uses_known_kinds(self):
        for a in knowledge.ARCHETYPES.values():
            self.assertTrue(set(a["capture"]) <= set(vocab.KINDS))
            self.assertTrue(set(a["needs"]) <= set(vocab.STAGES))
            self.assertTrue(a["mechanism"] and a["next_checks"] or not a["capture"])
        for c in knowledge.CATEGORIES.values():
            self.assertTrue(set(c["expects"]) <= set(vocab.KINDS))

    def test_every_capture_kind_has_an_observability_entry(self):
        for kind, (stage, _w, _d) in vocab.KINDS.items():
            if stage == "capture":
                mechs = vocab.CAPTURE_MECHANISMS[kind]
                self.assertTrue(all(m in vocab.OBSERVABILITY for m in mechs), kind)


if __name__ == "__main__":
    unittest.main()


class MasqueradeTests(unittest.TestCase):
    def test_system_names_and_lookalikes_outside_the_os_are_masquerade(self):
        for name in ("svchost.exe", "SVCHOST.EXE", "svch0st.exe", "scvhost.exe", "lsasss.exe", "csrs.exe"):
            self.assertTrue(vocab.is_masquerade(name, "temp"), name)
        # The real location, ordinary names, and short names are never masquerade.
        self.assertFalse(vocab.is_masquerade("svchost.exe", "os"))
        for name in ("chrome.exe", "notepad.exe", "python.exe", "", None, "ab.exe"):
            self.assertFalse(vocab.is_masquerade(name, "user_writable"), name)

    def test_linux_names_use_the_linux_list(self):
        self.assertTrue(vocab.is_masquerade("sshd", "user_writable", windows=False))
        self.assertFalse(vocab.is_masquerade("sshd", "os", windows=False))
        self.assertFalse(vocab.is_masquerade("svchost.exe", "temp", windows=False))

    def test_masquerade_alone_is_a_visibility_contradiction(self):
        r = engine.assess(subj(["conceal.masquerade"]))
        self.assertEqual(r["verdict"], "VISIBILITY_CONTRADICTION")

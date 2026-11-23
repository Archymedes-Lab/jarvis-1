import unittest
from unittest.mock import patch

from jarvis.collectors.host import posture
from jarvis.collectors.host.posture import run as posture_run
from jarvis.collectors.host.posture.sections import ASR_KEY, ASR_MORE, _memory_defense


def audit_with(**fields):
    data = {"hotfix": [{"id": "KB1", "on": "2026-09-01"}], **fields}
    with patch.object(posture_run, "ps_json", return_value=data), \
         patch.object(posture_run.broker, "result", return_value=(None, "not in tests")):
        return posture.audit()


def mitigations(**over):
    base = {"dep": "ON", "sehop": "ON", "aslr_bottomup": "ON", "aslr_highentropy": "ON",
            "aslr_forcerelocate": "ON", "cfg": "ON", "user_shadow_stack": "ON"}
    base.update(over)
    return base


def live_host():
    """The values read on the owner's machine on 2026-10-21."""
    return {"mitigations": mitigations(dep="NOTSET", sehop="NOTSET", cfg="NOTSET",
                                       user_shadow_stack="OFF"),
            "kernelshadow": None, "wdigest": None,
            "lsa": {"runasppl": 1, "runasppl_boot": 1}}


class MemoryDefenseTests(unittest.TestCase):
    def by_title(self, findings):
        return {f["title"]: f for f in findings}

    def test_hardened_system_reports_nothing(self):
        d = {"mitigations": mitigations(), "kernelshadow": 1, "wdigest": 0,
             "lsa": {"runasppl": 2}}
        self.assertEqual(_memory_defense(d), [])

    def test_disabled_dep_is_high_with_the_exact_remediation(self):
        f = self.by_title(_memory_defense({"mitigations": mitigations(dep="OFF")}))
        self.assertEqual(f["DEP is disabled system-wide"]["severity"], "high")
        self.assertIn("Set-ProcessMitigation -System -Enable DEP",
                      f["DEP is disabled system-wide"]["where"])

    def test_defaults_are_low_pins_not_disabled_claims(self):
        f = self.by_title(_memory_defense(live_host()))
        self.assertEqual(f["DEP is at its default, not pinned on"]["severity"], "low")
        self.assertNotIn("DEP is disabled system-wide", f)
        self.assertNotIn("SEHOP is disabled system-wide", f)
        self.assertNotIn("Control Flow Guard is disabled system-wide", f)
        self.assertEqual(f["hardware shadow stacks are not enforced system-wide"]["severity"], "low")
        self.assertEqual(
            f["kernel-mode hardware-enforced stack protection is not enabled"]["severity"], "low")
        self.assertNotIn("WDigest keeps plaintext passwords in LSASS", f)
        self.assertNotIn("LSA protection is on without a UEFI lock", f)
        self.assertTrue(all(x["severity"] == "low" for x in f.values()))

    def test_aslr_and_sehop_off_are_medium(self):
        f = self.by_title(_memory_defense(
            {"mitigations": mitigations(sehop="OFF", aslr_bottomup="OFF", aslr_highentropy="OFF",
                                        cfg="OFF")}))
        for title in ("SEHOP is disabled system-wide", "bottom-up ASLR is disabled system-wide",
                      "high-entropy ASLR is disabled system-wide",
                      "Control Flow Guard is disabled system-wide"):
            self.assertEqual(f[title]["severity"], "medium", title)

    def test_wdigest_plaintext_is_high_and_lsa_without_lock_is_low(self):
        f = self.by_title(_memory_defense(
            {"mitigations": mitigations(), "wdigest": 1, "kernelshadow": 1,
             "lsa": {"runasppl": 1, "runasppl_boot": None}}))
        self.assertEqual(f["WDigest keeps plaintext passwords in LSASS"]["severity"], "high")
        self.assertEqual(f["LSA protection is on without a UEFI lock"]["severity"], "low")

    def test_unreadable_mitigations_are_visibility_not_off(self):
        f = _memory_defense({"mitigations": None, "kernelshadow": 1})
        self.assertEqual([x["category"] for x in f], ["visibility"])
        self.assertEqual(f[0]["severity"], "low")

    def test_section_is_wired_and_categorised(self):
        titles = {f["title"]: f for f in audit_with(**live_host())}
        hit = titles["DEP is at its default, not pinned on"]
        self.assertEqual(hit["category"], "memory defense")

    def test_asr_audit_mode_is_not_counted_as_blocking(self):
        ids = list(ASR_KEY) + list(ASR_MORE)[:3]
        actions = [1] * len(ASR_KEY) + [2, 2, 6]
        pref = {"PUAProtection": 1, "EnableNetworkProtection": 1,
                "EnableControlledFolderAccess": 1,
                "AttackSurfaceReductionRules_Ids": ids,
                "AttackSurfaceReductionRules_Actions": actions}
        defender = {"RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True,
                    "IsTamperProtected": True, "AntivirusSignatureAge": 0,
                    "AMRunningMode": "Normal", "AMServiceEnabled": True,
                    "IoavProtectionEnabled": True, "OnAccessProtectionEnabled": True,
                    "AntispywareEnabled": True, "NISEnabled": True}
        titles = {f["title"]: f for f in audit_with(defender=defender, mppref=pref)}
        self.assertNotIn(f"{len(ASR_KEY)} of {len(ASR_KEY)} key ASR rules are not enforcing", titles)
        soft = [t for t in titles if t.endswith("further ASR rules are not blocking")]
        self.assertEqual(len(soft), 1)
        self.assertEqual(titles[soft[0]]["severity"], "low")
        self.assertIn("3 only audit/warn", titles[soft[0]]["detail"])
        self.assertIn(f"{len(ASR_MORE) - 3} not configured", titles[soft[0]]["detail"])
        pref["AttackSurfaceReductionRules_Actions"] = [2] + [1] * (len(ASR_KEY) - 1) + [1, 1, 1]
        titles = {f["title"] for f in audit_with(defender=defender, mppref=pref)}
        self.assertIn(f"1 of {len(ASR_KEY)} key ASR rules are not enforcing", titles)


if __name__ == "__main__":
    unittest.main()

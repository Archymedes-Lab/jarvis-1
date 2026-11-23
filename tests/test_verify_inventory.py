"""Inventory is lowered only on proof: a valid signature on the program the
finding names, never on a script host, never when unverifiable."""

import unittest
from unittest import mock

from jarvis.collectors import verify_inventory as v
from jarvis.platform import signatures


def run_key(cmd, sev="medium"):
    return {"category": "persistence", "severity": sev, "title": "autostart registry entry",
            "detail": f"X = {cmd[:20]}…", "where": "HKCU:\\Run",
            "response_target": {"kind": "runkey", "value": cmd}}


class VerifyInventoryTests(unittest.TestCase):
    def verdicts(self, mapping):
        return mock.patch.object(signatures, "verify", side_effect=lambda paths: {
            signatures.normalize(p): mapping.get(signatures.normalize(p),
                                                  {"status": "NotSigned", "signer": ""})
            for p in paths})

    def test_signed_program_is_lowered_with_its_proof(self):
        f = run_key('"C:\\Program Files\\Vendor\\app.exe" --tray')
        with self.verdicts({"C:\\Program Files\\Vendor\\app.exe":
                            {"status": "Valid", "signer": "CN=Vendor, O=Vendor Inc"}}):
            v.apply("control", [f])
        self.assertEqual(f["severity"], "low")
        self.assertIn("signed by Vendor Inc", f["detail"])

    def test_unsigned_unknown_or_missing_keep_their_severity(self):
        for status in ("NotSigned", "Unknown", "Missing", "HashMismatch"):
            f = run_key("C:\\x\\app.exe")
            with self.verdicts({"C:\\x\\app.exe": {"status": status, "signer": "O=X"}}):
                v.apply("control", [f])
            self.assertEqual(f["severity"], "medium", status)

    def test_signed_script_host_proves_nothing(self):
        f = run_key("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAAA")
        with self.verdicts({}) as verify:
            v.apply("control", [f])
        verify.assert_not_called()
        self.assertEqual(f["severity"], "medium")

    def test_high_and_critical_are_never_touched(self):
        f = run_key("C:\\Program Files\\Vendor\\app.exe", sev="high")
        with self.verdicts({}) as verify:
            v.apply("control", [f])
        verify.assert_not_called()
        self.assertEqual(f["severity"], "high")

    def test_other_jobs_are_not_affected(self):
        f = run_key("C:\\Program Files\\Vendor\\app.exe")
        with self.verdicts({}) as verify:
            v.apply("spy", [f])
        verify.assert_not_called()


class SignatureHelperTests(unittest.TestCase):
    def test_command_lines_resolve_to_the_program(self):
        e = signatures.executable
        self.assertEqual(e('"C:\\A B\\x.exe" -q'), "C:\\A B\\x.exe")
        self.assertEqual(e("C:\\A B\\x.exe -q"), "C:\\A B\\x.exe")
        self.assertEqual(e("\\SystemRoot\\system32\\DRIVERS\\y.sys"),
                         "C:\\Windows\\system32\\DRIVERS\\y.sys")
        self.assertEqual(e("%SystemRoot%\\system32\\svchost.exe -k x"),
                         "C:\\Windows\\system32\\svchost.exe")

    def test_only_store_or_system_packages_count(self):
        rows = [{"full": "A_1_x64__abc", "name": "A", "kind": "Store", "status": "Ok"},
                {"full": "B_1_x64__def", "name": "B", "kind": "Developer", "status": "Ok"}]
        paths = ["C:\\Program Files\\WindowsApps\\A_1_x64__abc\\a.exe",
                 "C:\\Program Files\\WindowsApps\\B_1_x64__def\\b.exe"]
        with mock.patch.object(signatures, "ps_json", return_value=rows):
            out = signatures._package_verdicts(paths)
        self.assertEqual(list(out), [paths[0]])

    def test_missing_file_is_missing_not_valid(self):
        self.assertEqual(signatures.verify(["C:\\definitely\\not\\here.exe"])
                         ["C:\\definitely\\not\\here.exe"]["status"], "Missing")

    def test_logi_payload_requires_both_exact_hashes_and_valid_catalog(self):
        exe = signatures._LOGI_EXE
        installer = "/mnt/c/Windows/System32/DriverStore/FileRepository/" \
                    "logi_download_assistant_component.inf_amd64_test/" \
                    "logi_download_assistant-2.0.529-win64.exe"
        def digest(path):
            return (signatures._LOGI_EXE_SHA256 if path == signatures._wsl(exe)
                    else signatures._LOGI_INSTALLER_SHA256)
        valid = {"status": "Valid", "signer":
                 "CN=Microsoft Windows Hardware Compatibility Publisher, "
                 "O=Microsoft Corporation"}
        with mock.patch.object(signatures.glob, "glob", return_value=[installer]), \
             mock.patch.object(signatures, "_sha256", side_effect=digest), \
             mock.patch.object(signatures, "ps_json", return_value=valid):
            self.assertEqual(signatures._logi_package_verdict(exe)["source"],
                             "package_payload")
        with mock.patch.object(signatures.glob, "glob", return_value=[installer]), \
             mock.patch.object(signatures, "_sha256", return_value="changed"), \
             mock.patch.object(signatures, "ps_json", return_value=valid) as ps:
            self.assertIsNone(signatures._logi_package_verdict(exe))
            ps.assert_not_called()
        with mock.patch.object(signatures.glob, "glob", return_value=[installer]), \
             mock.patch.object(signatures, "_sha256", side_effect=lambda path:
                               signatures._LOGI_EXE_SHA256 if path == signatures._wsl(exe)
                               else "changed"), \
             mock.patch.object(signatures, "ps_json", return_value=valid) as ps:
            self.assertIsNone(signatures._logi_package_verdict(exe))
            ps.assert_not_called()
        with mock.patch.object(signatures.glob, "glob", return_value=[installer]), \
             mock.patch.object(signatures, "_sha256", side_effect=digest), \
             mock.patch.object(signatures, "ps_json", return_value={"status": "NotSigned"}):
            self.assertIsNone(signatures._logi_package_verdict(exe))

    def test_payload_proof_does_not_claim_the_image_itself_is_signed(self):
        f = {"category": "spy", "severity": "medium",
             "title": "autostart binary is unsigned (NotSigned)",
             "detail": "Logi executable", "where": signatures._LOGI_EXE}
        verdict = {"status": "Valid", "source": "package_payload",
                   "signer": "O=Logitech (Microsoft WHCP-signed package)"}
        with mock.patch.object(signatures, "verify",
                               return_value={signatures._LOGI_EXE: verdict}):
            v.apply("spy", [f])
        self.assertEqual(f["severity"], "low")
        self.assertIn("exactly matches the payload", f["detail"])
        self.assertNotIn("is signed by", f["detail"])


if __name__ == "__main__":
    unittest.main()


class DefenderConfirmTests(unittest.TestCase):
    def test_live_state_replaces_a_stale_off_reading(self):
        from jarvis.collectors.host.posture import run
        d = {"defender": {"RealTimeProtectionEnabled": False, "BehaviorMonitorEnabled": True,
                          "IsTamperProtected": True}}
        live = {"RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True,
                "IsTamperProtected": True, "AMRunningMode": "Normal"}
        with mock.patch.object(run, "ps_json", return_value=live):
            run._confirm_defender(d)
        self.assertTrue(d["defender"]["RealTimeProtectionEnabled"])

    def test_failed_live_read_keeps_the_off_reading(self):
        from jarvis.collectors.host.posture import run
        d = {"defender": {"RealTimeProtectionEnabled": False, "BehaviorMonitorEnabled": True,
                          "IsTamperProtected": True}}
        with mock.patch.object(run, "ps_json", return_value=None):
            run._confirm_defender(d)
        self.assertFalse(d["defender"]["RealTimeProtectionEnabled"])

    def test_live_off_is_still_off(self):
        from jarvis.collectors.host.posture import run
        d = {"defender": {"RealTimeProtectionEnabled": False, "BehaviorMonitorEnabled": True,
                          "IsTamperProtected": True}}
        live = {"RealTimeProtectionEnabled": False, "BehaviorMonitorEnabled": True,
                "IsTamperProtected": True, "AMRunningMode": "Normal"}
        with mock.patch.object(run, "ps_json", return_value=live):
            run._confirm_defender(d)
        self.assertFalse(d["defender"]["RealTimeProtectionEnabled"])


class PthRecordTests(unittest.TestCase):
    def test_record_hash_match_names_the_package_and_edits_break_it(self):
        import base64
        import hashlib
        import os
        import tempfile

        from jarvis.collectors.host.toolchain import packaging
        with tempfile.TemporaryDirectory() as site:
            pth = os.path.join(site, "a1_coverage.pth")
            with open(pth, "wb") as fh:
                fh.write(b"import sys; exec('pass')\n")
            with open(pth, "rb") as fh:
                digest = base64.urlsafe_b64encode(hashlib.sha256(fh.read()).digest())
            os.makedirs(os.path.join(site, "coverage-7.13.4.dist-info"))
            with open(os.path.join(site, "coverage-7.13.4.dist-info", "RECORD"), "w") as fh:
                fh.write(f"a1_coverage.pth,sha256={digest.rstrip(b'=').decode()},25\n")
            self.assertEqual(packaging._record_owner(pth), "coverage-7.13.4")
            with open(pth, "ab") as fh:
                fh.write(b"import evil\n")
            self.assertEqual(packaging._record_owner(pth), "")


class DefenderBootSampleTests(unittest.TestCase):
    """A boot-time broker sample (signature age 65535, no preferences) must not
    read as protections off; an unreadable sample stays explicitly unknown."""

    ON = {"RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True,
          "IsTamperProtected": True, "AMRunningMode": "Normal"}

    def _sections(self, d):
        from jarvis.collectors.host.posture import sections
        return [(f["severity"], f["title"]) for f in sections._malware_defense(d)]

    def test_live_read_replaces_unknown_age_and_missing_preferences(self):
        from jarvis.collectors.host.posture import run
        d = {"defender": {**self.ON, "AntivirusSignatureAge": 65535}}
        live = {**self.ON, "AntivirusSignatureAge": 0,
                "pref": {"PUAProtection": 1, "EnableNetworkProtection": 1,
                         "EnableControlledFolderAccess": 0,
                         "AttackSurfaceReductionRules_Ids": [], "AttackSurfaceReductionRules_Actions": []}}
        with mock.patch.object(run, "ps_json", return_value=live) as ps:
            run._confirm_defender(d)
        ps.assert_called_once()
        self.assertEqual(d["defender"]["AntivirusSignatureAge"], 0)
        self.assertEqual(d["mppref"]["EnableNetworkProtection"], 1)
        titles = [t for _, t in self._sections(d)]
        self.assertNotIn("Network Protection is not enabled", titles)
        self.assertFalse(any("days old" in t for t in titles))

    def test_live_read_keeps_elevated_exclusions(self):
        from jarvis.collectors.host.posture import run
        d = {"defender": {**self.ON, "AntivirusSignatureAge": 65535},
             "mppref": {"ExclusionPath": ["C:\\evil"]}}
        live = {**self.ON, "AntivirusSignatureAge": 1, "pref": {"PUAProtection": 1}}
        with mock.patch.object(run, "ps_json", return_value=live):
            run._confirm_defender(d)
        self.assertEqual(d["mppref"]["ExclusionPath"], ["C:\\evil"])

    def test_failed_live_read_reports_unknown_not_off(self):
        from jarvis.collectors.host.posture import run
        d = {"defender": {**self.ON, "AntivirusSignatureAge": 65535}}
        with mock.patch.object(run, "ps_json", return_value=None):
            run._confirm_defender(d)
        found = self._sections(d)
        self.assertIn(("low", "Defender signature age is not known yet"), found)
        self.assertIn(("medium", "Defender preferences could not be read"), found)
        titles = [t for _, t in found]
        self.assertNotIn("Network Protection is not enabled", titles)
        self.assertFalse(any("ASR" in t for t in titles))

    def test_genuinely_old_signatures_and_off_preferences_still_report(self):
        d = {"defender": {**self.ON, "AntivirusSignatureAge": 20},
             "mppref": {"PUAProtection": 0, "EnableNetworkProtection": 0,
                        "EnableControlledFolderAccess": 1}}
        found = self._sections(d)
        self.assertIn(("high", "malware signatures are 20 days old"), found)
        self.assertIn(("medium", "Network Protection is not enabled"), found)

    def test_healthy_sample_skips_the_live_read(self):
        from jarvis.collectors.host.posture import run
        d = {"defender": {**self.ON, "AntivirusSignatureAge": 0},
             "mppref": {"PUAProtection": 1, "EnableNetworkProtection": 1,
                        "EnableControlledFolderAccess": 1}}
        with mock.patch.object(run, "ps_json") as ps:
            run._confirm_defender(d)
        ps.assert_not_called()

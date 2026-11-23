import time
import unittest
from unittest import mock

from jarvis.collectors.host.intrusion import run
from jarvis.collectors.host.intrusion.explain import explain_threat


class ExplainThreatTests(unittest.TestCase):
    def test_eicar_is_explained_as_the_harmless_test_file(self):
        text = explain_threat("Virus:DOS/EICAR_Test_File")
        self.assertIn("EICAR", text)
        self.assertIn("harmless", text)
        self.assertNotIn("copies itself", text)

    def test_type_platform_family_and_machine_learning_suffix(self):
        text = explain_threat("Trojan:Win32/Bearfoos.A!ml")
        self.assertIn("trojan", text)
        self.assertIn("Windows program", text)
        self.assertIn("Bearfoos", text)
        self.assertIn("machine-learning", text)
        self.assertIn("not what it did on this computer", text.replace("tells you the kind of threat, ", ""))

    def test_powershell_script_threat(self):
        text = explain_threat("Trojan:PowerShell/Boxter.HEG!MTB")
        self.assertIn("PowerShell script", text)
        self.assertIn("machine-learning", text)

    def test_unknown_and_empty_names_never_invent_a_verdict(self):
        self.assertEqual(explain_threat(""), "")
        self.assertEqual(explain_threat(None), "")
        self.assertIn("Defender", explain_threat("Weird:Thing/Name"))
        self.assertNotIn("ransom", explain_threat("Weird:Thing/Name").lower())


class DefenderFindingTests(unittest.TestCase):
    def _audit(self, threat_names, threats=()):
        data = {"runmru": [], "psHistory": [], "threatNames": list(threat_names),
                "threats": list(threats), "extensions": [], "recentExe": [],
                "credAccess": [], "credReaders": [], "credReadersOk": True,
                "bits": [], "bitsScope": "user"}
        with mock.patch.object(run, "ps_json", return_value=data):
            return run.audit()

    def test_eicar_file_still_on_disk_is_high_and_explained(self):
        out = self._audit([{"name": "Virus:DOS/EICAR_Test_File", "id": "2147519003", "executed": False,
                            "active": False, "onDisk": True,
                            "resources": "file:_C:\\Users\\x\\eicar.com.txt"}])
        hit = [f for f in out if f["title"] == "Defender detected a threat"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")
        self.assertIn("file is still on disk", hit[0]["detail"])
        self.assertIn("EICAR test file", hit[0]["detail"])

    def test_active_threat_is_critical_with_an_explanation(self):
        out = self._audit([{"name": "Trojan:Win32/Bearfoos.A!ml", "id": "1", "executed": True,
                            "active": True, "onDisk": True, "resources": "file:_C:\\a.exe"}])
        hit = [f for f in out if f["title"] == "Defender detected a threat"][0]
        self.assertEqual(hit["severity"], "critical")
        self.assertIn("trojan", hit["detail"])

    def test_old_history_stays_low(self):
        old = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 30 * 86400)) + "+00:00"
        out = self._audit(
            [{"name": "Trojan:Win32/Bearfoos.A!ml", "id": "7", "executed": False, "active": False,
              "onDisk": None, "resources": ""}],
            [{"time": old, "action": "True", "status": "1", "resources": "", "id": "7"}])
        hit = [f for f in out if f["title"] == "Defender detected a threat"][0]
        self.assertEqual(hit["severity"], "low")
        self.assertIn("historical", hit["detail"])


if __name__ == "__main__":
    unittest.main()

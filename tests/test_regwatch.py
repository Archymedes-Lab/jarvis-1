"""Registry key families judged by their writer.

Invariants (collectors/telemetry/regwatch.py)
  1. Judged by writer, never by value; the value is never quoted.
  2. One problem, one finding: no second report where a specific registry rule fired;
     writes fold per family and writer.
  3. Windows components and machine-wide programs writing these families are not reported.
  4. Severity is medium, never higher.
"""
import unittest

from jarvis.collectors.telemetry import regwatch, sysmon, techniques

S32 = "C:\\Windows\\System32\\"
POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableSmartScreen"
RUN = "HKU\\S-1-5-21-1-1-1-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"


def audit(writes):
    rows = [{"id": 13, "image": image, "reg_key": key, "reg_details": details, "time": "2026-11-10T12:00:00.000Z"}
            for image, key, details in writes]
    return [f for f in sysmon.audit(events=rows) if f.get("techniques")]


class Judge(unittest.TestCase):
    def test_every_family_is_reached_by_a_tool_and_not_by_a_windows_component(self):
        keys = {
            "policies": POLICY, "defender": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection",
            "lsa": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages",
            "winlogon": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", "autorun": RUN,
            "ifeo": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger",
            "accessibility": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs\\x\\StartExe",
            "appinit": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
            "timeprovider": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\X\\DllName",
            "netprovider": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NPPSpy\\NetworkProvider\\ProviderPath",
            "service": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Foo\\ImagePath",
            "environment": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path",
            "remote": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections",
            "proxy": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer",
            "openwith": "HKU\\S-1-5-21-1_Classes\\ms-settings\\shell\\open\\command\\DelegateExecute",
        }
        self.assertEqual(set(keys), {f[0] for f in regwatch.FAMILIES})
        for fid, key in keys.items():
            self.assertEqual(regwatch.judge(S32 + "reg.exe", key)[0], fid, fid)
            for component in ("svchost.exe", "services.exe", "msiexec.exe", "winlogon.exe", "lsass.exe"):
                self.assertIsNone(regwatch.judge(S32 + component, key), (fid, component))
            self.assertIsNone(regwatch.judge("C:\\Program Files\\Vendor\\setup.exe", key), fid)

    def test_keys_outside_the_families_are_not_judged(self):
        for key in ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Foo\\Start",
                    "HKU\\S-1-5-21-1\\Software\\Vendor\\App\\Setting",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Other", "", None):
            self.assertIsNone(regwatch.judge(S32 + "reg.exe", key), key)

    def test_a_program_in_a_user_folder_is_reported_except_where_applications_register_themselves(self):
        user = "C:\\Users\\u\\AppData\\Local\\Temp\\a.exe"
        self.assertEqual(regwatch.judge(user, POLICY)[3], "user-path")
        self.assertIsNone(regwatch.judge(user, RUN))                                   # left to the autostart inventory
        self.assertIsNone(regwatch.judge("C:\\Users\\u\\AppData\\Local\\Discord\\Update.exe", RUN))
        # Defender's own engine lives under ProgramData and writes its own settings.
        engine = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe"
        self.assertEqual(regwatch.judge(engine, "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\X")[3], "shared-data")

    def test_scripting_tools_are_reported_wherever_they_live(self):
        for tool in ("powershell.exe", "PWSH.EXE", "cmd.exe", "wscript.exe", "regedit.exe", "python.exe"):
            self.assertEqual(regwatch.judge("D:\\any\\" + tool, RUN)[3], "tool", tool)


class Detector(unittest.TestCase):
    def test_a_tool_write_is_one_medium_finding_that_never_shows_the_value(self):
        found = audit([(S32 + "reg.exe", POLICY, "DWORD (0x00000000)"),
                       (S32 + "reg.exe", POLICY.replace("EnableSmartScreen", "Other"), "hunter2-secret")])
        self.assertEqual(len(found), 1)                              # folded per family and writer
        f = found[0]
        self.assertEqual((f["severity"], f["techniques"]), ("medium", ["T1112"]))
        self.assertIn("2 writes", f["detail"])
        self.assertNotIn("hunter2", f["detail"])
        self.assertNotIn("0x00000000", f["detail"])

    def test_a_windows_component_write_raises_nothing(self):
        self.assertEqual(audit([(S32 + "svchost.exe", POLICY, "DWORD (0x00000000)")]), [])

    def test_a_write_a_specific_rule_reports_is_not_reported_twice(self):
        # Every specific rule whose key lies in a watched family, written by a tool:
        # the family watch would also have a reason, and must stay silent.
        both = [r for r in techniques.REG_RULES if regwatch.family(r.sample[1])]
        self.assertTrue(both)
        for rule in both:
            _image, key, details = rule.sample
            self.assertTrue(regwatch.judge(S32 + "reg.exe", key))
            found = audit([(S32 + "reg.exe", key, details)])
            self.assertEqual([f["severity"] for f in found], [rule.severity], rule.title)

    def test_a_benign_lookalike_of_a_specific_rule_is_never_reported_as_that_rules_technique(self):
        # The family watch may report the same write for its own reason (a tool changed the
        # family); it must not restate the specific rule's claim about the value.
        wrong = [(r.title, b) for r in techniques.REG_RULES for b in r.benign
                 if (j := regwatch.judge(b[0], b[1])) and not techniques.registry(b[1], b[2])
                 and set(r.tids) & set(j[1])]
        self.assertEqual(wrong, [])

    def test_severity_is_never_above_medium(self):
        self.assertEqual(regwatch.SEVERITY, "medium")


if __name__ == "__main__":
    unittest.main()


class SharedDataProvenance(unittest.TestCase):
    def test_shared_data_location_never_proves_a_trusted_writer(self):
        for image in (r"C:\ProgramData\UserCreated\agent.exe",
                      r"C:\ProgramData\Microsoft\Windows Defender\Platform\fake\MsMpEng.exe",
                      "d:/PROGRAMDATA/user-created/tool.exe"):
            result = regwatch.judge(image, POLICY)
            self.assertIsNotNone(result, image)
            self.assertEqual(result[3], "shared-data")

    def test_unknown_provenance_is_explicit_and_value_is_withheld(self):
        findings = audit([(r"C:\ProgramData\UserCreated\agent.exe", POLICY, "secret-registry-value")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'medium')
        self.assertIn('location alone does not establish', findings[0]['detail'])
        self.assertIn('legitimate vendor security engines', findings[0]['detail'])
        self.assertNotIn('secret-registry-value', str(findings))

    def test_similar_directory_names_are_not_treated_as_programdata(self):
        self.assertIsNone(regwatch.judge(r"C:\ProgramDatabase\agent.exe", POLICY))
        self.assertIsNone(regwatch.judge(None, POLICY))

    def test_scripting_tool_identity_remains_the_more_specific_reason(self):
        self.assertEqual(regwatch.judge(r"C:\ProgramData\tools\powershell.exe", POLICY)[3], 'tool')

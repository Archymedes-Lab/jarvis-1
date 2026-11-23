import pathlib
import unittest
import xml.etree.ElementTree as ET

from jarvis.collectors.telemetry import sysmon_policy, techniques

POLICY = pathlib.Path(__file__).parents[1] / "windows-sysmon" / "jarvis-windows-baseline.xml"
INSTALLER = pathlib.Path(__file__).parents[1] / "scripts" / "repair" / "apply-jarvis-sysmon-policy.ps1"


class WindowsSysmonPolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(POLICY).getroot()
        self.events = self.root.find("EventFiltering")

    def event(self, name):
        return self.events.find(name)

    def test_policy_is_well_formed_and_uses_current_schema(self):
        self.assertEqual(self.root.tag, "Sysmon")
        self.assertEqual(self.root.attrib["schemaversion"], "4.90")

    def test_process_creation_has_no_exclusions(self):
        event = self.event("ProcessCreate")
        self.assertEqual(event.attrib["onmatch"], "exclude")
        self.assertEqual(list(event), [])

    def test_high_volume_process_termination_is_limited(self):
        event = self.event("ProcessTerminate")
        self.assertEqual(event.attrib["onmatch"], "include")
        self.assertEqual([node.text for node in event], ["C:\\Users\\", "\\Device\\"])

    def registry(self, onmatch):
        found = [event for event in self.events.iter("RegistryEvent")
                 if event.attrib["onmatch"] == onmatch]
        self.assertEqual(len(found), 1)
        return found[0]

    def test_registry_collection_is_high_signal_not_unbounded(self):
        event = self.registry("include")
        targets = [node.text for node in event.findall("TargetObject")]
        self.assertIn("\\Image File Execution Options\\", targets)
        # The bare Services subtree was 93% of registry volume and overflowed
        # the driver queue at boot 187 (2026-10-27); it must not come back.
        self.assertNotIn("\\CurrentControlSet\\Services\\", targets)

    def recorded(self, event_type, key):
        return sysmon_policy.registry_recorded(self.root, event_type, key)

    def test_service_persistence_and_tampering_are_still_recorded(self):
        svc = "HKLM\\System\\CurrentControlSet\\Services\\"
        for key in ("Evil\\ImagePath", "Evil\\Parameters\\ServiceDll", "WinDefend\\Start",
                    "Evil\\Type", "Evil\\FailureCommand", "Evil\\ObjectName",
                    "WinDefend\\Security\\Security", "Evil\\DependOnService",
                    "Tcpip\\Parameters\\NameServer",
                    "Tcpip\\Parameters\\Interfaces\\{0}\\NameServer",
                    "Tcpip\\Parameters\\DataBasePath", "W32Time\\Parameters\\NtpServer",
                    "W32Time\\TimeProviders\\Evil\\DllName",
                    "Evil\\NetworkProvider\\ProviderPath",
                    "WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\1\\LibraryPath",
                    "DNS\\Parameters\\ServerLevelPluginDll",
                    "LanmanServer\\Parameters\\NullSessionPipes",
                    "SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\{1}",
                    "PortProxy\\v4tov4\\tcp\\0.0.0.0/445",
                    "SysmonDrv\\Parameters\\Rules", "JarvisNativeSensor\\Start",
                    "EventLog\\Security\\MaxSize", "Evil\\Parameters\\Application",
                    "Evil\\Parameters\\AppParameters"):
            self.assertTrue(self.recorded("SetValue", svc + key), key)
        self.assertTrue(self.recorded("DeleteKey", svc + "WinDefend"))

    def test_measured_service_noise_is_no_longer_recorded(self):
        svc = "HKLM\\System\\CurrentControlSet\\Services\\"
        for key in ("DisplayEnhancementService\\State\\ScreenBrightnessPercent",
                    "Tcpip\\Parameters\\Interfaces\\{0}\\DhcpIPAddress",
                    "Tcpip\\Parameters\\Interfaces\\{0}\\LeaseObtainedTime",
                    "WFPLWFS\\Parameters\\SkipNdisAdaptersKeyGeneration",
                    "UmPass\\Enum\\Count", "NetBT\\Linkage\\Bind",
                    "hns\\State\\HostComputeNetwork\\x"):
            self.assertFalse(self.recorded("SetValue", svc + key), key)
        # A new service key alone is still the excluded CreateKey noise; its
        # ImagePath write is what records it.
        self.assertFalse(self.recorded("CreateKey", svc + "Evil"))

    def test_every_registry_detector_sample_is_recorded_by_the_baseline(self):
        # A detector that reads a key the policy does not record is blind
        # without failing: prove each one's positive sample reaches the log.
        for rule in techniques.REG_RULES:
            _image, key, _details = rule.sample
            self.assertTrue(self.recorded("SetValue", key), (rule.title, key))

    def test_wsl_boundary_keys_and_files_are_recorded(self):
        # The registration keys any user process can write (DefaultUid, BasePath,
        # Flags), the service plugins, the policy key, the VM config file and
        # Windows-side writes into the distro over the wsl.localhost share.
        targets = [node.text for node in self.registry("include").findall("TargetObject")]
        self.assertIn("\\CurrentVersion\\Lxss\\", targets)
        self.assertIn("\\Policies\\Microsoft\\Windows\\WSL", targets)
        files = [node.text for node in self.event("FileCreate").findall("TargetFilename")]
        self.assertIn("\\.wslconfig", files)
        self.assertIn("\\wsl.localhost\\", files)
        self.assertIn("\\wsl$\\", files)

    def test_registry_include_and_exclude_live_in_separate_rule_groups(self):
        groups = self.events.findall("RuleGroup")
        kinds = sorted(group.find("RegistryEvent").attrib["onmatch"] for group in groups
                       if group.find("RegistryEvent") is not None)
        self.assertEqual(kinds, ["exclude", "include"])

    def test_registry_exclusions_only_drop_measured_noise_operations(self):
        # Every exclusion is an AND of one noise operation and one key, so
        # deletions, renames and security value changes are never excluded.
        rules = self.registry("exclude").findall("Rule")
        self.assertEqual(len(rules), 6)
        for rule in rules:
            self.assertEqual(rule.attrib["groupRelation"], "and")
            (kind,) = [n.text for n in rule.findall("EventType")]
            (target,) = [n.text for n in rule.findall("TargetObject")]
            self.assertIn(kind, ("CreateKey", "SetValue"))
            # The consent-store exclusion drops only the per-use time stamps;
            # the Allow/Deny switch (\Value) stays recorded and attributed.
            self.assertTrue("\\Services\\" in target
                            or ("\\ConsentStore\\" in target and "LastUsedTime" in target),
                            target)
        excluded = [n.text for n in self.registry("exclude").iter("TargetObject")]
        for signal in ("NameServer", "\\Parameters\\ServiceDll", "ImagePath",
                       "\\CurrentVersion\\Run", "Winlogon", "NtpServer",
                       "ConsentStore\\microphone\\Value", "\\Value"):
            self.assertFalse(any(signal in value for value in excluded), signal)
        self.assertEqual(sum(1 for _ in self.registry("exclude").iter("EventType")
                             if _.text in ("DeleteKey", "DeleteValue", "RenameKey")), 0)

    def test_credential_access_and_injection_evidence_remain_enabled(self):
        access = self.event("ProcessAccess")
        self.assertEqual(access.attrib["onmatch"], "include")
        self.assertIn("\\lsass.exe", [node.text for node in access])
        self.assertEqual(self.event("CreateRemoteThread").attrib["onmatch"], "exclude")

    def test_browser_memory_opens_are_recorded_except_by_the_browser_itself(self):
        access = self.event("ProcessAccess")
        rules = access.findall("Rule")
        targets = sorted(rule.find("TargetImage").text for rule in rules)
        self.assertEqual(targets, ["\\brave.exe", "\\chrome.exe", "\\firefox.exe", "\\msedge.exe"])
        for rule in rules:
            self.assertEqual(rule.attrib["groupRelation"], "and")
            source = rule.find("SourceImage")
            self.assertEqual(source.attrib["condition"], "excludes")
            self.assertEqual(source.text, rule.find("TargetImage").text)

    def test_only_unsigned_image_loads_are_recorded(self):
        loads = self.event("ImageLoad")
        self.assertEqual(loads.attrib["onmatch"], "include")
        self.assertEqual([(n.tag, n.attrib["condition"], n.text) for n in loads],
                         [("Signed", "is", "false")])

    def test_defence_tampering_registry_families_are_recorded(self):
        targets = [n.text for n in self.registry("include").iter("TargetObject")]
        for family in ("\\Windows Defender\\Exclusions\\", "\\Windows Defender\\Real-Time Protection\\",
                       "\\Policies\\Microsoft\\Windows Defender\\", "\\CLSID\\;\\InprocServer32",
                       "\\Control\\Lsa\\;Packages", "\\Microsoft\\AMSI\\Providers\\",
                       "\\WMI\\Autologger\\;\\Start"):
            self.assertIn(family, targets)

    def test_installer_verifies_process_starts_are_not_filtered_after_apply(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("$create.Success", installer)
        self.assertIn("\\bfilter:\\s*", installer)

    def test_installer_refuses_unexpected_policy_and_backs_up_first(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        refuse = installer.index("does not match the expected")
        backup = installer.index("'reg.exe') export")
        apply = installer.index("& $svc.Exe -c $applied")
        self.assertLess(refuse, backup)
        self.assertLess(backup, apply)
        # Verify, then apply the same copy: the hashed file is the protected
        # copy in the vault backup, never the caller's path.
        copy = installer.index("Copy-Item -LiteralPath $PolicyPath -Destination $applied")
        hashed = installer.index("Get-FileHash -Algorithm SHA256 -LiteralPath $applied")
        self.assertLess(copy, hashed)
        self.assertLess(hashed, refuse)
        self.assertNotIn("-c $PolicyPath", installer)
        self.assertNotIn("-LiteralPath $PolicyPath).Hash", installer)
        self.assertIn("Jarvis\\Vault", installer)
        self.assertIn("-Pattern 'Rules'", installer)

    def test_installer_restores_the_backup_when_verification_fails(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        failed = installer.index("if (-not $receipt.verified)")
        self.assertIn("Restore-Backup $backup", installer[failed:])
        for check in ("running config hash differs", "ProcessCreate is filtered",
                      "registry noise exclusions are missing"):
            self.assertIn(check, installer)


if __name__ == "__main__":
    unittest.main()

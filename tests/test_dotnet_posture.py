""".NET runtime hijack points and AMSI (dotnet_posture.py).

The clean baseline measured on 2026-09-28 must read ok, and each documented
hijack must be reported at its severity. Planting these live would change the
runtime of every .NET program the owner starts, so they are fixtures.
"""

import unittest
from unittest import mock

from jarvis.collectors.host import dotnet_posture as dp

DEFENDER = {"clsid": dp.DEFENDER_AMSI,
            "dll": r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MpOav.dll"'}
BASELINE = {
    "env": [],
    "registry": [
        {"key": r"HKLM:\SOFTWARE\Microsoft\.NETFramework", "name": "Enable64Bit", "value": "1"},
        {"key": r"HKLM:\SOFTWARE\Microsoft\.NETFramework", "name": "InstallRoot",
         "value": "C:\\Windows\\Microsoft.NET\\Framework64\\"},
        {"key": r"HKLM:\SOFTWARE\Microsoft\.NETFramework", "name": "UseRyuJIT", "value": "1"},
        {"key": r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework", "name": "InstallRoot",
         "value": "C:\\Windows\\Microsoft.NET\\Framework\\"}],
    "amsi": [DEFENDER], "amsi_enable": [], "errors": []}


def with_(**changes):
    data = {k: list(v) for k, v in BASELINE.items()}
    for k, v in changes.items():
        data[k] = v
    return data


def severities(data):
    return {f["title"]: f["severity"] for f in dp.analyse(data)}


class DotnetPostureTests(unittest.TestCase):
    def test_measured_baseline_is_ok(self):
        out = dp.analyse(BASELINE)
        self.assertEqual([f["severity"] for f in out], ["ok"])

    def test_profiler_startup_hook_and_appdomain_injection_are_high(self):
        for name in ("COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH_64",
                     "CORECLR_PROFILER_PATH", "DOTNET_STARTUP_HOOKS",
                     "APPDOMAIN_MANAGER_ASM", "APPDOMAIN_MANAGER_TYPE"):
            for scope in ("user", "machine"):
                out = severities(with_(env=[{"scope": scope, "name": name, "value": "x"}]))
                self.assertEqual(list(out.values()), ["high"], (name, scope))

    def test_runtime_etw_off_and_component_replacement_are_high(self):
        for name, value in (("COMPlus_ETWEnabled", "0"), ("DOTNET_ETWEnabled", "0"),
                            ("COMPlus_AltJit", "*"), ("DOTNET_GCName", "gc.dll"),
                            ("COMPlus_JitName", "j.dll")):
            out = severities(with_(env=[{"scope": "user", "name": name, "value": value}]))
            self.assertEqual(list(out.values()), ["high"], name)
        # ETW explicitly on is not a finding of that kind.
        out = severities(with_(env=[{"scope": "user", "name": "DOTNET_ETWEnabled", "value": "1"}]))
        self.assertEqual(list(out.values()), ["low"])

    def test_registry_config_is_checked_like_the_environment(self):
        key = r"HKCU:\SOFTWARE\Microsoft\.NETFramework"
        cases = {("ETWEnabled", "0"): "high", ("AltJitName", "x.dll"): "high",
                 ("DbgManagedDebugger", "evil.exe"): "medium", ("SomethingNew", "1"): "low"}
        for (name, value), sev in cases.items():
            reg = BASELINE["registry"] + [{"key": key, "name": name, "value": value}]
            self.assertEqual(list(severities(with_(registry=reg)).values()), [sev], name)

    def test_benign_developer_variables_are_quiet(self):
        env = [{"scope": "user", "name": "DOTNET_CLI_TELEMETRY_OPTOUT", "value": "1"},
               {"scope": "user", "name": "DOTNET_ROOT", "value": "C:\\dotnet"}]
        out = dp.analyse(with_(env=env))
        self.assertEqual([f["severity"] for f in out], ["ok"])
        self.assertIn("DOTNET_CLI_TELEMETRY_OPTOUT", out[0]["detail"])
        self.assertIn("DOTNET_ROOT", out[0]["detail"])
        self.assertNotIn("C:\\dotnet", out[0]["detail"])

    def test_amsi_provider_removal_redirect_and_additions(self):
        self.assertEqual(list(severities(with_(amsi=[])).values()), ["high"])
        other = {"clsid": "{11111111-2222-3333-4444-555555555555}", "dll": r"C:\Users\x\a.dll"}
        out = severities(with_(amsi=[other]))
        self.assertEqual(sorted(out.values()), ["medium", "medium"])
        hijacked = dict(DEFENDER, dll=r"C:\Users\x\AppData\MpOav.dll")
        self.assertEqual(list(severities(with_(amsi=[hijacked])).values()), ["high"])
        out = severities(with_(amsi=[DEFENDER, other]))
        self.assertEqual(list(out.values()), ["medium"])

    def test_amsi_enable_off_is_high(self):
        out = severities(with_(amsi_enable=[{"key": r"HKCU:\Software\Microsoft\Windows Script\Settings",
                                             "value": "0"}]))
        self.assertEqual(list(out.values()), ["high"])

    def test_unreadable_probe_is_visible_not_ok(self):
        with mock.patch.object(dp, "ps_json", return_value=None), \
                mock.patch.object(dp.collection, "failed") as failed:
            out = dp.audit()
        self.assertEqual([f["severity"] for f in out], ["medium"])
        failed.assert_called_once()

    def test_probe_is_read_only(self):
        text = dp.PS_DOTNET
        for verb in ("Set-Item", "New-Item", "Remove-Item", "SetEnvironmentVariable",
                     "Set-ItemProperty", "Start-Process", "Invoke-Expression"):
            self.assertNotIn(verb, text)


if __name__ == "__main__":
    unittest.main()

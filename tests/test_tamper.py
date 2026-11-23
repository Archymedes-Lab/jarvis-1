"""Tamper audit: attempts to blind the defenses (collectors/process/tamper.py).

The quiet cases are the routine records measured on this machine on
2026-10-11: 63 Defender configuration changes in 24 h (diagnostics, cloud
lookup timestamps, service start states), Sysmon "Started" at each boot and
Security 1100 at each shutdown. None of them may be reported.
"""
import unittest
from unittest import mock

from jarvis.collectors.process import tamper

WHEN = "2026-10-11T10:00:00.0000000Z"
DEF = r"HKLM\SOFTWARE\Microsoft\Windows Defender"


def payload(**sources):
    base = {k: {"ok": True, "events": []} for k in
            ("defender", "sysmon", "services", "system_clear", "app_crashes", "security")}
    base.update({"writers": {"ok": True, "events": []}, "autologgers": []})
    for k, v in sources.items():
        base[k] = v if k in ("writers", "autologgers") else {"ok": True, "events": v}
    return base


def change(key, value, eid=5007):
    return {"id": eid, "t": WHEN, "msg": f"Configuration changed.\nOld value: \nNew value: {key} = {value}"}


def high(findings):
    return [f["title"] for f in findings if f["severity"] == "high"]


class QuietTests(unittest.TestCase):
    def test_routine_defender_changes_measured_on_this_machine_are_quiet(self):
        routine = [change(DEF + r"\Diagnostics\InitializingComponentProgress", "ServiceStartedSuccessfully"),
                   change(DEF + r"\SpyNet\LastMAPSFailureTimeString", "2026-10-11"),
                   change(DEF + r"\ServiceStartStates", "0x1"),
                   change(DEF + r"\CoreService\WdConfigHash", "abc"),
                   change(DEF + r"\Real-Time Protection\DisableRealtimeMonitoring", "0x0"),
                   change(DEF + r"\Spynet\SpyNetReporting", "0x2")]
        out = tamper.findings(payload(defender=routine))
        self.assertEqual([(f["severity"], f["title"]) for f in out],
                         [("ok", "No attempt to blind the defenses recorded")])

    def test_boot_and_shutdown_records_are_quiet(self):
        out = tamper.findings(payload(
            sysmon=[{"id": 4, "t": WHEN, "msg": "State: Started Version: 15.21"},
                    {"id": 255, "t": WHEN, "msg": "ID: QUEUE Events dropped"}],
            security=[{"id": 1100, "t": WHEN, "msg": "The event logging service has shut down."}],
            services=[{"id": 7036, "t": WHEN, "msg": "The Microsoft Defender Antivirus Service "
                       "service entered the running state."},
                      {"id": 7034, "t": WHEN, "msg": "The Print Spooler service terminated unexpectedly."}],
            autologgers=[{"name": "DefenderApiLogger", "exists": True, "start": -1, "disabled": []},
                         {"name": "EventLog-System", "exists": True, "start": 1, "disabled": []}]))
        self.assertEqual(high(out), [])
        self.assertEqual(out[-1]["severity"], "ok")


class ExclusionTests(unittest.TestCase):
    def test_exclusion_added_is_high_and_names_the_writer(self):
        key = DEF + r"\Exclusions\Paths\C:\Users\Public\x"
        out = tamper.findings(payload(
            defender=[change(key, "0x0")],
            writers={"ok": True, "events": [{"t": "2026-10-11T09:59:59Z", "id": 13,
                                             "image": r"C:\Windows\System32\reg.exe", "target": key}]}))
        hit = [f for f in out if "(T1679)" in f["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")
        self.assertIn(r"C:\Users\Public\x", hit[0]["title"])
        self.assertIn("reg.exe", hit[0]["detail"])

    def test_writer_after_the_change_is_not_blamed(self):
        key = DEF + r"\Exclusions\Extensions\.ps1"
        out = tamper.findings(payload(
            defender=[change(key, "0x0")],
            writers={"ok": True, "events": [{"t": "2026-10-11T10:05:00Z", "image": "late.exe",
                                             "target": key}]}))
        detail = [f for f in out if "(T1679)" in f["title"]][0]["detail"]
        self.assertIn("was not recorded", detail)
        self.assertNotIn("late.exe", detail)

    def test_every_exclusion_kind_is_reported(self):
        for kind in ("Paths", "Extensions", "Processes", "IpAddresses", "TemporaryPaths"):
            out = tamper.findings(payload(defender=[change(DEF + rf"\Exclusions\{kind}\x", "0x0")]))
            self.assertEqual(len([t for t in high(out) if "(T1679)" in t]), 1, kind)


class WeakeningTests(unittest.TestCase):
    def test_protection_switched_off_by_setting_or_event(self):
        cases = [change(DEF + r"\Real-Time Protection\DisableRealtimeMonitoring", "0x1"),
                 change(DEF + r"\Real-Time Protection\DisableBehaviorMonitoring", "1"),
                 change(DEF + r"\Spynet\SubmitSamplesConsent", "0x0"),
                 change(DEF + r"\Features\TamperProtection", "0x4"),
                 {"id": 5001, "t": WHEN, "msg": "Real-time Protection scanning ... disabled."},
                 {"id": 5013, "t": WHEN, "msg": "Tamper protection blocked a change"}]
        for event in cases:
            out = tamper.findings(payload(defender=[event]))
            self.assertEqual(len([t for t in high(out) if "(T1685)" in t]), 1, event)

    def test_sysmon_stopped_reconfigured_and_service_disabled(self):
        out = tamper.findings(payload(
            sysmon=[{"id": 4, "t": WHEN, "msg": "State: Stopped"},
                    {"id": 16, "t": WHEN, "msg": "Configuration file: x.xml"}],
            services=[{"id": 7040, "t": WHEN, "msg": "The start type of the Sysmon64 service was "
                       "changed from auto start to disabled."}]))
        self.assertIn("Sysmon service stopped (T1685)", high(out))
        self.assertIn("Sysmon64 set to disabled (T1685)", high(out))
        self.assertIn(("medium", "Sysmon configuration changed (T1685)"),
                      [(f["severity"], f["title"]) for f in out])

    def test_logs_cleared_and_etw_sessions_silenced(self):
        out = tamper.findings(payload(
            system_clear=[{"id": 104, "t": WHEN, "msg": "cleared"}],
            security=[{"id": 1102, "t": WHEN, "msg": "The audit log was cleared."}],
            autologgers=[{"name": "EventLog-Security", "exists": True, "start": 0, "disabled": []},
                         {"name": "DefenderAuditLogger", "exists": True, "start": 1,
                          "disabled": ["{11cd958a}"]}]))
        for title in ("System event log cleared (T1685)", "Security event log cleared (T1685)",
                      "ETW session EventLog-Security disabled at boot (T1685)",
                      "Providers switched off in ETW session DefenderAuditLogger (T1685)"):
            self.assertIn(title, high(out))


class CrashTests(unittest.TestCase):
    def crash(self, app, code="0xc0000409"):
        return {"id": 1000, "t": WHEN,
                "msg": f"Faulting application name: {app}, version: 1\nException code: {code}"}

    def test_core_engine_crash_is_high_with_the_exception_explained(self):
        out = tamper.findings(payload(app_crashes=[self.crash("MsMpEng.exe")]))
        hit = [f for f in out if "(T1687)" in f["title"]][0]
        self.assertEqual(hit["severity"], "high")
        self.assertIn("0xc0000409", hit["detail"])
        self.assertIn("low memory", hit["detail"])

    def test_single_secondary_crash_is_medium_and_repeats_are_high(self):
        # NisSrv.exe crashed once on 2026-10-11 during host memory exhaustion.
        once = tamper.findings(payload(app_crashes=[self.crash("NisSrv.exe")]))
        self.assertEqual([f["severity"] for f in once if "(T1687)" in f["title"]], ["medium"])
        twice = tamper.findings(payload(app_crashes=[self.crash("NisSrv.exe")] * 2))
        self.assertEqual([f["severity"] for f in twice if "(T1687)" in f["title"]], ["high"])

    def test_security_service_terminating_is_high(self):
        out = tamper.findings(payload(services=[{"id": 7034, "t": WHEN, "msg":
                                                 "The Windows Event Log service terminated unexpectedly."}]))
        self.assertIn("Windows Event Log terminated unexpectedly (T1687)", high(out))


class UnknownTests(unittest.TestCase):
    def test_no_payload_is_unknown_not_clean(self):
        out = tamper.findings(None)
        self.assertEqual([(f["severity"], f["title"]) for f in out],
                         [("medium", "Tamper audit unavailable")])

    def test_unreadable_source_is_reported_and_never_ok(self):
        data = payload()
        data["defender"] = {"ok": False, "error": "Access denied", "events": []}
        data["security"] = {"ok": False, "error": "Access denied", "events": []}
        out = tamper.findings(data)
        titles = [(f["severity"], f["title"]) for f in out]
        self.assertIn(("medium", "Tamper audit could not read the Defender operational log"), titles)
        self.assertIn(("low", "Tamper audit could not read the Security log"), titles)
        self.assertNotIn("ok", [f["severity"] for f in out])

    def test_missing_source_counts_as_unreadable(self):
        data = payload()
        del data["services"]
        out = tamper.findings(data)
        self.assertIn("Tamper audit could not read the System log service events",
                      [f["title"] for f in out])


class EvasionWiringTests(unittest.TestCase):
    def test_live_evasion_run_includes_the_tamper_audit(self):
        from jarvis.collectors.process import evasion
        with mock.patch.object(evasion, "ps_json", return_value={}), \
             mock.patch.object(tamper, "audit", return_value=[
                 {"category": "tamper", "severity": "high", "title": "x (T1679)",
                  "detail": "", "where": "", "host": "win"}]) as read:
            out = evasion.audit()
        read.assert_called_once()
        self.assertIn("x (T1679)", [f["title"] for f in out])

    def test_probe_replay_never_reads_windows(self):
        from jarvis.collectors.process import evasion
        with mock.patch.object(tamper, "audit") as read:
            evasion.audit(data={})
        read.assert_not_called()

    def test_a_failing_tamper_read_does_not_cost_the_evasion_audit(self):
        from jarvis.collectors.process import evasion
        with mock.patch.object(evasion, "ps_json", return_value={}), \
             mock.patch.object(tamper, "audit", side_effect=RuntimeError("bridge")):
            out = evasion.audit()
        self.assertIn("Tamper audit failed", [f["title"] for f in out])
        self.assertTrue(any(f["category"] == "byovd" for f in out))


if __name__ == "__main__":
    unittest.main()

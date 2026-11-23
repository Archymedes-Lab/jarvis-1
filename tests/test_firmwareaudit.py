"""HP firmware audit log: elevated reader safety rules, broker gating, findings."""
import os
import re
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import firmwareaudit
from jarvis.core import collection
from jarvis.core.paths import REPO_ROOT, win_script
from jarvis.core.store import Store
from jarvis.platform import broker


def record(n, source=0x80, event=0x2C, severity="Info", desc="HP Sure Start detected a BIOS update operation completed.",
           ts="2026-10-20T09:00:00"):
    return {"message_number": n, "source": source, "source_name": "General BIOS Messages",
            "event_id": event, "severity": severity, "state": "S0", "exact": True,
            "timestamp": ts, "description": desc}


def read(*records, **over):
    data = {"schema": 1, "available": True, "reason": "", "records": list(records),
            "problems": [], "errors": [], "truncated": False,
            "module": {"name": "HP.Firmware", "version": "1.9.0", "root": "C:\\Program Files"}}
    data.update(over)
    return data


class ReaderScriptRules(unittest.TestCase):
    """The elevated reader must not load anything the unelevated user can change."""

    @classmethod
    def setUpClass(cls):
        with open(win_script("hp_firmware_audit.ps1"), encoding="utf-8") as fh:
            cls.text = fh.read()
        cls.code = "\n".join(l.split("#", 1)[0] for l in cls.text.splitlines())

    def test_registered_with_the_broker_under_one_name(self):
        self.assertEqual(broker.SCRIPTS["fwaudit"], "hp_firmware_audit.ps1")
        script = REPO_ROOT / "jarvis-elevated-broker.ps1"
        if not script.exists():
            self.skipTest("release trees carry the legacy broker-jarvis.ps1; "
                          "the broker is installed from the checkout")
        with open(script, encoding="utf-8") as fh:
            self.assertIn("fwaudit  = @{ script = 'hp_firmware_audit.ps1'", fh.read())

    def test_modules_come_from_program_files_by_full_path_only(self):
        # From the OS, not %ProgramFiles%: the user's environment can redefine it.
        self.assertIn("Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsPowerShell\\Modules'",
                      self.code)
        self.assertNotIn("$env:ProgramFiles", self.code)
        imports = re.findall(r"Import-Module[^\n]*", self.code)
        self.assertEqual(len(imports), 1)
        self.assertIn("-Name (Join-Path $roots[$i]", imports[0])
        # The #requires by-name lookups must resolve to system folders only.
        pin = self.code.index("$env:PSModulePath = \"$base;$([Environment]::SystemDirectory)")
        self.assertLess(pin, self.code.index("Import-Module"))
        for user_path in ("Documents", "$env:USERPROFILE", "LOCALAPPDATA", "CurrentUser"):
            self.assertNotIn(user_path, self.code)

    def test_integrity_is_checked_before_anything_loads(self):
        refuse = self.code.index("if ($problems.Count)")
        self.assertLess(self.code.index("Get-WriteProblem $file.FullName"), refuse)
        self.assertLess(self.code.index("Get-SignerProblem $file.FullName"), refuse)
        self.assertLess(refuse, self.code.index("Import-Module"))
        self.assertIn("$Signers = @('HP Inc.', 'Microsoft Corporation')", self.code)
        self.assertIn("if ($sig.Status -ne 'Valid')", self.code)
        # Only SYSTEM, Administrators and TrustedInstaller may write or own.
        writers = re.search(r"\$Writers = @\(([^)]*)\)", self.code, re.S).group(1)
        self.assertEqual(sorted(re.findall(r"'(S-[0-9-]+)'", writers)), sorted([
            "S-1-5-18", "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"]))
        self.assertIn("owned by", self.code)
        # The loaded modules are re-checked for where they actually came from.
        self.assertIn("ModuleBase.StartsWith($base", self.code)

    def test_records_leave_the_list_as_an_array(self):
        # Windows PowerShell 5.1 throws "Argument types do not match" for
        # @($list) on a List[object] of ordered dictionaries: the first real
        # read (2026-10-24, 46 records) reported none because of it.
        self.assertNotRegex(self.code, r"=\s*@\(\s*\$records\s*\)")
        self.assertIn("$out.records = $records.ToArray()", self.code)

    def test_read_only(self):
        for verb in ("Set-", "Remove-", "Clear-", "New-Item", "Out-File", "Set-Content",
                     "Invoke-HP", "Send-HP", "Update-", "Install-"):
            self.assertNotIn(verb, self.code, verb)
        calls = set(re.findall(r"\b(Get-HP\w+)", self.code))
        self.assertEqual(calls, {"Get-HPFirmwareAuditLog"})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "test.db"))
        self.addCleanup(self.store.close)

    def audit(self, data, why=""):
        with mock.patch.object(broker, "result", return_value=(data, why)), \
                mock.patch.object(collection, "failed") as failed, \
                mock.patch.object(collection, "succeeded") as succeeded:
            out = firmwareaudit.audit(self.store)
        return out, failed, succeeded


class CollectorTests(Base):
    def test_no_broker_result_is_visibility_with_setup_steps(self):
        out, failed, succeeded = self.audit(None, "the elevated broker is not installed")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["category"], "visibility")
        self.assertIn("Install-Module HPCMSL -Scope AllUsers -AcceptLicense", out[0]["detail"])
        failed.assert_called_once()
        succeeded.assert_not_called()

    def test_not_installed_reason_carries_setup_steps(self):
        out, failed, _ = self.audit(read(available=False,
                                         reason="HP CMSL is not installed for all users (Program Files)"))
        self.assertIn("-Scope AllUsers", out[0]["detail"])
        failed.assert_called_once()

    def test_integrity_refusal_is_medium_and_names_the_problem(self):
        out, failed, _ = self.audit(read(
            available=False, reason="refused: 1 integrity problem(s) in the HP modules; nothing was loaded",
            problems=["\\HP.Private\\1.9.0\\dfmbios64.dll: writable by S-1-5-32-545"]))
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("dfmbios64.dll: writable by S-1-5-32-545", out[0]["detail"])
        self.assertIn("loaded nothing", out[0]["detail"])
        failed.assert_called_once()

    def test_malformed_output_is_not_clean(self):
        for bad in ({"schema": 2}, read(record(1, severity=3)),
                    read(*[record(i) for i in range(513)]),
                    read(record(1, desc="x" * 301)), read(record(True))):
            out, failed, succeeded = self.audit(bad)
            self.assertIn("malformed", out[0]["title"])
            succeeded.assert_not_called()

    def test_first_read_reports_warnings_without_calling_them_new(self):
        out, _failed, succeeded = self.audit(read(
            record(1), record(2, source=0x03, event=0x1E, severity="Warn",
                              desc="Sure Start found the primary BIOS ... corrupted or missing.")))
        by = {f["title"]: f for f in out}
        warn = by["HP firmware: Sure Start found the primary BIOS ... corrupted or missing."]
        self.assertEqual(warn["severity"], "medium")
        self.assertNotIn("new since", warn["detail"])
        self.assertIn("HP firmware informational records", by)
        self.assertEqual(by["HP firmware audit log read"]["severity"], "ok")
        succeeded.assert_called_once()

    def test_later_read_marks_only_new_records(self):
        first = record(2, source=0x82, event=0x1E, severity="Warn", desc="Runtime intrusion")
        self.audit(read(first))
        out, _f, _s = self.audit(read(first, record(3, source=0x82, event=0x1E, severity="Warn",
                                                    desc="Runtime intrusion", ts="2026-10-23T11:37:00")))
        intrusion = [f for f in out if f["title"] == "HP firmware: Runtime intrusion"][0]
        self.assertEqual(intrusion["severity"], "high")     # attack source raised
        self.assertIn("2 record(s)", intrusion["detail"])
        self.assertIn("1 new since the last read", intrusion["detail"])
        self.assertIn("newest 2026-10-23T11:37:00", intrusion["detail"])

    def test_unknown_severity_is_not_dismissed_and_critical_is_high(self):
        out, _f, _s = self.audit(read(record(1, severity="", desc=""),
                                      record(2, source=0x8A, event=0x20, severity="Critical",
                                             desc="Tamper")))
        sev = {f["title"]: f["severity"] for f in out}
        self.assertEqual(sev["HP firmware: event 44"], "medium")
        self.assertEqual(sev["HP firmware: Tamper"], "high")

    def test_registered_unscored_job(self):
        from jarvis.response.reporting import score
        from jarvis.response.reporting.commands import JOB_COMMANDS
        from jarvis.service.jobs import RUNNERS
        from jarvis.service.schedule import JOBS
        self.assertIn("fwaudit", RUNNERS)
        self.assertEqual(JOBS["fwaudit"][0], 1800)
        self.assertIn("fwaudit", score.UNSCORED)
        self.assertIn("fwaudit", JOB_COMMANDS)
        try:        # the mechanism registry, where this tree has one
            from jarvis.core import mechanisms
        except ImportError:
            return
        self.assertEqual(mechanisms.BY_NAME["fwaudit"].domain, "windows")


if __name__ == "__main__":
    unittest.main()

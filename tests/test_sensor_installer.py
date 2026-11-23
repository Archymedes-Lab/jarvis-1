"""The native sensor installer runs elevated, so what it compiles and what it
leaves behind are security boundaries (windows-sensor/install.ps1 and
`jarvis sensor`).

Invariants under test:
  * an elevated install compiles only the JarvisSensor.cs whose SHA-256 the
    caller fixed before elevation; one changed byte stops it before csc runs;
  * the elevated command checks every file it will execute after copying it
    into an administrator-only folder, so swapping a file in the user's TEMP
    between staging and the UAC prompt runs nothing;
  * -Remove revokes what -Install granted: the logon-as-a-service right and
    Event Log Readers membership of NT SERVICE\\JarvisNativeSensor, by SID,
    so they go even after the service (and its name lookup) is gone.

The PowerShell parts run in real Windows PowerShell 5.1 when interop is
available; nothing here needs or requests elevation.
"""

import base64
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.cli.commands import sensor

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "windows-sensor" / "install.ps1"
POWERSHELL, WSLPATH = shutil.which("powershell.exe"), shutil.which("wslpath")


def winpath(path):
    return subprocess.run([WSLPATH, "-w", str(path)], capture_output=True, text=True,
                          check=True).stdout.strip()


def ps(script, timeout=60):
    """Run Windows PowerShell 5.1 unelevated -> (exit code, stdout, stderr)."""
    # Process-scope Bypass, as the real elevated launch passes -ExecutionPolicy
    # Bypass: scripts on the \\wsl share are otherwise refused as unsigned.
    encoded = base64.b64encode(("$ProgressPreference='SilentlyContinue';"
                                "Set-ExecutionPolicy -Scope Process Bypass -Force;" + script)
                               .encode("utf-16le")).decode("ascii")
    # WSL sometimes fails to start the Windows process at all (UtilAcceptVsock
    # timeouts under load); that says nothing about the script, so retry once.
    for _attempt in range(2):
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, text=True, errors="replace", timeout=timeout, cwd="/")
        if "UtilAcceptVsock" not in r.stderr:
            break
        time.sleep(5)
    return r.returncode, r.stdout.replace("\r", ""), r.stderr.replace("\r", "")


def functions(*names):
    """PowerShell that defines `names` from install.ps1 without running the script."""
    wanted = ",".join(f"'{n}'" for n in names)
    return (f"$ast=[Management.Automation.Language.Parser]::ParseFile('{winpath(INSTALLER)}',[ref]$null,[ref]$null);"
            "foreach($f in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true))"
            f"{{ if(@({wanted}) -contains $f.Name){{ . ([scriptblock]::Create($f.Extent.Text)) }} }};")


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class InstallerPowerShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=os.path.expanduser("~/.cache")))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_virtual_account_sid_matches_what_windows_reports(self):
        # Ground truth from Windows itself for an account that always exists.
        code, out, err = ps(functions("Get-VirtualAccountSid") +
                            "(New-Object Security.Principal.NTAccount('NT SERVICE\\TrustedInstaller'))"
                            ".Translate([Security.Principal.SecurityIdentifier]).Value;"
                            "Get-VirtualAccountSid 'TrustedInstaller'; Get-VirtualAccountSid 'trustedinstaller';"
                            "Get-VirtualAccountSid 'JarvisNativeSensor'")
        self.assertEqual(code, 0, err[-400:])
        truth, mine, lower, sensor_sid = out.split()
        self.assertEqual(mine, truth)
        self.assertEqual(lower, truth)
        self.assertRegex(sensor_sid, r"^S-1-5-80(-\d+){5}$")
        self.assertNotEqual(sensor_sid, truth)

    def test_revoking_the_logon_right_removes_exactly_that_sid(self):
        sid = "S-1-5-80-1-2-3-4-5"
        cases = {
            f"SeServiceLogonRight = *{sid},*S-1-5-80-0": "SeServiceLogonRight = *S-1-5-80-0",
            f"SeServiceLogonRight = *S-1-5-80-0,*{sid}": "SeServiceLogonRight = *S-1-5-80-0",
            f"SeServiceLogonRight = *S-1-5-80-0,*{sid},*S-1-5-20": "SeServiceLogonRight = *S-1-5-80-0,*S-1-5-20",
            # A longer SID that starts with ours is someone else's grant.
            f"SeServiceLogonRight = *{sid}9,*S-1-5-80-0": f"SeServiceLogonRight = *{sid}9,*S-1-5-80-0",
            "SeServiceLogonRight = *S-1-5-80-0": "SeServiceLogonRight = *S-1-5-80-0",
        }
        script = functions("Remove-SidFromLogonRight")
        for i, line in enumerate(cases):
            script += (f"$r=Remove-SidFromLogonRight @('[Privilege Rights]','{line}','SeBatchLogonRight = *{sid}') '{sid}';"
                       f"'CASE{i}|' + ($r -join '|');")
        code, out, err = ps(script)
        self.assertEqual(code, 0, err[-400:])
        got = dict(re.findall(r"^CASE(\d+)\|(.*)$", out, re.M))
        for i, (line, want) in enumerate(cases.items()):
            with self.subTest(line=line):
                # Other rights keep the SID: only the logon right is revoked.
                self.assertEqual(got[str(i)], f"[Privilege Rights]|{want}|SeBatchLogonRight = *{sid}")

    def test_reviewed_source_check_refuses_one_changed_byte(self):
        src = self.tmp / "JarvisSensor.cs"
        src.write_bytes(b"class S { }\n")
        good = hashlib.sha256(src.read_bytes()).hexdigest()
        script = functions("Assert-ReviewedSource") + "".join(
            f"try {{ Assert-ReviewedSource '{winpath(src)}' '{h}'; 'R{i}|ok' }} catch {{ 'R{i}|refused' }};"
            for i, h in enumerate([good, good.upper(), "0" * 64, "", "zz"]))
        code, out, err = ps(script)
        self.assertEqual(code, 0, err[-400:])
        self.assertEqual(re.findall(r"^R\d\|(\w+)$", out, re.M), ["ok", "ok", "refused", "refused", "refused"])
        src.write_bytes(b"class S { } \n")
        code, out, _ = ps(functions("Assert-ReviewedSource") +
                          f"try {{ Assert-ReviewedSource '{winpath(src)}' '{good}'; 'ok' }} catch {{ 'refused' }}")
        self.assertEqual(out.strip(), "refused")

    def test_group_membership_is_read_by_sid(self):
        # Unelevated read of a group that always holds these well-known SIDs.
        code, out, err = ps(functions("Get-LocalGroupAdsi", "Get-GroupMemberSids") +
                            "Get-GroupMemberSids 'S-1-5-32-545'")
        self.assertEqual(code, 0, err[-400:])
        members = out.split()
        self.assertTrue({"S-1-5-4", "S-1-5-11"} & set(members), members)
        self.assertTrue(all(re.match(r"^S-1-[0-9-]+$", m) for m in members), members)

    def test_install_without_a_reviewed_hash_is_refused_before_anything_else(self):
        code, out, err = ps(f"& '{winpath(INSTALLER)}' -Install")
        self.assertNotEqual(code, 0)
        self.assertIn("SourceSha256", out + err)
        # A well-formed hash passes that gate and stops at the elevation check
        # instead (this test never runs elevated).
        code, out, err = ps(f"& '{winpath(INSTALLER)}' -Install -SourceSha256 {'a' * 64}")
        self.assertNotEqual(code, 0)
        self.assertIn("elevated", out + err)
        self.assertNotIn("SourceSha256", out + err)

    def test_elevated_command_runs_only_files_matching_their_reviewed_hashes(self):
        stage = self.tmp / "stage"
        stage.mkdir()
        trusted = self.tmp / "ProgramFiles"
        trusted.mkdir()
        marker = self.tmp / "ran.txt"
        stub = f"param([switch]$Install,[string]$SourceSha256) \"ran $Install $SourceSha256\" | Set-Content -LiteralPath '{winpath(marker)}'\n"
        (stage / "install.ps1").write_text(stub)
        (stage / "JarvisSensor.cs").write_text("class S { }\n")
        hashes = {n: hashlib.sha256((stage / n).read_bytes()).hexdigest() for n in sensor.SENSOR_FILES}

        def run_inner(args):
            inner = sensor._inner(winpath(stage), hashes, args)
            return ps(f"$env:ProgramFiles='{winpath(trusted)}';" + inner)

        code, out, err = run_inner(["-Install"])
        self.assertEqual(code, 0, (out + err)[-400:])
        self.assertEqual(marker.read_text().split(), ["ran", "True", hashes["JarvisSensor.cs"]])
        self.assertEqual(list((trusted / "Jarvis").rglob("*")), [], "trusted stage left behind")

        # A swap in the user-writable stage after hashing: nothing runs.
        marker.unlink()
        (stage / "install.ps1").write_text(stub + "'swapped' | Out-Null\n")
        code, out, err = run_inner(["-Install"])
        self.assertNotEqual(code, 0)
        self.assertIn("install.ps1", out + err)
        self.assertFalse(marker.exists())
        (stage / "install.ps1").write_text(stub)
        (stage / "JarvisSensor.cs").write_text("class S { int x; }\n")
        code, out, err = run_inner(["-Install"])
        self.assertNotEqual(code, 0)
        self.assertIn("JarvisSensor.cs", out + err)
        self.assertFalse(marker.exists())


class ElevatedCommandTests(unittest.TestCase):
    def test_hashes_are_fixed_from_the_checkout_before_elevation(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "C:\\Users\\u\\AppData\\Local\\Temp\\jarvis-sensor-1\n", "")

        with mock.patch.object(sensor.win, "available", return_value=True), \
             mock.patch.object(sensor.subprocess, "run", side_effect=fake_run):
            sensor._elevated(["-Install"])
        script = calls[-1][-1]
        # The elevated process is launched on inline code, never -File on the
        # user-writable stage; that code carries the hashes fixed here.
        self.assertNotIn("'-File'", script)
        encoded = re.search(r"'-EncodedCommand','([A-Za-z0-9+/=]+)'", script).group(1)
        inner = base64.b64decode(encoded).decode("utf-16le")
        for name in sensor.SENSOR_FILES:
            digest = hashlib.sha256((ROOT / "windows-sensor" / name).read_bytes()).hexdigest()
            self.assertIn(digest, inner.lower(), name)
        self.assertIn("-SourceSha256", inner)
        # The transcript goes under Program Files, not the user's stage.
        self.assertIn("Jarvis\\Logs\\sensor-install.log", inner)
        self.assertNotIn("log.txt", script + inner)

    def test_every_grant_made_by_install_has_its_inverse_in_remove(self):
        text = INSTALLER.read_text()
        remove = text[text.index("if ($Remove) {"):text.index("$source = ")]
        for grant, inverse in (("Grant-LogonAsService", "Revoke-LogonAsService"),
                               ("Add-LocalGroupMember", "Remove-GroupMemberSid"),
                               ("Add-AsrExclusion", "Remove-AsrExclusion")):
            with self.subTest(grant=grant):
                self.assertIn(grant, text)
                self.assertIn(inverse, remove)


if __name__ == "__main__":
    unittest.main()

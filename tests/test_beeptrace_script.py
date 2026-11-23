"""The elevated Beep() trace job and the hook's inference, in Windows PowerShell 5.1.

The job needs administrator for its ETW session, so its functions and its
compiled helper are loaded and exercised unelevated: the helper must compile,
its canary must open the Beep device silently (no IOCTL, so no tone), and an
unelevated start must come back as a reason, never an exception. The run's
safety order (nothing deleted before the inventory holding it is written; the
session stopped when the kernel filter is not applied) is checked on the
source. The hook's foreground inference is compiled and run on a real process
tree.
"""

import base64
import json
import re
import shutil
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "jarvis/platform/win/beeptrace.ps1"
HOOK = ROOT / "jarvis/platform/win/inputhook.ps1"
POWERSHELL, WSLPATH = shutil.which("powershell.exe"), shutil.which("wslpath")


def winpath(path):
    return subprocess.run([WSLPATH, "-w", str(path)], capture_output=True, text=True,
                          check=True).stdout.strip()


def ps(body, script=SCRIPT, source_var="$traceSrc", timeout=120):
    """Run `body` with the script's functions defined and its C# compiled."""
    load = (
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$e=$null;"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{winpath(script)}',[ref]$null,[ref]$e);"
        "if($e){throw ($e|%{$_.Message})};"
        "foreach($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)){"
        " . ([scriptblock]::Create($f.Extent.Text)) };$sigCache=@{};"
        "$a=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and "
        f"$n.Left.Extent.Text -eq '{source_var}'}},$true)|Select -First 1;"
        ". ([scriptblock]::Create($a.Extent.Text));"
        f"Add-Type -TypeDefinition {source_var};"
    )
    encoded = base64.b64encode((load + body).encode("utf-16le")).decode("ascii")
    # WSL interop launches fail transiently under load (UtilAcceptVsock
    # accept4 110, seen 2026-11-03); that is the host, not the script.
    for attempt in range(3):
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, text=True, errors="replace", timeout=timeout, cwd="/")
        if "UtilAcceptVsock" not in r.stderr:
            break
        time.sleep(5 * (attempt + 1))
    if r.returncode:
        raise AssertionError(r.stderr or r.stdout)
    return json.loads(r.stdout.replace("\r", "").strip().splitlines()[-1])


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class TraceHelperTests(unittest.TestCase):
    def test_compiles_opens_the_device_silently_and_refuses_cleanly_unelevated(self):
        out = ps("$c=[JarvisBeepTrace]::Canary();"
                 "$w=[JarvisBeepTrace]::Start('JarvisBeepTraceTest',\"$env:TEMP\\jbt-test.etl\",4,"
                 "[Guid]'edd08927-9cc4-4e65-b970-c2560fb5c289',0x80,12,'FileName','\\Device\\Beep');"
                 "@{canary=$c;why=$w;op=[JarvisBeepTrace]::LastOp;"
                 "running=([JarvisBeepTrace]::QueryStatus('JarvisBeepTraceTest') -eq 0)}|ConvertTo-Json -Compress")
        self.assertEqual(out["canary"], 0)
        # Built both filters (the manifest lookup and the payload filter
        # work unelevated); only the session itself needs administrator.
        self.assertEqual(out["op"], "is")
        self.assertIn("could not start (5)", out["why"])
        self.assertFalse(out["running"])

    def test_canary_check(self):
        out = ps("$s=[pscustomobject]@{canary=[pscustomobject]@{pid=42;ms=1000000}};"
                 "$hit=@(@{pid=42;ms=1004000});$miss=@(@{pid=42;ms=1020000},@{pid=7;ms=1000000});"
                 "@{seen=(Test-Canary $s $hit);missing=(Test-Canary $s $miss);"
                 "none=($null -eq (Test-Canary ([pscustomobject]@{canary=$null}) $hit))}|ConvertTo-Json -Compress")
        self.assertEqual(out, {"seen": True, "missing": False, "none": True})

    def test_inventory_is_deduplicated_windowed_and_bounded(self):
        out = ps("$old=@([pscustomobject]@{pid=1;ms=1000},[pscustomobject]@{pid=2;ms=90000000});"
                 "$new=@([pscustomobject]@{pid=2;ms=90000000},[pscustomobject]@{pid=3;ms=90000500},"
                 "[pscustomobject]@{pid=4;ms=90000600});"
                 "$m=Merge-Rows $old $new 90001000 86400000 2;"
                 "@{pids=@($m.rows|%{$_.pid});dropped=$m.dropped}|ConvertTo-Json -Compress")
        # pid 1 is older than 24 h; pid 2 is not doubled; the newest two are kept, oldest first.
        self.assertEqual(out, {"pids": [3, 4], "dropped": 1})

    def test_an_open_of_any_other_file_is_a_breach(self):
        out = ps("function ev($n){$x=[pscustomobject]@{ProcessId=17760;TimeCreated=[datetime]'2026-11-03T13:39:37Z'};"
                 "$x|Add-Member ScriptMethod ToXml ([scriptblock]::Create(\"'<Event><EventData><Data Name=\"\"FileName\"\">$n</Data></EventData></Event>'\"));$x};"
                 "$a=Read-Open (ev '\\Device\\Beep') '\\Device\\Beep';"
                 "$b=Read-Open (ev '\\Device\\HarddiskVolume3\\x.txt') '\\Device\\Beep';"
                 "@{a=$a.beep;b=$b.beep;pid=$a.pid}|ConvertTo-Json -Compress")
        self.assertEqual(out, {"a": True, "b": False, "pid": 17760})


class RunOrderTests(unittest.TestCase):
    """Checked on the source: the job's safety order."""

    @classmethod
    def setUpClass(cls):
        cls.src = SCRIPT.read_text(encoding="utf-8")
        cls.body = cls.src.split("# --- the run", 1)[1]

    def test_parsed_files_are_removed_only_after_the_inventory_is_written(self):
        self.assertLess(self.body.index("Move-Item -LiteralPath \"$Inv.new\""),
                        self.body.index("foreach ($f in $done) { Remove-Item"))

    def test_an_unapplied_filter_stops_the_session_at_once(self):
        block = self.body.split("if ($size -gt $BreachBytes) {", 1)[1].split("}", 1)[0]
        self.assertIn("StopSession($Name)", block)
        self.assertIn("$mode = 'refused'", block)

    def test_bounded_file_and_inventory(self):
        self.assertRegex(self.src, r"\$CapMB = [1-8]\n")
        self.assertRegex(self.src, r"\$MaxRows = \d{3}\n")
        self.assertIn("$MaxPending = 3", self.src)

    def test_never_sends_a_beep_ioctl_or_reads_content(self):
        helper = self.src.split("$traceSrc = @'", 1)[1].split("'@", 1)[0]
        self.assertNotIn("DeviceIoControl", helper)
        self.assertNotIn("NtDeviceIoControlFile", helper)
        self.assertNotRegex(self.src, re.compile(r"CommandLine|MainWindowTitle", re.I))


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class LikelySourceTests(unittest.TestCase):
    def test_children_are_candidates_and_console_hosts_are_not(self):
        out = ps("$t=[JarvisSound.Listener].Assembly.GetType('JarvisSound.BeepCallers');"
                 "$m=$t.GetMethod('Likely',[Reflection.BindingFlags]'NonPublic,Static');"
                 "$alone=$m.Invoke($null,@([uint32]$PID));"
                 "$p=Start-Process cmd.exe -ArgumentList '/c ping -n 6 127.0.0.1 >nul' -WindowStyle Hidden -PassThru;"
                 "Start-Sleep -Milliseconds 700;"
                 "$withChild=$m.Invoke($null,@([uint32]$PID));"
                 "$gone=$m.Invoke($null,@([uint32]4000000000));"
                 "$n=$t.GetMethod('NotCaller',[Reflection.BindingFlags]'NonPublic,Static');"
                 "$hosts=@('conhost.exe','OpenConsole.exe','WindowsTerminal.exe','wsl.exe','ubuntu2404.exe','powershell.exe')|%{$n.Invoke($null,@([string]$_))};"
                 "try{$p.Kill()}catch{};"
                 "@{alone=$alone;child=$withChild;gone=$gone;self=$PID;cmd=$p.Id;hosts=$hosts}|ConvertTo-Json -Compress",
                 script=HOOK, source_var="$soundSrc")
        # Nothing under it: the window's own process is the one candidate.
        self.assertIn(f'"likely_pid":{out["self"]},"likely_n":1', out["alone"])
        # Programs under it are the candidates (cmd and the ping it runs, two
        # levels down), so none is named; its console host is not one, and the
        # window's own process no longer is.
        self.assertIn('"likely_pid":0,"likely_n":2', out["child"])
        self.assertIn(f'cmd:{out["cmd"]}', out["child"])
        self.assertIn("PING:", out["child"].upper())
        self.assertNotIn("conhost", out["child"].lower())
        self.assertNotIn(f':{out["self"]}"', out["child"])
        self.assertEqual(out["gone"], "")
        self.assertEqual(out["hosts"], [True, True, True, True, True, False])


if __name__ == "__main__":
    unittest.main()

"""The elevated input-audit job, executed in Windows PowerShell 5.1.

The job itself needs elevation and a live ETW session, so its functions are
loaded through the PowerShell parser and exercised on their own; the order of
the run (nothing deleted before the inventory holding it is written) is
checked on the source. 2026-10-31: a killed run lost the post-logon trace
every time, because the next run deleted it unparsed.
"""

import base64
import json
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "jarvis/platform/win/inputaudit.ps1"
POWERSHELL, WSLPATH = shutil.which("powershell.exe"), shutil.which("wslpath")


def winpath(path):
    return subprocess.run([WSLPATH, "-w", str(path)], capture_output=True, text=True,
                          check=True).stdout.strip()


def ps(body, timeout=90):
    """Run `body` with every function of the job defined, nothing of the run."""
    load = (
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{winpath(SCRIPT)}',[ref]$null,[ref]$null);"
        "foreach($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)){"
        " . ([scriptblock]::Create($f.Extent.Text)) };$sigCache=@{};"
    )
    encoded = base64.b64encode((load + body).encode("utf-16le")).decode("ascii")
    for _attempt in range(2):
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                           capture_output=True, text=True, errors="replace", timeout=timeout, cwd="/")
        if "UtilAcceptVsock" not in r.stderr:
            break
        time.sleep(5)
    if r.returncode:
        raise AssertionError(r.stderr or r.stdout)
    return json.loads(r.stdout.replace("\r", "").strip().splitlines()[-1])


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class QueueTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="inputaudit-", dir=Path.home() / ".cache"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.w = winpath(self.dir)

    def files(self, sizes):
        for i, size in enumerate(sizes):
            (self.dir / f"session.pending-{i:019d}.etl").write_bytes(b"x" * size)

    def select(self, tries="@{}", max_files=4, max_bytes=1 << 30, max_tries=3):
        return ps(
            f"$s=Select-Queue @(Get-ChildItem -LiteralPath '{self.w}' -Filter 'session.pending-*.etl') "
            f"{tries} {max_files} {max_bytes} {max_tries};"
            "[pscustomobject]@{keep=@($s.keep|%{$_.Name});"
            "drop=@($s.drop|%{$_.file.Name+':'+$_.reason})}|ConvertTo-Json -Compress")

    def test_queue_keeps_the_newest_within_the_file_bound(self):
        self.files([1] * 6)
        r = self.select(max_files=4)
        self.assertEqual(r["keep"], [f"session.pending-{i:019d}.etl" for i in (2, 3, 4, 5)])
        self.assertEqual(r["drop"], [f"session.pending-{i:019d}.etl:bound" for i in (0, 1)])

    def test_byte_bound_drops_oldest_but_never_the_last_file(self):
        self.files([100, 100, 100])
        r = self.select(max_bytes=150)
        self.assertEqual(r["keep"], ["session.pending-0000000000000000002.etl"])
        r = self.select(max_bytes=10)          # one file over the bound is still parsed
        self.assertEqual(len(r["keep"]), 1)

    def test_a_file_that_keeps_killing_the_run_is_dropped_and_named(self):
        self.files([1, 1])
        r = self.select(tries="@{'session.pending-0000000000000000000.etl'=3}")
        self.assertEqual(r["drop"], ["session.pending-0000000000000000000.etl:retries"])
        self.assertEqual(r["keep"], ["session.pending-0000000000000000001.etl"])
        r = self.select(tries="@{'session.pending-0000000000000000000.etl'=2}")
        self.assertEqual(r["drop"], [])         # below the limit it is retried

    def test_closed_trace_is_queued_never_overwritten(self):
        (self.dir / "session.etl").write_bytes(b"a")
        r = ps(f"Add-ToQueue '{self.w}' '{self.w}\\session.etl';"
               f"Set-Content -LiteralPath '{self.w}\\session.etl' -Value b -NoNewline;"
               f"Add-ToQueue '{self.w}' '{self.w}\\session.etl';"
               f"Add-ToQueue '{self.w}' '{self.w}\\missing.etl';"
               f"@(Get-ChildItem -LiteralPath '{self.w}' | Sort-Object Name | %{{ $_.Name+'='+(Get-Content -LiteralPath $_.FullName -Raw) }})|ConvertTo-Json -Compress")
        self.assertEqual(len(r), 2)
        self.assertTrue(all(re.fullmatch(r"session\.pending-\d{19}\.etl=.", x) for x in r), r)
        self.assertEqual([x[-1] for x in r], ["a", "b"])      # name order is age order

    def test_attempt_counts_survive_and_a_corrupt_file_reads_empty(self):
        r = ps(f"$p='{self.w}\\attempts.json';$t=@{{x=2}};Save-Tries $p $t;"
               "$a=Read-Tries $p;Set-Content -LiteralPath $p -Value '{not json';$b=Read-Tries $p;"
               "[pscustomobject]@{a=$a['x'];b=$b.Count}|ConvertTo-Json -Compress")
        self.assertEqual(r, {"a": 2, "b": 0})


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class IdentityAndBucketTests(unittest.TestCase):
    def test_creator_is_the_newest_creation_at_or_before_the_event(self):
        r = ps("$t0=[datetime]'2026-10-31 19:00:00';"
               "$c=@(@{time=$t0;image='old.exe'},@{time=$t0.AddMinutes(5);image='mid.exe'},@{time=$t0.AddMinutes(9);image='reuse.exe'});"
               "[pscustomobject]@{a=(Find-Creator $c $t0.AddMinutes(7)).image;"
               "b=(Find-Creator $c $t0.AddSeconds(-30));"
               "c=(Find-Creator @() $t0)}|ConvertTo-Json -Compress")
        self.assertEqual(r, {"a": "mid.exe", "b": None, "c": None})

    def test_buckets_fold_per_minute_and_stop_at_the_cap(self):
        r = ps("$b=@{};$t=[datetime]'2026-10-31 19:00:05';"
               "$mk={param($s,$calls) @{kind='poll';type='getasynckeystate';pid=42;when=$t.AddSeconds($s);calls=$calls;ms=1}};"
               "$ok=@((Add-ToBucket $b (& $mk 0 5) 2),(Add-ToBucket $b (& $mk 20 9) 2),"
               "(Add-ToBucket $b (& $mk 70 1) 2),(Add-ToBucket $b (& $mk 200 1) 2));"
               "$first=$b.Values|Sort-Object {$_.first}|Select-Object -First 1;"
               "[pscustomobject]@{ok=$ok;n=$b.Count;count=$first.count;calls=$first.calls;"
               "span=$first.last-$first.first}|ConvertTo-Json -Compress")
        self.assertEqual(r["ok"], [True, True, True, False])   # 4th would be a 3rd bucket
        self.assertEqual(r["n"], 2)
        self.assertEqual((r["count"], r["calls"], r["span"]), (2, 9, 20))


@unittest.skipUnless(POWERSHELL and WSLPATH, "Windows PowerShell unavailable")
class ParseSectionTests(unittest.TestCase):
    """The run's own parse section, with Get-WinEvent replaced by a fake."""

    def test_bad_event_is_counted_and_unreadable_file_is_kept(self):
        d = Path(tempfile.mkdtemp(prefix="inputaudit-", dir=Path.home() / ".cache"))
        self.addCleanup(shutil.rmtree, d, True)
        for name in ("session.pending-0000000000000000001.etl", "session.pending-0000000000000000002.etl"):
            (d / name).write_bytes(b"x")
        src = SCRIPT.read_text(encoding="utf-8")
        section = src[src.index("# --- parse the queued files"):src.index("# --- who registered")]
        fake = r"""
function Get-WinEvent { [CmdletBinding()] param($Path, $LogName, [switch]$Oldest, $FilterXPath)
  if ($Path -like '*0002.etl') { throw 'the file is corrupt' }
  $mk = { param($id, $procId, $xml)
    $o = [pscustomobject]@{ Id = $id; ProcessId = $procId; TimeCreated = [datetime]'2026-10-31 19:10:00' }
    $o | Add-Member ScriptMethod ToXml ([scriptblock]::Create("'$xml'")) -PassThru }
  & $mk 1002 11 '<Event><EventData><Data Name="FilterType">13</Data><Data Name="pstrLib"></Data><Data Name="ReturnValue">1</Data></EventData></Event>'
  $bad = [pscustomobject]@{ Id = 1002; ProcessId = 12; TimeCreated = [datetime]'2026-10-31 19:10:00' }
  $bad | Add-Member ScriptMethod ToXml { throw 'malformed' } -PassThru
  & $mk 1000 13 '<Event><EventData></EventData></Event>'
}
"""
        body = (fake + f"$Dir='{winpath(d)}';$TriesFile=Join-Path $Dir 'attempts.json';$tries=@{{}};"
                "$CapMB=128;$MaxBuckets=5000;$BudgetSec=150;$WantIds='*';"
                "$sel=@{keep=@(Get-ChildItem -LiteralPath $Dir -Filter 'session.pending-*.etl'|Sort-Object Name)};"
                "$clock=[Diagnostics.Stopwatch]::StartNew();" + section +
                "[pscustomobject]@{parsed=$parsed;failed=$failed;buckets=$buckets.Count;"
                "done=@($done|%{$_.Name});backlog=$backlog;tries=$tries['session.pending-0000000000000000002.etl']}"
                "|ConvertTo-Json -Compress")
        r = ps(body)
        self.assertEqual(r["parsed"], 3)           # the stream went on past the bad event
        self.assertEqual(r["buckets"], 2)          # hook (pid 11) and winevent (pid 13)
        self.assertEqual(r["failed"], 2)           # one bad event, one unreadable file
        self.assertEqual(r["done"], ["session.pending-0000000000000000001.etl"])
        self.assertEqual(r["backlog"], 1)          # the unreadable file stays queued
        self.assertEqual(r["tries"], 1)            # and its attempt was recorded


class RunOrderTests(unittest.TestCase):
    """The run needs elevation; its ordering invariants are read from the source."""

    def setUp(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))

    def test_no_closed_trace_is_deleted_unparsed(self):
        self.assertNotRegex(self.code, r"Remove-Item\s+\$(Old|Etl)\b")
        self.assertIn("Add-ToQueue $Dir $Old", self.code)
        self.assertEqual(self.code.count("Add-ToQueue $Dir $Etl"), 2)   # both rotation paths

    def test_parsed_files_are_removed_only_after_the_inventory_is_written(self):
        written = self.code.index("Move-Item -LiteralPath \"$Inv.new\" -Destination $Inv")
        removed = self.code.index("foreach ($f in $done)")
        self.assertLess(written, removed)

    def test_an_attempt_is_recorded_before_the_parse_that_may_be_killed(self):
        loop = self.code[self.code.index("foreach ($f in $sel.keep)"):]
        self.assertLess(loop.index("Save-Tries $TriesFile $tries"), loop.index("Get-WinEvent -Path"))

    def test_an_unreadable_file_is_kept_for_retry_not_deleted(self):
        loop = self.code[self.code.index("foreach ($f in $sel.keep)"):self.code.index("$backlog =")]
        self.assertIn("$readOk = $false", loop)
        self.assertIn("if ($readOk) { $done += $f }", loop)
        self.assertNotRegex(loop, r"\n\s*\$done \+= \$f\s*\n")      # never unconditionally
        # each event has its own catch inside the stream
        stream = loop[loop.index("ForEach-Object {"):]
        self.assertLess(stream.index("try {"), stream.index("Read-Registration"))
        self.assertIn("$script:failed++", stream)

    def test_events_are_streamed_and_processes_looked_up_by_id(self):
        self.assertNotIn("@(Get-WinEvent", self.code)
        self.assertNotIn("foreach ($e in (Get-WinEvent", self.code)
        self.assertNotRegex(self.code, r"Get-Process\s+-ErrorAction")   # no full snapshot
        self.assertIn("Get-Process -Id $id", self.code)

    def test_drops_backlog_and_overflow_are_reported(self):
        for field in ("dropped_files", "dropped_retries", "backlog_files", "overflow",
                      "identity_failures"):
            self.assertIn(f"{field} =", self.code)

    def test_no_two_variables_differ_only_by_case(self):
        # PowerShell names are case-insensitive: $Tries (a path) and $tries (a
        # table) were one variable in a draft of this fix, and the run died.
        spellings = {}
        for name in re.findall(r"\$(?:script:)?([A-Za-z_]\w*)", self.code):
            spellings.setdefault(name.lower(), set()).add(name)
        self.assertEqual({k: v for k, v in spellings.items() if len(v) > 1}, {})

    def test_internal_budget_fits_inside_the_broker_limit(self):
        budget = int(re.search(r"\$BudgetSec = (\d+)", self.code).group(1))
        broker = (ROOT / "jarvis-elevated-broker.ps1").read_text(encoding="utf-8")
        limit = int(re.search(r"inputaudit = @\{ script = 'inputaudit.ps1';\s+timeout = (\d+)", broker).group(1))
        # The longest single file measured took 38 s to read; one may start at the budget.
        self.assertLessEqual(budget + 120, limit)


if __name__ == "__main__":
    unittest.main()

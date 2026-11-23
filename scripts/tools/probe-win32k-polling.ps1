<#
.SYNOPSIS
  Re-measure whether Windows logs GetAsyncKeyState polling (Win32k event 1003)
  on this build, with a control that polls at a realistic keylogger rate.

.DESCRIPTION
  The 2026-09-23 probe concluded that 1003 is never emitted. The kernel code
  (EtwTraceGetAsyncKeyState / ReportGetAsyncKeyStateAnomaly) emits 1003 only
  at a key event, for processes whose calls since the previous key event
  divided by the elapsed milliseconds is >= 1. That probe polled at roughly
  0.1 calls/ms, so its silence was not a valid negative. This control polls
  every virtual key (8..255) in a tight loop, which a real polling keylogger
  must also do, and discards every return value: nothing typed is read,
  stored or sent anywhere.

  Run elevated (ETW consumers need it). While it runs, type normally in any
  window for the whole window: the kernel only evaluates the anomaly when a
  key event arrives. The owner must be present; this is not for the scheduler.

  Output: C:\ProgramData\Jarvis\Probe\w32k_poll_result.json with the control
  pid, every 1003 row (pid, MsSinceLastKeyEvent, BackgroundCallCount) and
  whether the control pid was attributed. The session is private to this
  probe; the broker's JarvisInputAudit session is untouched.

.PARAMETER Seconds   Polling window (default 45).
.PARAMETER Keyword   Win32k keyword mask (default 0x400 = AuditApiCalls; 0x1400 adds the
                     mask the Velociraptor artifact uses, to test whether 1003 needs it).
#>
[CmdletBinding()]
param([int]$Seconds = 45, [string]$Keyword = '0x400')
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole('Administrators')) {
    throw 'run elevated: ETW consumers need an administrator token' }
$dir = 'C:\ProgramData\Jarvis\Probe'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
$name = 'JarvisPollProbe'; $etl = Join-Path $dir 'poll_probe.etl'
& logman.exe stop $name -ets *> $null
Remove-Item $etl -ErrorAction SilentlyContinue
& logman.exe start $name -p Microsoft-Windows-Win32k $Keyword 0x5 -o $etl -bs 64 -nb 4 16 -ets | Out-Null
if ($LASTEXITCODE -ne 0) { throw "logman start failed ($LASTEXITCODE)" }

# The control: a separate process so the event's PID attribution is tested.
$control = @'
param([int]$Seconds)
Add-Type -Namespace P -Name K -MemberDefinition '[DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);'
$end = [DateTime]::UtcNow.AddSeconds($Seconds); $calls = [int64]0
while ([DateTime]::UtcNow -lt $end) {
    for ($k = 8; $k -lt 256; $k++) { [void][P.K]::GetAsyncKeyState($k); $calls++ }   # value discarded
    Start-Sleep -Milliseconds 1
}
Write-Output $calls
'@
$cpath = Join-Path $dir 'poll_control.ps1'; Set-Content -LiteralPath $cpath -Value $control -Encoding ASCII
$started = Get-Date
$p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$cpath,'-Seconds',$Seconds) `
     -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dir 'poll_control.out')
Write-Host "control pid $($p.Id): type in any window for $Seconds s ..."
$p.WaitForExit()
Start-Sleep -Seconds 2
& logman.exe stop $name -ets | Out-Null
$calls = [string](Get-Content (Join-Path $dir 'poll_control.out') -ErrorAction SilentlyContinue | Select-Object -Last 1)

$rows = @(); $byId = @{}
foreach ($e in @(Get-WinEvent -Path $etl -Oldest -ErrorAction SilentlyContinue)) {
    $byId[[string]$e.Id] = 1 + [int]$byId[[string]$e.Id]
    if ($e.Id -ne 1003) { continue }
    $d = @{}; foreach ($f in @(([xml]$e.ToXml()).Event.EventData.Data)) { if ($f) { $d[[string]$f.Name] = [string]$f.'#text' } }
    $rows += [pscustomobject]@{ time = $e.TimeCreated.ToString('o'); header_pid = $e.ProcessId; fields = $d }
}
$hit = @($rows | Where-Object { $_.header_pid -eq $p.Id -or $_.fields['PID'] -eq [string]$p.Id }).Count
# The broker reads its trace with this event-id filter; prove it returns the same 1003 count.
$sw = [Diagnostics.Stopwatch]::StartNew()
$filtered = @(Get-WinEvent -Path $etl -Oldest -FilterXPath "*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1003)]]" -ErrorAction SilentlyContinue)
$filteredMs = [int]$sw.ElapsedMilliseconds
$filtered1003 = @($filtered | Where-Object { $_.Id -eq 1003 }).Count
$out = [ordered]@{
    build = [Environment]::OSVersion.Version.ToString(); keyword = $Keyword; seconds = $Seconds
    control_pid = $p.Id; control_calls = $calls
    control_calls_per_ms = if ($calls) { [math]::Round([double]$calls / ($Seconds * 1000), 2) } else { $null }
    events_by_id = $byId; polling_rows = $rows; control_attributed = ($hit -gt 0)
    xpath_filtered_total = $filtered.Count; xpath_filtered_1003 = $filtered1003; xpath_filter_ms = $filteredMs
    xpath_filter_matches = ($filtered1003 -eq $rows.Count)
    verdict = if ($hit -gt 0) { '1003 fires on this build; the 2026-09-23 negative was a probe artifact' }
              elseif ($rows.Count) { '1003 fires but not for the control; check pid attribution' }
              else { 'no 1003 at this rate; were keys typed during the window?' }
}
$out | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'w32k_poll_result.json') -Encoding UTF8
Remove-Item $cpath, (Join-Path $dir 'poll_control.out') -ErrorAction SilentlyContinue
$out | ConvertTo-Json -Depth 6

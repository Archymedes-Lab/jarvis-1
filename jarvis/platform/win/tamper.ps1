$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# Read-only evidence for the tamper audit (collectors/process/tamper.py).
# Every source reports ok/error separately: an unreadable log is "unknown",
# never "nothing happened". All queries are bounded by time and MaxEvents;
# message text is truncated. Classification happens in Python, not here.
$o = [ordered]@{}
$day = (Get-Date).AddHours(-24)
$week = (Get-Date).AddDays(-7)

function T($s, $n = 700) {
  if ($null -eq $s) { return '' }
  $x = [string]$s
  if ($x.Length -gt $n) { return $x.Substring(0, $n) }
  return $x
}

function Ev($filter, $max, $match) {
  $r = @(); $err = $null
  try { $r = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $max -ErrorAction Stop) }
  catch {
    # "No events were found" is a clean, successful answer.
    if ($_.Exception.Message -notmatch 'No events were found') { $err = $_.Exception.Message }
  }
  if ($match) { $r = @($r | Where-Object { $_.Message -match $match }) }
  [pscustomobject]@{
    ok = ($null -eq $err)
    error = (T $err 200)
    capped = ($r.Count -ge $max)
    events = @($r | ForEach-Object {
      [pscustomobject]@{
        t = $_.TimeCreated.ToUniversalTime().ToString('o')
        id = [int]$_.Id
        provider = [string]$_.ProviderName
        msg = (T $_.Message)
      } })
  }
}

$defLog = 'Microsoft-Windows-Windows Defender/Operational'
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'

$o.defender = Ev @{ LogName = $defLog; Id = 5001, 5004, 5007, 5010, 5012, 5013; StartTime = $day } 400 $null
$o.sysmon = Ev @{ LogName = $sysmonLog; Id = 4, 16, 255; StartTime = $day } 300 $null
$svc = 'Sysmon|Windows Event Log|Microsoft Defender|Windows Defender|JarvisNativeSensor|JarvisSensor'
$o.app_crashes = Ev @{ LogName = 'Application'; Id = 1000; StartTime = $day } 200 'MsMpEng\.exe|MpDefenderCoreService|Sysmon(64)?\.exe|NisSrv\.exe|SecurityHealthService|jarvis'
$o.services = Ev @{ LogName = 'System'; Id = 7034, 7036, 7040; StartTime = $day } 4000 $svc
$o.system_clear = Ev @{ LogName = 'System'; Id = 104; StartTime = $week } 50 $null
# Reading Security usually needs administrator or Event Log Readers.
$o.security = Ev @{ LogName = 'Security'; Id = 1100, 1102; StartTime = $week } 50 $null

# Who wrote each Defender setting: Sysmon registry events (12/13/14) in a
# short window before each 5007, restricted to Defender keys. Windows are
# merged and capped; a missing writer is reported as unknown in Python.
$writers = @(); $wErr = $null; $windows = @()
$changes = @($o.defender.events | Where-Object { $_.id -eq 5007 } | Select-Object -First 30)
foreach ($c in $changes) {
  $t = [datetime]::Parse($c.t).ToUniversalTime()
  $windows += , @($t.AddSeconds(-20), $t.AddSeconds(5))
}
$windows = @($windows | Sort-Object { $_[0] })
$merged = @()
foreach ($w in $windows) {
  if ($merged.Count -and $w[0] -le $merged[-1][1]) {
    if ($w[1] -gt $merged[-1][1]) { $merged[-1][1] = $w[1] }
  } else { $merged += , @($w[0], $w[1]) }
}
foreach ($w in ($merged | Select-Object -First 15)) {
  $a = $w[0].ToString('yyyy-MM-ddTHH:mm:ss.fffZ'); $b = $w[1].ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $x = "*[System[(EventID=12 or EventID=13 or EventID=14) and TimeCreated[@SystemTime>='$a' and @SystemTime<='$b']]]"
  try {
    Get-WinEvent -LogName $sysmonLog -FilterXPath $x -MaxEvents 500 -ErrorAction Stop | ForEach-Object {
      $d = @{}
      ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
      if ([string]$d.TargetObject -match 'Windows Defender') {
        $writers += [pscustomobject]@{
          t = $_.TimeCreated.ToUniversalTime().ToString('o'); id = [int]$_.Id
          image = (T $d.Image 300); target = (T $d.TargetObject 400); details = (T $d.Details 200)
        }
      }
    }
  } catch {
    if ($_.Exception.Message -notmatch 'No events were found') { $wErr = (T $_.Exception.Message 200) }
  }
}
$o.writers = [pscustomobject]@{ ok = ($null -eq $wErr); error = $wErr; windows = $merged.Count; events = $writers }

# ETW autologger sessions that feed the event logs and Defender. Start=0 on a
# session, or Enabled=0 on its providers, silences it from the next boot.
$al = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
$o.autologgers = @('EventLog-Application', 'EventLog-System', 'EventLog-Security',
                   'DefenderApiLogger', 'DefenderAuditLogger') | ForEach-Object {
  $p = Join-Path $al $_
  if (Test-Path $p) {
    $s = (Get-ItemProperty $p -Name Start).Start
    $off = @(Get-ChildItem $p | Where-Object {
      $e = (Get-ItemProperty $_.PSPath -Name Enabled).Enabled
      $null -ne $e -and [int]$e -eq 0 } | ForEach-Object { $_.PSChildName })
    [pscustomobject]@{ name = $_; exists = $true; readable = $true
                       start = if ($null -eq $s) { -1 } else { [int]$s }; disabled = $off }
  } else {
    [pscustomobject]@{ name = $_; exists = $false; readable = (Test-Path $al); start = -1; disabled = @() }
  }
}

$payload = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))

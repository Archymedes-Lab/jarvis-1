# jarvis: winblocks reader
# Reads what Windows Security already recorded about actions it blocked or would have
# blocked (attack surface reduction 1121/1122, controlled folder access 1123/1124) in
# Microsoft-Windows-Windows Defender/Operational. Read-only: no setting is changed, no
# exclusion is added, nothing is unblocked. Returns grouped counts, not raw events.
$ErrorActionPreference = 'Stop'
$o = @{ groups=@(); read=0; more=$false; since_hours=24; errors=@() }
try {
  $since = (Get-Date).AddHours(-24)
  $events = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1121,1122,1123,1124; StartTime=$since } -MaxEvents 600 -ErrorAction SilentlyContinue)
  $o.read = $events.Count
  if ($events.Count -ge 600) { $o.more = $true }
  $by = @{}
  foreach ($e in $events) {
    $d = @{}
    try { foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' } } catch { continue }
    $rule = ([string]$d['ID']).ToLower()
    $blocked = [string]$d['Path']
    $by_proc = [string]$d['Process Name']
    # Argus's own PowerShell payloads carry a marker on their first line. When one of
    # them opened the file (to hash or check its signature), that is a read, not a launch.
    $own = [bool](([string]$d['Parent Commandline']) -match 'jarvis-[a-z]+-payload|# jarvis: ')
    $key = "$($e.Id)|$rule|$blocked|$by_proc|$own"
    if (-not $by.ContainsKey($key)) {
      $by[$key] = @{ id=[int]$e.Id; rule=$rule; path=$blocked; process=$by_proc; own_check=$own; count=0
                     last=$e.TimeCreated.ToUniversalTime().ToString('o') }
    }
    $by[$key].count++
  }
  $o.groups = @($by.Values | Sort-Object { $_.count } -Descending | Select-Object -First 80)
  if ($by.Count -gt 80) { $o.more = $true }
} catch { $o.errors += ('read failed: ' + $_.Exception.GetType().Name) }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 4 -Compress)))

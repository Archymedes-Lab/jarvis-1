# Read-only Sysmon pressure evidence for the elevated JARVIS broker.
# Returns aggregate counts only: no registry values, command lines, or raw events.
#
# Reads through EventLogReader and positional Properties rather than
# Get-WinEvent: Get-WinEvent renders every event's message text, which took
# 230s for 14.6k events and outran the broker's 120s job timeout. The reader
# path measured 2.3s for the same query. Sysmon 12/13/14 share the layout
# RuleName(0), EventType, UtcTime, ProcessGuid, ProcessId, Image(5), ...

# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'Stop'
$MaxEvents = 200000
$BudgetSeconds = 90
$result = [ordered]@{
  ok = $false
  boot = ''
  retained_registry_events = 0
  by_rule = @()
  by_image = @()
  drops = @()
  truncated = $false
  error = ''
}

$reader = $null
try {
  $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
  $result.boot = $boot.ToString('o')
  $xpath = "*[System[(EventID=12 or EventID=13 or EventID=14 or EventID=255) and " +
           "TimeCreated[@SystemTime>='" + $boot.ToString('o') + "']]]"
  $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
    'Microsoft-Windows-Sysmon/Operational',
    [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
  $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $seen = 0
  $rules = @{}
  $images = @{}
  while ($null -ne ($event = $reader.ReadEvent())) {
    try {
      $seen++
      if ($event.Id -eq 255) {
        # UtcTime | ID | Description; the description carries the counts.
        $text = (@($event.Properties | ForEach-Object { [string]$_.Value }) -join ' ')
        $counts = [ordered]@{}
        foreach ($match in [regex]::Matches($text, '([A-Za-z][A-Za-z0-9]+):(\d+)')) {
          if ($match.Groups[1].Value -ne 'DriverQueueSize') {
            $counts[$match.Groups[1].Value] = [int64]$match.Groups[2].Value
          }
        }
        $queue = [regex]::Match($text, 'DriverQueueSize:\s*(\d+)')
        if ($result.drops.Count -lt 20) {
          $result.drops += [ordered]@{
            at = $event.TimeCreated.ToUniversalTime().ToString('o')
            counts = $counts
            driver_queue_size = if ($queue.Success) { [int64]$queue.Groups[1].Value } else { $null }
          }
        }
      } else {
        $result.retained_registry_events++
        $props = $event.Properties
        $rule = if ($props.Count -gt 0 -and [string]$props[0].Value) { [string]$props[0].Value } else { '(none)' }
        $path = if ($props.Count -gt 5) { [string]$props[5].Value } else { '' }
        $image = if ($path) { [IO.Path]::GetFileName($path) } else { '(unknown)' }
        $rules[$rule] = 1 + [int64]($rules[$rule])
        $images[$image] = 1 + [int64]($images[$image])
      }
    } finally {
      $event.Dispose()
    }
    if ($seen -ge $MaxEvents -or $clock.Elapsed.TotalSeconds -ge $BudgetSeconds) {
      $result.truncated = $true
      break
    }
  }
  $result.by_rule = @($rules.GetEnumerator() | Sort-Object Value -Descending |
    Select-Object -First 20 | ForEach-Object {
      [ordered]@{ name = [string]$_.Key; count = [int64]$_.Value }
    })
  $result.by_image = @($images.GetEnumerator() | Sort-Object Value -Descending |
    Select-Object -First 20 | ForEach-Object {
      [ordered]@{ name = [string]$_.Key; count = [int64]$_.Value }
    })
  $result.ok = $true
} catch {
  $result.error = [string]$_.Exception.Message
} finally {
  if ($null -ne $reader) { $reader.Dispose() }
}

$json = $result | ConvertTo-Json -Depth 7 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

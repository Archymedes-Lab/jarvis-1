
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$o.bootTime = $boot.ToString('o')

# --- what Task Scheduler launched since boot (129 = created task process) ---
$o.taskRuns = @(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=129,100,200;
        StartTime=$boot } -MaxEvents 200 |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      time = $_.TimeCreated.ToString('o')
      id   = $_.Id
      task = [string]$d['TaskName']
      path = [string]$d['Path']
      cmd  = [string]$d['ActionName']
    } })

# Event 200 records the action that actually started, unlike 100/129, which
# only name the task/process. A full since-boot window is required before a
# signer can explain a task run; a capped result cannot prove all actions.
$actionEvents = @(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=200;
        StartTime=$boot } -MaxEvents 1000)
$o.taskActionsComplete = $actionEvents.Count -gt 0 -and $actionEvents.Count -lt 1000
$o.taskActions = @($actionEvents | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ task=[string]$d['TaskName']; action=[string]$d['ActionName'] }
  })

# --- every autostart entry, with enough detail to tell if it shows a window ---
# The executed image is captured separately from the full command line. What an
# entry is allowed to run is decided by that image, not by any path that happens
# to appear later on the line -- `cmd.exe /c del "<appdata path>"` executes
# System32\cmd.exe and merely names a file to delete, which is a very different
# thing from launching something out of AppData.
$items = New-Object System.Collections.ArrayList
function Resolve-Exe([string]$cmd) {
  if (-not $cmd) { return '' }
  $c = $cmd.Trim()
  if ($c -match '^\s*"([^"]+)"') { $exe = $matches[1] }
  else { $exe = ($c -split '\s+')[0] }
  $exe = [Environment]::ExpandEnvironmentVariables($exe)
  if ($exe -and -not [IO.Path]::IsPathRooted($exe)) {
    $w = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue |
         Select-Object -First 1
    if ($w) { $exe = $w.Source }
  }
  return $exe
}
$sigCache = @{}
function Get-Sig([string]$exe) {
  if (-not $exe) { return 'unknown|' }
  if ($sigCache.ContainsKey($exe)) { return $sigCache[$exe] }
  $r = 'unknown|'
  if (Test-Path -LiteralPath $exe -PathType Leaf) {
    $s = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction SilentlyContinue
    if ($s) {
      $subj = ''
      if ($s.SignerCertificate) {
        $subj = ($s.SignerCertificate.Subject -replace '^CN=', '') -replace ',.*$', ''
      }
      $r = "$($s.Status)|$subj"
    }
  } else { $r = 'missing|' }
  $sigCache[$exe] = $r
  return $r
}
foreach ($k in @(
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
  $p = Get-ItemProperty -Path $k
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
    ForEach-Object { [void]$items.Add([pscustomobject]@{
      kind='run-key'; name=$_.Name; cmd=[string]$_.Value; where=$k
      exe=(Resolve-Exe ([string]$_.Value)) }) } }
}
Get-ChildItem -File -Path @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") |
  ForEach-Object { [void]$items.Add([pscustomobject]@{
    kind='startup-folder'; name=$_.Name; cmd=$_.FullName; where=$_.DirectoryName
    exe=$_.FullName }) }
Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and
    ($_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Boot|Logon' }) } |
  ForEach-Object {
    $t = $_
    $a = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
    $x = ($t.Actions | ForEach-Object { $_.Execute } | Where-Object { $_ } |
          Select-Object -First 1)
    [void]$items.Add([pscustomobject]@{
      kind='boot-task'; name=$t.TaskName; cmd=$a; where=$t.TaskPath
      exe=(Resolve-Exe ([string]$x)) }) }
foreach ($it in $items) {
  $parts = (Get-Sig ([string]$it.exe)) -split '\|', 2
  Add-Member -InputObject $it -NotePropertyName sig    -NotePropertyValue $parts[0]
  Add-Member -InputObject $it -NotePropertyName signer -NotePropertyValue $parts[1]
}
$o.autostart = @($items)

# --- things that crashed or errored around boot, another cause of a flash ---
$o.crashes = @(Get-WinEvent -FilterHashtable @{
        LogName='Application'; Level=1,2; StartTime=$boot } -MaxEvents 60 |
  ForEach-Object { [pscustomobject]@{
      time=$_.TimeCreated.ToString('o'); src=[string]$_.ProviderName
      msg=(($_.Message -replace "`r`n",' ') -replace '\s+',' ') } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

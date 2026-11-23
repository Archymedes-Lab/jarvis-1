# jarvis: psscript reader
# Reads PowerShell script-block records (event 4104) that Windows already wrote to
# Microsoft-Windows-PowerShell/Operational. Read-only: it changes no setting, enables
# no logging and writes no file. The request arrives on stdin as JSON:
#   after      last record id already read (0 = start at the oldest record kept)
#   own        SHA-256 (hex) of scripts the monitor launched itself
#   max_events records read per pass          max_blocks  foreign blocks returned
#   max_text   characters of one block's text  max_total   characters of text in all
# Script text of the monitor's own scripts never leaves this process: only blocks that
# are not its own are returned, capped, for rule matching in memory.
$ErrorActionPreference = 'Stop'
$o = @{ enabled=$null; log=$null; first=0; last=0; read=0; own=0; blocks=@(); more=$false; errors=@() }
try {
  $req = $jarvisReq | ConvertFrom-Json
  $after = [int64]$req.after
  $maxEvents = [Math]::Min([Math]::Max([int]$req.max_events, 1), 5000)
  $maxBlocks = [Math]::Min([Math]::Max([int]$req.max_blocks, 1), 500)
  $maxText = [Math]::Min([Math]::Max([int]$req.max_text, 256), 65536)
  $maxTotal = [Math]::Min([Math]::Max([int]$req.max_total, 1024), 4194304)
  $ownSet = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($h in @($req.own)) { if ($h -match '^[0-9a-f]{64}$') { [void]$ownSet.Add([string]$h) } }
} catch { $o.errors += 'request unreadable'; $after = [int64]0; $maxEvents = 1000; $maxBlocks = 100; $maxText = 4096; $maxTotal = 262144; $ownSet = New-Object 'System.Collections.Generic.HashSet[string]' }

$name = 'Microsoft-Windows-PowerShell/Operational'
try {
  $p = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
  $o.enabled = [bool]($p -and $p.EnableScriptBlockLogging -eq 1)
} catch { $o.errors += 'policy unreadable' }
try {
  $l = Get-WinEvent -ListLog $name
  $oldest = [int64]0
  $first = Get-WinEvent -LogName $name -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
  if ($first) { $oldest = [int64]$first.RecordId }
  $newest = Get-WinEvent -LogName $name -MaxEvents 1 -ErrorAction SilentlyContinue
  $o.log = @{ newest=([int64]$(if ($newest) { $newest.RecordId } else { 0 })); enabled=[bool]$l.IsEnabled; records=[int64]$l.RecordCount; max_bytes=[int64]$l.MaximumSizeInBytes; oldest=$oldest }
} catch { $o.errors += 'log metadata unreadable' }

$sha = [Security.Cryptography.SHA256]::Create()
function HashOf([string]$t) { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($t)))).Replace('-', '').ToLower() }

try {
  $xp = "*[System[(EventID=4104) and (EventRecordID>$after)]]"
  $events = @(Get-WinEvent -LogName $name -FilterXPath $xp -MaxEvents $maxEvents -Oldest -ErrorAction SilentlyContinue)
  $o.read = $events.Count
  if ($events.Count -ge $maxEvents) { $o.more = $true }
  # Reassemble blocks that Windows split into numbered parts.
  $order = New-Object System.Collections.ArrayList
  $byId = @{}
  foreach ($e in $events) {
    $rec = [int64]$e.RecordId
    if ($o.first -eq 0) { $o.first = $rec }
    $o.last = $rec
    $pr = $e.Properties
    if ($pr.Count -lt 5) { continue }
    $id = [string]$pr[3].Value
    if (-not $byId.ContainsKey($id)) {
      $byId[$id] = @{ id=$id; rec=$rec; time=$e.TimeCreated.ToUniversalTime(); pid=[int]$e.ProcessId; level=[int]$e.Level
                      total=[int]$pr[1].Value; parts=@{}; path=[string]$pr[4].Value }
      [void]$order.Add($id)
    }
    $b = $byId[$id]
    $b.parts[[int]$pr[0].Value] = [string]$pr[2].Value
    if ([int]$e.Level -lt $b.level) { $b.level = [int]$e.Level }
  }
  $total = 0
  $out = New-Object System.Collections.ArrayList
  foreach ($id in $order) {
    $b = $byId[$id]
    $complete = ($b.parts.Count -eq $b.total)
    $sb = New-Object Text.StringBuilder
    foreach ($n in ($b.parts.Keys | Sort-Object)) { [void]$sb.Append($b.parts[$n]) }
    $text = $sb.ToString()
    $h = HashOf $text
    $isOwn = $false
    # A process id is not authority for later blocks (reuse and injected content).
    if ($complete -and $ownSet.Contains($h)) { $isOwn = $true }
    if ($isOwn) { $o.own++; continue }
    if ($out.Count -ge $maxBlocks -or $total -ge $maxTotal) { $o.more = $true; $o.last = $b.rec - 1; break }
    $cut = $text
    if ($cut.Length -gt $maxText) { $cut = $cut.Substring(0, $maxText) }
    if ($cut.Length -gt ($maxTotal - $total)) { $cut = $cut.Substring(0, $maxTotal - $total) }
    $total += $cut.Length
    [void]$out.Add(@{ rec=$b.rec; time=$b.time.ToString('o'); pid=$b.pid; level=$b.level; path=$b.path
                      sha=$h; len=$text.Length; complete=$complete; truncated=($cut.Length -lt $text.Length); text=$cut })
  }
  $o.blocks = @($out.ToArray())
} catch { $o.errors += ('read failed: ' + $_.Exception.GetType().Name) }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 5 -Compress)))

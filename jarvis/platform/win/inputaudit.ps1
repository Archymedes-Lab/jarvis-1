# Who is watching the mouse and keyboard? Elevated broker job.
#
# Windows records, in the Microsoft-Windows-Win32k provider's AuditApiCalls
# keyword (0x400), each call that registers an input watcher:
#   1002  SetWindowsHookEx         FilterType 13 keyboard-LL, 14 mouse-LL, ...
#   1001  RegisterRawInputDevices  UsagePage/Usage/Flags (0x100 = background sink)
#   1000  SetWinEventHook          focus and window-event watchers
#   1003  GetAsyncKeyState         written at a key event for a process that
#         polled at >= 1 call/ms since the previous key event (kernel gate);
#         fields PID, MsSinceLastKeyEvent, BackgroundCallCount
# Measured on this machine (build 26200): 1002 and 1001 fire under 0x400 and
# name the calling process (2026-09-23). 1003 fires only when keyword 0x1000
# is enabled as well (2026-10-21: 0x400 alone and 0x1000 alone gave none at
# 14 calls/ms; 0x1400 gave 102 in 45 s, all attributed by EventData.PID).
#
# A registration is logged once, when it happens, so this job keeps a trace
# session running between broker runs ("JarvisInputAudit", real-time to a file
# in this admin-only folder). It is the broker's one stateful job: it starts
# JARVIS's own ETW session and keeps an inventory here, and changes no system
# setting. The session does not survive a reboot, so anything that registered
# between boot and the first run after it is unseen; that gap is reported.
#
# Each run: stop the session (flushing its file), start a fresh one, queue the
# closed file, parse the queue oldest first, merge it into the inventory, drop
# watchers whose process has exited (after reporting them once), and print the
# inventory as base64 JSON. It keeps process ids, image paths, signer status,
# hook types and counts. Never key codes, window titles or command lines.
#
# A closed trace is deleted only after the inventory holding its rows is
# written. 2026-10-31: the first run after logon met a 75 MB trace with 40
# exited registrants, one 1.7 s Sysmon scan each, passed the broker's limit and
# was killed; the next run deleted that file unparsed, so the post-logon window
# (where persistence registers its hooks) was lost every time. Now a killed run
# leaves its files queued, the queue is bounded, a file that keeps killing the
# run is dropped after $MaxTries, and every drop is reported.

# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'Stop'
$Name = 'JarvisInputAudit'
$Sys32 = [Environment]::SystemDirectory
$Logman = Join-Path $Sys32 'logman.exe'
# From the system drive, not %ProgramData% (the user's environment can set it).
$Dir = Join-Path ([IO.Path]::GetPathRoot($Sys32)) 'ProgramData\Jarvis\Broker\inputaudit'
$Etl = Join-Path $Dir 'session.etl'
$Old = Join-Path $Dir 'session.prev.etl'      # left by a run of the old layout
$Inv = Join-Path $Dir 'inventory.json'
$TriesFile = Join-Path $Dir 'attempts.json'
$MaxRows = 400
$Keyword = '0x1400'
$CapMB = 128          # about 52 MB per 15 min was measured; logging stops at the cap, which the output reports
$MaxQueue = 4         # closed trace files kept for parsing
$MaxQueueMB = 384
$MaxTries = 3         # runs a file may be started in before it is dropped as unparseable
$BudgetSec = 150      # no new file is started after this; the broker kills the job at 400 s
$PidsPerQuery = 20    # one Sysmon log scan per batch (about 5 s); 40 ids is an invalid query (measured 2026-10-31)
$MaxBuckets = 5000    # distinct kind|type|pid|minute groups held per run; the rest is counted
$WantIds = "*[System[(EventID=1000 or EventID=1001 or EventID=1002 or EventID=1003)]]"
New-Item -ItemType Directory -Force $Dir | Out-Null
$clock = [Diagnostics.Stopwatch]::StartNew()

function Unix([datetime]$t) { [DateTimeOffset]::new($t.ToUniversalTime()).ToUnixTimeSeconds() }
function Running { & $Logman query $Name -ets *> $null; return $LASTEXITCODE -eq 0 }
function Start-Session {
    # 0x1400: AuditApiCalls (0x400) plus the 0x1000 bit that 1003 (key-state
    # polling) is gated on. Measured 2026-10-21: 0x400 alone and 0x1000 alone
    # each gave no 1003 at 14 calls/ms; together, 102 events in 45 s, all
    # attributed. 0x1000 adds about 450 other Win32k events a second, so the
    # file is capped and parsed with an event-id filter (0.8 s for 20k events
    # against 23 s unfiltered).
    & $Logman start $Name -p Microsoft-Windows-Win32k $Keyword 0x5 -o $Etl -bs 64 -nb 4 16 -max $CapMB -ets | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "logman start failed ($LASTEXITCODE)" }
}

# --- the queue of closed trace files ---------------------------------------
function Add-ToQueue([string]$queueDir, [string]$path) {
    # Never delete a closed trace unparsed: move it into the queue under a name
    # that sorts by age.
    if (-not (Test-Path -LiteralPath $path)) { return }
    $ticks = [DateTime]::UtcNow.Ticks
    do {
        $dest = Join-Path $queueDir ('session.pending-{0:D19}.etl' -f $ticks)
        $ticks++
    } while (Test-Path -LiteralPath $dest)
    Move-Item -LiteralPath $path -Destination $dest
}

function Read-Tries([string]$path) {
    $t = @{}
    if (Test-Path -LiteralPath $path) {
        try {
            (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).PSObject.Properties |
                ForEach-Object { $t[[string]$_.Name] = [int]$_.Value }
        } catch { }
    }
    return $t
}

function Save-Tries([string]$path, [hashtable]$tries) {
    ([pscustomobject]$tries) | ConvertTo-Json -Compress | Set-Content -LiteralPath "$path.new" -Encoding UTF8
    Move-Item -LiteralPath "$path.new" -Destination $path -Force
}

function Select-Queue([object[]]$files, [hashtable]$tries, [int]$maxFiles, [int64]$maxBytes, [int]$triesLimit) {
    # Oldest first. Returns @{ keep; drop } where each drop names its reason.
    # A file that was started $triesLimit times and never finished is the one
    # killing the run; beyond the bounds the oldest files go first.
    $keep = New-Object System.Collections.ArrayList
    $drop = New-Object System.Collections.ArrayList
    foreach ($f in @($files | Sort-Object Name)) {
        if ([int]$tries[[string]$f.Name] -ge $triesLimit) {
            [void]$drop.Add([pscustomobject]@{ file = $f; reason = 'retries' })
        } else { [void]$keep.Add($f) }
    }
    $bytes = [int64]0
    foreach ($f in $keep) { $bytes += [int64]$f.Length }
    while ($keep.Count -gt $maxFiles -or ($keep.Count -gt 1 -and $bytes -gt $maxBytes)) {
        $f = $keep[0]; $keep.RemoveAt(0); $bytes -= [int64]$f.Length
        [void]$drop.Add([pscustomobject]@{ file = $f; reason = 'bound' })
    }
    return @{ keep = @($keep); drop = @($drop) }
}

# --- identify a process as it was when it registered ----------------------
function Find-Creator([object[]]$creates, [datetime]$when) {
    # The newest creation of this id at or before the event; a later one is a
    # reuse of the id, not the registrant.
    $best = $null
    foreach ($c in @($creates)) {
        if ($c.time -le $when.AddSeconds(1) -and (-not $best -or $c.time -gt $best.time)) { $best = $c }
    }
    return $best
}

function Sysmon-Creates([int[]]$procIds, [int]$chunk) {
    # One scan of the Sysmon log per $chunk ids instead of one per id
    # (2026-10-31: 40 single-id scans cost about 68 s). Streamed. Returns
    # @{ map = pid -> list of @{ time; image }; failed = queries that errored }.
    $map = @{}; $failed = 0
    $ids = @($procIds | Sort-Object -Unique)
    for ($i = 0; $i -lt $ids.Count; $i += $chunk) {
        $part = @($ids[$i..([Math]::Min($i + $chunk, $ids.Count) - 1)])
        $or = ($part | ForEach-Object { "Data[@Name='ProcessId']='$_'" }) -join ' or '
        $xp = "*[System[EventID=1]] and *[EventData[$or]]"
        try {
            Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xp -ErrorAction Stop | ForEach-Object {
                $d = Read-Data $_
                $p = 0
                if (-not [int]::TryParse($d['ProcessId'], [ref]$p)) { return }
                if (-not $map.ContainsKey($p)) { $map[$p] = New-Object System.Collections.ArrayList }
                [void]$map[$p].Add(@{ time = $_.TimeCreated; image = $d['Image'] })
            }
        } catch { if ($_.Exception.Message -notmatch 'No events') { $failed++ } }
    }
    return @{ map = $map; failed = $failed }
}

function Read-Data($e) {
    $d = @{}
    foreach ($x in @(([xml]$e.ToXml()).Event.EventData.Data)) { if ($x) { $d[[string]$x.Name] = [string]$x.'#text' } }
    return $d
}

function Read-Registration($e) {
    # One audit event as @{ kind; type; pid; when; ... }, or $null if not a watcher.
    $d = Read-Data $e
    $r = @{ type = ''; pid = [int]$e.ProcessId; when = $e.TimeCreated; lib = ''; failed = $false }
    switch ([int]$e.Id) {
        1002 {
            $r.kind = 'hook'; $r.type = [string](Signed32 $d['FilterType'])
            $r.lib = [string]$d['pstrLib']
            if ($d['ReturnValue'] -eq '0') { $r.failed = $true }
        }
        1001 {
            $r.kind = 'rawinput'
            $r.type = "$($d['UsagePage'])/$($d['Usage'])/$(Signed32 $d['Flags'])"
            $r.visible_windows = Signed32 $d['cVisWindows']
        }
        1000 { $r.kind = 'winevent'; $r.type = 'any' }
        1003 {
            # Written by the kernel at a key event, for a process that called
            # the key-state API at >= 1 call/ms since the previous key event.
            # The polling process is EventData.PID, not the header pid.
            $r.kind = 'poll'; $r.type = 'getasynckeystate'
            if ($d['PID']) { $r.pid = [int]$d['PID'] }
            $r.calls = Signed32 $d['BackgroundCallCount']
            $r.ms = Signed32 $d['MsSinceLastKeyEvent']
        }
        default { return $null }
    }
    return $r
}

function Add-ToBucket([hashtable]$buckets, [hashtable]$r, [int]$max) {
    # Fold one registration into its kind|type|pid|minute bucket. A process id
    # reused within the same minute for the same watcher type is the only
    # thing merged. Returns $false when a new bucket would pass $max.
    $t = Unix $r.when
    $key = "$($r.kind)|$($r.type)|$($r.pid)|$([int64][Math]::Floor($t / 60))"
    $b = $buckets[$key]
    if (-not $b) {
        if ($buckets.Count -ge $max) { return $false }
        $buckets[$key] = @{ kind = $r.kind; type = $r.type; pid = $r.pid; when = $r.when
                            first = $t; last = $t; count = 1; lib = [string]$r.lib
                            failed = [bool]$r.failed; visible_windows = $r.visible_windows
                            calls = $r.calls; ms = $r.ms }
        return $true
    }
    $b.count++
    if ($t -gt $b.last) { $b.last = $t }
    if ($null -ne $r.calls -and ($null -eq $b.calls -or $r.calls -gt $b.calls)) { $b.calls = $r.calls; $b.ms = $r.ms }
    return $true
}

$sigCache = @{}
function Signer([string]$path) {
    if (-not $path) { return @{ status = 'unknown'; signer = '' } }
    if (-not $sigCache.ContainsKey($path)) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $path
            $cn = if ($s.SignerCertificate) { ($s.SignerCertificate.Subject -replace '^.*?CN=("?)([^,"]+)\1.*$', '$2') } else { '' }
            $sigCache[$path] = @{ status = [string]$s.Status; signer = $cn }
        } catch { $sigCache[$path] = @{ status = 'unreadable'; signer = '' } }
    }
    return $sigCache[$path]
}

function Signed32([string]$v) {
    $n = [int64]0
    if (-not [int64]::TryParse($v, [ref]$n)) { return $null }
    if ($n -gt 2147483647) { $n -= 4294967296 }
    return [int]$n
}

# --- the run ----------------------------------------------------------------
# (tests load the functions above through the PowerShell parser; no switch here)
$boot = Unix (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$state = $null
if (Test-Path $Inv) { try { $state = Get-Content $Inv -Raw | ConvertFrom-Json } catch { $state = $null } }
if (-not $state -or [int64]$state.boot -ne $boot) {
    # A new boot: every process in the old inventory is gone.
    $state = [pscustomobject]@{ boot = $boot; session_started = 0; runs = 0; rows = @() }
}

$gapMs = $null
$fresh = $false
Add-ToQueue $Dir $Old
if (Running) {
    $t0 = Get-Date
    & $Logman stop $Name -ets | Out-Null
    Add-ToQueue $Dir $Etl
    Start-Session
    $gapMs = [int]((Get-Date) - $t0).TotalMilliseconds
} else {
    # No session: a reboot ended it, so its file is closed. It holds the end of
    # the previous boot; queue it rather than delete it.
    Add-ToQueue $Dir $Etl
    Start-Session
    $fresh = $true
    if (-not [int64]$state.session_started) { $state.session_started = Unix (Get-Date) }
}

$tries = Read-Tries $TriesFile
$sel = Select-Queue @(Get-ChildItem -LiteralPath $Dir -Filter 'session.pending-*.etl') $tries $MaxQueue ([int64]$MaxQueueMB * 1MB) $MaxTries
$dropped = @()
foreach ($d in $sel.drop) {
    $dropped += [pscustomobject]@{ bytes = [int64]$d.file.Length; reason = $d.reason }
    Remove-Item -LiteralPath $d.file.FullName -ErrorAction SilentlyContinue
    $tries.Remove([string]$d.file.Name)
}

# --- parse the queued files, oldest first, within the time budget ---------
# Memory stays flat whatever the trace size: events are streamed, never
# collected, and folded into one bucket per kind|type|pid|minute (a 75 MB
# post-logon trace held 169 wanted events in 87 such buckets). Buckets are
# capped; anything past the cap is counted and reported, not kept.
$parsed = 0; $failed = 0; $seen1003 = 0; $overflow = 0
$etlBytes = [int64]0; $capped = $false
$done = @()
$buckets = @{}
foreach ($f in $sel.keep) {
    # Always make progress on one file; start no further file past the budget.
    if ($done.Count -and $clock.Elapsed.TotalSeconds -ge $BudgetSec) { break }
    # Counted before the parse, so a run killed inside it still counts.
    $tries[[string]$f.Name] = [int]$tries[[string]$f.Name] + 1
    Save-Tries $TriesFile $tries
    $etlBytes += [int64]$f.Length
    if ([int64]$f.Length -ge ([int64]$CapMB * 1MB)) { $capped = $true }
    $readOk = $true
    try {
        Get-WinEvent -Path $f.FullName -Oldest -FilterXPath $WantIds -ErrorAction Stop | ForEach-Object {
            # One bad event must not end the stream: count it and go on.
            try {
                $script:parsed++
                $r = Read-Registration $_
                if (-not $r) { return }
                if ($r.kind -eq 'poll') { $script:seen1003++ }
                if (-not (Add-ToBucket $buckets $r $MaxBuckets)) { $script:overflow++ }
            } catch { $script:failed++ }
        }
    } catch { if ($_.Exception.Message -notmatch 'No events') { $failed++; $readOk = $false } }
    # A file that could not be read stays queued; after $MaxTries it is dropped
    # and reported, never deleted as if it had been parsed.
    if ($readOk) { $done += $f }
}
$backlog = @(Get-ChildItem -LiteralPath $Dir -Filter 'session.pending-*.etl').Count - $done.Count

# --- who registered: the live process first, then one batched Sysmon pass --
# Only the ids that matter are looked up; no snapshot of every process.
$ids = @{}
foreach ($b in $buckets.Values) { $ids[[int]$b.pid] = $true }
foreach ($r in @($state.rows)) { if ($r) { $ids[[int]$r.pid] = $true } }
$procs = @{}
foreach ($id in $ids.Keys) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($p) {
        $st = $null; try { $st = $p.StartTime } catch { }
        $procs[$id] = @{ start = $st; path = [string]$p.Path }
        $p.Dispose()
    }
}
$needSysmon = @{}
foreach ($b in $buckets.Values) {
    $p = $procs[[int]$b.pid]
    # A live process with this id that started after the event is a reuse
    # of the id, not the registrant.
    if ($p -and $p.start -and $p.start -le $b.when.AddSeconds(1)) {
        $b.who = @{ path = $p.path; start = Unix $p.start; via = 'live' }
    } else { $needSysmon[[int]$b.pid] = $true }
}
$identityFailures = 0
if ($needSysmon.Count) {
    $sm = Sysmon-Creates @($needSysmon.Keys) $PidsPerQuery
    $identityFailures = $sm.failed
    foreach ($b in $buckets.Values) {
        if ($b.who) { continue }
        $c = Find-Creator @($sm.map[[int]$b.pid]) $b.when
        $b.who = if ($c) { @{ path = [string]$c.image; start = Unix $c.time; via = 'sysmon' } }
                 else { @{ path = ''; start = 0; via = 'unresolved' } }
    }
    $sm = $null
}

# --- merge into the inventory ----------------------------------------------
$rows = @{}
foreach ($r in @($state.rows)) { if ($r) { $rows[[string]$r.key] = $r } }
$touched = @{}
foreach ($b in $buckets.Values) {
    try {
        $w = $b.who
        $key = "$($b.kind)|$($b.type)|$($w.path.ToLower())|$($b.pid)|$($w.start)"
        $touched[$key] = $true
        if ($rows.ContainsKey($key)) {
            $row = $rows[$key]
            $row.count = [int]$row.count + $b.count
            if ($b.last -gt [int64]$row.last) { $row.last = $b.last }
            if ($null -ne $b.calls -and $b.calls -gt [int]$row.calls) { $row.calls = $b.calls; $row.ms = $b.ms }
        } else {
            if ($rows.Count -ge $MaxRows) { $overflow++; continue }
            $sig = Signer $w.path
            $rows[$key] = [pscustomobject]@{
                key = $key; kind = $b.kind; type = $b.type; pid = $b.pid
                start = $w.start; path = $w.path; via = $w.via
                sig = $sig.status; signer = $sig.signer
                first = $b.first; last = $b.last; count = $b.count
                lib = $b.lib; failed = $b.failed
                visible_windows = $b.visible_windows
                calls = $b.calls; ms = $b.ms }
        }
    } catch { $failed++ }
}
$buckets = $null

# --- keep only watchers whose process is still the same process -----------
$alive = @{}
foreach ($id in $procs.Keys) {
    $st = $procs[$id].start
    $alive[[int]$id] = if ($st) { Unix $st } else { -1 }
}
$kept = @(); $ended = 0
$unresolved = @(); $gone = @()
foreach ($row in $rows.Values) {
    if (-not [int64]$row.start) {
        # Never identified, so a later process reusing the id cannot be told
        # apart from it: report it in the run that saw it, never carry it.
        if ($touched.ContainsKey($row.key)) { $unresolved += $row }
        continue
    }
    $s = $alive[[int]$row.pid]
    $same = ($null -ne $s) -and (($s -eq -1) -or ([math]::Abs($s - [int64]$row.start) -le 2))
    if ($same) { $kept += $row } else {
        $ended++
        # Seen this run but already gone: a watcher that ran briefly between
        # two runs must still be reported once, or it would never be seen.
        if ($touched.ContainsKey($row.key)) {
            $row | Add-Member -NotePropertyName exited -NotePropertyValue $true -Force
            $gone += $row
        }
    }
}

$state.rows = $kept
$state.runs = [int]$state.runs + 1
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Inv.new" -Encoding UTF8
Move-Item -LiteralPath "$Inv.new" -Destination $Inv -Force

# Only now, with their rows written, are the parsed files removed.
foreach ($f in $done) {
    Remove-Item -LiteralPath $f.FullName -ErrorAction SilentlyContinue
    $tries.Remove([string]$f.Name)
}
Save-Tries $TriesFile $tries

$o = [ordered]@{
    version = 2; boot = $boot; session_started = [int64]$state.session_started
    fresh_session = $fresh; rotate_gap_ms = $gapMs; runs = $state.runs
    parsed = $parsed; parse_failures = $failed; polling_events = $seen1003
    keyword = $Keyword; polling_logged = ($Keyword -eq '0x1400')
    etl_bytes = $etlBytes; etl_capped = $capped
    files_parsed = $done.Count; backlog_files = $backlog
    dropped_files = @($dropped).Count
    dropped_bytes = [int64](($dropped | Measure-Object -Property bytes -Sum).Sum)
    dropped_retries = @($dropped | Where-Object { $_.reason -eq 'retries' }).Count
    identity_failures = $identityFailures; overflow = $overflow
    run_seconds = [int]$clock.Elapsed.TotalSeconds
    ended = $ended
    watchers = @(@($kept) + @($unresolved) + @($gone) | Where-Object { $_ })
    winevent_watchers = @($kept | Where-Object { $_.kind -eq 'winevent' }).Count
}
$json = $o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

# Instant revival: the watchdog that checks every few seconds.
#
# jarvis-wake-watchdog.ps1 runs every five minutes and jarvis-health-monitor.ps1 every minute.
# Both are too slow to *fix* anything quickly, and the health monitor only tells you.
# This is one long-lived loop that asks JARVIS how it is every $Interval
# seconds and repairs the smallest thing that explains the answer:
#
#   * JARVIS answers but a required protection source is stale or unavailable
#       -> queue that collector now through /api/run. No restart: the daemon
#          is alive, and killing it would open a bigger gap than the one seen.
#   * JARVIS does not answer, or answers that its scheduler has stalled
#       -> distro stopped:        start it (systemd brings jarvis.service up)
#       -> unit not active:       restart jarvis.service
#       -> unit active but silent or stalled for $HungAfter seconds: restart it
#
# Every restart is budgeted: at least $RestartGap seconds apart and at most
# $RestartBudget in 15 minutes. Past that the loop stops acting, says so in its
# state file, and leaves the fault to a human and the health monitor's email. A
# reviver that restart-loops a sick daemon is an outage of its own.
#
#   .\jarvis-reviver.ps1                 run the loop (what the task does)
#   .\jarvis-reviver.ps1 -Once           one check, then exit
#   .\jarvis-reviver.ps1 -Once -DryRun   one check, log what it would do
#   .\jarvis-reviver.ps1 -Install        register the task and start it now
#   .\jarvis-reviver.ps1 -Remove         stop and unregister it
#
# Maintenance: while a file named "pause" exists next to the state file
# (%LOCALAPPDATA%\Jarvis\Reviver\pause), it keeps checking but repairs nothing,
# so a deliberate `systemctl stop jarvis` is not undone five seconds later.
# The file's first line may be a Unix time at which the pause ends by itself.

param(
    [switch]$Install,
    [switch]$Remove,
    [switch]$Once,
    [switch]$DryRun,
    [string]$Distro = 'Ubuntu',
    [string]$TaskName = 'jarvis reviver',
    [string]$RepoRoot = '',
    [string]$HealthUrl = 'http://127.0.0.1:8787/api/health',
    [int]$Interval = 5,
    [int]$HungAfter = 90,
    # A daemon this young that is merely silent is in its cold start (catching
    # up backlogs after a boot or resume), not hung. Restarting it then reset
    # the catch-up: eight 3-restart storms, 2026-10-04..11, each ending in
    # "needs a human". systemd's WatchdogSec=900 and the selfcheck timer still
    # restart a daemon that never comes up; a unit that is not active is
    # restarted at once, grace or not.
    [int]$StartGrace = 300,
    # /api/run kicks back off per source, from KickMin to KickMax seconds.
    [int]$KickMin = 30,
    [int]$KickMax = 600,
    [int]$RestartGap = 60,
    [int]$RestartBudget = 3,
    [int]$MaxSeconds = 0,          # testing: leave the loop after this long
    [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'Jarvis\Reviver')
)

$ErrorActionPreference = 'Continue'
# .NET cuts a non-200 reply at 64 KB; /api/health answers 503 when degraded and is ~90 KB, so the probe
# misread a live daemon as silent and restarted it (measured 2026-11-04). Read up to 4 MB.
[Net.HttpWebRequest]::DefaultMaximumErrorResponseLength = 4096
$self = $MyInvocation.MyCommand.Path
$log = Join-Path $StateRoot 'revive.log'
$statePath = Join-Path $StateRoot 'state.json'
$base = $HealthUrl -replace '/api/health$', ''

function Say($m) {
    $line = "{0} {1}{2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $(if ($DryRun) { '[dry-run] ' } else { '' }), $m
    Write-Host $line
    try {
        Add-Content -LiteralPath $log -Value $line
        if ((Get-Item -LiteralPath $log).Length -gt 1MB) {
            (Get-Content -LiteralPath $log -Tail 2000) | Set-Content -LiteralPath $log
        }
    } catch { }
}

function Save-State($s) {
    try {
        $tmp = $statePath + '.new'
        $s | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $statePath -Force
    } catch { }
}

function Get-JarvisClientToken {
    # A paired client token (`jarvis desktop pair --name supervisor`, saved on its own
    # line). Every API route but liveness needs one; without it this script sees
    # liveness only. Keep the file readable by this account alone.
    $path = if ($env:JARVIS_CLIENT_TOKEN_FILE) { $env:JARVIS_CLIENT_TOKEN_FILE } else { Join-Path $env:LOCALAPPDATA 'Jarvis\client.token' }
    try { $t = ([IO.File]::ReadAllText($path)).Trim() } catch { return $null }
    if ($t -cmatch '^jc1_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$') { return $t }
    return $null
}
function Add-JarvisToken($req) {
    $tok = Get-JarvisClientToken
    if ($tok) { $req.Headers.Add('X-JARVIS-Token', $tok) }
}
function Now { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

# --- install / remove --------------------------------------------------------
if ($Install -or $Remove) {
    [void](New-Item -ItemType Directory -Path $StateRoot -Force)
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($Remove) { Say "removed task '$TaskName'"; return }

    # Run from a local copy: a script on the \\wsl share is unreadable exactly
    # when WSL is down, which is when this has to run.
    $script = Join-Path $StateRoot 'jarvis-reviver.ps1'
    if ($self -ne $script) { Copy-Item -LiteralPath $self -Destination $script -Force }
    $argline = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
               $script + '" -Distro "' + $Distro + '"'
    if ($RepoRoot) { $argline += ' -RepoRoot "' + $RepoRoot + '"' }
    # conhost --headless: -WindowStyle Hidden alone still flashes a console window.
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" `
        -Argument ('--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" + '" ' + $argline)
    # The loop is meant to run forever. The repeating trigger is its resurrection:
    # while it runs, IgnoreNew drops each trigger; if it has died, the next one
    # (at most five minutes away) starts it again.
    $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME),
                  (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                     -RepetitionInterval (New-TimeSpan -Minutes 5) `
                     -RepetitionDuration (New-TimeSpan -Days 3650)))
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    # ExecutionTimeLimit of zero means no limit; a finite one would kill the loop.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal `
        -Settings $settings -Description 'Checks JARVIS every few seconds and revives what has stopped' | Out-Null
    $check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $check) { Say "FAILED to register task '$TaskName'"; exit 1 }
    Start-ScheduledTask -TaskName $TaskName
    Say "registered and started task '$TaskName' (checks every ${Interval}s)"
    return
}

# --- probes ------------------------------------------------------------------
function Get-Health {
    # Raw HttpWebRequest with the proxy off: the same reason as the health monitor --
    # Invoke-RestMethod can block past its timeout in a hidden task session.
    try {
        # A non-200 reply is cut at DefaultMaximumErrorResponseLength (64 KB) and the
        # health body is 72-76 KB: a live 503 parsed as silence (2026-10-31). Bounded
        # at 4 MB (the unit is KB).
        [Net.HttpWebRequest]::DefaultMaximumErrorResponseLength = 4096
        $req = [Net.HttpWebRequest]::Create($HealthUrl)
        Add-JarvisToken $req
        $req.Proxy = $null; $req.Timeout = 4000; $req.ReadWriteTimeout = 4000; $req.KeepAlive = $false
        $resp = $req.GetResponse()
    } catch [Net.WebException] {
        $resp = $_.Exception.Response
        if (-not $resp) { return @{ answered = $false } }
    } catch { return @{ answered = $false } }
    try {
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        try { $h = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
    } catch { return @{ answered = $false } } finally { $resp.Dispose() }
    if ($h.service -ne 'JARVIS') { return @{ answered = $false } }
    return @{ answered = $true; live = ($h.live -eq $true); healthy = ($h.healthy -eq $true); body = $h }
}

function Invoke-Run([string]$job) {
    if ($DryRun) { return $true }
    try {
        $req = [Net.HttpWebRequest]::Create("$base/api/run?job=$([uri]::EscapeDataString($job))")
        $req.Proxy = $null; $req.Timeout = 4000; $req.Method = 'POST'; $req.ContentLength = 0
        Add-JarvisToken $req
        $req.GetResponse().Dispose()
        return $true
    } catch { return $false }
}

# wsl.exe can hang when the VM is wedged, so every call into the distro runs
# with a wall-clock ceiling.
function Invoke-Wsl([string[]]$WslArgs, [int]$Seconds = 20) {
    $j = Start-Job -ScriptBlock {
        param($a)
        $prev = [Console]::OutputEncoding
        try { [Console]::OutputEncoding = [Text.Encoding]::Unicode; (& wsl.exe @a 2>$null) -join "`n" }
        finally { [Console]::OutputEncoding = $prev }
    } -ArgumentList (, $WslArgs)
    if (Wait-Job $j -Timeout $Seconds) {
        $out = Receive-Job $j; Remove-Job $j -Force -ErrorAction SilentlyContinue
        return @{ ok = $true; out = "$out" }
    }
    Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue
    return @{ ok = $false; out = '' }
}

function Test-DistroRunning {
    $r = Invoke-Wsl @('-l', '--running') 15
    if (-not $r.ok) { return $null }
    return ($r.out -replace "`0", '') -match [regex]::Escape($Distro)
}

# The states `systemctl is-active` can print. Anything else on its output is
# not a unit state: when wsl.exe itself cannot reach the WSL service it prints
# "error code: wsl/service/0x8007274c" (WSAETIMEDOUT) on stdout, and reading
# that as "the unit is not active" made the wake watchdog restart a running daemon
# about 30 times between 2026-10-13 and 2026-10-27. Unknown means unknown.
function ConvertTo-UnitState([string]$text) {
    $known = @('active', 'reloading', 'inactive', 'failed', 'activating',
               'deactivating', 'maintenance', 'refreshing')
    $lines = @(@("$text" -split "`n") | ForEach-Object { "$_".Trim().ToLower() } | Where-Object { $_ -ne '' })
    if ($lines.Count -eq 0) { return '' }
    $last = [string]$lines[-1]
    if ($known -contains $last) { return $last }
    return ''
}

function Get-UnitState {
    # Not the UTF-16 listing: systemctl's own output is UTF-8, so read it plainly.
    $j = Start-Job -ScriptBlock { param($d) (& wsl.exe -d $d --exec systemctl is-active jarvis.service 2>$null) -join "`n" } -ArgumentList $Distro
    if (Wait-Job $j -Timeout 20) {
        $out = "$(Receive-Job $j)"; Remove-Job $j -Force -ErrorAction SilentlyContinue
        return ConvertTo-UnitState $out
    }
    Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue
    return ''
}

function Get-UnitAge {
    # Seconds since jarvis.service last became active, from the guest's own
    # monotonic clock (wall-clock steps cannot skew it), or $null if unknown.
    $j = Start-Job -ScriptBlock { param($d)
        (& wsl.exe -d $d --exec sh -c 'read u rest < /proc/uptime; echo $u $(systemctl show jarvis.service -p ActiveEnterTimestampMonotonic --value)' 2>$null) -join "`n" } -ArgumentList $Distro
    if (Wait-Job $j -Timeout 20) {
        $out = "$(Receive-Job $j)"; Remove-Job $j -Force -ErrorAction SilentlyContinue
        return ConvertTo-UnitAge $out
    }
    Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue
    return $null
}

function ConvertTo-UnitAge([string]$text) {
    # "<uptime seconds> <ActiveEnterTimestampMonotonic microseconds>"
    $f = @("$text".Trim() -split '\s+')
    if ($f.Count -lt 2) { return $null }
    $up = 0.0; $mono = 0.0
    if (-not [double]::TryParse($f[-2], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$up)) { return $null }
    if (-not [double]::TryParse($f[-1], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$mono)) { return $null }
    if ($mono -le 0) { return $null }          # never active: no start to measure from
    $age = $up - $mono / 1e6
    if ($age -lt 0) { return $null }
    return [int]$age
}

function Test-StartGrace($unitAge) {
    # True while a silent unit is young enough to still be starting. Unknown
    # age gives no grace: the reviver then behaves as it always did.
    return ($null -ne $unitAge -and [int]$unitAge -lt $StartGrace)
}

function Test-ShouldKick([string]$name, [string]$status, [long]$last, [int]$wait, [long]$now) {
    # Re-run a source through /api/run only when re-running can help: it is
    # stale, missing or unavailable (not partial, not the storage probe), and
    # its back-off has elapsed.
    if ($status -eq 'complete' -or $status -eq 'partial' -or $name -eq 'storage') { return $false }
    return ($now - $last -ge $wait)
}

function Get-KickWait([object]$previous) {
    # Next wait after a kick: double the last one, within KickMin..KickMax.
    $w = [int]$previous
    if ($w -lt $KickMin) { return $KickMin }
    return [Math]::Min($KickMax, $w * 2)
}

# --- the loop ----------------------------------------------------------------
[void](New-Item -ItemType Directory -Path $StateRoot -Force)
$mutex = New-Object Threading.Mutex($false, 'Local\JarvisReviver')
if (-not $Once) {
    try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) { return }   # another reviver is already watching
}

$st = @{ healthy = $null; firstFailure = 0; lastAction = ''; lastActionAt = 0; lastResult = '';
         restarts = @(); gaveUp = $false; kicked = @{}; kickWait = @{}; gapSince = 0; graceNoted = 0;
         startedAt = (Now); pid = $PID; silentSince = 0 }
if (Test-Path -LiteralPath $statePath) {
    try {
        $old = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $st.restarts = @($old.restarts | Where-Object { $_ -gt (Now) - 900 })
    } catch { }
}
$lastSync = 0

function Act([string]$what, [scriptblock]$do) {
    $st.lastAction = $what; $st.lastActionAt = (Now)
    Say $what
    if (-not $DryRun) { & $do }
}

function Restart-Allowed {
    $now = Now
    $st.restarts = @($st.restarts | Where-Object { $_ -gt $now - 900 })
    if ($st.restarts.Count -ge $RestartBudget) {
        if (-not $st.gaveUp) {
            $st.gaveUp = $true
            Say "restart budget spent ($RestartBudget in 15 min) -- not restarting again; needs a human"
        }
        return $false
    }
    if ($st.restarts.Count -and $now - ($st.restarts | Measure-Object -Maximum).Maximum -lt $RestartGap) { return $false }
    return $true
}

function Restart-Jarvis([string]$why) {
    if (-not (Restart-Allowed)) { return }
    $st.restarts = @($st.restarts) + (Now)
    # Through the root-owned restart gate when it is installed: it re-checks the
    # fault itself, records the warrant and refuses a live daemon
    # (scripts/repair/jarvis-restart-gate). The legacy command stays only until
    # the owner revokes its sudo rule.
    $reason = if ($why -like 'unit is*') { 'unit-down' } else { 'health-silent' }
    $cmd = "if [ -x /usr/local/sbin/jarvis-restart-gate ]; then exec sudo -n /usr/local/sbin/jarvis-restart-gate --actor reviver --reason $reason; fi; systemctl restart jarvis.service 2>/dev/null || sudo -n systemctl restart jarvis.service"
    Act "restarting jarvis.service: $why" {
        [void](Invoke-Wsl @('-d', $Distro, '--exec', 'bash', '-lc', $cmd) 45)
    }
}

function Test-Paused {
    $f = Join-Path $StateRoot 'pause'
    if (-not (Test-Path -LiteralPath $f)) { return $false }
    $until = 0
    try { $until = [long]((Get-Content -LiteralPath $f -TotalCount 1) -as [long]) } catch { }
    if ($until -and (Now) -ge $until) {
        Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
        Say "maintenance pause expired -- reviving again"
        return $false
    }
    return $true
}

while ($true) {
    $now = Now
    $h = Get-Health
    $st.checkedAt = $now
    $paused = Test-Paused
    if ($paused -ne [bool]$st.paused) { Say $(if ($paused) { 'paused for maintenance -- checking only' } else { 'maintenance pause lifted' }) }
    $st.paused = $paused

    if ($h.answered -and $h.live) {
        # Any live answer ends a silence. Silence has its own clock: before
        # 2026-11-04 it shared firstFailure with "alive but degraded", so one missed
        # probe after hours of a degraded-but-live daemon read as "silent for
        # 7817s" and restarted it at once (5 restarts 17:24-18:05).
        $st.silentSince = 0
        if ($h.healthy) {
            if ($st.healthy -eq $false) {
                $down = $now - [long]$st.firstFailure
                Say "JARVIS healthy again after ${down}s$(if ($st.lastAction) { " (last action: $($st.lastAction))" })"
                $st.lastResult = "recovered after ${down}s"
            }
            $st.healthy = $true; $st.firstFailure = 0; $st.gaveUp = $false; $st.gapSince = 0
            $st.kickWait = @{}
        } else {
            # Alive, but a required source is stale or blind: run it now.
            if ($st.healthy -ne $false) { $st.firstFailure = $now }
            $st.healthy = $false
            foreach ($p in $(if ($paused) { @() } else { $h.body.sources.PSObject.Properties })) {
                if ($p.Value.status -eq 'complete') { $st.kickWait.Remove($p.Name); continue }
                # A partial source ran and reported a blind spot; running it again
                # does not repair the sensor behind it, it only adds load. The
                # scheduler already retries failed collectors on its own.
                $last = [long]($st.kicked[$p.Name])
                $wait = if ($st.kickWait.ContainsKey($p.Name)) { [int]$st.kickWait[$p.Name] } else { $KickMin }
                if (-not (Test-ShouldKick $p.Name ([string]$p.Value.status) $last $wait $now)) { continue }
                $st.kicked[$p.Name] = $now
                $st.kickWait[$p.Name] = Get-KickWait $wait
                $ok = Invoke-Run $p.Name
                $st.lastAction = "queued $($p.Name) ($($p.Value.status): $($p.Value.reason))"
                $st.lastActionAt = $now
                Say "$($st.lastAction)$(if (-not $ok) { ' -- request failed' })"
            }
        }
    } else {
        if ($st.healthy -ne $false) { $st.firstFailure = $now }
        if (-not [long]$st.silentSince) { $st.silentSince = $now; Say "JARVIS not answering$(if ($h.answered) { ' (scheduler stalled)' })" }
        $st.healthy = $false
        $age = $now - [long]$st.silentSince
        $settling = ($now - [long]$st.lastActionAt) -lt 45   # give the last fix time to land
        if ($age -ge 10 -and -not $settling -and -not $st.gaveUp -and -not $paused) {
            $running = Test-DistroRunning
            if ($running -eq $false) {
                Act "distro '$Distro' is not running -- starting it" {
                    [void](Invoke-Wsl @('-d', $Distro, '--exec', '/bin/true') 60)
                }
            } elseif ($running) {
                $unit = Get-UnitState
                if ($unit -in @('activating', 'reloading', 'deactivating')) {
                    # systemd is already mid-restart; racing it helps nobody.
                } elseif ($unit -ne '' -and $unit -ne 'active') {
                    Restart-Jarvis "unit is '$unit'"
                } elseif ($unit -eq 'active' -and $age -ge $HungAfter) {
                    $unitAge = if ($h.answered) { $null } else { Get-UnitAge }
                    if (Test-StartGrace $unitAge) {
                        # Silent, but started under StartGrace ago: still starting.
                        if ($st.graceNoted -ne $st.firstFailure) {
                            $st.graceNoted = $st.firstFailure
                            Say "not restarting: jarvis.service became active ${unitAge}s ago and is still starting (grace ${StartGrace}s)"
                        }
                    } else {
                        Restart-Jarvis "active but $(if ($h.answered) { 'stalled' } else { 'silent' }) for ${age}s"
                    }
                }
            }
        }
    }

    # Keep the deployed copy in step with the checkout, as the wake watchdog does.
    if ($RepoRoot -and -not $Once -and $now - $lastSync -ge 600) {
        $lastSync = $now
        try {
            $rel = ($RepoRoot -replace '/', '\').TrimEnd('\')
            $unc = "\\wsl.localhost\$Distro$rel\jarvis-reviver.ps1"
            $repoTxt = Get-Content -LiteralPath $unc -Raw -ErrorAction Stop
            $mine = Get-Content -LiteralPath $self -Raw -ErrorAction Stop
            $norm = { param($s) ($s -replace "`r`n", "`n").TrimEnd() }
            if ($repoTxt.Length -gt 2000 -and $repoTxt -match 'Instant revival' -and
                (& $norm $repoTxt) -ne (& $norm $mine)) {
                Set-Content -LiteralPath $self -Value $repoTxt -NoNewline -Encoding UTF8
                Say "updated from repo -- handing over to the new copy"
                Save-State $st
                $mutex.ReleaseMutex()
                Start-Process -FilePath "$env:SystemRoot\System32\conhost.exe" -ArgumentList (
                    '--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" +
                    '" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $self +
                    '" -Distro "' + $Distro + '" -RepoRoot "' + $RepoRoot + '"')
                return
            }
        } catch { }
    }

    Save-State $st
    if ($Once -or ($MaxSeconds -and $now - [long]$st.startedAt -ge $MaxSeconds)) { return }
    Start-Sleep -Seconds $Interval
}

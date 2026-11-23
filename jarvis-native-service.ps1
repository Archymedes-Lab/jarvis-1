# Native service: JARVIS on a Windows machine that has no WSL.
#
# Under WSL, systemd keeps jarvis.service running and jarvis-reviver.ps1 revives
# it from outside. A machine without WSL has neither, so this one long-lived
# loop is both: it starts the daemon (python -m jarvis serve) as its own child,
# asks it how it is every $Interval seconds, and restarts it when
#
#   * the daemon process has exited, or
#   * it has not answered, or has answered that its scheduler stalled, for
#     $HungAfter seconds.
#
# Every restart is budgeted: at least $RestartGap seconds apart and at most
# $RestartBudget in 15 minutes. Past that the loop stops acting and says so in
# its state file. A supervisor that restart-loops a sick daemon is an outage of
# its own.
#
# It only ever stops the process it started itself (or, after its own restart,
# the recorded pid when that is still the same python running "-m jarvis
# serve"). It needs no elevation and changes no Windows setting.
#
#   .\jarvis-native-service.ps1 -Install [-Python C:\...\python.exe] [-Port 8787]
#   .\jarvis-native-service.ps1 -Install -Engine C:\...\jarvis.exe [-Port 8787]
#                                          the compiled edition: no Python needed
#   .\jarvis-native-service.ps1 -Remove       stop the daemon, unregister the task
#   .\jarvis-native-service.ps1 -Once         one check, then exit
#   .\jarvis-native-service.ps1               run the loop (what the task does)
#
# Maintenance: while %LOCALAPPDATA%\Jarvis\NativeService\pause exists the loop
# keeps checking but starts and stops nothing. Its first line may be a Unix
# time at which the pause ends by itself.

param(
    [switch]$Install,
    [switch]$Remove,
    [switch]$Once,
    [switch]$DryRun,
    [string]$TaskName = 'jarvis native service',
    [string]$RepoRoot = '',
    [string]$Python = '',
    [string]$Engine = '',          # the compiled edition's program; replaces -Python
    [int]$Port = 0,
    [int]$Interval = 5,
    [int]$HungAfter = 90,
    [int]$StartGrace = 120,
    [int]$RestartGap = 60,
    [int]$RestartBudget = 3,
    [int]$MaxSeconds = 0,          # testing: leave the loop after this long
    [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'Jarvis\NativeService')
)

$ErrorActionPreference = 'Continue'
# .NET cuts a non-200 reply at 64 KB; /api/health answers 503 when degraded and is ~90 KB, so the probe
# misread a live daemon as silent and restarted it (measured 2026-11-04). Read up to 4 MB.
[Net.HttpWebRequest]::DefaultMaximumErrorResponseLength = 4096
$self = $MyInvocation.MyCommand.Path
$log = Join-Path $StateRoot 'service.log'
$statePath = Join-Path $StateRoot 'state.json'
$configPath = Join-Path $StateRoot 'service.json'

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

function Save-Json($value, [string]$path) {
    try {
        $tmp = $path + '.new'
        $value | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $path -Force
    } catch { }
}

function Now { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

function Test-Python([string]$exe) {
    # 3.12 is what JARVIS is written for; an older interpreter fails at import.
    if (-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
    try {
        $v = & $exe -c "import sys; print(int(sys.version_info >= (3, 12)))" 2>$null
        return ("$v".Trim() -eq '1')
    } catch { return $false }
}

function Find-Python {
    $found = @()
    foreach ($candidate in @(@('py.exe', '-3'), @('python.exe'), @('python3.exe'))) {
        $cmd = Get-Command $candidate[0] -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $rest = @($candidate | Select-Object -Skip 1) + @('-c', 'import sys; print(sys.executable)')
            $path = (& $cmd.Source @rest 2>$null | Select-Object -First 1)
            if ($path) { $found += "$path".Trim() }
        } catch { }
    }
    foreach ($p in $found) { if (Test-Python $p) { return $p } }
    return ''
}

function Test-Engine([string]$exe) {
    return [bool]($exe -and $exe -like '*.exe' -and (Test-Path -LiteralPath $exe -PathType Leaf))
}

function Get-DaemonProcess([int]$processId, [string]$exe) {
    # The recorded pid counts only while it is still the JARVIS daemon: Windows
    # reuses pids, and this loop may stop what it finds. The compiled edition's
    # program must be exactly the configured engine (its path is the only thing
    # that names it); a python must be running "-m jarvis serve".
    if ($processId -le 0) { return $null }
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
    } catch { return $null }
    if (-not $p -or -not $p.CommandLine) { return $null }
    if ($Engine) {
        if (-not $p.ExecutablePath -or $p.ExecutablePath -ne $Engine) { return $null }
        if ($p.CommandLine -notmatch '\sserve\s') { return $null }
        return $p
    }
    if ($p.ExecutablePath -and $exe -and ($p.ExecutablePath -ne $exe)) { return $null }
    if ($p.CommandLine -notmatch '-m\s+jarvis\s+serve\b') { return $null }
    return $p
}

function Stop-Daemon([int]$processId, [string]$exe) {
    if (-not (Get-DaemonProcess $processId $exe)) { return $false }
    try {
        Stop-Process -Id $processId -Force -ErrorAction Stop
        Wait-Process -Id $processId -Timeout 15 -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

# --- install / remove --------------------------------------------------------
if ($Install -or $Remove) {
    [void](New-Item -ItemType Directory -Path $StateRoot -Force)
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    # Stopping the task does not end the loop it started (measured on a clean
    # windows-2025 host: the PowerShell loop outlived Stop-ScheduledTask). A
    # loop left running keeps the single-instance lock, so after an upgrade the
    # new task's loop would exit at once and the old one would go on supervising
    # with the old program, and after a removal it could start the daemon
    # again. End exactly the loops that run this service's staged script.
    $staged = Join-Path $StateRoot 'jarvis-native-service.ps1'
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and
                       $_.CommandLine.IndexOf($staged, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                       $_.CommandLine -notmatch '\s-(Install|Remove|Once)\b' } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            Say "stopped the supervisor loop (pid $($_.ProcessId))"
        }
    $old = $null
    try { $old = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
    $oldConfig = $null
    try { $oldConfig = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
    $newEngine = $Engine
    $Engine = $(if ($oldConfig -and $oldConfig.engine) { "$($oldConfig.engine)" } else { '' })
    if ($old -and $old.pid -and (Stop-Daemon ([int]$old.pid) "$($oldConfig.python)")) {
        Say "stopped the daemon (pid $($old.pid))"
    }
    $Engine = $newEngine
    if ($Remove) { Say "removed task '$TaskName'"; return }
    # Installing is a person choosing to run it: start with a fresh restart budget.
    # A kept state from before (an uninstall that kept history, a budget spent by a
    # crashing build) would otherwise stop the new loop from starting the daemon
    # (clean windows-2025 run 41839251050: reinstall exit 2). The log is kept.
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue

    if ($Engine) {
        if (-not (Test-Engine $Engine)) { Say "FAILED: $Engine is not a program file"; exit 1 }
        $Engine = (Resolve-Path -LiteralPath $Engine).ProviderPath
        # The compiled program carries its own code: its folder is the code root.
        if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $Engine }
    }
    if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $self }
    $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).ProviderPath.TrimEnd('\')
    if ($RepoRoot -like '\\*') {
        # A copy on the \\wsl share is the WSL topology: quickstart.ps1 without
        # -Native keeps the daemon inside the distro, where it already runs.
        Say "FAILED: $RepoRoot is a network path. Install from a local Windows folder."
        exit 1
    }
    if ($Engine) {
        $Python = ''
    } elseif (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'jarvis\__main__.py'))) {
        Say "FAILED: no jarvis package under $RepoRoot"; exit 1
    } elseif ($Python) {
        if (-not (Test-Python $Python)) { Say "FAILED: $Python is not Python 3.12 or newer"; exit 1 }
        $Python = (Resolve-Path -LiteralPath $Python).ProviderPath
    } else {
        $Python = Find-Python
        if (-not $Python) { Say "FAILED: Python 3.12 or newer was not found. Install it, or pass -Python."; exit 1 }
    }
    if ($Port -le 0) { $Port = 8787 }
    Save-Json @{ python = $Python; engine = $Engine; port = $Port; repoRoot = $RepoRoot } $configPath

    # Run from a staged copy so the task's script is one fixed, fingerprinted
    # file (the control audit verifies it) rather than whatever is in the tree.
    $script = Join-Path $StateRoot 'jarvis-native-service.ps1'
    if ($self -ne $script) { Copy-Item -LiteralPath $self -Destination $script -Force }
    $argline = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
               $script + '" -RepoRoot "' + $RepoRoot + '"'
    # conhost --headless: -WindowStyle Hidden alone still flashes a console window.
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" `
        -Argument ('--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" + '" ' + $argline)
    # The loop is meant to run forever. The repeating trigger is its resurrection.
    # Parallel, not IgnoreNew: when the loop's PowerShell dies the task can stay
    # "Running" (conhost outlives it; measured on windows-2025, run 41839251050), and
    # IgnoreNew then dropped every trigger. A trigger that fires while the loop runs
    # exits at once on the single-instance lock below, so there is never a second loop.
    $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME),
                  (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                     -RepetitionInterval (New-TimeSpan -Minutes 5) `
                     -RepetitionDuration (New-TimeSpan -Days 3650)))
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances Parallel -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal `
        -Settings $settings -Description 'Runs the JARVIS daemon natively and restarts it when it stops' | Out-Null
    $check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $check) { Say "FAILED to register task '$TaskName'"; exit 1 }
    Start-ScheduledTask -TaskName $TaskName
    Say "registered and started task '$TaskName' ($(if ($Engine) { $Engine } else { $Python }), port $Port, code $RepoRoot)"
    return
}

# --- configuration -----------------------------------------------------------
$config = $null
try { $config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
if (-not $Engine -and $config -and $config.engine) { $Engine = "$($config.engine)" }
if (-not $Python -and -not $Engine -and $config) { $Python = "$($config.python)" }
if ($Port -le 0) { $Port = $(if ($config -and $config.port) { [int]$config.port } else { 8787 }) }
if (-not $RepoRoot -and $config) { $RepoRoot = "$($config.repoRoot)" }
$HealthUrl = "http://127.0.0.1:$Port/api/health"

function Get-Health {
    # Raw HttpWebRequest with the proxy off: Invoke-RestMethod can block past
    # its timeout in a hidden task session.
    try {
        # A non-200 reply is cut at DefaultMaximumErrorResponseLength (64 KB) and the
        # health body is 72-76 KB: a live 503 parsed as silence (2026-10-31). Bounded
        # at 4 MB (the unit is KB).
        [Net.HttpWebRequest]::DefaultMaximumErrorResponseLength = 4096
        $req = [Net.HttpWebRequest]::Create($HealthUrl)
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
    return @{ answered = $true; live = ($h.live -eq $true); healthy = ($h.healthy -eq $true) }
}

if ($Once) {
    $h = Get-Health
    $saved = $null
    try { $saved = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
    $alive = [bool]($saved -and (Get-DaemonProcess ([int]$saved.pid) $Python))
    Say ("daemon process: {0}; answering: {1}; scheduler live: {2}; protection healthy: {3}" -f `
        $(if ($alive) { "pid $($saved.pid)" } else { 'not running' }), [bool]$h.answered, [bool]$h.live, [bool]$h.healthy)
    if ($h.answered -and $h.live) { exit 0 } else { exit 1 }
}

# --- one instance ------------------------------------------------------------
[void](New-Item -ItemType Directory -Path $StateRoot -Force)
$mutex = New-Object Threading.Mutex($false, 'Local\JarvisNativeService')
$owned = $false
try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
if (-not $owned) { return }

if ($Engine) {
    if (-not (Test-Engine $Engine)) { Say "the configured program is missing ($Engine) -- run -Install again"; exit 1 }
} else {
    if (-not (Test-Python $Python)) { Say "no usable Python configured ($Python) -- run -Install again"; exit 1 }
    if (-not $RepoRoot -or -not (Test-Path -LiteralPath (Join-Path $RepoRoot 'jarvis\__main__.py'))) {
        Say "no jarvis package under '$RepoRoot' -- run -Install again"; exit 1
    }
}

$st = @{ startedAt = (Now); checkedAt = 0; pid = 0; daemonStartedAt = 0; healthy = $null
         firstFailure = 0; lastAction = ''; lastActionAt = 0; restarts = @(); gaveUp = $false
         paused = $false; port = $Port; python = $Python; engine = $Engine; repoRoot = $RepoRoot }
try {
    $saved = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json
    $st.restarts = @($saved.restarts | Where-Object { $_ })
    # Adopt a daemon a previous instance of this loop started, if it is still it.
    if (Get-DaemonProcess ([int]$saved.pid) $Python) {
        $st.pid = [int]$saved.pid; $st.daemonStartedAt = [long]$saved.daemonStartedAt
        Say "adopted the running daemon (pid $($st.pid))"
    }
} catch { }

function Restart-Allowed {
    $now = Now
    $st.restarts = @($st.restarts | Where-Object { $_ -gt $now - 900 })
    if ($st.restarts.Count -ge $RestartBudget) {
        if (-not $st.gaveUp) {
            $st.gaveUp = $true
            Say "restart budget spent ($RestartBudget in 15 min) -- not starting again; needs a human"
        }
        return $false
    }
    if ($st.restarts.Count -and $now - ($st.restarts | Measure-Object -Maximum).Maximum -lt $RestartGap) { return $false }
    return $true
}

function Start-Daemon([string]$why) {
    if (-not (Restart-Allowed)) { return }
    $st.restarts = @($st.restarts) + (Now)
    $st.lastAction = "starting the daemon: $why"; $st.lastActionAt = (Now)
    Say $st.lastAction
    if ($DryRun) { return }
    # Keep the previous run's output: it is usually the reason for this start.
    foreach ($name in @('daemon.out.log', 'daemon.err.log')) {
        $f = Join-Path $StateRoot $name
        if (Test-Path -LiteralPath $f) { Move-Item -LiteralPath $f -Destination ($f + '.1') -Force -ErrorAction SilentlyContinue }
    }
    try {
        # -u: unbuffered, so the log shows what happened right up to a crash
        # (the compiled program is built unbuffered).
        if ($Engine) { $file = $Engine; $argv = @('serve', '--port', "$Port") }
        else { $file = $Python; $argv = @('-u', '-m', 'jarvis', 'serve', '--port', "$Port") }
        $p = Start-Process -FilePath $file -ArgumentList $argv `
            -WorkingDirectory $RepoRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $StateRoot 'daemon.out.log') `
            -RedirectStandardError (Join-Path $StateRoot 'daemon.err.log')
        $st.pid = $p.Id; $st.daemonStartedAt = (Now)
    } catch {
        $st.pid = 0
        Say "could not start the daemon: $($_.Exception.Message)"
    }
}

function Test-Paused {
    $f = Join-Path $StateRoot 'pause'
    if (-not (Test-Path -LiteralPath $f)) { return $false }
    $until = 0
    try { $until = [long]((Get-Content -LiteralPath $f -TotalCount 1) -as [long]) } catch { }
    if ($until -and (Now) -ge $until) {
        Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
        Say "maintenance pause expired -- supervising again"
        return $false
    }
    return $true
}

while ($true) {
    $now = Now
    $st.checkedAt = $now
    $paused = Test-Paused
    if ($paused -ne [bool]$st.paused) {
        Say $(if ($paused) { 'paused for maintenance -- checking only' } else { 'maintenance pause lifted' })
        # Lifting a pause is a person acting: if the budget had run out before,
        # supervise again. The restart budget itself still applies.
        if (-not $paused -and $st.gaveUp) { $st.gaveUp = $false; Say 'supervising again after the pause (restart budget still applies)' }
    }
    $st.paused = $paused

    $running = [bool](Get-DaemonProcess $st.pid $Python)
    $h = Get-Health
    if ($h.answered -and $h.live) {
        if ($st.healthy -eq $false) { Say "JARVIS answering again after $($now - [long]$st.firstFailure)s" }
        $st.healthy = $true; $st.firstFailure = 0; $st.gaveUp = $false
    } else {
        if ($st.healthy -ne $false) { $st.firstFailure = $now }
        $st.healthy = $false
        $age = $now - [long]$st.firstFailure
        if (-not $paused -and -not $st.gaveUp) {
            if (-not $running) {
                if ($h.answered) {
                    # Something this loop did not start holds the port. Starting
                    # a second daemon would only fail to bind; say so instead.
                    if ($st.lastAction -ne 'port answered by a daemon this loop did not start') {
                        $st.lastAction = 'port answered by a daemon this loop did not start'; $st.lastActionAt = $now
                        Say $st.lastAction
                    }
                } else {
                    Start-Daemon $(if ($st.pid) { "process $($st.pid) has exited" } else { 'not running' })
                }
            } elseif ($age -ge $HungAfter -and ($now - [long]$st.daemonStartedAt) -ge $StartGrace -and (Restart-Allowed)) {
                $why = "$(if ($h.answered) { 'scheduler stalled' } else { 'silent' }) for ${age}s"
                Say "stopping the daemon (pid $($st.pid)): $why"
                if (-not $DryRun) { [void](Stop-Daemon $st.pid $Python) }
                Start-Daemon $why
            }
        }
    }

    Save-Json $st $statePath
    if ($MaxSeconds -and $now - [long]$st.startedAt -ge $MaxSeconds) { return }
    Start-Sleep -Seconds $Interval
}

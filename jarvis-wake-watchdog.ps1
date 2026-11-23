# The outermost watchdog: the one that runs when WSL is not.
#
# Everything else that keeps jarvis alive lives *inside* the distro --
# systemd's Restart=always, the sd_notify watchdog, jarvis-selfcheck.timer.
# All of it is gone the moment the WSL utility VM stops, and nothing inside a
# stopped VM can start it again. This script is the layer that can: registered
# as a scheduled task that fires at logon and every five minutes forever, it
#
#   1. starts the distro if it is not running,
#   2. restarts jarvis.service if the distro is up but the unit is not,
#   3. rebuilds the Windows interop bridge (wsl --shutdown) if /mnt/c has
#      wedged -- the failure that blinds every Windows-side collector and, left
#      alone, feeds this watchdog garbage readings of its own,
#   4. re-stages itself from the in-repo copy so a `git pull` reaches the
#      deployed task without a reinstall,
#   5. writes one line per run so a repeating failure is visible afterwards.
#
# It is deliberately dumb and side-effect-light. It does not parse findings or
# send mail -- jarvis does that better from the inside, and a watchdog that can
# itself fail in interesting ways is not a watchdog. Every corrective action is
# gated on two consecutive confirmations and rate-limited so a transient blip
# can never turn into a restart or shutdown loop.
#
#   .\jarvis-wake-watchdog.ps1            one check now
#   .\jarvis-wake-watchdog.ps1 -Install   register the repeating task (no elevation)
#   .\jarvis-wake-watchdog.ps1 -Remove    unregister it

param(
    [switch]$Install,
    [switch]$Remove,
    [string]$Distro = 'Ubuntu',
    [string]$TaskName = 'jarvis wake watchdog',
    # WSL path of the jarvis checkout, e.g. /home/chris/jarvis. When set, each
    # run compares this script against <RepoRoot>/jarvis-wake-watchdog.ps1 and copies the
    # repo version over itself if they differ. install.sh bakes it in.
    [string]$RepoRoot = '',
    # Rebuild the interop bridge with `wsl --shutdown` when /mnt/c is unreadable.
    #
    # Typed as [string], not [bool], on purpose. Under -File every argument
    # reaches the script as a string, and the [bool] binder rejects most of
    # the forms a scheduled-task action can carry -- including the colon form
    # this script used to register. The task then exits 1 on every run, before
    # its first line of work, so nothing is logged and the watchdog is dead
    # while Task Scheduler still reports it Ready. Parse the value here
    # instead, where the failure cannot be silent.
    [string]$RecoverInterop = 'true'
)

# Anything but an explicit off value means on, so a malformed argument fails
# towards doing the recovery rather than silently skipping it.
$RecoverInteropOff = @('0', 'false', 'no', 'off', '$false')
$RecoverInteropOn  = -not ($RecoverInteropOff -contains $RecoverInterop.Trim().ToLower())

$ErrorActionPreference = 'Continue'
$logDir = Join-Path $env:LOCALAPPDATA 'WSLKeepalive'
$log    = Join-Path $logDir 'jarvis-wake.log'
$self   = $MyInvocation.MyCommand.Path

function Say($m) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Write-Host $line
    try {
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -Path $log -Value $line
        # Keep the log from growing without bound; this runs every 5 minutes.
        if ((Get-Item $log).Length -gt 1MB) {
            (Get-Content $log -Tail 2000) | Set-Content $log
        }
    } catch { }
}

# Run a scriptblock with a hard wall-clock ceiling. A wedged 9p mount does not
# fail fast -- a stat on /mnt/c hangs -- so every probe that crosses into the
# distro has to be able to give up. Returns @{ ok = <finished?>; out = <value> }.
function Invoke-WithTimeout([scriptblock]$Body, [int]$Seconds) {
    $j = Start-Job -ScriptBlock $Body
    if (Wait-Job $j -Timeout $Seconds) {
        $out = Receive-Job $j
        Remove-Job $j -Force -ErrorAction SilentlyContinue
        return @{ ok = $true; out = $out }
    }
    Stop-Job $j -ErrorAction SilentlyContinue
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    return @{ ok = $false; out = $null }
}

# --- install / remove ------------------------------------------------------
if ($Install -or $Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($Remove) { Say "removed task '$TaskName'"; return }

    # RunLevel Limited is load-bearing: asking for Highest makes registration
    # itself require an elevated shell and fails with 0x80070005. Starting WSL
    # and restarting a unit inside it need no admin rights.
    $argline = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass ' +
               '-File "' + $self + '" -Distro "' + $Distro + '"'
    if ($RepoRoot) { $argline += ' -RepoRoot "' + $RepoRoot + '"' }
    # Pass the value as its own token, not with a colon. Under -File every
    # argument arrives as a string, and the [bool] binder rejects the colon
    # form outright -- `-RecoverInterop:True` fails with "Cannot process
    # argument transformation", so the task exits 1 before its first line of
    # work and the failure is invisible in the log it never reaches.
    $argline += " -RecoverInterop $RecoverInterop"
    # conhost --headless: -WindowStyle Hidden alone still flashes a console window each run.
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" `
        -Argument ('--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" + '" ' + $argline)

    # Two triggers: at logon, and every five minutes forever afterwards.
    $atLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    # RepetitionDuration wants a finite, in-range value. Both idioms for
    # "forever" are rejected by Task Scheduler with 0x80041318: MaxValue
    # serialises to P99999999DT23H59M59S and Zero to PT0S, and this build
    # accepts neither. Ten years is finite, valid, and long enough that the
    # distinction stops mattering.
    $repeat  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                 -RepetitionInterval (New-TimeSpan -Minutes 5) `
                 -RepetitionDuration (New-TimeSpan -Days 3650)

    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
                   -LogonType Interactive -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                   -DontStopIfGoingOnBatteries -StartWhenAvailable `
                   -MultipleInstances IgnoreNew `
                   -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Trigger @($atLogon, $repeat) -Principal $principal -Settings $settings `
        -Description 'Starts WSL, jarvis.service and the interop bridge if any has stopped' | Out-Null

    # Verify rather than assume. $ErrorActionPreference is Continue, so a failed
    # registration would otherwise be followed by a cheerful success message --
    # and a watchdog you believe is installed but is not is worse than none.
    $check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $check) {
        Say "FAILED to register task '$TaskName'"
        exit 1
    }
    Say "registered task '$TaskName' [$($check.State)] (at logon + every 5 min)"
    return
}

# --- 1. is the distro up? ------------------------------------------------------
# `wsl -l --running` is the cheap way to ask whether the VM is up. It does not
# start the distro as a side effect, which matters: a probe that starts what it
# is measuring can never report a problem.
#
# wsl.exe writes its listing as UTF-16LE. Read with the default console
# encoding it comes back as "U b u n t u" -- every character separated by the
# decoded NUL half of each code unit -- so a plain -match on the distro name
# silently never matches. That failure mode is worse than useless here: the
# watchdog would conclude WSL was down on every single run, try to start an
# already-running distro forever, and never reach the jarvis.service check
# below. Force the encoding for the call and restore it afterwards.
function Get-RunningDistros {
    $prev = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        return ((& wsl.exe -l --running) -join ' ')
    } finally {
        [Console]::OutputEncoding = $prev
    }
}

$running = Get-RunningDistros
if ($running -notmatch [regex]::Escape($Distro)) {
    Say "distro '$Distro' is NOT running -- starting it"
    & wsl.exe -d $Distro --exec /bin/true 2>&1 | Out-Null
    Start-Sleep -Seconds 10
    $running = Get-RunningDistros
    if ($running -notmatch [regex]::Escape($Distro)) {
        Say "FAILED to start '$Distro'"
        exit 1
    }
    Say "'$Distro' started; systemd will bring jarvis.service up"
}

# --- 2. keep the deployed copy in step with the repo -------------------------
# The task action points at this file wherever it was registered from -- a copy
# under %LOCALAPPDATA%, because a script that lives inside the distro cannot be
# read while the distro is down, which is exactly when this has to run. That
# copy otherwise drifts from the checkout forever. Reconcile it here: read the
# repo version over the \\wsl.localhost share (independent of /mnt/c), and if it
# differs and still looks like this script, overwrite and re-register.
if ($RepoRoot) {
    try {
        $rel = ($RepoRoot -replace '/', '\').TrimEnd('\')
        $unc = "\\wsl.localhost\$Distro$rel\jarvis-wake-watchdog.ps1"
        if (-not (Test-Path -LiteralPath $unc)) {
            $unc = "\\wsl`$\$Distro$rel\jarvis-wake-watchdog.ps1"
        }
        $repoTxt = (Get-Content -LiteralPath $unc -Raw -ErrorAction Stop)
        $mine    = (Get-Content -LiteralPath $self -Raw -ErrorAction Stop)
        $norm    = { param($s) ($s -replace "`r`n", "`n").TrimEnd() }
        if ($repoTxt.Length -gt 1500 -and
            $repoTxt -match 'jarvis wake watchdog' -and
            $repoTxt -match 'needs a human' -and
            (& $norm $repoTxt) -ne (& $norm $mine)) {
            Set-Content -LiteralPath $self -Value $repoTxt -NoNewline -Encoding UTF8
            Say "re-staged from repo ($($repoTxt.Length) chars) -- re-registering task"
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
                -File $self -Install -Distro $Distro -RepoRoot $RepoRoot `
                -RecoverInterop $RecoverInterop 2>&1 | Out-Null
            exit 0
        }
    } catch {
        Say "self-sync skipped: $($_.Exception.Message)"
    }
}

# --- 3. is jarvis.service up? -----------------------------------------------
# `systemctl is-active` is read via its own output, not `2>&1`: merging stderr
# folds any stray warning line into the value and makes a healthy unit read as
# "not active", and this task runs every five minutes -- a false negative here
# is a restart loop that kills every in-flight collector and leaves them
# permanently "stale" while the unit itself never actually stopped. Take the
# last non-empty line, and treat the transient states systemd passes through
# during a legitimate restart as healthy so we do not race our own backstop.
# The states `systemctl is-active` can print. Anything else on its output is
# not a unit state: when wsl.exe itself cannot reach the WSL service it prints
# "error code: wsl/service/0x8007274c" (WSAETIMEDOUT) on stdout, and reading
# that as "the unit is not active" made this watchdog restart a running daemon
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
    $raw = (& wsl.exe -d $Distro --exec systemctl is-active jarvis.service 2>$null)
    # Wrap the whole pipeline in @(), not just $raw. A pipeline that emits one
    # item returns that item, not a one-element array, so $lines[-1] indexed
    # the last *character* of "active" and [char] has no ToLower() in Windows
    # PowerShell. The method-not-found exception left the function returning
    # nothing, the caller read that as "the unit is not running", and the
    # watchdog restarted a healthy daemon every five minutes.
    return ConvertTo-UnitState (@($raw) -join "`n")
}

# Read it until it answers. An empty result means the query itself failed --
# wsl.exe was busy, or the interop call was re-entered -- and that is not the
# same claim as "the unit is stopped". Restarting on an unreadable state is
# how a watchdog becomes the outage: it fires every five minutes and kills
# every in-flight collector on a unit that never stopped.
function Get-UnitStateConfirmed($tries = 3, $gapSeconds = 5) {
    for ($i = 1; $i -le $tries; $i++) {
        $s = Get-UnitState
        if ($s -ne '') { return $s }
        if ($i -lt $tries) { Start-Sleep -Seconds $gapSeconds }
    }
    return ''
}

$healthy = @('active', 'activating', 'reloading')
$state = Get-UnitStateConfirmed
if ($state -eq '') {
    # Could not read the state at all. Say so and leave the unit alone; the
    # next tick is five minutes away and systemd's own Restart=always still
    # covers an actual crash in the meantime.
    Say "could not read jarvis.service state after 3 attempts -- not restarting on an unknown state"
}
elseif ($healthy -notcontains $state) {
    # One bad read is not enough. Confirm it 5s later before acting, so a
    # restart we (or jarvis-selfcheck.timer) triggered a moment ago is not
    # counted twice.
    Start-Sleep -Seconds 5
    $state = Get-UnitStateConfirmed
    if ($state -ne '' -and $healthy -notcontains $state) {
        Say "jarvis.service is '$state' -- restarting"
        & wsl.exe -d $Distro --exec bash -lc 'if [ -x /usr/local/sbin/jarvis-restart-gate ]; then exec sudo -n /usr/local/sbin/jarvis-restart-gate --actor wake-watchdog --reason unit-down; fi; systemctl restart jarvis.service 2>/dev/null || sudo -n systemctl restart jarvis.service' 2>&1 | Out-Null
        Start-Sleep -Seconds 5
        $state2 = Get-UnitStateConfirmed
        if ($healthy -contains $state2) { Say "jarvis.service is '$state2' again" }
        else { Say "jarvis.service still '$state2' after restart -- needs a human"; exit 1 }
    }
}

# --- 4. is the Windows interop bridge alive? ------------------------------------
# When the 9p server behind /mnt/c wedges, every Windows-side collector goes
# blind and `wsl --shutdown` is the documented rebuild (see coverage.py). Doing
# that automatically is safe only if it cannot loop: require the bridge to read
# as broken on two consecutive runs (~>= 8 min), and never shut down twice
# inside 20 minutes.
if ($RecoverInteropOn) {
    $stampBad  = Join-Path $logDir 'interop-bad-since'
    $stampDown = Join-Path $logDir 'last-shutdown'

    $probe = Invoke-WithTimeout {
        & wsl.exe -d $using:Distro --exec test -r /mnt/c/Windows/System32/cmd.exe
        $LASTEXITCODE
    } 25
    $interopOk = $probe.ok -and ("$($probe.out)".Trim() -eq '0')

    if ($interopOk) {
        Remove-Item $stampBad -ErrorAction SilentlyContinue
    }
    else {
        if (-not (Test-Path $stampBad)) {
            Set-Content $stampBad (Get-Date -Format 'o')
            Say "interop probe failed (/mnt/c unreadable) -- watching, will rebuild next cycle if still broken"
        }
        else {
            $since = try { [datetime]::Parse((Get-Content $stampBad -Raw).Trim()) } catch { Get-Date }
            $badMin = [int]((Get-Date) - $since).TotalMinutes
            if ($badMin -ge 8) {
                $recent = $false
                if (Test-Path $stampDown) {
                    $last = try { [datetime]::Parse((Get-Content $stampDown -Raw).Trim()) } catch { [datetime]::MinValue }
                    if (((Get-Date) - $last).TotalMinutes -lt 20) {
                        $recent = $true
                        Say "interop STILL wedged ${badMin}m after a wsl --shutdown $([int]((Get-Date)-$last).TotalMinutes)m ago -- needs a human"
                    }
                }
                if (-not $recent) {
                    Say "interop bridge wedged ${badMin}m -- wsl --shutdown to rebuild it"
                    Set-Content $stampDown (Get-Date -Format 'o')
                    & wsl.exe --shutdown 2>&1 | Out-Null
                    Start-Sleep -Seconds 8
                    & wsl.exe -d $Distro --exec /bin/true 2>&1 | Out-Null
                    Start-Sleep -Seconds 12
                    $again = Invoke-WithTimeout {
                        & wsl.exe -d $using:Distro --exec test -r /mnt/c/Windows/System32/cmd.exe
                        $LASTEXITCODE
                    } 25
                    if ($again.ok -and "$($again.out)".Trim() -eq '0') {
                        Remove-Item $stampBad -ErrorAction SilentlyContinue
                        Say "interop rebuilt; /mnt/c readable again"
                    }
                    else {
                        Say "interop not readable yet -- systemd is bringing the distro back; next cycle re-checks"
                    }
                }
            }
        }
    }
}

exit 0

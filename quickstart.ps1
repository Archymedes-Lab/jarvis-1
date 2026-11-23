# Windows-side quickstart: the one layer that keeps JARVIS alive when WSL is not.
#
#   powershell -ExecutionPolicy Bypass -File .\quickstart.ps1
#       start the distro if needed, register the wake watchdog task (fires at
#       logon and every 5 min), and verify the dashboard answers
#
#   .\quickstart.ps1 -Distro Ubuntu -Port 8787     override the defaults
#   .\quickstart.ps1 -Remove                        unregister the wake task
#
#   .\quickstart.ps1 -Native [-Python C:\...\python.exe]
#       a machine without WSL: run the daemon on Windows itself (Python 3.12+)
#       under the native service task. Chosen automatically when this copy is
#       on a local drive and the distro does not exist. Linux-only audits are
#       reported as not applicable there; see docs/architecture/NATIVE-HOSTS.md
#
# No elevation required. Firewall logging and browser hardening are a separate,
# elevated step: .\scripts\harden\secure-internet.ps1 -Firewall  /  -Browsers
[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu',
    [int]$Port = 8787,
    [switch]$Remove,
    [switch]$Native,
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
function Say($m) { Write-Host "  $m" }

function Test-Distro {
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }
    # wsl.exe prints UTF-16; without the NULs removed no name ever matches.
    $names = ((& wsl.exe -l -q 2>$null) -join "`n") -replace "`0", ''
    return [bool]($names -split "`n" | Where-Object { $_.Trim() -eq $Distro })
}

function Wait-Dashboard {
    foreach ($i in 1..40) {
        try {
            $null = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1:$Port/api/live"
            return $true
        } catch { Start-Sleep -Seconds 1 }
    }
    return $false
}

$nativeService = Join-Path $here 'jarvis-native-service.ps1'
if (-not $Native -and $here -notlike '\\*' -and -not (Test-Distro)) {
    Say "no WSL distro '$Distro' on this machine - running JARVIS natively on Windows"
    $Native = $true
}
if ($Native) {
    if (-not (Test-Path -LiteralPath $nativeService)) { throw "jarvis-native-service.ps1 not found next to this script ($here)" }
    if ($Remove) { & $nativeService -Remove; return }
    Write-Host "`n1/2  Native service (scheduled task, no elevation)" -ForegroundColor Cyan
    $install = @{ Install = $true; RepoRoot = $here; Port = $Port }
    if ($Python) { $install.Python = $Python }
    & $nativeService @install
    if ($LASTEXITCODE) { throw "the native service was not installed (see the message above)" }
    Write-Host "`n2/2  Dashboard" -ForegroundColor Cyan
    if (Wait-Dashboard) { Say "up: http://127.0.0.1:$Port" }
    else { Say "dashboard not answering on :$Port yet - see $env:LOCALAPPDATA\Jarvis\NativeService\daemon.err.log" }
    Write-Host @"

  dashboard:  http://127.0.0.1:$Port
  status:     .\jarvis-native-service.ps1 -Once
  remove:     .\quickstart.ps1 -Native -Remove
  optional:   .\jarvis-health-monitor.ps1 -Install      (outage notice from outside the daemon)
              python -m jarvis sensor install           (native event sensor, one UAC prompt)
              python -m jarvis broker install           (elevated read-only collectors, one UAC prompt)
"@
    return
}

$wake = Join-Path $here 'jarvis-wake-watchdog.ps1'
if (-not (Test-Path -LiteralPath $wake)) { throw "jarvis-wake-watchdog.ps1 not found next to this script ($here)" }

if ($Remove) {
    $revive = Join-Path $here 'jarvis-reviver.ps1'
    if (Test-Path -LiteralPath $revive) { & $revive -Remove }
    & $wake -Remove -Distro $Distro
    return
}

Write-Host "`n1/3  Distro" -ForegroundColor Cyan
$running = (& wsl.exe -l --running) -join ' '
if ($running -notmatch [regex]::Escape($Distro)) {
    Say "'$Distro' is not running - starting it"
    & wsl.exe -d $Distro --exec /bin/true | Out-Null
}
$active = (& wsl.exe -d $Distro --exec systemctl is-active jarvis.service 2>$null | Out-String).Trim()
Say "jarvis.service: $active"
if ($active -ne 'active') {
    Say "asking systemd to start it"
    & wsl.exe -d $Distro --exec bash -lc 'if [ -x /usr/local/sbin/jarvis-restart-gate ]; then exec sudo -n /usr/local/sbin/jarvis-restart-gate --actor quickstart --reason unit-down; fi; systemctl restart jarvis.service 2>/dev/null || sudo -n systemctl restart jarvis.service' | Out-Null
}

Write-Host "`n2/3  Wake watchdog (scheduled task)" -ForegroundColor Cyan
# -RepoRoot lets each run reconcile the staged copy against this checkout, so a
# later `git pull` reaches the task without re-installing.
$repoRoot = (& wsl.exe -d $Distro --exec wslpath -a $here 2>$null | Out-String).Trim()
if (-not $repoRoot) { $repoRoot = $here }
& $wake -Install -Distro $Distro -RepoRoot $repoRoot
# The instant reviver: checks every few seconds and revives what has stopped.
$revive = Join-Path $here 'jarvis-reviver.ps1'
if (Test-Path -LiteralPath $revive) { & $revive -Install -Distro $Distro -RepoRoot $repoRoot }

Write-Host "`n3/3  Dashboard" -ForegroundColor Cyan
$ok = $false
foreach ($i in 1..20) {
    try {
        $null = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1:$Port/api/live"
        $ok = $true; break
    } catch { Start-Sleep -Seconds 1 }
}
if ($ok) { Say "up: http://127.0.0.1:$Port" }
else     { Say "dashboard not answering on :$Port yet - check 'journalctl -u jarvis.service' inside WSL" }

Write-Host @"

  dashboard:  http://127.0.0.1:$Port   (open the "ops & setup" tab)
  hardening:  .\scripts\harden\secure-internet.ps1 -Firewall   (elevated)
              .\scripts\harden\secure-internet.ps1 -Browsers
  remove:     .\quickstart.ps1 -Remove
"@

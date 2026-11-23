# The Windows service path, from source, on a clean Windows host: minutes, not
# the compiled build's quarter hour. It runs the same `native install` the Setup
# runs (task, daemon start, health, desktop pairing) and removes it again, so a
# start-up crash or a refused pairing fails the release run before the compile
# finishes. The compiled program is still tested by install_test.ps1.
#
#   powershell -File release/windows/source_smoke.ps1 -Python <python.exe>

param([Parameter(Mandatory = $true)][string]$Python)

$ErrorActionPreference = 'Stop'
$script:failed = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "PASS  $what" } else { Write-Host "FAIL  $what"; $script:failed++ }
}
function Run-Cli {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = (& $Python -m jarvis @args 2>&1 | ForEach-Object { "$_" } | Out-String); return @($LASTEXITCODE, $out) }
    finally { $ErrorActionPreference = $saved }
}

$state = Join-Path $env:LOCALAPPDATA 'Jarvis\NativeService'
$token = Join-Path $env:APPDATA 'local.jarvis.desktop\client.token'

Write-Host "== native install (from source)"
$code, $out = Run-Cli native install
Write-Host $out
Check ($code -eq 0) "native install exit code 0 (was $code)"
Check ([bool](Get-ScheduledTask -TaskName 'jarvis native service' -ErrorAction SilentlyContinue)) 'task registered'
Check ($out -match 'desktop app: paired') 'desktop app paired'
Check (Test-Path -LiteralPath $token) 'desktop token written'
if ($code -ne 0) {
    foreach ($f in 'install.log', 'service.log', 'daemon.err.log', 'daemon.out.log') {
        $p = Join-Path $state $f
        if (Test-Path -LiteralPath $p) { Write-Host "-- $f"; Get-Content -LiteralPath $p -Tail 60 | Out-Host }
    }
}

Write-Host "== status"
$code, $out = Run-Cli native status
Write-Host $out
Check ($out -match 'daemon process: pid') 'supervisor sees the daemon'

Write-Host "== native uninstall"
$code, $out = Run-Cli native uninstall
Write-Host $out
Check ($code -eq 0) "native uninstall exit code 0 (was $code)"
Check (-not (Get-ScheduledTask -TaskName 'jarvis native service' -ErrorAction SilentlyContinue)) 'task removed'
Check (-not (Test-Path -LiteralPath $token)) 'desktop token removed'

if ($script:failed) { Write-Host "$($script:failed) check(s) failed"; exit 1 }
Write-Host 'all checks passed'

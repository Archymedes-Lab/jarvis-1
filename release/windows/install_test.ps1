# Install, run, observe and remove the Windows edition on a clean Windows host
# (the windows-2025 runner: no WSL distribution, no previous install).
#
#   powershell -File release/windows/install_test.ps1 -Setup <ARGUS-INSTINCT-Setup-windows-x64.exe>
#
# Every check prints PASS or FAIL; the script exits 1 on any FAIL. What it shows:
#   1. the Setup installs per user and exits 0 only once the service answers;
#   2. the service is the registered per-user task, healthy and live;
#   3. the engine adapts to this host: the Linux-only checks are listed as not
#      applicable here, never as failing or healthy;
#   4. a positive control: a harmless autostart entry planted in the current
#      user's Run key is found by the compiled startup audit, and is gone from
#      it once removed (absent before, present while planted, absent after);
#   5. the uninstaller removes the task, the program, the uninstall entry and
#      the desktop app's token; the user's history is kept and reported.

param([Parameter(Mandatory = $true)][string]$Setup,
      [ValidateSet('all', 'supervisor', 'pause', 'app-open', 'budget', 'lifecycle')][string]$Scenario = 'all')

# CI runs one scenario per clean host, in parallel (.github/workflows/release.yml): the scenarios
# share the supervisor's restart budget, which only a fresh host gives back. 'all' (the default)
# is the original single-host run, in order. The install and its health checks run in every case.
#   supervisor  killed daemon, then killed supervisor loop (repeating trigger)
#   pause       maintenance pause
#   app-open    recovery with the real app window process running
#   budget      a daemon that keeps dying is not restarted forever
#   lifecycle   positive control, native stop, uninstall, reinstall + /PURGE
function Want([string]$name) { return ($Scenario -eq 'all' -or $Scenario -eq $name) }

$ErrorActionPreference = 'Stop'
$script:failed = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "PASS  $what" } else { Write-Host "FAIL  $what"; $script:failed++ }
}

$product = 'ARGUS-INSTINCT'
$install = Join-Path $env:LOCALAPPDATA "Programs\$product"
$engine = Join-Path $install 'engine\argus-instinct.exe'
$task = 'argus native service'
$uninstKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$product"
$appDir = Join-Path $env:APPDATA 'local.argus.desktop'
$probeName = 'ArgusInstallProbe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

function Health([int]$port) {
    try {
        $req = [Net.HttpWebRequest]::Create("http://127.0.0.1:$port/api/health")
        $req.Proxy = $null; $req.Timeout = 5000
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response }
        if (-not $resp) { return $null }
        $r = New-Object IO.StreamReader($resp.GetResponseStream())
        try { return ($r.ReadToEnd() | ConvertFrom-Json) } finally { $r.Dispose(); $resp.Dispose() }
    } catch { return $null }
}

# PowerShell 5.1 turns a native program's stderr into a terminating error under
# ErrorActionPreference=Stop: run the engine with Continue and keep its output.
function Run-Engine {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { return (& $engine @args 2>&1 | ForEach-Object { "$_" } | Out-String) }
    finally { $ErrorActionPreference = $saved }
}

function Boot-Findings {
    $out = Run-Engine boot --json
    $start = $out.IndexOf('[')
    if ($start -lt 0) { return @() }
    try { return @($out.Substring($start) | ConvertFrom-Json) } catch { return @() }
}

function Probe-Seen {
    return [bool](@(Boot-Findings | Where-Object { "$($_.detail)" -like "*$probeName*" }).Count)
}

Write-Host "== host"
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
$distros = if ($wsl) { (& wsl.exe --list --quiet 2>$null | Out-String).Trim() } else { '' }
Write-Host "Windows $([Environment]::OSVersion.Version); WSL distributions: $(if ($distros) { $distros } else { 'none' })"
Check (-not (Test-Path -LiteralPath $install)) 'no previous install'

Write-Host "== install (silent)"
$p = Start-Process -FilePath $Setup -ArgumentList '/S' -Wait -PassThru
Check ($p.ExitCode -eq 0) "Setup /S exit code 0 (was $($p.ExitCode))"
Check (Test-Path -LiteralPath $engine) 'engine installed per user'
Check (Test-Path -LiteralPath (Join-Path $install 'argus-desktop.exe')) 'desktop app installed'
Check (Test-Path -LiteralPath $uninstKey) 'uninstall entry for the current user'
# -Include is ignored with -LiteralPath: filter on the extension itself.
$scripts = @(Get-ChildItem -LiteralPath $install -Recurse -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -in '.py', '.pyc', '.ps1', '.cs' })
Check ($scripts.Count -eq 0) "no source or script files in the program folder ($($scripts.Count))"
$scripts | Select-Object -First 10 | ForEach-Object { Write-Host "      $($_.FullName)" }
$lnk = Join-Path ([Environment]::GetFolderPath('Programs')) "$product.lnk"
Check (Test-Path -LiteralPath $lnk) 'Start menu entry'

$setupLog = Join-Path $install 'install.log'
if (Test-Path -LiteralPath $setupLog) { Write-Host "-- the Setup's install step:"; Get-Content -LiteralPath $setupLog | Out-Host }
Write-Host "== service"
$t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
$state = Join-Path $env:LOCALAPPDATA 'Argus\NativeService'
if (-not $t) {
    # Diagnose before judging: what the Setup's own step would have printed.
    Write-Host "-- no task after Setup: running the install step by hand"
    $out = Run-Engine native install
    Write-Host $out
    Write-Host "-- native install exit code: $LASTEXITCODE"
    foreach ($f in 'service.log', 'daemon.err.log', 'daemon.out.log') {
        $pth = Join-Path $state $f
        if (Test-Path -LiteralPath $pth) { Write-Host "-- $f"; Get-Content -LiteralPath $pth -Tail 40 | Out-Host }
    }
    Check $false 'the Setup registered the service by itself'
    $t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
}
Check ([bool]$t) "scheduled task '$task' registered"
if ($t) { Check ($t.Principal.RunLevel -eq 'Limited') 'task runs without elevation' }
$port = 8787
$portFile = Join-Path $appDir 'port'
if (Test-Path -LiteralPath $portFile) { $port = [int](Get-Content -LiteralPath $portFile -TotalCount 1) }
$h = Health $port
if (-not ($h -and $h.live -eq $true)) {
    # Diagnose before judging: the service's own logs, then the engine in the
    # foreground on a spare port so a start-up failure prints its reason.
    Write-Host "-- health on port $port`: $(if ($h) { $h | ConvertTo-Json -Compress -Depth 3 } else { 'no answer' })"
    foreach ($f in 'install.log', 'service.log', 'daemon.err.log', 'daemon.out.log', 'service.json') {
        $pth = Join-Path $state $f
        if (Test-Path -LiteralPath $pth) { Write-Host "-- $f"; Get-Content -LiteralPath $pth -Tail 60 | Out-Host }
        else { Write-Host "-- $f (missing)" }
    }
    Get-CimInstance Win32_Process -Filter "Name = 'argus-instinct.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "-- running: $($_.ProcessId) $($_.ExecutablePath) :: $($_.CommandLine)" }
    $fgOut = Join-Path $env:TEMP 'argus-fg.out.log'; $fgErr = Join-Path $env:TEMP 'argus-fg.err.log'
    $fg = Start-Process -FilePath $engine -ArgumentList 'serve', '--port', '8799' -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $fgOut -RedirectStandardError $fgErr
    $fgh = $null
    for ($i = 0; $i -lt 30 -and -not $fg.HasExited; $i++) { Start-Sleep -Seconds 3; $fgh = Health 8799; if ($fgh -and $fgh.live -eq $true) { break } }
    Write-Host "-- foreground serve: exited=$($fg.HasExited) code=$(if ($fg.HasExited) { $fg.ExitCode } else { '-' }) health=$(if ($fgh) { $fgh | ConvertTo-Json -Compress -Depth 3 } else { 'no answer' })"
    if (-not $fg.HasExited) { Stop-Process -Id $fg.Id -Force -ErrorAction SilentlyContinue }
    foreach ($f in $fgOut, $fgErr) { if (Test-Path -LiteralPath $f) { Write-Host "-- $f"; Get-Content -LiteralPath $f -Tail 60 | Out-Host } }
}
Check ($h -and $h.service -eq 'ARGUS') "health answers as ARGUS on port $port"
Check ($h -and $h.live -eq $true) 'scheduler live'
Check (Test-Path -LiteralPath (Join-Path $appDir 'client.token')) 'desktop app paired (token written)'

Write-Host "== adapts to this host"
$status = Run-Engine native status --all
Write-Host $status
Check ($status -match 'not here\s+auditd\b') 'Linux-only audit listed as not applicable here'
Check ($status -match 'daemon process: pid') 'supervisor sees the daemon it started'
$welcome = Run-Engine welcome
Write-Host $welcome
Check ($welcome -match 'for Windows') "first-run statement chosen for native Windows"

if (Want 'lifecycle') {
Write-Host "== positive control: a planted autostart entry"
# A brand-new profile can lack the Run key itself.
if (-not (Test-Path -LiteralPath $runKey)) { New-Item -Path $runKey -Force | Out-Null }
Remove-ItemProperty -Path $runKey -Name $probeName -ErrorAction SilentlyContinue
Check (-not (Probe-Seen)) 'absent before planting (negative control)'
New-ItemProperty -Path $runKey -Name $probeName -Value 'cmd.exe /c exit' -PropertyType String -Force | Out-Null
try {
    Check (Probe-Seen) 'found by the compiled startup audit while planted'
} finally {
    Remove-ItemProperty -Path $runKey -Name $probeName -ErrorAction SilentlyContinue
}
Check (-not (Probe-Seen)) 'gone once removed'
}

Write-Host "== recovery and supervision (the service's supervisor loop; app closed, then open)"
# What is checked, and why in this order: the supervisor restarts at most 3 times in 15
# minutes (the install's own start counts), so scenarios that need a restart are spaced by
# Wait-Budget, and the last one spends the budget on purpose to show a crashing daemon is
# not restarted forever. Token and history are checked after every recovery.
$tokenFile = Join-Path $appDir 'client.token'
$tokenBefore = (Get-Content -LiteralPath $tokenFile -Raw)
$histDir = Join-Path $env:USERPROFILE '.argus'
New-Item -ItemType Directory -Force -Path $histDir | Out-Null
$marker = Join-Path $histDir 'recovery-marker'
Set-Content -LiteralPath $marker -Value 'kept'
$appExe = Join-Path $install 'argus-desktop.exe'
$pauseFile = Join-Path $state 'pause'

function Skip([string]$what, [string]$why) { Write-Host "SKIP  $what  [$why]" }
# The leading comma keeps the array: PowerShell unrolls a returned array, and on 5.1 a single
# CIM object has no .Count, so "exactly one" read as "()" and failed (run 41801062950).
function Daemon-Procs {
    return ,@(Get-CimInstance Win32_Process -Filter "Name='argus-instinct.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match ' serve ' })
}
function Supervisor-Procs {
    return ,@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'native-service' })
}
function Kill-Tree([int]$id) {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\taskkill.exe') -ArgumentList '/F', '/T', '/PID', "$id" `
        -Wait -WindowStyle Hidden | Out-Null
}
function Kill-Daemon { foreach ($p in (Daemon-Procs)) { Kill-Tree $p.ProcessId } }
# What the supervisor itself saw, printed whenever a recovery check fails: a red check
# without the service log cannot be told apart from a test mistake.
$script:shownAt = 0
function Show-Service([string]$label) {
    if ($script:failed -le $script:shownAt) { return }
    $script:shownAt = $script:failed
    Write-Host "----- after '$label': supervisor log, state, daemon errors"
    foreach ($n in @('service.log', 'state.json', 'daemon.err.log')) {
        $f = Join-Path $state $n
        if (Test-Path -LiteralPath $f) { Write-Host "--- $n"; Get-Content -LiteralPath $f -Tail 40 | ForEach-Object { Write-Host "    $_" } }
    }
    Write-Host ("--- processes: daemons {0}, supervisor loops {1}; task state {2}" -f (Daemon-Procs).Count, (Supervisor-Procs).Count,
        $((Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue).State))
    Write-Host "-----"
}
function Wait-Until([scriptblock]$cond, [int]$seconds, [int]$every = 2) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) { if (& $cond) { return $true }; Start-Sleep -Seconds $every }
    return [bool](& $cond)
}
function Up { $hh = Health $port; return [bool]($hh -and $hh.live -eq $true) }
function Down { return -not (Health $port) }
function Authed-Code {
    try {
        $req = [Net.HttpWebRequest]::Create("http://127.0.0.1:$port/api/pulse")
        $req.Proxy = $null; $req.Timeout = 20000
        $req.Headers.Add('X-ARGUS-Token', (Get-Content -LiteralPath $tokenFile -Raw).Trim())
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response }
        if (-not $resp) { return 0 }
        $code = [int]$resp.StatusCode
        $resp.Dispose()
        return $code
    } catch { return 0 }
}
function Restarts-In-Window {
    try {
        $s = Get-Content -LiteralPath (Join-Path $state 'state.json') -Raw | ConvertFrom-Json
        $nowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        return @($s.restarts | Where-Object { $_ -and $_ -gt $nowUnix - 900 }).Count
    } catch { return 0 }
}
function Wait-Budget {
    # Let restarts age out of the supervisor's 15-minute window so the next scenario is allowed one.
    Write-Host "      (waiting for the supervisor's restart window: $(Restarts-In-Window) restart(s) in the last 15 min)"
    [void](Wait-Until { (Restarts-In-Window) -le 1 } 960 15)
}
function Intact([string]$label) {
    Check ((Get-Content -LiteralPath $tokenFile -Raw) -eq $tokenBefore -and (Authed-Code) -eq 200) "$label`: the same token still works"
    Check (Test-Path -LiteralPath $marker) "$label`: history is intact"
}
function App-Check {
    $a = Start-Process -FilePath $appExe -ArgumentList '--check' -Wait -PassThru -WindowStyle Hidden
    return $a.ExitCode
}

Check ((Daemon-Procs).Count -eq 1) "one daemon process before the scenarios ($((Daemon-Procs).Count))"
Check ((Supervisor-Procs).Count -ge 1) "the supervisor loop is running ($((Supervisor-Procs).Count) process(es))"

if (Want 'supervisor') {
# 1. App closed: the supervisor alone brings a killed daemon back.
$t0 = Get-Date
Kill-Daemon
Check (Wait-Until { Down } 30) 'supervisor (app closed): the daemon is really down'
$back = Wait-Until { Up } 150 3
Check $back "supervisor (app closed): the daemon is back after $([int]((Get-Date) - $t0).TotalSeconds) s"
Check ((Daemon-Procs).Count -eq 1) "supervisor (app closed): exactly one daemon ($((Daemon-Procs).Count))"
Intact 'supervisor (app closed)'
Show-Service 'supervisor (app closed)'

# 2. The supervisor itself dies, the daemon lives on: the repeating trigger revives the loop (at most ~5 min).
# Only the loop's own process: taskkill /T would take its child, the daemon, with it.
foreach ($p in (Supervisor-Procs)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 3
Check ((Supervisor-Procs).Count -eq 0) 'watchdog: the supervisor loop was killed'
Check (Up) 'watchdog: the daemon keeps answering without its supervisor'
$revived = Wait-Until { (Supervisor-Procs).Count -ge 1 } 420 5
Check $revived 'watchdog: the task starts the supervisor loop again (repeating trigger)'
Check ((Supervisor-Procs).Count -eq 1) "watchdog: exactly one supervisor loop ($((Supervisor-Procs).Count))"
Check ((Daemon-Procs).Count -eq 1 -and (Up)) 'watchdog: still exactly one daemon, and it answers'
Intact 'watchdog (supervisor revived)'
Show-Service 'watchdog (supervisor revived)'
}

if (Want 'pause') {
# 3. Maintenance pause: nothing is started while it exists, by the supervisor or by the app.
Set-Content -LiteralPath $pauseFile -Value ''
Start-Sleep -Seconds 8
Kill-Daemon
Check (Wait-Until { Down } 30) 'pause: the daemon is down'
Start-Sleep -Seconds 75
Check ((Down) -and (Daemon-Procs).Count -eq 0) 'pause: the supervisor leaves it down for more than a minute'
$code = App-Check
Check ($code -eq 3 -and (Down) -and (Daemon-Procs).Count -eq 0) "pause: the app does not start it either (app check exit $code)"
Remove-Item -LiteralPath $pauseFile -Force
Check (Wait-Until { Up } 180 3) 'pause: lifting it brings the daemon back'
Check ((Daemon-Procs).Count -eq 1) "pause: exactly one daemon ($((Daemon-Procs).Count))"
Intact 'pause'
Show-Service 'pause'
}

if (Want 'app-open') {
# 4. App open: the real app window process is running while the daemon dies.
Wait-Budget
$proc = Start-Process -FilePath $appExe -ArgumentList '--hidden' -PassThru
Start-Sleep -Seconds 25
if ($proc.HasExited) {
    Skip 'recovery (app open)' "the app exited with $($proc.ExitCode) within 25 s: this host may have no usable desktop session or WebView2, so the window itself was not exercised"
} else {
    Write-Host "NOTE  the app window process stayed up for 25 s here (WebView2 and a desktop session exist)"
    $t0 = Get-Date
    Kill-Daemon
    Check (Wait-Until { Down } 30) 'recovery (app open): the daemon is really down'
    Check (Wait-Until { Up } 200 3) "recovery (app open): monitoring resumes after $([int]((Get-Date) - $t0).TotalSeconds) s"
    Check (Wait-Until { (Daemon-Procs).Count -eq 1 } 30) "recovery (app open): exactly one daemon, the app and the supervisor did not both start one ($((Daemon-Procs).Count))"
    Intact 'recovery (app open)'
    Show-Service 'recovery (app open)'
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
}

if (Want 'budget') {
# 5. A daemon that keeps dying is not restarted forever: the budget is spent on purpose.
Wait-Budget
$stopped = $false
for ($i = 1; $i -le 5 -and -not $stopped; $i++) {
    Kill-Daemon
    Check (Wait-Until { Down } 30) "budget: kill $i - the daemon is down"
    if (-not (Wait-Until { Up } 150 3)) { $stopped = $true }
}
Check $stopped 'budget: after a few restarts the supervisor stops restarting a daemon that keeps dying'
$svcLog = ''
if (Test-Path -LiteralPath (Join-Path $state 'service.log')) { $svcLog = (Get-Content -LiteralPath (Join-Path $state 'service.log') -Tail 300 | Out-String) }
Check ($svcLog -match 'restart budget spent') 'budget: the supervisor says why in its log'
Check ((Supervisor-Procs).Count -ge 1) 'budget: the supervisor itself is still running'
Check ((Daemon-Procs).Count -eq 0) 'budget: no restart loop - nothing was started past the budget'
Show-Service 'budget: no restart loop - nothing was started past the budget'
}

if (Want 'lifecycle') {
# 6. `native stop` (what an upgrade or removal runs) leaves it stopped, and the app does not undo it.
$o = Run-Engine native stop
Write-Host $o
Check (-not (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)) 'stop: the service task is gone'
Check ((Supervisor-Procs).Count -eq 0) 'stop: the supervisor loop is gone'
$code = App-Check
Start-Sleep -Seconds 20
Check ($code -eq 3 -and (Down) -and (Daemon-Procs).Count -eq 0) "stop: the app does not start a second copy (app check exit $code)"
Check ((Test-Path -LiteralPath $tokenFile) -and ((Get-Content -LiteralPath $tokenFile -Raw) -eq $tokenBefore)) 'stop: the pairing is kept'
Check (Test-Path -LiteralPath $marker) 'stop: history is intact'
Show-Service 'stop: history is intact'

Write-Host "== uninstall (silent)"
$u = Start-Process -FilePath (Join-Path $install 'Uninstall.exe') -ArgumentList '/S', "_?=$install" -Wait -PassThru
Check ($u.ExitCode -eq 0) "uninstaller exit code 0 (was $($u.ExitCode))"
Remove-Item -LiteralPath (Join-Path $install 'Uninstall.exe') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $install -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Check (-not (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)) 'task removed'
Check (-not (Test-Path -LiteralPath $engine)) 'program removed'
Check (-not (Test-Path -LiteralPath $uninstKey)) 'uninstall entry removed'
Check (-not (Test-Path -LiteralPath (Join-Path $appDir 'client.token'))) 'desktop token removed'
Check (-not (Health $port)) 'nothing answers on the port any more'
Check (-not (Test-Path -LiteralPath $lnk)) 'Start menu entry removed'
Check (-not (Test-Path -LiteralPath $appDir)) "the app's settings and pairing folder removed"
Check (-not (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'local.argus.desktop'))) "the app's browser profile removed"
# A silent uninstall keeps the history (evidence) unless /PURGE is given.
Check ((Test-Path -LiteralPath $histDir) -and (Test-Path -LiteralPath $marker)) 'silent uninstall keeps the history'

Write-Host "== reinstall, then uninstall with /PURGE"
$p = Start-Process -FilePath $Setup -ArgumentList '/S' -Wait -PassThru
Check ($p.ExitCode -eq 0) "reinstall: Setup /S exit code 0 (was $($p.ExitCode))"
Check (Test-Path -LiteralPath $marker) 'reinstall: the kept history is still there'
$u = Start-Process -FilePath (Join-Path $install 'Uninstall.exe') -ArgumentList '/S', '/PURGE', "_?=$install" -Wait -PassThru
Check ($u.ExitCode -eq 0) "purge: uninstaller exit code 0 (was $($u.ExitCode))"
Remove-Item -LiteralPath (Join-Path $install 'Uninstall.exe') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $install -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Check (-not (Test-Path -LiteralPath $histDir)) 'purge: the history is deleted'
Check (-not (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Argus'))) "purge: the service's logs are deleted"
Check (-not (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)) 'purge: task removed'
Check (-not (Health $port)) 'purge: nothing answers on the port'
}

if ($script:failed) { Write-Host "$($script:failed) check(s) failed"; exit 1 }
Write-Host 'all checks passed'

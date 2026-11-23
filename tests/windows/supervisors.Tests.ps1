# Regression checks for the Windows supervisors' outage decisions.
# Run by tests/test_windows_supervisors.py. Never touches live supervisor
# state: every run uses -StateRoot under -Work, toasts and mail are captured to
# a file, and the health endpoint is a one-shot stub on a test port.
param([Parameter(Mandatory=$true)][string]$Dir, [Parameter(Mandatory=$true)][string]$Work)
$ErrorActionPreference = 'Stop'
$script:fail = 0
function Check([bool]$ok, [string]$name) { if (-not $ok) { $script:fail++; Write-Output "FAIL: $name" } }

# --- reviver decisions, loaded from the real script ------------------------
$StartGrace = 300; $KickMin = 30; $KickMax = 600
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Dir 'jarvis-reviver.ps1'), [ref]$null, [ref]$null)
$wanted = 'ConvertTo-UnitAge','ConvertTo-UnitState','Test-StartGrace','Test-ShouldKick','Get-KickWait'
foreach ($f in $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($wanted -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
foreach ($n in $wanted) { Check ([bool](Get-Command $n -ErrorAction SilentlyContinue)) "reviver defines $n" }

Check ((ConvertTo-UnitAge '4300.25 4000000000') -eq 300) 'unit age from uptime and monotonic start'
Check ((ConvertTo-UnitAge "sh: warning`n4300.25 4000000000") -eq 300) 'unit age ignores leading noise'
Check ($null -eq (ConvertTo-UnitAge '100.0 0')) 'never-active unit has no age'
Check ($null -eq (ConvertTo-UnitAge '10.0 20000000')) 'start after uptime is not an age'
Check ($null -eq (ConvertTo-UnitAge 'garbage')) 'unparseable output has no age'
Check ($null -eq (ConvertTo-UnitAge '')) 'empty output has no age'

# Unit state: only a real systemctl state is a state. wsl.exe prints its own
# service timeout on stdout; read as a state it restarted a running daemon.
function Test-UnitStateParser([string]$who) {
    Check ((ConvertTo-UnitState "active") -eq 'active') "$who`: active"
    Check ((ConvertTo-UnitState "warning: x`nFailed`n") -eq 'failed') "$who`: last line, case-folded"
    Check ((ConvertTo-UnitState "inactive`r`n") -eq 'inactive') "$who`: CRLF inactive"
    Check ((ConvertTo-UnitState 'error code: wsl/service/0x8007274c') -eq '') "$who`: WSL timeout is unknown, not stopped"
    Check ((ConvertTo-UnitState "active`nerror code: wsl/service/0x8007274c") -eq '') "$who`: trailing WSL error is unknown"
    Check ((ConvertTo-UnitState 'The Windows Subsystem for Linux has not been enabled.') -eq '') "$who`: WSL banner is unknown"
    Check ((ConvertTo-UnitState '') -eq '') "$who`: empty is unknown"
}
Test-UnitStateParser 'reviver'
$wakeAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Dir 'jarvis-wake-watchdog.ps1'), [ref]$null, [ref]$null)
$wakeFn = @($wakeAst.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'ConvertTo-UnitState' }, $true))
Check ($wakeFn.Count -eq 1) 'wake watchdog defines ConvertTo-UnitState'
if ($wakeFn.Count -eq 1) { . ([scriptblock]::Create($wakeFn[0].Extent.Text)); Test-UnitStateParser 'wake watchdog' }
$wakeText = Get-Content -LiteralPath (Join-Path $Dir 'jarvis-wake-watchdog.ps1') -Raw
Check ($wakeText -match 'return ConvertTo-UnitState') 'wake watchdog reads unit state through the parser'
$reviverText = Get-Content -LiteralPath (Join-Path $Dir 'jarvis-reviver.ps1') -Raw
Check ($reviverText -match 'return ConvertTo-UnitState') 'reviver reads unit state through the parser'

Check (Test-StartGrace 0) 'just started is in grace'
Check (Test-StartGrace 299) 'under grace holds'
Check (-not (Test-StartGrace 300)) 'grace ends at StartGrace'
Check (-not (Test-StartGrace $null)) 'unknown age gives no grace'

$now = 1000000
Check (-not (Test-ShouldKick 'native' 'partial' 0 30 $now)) 'partial source is not re-run'
Check (-not (Test-ShouldKick 'scan' 'complete' 0 30 $now)) 'complete source is not re-run'
Check (-not (Test-ShouldKick 'storage' 'unavailable' 0 30 $now)) 'storage probe is not a job'
Check (Test-ShouldKick 'scan' 'stale' ($now - 30) 30 $now) 'stale source re-run after its wait'
Check (-not (Test-ShouldKick 'scan' 'stale' ($now - 29) 30 $now)) 'stale source waits out back-off'
Check (Test-ShouldKick 'veil' 'not_reporting' 0 600 $now) 'missing source re-run once wait elapsed'
Check ((Get-KickWait 0) -eq 30) 'first wait is KickMin'
Check ((Get-KickWait 30) -eq 60) 'wait doubles'
Check ((Get-KickWait 400) -eq 600) 'wait caps at KickMax'
Check ((Get-KickWait 600) -eq 600) 'wait stays at KickMax'

# --- health monitor, the real script with delivery mocked ------------------
$monitor = Get-Content -Raw -LiteralPath (Join-Path $Dir 'jarvis-health-monitor.ps1')
$marker = "[void](New-Item -ItemType Directory -Path `$StateRoot -Force)`r`n`$state=@{"
if ($monitor.IndexOf($marker) -lt 0) { $marker = $marker -replace "`r`n", "`n" }
Check ($monitor.IndexOf($marker) -ge 0) 'health monitor main body marker found'
$mocks = @'
function Get-JarvisHealth { $global:MockHealth }
function Get-Reviver { $global:MockReviver }
function Show-JarvisToast([string]$t,[string]$b) { Add-Content -LiteralPath $env:JARVIS_TEST_LOG -Value "toast|$t|$b" }
function Send-JarvisMail([string]$t,[string]$b) { Add-Content -LiteralPath $env:JARVIS_TEST_LOG -Value "mail|$t" }

'@
$i = $monitor.IndexOf($marker)
$copy = Join-Path $Work 'monitor-under-test.ps1'
Set-Content -LiteralPath $copy -Value ($monitor.Substring(0, $i) + $mocks + $monitor.Substring($i)) -Encoding UTF8
$root = Join-Path $Work 'state'; [void](New-Item -ItemType Directory -Force -Path $root)
$env:JARVIS_TEST_LOG = Join-Path $Work 'delivered.log'
$working = @{present=$true;active=$true;gaveUp=$false;paused=$false;action='';actionAt=0}
function Seed($extra) {
    $t = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $s = @{failures=1;firstFailure=$t-400;emailLevel=-1;toastLevel=-1;lastMailAttempt=0;lastToastAttempt=0;lastHealthy=0}
    foreach ($k in $extra.Keys) { $s[$k] = $extra[$k] }
    $s | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'state.json') -Encoding UTF8
}
function Run($health) {
    $global:MockHealth = $health; $global:MockReviver = $working
    if (Test-Path -LiteralPath $env:JARVIS_TEST_LOG) { Remove-Item -LiteralPath $env:JARVIS_TEST_LOG }
    & $copy -StateRoot $root -LegacyStateRoot (Join-Path $Work 'no-legacy') | Out-Null
    $log = if (Test-Path -LiteralPath $env:JARVIS_TEST_LOG) { @(Get-Content -LiteralPath $env:JARVIS_TEST_LOG) } else { @() }
    return @{ log = $log; state = (Get-Content -Raw -LiteralPath (Join-Path $root 'state.json') | ConvertFrom-Json) }
}
$degraded = @{healthy=$false;degraded=$true;reason='JARVIS is running but required coverage is degraded: native partial (The sensor cannot read Sysmon)'}
$down = @{healthy=$false;reason='JARVIS local health endpoint is unreachable'}
$ok = @{healthy=$true;reason='scheduler progress and required protection coverage verified'}

Seed @{stateError='Previous state was unreadable; outage confirmation restarted'}
$r = Run $degraded
Check (@($r.log | Where-Object { $_ -like 'toast|JARVIS coverage degraded|*' }).Count -eq 1) 'degraded coverage toasts as coverage degraded'
Check (@($r.log | Where-Object { $_ -like 'toast|*' -and $_ -like '*monitoring unavailable*' }).Count -eq 0) 'degraded coverage is not called unavailable'
Check (@($r.log | Where-Object { $_ -like '*cannot read Sysmon*' }).Count -eq 1) 'degraded toast names the source and reason'
Check (@($r.log | Where-Object { $_ -eq 'mail|[JARVIS] coverage degraded' }).Count -eq 1) 'degraded coverage is still mailed'
Check ($r.state.alertKind -eq 'degraded') 'alert kind recorded'
Check ($null -eq $r.state.stateError) 'stale unreadable-state note cleared on a clean read'

$r = Run $down
Check (@($r.log | Where-Object { $_ -like 'toast|JARVIS monitoring unavailable|*' }).Count -eq 1) 'worsening to unavailable alerts at once'
Check (@($r.log | Where-Object { $_ -eq 'mail|[JARVIS] monitoring unavailable' }).Count -eq 1) 'worsening to unavailable is mailed at once'
Check ($r.state.alertKind -eq 'unavailable') 'alert kind escalated'

$r = Run $down
Check ($r.log.Count -eq 0) 'same outage does not repeat the alert'

$r = Run $ok
Check (@($r.log | Where-Object { $_ -like 'toast|JARVIS recovered|*' }).Count -eq 1) 'recovery is announced'
Check ($r.state.alertKind -eq '') 'alert kind cleared on recovery'

# A working reviver still gets its three minutes before anyone is told.
Seed @{firstFailure = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 100}
$r = Run $degraded
Check ($r.log.Count -eq 0) 'reviver grace still holds a young outage'

# --- the real probe against a stub 503 -------------------------------------
$probeOnly = Join-Path $Work 'probe-under-test.ps1'
$port = 18787
Set-Content -LiteralPath $probeOnly -Value ($monitor -replace '127\.0\.0\.1:8787', "127.0.0.1:$port") -Encoding UTF8
$body = '{"service":"JARVIS","live":true,"healthy":false,"sources":{"scan":{"status":"complete","reason":"ok"},"native":{"status":"unavailable","reason":"collector coverage incomplete"},"sysmon":{"status":"partial","reason":"Sysmon is catching up a backlog"},"veil":{"status":"not_reporting","reason":"no observation yet"}}}'
$stub = Start-Job -ArgumentList $port, $body -ScriptBlock {
    param($port, $body)
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $port); $l.Start()
    try {
        $c = $l.AcceptTcpClient(); $s = $c.GetStream()
        $buf = New-Object byte[] 4096; [void]$s.Read($buf, 0, $buf.Length)
        $b = [Text.Encoding]::UTF8.GetBytes($body)
        $h = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 503 Service Unavailable`r`nContent-Type: application/json`r`nContent-Length: $($b.Length)`r`nConnection: close`r`n`r`n")
        $s.Write($h, 0, $h.Length); $s.Write($b, 0, $b.Length); $s.Flush(); $c.Close()
    } finally { $l.Stop() }
}
Start-Sleep -Milliseconds 1500
$probe = (& $probeOnly -ProbeOnly) | ConvertFrom-Json
Wait-Job $stub -Timeout 10 | Out-Null; Remove-Job $stub -Force
Check ($probe.healthy -eq $false -and $probe.degraded -eq $true) 'live 503 is classified as degraded coverage'
Check ($probe.reason -like '*native unavailable (collector coverage incomplete)*') 'probe names the unavailable required source'
Check ($probe.reason -like '*sysmon partial (Sysmon is catching up a backlog)*') 'probe names the partial required source'
Check ($probe.reason -notlike '*veil*') 'optional sources are not called required'

if ($script:fail) { Write-Output "$($script:fail) supervisor checks failed"; exit 1 }
Write-Output 'supervisor checks passed'
exit 0

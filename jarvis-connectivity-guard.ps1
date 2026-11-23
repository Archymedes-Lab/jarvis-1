# Runs independently of WSL; never disables an adapter or changes DNS/firewall rules.
# -Loop: one process probes every IntervalSeconds for LoopMinutes, then exits;
# the task (every 5 minutes, IgnoreNew) starts the next. Without -Loop: one probe.
param([switch]$Install, [switch]$ProbeOnly, [switch]$LibraryOnly,
      [switch]$Loop, [int]$LoopMinutes = 10, [int]$IntervalSeconds = 60,
      [string]$InterfaceName = 'Wi-Fi', [string]$ProfileName = '',
      [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'Jarvis\Connectivity'))
$ErrorActionPreference = 'Stop'
$taskName = 'JARVIS connectivity guard'

function Test-InternetTcp {
    foreach ($address in @('1.1.1.1', '8.8.8.8')) {
        $client = New-Object Net.Sockets.TcpClient
        try {
            $pending = $client.BeginConnect($address, 443, $null, $null)
            try {
                if ($pending.AsyncWaitHandle.WaitOne(3000)) {
                    $client.EndConnect($pending)
                    return $true
                }
            } finally { $pending.AsyncWaitHandle.Close() }
        } catch { } finally { $client.Dispose() }
    }
    return $false
}

function Get-ApplicationConnectivity {
    # curl's total deadline also bounds DNS and TLS. Use Windows' native curl,
    # respecting proxy/VPN routing; do not override the resolver or certificate checks.
    $checks = @()
    # HEAD only: a slow hotspot can take >10s to deliver a page body while
    # DNS, TCP and TLS are all fine, and TLS alone can exceed 4s there.
    foreach ($url in @('https://www.microsoft.com/', 'https://www.cloudflare.com/')) {
        $code = & "$env:SystemRoot\System32\curl.exe" --silent --head --output NUL --write-out '%{http_code}' --connect-timeout 10 --max-time 15 $url 2>$null
        $exitCode = $LASTEXITCODE
        $ok = ($exitCode -eq 0 -and [string]$code -match '^[234]\d\d$')
        $checks += @{url=$url; exitCode=$exitCode; httpStatus=[string]$code; healthy=$ok}
        if ($ok) {break}
    }
    return @{healthy=(@($checks | Where-Object healthy -eq $true).Count -gt 0); checks=$checks}
}

function Get-RecoveryDecision($status, $reachable, $failures, $firstFailure, $lastAttempt, $now, $paused) {
    if ($paused) { return 'paused' }
    if ($reachable) { return 'online' }
    if ($status -eq 'Up') { return 'upstream-unreachable' }
    if ($status -ne 'Disconnected') { return 'adapter-unavailable' }
    if ($failures -lt 3 -or ($now - $firstFailure) -lt 120) { return 'confirming-disconnect' }
    if (($now - $lastAttempt) -lt 300) { return 'cooldown' }
    return 'reconnect'
}

function Save-ConnectivityState($state) {
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $StateRoot 'state.json.new') -Encoding UTF8
    Move-Item -LiteralPath (Join-Path $StateRoot 'state.json.new') -Destination (Join-Path $StateRoot 'state.json') -Force
}

if ($LibraryOnly) { return }
if ($Install) {
    if ([string]::IsNullOrWhiteSpace($ProfileName)) { throw 'Specify an existing trusted WLAN ProfileName.' }
    $adapter = Get-NetAdapter -Name $InterfaceName
    if ($adapter.NdisPhysicalMedium -ne 9) { throw 'The selected adapter is not native Wi-Fi.' }
    & "$env:SystemRoot\System32\netsh.exe" wlan show profile "name=$ProfileName" "interface=$InterfaceName" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The selected saved Wi-Fi profile is unavailable.' }
    [void](New-Item -ItemType Directory -Path $StateRoot -Force)
    @{interface=$InterfaceName; profile=$ProfileName} | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $StateRoot 'config.json') -Encoding UTF8
    $script = Join-Path $StateRoot 'jarvis-connectivity-guard.ps1'
    if ($MyInvocation.MyCommand.Path -ne $script) {
        Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination $script -Force
    }
    # conhost --headless: -WindowStyle Hidden alone still flashes a console window each run.
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" -Argument (
        '--headless "' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" + '" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $script + '" -StateRoot "' + $StateRoot + '" -Loop')
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
    $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $principal.UserId),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)))
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    [void](Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force)
    Start-ScheduledTask -TaskName $taskName
    Write-Output 'Connectivity guard installed and started.'
    return
}

$cfg = Get-Content -LiteralPath (Join-Path $StateRoot 'config.json') -Raw | ConvertFrom-Json
$adapter = Get-NetAdapter -Name $cfg.interface
$reachable = Test-InternetTcp
$application = Get-ApplicationConnectivity
if ($ProbeOnly) {
    @{adapterStatus=[string]$adapter.Status; internetTcpReachable=$reachable; application=$application; profile=$cfg.profile} | ConvertTo-Json -Depth 5
    return
}
# IgnoreNew protects scheduled runs; the mutex also excludes manual invocations.
$mutex = New-Object Threading.Mutex($false, 'Local\JarvisConnectivityGuard')
$locked = $false
try {
    try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { return }
    $loopUntil = (Get-Date).AddMinutes([Math]::Max(1, $LoopMinutes))
    $first = $true
    while ($true) {
    if (-not $first) {
        Start-Sleep -Seconds ([Math]::Max(15, $IntervalSeconds))
        $cfg = Get-Content -LiteralPath (Join-Path $StateRoot 'config.json') -Raw | ConvertFrom-Json
        $adapter = Get-NetAdapter -Name $cfg.interface
        $reachable = Test-InternetTcp
        $application = Get-ApplicationConnectivity
    }
    $first = $false
    $state = @{failures=0; firstFailure=0; lastAttempt=0; attempts=0; lastHealthy=0; error=''}
    $saved = Join-Path $StateRoot 'state.json'
    if (Test-Path -LiteralPath $saved) {
        # Corrupt state fails closed: do not repeatedly reset the recovery budget.
        $old = Get-Content -LiteralPath $saved -Raw | ConvertFrom-Json
        foreach ($p in $old.PSObject.Properties) { $state[$p.Name] = $p.Value }
    }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    # A long gap, e.g. sleep/resume, needs fresh confirmation.
    if ($state.checkedAt -and ($now - $state.checkedAt) -gt 180) { $state.failures=0; $state.firstFailure=0 }
    $state.checkedAt=$now; $state.adapterStatus=[string]$adapter.Status
    $state.internetTcpReachable=$reachable; $state.error=''
    $state.application=$application
    $state.applicationFailures=if ($application.healthy) {0} else {[int]$state.applicationFailures+1}
    if ($application.healthy) {$state.lastApplicationHealthy=$now}
    $paused = Test-Path -LiteralPath (Join-Path $StateRoot 'paused')
    if ($reachable -or $adapter.Status -ne 'Disconnected' -or $paused) {
        $state.failures=0; $state.firstFailure=0
        if ($reachable) { $state.lastHealthy=$now }
    } else {
        if (-not $state.firstFailure) { $state.firstFailure=$now }
        $state.failures=[int]$state.failures+1
    }
    $state.action = Get-RecoveryDecision ([string]$adapter.Status) $reachable $state.failures $state.firstFailure $state.lastAttempt $now $paused
    if ($reachable -and -not $application.healthy) {$state.action='application-connectivity-degraded'}
    if ($state.action -eq 'reconnect') {
        # Persist the cooldown before attempting a command, including failed commands.
        $state.lastAttempt=$now; $state.attempts=[int]$state.attempts+1
        Save-ConnectivityState $state
        & "$env:SystemRoot\System32\netsh.exe" wlan connect "name=$($cfg.profile)" "interface=$($cfg.interface)" | Out-Null
        $state.connectExitCode=$LASTEXITCODE
        if ($LASTEXITCODE -ne 0) { $state.error='Saved-profile reconnect request failed.' }
        # An accepted request is not proof of connectivity; the next probe verifies it.
    }
    Save-ConnectivityState $state
    if (-not $Loop) { $state | ConvertTo-Json -Compress }
    if (-not $Loop -or (Get-Date) -ge $loopUntil) { break }
    }
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}

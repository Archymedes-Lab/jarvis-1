# Protected SYSTEM scheduled task. Observes the three isolated channel services
# while WSL is unavailable. Restarts are evidence-preserving and rate limited.
param([switch]$SelfTest)
$ErrorActionPreference = 'Stop'
function Get-RecoveryDecision([bool]$failed, [int]$previousStrikes,
                              [int]$recentAttempts, [bool]$servicePresent) {
    $strikes = if ($failed) { $previousStrikes + 1 } else { 0 }
    $action = 'none'
    if ($failed -and $strikes -ge 2) {
        if ($recentAttempts -ge 2) { $action = 'restart_budget_exhausted' }
        elseif (-not $servicePresent) { $action = 'service_missing' }
        else { $action = 'restart_requested' }
    }
    @{ strikes=$strikes; action=$action }
}
function Save-Monitor([string]$receiptPath, [string]$directory, [DateTime]$stamp,
                      [hashtable]$services) {
    $receipt = @{ schema=1; time=$stamp.ToString('o'); services=$services } | ConvertTo-Json -Depth 5 -Compress
    $temp = Join-Path $directory ('monitor.' + [guid]::NewGuid().ToString('N') + '.new')
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($receipt)
    $stream = [IO.FileStream]::new($temp, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $receiptPath) { [IO.File]::Replace($temp,$receiptPath,($receiptPath + '.prev')) }
    else { [IO.File]::Move($temp,$receiptPath) }
}
if ($SelfTest) {
    if ((Get-RecoveryDecision $true 0 0 $true).action -ne 'none' -or
        (Get-RecoveryDecision $true 1 0 $true).action -ne 'restart_requested' -or
        (Get-RecoveryDecision $true 2 2 $true).action -ne 'restart_budget_exhausted' -or
        (Get-RecoveryDecision $true 1 0 $false).action -ne 'service_missing' -or
        (Get-RecoveryDecision $false 4 2 $true).strikes -ne 0) {
        throw 'isolated monitor recovery policy failed'
    }
    $scratch = Join-Path $env:TEMP ('jarvis-monitor-selftest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch | Out-Null
    try {
        $receiptPath = Join-Path $scratch 'monitor.json'
        Save-Monitor $receiptPath $scratch ([DateTime]::UtcNow) @{
            JarvisSensorSysmon=@{ status='unavailable'; attempts=@('attempt-1'); action='restart_intent' }}
        Save-Monitor $receiptPath $scratch ([DateTime]::UtcNow) @{
            JarvisSensorSysmon=@{ status='unavailable'; attempts=@('attempt-1'); action='restart_failed' }}
        Save-Monitor $receiptPath $scratch ([DateTime]::UtcNow) @{
            JarvisSensorSysmon=@{ status='unavailable'; attempts=@('attempt-1','attempt-2'); action='restart_budget_exhausted' }}
        $saved = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
        if ($saved.services.JarvisSensorSysmon.attempts.Count -ne 2 -or
            $saved.services.JarvisSensorSysmon.action -ne 'restart_budget_exhausted') {
            throw 'isolated monitor intent persistence failed'
        }
    } finally { Remove-Item -LiteralPath $scratch -Recurse -Force }
    Write-Output 'isolated monitor recovery policy passed'
    return
}
$root = Join-Path $env:ProgramData 'Jarvis\Sensor'
if (-not (Test-Path -LiteralPath (Join-Path $root 'mode.json'))) { return }
$path = Join-Path $root 'monitor.json'
$channels = @(
    @{ Name='JarvisSensorSysmon'; Hash='461b8df16acfb5cc' },
    @{ Name='JarvisSensorDefender'; Hash='9e4df814a0bd703b' },
    @{ Name='JarvisSensorTasks'; Hash='19f0bcd199c90ed8' }
)
try {
    $gate = [IO.File]::Open((Join-Path $root 'monitor.lock'),
        [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
} catch [IO.IOException] { return } # another monitor pass is still active
try {
$now = [DateTime]::UtcNow
try { $prior = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json }
catch { $prior = $null }
$states = @{}
if ($prior -and $prior.services) {
    foreach ($property in $prior.services.PSObject.Properties) {
        $states[$property.Name] = $property.Value
    }
}
foreach ($item in $channels) {
    $name = $item.Name
    $previous = if ($prior) { $prior.services.PSObject.Properties[$name].Value } else { $null }
    $attempts = @()
    if ($previous) {
        foreach ($at in @($previous.attempts)) {
            try {
                $stamp = [DateTime]::Parse($at).ToUniversalTime()
                if (($now - $stamp).TotalMinutes -lt 60) { $attempts += $stamp.ToString('o') }
            } catch {}
        }
    }
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    $health = Join-Path (Join-Path $root $item.Hash) 'health.json'
    $age = $null
    if (Test-Path -LiteralPath $health) { $age = ($now - (Get-Item -LiteralPath $health).LastWriteTimeUtc).TotalSeconds }
    $failed = (-not $service -or $service.Status -ne 'Running' -or $null -eq $age -or $age -gt 90)
    $decision = Get-RecoveryDecision $failed $(if ($previous) { [int]$previous.strikes } else { 0 }) $attempts.Count ([bool]$service)
    $strikes = $decision.strikes
    $action = $decision.action
    if ($action -eq 'restart_requested') {
        $attempts += $now.ToString('o')
        # Intent and budget are durable before the protected service action.
        # An interrupted task cannot get a free, unrecorded retry next minute.
        $states[$name] = @{ status='unavailable'; heartbeat_age_s=$age;
            strikes=$strikes; attempts=$attempts; action='restart_intent' }
        Save-Monitor $path $root $now $states
        try {
            if ($service.Status -ne 'Stopped') { Stop-Service -Name $name -ErrorAction Stop }
            Start-Service -Name $name -ErrorAction Stop
        } catch { $action = 'restart_failed' }
    }
    $states[$name] = @{ status=$(if ($failed) { 'unavailable' } else { 'complete' });
        heartbeat_age_s=$age; strikes=$strikes; attempts=$attempts; action=$action }
}
Save-Monitor $path $root $now $states
} finally { $gate.Dispose() }

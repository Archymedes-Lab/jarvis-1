# Elevated, explicit cutover from the existing publisher to three SCM services.
# The legacy service and all batch/ack files remain in place for rollback.
param(
    [switch]$Install,
    [switch]$Rollback,
    [switch]$SelfTest,
    [string]$User = "$env:USERDOMAIN\$env:USERNAME"
)
$ErrorActionPreference = 'Stop'
# Locations from the operating system, not environment variables, which an
# elevated shell inherits from the (unelevated) user's own environment.
$Sys32 = [Environment]::SystemDirectory
$WinDir = Split-Path -Parent $Sys32
$ProgramFilesDir = [Environment]::GetFolderPath('ProgramFiles')
$ProgramDataDir = Join-Path ([IO.Path]::GetPathRoot($Sys32)) 'ProgramData'
$PowerShellExe = Join-Path $Sys32 'WindowsPowerShell\v1.0\powershell.exe'
if (-not $SelfTest -and $Install -eq $Rollback) { throw 'Choose exactly one of -Install or -Rollback.' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $SelfTest -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run from an elevated PowerShell.'
}
$trustedStage = Join-Path $ProgramFilesDir 'Jarvis\SensorStage'
if (-not $SelfTest -and [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') -ne $trustedStage.TrimEnd('\')) {
    throw "Run only the reviewed copy from the protected stage: $trustedStage"
}
$manifestPath = Join-Path $PSScriptRoot 'SHA256SUMS.json'
if (-not $SelfTest) {
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'Reviewed source hash manifest missing.' }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    foreach ($name in @('JarvisSensor.cs','monitor-isolated.ps1','install-isolated.ps1')) {
        $expected = $manifest.PSObject.Properties[$name].Value
        $actual = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash
        if (-not $expected -or $actual -ne $expected) { throw "Reviewed source hash mismatch: $name" }
    }
}
$root = Join-Path $ProgramDataDir 'Jarvis\Sensor'
$bin = Join-Path $ProgramFilesDir 'Jarvis\Sensor'
$exe = Join-Path $bin 'JarvisSensorIsolated.exe'
$monitor = Join-Path $bin 'monitor-isolated.ps1'
$monitorTask = 'JARVIS Native Sensor Monitor'
$mode = Join-Path $root 'mode.json'
$baselinePointer = Join-Path $root 'isolation-baseline.txt'
$oldName = 'JarvisNativeSensor'
$channels = @(
    @{ Name='JarvisSensorSysmon'; Channel='Microsoft-Windows-Sysmon/Operational' },
    @{ Name='JarvisSensorDefender'; Channel='Microsoft-Windows-Windows Defender/Operational' },
    @{ Name='JarvisSensorTasks'; Channel='Microsoft-Windows-TaskScheduler/Operational' }
)
function New-AdminOnlyDirectory([string]$prefix) {
    # A fresh folder under %SystemRoot%\Temp, created with its ACL in one call
    # (SYSTEM and Administrators only, nothing inherited). The user's %TEMP%
    # is writable by the unelevated user, who could edit a policy file there
    # between its writing and secedit applying it.
    $sid = { param($v) New-Object Security.Principal.SecurityIdentifier($v) }
    $sec = New-Object Security.AccessControl.DirectorySecurity
    $sec.SetOwner((& $sid 'S-1-5-32-544'))
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($s in @('S-1-5-18', 'S-1-5-32-544')) {
        $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((& $sid $s),
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    $path = Join-Path (Join-Path $WinDir 'Temp') ($prefix + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $path) { throw "refusing: $path already exists" }
    [void][IO.Directory]::CreateDirectory($path, $sec)
    return $path
}

function Grant-LogonAsService([string]$sid) {
    $temp = New-AdminOnlyDirectory 'jarvis-isolated-right-'
    try {
        $inf = Join-Path $temp 'rights.inf'
        $db = Join-Path $temp 'rights.sdb'
        & (Join-Path $Sys32 'secedit.exe') /export /cfg $inf /areas USER_RIGHTS | Out-Null
        Assert-Exit 'export service logon policy'
        $content = Get-Content -LiteralPath $inf
        $line = $content | Where-Object { $_ -match '^SeServiceLogonRight' }
        if ($line -and $line -match [regex]::Escape($sid)) { return }
        if ($line) {
            $content = $content -replace '^(SeServiceLogonRight\s*=\s*.*)$', "`$1,*$sid"
        } else {
            $content = $content -replace '(\[Privilege Rights\])', "`$1`r`nSeServiceLogonRight = *$sid"
        }
        Set-Content -LiteralPath $inf -Value $content -Encoding Unicode
        & (Join-Path $Sys32 'secedit.exe') /configure /db $db /cfg $inf /areas USER_RIGHTS | Out-Null
        Assert-Exit 'grant service logon right'
    } finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
}
function Assert-Exit([string]$label) {
    if ($LASTEXITCODE -ne 0) { throw "$label failed ($LASTEXITCODE)" }
}
function Stop-IfRunning([string]$name) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name $name -ErrorAction Stop
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}
function Channel-Dir([string]$channel) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hex = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($channel)))).Replace('-','').ToLowerInvariant()
        Join-Path $root $hex.Substring(0,16)
    } finally { $sha.Dispose() }
}
function Resolve-StoppedHead([string]$directory, [string]$channel,
                             [string]$sensor, [int64]$minimumSequence) {
    $head = Get-ChildItem -LiteralPath $directory -Filter '*.json' -File |
        Where-Object { $_.Name -match '^\d{20}\.json$' } |
        Sort-Object Name | Select-Object -Last 1
    if (-not $head) { throw "Latest stopped batch missing for $channel." }
    $batch = Get-Content -Raw -LiteralPath $head.FullName | ConvertFrom-Json
    if ($batch.channel -ne $channel -or $batch.sensor_id -ne $sensor -or
        [int64]$batch.sequence -lt $minimumSequence -or
        $batch.bookmark -notmatch '^record:\d+$') {
        throw "Latest stopped batch identity or cursor mismatch for $channel."
    }
    return $batch
}
function Move-NonBatchReceipts([string]$directory, [string]$destination) {
    # The legacy binary takes the ordinal-greatest *.json in a channel
    # directory as its cursor. An isolated per-channel health.json sorts after
    # every batch name, so leaving it in place blinds the restarted legacy
    # publisher. Preserve such receipts as evidence outside the spool.
    $moved = @()
    if (-not (Test-Path -LiteralPath $directory)) { return $moved }
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -Filter '*.json' -File |
                        Where-Object { $_.Name -notmatch '^\d{20}\.json$' })) {
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        $target = Join-Path $destination ((Split-Path $directory -Leaf) + '-' + $file.Name)
        Move-Item -LiteralPath $file.FullName -Destination $target
        $moved += $target
    }
    return $moved
}
function Wait-CompleteReceipt([string]$path, [string[]]$names, [int]$seconds) {
    # The legacy Sysmon read intermittently times out under host load, so one
    # pass in several reports that channel unavailable while its cursor keeps
    # advancing. Sample passes for a bounded time and accept only a fresh
    # receipt in which every channel is present and not unavailable.
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        try {
            $receipt = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
            $age = ((Get-Date) - (Get-Item -LiteralPath $path).LastWriteTime).TotalSeconds
            $complete = $age -lt 30
            foreach ($name in $names) {
                $state = $receipt.channels.PSObject.Properties[$name].Value
                if (-not $state -or $state.status -eq 'unavailable') { $complete = $false }
            }
            if ($complete) { return $receipt }
        } catch {}
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    throw "No fresh receipt with every channel available at $path; establish a healthy baseline first."
}
function Wait-MonitorReceipt([string]$path, [DateTime]$since, [string[]]$names, [int]$seconds) {
    # Under load, Task Scheduler took 28 s to create the SYSTEM process and the
    # pass took 6 s more; the task repeats every minute. Accept only a receipt
    # written after this task start, never an earlier attempt's, in which the
    # independent monitor itself judged every service complete.
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        try {
            if ((Get-Item -LiteralPath $path).LastWriteTime -gt $since) {
                $receipt = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
                $complete = $true
                foreach ($name in $names) {
                    $state = $receipt.services.PSObject.Properties[$name].Value
                    if (-not $state -or $state.status -ne 'complete') { $complete = $false }
                }
                if ($complete) { return $receipt }
            }
        } catch {}
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw 'Independent monitor did not confirm every service after this cutover.'
}
function New-MonitorAction([string]$script) {
    # schtasks /tr is passed through Windows PowerShell 5.1 native argument
    # quoting, which splits a quoted "Program Files" path (E_FAIL). A task
    # action object carries the arguments without a native command line.
    # Absolute: the task runs as SYSTEM, and a bare name is resolved through
    # PATH, where any earlier writable folder would win.
    New-ScheduledTaskAction -Execute $PowerShellExe -Argument (
        '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $script + '"')
}
if ($SelfTest) {
    $scratch = Join-Path $env:TEMP ('jarvis-stopped-cursor-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $scratch | Out-Null
    try {
        $channel = 'Microsoft-Windows-Windows Defender/Operational'
        $sensor = 'sensor-test'
        # The stopped aggregate has no Defender state, while its last immutable
        # batch continues the complete pre-stop receipt's sequence.
        $stoppedHealth = @{ channels=@{} }
        $valid = @{ channel=$channel; sensor_id=$sensor; sequence=8; bookmark='record:82' }
        $valid | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $scratch '00000000000000000008.json')
        if ($stoppedHealth.channels.Count -ne 0 -or
            (Resolve-StoppedHead $scratch $channel $sensor 7).sequence -ne 8) {
            throw 'Interrupted aggregate continuity self-test failed.'
        }
        $badIdentityRejected = $false
        try { $null = Resolve-StoppedHead $scratch $channel 'another-sensor' 7 }
        catch { $badIdentityRejected = $true }
        $rewindRejected = $false
        try { $null = Resolve-StoppedHead $scratch $channel $sensor 9 }
        catch { $rewindRejected = $true }
        if (-not $badIdentityRejected -or -not $rewindRejected) {
            throw 'Stopped cursor rejection self-test failed.'
        }
        # Rollback must leave only batches where the legacy binary picks its cursor.
        $channelDir = Join-Path $scratch '9e4df814a0bd703b'
        New-Item -ItemType Directory -Path $channelDir | Out-Null
        $valid | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $channelDir '00000000000000000008.json')
        '{"channels":{}}' | Set-Content -LiteralPath (Join-Path $channelDir 'health.json')
        $moved = @(Move-NonBatchReceipts $channelDir (Join-Path $scratch 'preserved'))
        $legacyHead = Get-ChildItem -LiteralPath $channelDir -Filter '*.json' -File |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($moved.Count -ne 1 -or -not (Test-Path -LiteralPath $moved[0]) -or
            $legacyHead.Name -ne '00000000000000000008.json') {
            throw 'Rollback receipt preservation self-test failed.'
        }
        $names = @('a/Operational','b/Operational')
        $receiptPath = Join-Path $scratch 'health.json'
        '{"channels":{"a/Operational":{"status":"complete"},"b/Operational":{"status":"complete"}}}' |
            Set-Content -LiteralPath $receiptPath
        if (-not (Wait-CompleteReceipt $receiptPath $names 3)) { throw 'Complete receipt self-test failed.' }
        '{"channels":{"a/Operational":{"status":"complete"},"b/Operational":{"status":"unavailable"}}}' |
            Set-Content -LiteralPath $receiptPath
        $partialRejected = $false
        try { $null = Wait-CompleteReceipt $receiptPath $names 2 } catch { $partialRejected = $true }
        if (-not $partialRejected) { throw 'Partial receipt self-test failed.' }
        $monitorPath = Join-Path $scratch 'monitor.json'
        $services = @('SvcA','SvcB')
        '{"services":{"SvcA":{"status":"complete"},"SvcB":{"status":"complete"}}}' |
            Set-Content -LiteralPath $monitorPath
        $staleRejected = $false
        try { $null = Wait-MonitorReceipt $monitorPath (Get-Date).AddSeconds(5) $services 2 }
        catch { $staleRejected = $true }
        $since = (Get-Date).AddSeconds(-1)
        '{"services":{"SvcA":{"status":"complete"},"SvcB":{"status":"unavailable"}}}' |
            Set-Content -LiteralPath $monitorPath
        $failedRejected = $false
        try { $null = Wait-MonitorReceipt $monitorPath $since $services 2 }
        catch { $failedRejected = $true }
        '{"services":{"SvcA":{"status":"complete"},"SvcB":{"status":"complete"}}}' |
            Set-Content -LiteralPath $monitorPath
        if (-not $staleRejected -or -not $failedRejected -or
            -not (Wait-MonitorReceipt $monitorPath $since $services 2)) {
            throw 'Monitor confirmation self-test failed.'
        }
        $action = New-MonitorAction 'C:\Program Files\Jarvis\Sensor\monitor-isolated.ps1'
        if ($action.Execute -ne $PowerShellExe -or
            $action.Arguments -notlike '*-File "C:\Program Files\Jarvis\Sensor\monitor-isolated.ps1"') {
            throw 'Monitor task action self-test failed.'
        }
    } finally { Remove-Item -LiteralPath $scratch -Recurse -Force }
    Write-Host 'stopped cursor continuity self-test passed'
    return
}
function Write-Mode {
    $temp = Join-Path $root ('mode.' + [guid]::NewGuid().ToString('N') + '.new')
    [IO.File]::WriteAllText($temp, '{"mode":"isolated","schema":1}', (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temp -Destination $mode -Force
}
function Restore-Legacy {
    $existingMonitor = Get-ScheduledTask -TaskName $monitorTask -ErrorAction SilentlyContinue
    if ($existingMonitor) {
        Disable-ScheduledTask -TaskName $monitorTask -ErrorAction Stop | Out-Null
    }
    foreach ($entry in $channels) {
        Stop-IfRunning $entry.Name
        # Demote before the legacy readback so a failed rollback cannot leave
        # paused isolated services set to start automatically.
        if (Get-Service -Name $entry.Name -ErrorAction SilentlyContinue) {
            & (Join-Path $Sys32 'sc.exe') config $entry.Name start= demand | Out-Null
            Assert-Exit 'disable isolated service'
        }
    }
    $identity = Get-Content -Raw -LiteralPath (Join-Path $root 'identity.json') | ConvertFrom-Json
    $resume = @{}
    foreach ($entry in $channels) {
        $head = Get-ChildItem -LiteralPath (Channel-Dir $entry.Channel) -Filter '*.json' -File |
            Where-Object { $_.Name -match '^\d{20}\.json$' } |
            Sort-Object Name | Select-Object -Last 1
        if (-not $head) { throw "Rollback cursor missing for $($entry.Channel); leave publishers stopped." }
        $batch = Get-Content -Raw -LiteralPath $head.FullName | ConvertFrom-Json
        if ($batch.channel -ne $entry.Channel -or $batch.sensor_id -ne $identity.sensor_id -or
            [int64]$batch.sequence -lt 1 -or $batch.bookmark -notmatch '^record:\d+$') {
            throw "Rollback cursor uncertain for $($entry.Channel); leave publishers stopped."
        }
        $resume[$entry.Name] = [int64]$batch.sequence
    }
    if (-not (Test-Path -LiteralPath $baselinePointer)) { throw 'Legacy backup pointer missing; leave publishers stopped for inspection.' }
    $saved = (Get-Content -Raw -LiteralPath $baselinePointer).Trim()
    $oldExe = Join-Path $saved 'JarvisSensor.exe'
    $savedAcl = Join-Path $saved 'spool-acl.txt'
    if (-not (Test-Path -LiteralPath $oldExe) -or -not (Test-Path -LiteralPath $savedAcl)) {
        throw 'Legacy binary or ACL backup missing; leave publishers stopped for inspection.'
    }
    $preserved = Join-Path $saved ('rollback-receipts-' + (Get-Date -Format 'yyyyMMddTHHmmss'))
    foreach ($entry in $channels) {
        foreach ($moved in @(Move-NonBatchReceipts (Channel-Dir $entry.Channel) $preserved)) {
            Write-Host "Preserved isolated receipt: $moved"
        }
    }
    Copy-Item -LiteralPath $oldExe -Destination (Join-Path $bin 'JarvisSensor.exe') -Force
    & (Join-Path $Sys32 'icacls.exe') (Split-Path $root -Parent) /restore $savedAcl /c | Out-Null
    Assert-Exit 'restore spool ACL'
    foreach ($entry in $channels) {
        $directory = Channel-Dir $entry.Channel
        if (Test-Path -LiteralPath $directory) {
            & (Join-Path $Sys32 'icacls.exe') $directory /grant "NT SERVICE\${oldName}:(OI)(CI)M" | Out-Null
            Assert-Exit 'legacy channel spool access'
        }
    }
    if (Test-Path -LiteralPath $mode) { Remove-Item -LiteralPath $mode -Force }
    $asrMarker = Join-Path $root 'isolation-asr-added'
    if (Test-Path -LiteralPath $asrMarker) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $exe -ErrorAction Stop
        Remove-Item -LiteralPath $asrMarker -Force
    }
    $legacy = Get-Service -Name $oldName -ErrorAction SilentlyContinue
    if (-not $legacy) { throw 'Legacy service missing; leave isolated services stopped for inspection.' }
    & (Join-Path $Sys32 'sc.exe') config $oldName start= auto | Out-Null
    Assert-Exit 'restore legacy startup'
    Start-Service -Name $oldName
    $deadline = (Get-Date).AddSeconds(90)
    $freshReady = $false
    do {
        $legacyHealth = Get-Content -Raw -LiteralPath (Join-Path $root 'health.json') | ConvertFrom-Json
        $ready = $true
        foreach ($entry in $channels) {
            $state = $legacyHealth.channels.PSObject.Properties[$entry.Channel].Value
            if (-not $state -or [int64]$state.last_sequence -lt $resume[$entry.Name] -or
                $state.status -eq 'unavailable') { $ready = $false }
        }
        if ($ready -and ((Get-Date) - (Get-Item -LiteralPath (Join-Path $root 'health.json')).LastWriteTime).TotalSeconds -lt 30) {
            $freshReady = $true
            break
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if (-not $freshReady) { throw 'Legacy service restarted but fresh cursor readback failed.' }
}
if ($Rollback) {
    Restore-Legacy
    Write-Host 'Legacy publisher resumed. Isolated service definitions, binaries, receipts and spool preserved.'
    return
}
if (-not (Get-Service -Name $oldName -ErrorAction SilentlyContinue)) { throw 'Legacy service missing; no cursor-preserving cutover source.' }
if (Test-Path -LiteralPath $mode) { throw 'Isolated mode already active; refusing a second cutover.' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'identity.json')) -or
    -not (Test-Path -LiteralPath (Join-Path $root 'device.json'))) {
    throw 'Existing sensor/device identities missing; inspect the spool before cutover.'
}
if (-not (Test-Path -LiteralPath (Join-Path $root 'health.json'))) {
    throw 'Legacy health receipt missing; inspect service and spool before cutover.'
}
$oldReceipt = Wait-CompleteReceipt (Join-Path $root 'health.json') @($channels | ForEach-Object { $_.Channel }) 90
$oldBatches = @{}
if (-not $oldReceipt.sensor_id -or -not $oldReceipt.device_id) {
    throw 'Legacy identity missing from health receipt; inspect before cutover.'
}
foreach ($entry in $channels) {
    $state = $oldReceipt.channels.PSObject.Properties[$entry.Channel].Value
    if (-not $state -or $state.status -eq 'unavailable') {
        throw "Legacy channel $($entry.Channel) is unavailable; establish a healthy baseline first."
    }
    $head = Join-Path (Channel-Dir $entry.Channel) ('{0:D20}.json' -f [int64]$state.last_sequence)
    if (-not (Test-Path -LiteralPath $head)) { throw "Latest legacy batch missing for $($entry.Channel)." }
    $oldBatches[$entry.Name] = Get-Content -Raw -LiteralPath $head | ConvertFrom-Json
}
# A Windows service can look healthy while the WSL ingester or the other
# collectors are blind. Refuse cutover until the running system supplies a
# fresh, complete baseline that can be compared with new receipts.
# Health sources and the state need a paired client token (jarvis desktop pair);
# without one, the cutover is refused below rather than judged on liveness alone.
$jarvisTokenPath = if ($env:JARVIS_CLIENT_TOKEN_FILE) { $env:JARVIS_CLIENT_TOKEN_FILE } else { Join-Path $env:LOCALAPPDATA 'Jarvis\client.token' }
$jarvisToken = try { ([IO.File]::ReadAllText($jarvisTokenPath)).Trim() } catch { '' }
if ($jarvisToken -cnotmatch '^jc1_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$') {
    throw "No paired client token at $jarvisTokenPath (jarvis desktop pair --name sensor-install); no cutover attempted."
}
$jarvisAuth = @{ 'X-JARVIS-Token' = $jarvisToken }
$jarvisHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/health' -TimeoutSec 10 -Headers $jarvisAuth
if (-not $jarvisHealth.healthy -or $jarvisHealth.sources.native.status -ne 'complete' -or
    $jarvisHealth.sources.bridge.status -ne 'complete') {
    throw 'JARVIS health/native/bridge baseline is incomplete; no cutover attempted.'
}
$jarvisState = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/state' -TimeoutSec 30 -Headers $jarvisAuth
$coverage = $jarvisState.jobs | Where-Object { $_.name -eq 'coverage' } | Select-Object -First 1
$collectorFailures = @($jarvisState.findings | Where-Object {
    $_.job -eq 'coverage' -and $_.category -eq 'collectors' -and
    $_.severity -in @('high','critical') })
if (-not $coverage -or $coverage.error -or $coverage.freshness -ne 'FRESH' -or
    $collectorFailures.Count -gt 0) {
    throw 'Collector coverage baseline is incomplete; no cutover attempted.'
}
$compiler = Join-Path $WinDir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '64-bit .NET Framework compiler unavailable.' }
# Existing deployment needed an ASR-only exclusion for its unsigned, protected
# service binary. Record whether this cutover added the new exact path.
$asrMarker = Join-Path $root 'isolation-asr-added'
$addedAsr = $false
try {
    $existingAsr = @((Get-MpPreference).AttackSurfaceReductionOnlyExclusions)
    if ($existingAsr -notcontains $exe) {
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions $exe
        Set-Content -LiteralPath $asrMarker -Value $exe
        $addedAsr = $true
    }
    $staged = Join-Path $bin 'JarvisSensorIsolated.cs'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'JarvisSensor.cs') -Destination $staged -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'monitor-isolated.ps1') -Destination $monitor -Force
    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /r:System.ServiceProcess.dll `
        /r:System.Web.Extensions.dll /out:$exe $staged
    Assert-Exit 'native sensor compilation'
    $baseline = Join-Path $bin ('isolation-baseline-' + (Get-Date -Format 'yyyyMMddTHHmmss'))
    New-Item -ItemType Directory -Path $baseline | Out-Null
    Copy-Item -LiteralPath (Join-Path $bin 'JarvisSensor.exe') -Destination $baseline
    Copy-Item -LiteralPath (Join-Path $root 'identity.json') -Destination $baseline
    Copy-Item -LiteralPath (Join-Path $root 'device.json') -Destination $baseline
    Copy-Item -LiteralPath (Join-Path $root 'health.json') -Destination $baseline
    @{ health_time=$jarvisHealth.time; native=$jarvisHealth.sources.native.status;
       bridge=$jarvisHealth.sources.bridge.status; coverage_ts=$coverage.ts;
       coverage_freshness=$coverage.freshness } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $baseline 'jarvis-baseline.json')
    & (Join-Path $Sys32 'sc.exe') qc $oldName | Set-Content -LiteralPath (Join-Path $baseline 'legacy-service.txt')
    & (Join-Path $Sys32 'icacls.exe') $root /save (Join-Path $baseline 'spool-acl.txt') /t /c | Out-Null
    Assert-Exit 'spool ACL backup'
    Get-FileHash -LiteralPath $exe -Algorithm SHA256 | Format-Table -AutoSize
    Write-Host "Rollback baseline: $baseline"
    Set-Content -LiteralPath $baselinePointer -Value $baseline
} catch {
    if ($addedAsr) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $exe -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $asrMarker -Force -ErrorAction SilentlyContinue
    }
    throw
}

# Stop the sole old writer before activating the new mode. No batch is removed.
try {
Stop-IfRunning $oldName
# OnStop can interrupt the legacy sequential pass after one channel and write
# an aggregate receipt without later channels. Preserve it as evidence, but
# keep the complete pre-stop receipt as the baseline; immutable highest batches
# are authoritative for the stopped publisher's final sequence and bookmark.
Copy-Item -LiteralPath (Join-Path $root 'health.json') -Destination (Join-Path $baseline 'stopped-health.json')
$oldBatches = @{}
foreach ($entry in $channels) {
    $state = $oldReceipt.channels.PSObject.Properties[$entry.Channel].Value
    # Publication can complete just before Stop-Service while the aggregate
    # health write is interrupted. The immutable highest batch is authoritative.
    $batch = Resolve-StoppedHead (Channel-Dir $entry.Channel) $entry.Channel `
        $oldReceipt.sensor_id ([int64]$state.last_sequence)
    $state.last_sequence = [int64]$batch.sequence
    $oldBatches[$entry.Name] = $batch
    $budget = if ($entry.Name -eq 'JarvisSensorSysmon') { 384MB } else { 64MB }
    $used = (Get-ChildItem -LiteralPath (Channel-Dir $entry.Channel) -Filter '*.json' -File |
        Measure-Object -Property Length -Sum).Sum
    if ([int64]$used -ge [int64]$budget) {
        throw "Preserved spool for $($entry.Channel) exceeds its isolated budget; no evidence was removed."
    }
}
& (Join-Path $Sys32 'sc.exe') config $oldName start= demand | Out-Null
Assert-Exit 'disable legacy automatic startup'
    # A manual start of the old service must obey the same mode marker. The
    # saved binary is restored before rollback starts the old publisher.
    Copy-Item -LiteralPath $exe -Destination (Join-Path $bin 'JarvisSensor.exe') -Force
    foreach ($entry in $channels) {
        $name = $entry.Name
        $account = "NT SERVICE\$name"
        $dir = Channel-Dir $entry.Channel
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $service) {
            New-Service -Name $name -BinaryPathName "`"$exe`" --service $name" `
                -DisplayName "JARVIS $name collector" -StartupType Automatic | Out-Null
        }
        & (Join-Path $Sys32 'sc.exe') sidtype $name unrestricted | Out-Null
        Assert-Exit "SID type $name"
        # In Windows PowerShell 5.1 an empty native argument is dropped, so
        # `password= ""` makes sc.exe reject the command (1639). SCM accepts
        # a virtual service account with the password option omitted; this
        # was read back on the stopped service before cutover.
        & (Join-Path $Sys32 'sc.exe') config $name obj= $account | Out-Null
        Assert-Exit "configure account $name"
        & (Join-Path $Sys32 'sc.exe') config $name start= auto | Out-Null
        Assert-Exit "configure startup $name"
        & (Join-Path $Sys32 'sc.exe') failure $name reset= 86400 actions= restart/5000/restart/30000/none/0 | Out-Null
        Assert-Exit "recovery $name"
        $sid = (New-Object Security.Principal.NTAccount($account)).Translate(
            [Security.Principal.SecurityIdentifier]).Value
        Grant-LogonAsService $sid
        $member = Get-LocalGroupMember -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $account }
        if (-not $member) { Add-LocalGroupMember -SID 'S-1-5-32-573' -Member $account }
        & (Join-Path $Sys32 'icacls.exe') $dir /inheritance:r /grant:r "${account}:(OI)(CI)M" `
            '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${User}:(OI)(CI)RX" | Out-Null
        Assert-Exit "spool ACL $name"
        & (Join-Path $Sys32 'icacls.exe') (Join-Path $root 'acks') /grant "${account}:(OI)(CI)RX" | Out-Null
        Assert-Exit "ack ACL $name"
        & (Join-Path $Sys32 'icacls.exe') $root /grant "${account}:(OI)(CI)RX" | Out-Null
        Assert-Exit "root read ACL $name"
        & (Join-Path $Sys32 'icacls.exe') $bin /grant "${account}:(OI)(CI)RX" | Out-Null
        Assert-Exit "binary read ACL $name"
    }
    & (Join-Path $Sys32 'icacls.exe') $root /remove:g "NT SERVICE\$oldName" | Out-Null
    Assert-Exit 'remove legacy spool write access'
    Write-Mode
    foreach ($entry in $channels) { Start-Service -Name $entry.Name }
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $system = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $monitorTask -Action (New-MonitorAction $monitor) -Trigger $trigger `
        -Principal $system -Force -ErrorAction Stop | Out-Null
    $monitorStarted = Get-Date
    Start-ScheduledTask -TaskName $monitorTask -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(90)
    do {
        $ready = $true
        foreach ($entry in $channels) {
            $health = Join-Path (Channel-Dir $entry.Channel) 'health.json'
            if (-not (Test-Path -LiteralPath $health) -or
                ((Get-Date) - (Get-Item -LiteralPath $health).LastWriteTime).TotalSeconds -gt 30) {
                $ready = $false
            }
        }
        if ($ready) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if (-not $ready) { throw 'One or more isolated services did not produce a fresh receipt.' }
    $null = Wait-MonitorReceipt (Join-Path $root 'monitor.json') $monitorStarted `
        @($channels | ForEach-Object { $_.Name }) 180
    foreach ($entry in $channels) {
        $oldState = $oldReceipt.channels.PSObject.Properties[$entry.Channel].Value
        $first = Join-Path (Channel-Dir $entry.Channel) ('{0:D20}.json' -f ([int64]$oldState.last_sequence + 1))
        $firstDeadline = (Get-Date).AddSeconds(120)
        while ((Get-Date) -lt $firstDeadline -and -not (Test-Path -LiteralPath $first)) {
            Start-Sleep -Seconds 2
        }
        if (-not (Test-Path -LiteralPath $first)) { throw "No first isolated batch for $($entry.Channel)." }
        $firstBatch = Get-Content -Raw -LiteralPath $first | ConvertFrom-Json
        if ([int64]$firstBatch.previous_sequence -ne [int64]$oldState.last_sequence -or
            $firstBatch.sensor_id -ne $oldReceipt.sensor_id -or
            ($firstBatch.generation -ne $oldBatches[$entry.Name].generation -and -not $firstBatch.gap)) {
            throw "First isolated batch did not continue $($entry.Channel) cursor."
        }
        # Same bounded sampling as the legacy baseline: one transient read
        # timeout is not a failed service, a persistent one is.
        $receipt = Wait-CompleteReceipt (Join-Path (Channel-Dir $entry.Channel) 'health.json') @($entry.Channel) 60
        $state = $receipt.channels.PSObject.Properties[$entry.Channel].Value
        if ($receipt.sensor_id -ne $oldReceipt.sensor_id -or $receipt.device_id -ne $oldReceipt.device_id) {
            throw "Channel $($entry.Channel) changed sensor or device identity."
        }
        if ([int64]$state.last_sequence -lt [int64]$oldState.last_sequence) {
            throw "Channel $($entry.Channel) regressed its published sequence."
        }
        $service = Get-CimInstance Win32_Service -Filter "Name='$($entry.Name)'"
        if (-not $service -or $service.State -ne 'Running' -or
            $service.StartName -ne "NT SERVICE\$($entry.Name)" -or
            $service.PathName -notlike "*$exe*") {
            throw "Channel $($entry.Channel) service identity or binary readback failed."
        }
    }
    Write-Host 'Three channel services produced fresh receipts. Verify ingestion, cursor continuity and soak before acceptance.'
} catch {
    $failure = $_
    Restore-Legacy
    throw "Cutover failed and legacy publisher was restarted: $failure"
}

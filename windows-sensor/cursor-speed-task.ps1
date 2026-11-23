# Install or inspect one independent, current-user cursor monitor task.
param(
    [ValidateSet('Install', 'Update', 'Status', 'Remove', 'SelfTest')][string]$Action = 'Status'
)
$ErrorActionPreference = 'Stop'
$name = 'JarvisCursorSpeed'
$dir = Join-Path $env:LOCALAPPDATA 'Jarvis\CursorSpeed'
$target = Join-Path $dir 'cursor-speed.ps1'
$source = Join-Path $PSScriptRoot 'cursor-speed.ps1'
$ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$argument = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $target + '"'

function Get-Observation([string]$TaskState, [Nullable[double]]$AgeSeconds, [string]$ReceiptStatus) {
    if ($TaskState -eq 'Running' -and $null -ne $AgeSeconds -and
        $AgeSeconds -ge 0 -and $AgeSeconds -le 30 -and $ReceiptStatus -eq 'complete') {
        return 'fresh'
    }
    if ($null -eq $AgeSeconds) { return 'unavailable' }
    return 'stale'
}

if ($Action -eq 'SelfTest') {
    if ((Get-Observation 'Running' 10 'complete') -ne 'fresh' -or
        (Get-Observation 'Ready' 10 'complete') -ne 'stale' -or
        (Get-Observation 'Running' 31 'complete') -ne 'stale' -or
        (Get-Observation 'Running' $null 'complete') -ne 'unavailable' -or
        (Get-Observation 'Running' 10 'partial') -ne 'stale') {
        throw 'cursor freshness self-test failed'
    }
    Write-Output 'cursor freshness self-test passed'
    return
}

if ($Action -eq 'Install') {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        throw "$name already exists; inspect it before replacing it"
    }
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $source -SelfTest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'cursor monitor self-test failed' }
    [void](New-Item -ItemType Directory -Path $dir -Force)
    Copy-Item -LiteralPath $source -Destination $target
    $taskAction = New-ScheduledTaskAction -Execute $ps -Argument $argument
    $logon = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    # Periodic trigger also recovers a process that exited after Task Scheduler's
    # bounded immediate restart attempts. IgnoreNew prevents duplicate workers.
    $periodic = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -RepetitionDuration (New-TimeSpan -Days 3650)
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -LogonType Interactive -RunLevel Limited
    try {
        Register-ScheduledTask -TaskName $name -Action $taskAction `
            -Trigger @($logon, $periodic) -Settings $settings -Principal $principal | Out-Null
        Start-ScheduledTask -TaskName $name
    } catch {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
        throw
    }
}
if ($Action -eq 'Update') {
    $existing = Get-ScheduledTask -TaskName $name -ErrorAction Stop
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (@($existing.Actions).Count -ne 1 -or
        $existing.Actions[0].Execute -ine $ps -or
        $existing.Actions[0].Arguments -cne $argument -or
        $existing.Principal.UserId.Split('\')[-1] -ine $currentUser.Split('\')[-1] -or
        $existing.Principal.LogonType -ne 'Interactive' -or
        $existing.Principal.RunLevel -ne 'Limited') {
        throw 'installed task differs from reviewed cursor task; refusing update'
    }
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $source -SelfTest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'new cursor monitor self-test failed' }
    $backup = "$target.previous"
    Stop-ScheduledTask -TaskName $name
    $staged = "$target.new"
    try {
        Copy-Item -LiteralPath $source -Destination $staged -Force
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        [IO.File]::Replace($staged, $target, $backup)
        Start-ScheduledTask -TaskName $name
    } catch {
        if (Test-Path -LiteralPath $backup) {
            Copy-Item -LiteralPath $backup -Destination $target -Force
        }
        Start-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        throw
    }
}
if ($Action -eq 'Remove') {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
    Write-Output 'Task removed; local measurements retained.'
    return
}
$task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
$statePath = Join-Path $dir 'state.json'
$state = $null
$age = $null
if (Test-Path -LiteralPath $statePath) {
    try {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $age = [Math]::Round(([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse($state.observed_utc)).TotalSeconds, 1)
    } catch { $age = $null }
}
$taskState = if ($task) { [string]$task.State } else { 'missing' }
$observation = Get-Observation $taskState $age ([string]$state.status)
[pscustomobject]@{
    task = $name
    task_state = $taskState
    observation = $observation
    age_seconds = $age
    state = $state
} | ConvertTo-Json -Depth 6 -Compress

# Rewraps JARVIS's existing monitor tasks in conhost --headless (no window ever),
# keeping their triggers, principal, settings and arguments exactly as registered.
# -SyncScripts also refreshes each installed script copy from this checkout. Leave it off
# until jarvis.service runs the same checkout: the new health monitor requires protection_healthy
# from /api/health and would alert against an older service that does not send it.
param([Parameter(Mandatory)][string]$RepoRoot, [switch]$DryRun, [switch]$SyncScripts)
$ErrorActionPreference = 'Stop'
$conhost = "$env:SystemRoot\System32\conhost.exe"
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$tasks = @{
    'JARVIS independent health monitor' = 'jarvis-health-monitor.ps1'
    'JARVIS connectivity guard'         = 'jarvis-connectivity-guard.ps1'
    'jarvis wake watchdog'              = 'jarvis-wake-watchdog.ps1'
}
foreach ($name in $tasks.Keys) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if (-not $task) { Write-Output "$name : not installed, skipped"; continue }
    if (@($task.Actions).Count -ne 1) { Write-Output "$name : unexpected action count, skipped"; continue }
    $a = $task.Actions[0]
    if ($a.Arguments -notmatch '(?i)(?:^|\s)-File\s+"([^"]+)"') { Write-Output "$name : no -File target, skipped"; continue }
    $target = $Matches[1]
    $source = Join-Path $RepoRoot $tasks[$name]
    if ([IO.Path]::GetFileName($target) -ne $tasks[$name]) { Write-Output "$name : target $target unexpected, skipped"; continue }
    $leaf = [IO.Path]::GetFileName($a.Execute)
    if ($leaf -ieq 'conhost.exe') { $inner = ($a.Arguments -replace '(?i)^--headless\s+"[^"]+"\s+', '') }
    elseif ($leaf -ieq 'powershell.exe') { $inner = $a.Arguments }
    else { Write-Output "$name : execute $($a.Execute) unexpected, skipped"; continue }
    $newArgs = '--headless "' + $ps + '" ' + $inner
    if ($DryRun) { Write-Output "$name : sync=$SyncScripts $source -> $target; action $conhost $newArgs"; continue }
    if ($SyncScripts) { Copy-Item -LiteralPath $source -Destination $target -Force }
    $action = if ($a.WorkingDirectory) { New-ScheduledTaskAction -Execute $conhost -Argument $newArgs -WorkingDirectory $a.WorkingDirectory }
              else { New-ScheduledTaskAction -Execute $conhost -Argument $newArgs }
    [void](Set-ScheduledTask -TaskName $name -TaskPath $task.TaskPath -Action $action)
    $check = (Get-ScheduledTask -TaskName $name).Actions[0]
    Write-Output ("$name : " + $(if ($check.Execute -eq $conhost -and $check.Arguments -eq $newArgs) {'updated'} else {'VERIFY FAILED'}))
}

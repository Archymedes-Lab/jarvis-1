# Independent, unprivileged interactive-session cursor speed monitor.
# No positions, clicks, keys, window titles or process names are persisted.
param(
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'Jarvis\CursorSpeed'),
    [switch]$SelfTest,
    [switch]$Once
)
$ErrorActionPreference = 'Stop'

function Get-WindowSpeed([double]$Distance, [double]$Seconds) {
    if ($Seconds -le 0) { throw 'invalid sample duration' }
    return [Math]::Round($Distance / $Seconds, 1)
}
function Get-WindowStatus([double]$Seconds) {
    if ($Seconds -gt 0 -and $Seconds -le 15) { return 'complete' }
    return 'partial'
}

if ($SelfTest) {
    if ((Get-WindowSpeed 500 10) -ne 50 -or (Get-WindowSpeed 0 10) -ne 0) {
        throw 'speed calculation self-test failed'
    }
    try { Get-WindowSpeed 1 0 | Out-Null; throw 'zero duration accepted' }
    catch { if ($_.Exception.Message -ne 'invalid sample duration') { throw } }
    if ((Get-WindowStatus 10) -ne 'complete' -or
        (Get-WindowStatus 60) -ne 'partial' -or
        (Get-WindowStatus 0) -ne 'partial') { throw 'gap self-test failed' }
    Write-Output 'cursor speed self-test passed'
    return
}

$source = @'
using System;
using System.Runtime.InteropServices;
public static class CursorSpeedWin32 {
    [StructLayout(LayoutKind.Sequential)] public struct Point { public int X; public int Y; }
    [DllImport("user32.dll", SetLastError=true)] public static extern bool GetCursorPos(out Point p);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool SystemParametersInfo(uint action, uint param, out int value, uint flags);
}
'@
Add-Type -TypeDefinition $source

$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($session -eq 0) { throw 'cursor monitoring requires an interactive session' }
$mutex = New-Object Threading.Mutex($false, "Local\JarvisCursorSpeed-$session")
if (-not $mutex.WaitOne(0)) { $mutex.Dispose(); return }
try {
    [void](New-Item -ItemType Directory -Path $StateDirectory -Force)
    $statePath = Join-Path $StateDirectory 'state.json'
    $eventsPath = Join-Path $StateDirectory 'events.jsonl'
    $maxBytes = 2MB
    $point = New-Object CursorSpeedWin32+Point
    $previous = $null
    $lastTick = [Diagnostics.Stopwatch]::GetTimestamp()
    $lastFlush = [DateTimeOffset]::UtcNow
    $lastSettings = $null
    $lastObserved = $null
    $samples = 0; $distance = 0.0; $peak = 0.0
    $sequence = 0
    if (Test-Path -LiteralPath $statePath) {
        try {
            $old = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            if ($old.sensor -eq 'cursor-speed' -and $old.session -eq $session -and
                [int]$old.sequence -ge 0) {
                $sequence = [int]$old.sequence
                $lastSettings = $old.settings | ConvertTo-Json -Compress
                $lastObserved = [DateTimeOffset]::Parse($old.observed_utc)
            }
        } catch { throw 'existing cursor state is unreadable; preserving it' }
    }
    while ($true) {
        Start-Sleep -Milliseconds 200
        $tick = [Diagnostics.Stopwatch]::GetTimestamp()
        $elapsed = ($tick - $lastTick) / [double][Diagnostics.Stopwatch]::Frequency
        $lastTick = $tick
        $ok = [CursorSpeedWin32]::GetCursorPos([ref]$point)
        if (-not $ok) { throw 'GetCursorPos failed' }
        if ($null -ne $previous -and $elapsed -gt 0 -and $elapsed -le 1) {
            $dx = [double]$point.X - $previous.X
            $dy = [double]$point.Y - $previous.Y
            $step = [Math]::Sqrt($dx * $dx + $dy * $dy)
            # A warp, desktop switch, or missed sample is not human movement.
            if ($step -le 1000) {
                $distance += $step
                if ($step -gt 0) {
                    $samples++
                    $peak = [Math]::Max($peak, $step / $elapsed)
                }
            }
        }
        $previous = [pscustomobject]@{ X = $point.X; Y = $point.Y }
        $now = [DateTimeOffset]::UtcNow
        if (($now - $lastFlush).TotalSeconds -lt 10) { continue }
        $seconds = ($now - $lastFlush).TotalSeconds
        # Sleep, a blocked desktop API, or a long scheduling pause leaves a
        # measurement gap; a divided total would disguise that gap as slowness.
        $complete = (Get-WindowStatus $seconds) -eq 'complete'
        $speed = $null
        if ($complete) { $speed = Get-WindowSpeed $distance $seconds }
        $pointerSpeed = 0
        if (-not [CursorSpeedWin32]::SystemParametersInfo(0x70, 0, [ref]$pointerSpeed, 0)) {
            throw 'SPI_GETMOUSESPEED failed'
        }
        $mouse = Get-ItemProperty 'HKCU:\Control Panel\Mouse' -ErrorAction Stop
        $settings = [ordered]@{
            pointer_speed = $pointerSpeed
            acceleration = [string]$mouse.MouseSpeed
            threshold1 = [string]$mouse.MouseThreshold1
            threshold2 = [string]$mouse.MouseThreshold2
        }
        $settingsJson = $settings | ConvertTo-Json -Compress
        $sequence++
        $state = [ordered]@{
            schema = 1; sensor = 'cursor-speed'; session = $session
            sequence = $sequence; observed_utc = $now.ToString('o')
            status = $(if ($complete) { 'complete' } else { 'partial' })
            window_seconds = [Math]::Round($seconds, 1)
            cursor_pixels_per_second = $speed
            movement_samples = $(if ($complete) { $samples } else { $null })
            peak_sample_pixels_per_second = $(if ($complete) { [Math]::Round($peak, 1) } else { $null })
            settings = $settings
        }
        $json = $state | ConvertTo-Json -Depth 4 -Compress
        # Commit a discrete setting transition first. An interrupted state
        # update may repeat that event after restart, but cannot erase it.
        if ($null -ne $lastObserved) {
            $restart = [ordered]@{ observed_utc = $state.observed_utc; session = $session
                                   sequence = $sequence; type = 'worker_restarted'
                                   since_last_receipt_seconds = [Math]::Round(($now - $lastObserved).TotalSeconds, 1) }
            if ((Test-Path $eventsPath) -and (Get-Item $eventsPath).Length -ge $maxBytes) {
                Move-Item -LiteralPath $eventsPath -Destination "$eventsPath.previous" -Force
            }
            [IO.File]::AppendAllText($eventsPath, (($restart | ConvertTo-Json -Compress) + "`n"), [Text.Encoding]::UTF8)
            $lastObserved = $null
        }
        if ($lastSettings -ne $settingsJson) {
            $event = [ordered]@{ observed_utc = $state.observed_utc; session = $session
                                  sequence = $sequence; type = $(if ($null -eq $lastSettings) { 'baseline' } else { 'settings_changed' })
                                  settings = $settings }
            if ((Test-Path $eventsPath) -and (Get-Item $eventsPath).Length -ge $maxBytes) {
                Move-Item -LiteralPath $eventsPath -Destination "$eventsPath.previous" -Force
            }
            [IO.File]::AppendAllText($eventsPath, (($event | ConvertTo-Json -Depth 4 -Compress) + "`n"), [Text.Encoding]::UTF8)
            $lastSettings = $settingsJson
        }
        $temp = "$statePath.tmp"
        [IO.File]::WriteAllText($temp, $json + "`n", [Text.Encoding]::UTF8)
        if (Test-Path -LiteralPath $statePath) {
            $swapBackup = "$statePath.swap-backup"
            if (Test-Path -LiteralPath $swapBackup) { Remove-Item -LiteralPath $swapBackup -Force }
            [IO.File]::Replace($temp, $statePath, $swapBackup)
            Remove-Item -LiteralPath $swapBackup -Force
        } else {
            [IO.File]::Move($temp, $statePath)
        }
        $lastFlush = $now
        $samples = 0; $distance = 0.0; $peak = 0.0
        if ($Once) { return }
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}

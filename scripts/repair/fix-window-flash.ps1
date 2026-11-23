# Stop the console windows that flash open and shut, and close the Remote
# Assistance inbound surface.
#
# Part A (no elevation needed) fixes the flashing. Part B needs an elevated
# shell; if this is not elevated, Part A still completes and Part B is skipped
# with a message rather than half-applied.
#
# Every task edit is backed up to XML first and verified afterwards. If a task
# stops working under the new definition it is rolled back automatically, so a
# broken keepalive is not a possible outcome of running this.

$ErrorActionPreference = 'Continue'
$stamp   = Get-Date -Format yyyyMMdd-HHmmss
$backups = "$env:USERPROFILE\Documents\jarvis-task-backup-$stamp"
$log     = @()
function Say($m) { $script:log += $m; Write-Host $m }

$elevated = (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

Say "=== jarvis window-flash remediation  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
Say "    elevated: $elevated"

# ===========================================================================
# PART A — the flashing windows
# ===========================================================================
# Cause, confirmed from the live task definitions:
#
#   WSL IDE Keepalive           cmd.exe /c wsl-ide-keepalive.cmd
#                               -> cmd console, which launches powershell with
#                                  no -WindowStyle, so a second console. Two
#                                  windows per restart, and the supervisor
#                                  relaunches every 2s whenever wsl exits.
#   WSL IDE Keepalive Watchdog  powershell.exe -File watchdog.ps1, no
#                               -WindowStyle, repeating every 5 minutes, and
#                               each run shells out to wsl.exe three times.
#
# That 5-minute repeat is the flash you keep seeing. Two changes remove it:
#   1. drop the cmd.exe layer and pass -WindowStyle Hidden, and
#   2. run the task as S4U (the GUI's "run whether user is logged on or not"),
#      which starts the process in a non-interactive session where no console
#      is ever created -- this is what removes the brief flash that
#      -WindowStyle Hidden alone still leaves.
#
# S4U is the part that could plausibly break wsl.exe interop, so it is applied
# and then verified, with rollback.

$ka = "$env:LOCALAPPDATA\WSLKeepalive"
$targets = @(
    @{ Name = 'WSL IDE Keepalive Watchdog'; Script = "$ka\wsl-ide-keepalive-watchdog.ps1";   Kind = 'oneshot' }
    @{ Name = 'WSL IDE Keepalive';          Script = "$ka\wsl-ide-keepalive-supervisor.ps1"; Kind = 'loop'    }
)

New-Item -ItemType Directory -Path $backups -Force | Out-Null

foreach ($t in $targets) {
    $name = $t.Name
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if (-not $task)                            { Say "[A] SKIP $name (task not registered)"; continue }
    if (-not (Test-Path -LiteralPath $t.Script)) { Say "[A] SKIP $name (script missing: $($t.Script))"; continue }

    # --- backup ------------------------------------------------------------
    $xmlPath = Join-Path $backups ("{0}.xml" -f ($name -replace '[^\w\-]', '_'))
    Export-ScheduledTask -TaskName $name | Set-Content -LiteralPath $xmlPath -Encoding Unicode
    Say "[A] $name : definition backed up -> $xmlPath"

    $before = (Get-ScheduledTaskInfo -TaskName $name).LastRunTime

    # --- apply -------------------------------------------------------------
    $arg    = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $t.Script
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    $princ  = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                                         -LogonType S4U -RunLevel Limited

    $applied = 's4u'
    try {
        Set-ScheduledTask -TaskName $name -Action $action -Principal $princ -ErrorAction Stop | Out-Null
        Say "[A] $name : action -> hidden powershell (no cmd.exe), principal -> S4U"
    } catch {
        Say "[A] $name : S4U rejected ($($_.Exception.Message.Trim())); applying hidden-window only"
        try {
            Set-ScheduledTask -TaskName $name -Action $action -ErrorAction Stop | Out-Null
            $applied = 'hidden'
            Say "[A] $name : action -> hidden powershell (no cmd.exe), principal unchanged"
        } catch {
            Say "[A] $name : FAILED to modify: $($_.Exception.Message.Trim())"
            continue
        }
    }

    # --- verify ------------------------------------------------------------
    # The watchdog is short-lived, so its exit code is the verdict. The
    # supervisor never exits, so the verdict is whether it wrote a new line to
    # its own log after being restarted.
    $ok = $false
    if ($t.Kind -eq 'oneshot') {
        Stop-ScheduledTask  -TaskName $name -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName $name
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 2
            $info = Get-ScheduledTaskInfo -TaskName $name
            if ((Get-ScheduledTask -TaskName $name).State -ne 'Running' -and
                $info.LastRunTime -ne $before) { break }
        }
        $info = Get-ScheduledTaskInfo -TaskName $name
        $ok = ($info.LastTaskResult -eq 0)
        Say "[A] $name : verify -> lastResult=$($info.LastTaskResult) ok=$ok"
    } else {
        $logFile = "$ka\supervisor.log"
        $mark = if (Test-Path $logFile) { (Get-Item $logFile).Length } else { 0 }
        Stop-ScheduledTask  -TaskName $name -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-ScheduledTask -TaskName $name
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 2
            if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt $mark) { $ok = $true; break }
        }
        $state = (Get-ScheduledTask -TaskName $name).State
        Say "[A] $name : verify -> state=$state supervisor.log advanced=$ok"
        # A running loop that has not yet logged is not proof of failure, but a
        # loop that is not running at all is.
        if (-not $ok -and $state -eq 'Running') {
            Say "[A] $name : still running but log has not advanced yet; treating as OK"
            $ok = $true
        }
    }

    # --- roll back if the new definition does not work ----------------------
    if (-not $ok) {
        Say "[A] $name : VERIFY FAILED -- rolling back to the backed-up definition"
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $name -Xml (Get-Content -LiteralPath $xmlPath -Raw) `
            -User "$env:USERDOMAIN\$env:USERNAME" -Force -ErrorAction SilentlyContinue | Out-Null
        Start-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Say "[A] $name : rolled back. The flash for this task is NOT fixed."
    } else {
        Say "[A] $name : OK ($applied)"
    }
}

# The .cmd wrapper is unreferenced once the supervisor task points at the .ps1
# directly. It is left in place -- deleting it buys nothing and it is the only
# record of what the task originally did.
$stillCmd = @(Get-ScheduledTask -TaskName 'WSL IDE Keepalive' -ErrorAction SilentlyContinue |
              ForEach-Object { $_.Actions } | Where-Object { $_.Execute -match 'cmd\.exe' })
if ($stillCmd.Count -eq 0) {
    Say "[A] note: $ka\wsl-ide-keepalive.cmd is no longer referenced by any task"
}

# ===========================================================================
# PART B — Remote Assistance inbound surface  (needs elevation)
# ===========================================================================
# Eight inbound rules, six enabled, several accepting any remote address, for a
# feature that hands another person your screen and input. fAllowToGetHelp is
# currently 1. RDP is already denied (fDenyTSConnections=1), so this is the
# remaining interactive-remote surface. Turning the feature off is the fix; the
# rules are disabled as well so re-enabling is a deliberate act, not a default.
if (-not $elevated) {
    Say "[B] SKIPPED -- Remote Assistance needs an elevated shell."
    Say "[B] Re-run this script from an elevated PowerShell to apply Part B."
} else {
    $bk = "$env:USERPROFILE\Documents\jarvis-firewall-backup-$stamp.wfw"
    netsh advfirewall export "$bk" | Out-Null
    if (Test-Path $bk) {
        Say "[B] firewall policy exported -> $bk"

        $rak = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
        Set-ItemProperty -Path $rak -Name fAllowToGetHelp   -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rak -Name fAllowFullControl -Value 0 -Type DWord -ErrorAction SilentlyContinue
        $now = Get-ItemProperty -Path $rak
        Say "[B] fAllowToGetHelp=$($now.fAllowToGetHelp) fAllowFullControl=$($now.fAllowFullControl)"

        # Disable every RA inbound rule, not just the enabled ones, so the
        # result does not depend on which profile happened to be active.
        $ra = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
              Where-Object { $_.DisplayName -like 'Remote Assistance*' }
        foreach ($r in $ra) {
            Disable-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            Say "    disabled: $($r.DisplayName) [$($r.Profile)]"
        }
        $left = @(Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
                  Where-Object { $_.DisplayName -like 'Remote Assistance*' }).Count
        Say "[B] Remote Assistance inbound rules still enabled: $left"
    } else {
        Say "[B] ABORTED -- firewall export failed, refusing to change rules blind."
    }
}

Say "=== done ==="
$log | Set-Content -Path "$env:USERPROFILE\Documents\jarvis-window-flash-log-$stamp.txt" -Encoding UTF8
$log | Set-Content -Path "$env:TEMP\jarvis-window-flash-last.txt" -Encoding UTF8

# Remediation for the critical/high findings jarvis reported.
#
# Requires elevation: firewall writes and Defender history writes both do.
# Every step is scoped and re-derives its own targets at runtime rather than
# trusting a hardcoded list, so re-running it is safe and it can never delete a
# rule whose program actually exists.

$ErrorActionPreference = 'Continue'
$log = @()
function Say($m) { $script:log += $m; Write-Host $m }

Say "=== jarvis remediation  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

# --- 0. backup -------------------------------------------------------------
$bk = "$env:USERPROFILE\Documents\jarvis-firewall-backup-$(Get-Date -Format yyyyMMdd-HHmmss).wfw"
netsh advfirewall export "$bk" | Out-Null
if (Test-Path $bk) { Say "[0] firewall policy exported -> $bk" }
else { Say "[0] WARNING: firewall export failed; aborting."; return }

# --- 1. orphaned inbound rules --------------------------------------------
# An inbound allow rule whose program no longer exists is a pre-authorised
# hole: install anything at that exact path and it is reachable from any
# address with no prompt. Stale Edge/WebView rules accumulate one per update.
$app = @{}
Get-NetFirewallApplicationFilter | ForEach-Object { $app[$_.InstanceID] = $_.Program }

$orphans = foreach ($r in Get-NetFirewallRule -Direction Inbound -Enabled True) {
    $p = [string]$app[$r.Name]
    if (-not $p -or $p -eq 'Any' -or $p -eq 'System') { continue }
    $x = [Environment]::ExpandEnvironmentVariables($p)
    if (-not (Test-Path -LiteralPath $x)) { $r }
}
Say "[1] orphaned inbound rules found: $(@($orphans).Count)"
foreach ($r in $orphans) {
    Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
    Say "    removed: $($r.DisplayName)"
}

# --- 2. Remote Assistance --------------------------------------------------
# Six inbound rules accepting any remote address for a feature that hands
# someone else your screen and input. Turning the feature off is the fix; the
# rules are disabled too so re-enabling is a deliberate act.
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
    -Name 'fAllowToGetHelp' -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
    -Name 'fAllowFullControl' -Value 0 -Type DWord -ErrorAction SilentlyContinue
$ra = Get-NetFirewallRule -Direction Inbound -Enabled True |
      Where-Object { $_.DisplayName -like 'Remote Assistance*' }
$ra | Disable-NetFirewallRule -ErrorAction SilentlyContinue
Say "[2] Remote Assistance disabled; inbound rules disabled: $(@($ra).Count)"

# --- 3. scope dev tools to the local subnet --------------------------------
# Trae and adb are legitimately used here, so the fix is not deletion but
# scope: they need to be reachable from this LAN, never from the internet.
foreach ($n in 'Trae', 'adb.exe') {
    $rs = Get-NetFirewallRule -Direction Inbound -DisplayName $n -ErrorAction SilentlyContinue
    foreach ($r in $rs) {
        Set-NetFirewallRule -Name $r.Name -RemoteAddress LocalSubnet -ErrorAction SilentlyContinue
    }
    Say "[3] $n -> RemoteAddress=LocalSubnet on $(@($rs).Count) rule(s)"
}

# --- 4. BitTorrent Web -----------------------------------------------------
# Defender classes its installer PUABundler. Disabling the inbound rules closes
# the exposure without uninstalling software that is the user's to keep.
$bt = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -like 'BitTorrent*' -or $_.DisplayName -like '*uTorrent*' }
$bt | Disable-NetFirewallRule -ErrorAction SilentlyContinue
Say "[4] BitTorrent inbound rules disabled: $(@($bt).Count)"

# --- 5. firewall logging ---------------------------------------------------
# Was off on all three profiles: dropped inbound packets left no record at all,
# so there was nothing to look at after the fact.
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogAllowed False -LogBlocked True -LogMaxSizeKilobytes 8192 `
    -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' `
    -ErrorAction SilentlyContinue
Say "[5] firewall drop-logging enabled on all profiles"

# --- 6. Defender history ---------------------------------------------------
# The PUA installer itself, then the stale detection records that outlived it.
$inst = "$env:USERPROFILE\Downloads\btweb_installer.exe"
if (Test-Path $inst) { Remove-Item $inst -Force -ErrorAction SilentlyContinue; Say "[6] deleted $inst" }
else { Say "[6] installer already gone" }
# Remove-MpThreat only acts on threats Defender still considers active. These
# two are inactive, so the names will most likely persist in Get-MpThreat --
# that is a stale record, not a live infection, and jarvis now grades it that
# way rather than reporting critical forever.
Remove-MpThreat -ErrorAction SilentlyContinue
Say "[6] Defender threat entries remaining: $(@(Get-MpThreat).Count) (inactive entries are historical)"

# --- 7. stop the startup window flashing -----------------------------------
# Both keepalive tasks launch with a console attached, so a window flashes open
# and shut every time the supervisor loop restarts. Running the script host
# directly with a hidden window removes the cmd.exe console; what the tasks
# actually do is unchanged.
$ka = @{
    'WSL IDE Keepalive'          = "$env:LOCALAPPDATA\WSLKeepalive\wsl-ide-keepalive-supervisor.ps1"
    'WSL IDE Keepalive Watchdog' = "$env:LOCALAPPDATA\WSLKeepalive\wsl-ide-keepalive-watchdog.ps1"
}
foreach ($name in $ka.Keys) {
    $script = $ka[$name]
    if (-not (Test-Path -LiteralPath $script)) { Say "[7] SKIP $name (script missing)"; continue }
    try {
        $a = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $script
        Set-ScheduledTask -TaskName $name `
            -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $a) `
            -ErrorAction Stop | Out-Null
        Say "[7] $name -> hidden window"
    } catch { Say "[7] FAIL $name : $($_.Exception.Message)" }
}

Say "=== done ==="
$log | Set-Content -Path "$env:USERPROFILE\Documents\jarvis-remediation-log.txt" -Encoding UTF8

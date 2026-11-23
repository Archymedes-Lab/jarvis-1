# The one JARVIS step that needs Administrator: Windows Firewall connection
# logging and Attack Surface Reduction rules. Everything reversible.
#
#   .\harden-elevated.ps1            firewall logging on; ASR rules in AuditMode
#   .\harden-elevated.ps1 -Enforce   ...and flip the ASR rules to Enabled
#   .\harden-elevated.ps1 -Undo      restore firewall logging; disable the rules
#
# quickstart.sh stages this to %LOCALAPPDATA%\Jarvis and runs it via one UAC
# prompt. It can also be run by hand from an elevated PowerShell.
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Enforce, [switch]$Undo)
$ErrorActionPreference = 'Stop'

$dir = Join-Path $env:LOCALAPPDATA 'Jarvis\InternetProtection'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$fwBackup = Join-Path $dir 'firewall-before.json'

# --- 1. Windows Firewall: record allowed as well as blocked -------------------
# Changes no allow/block rules, only logging. 32 MB per profile log.
if ($Undo) {
    if (Test-Path -LiteralPath $fwBackup) {
        foreach ($r in (Get-Content -LiteralPath $fwBackup -Raw | ConvertFrom-Json)) {
            Set-NetFirewallProfile -Name $r.Name -LogAllowed $r.LogAllowed `
                -LogBlocked $r.LogBlocked -LogMaxSizeKilobytes $r.LogMaxSizeKilobytes
        }
        Write-Host 'firewall logging: restored from backup'
    } else {
        Write-Host 'firewall logging: no backup found, left as-is'
    }
} else {
    if (-not (Test-Path -LiteralPath $fwBackup)) {
        Get-NetFirewallProfile |
            Select-Object Name, LogAllowed, LogBlocked, LogMaxSizeKilobytes |
            ConvertTo-Json | Set-Content -LiteralPath $fwBackup -Encoding UTF8
    }
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
    Write-Host 'firewall logging: allowed + blocked, 32 MB per profile'
}
Get-NetFirewallProfile |
    Format-Table Name, Enabled, LogAllowed, LogBlocked, LogMaxSizeKilobytes

# --- 2. Attack Surface Reduction rules --------------------------------------
# The seven high-signal rules the posture collector flags, plus LSASS theft.
$ids = @(
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',  # block executable content from email
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # block Office child processes
    '3B576869-A4EC-4529-8536-B80A7769E899',  # block Office executable content
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',  # block Office code injection
    'D3E037E1-3EB8-44C8-A917-57927947596D',  # block JS/VBS launching downloads
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',  # block obfuscated scripts
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',  # block Win32 API calls from macros
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'   # block credential stealing from LSASS
)
$action = if ($Undo) { 'Disabled' } elseif ($Enforce) { 'Enabled' } else { 'AuditMode' }
foreach ($id in $ids) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id `
        -AttackSurfaceReductionRules_Actions $action
}
Write-Host "ASR rules: $action"
$p = Get-MpPreference
for ($i = 0; $i -lt $p.AttackSurfaceReductionRules_Ids.Count; $i++) {
    '  {0}  {1}' -f $p.AttackSurfaceReductionRules_Ids[$i],
                    $p.AttackSurfaceReductionRules_Actions[$i]
}

# --- 3. Credential Guard: report only (needs reboot + BIOS virtualization) --
$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($dg -and $dg.SecurityServicesRunning -contains 1) {
    Write-Host 'Credential Guard: running'
} else {
    Write-Host 'Credential Guard: NOT running. Settings > Privacy & security >'
    Write-Host '  Windows Security > Device security > Core isolation >'
    Write-Host '  Memory integrity = On, then reboot. Needs virtualization in BIOS.'
}

Write-Host "`ndone. undo: -Undo   enforce ASR: -Enforce"

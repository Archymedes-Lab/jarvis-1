# Closes the two exposures measured in PROTECTION-REVIEW-2026-10-21 that need an
# administrator, in one elevated run with receipts and an -Undo:
#
#   F4  the BitTorrent Web inbound allow rules on the Public profile are disabled
#       (the client keeps working; only unsolicited inbound peers on public networks stop)
#   F5  the revised JARVIS Sysmon baseline is applied through the existing
#       apply-jarvis-sysmon-policy.ps1 (exact backup, hash-checked, auto-restore on a
#       failed readback), which removes the registry volume that overflows the driver
#       queue at every boot
#
#   .\close-exposures.ps1 -PolicyPath <baseline.xml> -ExpectedSha256 <hex>
#   .\close-exposures.ps1 -Undo        re-enables the BitTorrent rules; Sysmon rollback is
#                                      apply-jarvis-sysmon-policy.ps1 -Rollback <backup folder>
# Apply the Sysmon policy only after the release that carries the same baseline is live,
# or the evidence job reports the running policy as drifted.
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$PolicyPath = '', [string]$ExpectedSha256 = '', [switch]$Undo)
$ErrorActionPreference = 'Continue'
$dir = Join-Path $env:LOCALAPPDATA 'Jarvis\Hardening'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$receipt = [ordered]@{ at = (Get-Date).ToString('o'); mode = $(if ($Undo) { 'undo' } else { 'apply' }); steps = @() }
function Step([string]$name, [scriptblock]$do, [scriptblock]$verify) {
    $r = [ordered]@{ step = $name; ok = $false; detail = '' }
    try { & $do | Out-Null; $r.detail = [string](& $verify); $r.ok = $true } catch { $r.detail = "FAILED: $($_.Exception.Message)" }
    $script:receipt.steps += $r
    Write-Host ("{0,-4} {1}: {2}" -f $(if ($r.ok) { 'ok' } else { 'FAIL' }), $name, $r.detail)
}
$bt = Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object {
    ($_ | Get-NetFirewallApplicationFilter).Program -match 'BitTorrent Web\\btweb\.exe$' }
if ($Undo) {
    Step 'BitTorrent Web inbound rules re-enabled' { $bt | Enable-NetFirewallRule } { ($bt | % { $_.DisplayName + '=' + (Get-NetFirewallRule -Name $_.Name).Enabled }) -join ', ' }
} else {
    Step 'BitTorrent Web inbound rules disabled (public exposure)' {
        $bt | Disable-NetFirewallRule
    } { ($bt | % { $_.DisplayName + '=' + (Get-NetFirewallRule -Name $_.Name).Enabled }) -join ', ' }
    Step 'btweb listener state after the change' { } {
        (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -eq 'btweb' } | % { "$($_.LocalAddress):$($_.LocalPort)" }) -join ' ' }
    if ($PolicyPath -and $ExpectedSha256) {
        $apply = Join-Path (Split-Path -Parent $PSScriptRoot) 'repair\apply-jarvis-sysmon-policy.ps1'
        Step 'Sysmon baseline applied (backup + readback inside the apply script)' {
            & $apply -PolicyPath $PolicyPath -ExpectedSha256 $ExpectedSha256
        } { (& 'C:\Windows\Sysmon64.exe' -c 2>&1 | Select-String -Pattern 'Hashing|RegistryEvent' | Select-Object -First 2) -join ' | ' }
    } else {
        Write-Host 'Sysmon baseline not applied: pass -PolicyPath and -ExpectedSha256 after the release is live.'
    }
}
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir ("exposures-receipt-{0}.json" -f (Get-Date -Format yyyyMMdd-HHmmss))) -Encoding UTF8
$failed = @($receipt.steps | Where-Object { -not $_.ok }).Count
Write-Host ("{0} steps, {1} failed. Receipt in {2}" -f $receipt.steps.Count, $failed, $dir)
if ($failed) { exit 1 }

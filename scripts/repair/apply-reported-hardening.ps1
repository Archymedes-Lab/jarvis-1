#Requires -RunAsAdministrator
# Applies the Windows fixes the JARVIS security report asks for, in one elevated
# run, and records everything it changes so each step can be undone:
#
#   1. inbound firewall exposures  (repair-reported-firewall.ps1, same folder)
#   2. the seven key Attack Surface Reduction rules -> Enabled
#   3. Credential Guard (with virtualization-based security) — takes effect
#      after a reboot, which this script never performs
#
#   powershell -ExecutionPolicy Bypass -File apply-reported-hardening.ps1
#   powershell -ExecutionPolicy Bypass -File apply-reported-hardening.ps1 -Undo <record.json>
#
# A transcript and a rollback record are written to %LOCALAPPDATA%\Jarvis\repairs.
[CmdletBinding()]
param([string]$Undo = '', [switch]$CredentialGuardOnly)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:LOCALAPPDATA 'Jarvis\repairs'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Start-Transcript -LiteralPath (Join-Path $dir "hardening-$stamp.log") | Out-Null

$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA'
$dg  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
function Get-Value($path, $name) {
    $item = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue
    if ($item) { $item.$name } else { $null }
}
function Set-OrClear($path, $name, $value) {
    if ($null -eq $value) { Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction SilentlyContinue; return }
    # Never New-Item -Force on a key that exists: for the registry provider that
    # deletes and recreates the key, taking every subkey with it.
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path | Out-Null }
    Set-ItemProperty -LiteralPath $path -Name $name -Value $value -Type DWord
}

try {
    if ($Undo) {
        $r = Get-Content -LiteralPath $Undo -Raw | ConvertFrom-Json
        for ($i = 0; $i -lt @($r.asr.ids).Count; $i++) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $r.asr.ids[$i] -AttackSurfaceReductionRules_Actions $r.asr.actions[$i]
        }
        foreach ($id in $r.asrAdded) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id -ErrorAction SilentlyContinue }
        Set-OrClear $lsa 'LsaCfgFlags' $r.registry.LsaCfgFlags
        Set-OrClear $dg 'EnableVirtualizationBasedSecurity' $r.registry.EnableVirtualizationBasedSecurity
        Set-OrClear $dg 'RequirePlatformSecurityFeatures' $r.registry.RequirePlatformSecurityFeatures
        Write-Host "restored ASR and Credential Guard settings from $Undo (reboot to apply)."
        Write-Host "firewall rules: re-enable with the firewall record printed when they were disabled."
        return
    }

    # --- rollback record, written before anything changes ------------------
    $pref = Get-MpPreference
    $ids = @($pref.AttackSurfaceReductionRules_Ids)
    $record = [ordered]@{
        at = (Get-Date).ToString('o')
        asr = @{ ids = $ids; actions = @($pref.AttackSurfaceReductionRules_Actions) }
        asrAdded = @()
        registry = [ordered]@{
            LsaCfgFlags = Get-Value $lsa 'LsaCfgFlags'
            EnableVirtualizationBasedSecurity = Get-Value $dg 'EnableVirtualizationBasedSecurity'
            RequirePlatformSecurityFeatures = Get-Value $dg 'RequirePlatformSecurityFeatures'
        }
    }
    $key = @{
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'block Office apps creating child processes'
        '3B576869-A4EC-4529-8536-B80A7769E899' = 'block Office apps creating executable content'
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'block obfuscated scripts'
        'D3E037E1-3EB8-44C8-A917-57927947596D' = 'block JS/VBS launching downloaded content'
        '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'block credential theft from LSASS'
        '01443614-CD74-433A-B99E-2ECDC07BFC25' = 'block executables unless they meet prevalence/age criteria'
        '56A863A9-875E-4185-98A7-B882C64B5CE5' = 'block abuse of vulnerable signed drivers'
    }
    $record.asrAdded = @($key.Keys | Where-Object { $ids -notcontains $_ -and $ids -notcontains $_.ToLower() })
    $recordPath = Join-Path $dir "hardening-$stamp.json"
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $recordPath -Encoding UTF8
    Write-Host "rollback record: $recordPath"

    if (-not $CredentialGuardOnly) {
    # --- 1. firewall -----------------------------------------------------------
    Write-Host "`n== firewall exposures"
    & (Join-Path $PSScriptRoot 'repair-reported-firewall.ps1')

    # --- 2. ASR ------------------------------------------------------------------
    Write-Host "`n== attack surface reduction"
    foreach ($id in $key.Keys) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
    }
    $after = Get-MpPreference
    for ($i = 0; $i -lt $after.AttackSurfaceReductionRules_Ids.Count; $i++) {
        $id = $after.AttackSurfaceReductionRules_Ids[$i].ToUpper()
        if ($key.ContainsKey($id)) {
            $state = @{0='Disabled';1='Enabled';2='AuditMode';6='Warn'}[[int]$after.AttackSurfaceReductionRules_Actions[$i]]
            Write-Host ("  {0,-9} {1}" -f $state, $key[$id])
        }
    }
    Write-Host "  if a program you built yourself is blocked, relax only that rule:"
    Write-Host "  Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Warn"
    }

    # --- 3. Credential Guard ---------------------------------------------------
    # LsaCfgFlags 2 = on without UEFI lock: the same protection, and it can be
    # turned off again without clearing firmware variables (1 would lock it).
    Write-Host "`n== Credential Guard"
    # Memory integrity (HVCI) keeps its on/off setting under DeviceGuard\Scenarios.
    # If it is running now, make sure that setting says so, so the next boot
    # keeps it on (an earlier version of this script could recreate the
    # DeviceGuard key and drop it).
    $dgs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    $hvciKey = "$dg\Scenarios\HypervisorEnforcedCodeIntegrity"
    if ($dgs -and @($dgs.SecurityServicesRunning) -contains 2) {
        if (-not (Test-Path -LiteralPath "$dg\Scenarios")) { New-Item -Path "$dg\Scenarios" | Out-Null }
        Set-OrClear $hvciKey 'Enabled' 1
        Write-Host "  memory integrity (HVCI) is running; its setting is recorded as Enabled=1."
    }
    Set-OrClear $dg 'EnableVirtualizationBasedSecurity' 1
    Set-OrClear $dg 'RequirePlatformSecurityFeatures' 1
    Set-OrClear $lsa 'LsaCfgFlags' 2
    Write-Host "  configured (virtualization-based security + Credential Guard, no UEFI lock)."
    Write-Host "  takes effect after your next reboot."

    Write-Host "`ndone. undo: powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Undo `"$recordPath`""
    @{ ok = $true; record = $recordPath } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dir 'hardening-last.json') -Encoding UTF8
} catch {
    Write-Host "FAILED: $($_.Exception.Message)"
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dir 'hardening-last.json') -Encoding UTF8
} finally {
    Stop-Transcript | Out-Null
}

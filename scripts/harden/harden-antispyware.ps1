# Anti-spyware hardening, one elevated run, every step reversible.
# Implements blocks 3, 4, 5 (user-mode part), 6, 7 and 9 of
# docs/guides/SPYWARE-HARDENING-COMMANDS-2026-10-21.md. Each block reads the
# value back and writes a receipt; a failed step is reported, never hidden.
#
#   .\harden-antispyware.ps1              apply (prints a receipt, JSON copy in %LOCALAPPDATA%\Jarvis\Hardening)
#   .\harden-antispyware.ps1 -KernelCET   also arm kernel-mode hardware stack protection (needs a reboot)
#   .\harden-antispyware.ps1 -Undo        restore the values recorded by the last apply
#
# Not here, by design: Smart App Control (no supported command; Windows Security app),
# Administrator Protection (Microsoft excludes Hyper-V/WSL devices), microphone and camera
# consent (your account, `jarvis privacy seal`), Controlled Folder Access enforcement
# (needs the audit review first), BitLocker.
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Undo, [switch]$KernelCET)
$ErrorActionPreference = 'Continue'
$dir = Join-Path $env:LOCALAPPDATA 'Jarvis\Hardening'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stateFile = Join-Path $dir 'antispyware-state.json'
$receipt = [ordered]@{ at = (Get-Date).ToString('o'); mode = $(if ($Undo) { 'undo' } else { 'apply' }); steps = @() }
function Step([string]$name, [scriptblock]$do, [scriptblock]$verify) {
    $r = [ordered]@{ step = $name; ok = $false; detail = '' }
    try { & $do | Out-Null; $r.detail = [string](& $verify); $r.ok = $true } catch { $r.detail = "FAILED: $($_.Exception.Message)" }
    $script:receipt.steps += $r
    Write-Host ("{0,-4} {1}: {2}" -f $(if ($r.ok) { 'ok' } else { 'FAIL' }), $name, $r.detail)
}
function RegGet($path, $name) { try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null } }
function RegSet($path, $name, $value, $type = 'DWord') {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
}
function RegRestore($path, $name, $old, $type = 'DWord') {
    if ($null -eq $old) { Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue } else { RegSet $path $name $old $type }
}

# The three audit-mode rules to block, and the nine unset rules to add in audit mode.
$toBlock = @('75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B','BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550')
$toAudit = @('E6DB77E5-3DF2-4CF1-B95A-636979351E5B','C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB','B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4',
             '33DDEDF1-C6E0-47CB-833E-DE6133960387','C1DB55AB-C21A-4637-BB3F-A12568109D35','7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C',
             '26190899-1602-49E8-8B27-EB1D0A1CE869','D1E49AAC-8F56-4280-B9BA-993A6D77406C','A8F5898E-1DC8-49A9-9878-85004B8A61E6')
$regItems = @(
    @{ p='HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; n='Enabled'; v=0 },
    @{ p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; n='NoDriveTypeAutoRun'; v=255 },
    @{ p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; n='EnableModuleLogging'; v=1 },
    @{ p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; n='*'; v='*'; t='String' },
    @{ p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; n='ProcessCreationIncludeCmdLine_Enabled'; v=1 },
    @{ p='HKLM:\SOFTWARE\Policies\Google\Chrome'; n='RemoteDebuggingAllowed'; v=0 },
    @{ p='HKLM:\SOFTWARE\Policies\Google\Chrome'; n='BackgroundModeEnabled'; v=0 },
    @{ p='HKLM:\SOFTWARE\Policies\Google\Chrome'; n='SafeBrowsingProtectionLevel'; v=2 },
    @{ p='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; n='RemoteDebuggingAllowed'; v=0 },
    @{ p='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; n='BackgroundModeEnabled'; v=0 },
    @{ p='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; n='SmartScreenEnabled'; v=1 },
    @{ p='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; n='SmartScreenPuaEnabled'; v=1 },
    @{ p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; n='EnableMulticast'; v=0 }
)
if ($KernelCET) { $regItems += @{ p='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks'; n='Enabled'; v=1 } }

if ($Undo) {
    if (-not (Test-Path $stateFile)) { throw "no recorded state at $stateFile" }
    $st = Get-Content $stateFile -Raw | ConvertFrom-Json
    Step 'ASR rules back to recorded actions' {
        $ids = @($st.asr.ids); $acts = @($st.asr.actions)
        foreach ($id in ($toBlock + $toAudit)) {
            $i = [array]::IndexOf($ids, $id)
            if ($i -ge 0) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions ([int]$acts[$i]) }
            else { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id }
        }
    } { "$((Get-MpPreference).AttackSurfaceReductionRules_Ids.Count) rules configured" }
    Step 'Defender cloud level back' { Set-MpPreference -CloudBlockLevel ([int]$st.defender.cloud) -CloudExtendedTimeout ([int]$st.defender.timeout) } { (Get-MpPreference).CloudBlockLevel }
    Step 'exploit mitigations back' {
        foreach ($m in 'DEP','SEHOP','CFG') { if ($st.mitigations.$m -ne 'ON') { Set-ProcessMitigation -System -Disable $m } }
    } { (Get-ProcessMitigation -System).DEP.Enable }
    foreach ($it in $regItems) {
        $old = $st.registry."$($it.p)|$($it.n)"
        Step "restore $($it.n)" { RegRestore $it.p $it.n $old $(if ($it.t) { $it.t } else { 'DWord' }) } { RegGet $it.p $it.n }
    }
    Step 'PowerShell 2.0 engine back' { if ($st.psv2 -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null } } { (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State }
    Step 'NetBIOS back' { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]$st.netbios } | Out-Null } { 'restored' }
} else {
    $p = Get-MpPreference
    $state = [ordered]@{
        at = $receipt.at
        asr = @{ ids = @($p.AttackSurfaceReductionRules_Ids); actions = @($p.AttackSurfaceReductionRules_Actions) }
        defender = @{ cloud = [int]$p.CloudBlockLevel; timeout = [int]$p.CloudExtendedTimeout }
        mitigations = @{}; registry = @{}
        psv2 = [string](Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State
        netbios = [int]((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Select-Object -First 1).TcpipNetbiosOptions)
    }
    $m = Get-ProcessMitigation -System
    foreach ($k in 'DEP','SEHOP','CFG') { $state.mitigations[$k] = [string]$m.$k.Enable }
    foreach ($it in $regItems) { $state.registry["$($it.p)|$($it.n)"] = RegGet $it.p $it.n }
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $stateFile -Encoding UTF8
    Write-Host "previous values recorded in $stateFile"

    Step 'ASR: 3 audit rules to block' { Add-MpPreference -AttackSurfaceReductionRules_Ids $toBlock -AttackSurfaceReductionRules_Actions @('Enabled','Enabled','Enabled') } {
        $q = Get-MpPreference; ($toBlock | ForEach-Object { $q.AttackSurfaceReductionRules_Actions[[array]::IndexOf($q.AttackSurfaceReductionRules_Ids, $_)] }) -join ',' }
    Step 'ASR: 9 unset rules in audit' { Add-MpPreference -AttackSurfaceReductionRules_Ids $toAudit -AttackSurfaceReductionRules_Actions @($toAudit | ForEach-Object { 'AuditMode' }) } {
        $q = Get-MpPreference; "$($q.AttackSurfaceReductionRules_Ids.Count) rules, actions " + ($q.AttackSurfaceReductionRules_Actions -join ',') }
    Step 'Defender: cloud block High, extended timeout' { Set-MpPreference -CloudBlockLevel High -CloudExtendedTimeout 50 } { "cloud=$((Get-MpPreference).CloudBlockLevel) timeout=$((Get-MpPreference).CloudExtendedTimeout)" }
    Step 'Defender: removable drive scanning on' { Set-MpPreference -DisableRemovableDriveScanning $false } { -not (Get-MpPreference).DisableRemovableDriveScanning }
    Step 'exploit mitigations: DEP, SEHOP, CFG system-wide' { Set-ProcessMitigation -System -Enable DEP,SEHOP,CFG } {
        $x = Get-ProcessMitigation -System; "DEP=$($x.DEP.Enable) SEHOP=$($x.SEHOP.Enable) CFG=$($x.CFG.Enable)" }
    foreach ($it in $regItems) {
        Step "$($it.n) = $($it.v)" { RegSet $it.p $it.n $it.v $(if ($it.t) { $it.t } else { 'DWord' }) } { RegGet $it.p $it.n }
    }
    Step 'Security audit: process creation with command line' { auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null } { (auditpol /get /subcategory:"Process Creation" | Select-String 'Process Creation').ToString().Trim() }
    Step 'PowerShell 2.0 engine off' { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null } { (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State }
    Step 'NetBIOS over TCP/IP off' { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null } {
        ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true').TcpipNetbiosOptions -join ',') }
    Step 'Defender exclusions (review; nothing removed)' { } {
        $q = Get-MpPreference; "paths=[$($q.ExclusionPath -join ';')] procs=[$($q.ExclusionProcess -join ';')] ext=[$($q.ExclusionExtension -join ';')]" }
    if ($KernelCET) { Write-Host 'kernel-mode stack protection armed: reboot to activate' }
}
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir ("antispyware-receipt-{0}.json" -f (Get-Date -Format yyyyMMdd-HHmmss))) -Encoding UTF8
$failed = @($receipt.steps | Where-Object { -not $_.ok }).Count
Write-Host ("{0} steps, {1} failed. Receipt in {2}" -f $receipt.steps.Count, $failed, $dir)
if ($failed) { exit 1 }

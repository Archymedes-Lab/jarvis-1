# Deep OS hardening for the findings `jarvis posture`, `jarvis firewall` and
# `jarvis backdoor` report that ..\repair\remediate-windows.ps1 does not already cover.
#
# The two scripts are additive, not alternatives:
#   remediate-windows.ps1  removes specific exposures that were found (orphaned
#                          rules, Remote Assistance, dev-tool scope).
#   harden-windows.ps1     turns on the OS-level controls that would have
#                          contained those exposures in the first place.
#
# REQUIRES ELEVATION. Every write here needs it, and the script refuses to run
# half-applied rather than reporting success for steps it silently skipped.
#
# SAFETY: Attack Surface Reduction and Controlled Folder Access break real
# workflows when set to Block without warning -- ASR's "Office child process"
# and "executable content" rules in particular. So they are applied in AUDIT
# mode by default: the OS logs what it *would* have blocked and changes
# nothing. Run for a few days, check the log, then re-run with -Enforce to
# promote to Block. That ordering is the whole point; do not skip it because
# audit mode "does nothing" -- it is how you find out what enforcing would cost.
#
#   .\harden-windows.ps1              audit mode, safe to run now
#   .\harden-windows.ps1 -Enforce     promote ASR + CFA to blocking
#   .\harden-windows.ps1 -WhatIf      print the plan, change nothing

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Enforce
)

$ErrorActionPreference = 'Continue'
$script:log = @()
function Say($m) { $script:log += $m; Write-Host $m }
function Warn($m) { $script:log += "WARN: $m"; Write-Warning $m }

# --- 0. elevation ----------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Error "This script must run from an ELEVATED PowerShell. Right-click PowerShell > Run as administrator, then re-run."
    return
}

$mode = if ($Enforce) { 'Enabled' } else { 'AuditMode' }
Say "=== jarvis deep hardening  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
Say "    ASR/CFA mode: $mode$(if (-not $Enforce) { '  (re-run with -Enforce to block)' })"

# --- 1. Defender internet/download baseline -------------------------------
# Blocks outbound connections to known-malicious hosts at the OS level, below
# the browser. jarvis's `hunt` can only tell you a C2 address was contacted
# after the fact; this refuses the connection.
if ($PSCmdlet.ShouldProcess('Defender', 'enable real-time, download, script, PUA and Network Protection')) {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
    $mp = Get-MpPreference
    Say "[1] Defender: realtime=$(-not $mp.DisableRealtimeMonitoring) behavior=$(-not $mp.DisableBehaviorMonitoring) downloads=$(-not $mp.DisableIOAVProtection) scripts=$(-not $mp.DisableScriptScanning) PUA=$($mp.PUAProtection) network=$($mp.EnableNetworkProtection)"
    if ($mp.DisableRealtimeMonitoring -or $mp.DisableBehaviorMonitoring -or
        $mp.DisableIOAVProtection -or $mp.DisableScriptScanning -or
        $mp.PUAProtection -ne 1 -or $mp.EnableNetworkProtection -ne 1) {
        Warn 'one or more Defender internet/download protections did not enter blocking mode; Tamper Protection, another antivirus, or organization policy may own the setting'
    }
}

# --- 2. Attack Surface Reduction ------------------------------------------
# All seven were "not enforcing". These are the rules that stop the delivery
# stage of nearly every commodity intrusion: a macro spawning a process, a
# script writing an executable, a downloaded script launching more code.
$asr = [ordered]@{
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Office apps creating child processes'
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Office apps creating executable content'
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'obfuscated scripts'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'JS/VBS launching downloaded content'
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'executable content from email/webmail'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Office apps creating child processes (Comm)'
    '01443614-CD74-433A-B99E-2ECDC07BFC25' = 'executables unless prevalent/trusted'
}
if ($PSCmdlet.ShouldProcess('Defender', "set $($asr.Count) ASR rules to $mode")) {
    foreach ($guid in $asr.Keys) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $guid `
                         -AttackSurfaceReductionRules_Actions $mode `
                         -ErrorAction SilentlyContinue
    }
    $set = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    Say "[2] ASR rules configured: $(@($set).Count) of $($asr.Count) -> $mode"
    if (-not $Enforce) {
        Say "    review what audit mode would have blocked in Event Viewer:"
        Say "    Applications and Services > Microsoft > Windows > Windows Defender > Operational  (ids 1121/1122)"
    }
}

# --- 3. Controlled Folder Access ------------------------------------------
# The anti-ransomware guard. In audit mode it records which programs write to
# Documents and friends, which is exactly the list you need before enforcing.
if ($PSCmdlet.ShouldProcess('Defender', "set Controlled Folder Access to $mode")) {
    Set-MpPreference -EnableControlledFolderAccess $mode -ErrorAction SilentlyContinue
    Say "[3] Controlled Folder Access = $((Get-MpPreference).EnableControlledFolderAccess)"
}

# --- 4. PowerShell script block logging ------------------------------------
# The single most useful forensic log on a Windows box: it records the actual
# script text that ran, after deobfuscation. This machine's own PowerShell
# history already shows a remote script piped into an elevated shell, and there
# is currently no record of what that script contained.
$sbl = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if ($PSCmdlet.ShouldProcess('PowerShell', 'enable script block logging')) {
    New-Item -Path $sbl -Force | Out-Null
    New-ItemProperty -Path $sbl -Name EnableScriptBlockLogging `
                     -Value 1 -PropertyType DWord -Force | Out-Null
    Say "[4] script block logging enabled -> Event log 'PowerShell/Operational' id 4104"
}

# --- 5. LSA protection (RunAsPPL) -----------------------------------------
# Runs LSASS as a protected process, so ordinary admin-level code can no longer
# open its memory and read credentials. This is the cheap half of what
# Credential Guard does and it needs no hypervisor reconfiguration.
#
# Takes effect at next boot. Set as a *value* rather than through Device Guard
# so it can be undone by deleting the value if a driver misbehaves.
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
if ($PSCmdlet.ShouldProcess('LSA', 'enable RunAsPPL')) {
    New-ItemProperty -Path $lsa -Name RunAsPPL -Value 1 `
                     -PropertyType DWord -Force | Out-Null
    Say "[5] LSA protection (RunAsPPL) set -- takes effect after reboot"
    Say "    undo:  Remove-ItemProperty -Path '$lsa' -Name RunAsPPL"
}

# --- 6. orphaned inbound firewall rules ------------------------------------
# Re-swept here because Edge and WebView2 add one rule per update and never
# remove the old ones -- the last sweep found 28. An inbound allow whose
# program no longer exists is a pre-authorised hole: drop any binary at that
# exact path and it is reachable from any address with no prompt.
if ($PSCmdlet.ShouldProcess('Firewall', 'export policy and remove orphaned inbound rules')) {
    $bk = "$env:USERPROFILE\Documents\jarvis-firewall-backup-$(Get-Date -Format yyyyMMdd-HHmmss).wfw"
    netsh advfirewall export "$bk" | Out-Null
    if (-not (Test-Path $bk)) {
        Warn "firewall export failed; skipping rule removal rather than deleting without a backup"
    } else {
        Say "[6] firewall policy exported -> $bk"
        $app = @{}
        Get-NetFirewallApplicationFilter | ForEach-Object { $app[$_.InstanceID] = $_.Program }
        $orphans = foreach ($r in Get-NetFirewallRule -Direction Inbound -Enabled True) {
            $p = [string]$app[$r.Name]
            if (-not $p -or $p -eq 'Any' -or $p -eq 'System') { continue }
            if (-not (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($p)))) { $r }
        }
        Say "    orphaned inbound rules: $(@($orphans).Count)"
        foreach ($r in $orphans) {
            Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            Say "    removed: $($r.DisplayName)"
        }
    }
}

# --- 7. firewall edge and logging -----------------------------------------
# Dropped inbound packets leaving no record means there is nothing to look at
# after the fact. Default-deny inbound still preserves explicit allow rules;
# outbound remains allowed so this does not silently break ordinary apps.
if ($PSCmdlet.ShouldProcess('Firewall', 'enable every profile, default-deny inbound and log dropped packets')) {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow
    foreach ($p in 'domainprofile','privateprofile','publicprofile') {
        netsh advfirewall set $p logging droppedconnections enable | Out-Null
        netsh advfirewall set $p logging maxfilesize 16384 | Out-Null
    }
    $profiles = @(Get-NetFirewallProfile)
    $bad = @($profiles | Where-Object {
        -not $_.Enabled -or [string]$_.DefaultInboundAction -ne 'Block'
    })
    Say "[7] firewall enabled/default-deny inbound; outbound allowed; dropped-packet logging on all profiles"
    if ($bad.Count) {
        Warn "firewall verification failed for: $($bad.Name -join ', ')"
    }
}

# --- 8. SmartScreen from browser to downloaded file -----------------------
# Edge's user-overridable defaults live in secure-daily-apps.ps1. These are
# the machine boundary: known-dangerous sites/downloads and shell-launched
# internet files cannot bypass the warning. Automatic HTTPS upgrades do not
# block legacy HTTP sites; HTTPS-Only remains a per-user browser default.
if ($PSCmdlet.ShouldProcess('Windows and Edge', 'enable non-bypassable SmartScreen protection')) {
    $shell = 'HKLM:\Software\Policies\Microsoft\Windows\System'
    New-Item -Path $shell -Force | Out-Null
    New-ItemProperty -Path $shell -Name EnableSmartScreen -Value 1 `
        -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $shell -Name ShellSmartScreenLevel -Value 'Block' `
        -PropertyType String -Force | Out-Null

    $edge = 'HKLM:\Software\Policies\Microsoft\Edge'
    New-Item -Path $edge -Force | Out-Null
    foreach ($name in 'SmartScreenEnabled','SmartScreenPuaEnabled',
                          'PreventSmartScreenPromptOverride',
                          'PreventSmartScreenPromptOverrideForFiles',
                          'HttpsUpgradesEnabled') {
        New-ItemProperty -Path $edge -Name $name -Value 1 `
            -PropertyType DWord -Force | Out-Null
    }
    Say '[8] Windows shell + Edge SmartScreen enabled; unsafe site/download bypass blocked; Edge HTTPS upgrades enabled'
}

# --- 9. SMBv1 --------------------------------------------------------------
# A 1980s protocol with no modern reason to be present. Reported as "not
# readable" without elevation, so check it properly now that we have it.
if ($PSCmdlet.ShouldProcess('SMBv1', 'disable if present')) {
    $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
        Say "[9] SMBv1 was ENABLED -- now disabled (reboot to complete)"
    } else {
        Say "[9] SMBv1 state: $(if ($f) { $f.State } else { 'not present' }) -- nothing to do"
    }
}

# --- 10. read what needed elevation ---------------------------------------
# Not changes: these are the three things jarvis reported as "not readable"
# rather than "bad", and the difference matters.
Say "--- state that only an elevated shell can read ---"
try {
    $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
    Say "    BitLocker C: $($bl.ProtectionStatus) / $($bl.VolumeStatus)"
} catch { Warn "BitLocker still unreadable: $($_.Exception.Message)" }
try {
    $tpm = Get-Tpm -ErrorAction Stop
    Say "    TPM present=$($tpm.TpmPresent) ready=$($tpm.TpmReady) enabled=$($tpm.TpmEnabled)"
} catch { Warn "TPM still unreadable: $($_.Exception.Message)" }
try {
    $ex = (Get-MpPreference).ExclusionPath
    Say "    Defender exclusion paths: $(if ($ex) { $ex -join '; ' } else { 'none' })"
} catch { Warn "Defender exclusions unreadable" }
Say "    Secure Boot: $(try { Confirm-SecureBootUEFI } catch { 'unreadable (legacy/BIOS boot)' })"

# --- 11. what this script deliberately does NOT do -------------------------
Say "--- left for you, on purpose ---"
Say "    Credential Guard: needs VBS policy + reboot and can break some VPN and"
Say "      virtualisation drivers. Enable via Settings > Privacy & security >"
Say "      Windows Security > Device security > Core isolation, once you have"
Say "      confirmed ProtonVPN and Vanguard tolerate it."
Say "    The two CodexSandbox* accounts are enabled, non-admin, hidden from the"
Say "      sign-in screen. Legitimate Codex CLI sandbox accounts -- disable them"
Say "      only if you no longer use Codex:  Disable-LocalUser -Name CodexSandboxOffline"

Say "=== done. $(@($script:log).Count) lines. Re-run `jarvis posture` to confirm. ==="
$script:log | Set-Content "$env:USERPROFILE\Documents\jarvis-harden-$(Get-Date -Format yyyyMMdd-HHmmss).log"

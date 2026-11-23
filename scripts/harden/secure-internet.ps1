# Reversible browser defaults and bounded Windows Firewall traffic logging.
# Run -Browsers as the browser user; run -Firewall in an elevated PowerShell.
# Restore with the same switch plus -Undo. Does not change network allow rules.
[CmdletBinding()]
param([switch]$Browsers, [switch]$Firewall, [switch]$Undo)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:LOCALAPPDATA 'Jarvis\InternetProtection'
if (-not ($Browsers -or $Firewall)) { throw 'Choose -Browsers or -Firewall (optionally -Undo).' }
New-Item -ItemType Directory -Path $dir -Force | Out-Null

if ($Firewall) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'Firewall logging requires an elevated Windows PowerShell.' }
    $backup = Join-Path $dir 'firewall-before.json'
    if ($Undo) {
        $rows = @(Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json)
        foreach ($row in $rows) {
            Set-NetFirewallProfile -Name $row.Name -LogAllowed $row.LogAllowed -LogBlocked $row.LogBlocked -LogMaxSizeKilobytes $row.LogMaxSizeKilobytes
        }
    } else {
        if (-not (Test-Path -LiteralPath $backup)) {
            Get-NetFirewallProfile | Select-Object Name,LogAllowed,LogBlocked,LogMaxSizeKilobytes |
                ConvertTo-Json | Set-Content -LiteralPath $backup -Encoding UTF8
        }
        Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
    }
    Get-NetFirewallProfile | Select-Object Name,Enabled,LogAllowed,LogBlocked,LogMaxSizeKilobytes
}

if ($Browsers) {
    $backup = Join-Path $dir 'browsers-before.json'
    $specs = @(
        @{path='HKCU:\Software\Policies\Google\Chrome\Recommended'; values=@{SafeBrowsingProtectionLevel=1; PasswordLeakDetectionEnabled=1; HttpsOnlyMode='force_balanced_enabled'}},
        @{path='HKCU:\Software\Policies\BraveSoftware\Brave\Recommended'; values=@{SafeBrowsingProtectionLevel=1; PasswordLeakDetectionEnabled=1; HttpsOnlyMode='force_balanced_enabled'}},
        @{path='HKCU:\Software\Policies\Microsoft\Edge\Recommended'; values=@{SmartScreenEnabled=1; SmartScreenPuaEnabled=1; PasswordMonitorAllowed=1; HttpsOnlyMode='force_balanced_enabled'}},
        @{path='HKCU:\Software\Policies\Mozilla\Firefox'; values=@{HttpsOnlyMode='enabled'}}
    )
    if ($Undo) {
        foreach ($row in @(Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json)) {
            if ($row.existed) {
                New-ItemProperty -LiteralPath $row.path -Name $row.name -Value $row.value -PropertyType $row.kind -Force | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $row.path -Name $row.name -ErrorAction SilentlyContinue
            }
        }
    } else {
        if (-not (Test-Path -LiteralPath $backup)) {
            $rows = @(foreach ($spec in $specs) {
                foreach ($name in $spec.values.Keys) {
                    $key = Get-Item -LiteralPath $spec.path -ErrorAction SilentlyContinue
                    $exists = $null -ne $key -and $key.GetValueNames() -contains $name
                    @{path=$spec.path; name=$name; existed=$exists;
                      value=$(if ($exists) {$key.GetValue($name)} else {$null});
                      kind=$(if ($exists) {[string]$key.GetValueKind($name)} else {'DWord'})}
                }
            })
            ConvertTo-Json -InputObject $rows -Depth 4 | Set-Content -LiteralPath $backup -Encoding UTF8
        }
        foreach ($spec in $specs) {
            New-Item -Path $spec.path -Force | Out-Null
            foreach ($name in $spec.values.Keys) {
                $value = $spec.values[$name]
                $current = Get-ItemProperty -LiteralPath $spec.path -Name $name -ErrorAction SilentlyContinue
                # Preserve enhanced Safe Browsing if already selected by policy.
                if ($name -eq 'SafeBrowsingProtectionLevel' -and $current.$name -eq 2) { continue }
                $kind = if ($value -is [int]) {'DWord'} else {'String'}
                New-ItemProperty -LiteralPath $spec.path -Name $name -Value $value -PropertyType $kind -Force | Out-Null
            }
        }
    }
    Write-Output 'Browser registry settings updated. Verify effective settings in chrome://policy, brave://policy, edge://policy, and about:policies. Recommended defaults remain user-overridable.'
}
Write-Output "Rollback records: $dir"

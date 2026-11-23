#Requires -RunAsAdministrator
# Disable only the three reported inbound exposures. Keep a rollback record.
$ErrorActionPreference = 'Stop'
$targets = @(
    @{ Name = 'Trae'; Program = 'C:\users\chris\appdata\local\programs\trae\trae.exe'; Orphan = $false },
    @{ Name = 'adb.exe'; Program = 'C:\users\chris\appdata\local\android\sdk\platform-tools\adb.exe'; Orphan = $false },
    # WebView2 updates leave one rule per retired version; match every such orphan.
    @{ Name = 'Microsoft Edge (mDNS-In)'; Program = 'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe'; Orphan = $true }
)
$selected = @(
    foreach ($target in $targets) {
        foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
            $_.DisplayName -eq $target.Name -and $_.Enabled -eq 'True' -and
            $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
        })) {
            $app = $rule | Get-NetFirewallApplicationFilter
            if ($app.Program -inotlike $target.Program) { continue }
            if ($target.Orphan -and (Test-Path -LiteralPath $app.Program)) {
                Write-Warning "Program now exists; leaving rule $($rule.Name) for review."
                continue
            }
            if ($rule.PolicyStoreSourceType -ne 'Local') {
                throw "Rule $($rule.Name) is centrally managed; change its source policy."
            }
            $rule
        }
    }
)
if ($selected.Count -eq 0) {
    Write-Host 'No enabled local inbound rules match the reported exposures.'
    return
}
$backupDir = Join-Path $env:LOCALAPPDATA 'JARVIS\repairs'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$backup = Join-Path $backupDir ('firewall-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.clixml')
$selected | Select-Object Name, DisplayName, Enabled | Export-Clixml -LiteralPath $backup
Write-Host "Rollback record: $backup"
Write-Host 'To restore: Import-Clixml -LiteralPath <record> | ForEach-Object { Enable-NetFirewallRule -Name $_.Name }'
foreach ($rule in $selected) {
    Disable-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name | Out-Null
    $live = Get-NetFirewallRule -PolicyStore ActiveStore -Name $rule.Name
    if ($live.Enabled -ne 'False') { throw "Rule remains enabled: $($rule.Name)" }
    Write-Host "Verified disabled: $($rule.DisplayName) [$($rule.Name)]"
}

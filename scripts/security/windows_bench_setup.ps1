# Controlled fixture preparation/cleanup only on an ephemeral GitHub Windows VM.
param([switch]$Cleanup)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:JARVIS_ARENA_SANDBOX -ne '1' -or -not $env:RUNNER_TEMP) { throw 'Not an explicitly marked hosted runner' }
foreach ($p in @("$HOME\.jarvis\jarvis.db", "$HOME\.argus\argus.db", "$env:ProgramData\Jarvis", "$env:ProgramFiles\Jarvis")) {
    if (Test-Path -LiteralPath $p) { throw 'Protected installation/data exists; refusing' }
}
$base = Join-Path $env:RUNNER_TEMP 'argus-windows-bench'
$stateFile = Join-Path $base 'setup.json'
$sysmon = Join-Path $base 'Sysmon64.exe'
if ($Cleanup) {
    if (-not (Test-Path -LiteralPath $stateFile)) { exit 0 }
    $state = Get-Content -Raw -LiteralPath $stateFile | ConvertFrom-Json
    $issues = New-Object System.Collections.Generic.List[string]
    try { if ($state.install_attempted) {
        $sig = Get-AuthenticodeSignature -LiteralPath $sysmon
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Cleanup binary trust failed' }
        & $sysmon -u
        if ($LASTEXITCODE -ne 0) { throw 'Sysmon cleanup failed' }
        if (Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue) { throw 'Sysmon service remains after cleanup' }
    }
    } catch { $issues.Add('Sysmon restoration failed') }
    try { Get-NetFirewallRule -Group $state.group -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
    catch { $issues.Add('Network rule removal failed') }
    foreach ($profile in $state.profiles) { try { Set-NetFirewallProfile -Name $profile.Name -Enabled $profile.Enabled } catch { $issues.Add('Network profile restoration failed') } }
    try { $key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if ($state.logging_value_present) { Set-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -Value ([int]$state.logging_value) }
    else { Remove-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue }
    & wevtutil sl 'Microsoft-Windows-PowerShell/Operational' "/e:$(([string][bool]$state.ps_enabled).ToLower())" "/ms:$($state.ps_bytes)"
    if ($LASTEXITCODE -ne 0) { throw 'PowerShell channel restoration failed' }
    } catch { $issues.Add('Script-block logging restoration failed') }
    if (@(Get-NetFirewallRule -Group $state.group -ErrorAction SilentlyContinue).Count) { $issues.Add('Fixture firewall rules remain') }
    if ($issues.Count) { throw ($issues -join '; ') }
    Write-Output 'Disposable fixture logging, network policy and Sysmon cleanup completed'
    exit 0
}
if (Test-Path -LiteralPath $base) { throw 'Fixture setup directory already exists' }
if ((Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue) -or (Get-CimInstance Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue)) { throw 'Existing Sysmon installation; refusing replacement' }
New-Item -ItemType Directory -Path $base | Out-Null
$zip = Join-Path $base 'Sysmon.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLower() -ne '00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54') { throw 'Pinned Sysmon package hash mismatch' }
Expand-Archive -LiteralPath $zip -DestinationPath $base
$sig = Get-AuthenticodeSignature -LiteralPath $sysmon
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Sysmon publisher trust failed' }
$log = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational'
$key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$old = Get-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
$profiles = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Enabled=[string]$_.Enabled } })
$group = "Argus disposable benchmark $env:GITHUB_RUN_ID"
$state = @{ group=$group; profiles=$profiles; ps_enabled=[bool]$log.IsEnabled; ps_bytes=[long]$log.MaximumSizeInBytes
            logging_value_present=($null -ne $old); logging_value=$(if ($old) { [int]$old.EnableScriptBlockLogging } else { 0 }); install_attempted=$true }
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $stateFile -Encoding UTF8
& $sysmon -accepteula -i (Join-Path $PSScriptRoot 'windows-bench-sysmon.xml')
if ($LASTEXITCODE -ne 0) { throw 'Sysmon fixture installation failed' }
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -LiteralPath $key -Name EnableScriptBlockLogging -Value 1 -Type DWord
& wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /e:true /ms:134217728
if ($LASTEXITCODE -ne 0) { throw 'PowerShell fixture log setup failed' }
# Only the benchmark interpreter and its local command shells; never the agent.
$programs = @((Get-Command python).Source, (Get-Command powershell.exe).Source, "$env:SystemRoot\System32\cmd.exe")
$i = 0
foreach ($program in $programs) {
    New-NetFirewallRule -DisplayName "$group $i" -Group $group -Direction Outbound -Action Block -Program $program -Profile Any | Out-Null
    $i++
}
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
$rules = @(Get-NetFirewallRule -Group $group -PolicyStore ActiveStore)
if ($rules.Count -ne $programs.Count -or @($rules | Where-Object { $_.Enabled -ne 'True' -or $_.Action -ne 'Block' -or $_.Direction -ne 'Outbound' }).Count) { throw 'Active network blocks did not verify' }
if (@(Get-NetFirewallProfile | Where-Object { [string]$_.Enabled -ne 'True' }).Count) { throw 'Firewall profile not active' }
Write-Output 'Pinned Microsoft-signed Sysmon, script-block logging and active scoped network blocks verified'

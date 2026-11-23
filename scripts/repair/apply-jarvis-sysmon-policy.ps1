#Requires -RunAsAdministrator
<#
Applies the JARVIS Windows Sysmon baseline with an exact, restorable backup.

Sysmon keeps its active rules in the registry (the driver's Parameters key),
not as XML, so the backup is a `reg export` of the service and driver keys:
restoring those values and restarting the service returns the previous rules
byte for byte. The readable `Sysmon -c` export and hashes are kept beside it.

Every backup and receipt goes into C:\ProgramData\Jarvis\Vault\sysmon, which
only Administrators and SYSTEM can modify. Nothing is applied unless the
policy file matches -ExpectedSha256 and the backup was written. After
applying, the running configuration hash must equal the policy hash,
ProcessCreate must be unfiltered and the registry noise exclusions must be
present; otherwise the backup is restored automatically.

  apply-jarvis-sysmon-policy.ps1 -PolicyPath <xml> -ExpectedSha256 <hex>
  apply-jarvis-sysmon-policy.ps1 -Rollback <backup folder>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PolicyPath = '',
    [string]$ExpectedSha256 = '',
    [string]$Rollback = ''
)

$ErrorActionPreference = 'Stop'
$Sys32 = [Environment]::SystemDirectory
# From the system drive, not %ProgramData%: an elevated shell of the same user
# inherits that user's own environment variables.
$VaultRoot = Join-Path ([IO.Path]::GetPathRoot($Sys32)) 'ProgramData\Jarvis\Vault'
$SysmonVault = Join-Path $VaultRoot 'sysmon'

function Lock-Folder([string]$path) {
    # SYSTEM and Administrators: full. The installing user: read. No other
    # account, and no inherited ProgramData ACEs (which let Users create files).
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & (Join-Path $Sys32 'icacls.exe') $path /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed on $path ($LASTEXITCODE)" }
    & (Join-Path $Sys32 'icacls.exe') $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        "*${owner}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $path ($LASTEXITCODE)" }
}

function Get-SysmonService {
    $svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -in @('Sysmon64', 'Sysmon') } |
        Select-Object -First 1
    if (-not $svc) { throw 'Sysmon service not installed' }
    $exe = [string]$svc.PathName
    $exe = if ($exe.StartsWith('"')) { $exe.Substring(1, $exe.IndexOf('"', 1) - 1) } else { ($exe -split '\s+')[0] }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Sysmon executable not found: $exe" }
    [pscustomobject]@{ Name = [string]$svc.Name; Exe = $exe }
}

function Get-SysmonDump([string]$exe) {
    # Sysmon writes UTF-16 to its native streams; capture it explicitly.
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $exe
    $start.Arguments = '-c'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::Unicode
    $start.StandardErrorEncoding = [Text.Encoding]::Unicode
    $p = [System.Diagnostics.Process]::Start($start)
    $out = $p.StandardOutput.ReadToEnd() + [Environment]::NewLine + $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "Sysmon -c exited $($p.ExitCode)" }
    return ($out -replace "`0", '')
}

function Get-ConfigHash([string]$dump) {
    $m = [regex]::Match($dump, '(?im)Config hash:\s*SHA256=([0-9a-f]{64})')
    if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }
    return ''
}

function Get-DriverName([string]$dump) {
    $m = [regex]::Match($dump, '(?im)Driver name:\s*(\S+)')
    if ($m.Success) { return $m.Groups[1].Value }
    return 'SysmonDrv'
}

function Test-Applied([string]$dump, [string]$hash) {
    $problems = @()
    if ((Get-ConfigHash $dump) -ne $hash) { $problems += 'running config hash differs from the policy' }
    $create = [regex]::Match($dump,
        '(?ms)^\s*-\s*ProcessCreate\s+onmatch:\s*exclude.*?(?=^\s*-\s*[A-Za-z][A-Za-z0-9]*\s+onmatch:|\z)')
    if (-not $create.Success -or $create.Value -match '(?im)\bfilter:\s*') {
        $problems += 'ProcessCreate is filtered or missing'
    }
    if ($dump -notmatch '(?im)^\s*-\s*RegistryEvent\s+onmatch:\s*exclude') {
        $problems += 'registry noise exclusions are missing'
    }
    return $problems
}

function Restore-Backup([string]$dir) {
    $svc = Get-SysmonService
    $regs = @(Get-ChildItem -LiteralPath $dir -Filter '*.reg' -File)
    if ($regs.Count -eq 0) { throw "no registry backup in $dir" }
    foreach ($reg in $regs) {
        & (Join-Path $Sys32 'reg.exe') import $reg.FullName 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "reg import failed for $($reg.Name) ($LASTEXITCODE)" }
    }
    Restart-Service -Name $svc.Name -Force
    Start-Sleep -Seconds 3
    $after = Get-SysmonDump $svc.Exe
    $expected = (Get-Content -LiteralPath (Join-Path $dir 'receipt.json') -Raw | ConvertFrom-Json).before_config_hash
    $now = Get-ConfigHash $after
    if ($expected -and $now -ne $expected) {
        throw "restored rules report config hash $now, backup recorded $expected; inspect $dir"
    }
    return $now
}

if ($Rollback) {
    $hash = Restore-Backup (Resolve-Path -LiteralPath $Rollback).ProviderPath
    Write-Output "Restored Sysmon rules from $Rollback (config hash $hash)."
    return
}

if (-not $PolicyPath -or -not $ExpectedSha256) { throw 'Use -PolicyPath with -ExpectedSha256, or -Rollback <backup folder>.' }
if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) { throw "Policy not found: $PolicyPath" }
$ExpectedSha256 = $ExpectedSha256.ToLowerInvariant()
if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') { throw 'Refusing: -ExpectedSha256 is not a SHA-256 hex digest.' }
$svc = Get-SysmonService
foreach ($dir in @($VaultRoot, $SysmonVault)) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}
Lock-Folder $VaultRoot
$backup = Join-Path $SysmonVault ('backup-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $backup | Out-Null

# Verify, then apply the same copy: the policy is copied into the
# administrator-only backup first, and that copy is hashed, parsed and given
# to Sysmon. The file at -PolicyPath can live in a folder the user can write,
# and a swap between the check and `sysmon -c` would install other rules.
$applied = Join-Path $backup 'applied-policy.xml'
Copy-Item -LiteralPath $PolicyPath -Destination $applied
(Get-Item -LiteralPath $applied).IsReadOnly = $true
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $applied).Hash.ToLowerInvariant()
if ($actual -ne $ExpectedSha256) { throw "Refusing: policy hash $actual does not match the expected $ExpectedSha256." }
$xml = New-Object System.Xml.XmlDocument
$xml.Load($applied)
$create = $xml.SelectSingleNode('/Sysmon/EventFiltering/ProcessCreate[@onmatch="exclude"]')
if ($null -eq $create -or $create.HasChildNodes) { throw 'Policy must keep an empty ProcessCreate exclude rule.' }

$before = Get-SysmonDump $svc.Exe
$driver = Get-DriverName $before
Set-Content -LiteralPath (Join-Path $backup 'before-export.txt') -Value $before -Encoding UTF8
foreach ($key in @("HKLM\SYSTEM\CurrentControlSet\Services\$driver", "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.Name)")) {
    $file = Join-Path $backup (($key -split '\\')[-1] + '.reg')
    & (Join-Path $Sys32 'reg.exe') export $key $file /y 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length -eq 0) {
        throw "Refusing: could not back up $key ($LASTEXITCODE); nothing was changed."
    }
}
if (-not (Select-String -LiteralPath (Join-Path $backup "$driver.reg") -Pattern 'Rules' -Quiet)) {
    throw "Refusing: the $driver backup does not contain the Rules value; nothing was changed."
}
$receipt = [ordered]@{
    at = (Get-Date).ToUniversalTime().ToString('o')
    service = $svc.Name; driver = $driver
    before_config_hash = Get-ConfigHash $before
    policy_sha256 = $ExpectedSha256
    applied = $false; verified = $false; rolled_back = $false; problems = @()
}
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'receipt.json') -Encoding UTF8

if (-not $PSCmdlet.ShouldProcess($svc.Exe, 'replace Sysmon configuration')) { return }
& $svc.Exe -c $applied | Out-Null
$receipt.applied = ($LASTEXITCODE -eq 0)
$after = if ($receipt.applied) { Get-SysmonDump $svc.Exe } else { '' }
Set-Content -LiteralPath (Join-Path $backup 'after-export.txt') -Value $after -Encoding UTF8
$receipt.problems = if ($receipt.applied) { @(Test-Applied $after $ExpectedSha256) } else { @("Sysmon rejected the policy ($LASTEXITCODE)") }
$receipt.verified = ($receipt.problems.Count -eq 0)
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'receipt.json') -Encoding UTF8
if (-not $receipt.verified) {
    Restore-Backup $backup | Out-Null
    $receipt.rolled_back = $true
    $receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'receipt.json') -Encoding UTF8
    Get-ChildItem -LiteralPath $backup -File | ForEach-Object { $_.IsReadOnly = $true }
    throw "Verification failed ($($receipt.problems -join '; ')); previous rules restored from $backup."
}
Get-ChildItem -LiteralPath $backup -File | ForEach-Object { $_.IsReadOnly = $true }
Write-Output "Applied and verified JARVIS Sysmon policy $ExpectedSha256. Exact backup: $backup"

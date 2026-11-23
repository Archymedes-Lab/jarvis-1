# HP firmware audit log (HP Sure Start), read-only. Run by the elevated broker.
#
# HP business machines keep a security journal inside the firmware: BIOS
# corruption and recovery, runtime intrusion detection in SMM, Secure Boot key
# repair, Intel ME/CSME recovery, DMA protection, Tamper Lock and Sure Admin
# events, from the embedded controller and the BIOS. Windows has no copy. HP's
# signed PowerShell library (CMSL, module HP.Firmware) reads it through a native
# HP DLL, and only as administrator.
#
# This runs elevated, so it must never load code the unelevated user can
# change, or anything running as that user inherits administrator through it:
#   * the modules are taken only from Program Files, by full path;
#   * PSModulePath is pinned to system folders first, because HP.Firmware
#     #requires HP.Private and HP.Utility by name and the default path searches
#     the user's own Documents folder;
#   * every file in the three module folders must be writable only by SYSTEM,
#     Administrators or TrustedInstaller, and every code file must carry a
#     valid Authenticode signature from HP Inc. (or Microsoft Corporation for
#     the Microsoft libraries HP ships) before anything is loaded.
# Any failure refuses the read and says why; nothing is loaded.
#
# It changes no setting and writes nothing. Output: base64 JSON on stdout.
# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'Stop'
$out = [ordered]@{ schema = 1; available = $false; reason = ''; module = $null
                   records = @(); problems = @(); errors = @(); truncated = $false }
$MaxRecords = 512
$Modules = @('HP.Private', 'HP.Utility', 'HP.Firmware')
$Signers = @('HP Inc.', 'Microsoft Corporation')
$CodeExt = @('.ps1', '.psm1', '.psd1', '.ps1xml', '.dll', '.exe', '.cdxml')
# SYSTEM, Administrators, TrustedInstaller.
$Writers = @('S-1-5-18', 'S-1-5-32-544',
             'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# Any right that changes content, names, permissions or ownership.
$WriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 `
             -bor 0x10000000 -bor 0x40000000

function Emit {
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($out | ConvertTo-Json -Depth 5 -Compress)))
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WriteProblem([string]$path) {
    # An allow entry that lets anyone but the system writers change the item.
    # Inherit-only entries (CREATOR OWNER) do not apply to the item itself.
    $acl = Get-Acl -LiteralPath $path
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if (([int]$ace.FileSystemRights -band $WriteMask) -eq 0) { continue }
        try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = [string]$ace.IdentityReference }
        if ($Writers -notcontains $sid) { return "writable by $sid" }
    }
    $owner = try { (New-Object Security.Principal.NTAccount($acl.Owner)).Translate(
        [Security.Principal.SecurityIdentifier]).Value } catch { [string]$acl.Owner }
    if ($Writers -notcontains $owner) { return "owned by $owner" }
    return $null
}

function Get-SignerProblem([string]$path) {
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    if ($sig.Status -ne 'Valid') { return "signature $($sig.Status)" }
    $org = ''
    if ($sig.SignerCertificate.Subject -match '(?:^|,\s*)O=("?)([^,"]+)\1') { $org = $Matches[2].Trim() }
    if ($Signers -notcontains $org) { return "signed by '$org'" }
    return $null
}

try {
    if (-not (Test-Admin)) { $out.reason = 'not elevated: the HP firmware log needs administrator'; Emit; return }
    $maker = [string](Get-CimInstance Win32_ComputerSystem).Manufacturer
    if ($maker -notmatch '^(HP|Hewlett)') { $out.reason = "not an HP machine ($maker)"; Emit; return }

    $base = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsPowerShell\Modules'
    $versions = @(Get-ChildItem -LiteralPath (Join-Path $base 'HP.Firmware') -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -as [version] } | Sort-Object { [version]$_.Name } -Descending)
    if (-not $versions) {
        $out.reason = 'HP CMSL is not installed for all users (Program Files)'; Emit; return
    }
    $ver = $versions[0].Name
    $roots = @()
    foreach ($name in $Modules) {
        $root = Join-Path $base "$name\$ver"
        if (-not (Test-Path -LiteralPath (Join-Path $root "$name.psd1"))) {
            $out.reason = "HP CMSL modules are not all version $ver ($name missing)"; Emit; return
        }
        $roots += $root
    }
    $out.module = [ordered]@{ name = 'HP.Firmware'; version = $ver; root = $base }

    # Integrity before anything loads: the module folders, every file in them,
    # and the folders above them up to the shared Modules folder.
    $problems = New-Object System.Collections.Generic.List[string]
    $dirs = @($base) + ($Modules | ForEach-Object { Join-Path $base $_ }) + $roots
    foreach ($root in $roots) { $dirs += @(Get-ChildItem -LiteralPath $root -Recurse -Directory | ForEach-Object FullName) }
    foreach ($dir in $dirs) {
        $why = Get-WriteProblem $dir
        if ($why) { $problems.Add("$($dir.Substring($base.Length)): $why") }
    }
    $files = foreach ($root in $roots) { Get-ChildItem -LiteralPath $root -Recurse -File }
    foreach ($file in $files) {
        $rel = $file.FullName.Substring($base.Length)
        $why = Get-WriteProblem $file.FullName
        if ($why) { $problems.Add("${rel}: $why") }
        if ($CodeExt -contains $file.Extension.ToLowerInvariant()) {
            $why = Get-SignerProblem $file.FullName
            if ($why) { $problems.Add("${rel}: $why") }
        }
    }
    if ($problems.Count) {
        $out.problems = @($problems | Select-Object -First 16)
        $out.reason = "refused: $($problems.Count) integrity problem(s) in the HP modules; nothing was loaded"
        Emit; return
    }

    $env:PSModulePath = "$base;$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules"
    foreach ($i in 0..2) {
        Import-Module -Name (Join-Path $roots[$i] "$($Modules[$i]).psd1") -Force -DisableNameChecking `
            -WarningAction SilentlyContinue | Out-Null
    }
    foreach ($name in $Modules) {
        $loaded = @(Get-Module -Name $name)
        if ($loaded.Count -ne 1 -or -not $loaded[0].ModuleBase.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
            $out.reason = "refused: $name loaded from outside Program Files"; Emit; return
        }
    }

    $rows = @(Get-HPFirmwareAuditLog -WarningAction SilentlyContinue)
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        if ($row -is [string]) { continue }   # "No records."
        $source = -1; $sourceName = [string]$row.source_id
        if ($sourceName -match '^(.*)\((\d+)\)\s*$') { $source = [int]$Matches[2]; $sourceName = $Matches[1].Trim() }
        $stamp = $null
        if ($row.timestamp -is [datetime]) { $stamp = $row.timestamp.ToString('yyyy-MM-ddTHH:mm:ss') }
        $desc = [string]$row.description
        if ($desc.Length -gt 300) { $desc = $desc.Substring(0, 300) }
        $records.Add([ordered]@{
            message_number = [int]$row.message_number; source = $source
            source_name = $sourceName.Substring(0, [Math]::Min(80, $sourceName.Length))
            event_id = [int]$row.event_id; severity = [string]$row.severity
            state = [string]$row.system_state_at_event; exact = [bool]$row.timestamp_is_exact
            timestamp = $stamp; description = $desc })
    }
    if ($records.Count -gt $MaxRecords) {
        $out.truncated = $true
        $records = $records.GetRange($records.Count - $MaxRecords, $MaxRecords)
    }
    # Not @($records): Windows PowerShell 5.1 throws "Argument types do not match"
    # wrapping a List[object] of ordered dictionaries that way (measured 2026-10-24,
    # the first run with CMSL installed: 46 records read, none reported).
    $out.records = $records.ToArray()
    $out.available = $true
} catch {
    $msg = [string]$_.Exception.Message
    if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
    $out.errors = @($_.Exception.GetType().Name + ': ' + $msg)
    if (-not $out.reason) { $out.reason = 'the firmware log read failed' }
}
Emit

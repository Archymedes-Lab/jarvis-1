# Append-only evidence vault, run by the elevated JARVIS broker.
#
# The unprivileged daemon stages copies of its sealed event-log segments, the
# chain file and timestamp anchors in %LOCALAPPDATA%\Jarvis\VaultInbox. The
# inbox is untrusted: anything running as the user can write there. This job
# moves staged files into C:\ProgramData\Jarvis\Vault, which only
# Administrators and SYSTEM can modify and only the owning user can read,
# under one rule: the vault only grows.
#
#   * The vaulted chain.jsonl must be a byte-for-byte prefix of the staged
#     one. Anything else means the live history was rewritten (or the inbox
#     forged); the staged chain is kept as divergence evidence and the vault
#     is left untouched.
#   * A file already in the vault is never overwritten or deleted. A staged
#     copy that differs from it is reported, not applied.
#   * A chain line is appended only after its segment is in the vault, or
#     the stager marked it as removed by retention before it was vaulted.
#
# The vault does not verify segment payload hashes itself (.NET Framework's
# GZipStream stops at the first gzip member); the daemon verifies vaulted
# copies read-only and reports any that fail. Output: base64 JSON, counts only.

# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'Stop'
# The user the broker was installed for, recorded by SID at install in this
# administrator-only folder. The broker runs as SYSTEM, so per-user state is
# read from HKEY_USERS\<SID>, read-only, never from this process's environment.
$UserSid = ''
try { $UserSid = [string](Get-Content -LiteralPath (Join-Path $PSScriptRoot 'user.json') -Raw | ConvertFrom-Json).sid } catch { }
if ($UserSid -notmatch '^S-1-(5-21|12-1)(-\d+)+$') { $UserSid = '' }
function Get-UserLocalAppData([string]$sid) {
    # From the administrator-owned profile list, not an environment variable.
    if (-not $sid) { return '' }
    $key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    $profile = (Get-ItemProperty -LiteralPath $key -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not $profile) { return '' }
    return (Join-Path $profile 'AppData\Local')
}
$Sys32 = [Environment]::SystemDirectory
# The vault path comes from the system drive, not %ProgramData%, which the
# user's own environment can redefine for this elevated process.
$Vault = Join-Path ([IO.Path]::GetPathRoot($Sys32)) 'ProgramData\Jarvis\Vault'
# The inbox in the recorded user's profile, located through the
# administrator-owned profile list; '' (and an error below) if unknown.
$UserLocal = Get-UserLocalAppData $UserSid
$Inbox = if ($UserLocal) { Join-Path $UserLocal 'Jarvis\VaultInbox' } else { '' }
$MaxBytes = 20GB
$BudgetSeconds = 90
$AnchorPattern = '^[0-9a-f]{64}(\.[a-z0-9]+)*\.(json|ots)$'

$result = [ordered]@{
  ok = $false
  vaulted_segments = 0
  head_segment = 0
  head_hash = ''
  new_segments = 0
  unvaulted_segments = 0
  new_anchors = 0
  anchor_conflicts = 0
  diverged = $false
  divergence = ''
  pending = ''
  bytes = 0
  full = $false
  truncated = $false
  error = ''
}

function Lock-Folder([string]$path) {
  # SYSTEM and Administrators: full. The recorded user: read, so the daemon
  # can verify. No other account: the history holds command lines. Owner
  # Administrators and the whole DACL replaced, not merged: a folder created
  # before the first run keeps neither its owner nor any extra entry.
  $sid = { param($v) New-Object Security.Principal.SecurityIdentifier($v) }
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetOwner((& $sid 'S-1-5-32-544'))
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  foreach ($grant in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'),
                       @($UserSid, 'ReadAndExecute'))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
      (& $sid $grant[0]), [Security.AccessControl.FileSystemRights]$grant[1], $inherit,
      [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
  }
  [IO.Directory]::SetAccessControl($path, $acl)
}

# The inbox is written by the unelevated user, and this job runs elevated. A
# junction, mount point or hard link planted in the inbox would make it read
# a file the user cannot, and copy it into the vault the user can read. Every
# inbox file is therefore opened once, checked through its handle (the path
# Windows resolved must be the one asked for, with a single link), and read
# only through that handle.
$HandleTypeError = ''
try { Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class JarvisInboxHandle {
    [StructLayout(LayoutKind.Sequential)]
    struct ByHandleInfo {
        public uint Attributes; public long Created; public long Accessed; public long Written;
        public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links;
        public uint IndexHigh; public uint IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint len, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle h, out ByHandleInfo info);
    public static string FinalPath(FileStream fs) {
        StringBuilder sb = new StringBuilder(1024);
        uint n = GetFinalPathNameByHandleW(fs.SafeFileHandle, sb, (uint)sb.Capacity, 0);
        if (n == 0 || n >= sb.Capacity) throw new IOException("final path unavailable");
        string s = sb.ToString();
        if (s.StartsWith(@"\\?\UNC\")) return @"\\" + s.Substring(8);
        if (s.StartsWith(@"\\?\")) return s.Substring(4);
        return s;
    }
    public static uint Links(FileStream fs) {
        ByHandleInfo info;
        if (!GetFileInformationByHandle(fs.SafeFileHandle, out info)) throw new IOException("file information unavailable");
        return info.Links;
    }
}
'@ } catch { $HandleTypeError = [string]$_.Exception.Message }

function Open-InboxFile([string]$path) {
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $final = [JarvisInboxHandle]::FinalPath($fs)
    if (-not [string]::Equals($final, [IO.Path]::GetFullPath($path), [StringComparison]::OrdinalIgnoreCase)) {
      throw "refused: staged $path resolves to another location"
    }
    if ([JarvisInboxHandle]::Links($fs) -ne 1) { throw "refused: staged $path is a hard link" }
    # Staged by the recorded user's daemon, so owned by that user.
    $owner = $fs.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $UserSid) { throw "refused: staged $path is owned by $owner, not the recorded user" }
    return $fs
  } catch { $fs.Dispose(); throw }
}

function Read-InboxBytes([string]$path) {
  $fs = Open-InboxFile $path
  try {
    $ms = New-Object IO.MemoryStream
    $fs.CopyTo($ms)
    return ,$ms.ToArray()
  } finally { $fs.Dispose() }
}

function Get-InboxSha256([string]$path) {
  $fs = Open-InboxFile $path
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose(); $fs.Dispose() }
}

function Get-InboxLength([string]$path) {
  $fs = Open-InboxFile $path
  try { return $fs.Length } finally { $fs.Dispose() }
}

function Get-Sha256([byte[]]$bytes, [int]$count) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($sha.ComputeHash($bytes, 0, $count)).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Get-FileSha256([string]$path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
}

function Add-Bytes([string]$path, [byte[]]$bytes) {
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
}

function Install-Copy([string]$source, [string]$target) {
  $temp = "$target.partial"
  if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
  $in = Open-InboxFile $source
  try {
    $out = New-Object IO.FileStream($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $in.CopyTo($out); $out.Flush($true) } finally { $out.Dispose() }
  } finally { $in.Dispose() }
  # Move fails rather than replacing: a file already in the vault stays.
  [IO.File]::Move($temp, $target)
  (Get-Item -LiteralPath $target).IsReadOnly = $true
}

try {
  if ($HandleTypeError) { throw "inbox handle checks unavailable: $HandleTypeError" }
  if (-not $UserSid -or -not $Inbox) { throw 'no recorded user or profile; reinstall the broker' }
  # The inbox folders themselves must be real folders, not links.
  foreach ($dir in @($Inbox, (Join-Path $Inbox 'eventlog'), (Join-Path $Inbox 'eventlog\segments'),
                     (Join-Path $Inbox 'anchors'))) {
    if ((Test-Path -LiteralPath $dir) -and
        ((Get-Item -LiteralPath $dir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "refused: inbox folder $dir is a link"
    }
  }
  if ((Test-Path -LiteralPath $Vault) -and
      ((Get-Item -LiteralPath $Vault -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "refused: $Vault is a link"
  }
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $segDir = Join-Path $Vault 'eventlog\segments'
  foreach ($dir in @($Vault, $segDir, (Join-Path $Vault 'anchors'), (Join-Path $Vault 'divergence'))) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  }
  Lock-Folder $Vault
  $chainPath = Join-Path $Vault 'eventlog\chain.jsonl'
  $digestPath = Join-Path $Vault 'eventlog\segments.sha256'
  $unvaultedPath = Join-Path $Vault 'eventlog\unvaulted.txt'
  # Assigned inside the branches: an if-expression would unroll the byte
  # arrays (an empty one becomes $null).
  [byte[]]$vaulted = New-Object byte[] 0
  if (Test-Path -LiteralPath $chainPath) { $vaulted = [IO.File]::ReadAllBytes($chainPath) }
  $inboxChain = Join-Path $Inbox 'eventlog\chain.jsonl'
  $staged = $null
  if (Test-Path -LiteralPath $inboxChain) { [byte[]]$staged = Read-InboxBytes $inboxChain }

  if ($null -ne $staged) {
    $prefix = $staged.Length -ge $vaulted.Length -and
              (Get-Sha256 $staged $vaulted.Length) -eq (Get-Sha256 $vaulted $vaulted.Length)
    if (-not $prefix) {
      $result.diverged = $true
      $result.divergence = 'staged chain does not extend the vaulted chain'
      $evidence = Join-Path $Vault ('divergence\chain-' + (Get-Sha256 $staged $staged.Length) + '.jsonl')
      if (-not (Test-Path -LiteralPath $evidence)) {
        [IO.File]::WriteAllBytes($evidence, $staged)
        (Get-Item -LiteralPath $evidence).IsReadOnly = $true
      }
    } else {
      $size = [int64](Get-ChildItem -LiteralPath $Vault -Recurse -File | Measure-Object Length -Sum).Sum
      $offset = $vaulted.Length
      while ($offset -lt $staged.Length) {
        $end = [Array]::IndexOf($staged, [byte]10, $offset)
        if ($end -lt 0) { break }                     # torn tail: wait for the stager
        $lineBytes = New-Object byte[] ($end - $offset + 1)
        [Array]::Copy($staged, $offset, $lineBytes, 0, $lineBytes.Length)
        $header = [Text.Encoding]::UTF8.GetString($lineBytes) | ConvertFrom-Json
        $name = '{0:D12}.jseg' -f [int64]$header.segment
        $source = Join-Path $Inbox "eventlog\segments\$name"
        $target = Join-Path $segDir $name
        if (Test-Path -LiteralPath $target) {
          if ((Test-Path -LiteralPath $source) -and (Get-InboxSha256 $source) -ne (Get-FileSha256 $target)) {
            $result.diverged = $true
            $result.divergence = "staged $name differs from its vaulted copy"
            break
          }
        } elseif (Test-Path -LiteralPath $source) {
          if ($size + (Get-InboxLength $source) -ge $MaxBytes) { $result.full = $true; break }
          Install-Copy $source $target
          $size += (Get-Item -LiteralPath $target).Length
          Add-Bytes $digestPath ([Text.Encoding]::ASCII.GetBytes("$name $(Get-FileSha256 $target)`n"))
          $result.new_segments++
        } elseif (Test-Path -LiteralPath "$source.pruned") {
          Add-Bytes $unvaultedPath ([Text.Encoding]::ASCII.GetBytes("$name removed by retention before it was vaulted`n"))
          $result.unvaulted_segments++
        } else {
          $result.pending = "waiting for staged $name"
          break
        }
        Add-Bytes $chainPath $lineBytes
        $offset = $end + 1
        if ($clock.Elapsed.TotalSeconds -ge $BudgetSeconds) { $result.truncated = $true; break }
      }
    }
  }

  $anchorInbox = Join-Path $Inbox 'anchors'
  if (Test-Path -LiteralPath $anchorInbox) {
    foreach ($file in Get-ChildItem -LiteralPath $anchorInbox -File) {
      if ($file.Name -notmatch $AnchorPattern) { continue }
      $target = Join-Path $Vault "anchors\$($file.Name)"
      if (Test-Path -LiteralPath $target) {
        if ((Get-InboxSha256 $file.FullName) -ne (Get-FileSha256 $target)) { $result.anchor_conflicts++ }
      } else {
        Install-Copy $file.FullName $target
        $result.new_anchors++
      }
    }
  }

  if (Test-Path -LiteralPath $chainPath) {
    $lines = @([IO.File]::ReadAllLines($chainPath) | Where-Object { $_ })
    $result.vaulted_segments = $lines.Count
    if ($lines.Count) {
      $head = $lines[-1] | ConvertFrom-Json
      $result.head_segment = [int64]$head.segment
      $result.head_hash = [string]$head.hash
    }
  }
  $result.bytes = [int64](Get-ChildItem -LiteralPath $Vault -Recurse -File | Measure-Object Length -Sum).Sum
  $result.full = $result.full -or $result.bytes -ge $MaxBytes
  $result.ok = $true
} catch {
  $result.error = [string]$_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 4 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

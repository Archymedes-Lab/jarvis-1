# Read-only active Sysmon configuration export for the elevated JARVIS broker.
# The broker stages this script in its administrator-only directory before use.
# Nothing here installs, updates, or reconfigures Sysmon.

# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
  installed = $false
  service = ''
  executable = ''
  exit_code = -1
  dump = ''
  error = ''
}

try {
  $svc = Get-CimInstance Win32_Service |
    Where-Object { $_.Name -in @('Sysmon64', 'Sysmon') } |
    Select-Object -First 1
  if (-not $svc) { throw 'Sysmon service not installed' }
  $result.installed = $true
  $result.service = [string]$svc.Name
  $exe = [string]$svc.PathName
  if ($exe.StartsWith('"')) {
    $exe = $exe.Substring(1, $exe.IndexOf('"', 1) - 1)
  } else {
    $exe = ($exe -split '\s+')[0]
  }
  if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'Sysmon executable from service registration does not exist'
  }
  $result.executable = $exe
  # Sysmon emits UTF-16 directly to its native streams. PowerShell's ordinary
  # native pipeline can swallow that output or leave embedded NULs, so capture
  # both streams with an explicit encoding instead of trusting the console.
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = $exe
  $start.Arguments = '-c'
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $start.StandardOutputEncoding = [Text.Encoding]::Unicode
  $start.StandardErrorEncoding = [Text.Encoding]::Unicode
  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $start
  if (-not $process.Start()) { throw 'Sysmon configuration export did not start' }
  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  $process.WaitForExit()
  $result.exit_code = [int]$process.ExitCode
  $result.dump = [string](($stdout + [Environment]::NewLine + $stderr) -replace "`0", '')
  if ($result.exit_code -ne 0) {
    throw "Sysmon configuration export exited $($result.exit_code)"
  }
} catch {
  $result.error = [string]$_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 4 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

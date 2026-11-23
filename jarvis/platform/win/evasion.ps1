
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. the two features that actually stop BYOVD -------------------------
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$o.hvciRunning = [bool](@($dg.SecurityServicesRunning) -contains 2)
$o.hvciConfigured = [bool](@($dg.SecurityServicesConfigured) -contains 2)
$o.vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus

$ci = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$v = (Get-ItemProperty -Path $ci -Name VulnerableDriverBlocklistEnable).VulnerableDriverBlocklistEnable
# Absent means "default", and the default is on for Windows 11 22H2 and later.
$o.blocklistValue = if ($null -eq $v) { -1 } else { [int]$v }

$hv = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$o.hvciRegEnabled = [int](Get-ItemProperty -Path $hv -Name Enabled).Enabled

# The ASR rule that blocks known-exploited signed drivers (Microsoft: 'Block abuse
# of exploited vulnerable signed drivers'). -1 not configured, -2 unreadable.
$asrId = '56a863a9-875e-4185-98a7-b882c64b5ce5'
$o.asrByovd = -2
$mp = Get-MpPreference
if ($mp) {
  $o.asrByovd = -1
  $ids = @($mp.AttackSurfaceReductionRules_Ids); $acts = @($mp.AttackSurfaceReductionRules_Actions)
  for ($i = 0; $i -lt $ids.Count; $i++) { if ([string]$ids[$i] -ieq $asrId -and $i -lt $acts.Count) { $o.asrByovd = [int]$acts[$i] } }
}

# Mandatory-profile hives: an NTUSER.MAN in a profile folder is loaded at logon
# instead of NTUSER.DAT, so registry persistence planted offline in it bypasses
# registry monitoring and needs no administrator rights (2026 research).
$o.manHives = @(); $o.manUnreadable = 0
foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -Force)) {
  try {
    $f = Get-Item -LiteralPath (Join-Path $d.FullName 'NTUSER.MAN') -Force -ErrorAction Stop
    $o.manHives += [pscustomobject]@{ path = [string]$f.FullName; size = [int64]$f.Length; written = $f.LastWriteTimeUtc.ToString('o') }
  } catch [System.Management.Automation.ItemNotFoundException] {
  } catch { $o.manUnreadable++ }
}

# --- 2. loaded kernel drivers ---------------------------------------------
# Only drivers outside the normal directories get an Authenticode check: over
# 300 drivers are loaded and signature verification is far too slow to run on
# all of them every pass.
$o.drivers = @(Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.State -eq 'Running' -and $_.PathName } |
  ForEach-Object {
    [pscustomobject]@{
      name = [string]$_.Name
      path = [string]$_.PathName
      start= [string]$_.StartMode
    } })

# --- 3. alternate data streams --------------------------------------------
# Zone.Identifier is the mark-of-the-web and is on nearly every downloaded file;
# any *other* stream is the interesting case. Scoped to the directories payloads
# stage in, and capped, because a full-disk stream enumeration is not something
# you can run every half hour.
$dirs = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop",
          "$env:TEMP", "$env:LOCALAPPDATA\Temp", "$env:PUBLIC",
          "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
$cut = (Get-Date).AddDays(-90)
$o.ads = @(foreach ($d in $dirs) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 -Force |
    Where-Object { $_.LastWriteTime -gt $cut } |
    Select-Object -First 400 |
    ForEach-Object {
      $f = $_
      Get-Item -LiteralPath $f.FullName -Stream * |
        Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } |
        ForEach-Object {
          [pscustomobject]@{ file=[string]$f.FullName
                             stream=[string]$_.Stream
                             size=[long]$_.Length }
        }
    }
})

# --- 4. shortcuts ----------------------------------------------------------
$shell = New-Object -ComObject WScript.Shell
$lnkDirs = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
             "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
             "$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop",
             "$env:USERPROFILE\Downloads")
$o.lnks = @(foreach ($d in $lnkDirs) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -Filter *.lnk -Force -ErrorAction SilentlyContinue |
    Select-Object -First 150 |
    ForEach-Object {
      $s = $shell.CreateShortcut($_.FullName)
      [pscustomobject]@{
        lnk    = [string]$_.FullName
        target = [string]$s.TargetPath
        args   = [string]$s.Arguments
        icon   = [string]$s.IconLocation
        wstyle = [int]$s.WindowStyle
      }
    }
})

# --- 5. where this machine has actually been resolving ---------------------
# The DNS client cache is the cheapest possible view of egress destinations by
# name, which is the only way dead-drop C2 is distinguishable at all.
$o.dns = [string[]]@(Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique)

# --- 6. autostart command lines, for the Unicode check ---------------------
$o.autoruns = @(
  foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
    if (-not (Test-Path $k)) { continue }
    $p = Get-ItemProperty $k
    $p.PSObject.Properties |
      Where-Object { $_.Name -notlike 'PS*' } |
      ForEach-Object { [pscustomobject]@{ key=$k; name=[string]$_.Name; cmd=[string]$_.Value } }
  })

$o.runmru = [string[]]@(
  $m = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
  if (Test-Path $m) {
    (Get-ItemProperty $m).PSObject.Properties |
      Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object { [string]$_.Value }
  })

$payload = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))

# Read-only WSL registration: per-distribution defaults, service plugins, policy.
# Nothing here writes.
$ErrorActionPreference = 'SilentlyContinue'
$o = @{distros=@(); defaultDistribution=''; plugins=@(); policy=@{}; wslVersion=''; errors=@()}
$lx = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
try {
  if (Test-Path $lx) {
    $root = Get-ItemProperty $lx
    $o.defaultDistribution = [string]$root.DefaultDistribution
    foreach ($k in (Get-ChildItem $lx | Where-Object { $_.PSChildName -like '{*}' } | Select-Object -First 32)) {
      $p = Get-ItemProperty $k.PSPath
      $uid = -1; if ($null -ne $p.DefaultUid) { $uid = [int64]$p.DefaultUid }
      $flags = -1; if ($null -ne $p.Flags) { $flags = [int64]$p.Flags }
      $ver = -1; if ($null -ne $p.Version) { $ver = [int64]$p.Version }
      $o.distros += @{guid=[string]$k.PSChildName; name=[string]$p.DistributionName;
                      defaultUid=$uid; basePath=[string]$p.BasePath; flags=$flags; version=$ver}
    }
  } else { $o.errors += 'no WSL registration in the user hive' }
} catch { $o.errors += 'WSL registration unreadable' }
try {
  $plug = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins'
  if (Test-Path $plug) {
    $names = @((Get-Item $plug).GetValueNames() | ForEach-Object { [string]$_ })
    $names += @(Get-ChildItem $plug | ForEach-Object { [string]$_.PSChildName })
    $o.plugins = @($names | Where-Object { $_ -ne '' } | Select-Object -First 16)
  }
} catch { $o.errors += 'WSL plugin list unreadable' }
try {
  $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WSL'
  if (Test-Path $pol) {
    $pp = Get-ItemProperty $pol
    foreach ($n in ($pp.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -First 32)) {
      $o.policy[[string]$n.Name] = [string]$n.Value
    }
  }
} catch { $o.errors += 'WSL policy unreadable' }
try { $o.wslVersion = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\MSI').Version } catch {}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 5 -Compress)))


# Storage headroom on the Windows side: the system drive, the WSL disk image,
# swap, page file policy, and the ballast file. One read, no changes.
$o = @{errors=@()}
try {
  $d = Get-PSDrive ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop
  $o.sys_drive = $env:SystemDrive; $o.sys_free = [double]$d.Free; $o.sys_total = [double]($d.Used + $d.Free)
} catch { $o.errors += 'system drive free space unreadable' }
try {
  $base = Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss -ErrorAction Stop |
    ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.BasePath } | Select-Object -First 1
  if ($base) {
    $v = Join-Path ($base.BasePath -replace '^\\\\\?\\','') 'ext4.vhdx'
    $o.vhdx_path = $v
    $o.vhdx_bytes = [double](Get-Item -LiteralPath $v -Force -ErrorAction Stop).Length
    $o.distro = [string]$base.DistributionName
  } else { $o.errors += 'no WSL distribution registered for this user' }
} catch { $o.errors += 'WSL disk image size unreadable' }
try {
  $cfg = Join-Path $env:USERPROFILE '.wslconfig'
  if (Test-Path -LiteralPath $cfg) {
    $line = Get-Content -LiteralPath $cfg -ErrorAction Stop | Where-Object { $_ -match '^\s*swapFile\s*=' } | Select-Object -First 1
    if ($line) { $sw = ($line -split '=',2)[1].Trim().Replace('\\','\'); if (Test-Path -LiteralPath $sw) { $o.swap_bytes = [double](Get-Item -LiteralPath $sw -Force).Length } }
  }
} catch { $o.errors += 'WSL swap file unreadable' }
try {
  $o.pagefile_automatic = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).AutomaticManagedPagefile
  $o.pagefile = @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop | ForEach-Object {
    @{name=[string]$_.Name; allocated_mb=[int]$_.AllocatedBaseSize; used_mb=[int]$_.CurrentUsage} })
} catch { $o.errors += 'page file state unreadable' }
try {
  $b = Join-Path $env:LOCALAPPDATA 'Jarvis\ballast.bin'
  $o.ballast_path = $b
  if (Test-Path -LiteralPath $b) { $o.ballast_bytes = [double](Get-Item -LiteralPath $b -Force).Length } else { $o.ballast_bytes = 0 }
} catch { $o.errors += 'ballast file unreadable' }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 4 -Compress)))

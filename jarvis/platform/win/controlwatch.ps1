
$o = @{brightness=@(); displays=@(); monitors=0; audioRender=@(); audioCapture=@();
       devices=@(); liveUse=@(); errors=@()}
try {
  $o.brightness = @(Get-CimInstance -Namespace root/WMI -ClassName WmiMonitorBrightness -ErrorAction Stop |
    ForEach-Object { @{id=[string]$_.InstanceName; active=[bool]$_.Active; value=[int]$_.CurrentBrightness} })
} catch { $o.errors += 'Brightness state unavailable or unsupported by this display' }
try {
  $o.displays = @(Get-CimInstance Win32_VideoController -ErrorAction Stop | ForEach-Object {
    @{id=[string]$_.DeviceID; name=[string]$_.Name; status=[string]$_.Status;
      driver=[string]$_.DriverVersion;
      mode=("{0}x{1}@{2}" -f [int]$_.CurrentHorizontalResolution,
            [int]$_.CurrentVerticalResolution, [int]$_.CurrentRefreshRate)} })
} catch { $o.errors += 'Display driver state unavailable' }
try {
  $o.monitors = @(Get-PnpDevice -Class Monitor -PresentOnly -ErrorAction Stop |
    Where-Object { $_.Status -eq 'OK' }).Count
} catch { $o.errors += 'Monitor count unavailable' }
try {
  $ae = @(Get-PnpDevice -Class AudioEndpoint -PresentOnly -ErrorAction Stop |
    ForEach-Object { @{id=[string]$_.InstanceId; name=[string]$_.FriendlyName; status=[string]$_.Status} })
  $o.audioRender  = @($ae | Where-Object { $_.id -match '\\Render\\'  -or $_.name -match 'Speakers|Headphones|Headset' })
  $o.audioCapture = @($ae | Where-Object { $_.id -match '\\Capture\\' -or $_.name -match 'Microphone|Mic |Line In' })
  if (-not $o.audioRender -and -not $o.audioCapture) { $o.audioRender = $ae }
} catch { $o.errors += 'Audio endpoint inventory unavailable' }
try {
  $o.devices = @(Get-PnpDevice -PresentOnly -ErrorAction Stop |
    Where-Object { $_.Class -in 'Keyboard','Mouse','HIDClass','Camera','Image','Monitor','Bluetooth' } |
    ForEach-Object { @{id=[string]$_.InstanceId; name=[string]$_.FriendlyName; class=[string]$_.Class; status=[string]$_.Status} })
} catch { $o.errors += 'Input, camera, and Bluetooth device inventory unavailable' }
try {
  foreach ($hive in @('HKCU:','HKLM:')) {
    $base = "$hive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    if (-not (Test-Path $base)) { continue }
    foreach ($capKey in (Get-ChildItem $base)) {
      $cap = $capKey.PSChildName
      foreach ($k in (Get-ChildItem $capKey.PSPath)) {
        $leaves = if ($k.PSChildName -eq 'NonPackaged') { Get-ChildItem $k.PSPath } else { @($k) }
        foreach ($l in $leaves) {
          $v = Get-ItemProperty $l.PSPath
          if ($null -eq $v.LastUsedTimeStart) { continue }
          $st = [int64]$v.LastUsedTimeStart; $sp = [int64]$v.LastUsedTimeStop
          if ($st -gt 0 -and $sp -eq 0) {
            $o.liveUse += @{cap=$cap; app=($l.PSChildName -replace '#','\');
                            since=[DateTime]::FromFileTime($st).ToString('o')}
          }
        }
      }
    }
  }
} catch { $o.errors += 'Capability-in-use ledger unreadable' }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 6 -Compress)))

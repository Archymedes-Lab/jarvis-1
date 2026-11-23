# Read-only privacy posture: consent store, AppPrivacy policy, capture devices.
# Nothing here writes. The seal/unseal writer is privacy_seal_apply.ps1.
$ErrorActionPreference = 'SilentlyContinue'
$o = @{caps=@{}; policy=@{}; devices=@(); captureEndpoints=@(); build=''; errors=@()}
$capNames = @('microphone','webcam','location','graphicsCaptureProgrammatic','graphicsCaptureWithoutBorder')
try { $o.build = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild } catch {}
function ReadValue($path) {
  if (-not (Test-Path $path)) { return $null }
  $v = (Get-ItemProperty $path).Value
  if ($null -eq $v) { return '' }
  return [string]$v
}
foreach ($cap in $capNames) {
  $row = @{user=@{global=$null; nonpackaged=$null}; machine=@{global=$null; nonpackaged=$null}; apps=@()}
  foreach ($pair in @(@('HKCU:','user'), @('HKLM:','machine'))) {
    $hive = $pair[0]; $slot = $pair[1]
    $base = "$hive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
    try {
      $row[$slot].global = ReadValue $base
      $row[$slot].nonpackaged = ReadValue "$base\NonPackaged"
      if (-not (Test-Path $base)) { continue }
      foreach ($k in (Get-ChildItem $base)) {
        $kind = 'packaged'
        $leaves = @($k)
        if ($k.PSChildName -eq 'NonPackaged') { $kind = 'desktop'; $leaves = @(Get-ChildItem $k.PSPath) }
        foreach ($l in $leaves) {
          if ($row.apps.Count -ge 128) { $o.errors += 'consent app budget exhausted'; break }
          $v = Get-ItemProperty $l.PSPath
          $st = 0; $sp = 0
          if ($null -ne $v.LastUsedTimeStart) { $st = [int64]$v.LastUsedTimeStart }
          if ($null -ne $v.LastUsedTimeStop) { $sp = [int64]$v.LastUsedTimeStop }
          $val = ''
          if ($null -ne $v.Value) { $val = [string]$v.Value }
          $row.apps += @{name=($l.PSChildName -replace '#','\'); kind=$kind; hive=$slot;
                         value=$val; start=$st; stop=$sp}
        }
      }
    } catch { $o.errors += "consent store for $cap unreadable in $slot hive" }
  }
  $o.caps[$cap] = $row
}
try {
  $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
  foreach ($name in @('LetAppsAccessMicrophone','LetAppsAccessCamera','LetAppsAccessLocation')) {
    $v = $null
    if ($pol -and $null -ne $pol.$name) { $v = [int]$pol.$name }
    $o.policy[$name] = $v
  }
} catch { $o.errors += 'AppPrivacy policy unreadable' }
try {
  $o.devices = @(Get-PnpDevice -Class Camera,Image,Bluetooth -PresentOnly -ErrorAction Stop |
    Select-Object -First 64 | ForEach-Object {
      @{id=[string]$_.InstanceId; name=[string]$_.FriendlyName; class=[string]$_.Class;
        status=[string]$_.Status; problem=[int]$_.ProblemCode} })
} catch { $o.errors += 'camera and Bluetooth device inventory unavailable' }
try {
  $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture'
  $o.captureEndpoints = @(Get-ChildItem $base -ErrorAction Stop | Select-Object -First 64 | ForEach-Object {
    $st = (Get-ItemProperty $_.PSPath).DeviceState
    $nm = (Get-ItemProperty "$($_.PSPath)\Properties").'{a45c254e-df1c-4efd-8020-67d146a850e0},2'
    $raw = 0
    if ($null -ne $st) { $raw = [int64]$st }
    @{id=[string]$_.PSChildName; name=[string]$nm; state=[int]($raw -band 0xF)} })
} catch { $o.errors += 'capture endpoint registry unavailable' }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 6 -Compress)))

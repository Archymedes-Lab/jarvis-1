
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# --- 1. Who used the microphone / camera / location, and when -------------
$caps = New-Object System.Collections.ArrayList
foreach ($hive in @('HKCU:','HKLM:')) {
  $base = "$hive\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
  # Every capability Windows keeps a ledger for, not a hand-picked three.
  # Screen capture (graphicsCapture*), notification reading and app diagnostics
  # are exactly what surveillance software wants and were previously unread.
  if (-not (Test-Path $base)) { continue }
  foreach ($capKey in (Get-ChildItem $base)) {
    $cap = $capKey.PSChildName
    $capPath = $capKey.PSPath
    foreach ($k in (Get-ChildItem $capPath)) {
      # Desktop (non-Store) apps are nested one level deeper under NonPackaged,
      # with their path encoded using '#' in place of the separators.
      $leaves = if ($k.PSChildName -eq 'NonPackaged') { Get-ChildItem $k.PSPath } else { @($k) }
      foreach ($l in $leaves) {
        $v = Get-ItemProperty $l.PSPath
        if ($null -eq $v.LastUsedTimeStart) { continue }
        $st = [int64]$v.LastUsedTimeStart
        $sp = [int64]$v.LastUsedTimeStop
        [void]$caps.Add([pscustomobject]@{
          cap   = $cap
          hive  = $hive
          app   = ($l.PSChildName -replace '#','\')
          start = if ($st -gt 0) { [DateTime]::FromFileTime($st).ToString('o') } else { '' }
          stop  = if ($sp -gt 0) { [DateTime]::FromFileTime($sp).ToString('o') } else { '' }
          inUse = ($st -gt 0 -and $sp -eq 0)
        })
      }
    }
  }
}
$o.caps = @($caps)

# --- 2. Every autostart binary, with its Authenticode signature -----------
$paths = New-Object System.Collections.ArrayList
$shell = New-Object -ComObject WScript.Shell
function Add-Path([string]$cmd) {
  if (-not $cmd) { return }
  $c = $cmd.Trim()
  # Pull the executable out of a command line, quoted or not.
  if ($c.StartsWith('"')) { $p = ($c -split '"')[1] }
  else { $m = [regex]::Match($c, '^(.*?\.(exe|dll|scr|com|bat|cmd|vbs|ps1|lnk))\b',
                             'IgnoreCase'); $p = if ($m.Success) { $m.Groups[1].Value } else { $c } }
  if (-not $p) { return }
  # A shortcut carries no signature of its own; follow it to the real binary.
  if ($p -like '*.lnk' -and (Test-Path -LiteralPath $p)) {
    $t = $shell.CreateShortcut($p).TargetPath
    if ($t) { $p = $t }
  }
  if (Test-Path -LiteralPath $p -PathType Leaf) { [void]$paths.Add($p) }
}

foreach ($k in @(
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
   'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
   'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')) {
  $p = Get-ItemProperty -Path $k
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { Add-Path ([string]$_.Value) } }
}
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } |
  ForEach-Object { Add-Path $_.PathName }
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } |
  ForEach-Object { $_.Actions | ForEach-Object { Add-Path $_.Execute } }
Get-ChildItem -File -Path @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") |
  ForEach-Object { Add-Path $_.FullName }

$o.sigs = @($paths | Select-Object -Unique | ForEach-Object {
  $s = Get-AuthenticodeSignature -LiteralPath $_
  $f = Get-Item -LiteralPath $_
  [pscustomobject]@{
    path    = $_
    status  = [string]$s.Status
    signer  = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }
    written = $f.LastWriteTime.ToString('o')
  }
})

# --- 3. Input devices able to send volume/media commands ------------------
$o.hid = @(Get-CimInstance Win32_PnPEntity |
  Where-Object { $_.Name -match 'Consumer Control|HID Keyboard|Multimedia|Audio Control' -and
                 $_.Status -eq 'OK' } |
  Select-Object -First 25 @{n='name';e={$_.Name}}, @{n='id';e={$_.DeviceID}},
                          @{n='mfr';e={$_.Manufacturer}})

$o.audio = @(Get-CimInstance Win32_SoundDevice |
  Select-Object @{n='name';e={$_.Name}}, @{n='status';e={$_.Status}})

# --- 4. Software with a global input hook or accessibility control --------
# UIAccess / accessibility apps can drive the desktop; so can anything holding
# a low-level keyboard hook. Enumerating the modules is native work, so we look
# at the practical proxy: running processes from known input-automation tools.
$o.procs = @(Get-Process | ForEach-Object {
  [pscustomobject]@{ pid=$_.Id; name=$_.ProcessName; path=$_.Path;
                     title=$_.MainWindowTitle } })

# --- 5. Keyboard stack integrity -------------------------------------------
# A software keylogger that wants every keystroke regardless of which window has
# focus has two durable options, and both are visible from here.
#
#   * A keyboard class filter driver. It sits in the driver stack above
#     kbdclass and sees scancodes before any application does. The stack is
#     declared in one registry value, and on a healthy machine that value is
#     exactly 'kbdclass'.
#   * A Scancode Map. It remaps keys in the kernel. It has legitimate uses
#     (swapping Caps Lock), but it is also how a key can be made to do something
#     other than what is printed on it, and an unexpected one is worth seeing.
$kb = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}'
$ms = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96F-E325-11CE-BFC1-08002BE10318}'
$o.kbdUpperFilters = [string[]]@((Get-ItemProperty $kb).UpperFilters)
$o.kbdLowerFilters = [string[]]@((Get-ItemProperty $kb).LowerFilters)
$o.mouUpperFilters = [string[]]@((Get-ItemProperty $ms).UpperFilters)
$sc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout').'Scancode Map'
$o.scancodeMap = if ($sc) { [BitConverter]::ToString($sc) } else { '' }

# Physically present keyboards. A hardware keylogger that sits between a USB
# keyboard and the port has to enumerate as a keyboard itself to pass keystrokes
# through, so an unaccounted-for entry here is the artifact it cannot avoid.
$o.keyboards = @(Get-PnpDevice -Class Keyboard |
  Select-Object @{n='name';e={[string]$_.FriendlyName}},
                @{n='id';e={[string]$_.InstanceId}},
                @{n='status';e={[string]$_.Status}})

# Every USB device this machine has ever enumerated, so a keyboard that was
# attached once and removed still shows up.
$o.usbHistory = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' |
  ForEach-Object {
    $vid = $_.PSChildName
    $desc = @(Get-ChildItem $_.PSPath | ForEach-Object {
                (Get-ItemProperty $_.PSPath).DeviceDesc }) -replace '^@.*;',''
    [pscustomobject]@{ id=[string]$vid; desc=[string]($desc -join '; ') } })

# The accessibility binaries run as SYSTEM from the logon screen, before anyone
# signs in. An IFEO debugger on one of them is a keyboard-reachable backdoor.
$o.ifeoAccessibility = @(
  foreach ($f in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','atbroker.exe') {
    $d = (Get-ItemProperty ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $f)).Debugger
    if ($d) { [pscustomobject]@{ file=$f; debugger=[string]$d } }
  })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

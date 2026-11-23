
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

function Get-Val($path, $name) {
  $p = Get-ItemProperty -Path $path -Name $name
  if ($p) { return [string]$p.$name }
  return ''
}

# --- loader abuse ---------------------------------------------------------
$o.appinit = @(foreach ($k in @(
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
  $v = Get-Val $k 'AppInit_DLLs'
  $e = Get-Val $k 'LoadAppInit_DLLs'
  if ($v) { [pscustomobject]@{ key=$k; dlls=$v; enabled=$e } }
})

# Image File Execution Options: a "Debugger" value replaces the program itself.
$o.ifeo = @(Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  ForEach-Object {
    $dbg = Get-Val $_.PSPath 'Debugger'
    $flt = Get-Val $_.PSPath 'GlobalFlag'
    if ($dbg -or $flt -eq '512') {
      [pscustomobject]@{ target=$_.PSChildName; debugger=$dbg; globalFlag=$flt } } })

# --- logon chain ----------------------------------------------------------
$wl = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$o.winlogon = [pscustomobject]@{
  shell    = Get-Val $wl 'Shell'
  userinit = Get-Val $wl 'Userinit'
  taskman  = Get-Val $wl 'Taskman'
  appsetup = Get-Val $wl 'AppSetup'
}

$o.activeSetup = @(Get-ChildItem 'HKLM:\Software\Microsoft\Active Setup\Installed Components' |
  ForEach-Object {
    $sp = Get-Val $_.PSPath 'StubPath'
    if ($sp) { [pscustomobject]@{ key=$_.PSChildName; stub=$sp } } })

# --- COM hijacking --------------------------------------------------------
# A CLSID registered under HKCU wins over the machine-wide one, so a per-user
# InprocServer32 pointing outside Windows is how a normal app is made to load
# somebody else's DLL.
function Resolve-Dll([string]$dll) {
  if (-not $dll) { return $null }
  $p = [Environment]::ExpandEnvironmentVariables($dll.Trim('"'))
  # A bare name resolves out of System32 at load time.
  if ($p -notmatch '[\\/]') { $p = Join-Path $env:SystemRoot "System32\$p" }
  return [pscustomobject]@{ path=$p; exists=[bool](Test-Path -LiteralPath $p) }
}

$o.comHijack = @(Get-ChildItem 'HKCU:\Software\Classes\CLSID' |
  ForEach-Object {
    $ip = Join-Path $_.PSPath 'InprocServer32'
    if (Test-Path $ip) {
      $dll = [string](Get-ItemProperty $ip).'(default)'
      if ($dll) {
        $r = Resolve-Dll $dll
        [pscustomobject]@{ clsid=$_.PSChildName; dll=$dll
                           path=$r.path; exists=$r.exists } } } })

# --- privileged plumbing --------------------------------------------------
$lsa = 'HKLM:\System\CurrentControlSet\Control\Lsa'
$o.lsa = [pscustomobject]@{
  security     = [string]((Get-ItemProperty $lsa).'Security Packages' -join ',')
  notification = [string]((Get-ItemProperty $lsa).'Notification Packages' -join ',')
  authentication = [string]((Get-ItemProperty $lsa).'Authentication Packages' -join ',')
}
$o.printMonitors = @(Get-ChildItem 'HKLM:\System\CurrentControlSet\Control\Print\Monitors' |
  ForEach-Object { [pscustomobject]@{ name=$_.PSChildName; dll=(Get-Val $_.PSPath 'Driver') } })
$o.netsh = @((Get-Item 'HKLM:\Software\Microsoft\Netsh').Property |
  ForEach-Object { [pscustomobject]@{ name=$_; dll=(Get-Val 'HKLM:\Software\Microsoft\Netsh' $_) } })
$o.timeProviders = @(Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders' |
  ForEach-Object { [pscustomobject]@{ name=$_.PSChildName; dll=(Get-Val $_.PSPath 'DllName')
                                      enabled=(Get-Val $_.PSPath 'Enabled') } })

# --- explorer extension points -------------------------------------------
# Extension points hold CLSIDs, not paths. Resolving each one to the DLL it
# actually loads is what makes the difference between "a hook exists" (always
# true) and "a hook loads code from somewhere it shouldn't".
function Resolve-Clsid([string]$clsid) {
  foreach ($root in @('HKLM:\Software\Classes\CLSID', 'HKCU:\Software\Classes\CLSID',
                      'HKLM:\Software\Wow6432Node\Classes\CLSID')) {
    $ip = "$root\$clsid\InprocServer32"
    if (Test-Path $ip) {
      $d = [string](Get-ItemProperty $ip).'(default)'
      if ($d) { return $d }
    }
  }
  return ''
}

$o.shellHooks = @(foreach ($k in @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects')) {
  if (Test-Path $k) {
    (Get-Item $k).Property | Where-Object { $_ -ne '(default)' } | ForEach-Object {
      $dll = Resolve-Clsid $_
      $r = Resolve-Dll $dll
      [pscustomobject]@{ key=$k; name=$_; dll=$dll
                         path=$(if($r){$r.path}else{''}); exists=$(if($r){$r.exists}else{$false}) } }
    Get-ChildItem $k | ForEach-Object {
      $dll = Resolve-Clsid $_.PSChildName
      $r = Resolve-Dll $dll
      [pscustomobject]@{ key=$k; name=$_.PSChildName; dll=$dll
                         path=$(if($r){$r.path}else{''}); exists=$(if($r){$r.exists}else{$false}) } } } })

# --- screensaver + accessibility backdoor --------------------------------
$o.screensaver = Get-Val 'HKCU:\Control Panel\Desktop' 'SCRNSAVE.EXE'
$o.accessibility = @(foreach ($n in @('sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','atbroker.exe')) {
  $p = "C:\Windows\System32\$n"
  if (Test-Path $p) {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    [pscustomobject]@{ name=$n; status=[string]$s.Status
                       signer=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''} } } })

# --- execution history (UserAssist) --------------------------------------
function Rot13([string]$s) {
  -join ($s.ToCharArray() | ForEach-Object {
    if ($_ -match '[a-zA-Z]') {
      $b = if ([char]::IsUpper($_)) { 65 } else { 97 }
      [char]((([int][char]$_ - $b + 13) % 26) + $b)
    } else { $_ } })
}
$ua = New-Object System.Collections.ArrayList
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' |
  ForEach-Object {
    $c = Join-Path $_.PSPath 'Count'
    if (Test-Path $c) {
      $props = Get-ItemProperty $c
      $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        $d = $_.Value
        if ($d -is [byte[]] -and $d.Length -ge 68) {
          $runs = [BitConverter]::ToInt32($d, 4)
          $ft   = [BitConverter]::ToInt64($d, 60)
          if ($ft -gt 0 -and $runs -gt 0) {
            [void]$ua.Add([pscustomobject]@{
              name = Rot13 $_.Name
              runs = $runs
              last = [DateTime]::FromFileTime($ft).ToString('o') }) } } } } }
$o.userAssist = @($ua | Sort-Object last -Descending | Select-Object -First 40)

# --- running processes, for masquerade and parentage checks ---------------
$o.procs = @(Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{ pid=$_.ProcessId; ppid=$_.ParentProcessId
                     name=$_.Name; path=$_.ExecutablePath } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

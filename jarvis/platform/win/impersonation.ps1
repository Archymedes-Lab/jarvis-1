
$ErrorActionPreference = 'SilentlyContinue'
$o = @{ me=''; logons=@(); console=-1; locked=-1; rdp=@(); creds=@();
        atServices=@(); autoLogon=@{}; errors=@() }

$o.me = "$env:USERDOMAIN\$env:USERNAME"

# Logon sessions, with the account behind each one. Win32_LogonSession alone
# does not say who; the association to Win32_Account does.
try {
  $o.logons = @(Get-CimInstance Win32_LogonSession -ErrorAction Stop |
    ForEach-Object {
      $id = $_.LogonId
      $who = (Get-CimInstance -Query "ASSOCIATORS OF {Win32_LogonSession.LogonId='$id'} WHERE ResultClass=Win32_Account" |
              Select-Object -First 1)
      @{ id=[string]$id; type=[int]$_.LogonType
         start=[string]$_.StartTime
         user=if ($who) { "$($who.Domain)\$($who.Name)" } else { '' } }
    })
} catch { $o.errors += 'Logon session enumeration unavailable' }

# Is anyone physically at the console, and is it locked? LogonUI owns the
# secure desktop while the workstation is locked.
try {
  $o.console = [int](Get-Process -Name explorer -ErrorAction SilentlyContinue |
                     Select-Object -First 1 -ExpandProperty SessionId)
  $o.locked  = [int][bool](Get-Process -Name LogonUI -ErrorAction SilentlyContinue)
} catch { $o.errors += 'Console session state unavailable' }

# Active remote-desktop sessions.
try {
  $q = (qwinsta 2>$null)
  $o.rdp = @($q | Where-Object { $_ -match 'rdp-tcp#' -and $_ -match 'Active' } |
    ForEach-Object { ($_ -replace '\s+', ' ').Trim() })
} catch { $o.errors += 'Remote session list unavailable' }

# Stored credentials let software authenticate as you with no prompt.
try {
  $o.creds = @((cmdkey /list 2>$null) | Where-Object { $_ -match 'Target:' } |
    ForEach-Object { ($_ -replace '.*Target:\s*', '').Trim() })
} catch { $o.errors += 'Stored credential list unavailable' }

# Assistive technology registered to run on the secure desktop. An AT can drive
# the UI through UI Automation without producing any input event at all.
try {
  $atBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs'
  $o.atServices = @(Get-ChildItem $atBase -ErrorAction Stop | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    @{ name=[string]$_.PSChildName
       exe=[string]$p.ATExe
       desc=[string]$p.Description
       startExe=[string]$p.StartExe } })
} catch { }

# Automatic logon stores a password in the clear and logs a session in with no
# one present.
try {
  $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
  $o.autoLogon = @{ enabled=[string]$wl.AutoAdminLogon
                    user=[string]$wl.DefaultUserName
                    hasPassword=[bool]$wl.DefaultPassword }
} catch { }

$json = $o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
